/**
 * Next-Generation Dots AI Platform - HTTP REST & SSE Server (Phase 8A)
 *
 * Architectural Mandate:
 * Exposes a zero-dependency Node.js HTTP REST API and Server-Sent Events stream
 * backed by DotsRuntime, enforcing token authentication, role-based approval
 * restrictions, strict scope isolation, request-size limits, and secret scrubbing.
 */

import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type {
  ApprovalDecision,
  ConversationMessageRole,
  ConversationStatus,
  CreateMemoryInput,
  CreateScheduleInput,
  ImportConflictStrategy,
  MemoryCategory,
  MemoryExportBundle,
  MemoryStatus,
  ProposalDecision,
  ScheduleStatus,
  ScopeIdentifier,
  TaskStatus,
  UpdateMemoryInput,
  WritableMemoryStatus
} from '../domain/types.ts';
import {
  AgentCapabilityError,
  AgentNotFoundError,
  ConcurrencyConflictError,
  ConversationNotFoundError,
  ConversationScopeViolationError,
  DomainError,
  MemoryConflictError,
  MemoryNotFoundError,
  MemoryScopeViolationError,
  ScheduleConflictError,
  ScheduleNotFoundError,
  SecurityViolationError,
  TaskNotFoundError,
  ValidationError
} from '../domain/errors.ts';
import { CircuitBreakerError } from '../domain/errors.ts';
import { BudgetExceededError } from '../model/budget-tracker.ts';
import { defaultSecretScrubber } from '../model/secret-scrubber.ts';
import type { RuntimeEvent } from '../runtime/event-bus.ts';
import { parseScopeSpec } from '../runtime/config.ts';
import {
  DotsRuntime,
  scrubPublicData,
  toPublicConversationView,
  toPublicMessageView,
  type AuthenticatedSession
} from '../runtime/app.ts';

class PayloadTooLargeError extends Error {
  public readonly maxBytes: number;

  constructor(maxBytes: number) {
    super(`Request body exceeds maximum allowed size of ${maxBytes} bytes.`);
    this.maxBytes = maxBytes;
  }
}

export interface DotsHttpServerOptions {
  readonly host?: string;
  readonly port?: number;
  readonly maxBodyBytes?: number;
  readonly sseHeartbeatMs?: number;
}

export interface StartedServerInfo {
  readonly host: string;
  readonly port: number;
  readonly url: string;
}

interface SseClient {
  readonly res: ServerResponse;
  readonly unsubscribe: () => void;
  readonly heartbeat: ReturnType<typeof setInterval>;
}

function getHeaderSingle(req: IncomingMessage, name: string): string | undefined {
  const val = req.headers[name.toLowerCase()];
  if (typeof val === 'string') {
    return val;
  }
  if (Array.isArray(val) && val.length > 0) {
    return val[0];
  }
  return undefined;
}

function parseOptionalInt(raw: string | null, name: string): number | undefined {
  if (raw === null || raw.trim() === '') {
    return undefined;
  }
  const n = Number(raw);
  if (!Number.isInteger(n) || n < 0) {
    throw new ValidationError(`Query parameter '${name}' must be a non-negative integer.`);
  }
  return n;
}

function parseOptionalBool(raw: string | null, name: string): boolean | undefined {
  if (raw === null || raw.trim() === '') {
    return undefined;
  }
  const lower = raw.trim().toLowerCase();
  if (lower === 'true' || lower === '1') {
    return true;
  }
  if (lower === 'false' || lower === '0') {
    return false;
  }
  throw new ValidationError(`Query parameter '${name}' must be a boolean.`);
}

export class DotsHttpServer {
  private readonly runtime: DotsRuntime;
  private readonly host: string;
  private readonly port: number;
  private readonly maxBodyBytes: number;
  private readonly sseHeartbeatMs: number;
  private readonly sseClients: Set<SseClient> = new Set();
  private server: Server | null = null;

  constructor(runtime: DotsRuntime, options: DotsHttpServerOptions = {}) {
    this.runtime = runtime;
    this.host = options.host ?? runtime.config.host;
    this.port = options.port ?? runtime.config.port;
    this.maxBodyBytes = options.maxBodyBytes ?? runtime.config.maxBodyBytes;
    this.sseHeartbeatMs = Math.max(1000, options.sseHeartbeatMs ?? 15_000);
  }

  public async start(): Promise<StartedServerInfo> {
    if (this.server) {
      const addr = this.server.address();
      const boundPort = typeof addr === 'object' && addr ? addr.port : this.port;
      return {
        host: this.host,
        port: boundPort,
        url: `http://${this.host}:${boundPort}`
      };
    }

    await this.runtime.start();

    const server = createServer((req, res) => {
      void this.handleRequest(req, res);
    });
    this.server = server;

    await new Promise<void>((resolve, reject) => {
      const onError = (err: Error) => {
        server.off('listening', onListening);
        reject(err);
      };
      const onListening = () => {
        server.off('error', onError);
        resolve();
      };
      server.once('error', onError);
      server.once('listening', onListening);
      server.listen(this.port, this.host);
    });

    const addr = server.address();
    const boundPort = typeof addr === 'object' && addr ? addr.port : this.port;
    const url = `http://${this.host}:${boundPort}`;

    this.runtime.logger.info('http', 'listening', {
      host: this.host,
      port: boundPort,
      maxBodyBytes: this.maxBodyBytes
    });

    return { host: this.host, port: boundPort, url };
  }

  public async stop(): Promise<void> {
    for (const client of Array.from(this.sseClients)) {
      this.closeSseClient(client);
    }

    const server = this.server;
    this.server = null;
    if (server) {
      await new Promise<void>((resolve) => {
        server.close(() => resolve());
      });
    }

    await this.runtime.stop();
  }

  private closeSseClient(client: SseClient): void {
    if (!this.sseClients.has(client)) {
      return;
    }
    this.sseClients.delete(client);
    clearInterval(client.heartbeat);
    client.unsubscribe();
    if (!client.res.writableEnded) {
      client.res.end();
    }
  }

  private async handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const method = (req.method ?? 'GET').toUpperCase();
    const rawUrl = req.url ?? '/';

    let url: URL;
    try {
      url = new URL(rawUrl, 'http://localhost');
    } catch {
      this.sendJson(res, 400, { error: { code: 'VALIDATION_ERROR', message: 'Malformed request URL.' } });
      return;
    }

    const pathname = url.pathname;

    try {
      if (method === 'GET' && (pathname === '/health' || pathname === '/api/health')) {
        this.sendJson(res, 200, this.runtime.getHealth());
        return;
      }

      if (!pathname.startsWith('/api/')) {
        this.sendJson(res, 404, { error: { code: 'NOT_FOUND', message: 'Route not found.' } });
        return;
      }

      // Authenticate every /api/* request
      const session = this.authenticateRequest(req, url);

      if (method === 'GET' && pathname === '/api/events') {
        this.handleSse(req, res, url, session);
        return;
      }

      const taskEventsMatch = /^\/api\/tasks\/([^/]+)\/events$/.exec(pathname);
      if (method === 'GET' && taskEventsMatch) {
        const taskId = decodeURIComponent(taskEventsMatch[1]!);
        this.runtime.getTaskDetails(session.caller, taskId);
        this.handleSse(req, res, url, session, taskId);
        return;
      }

      await this.routeApi(method, pathname, url, req, res, session);
    } catch (err) {
      this.handleError(res, err, pathname);
    }
  }

  private authenticateRequest(req: IncomingMessage, url: URL): AuthenticatedSession {
    const authHeader = getHeaderSingle(req, 'authorization');
    const tokenHeader = getHeaderSingle(req, 'x-dots-token');
    const credentials = authHeader ?? tokenHeader;

    const scopeHeader = getHeaderSingle(req, 'x-dots-scope');
    let requestedScope: ScopeIdentifier | undefined;
    if (scopeHeader) {
      requestedScope = parseScopeSpec(scopeHeader);
    } else {
      const scopeType = getHeaderSingle(req, 'x-scope-type') ?? url.searchParams.get('scopeType') ?? undefined;
      const scopeId = getHeaderSingle(req, 'x-scope-id') ?? url.searchParams.get('scopeId') ?? undefined;
      if (scopeType && scopeId) {
        requestedScope = parseScopeSpec(`${scopeType}:${scopeId}`);
      } else if (scopeType || scopeId) {
        throw new ValidationError('Both scopeType and scopeId must be provided when specifying scope.');
      }
    }

    return this.runtime.authenticateUser(credentials, requestedScope);
  }

  private handleSse(
    req: IncomingMessage,
    res: ServerResponse,
    url: URL,
    session: AuthenticatedSession,
    forcedTaskId?: string
  ): void {
    const filterTaskId = forcedTaskId ?? (url.searchParams.get('taskId')?.trim() || undefined);
    const filterScheduleId = url.searchParams.get('scheduleId')?.trim() || undefined;
    const typeParam = url.searchParams.get('type')?.trim();
    const filterTypes = typeParam
      ? new Set(typeParam.split(',').map((t) => t.trim()).filter(Boolean))
      : null;

    res.writeHead(200, {
      'Content-Type': 'text/event-stream; charset=utf-8',
      'Cache-Control': 'no-cache, no-transform',
      Connection: 'keep-alive',
      'X-Accel-Buffering': 'no'
    });

    res.write(': connected\n\n');

    const scope = session.caller.scope;
    const unsubscribe = this.runtime.eventBus.subscribe((event: RuntimeEvent) => {
      // Strict scope isolation: never leak events from another scope
      if (event.scope.scopeType !== scope.scopeType || event.scope.scopeId !== scope.scopeId) {
        return;
      }
      if (filterTaskId && event.taskId !== filterTaskId) {
        return;
      }
      if (filterScheduleId && event.scheduleId !== filterScheduleId) {
        return;
      }
      if (filterTypes && !filterTypes.has(event.type)) {
        return;
      }
      if (res.writableEnded) {
        return;
      }
      const safePayload = JSON.stringify(scrubPublicData(event));
      res.write(`id: ${event.id}\nevent: ${event.type}\ndata: ${safePayload}\n\n`);
    });

    const heartbeat = setInterval(() => {
      if (!res.writableEnded) {
        res.write(': heartbeat\n\n');
      }
    }, this.sseHeartbeatMs);
    heartbeat.unref?.();

    const client: SseClient = { res, unsubscribe, heartbeat };
    this.sseClients.add(client);

    req.on('close', () => this.closeSseClient(client));
    res.on('error', () => this.closeSseClient(client));
  }

  private async routeApi(
    method: string,
    pathname: string,
    url: URL,
    req: IncomingMessage,
    res: ServerResponse,
    session: AuthenticatedSession
  ): Promise<void> {
    const { caller, principal } = session;

    // --- Tasks ---
    if (method === 'POST' && pathname === '/api/tasks') {
      const body = await this.readJsonObject(req);
      const task = await this.runtime.submitTask(caller, {
        objective: typeof body.objective === 'string' ? body.objective : undefined,
        goal: typeof body.goal === 'string' ? body.goal : undefined,
        description: typeof body.description === 'string' ? body.description : undefined,
        agentId: typeof body.agentId === 'string' ? body.agentId : undefined,
        parameters: body.parameters && typeof body.parameters === 'object' && !Array.isArray(body.parameters)
          ? (body.parameters as Record<string, unknown>)
          : (body.parameters as any),
        metadata: body.metadata && typeof body.metadata === 'object' && !Array.isArray(body.metadata)
          ? (body.metadata as Record<string, unknown>)
          : undefined,
        run: body.run === true
      });
      this.sendJson(res, 201, { task });
      return;
    }

    if (method === 'GET' && pathname === '/api/tasks') {
      const status = (url.searchParams.get('status')?.trim() || undefined) as TaskStatus | undefined;
      const agentId = url.searchParams.get('agentId')?.trim() || undefined;
      const limit = parseOptionalInt(url.searchParams.get('limit'), 'limit');
      const offset = parseOptionalInt(url.searchParams.get('offset'), 'offset');
      const result = this.runtime.listTasksWithTotal(caller, { status, agentId, limit, offset });
      this.sendJson(res, 200, { tasks: result.tasks, total: result.total });
      return;
    }

    let match = /^\/api\/tasks\/([^/]+)$/.exec(pathname);
    if (match && method === 'GET') {
      const taskId = decodeURIComponent(match[1]!);
      const details = this.runtime.getTaskDetails(caller, taskId);
      this.sendJson(res, 200, details);
      return;
    }

    match = /^\/api\/tasks\/([^/]+)\/status$/.exec(pathname);
    if (match && method === 'GET') {
      const taskId = decodeURIComponent(match[1]!);
      const details = this.runtime.getTaskDetails(caller, taskId);
      this.sendJson(res, 200, {
        taskId: details.task.id,
        status: details.task.status,
        goal: details.task.goal,
        currentStepIndex: details.task.currentStepIndex,
        completedAt: details.task.completedAt,
        errorSummary: details.task.errorSummary
      });
      return;
    }

    match = /^\/api\/tasks\/([^/]+)\/result$/.exec(pathname);
    if (match && method === 'GET') {
      const taskId = decodeURIComponent(match[1]!);
      const result = this.runtime.getTaskResult(caller, taskId);
      this.sendJson(res, 200, { result });
      return;
    }

    match = /^\/api\/tasks\/([^/]+)\/audit$/.exec(pathname);
    if (match && method === 'GET') {
      const taskId = decodeURIComponent(match[1]!);
      const details = this.runtime.getTaskDetails(caller, taskId);
      this.sendJson(res, 200, { taskId, events: details.auditEvents, count: details.auditEvents.length });
      return;
    }

    match = /^\/api\/tasks\/([^/]+)\/run$/.exec(pathname);
    if (match && method === 'POST') {
      await this.readOptionalJsonObject(req);
      const taskId = decodeURIComponent(match[1]!);
      const task = await this.runtime.runTask(caller, taskId);
      this.sendJson(res, 200, { task });
      return;
    }

    match = /^\/api\/tasks\/([^/]+)\/cancel$/.exec(pathname);
    if (match && method === 'POST') {
      const body = await this.readOptionalJsonObject(req);
      const taskId = decodeURIComponent(match[1]!);
      const reason = typeof body.reason === 'string' ? body.reason : undefined;
      const task = this.runtime.cancelTask(caller, taskId, reason);
      this.sendJson(res, 200, { task });
      return;
    }

    // --- Tools ---
    if (method === 'GET' && pathname === '/api/tools') {
      const tools = this.runtime.listTools().map((t) => ({
        name: t.definition.name,
        description: t.definition.description,
        riskTier: t.riskTier,
        parameters: t.definition.parameters,
        required: t.definition.required ?? []
      }));
      this.sendJson(res, 200, { tools, count: tools.length });
      return;
    }

    // --- Agents ---
    if (method === 'GET' && pathname === '/api/agents') {
      const agents = this.runtime.listAgents();
      this.sendJson(res, 200, { agents, count: agents.length });
      return;
    }

    // --- Approvals ---
    if (method === 'GET' && pathname === '/api/approvals') {
      const decision = (url.searchParams.get('decision')?.trim() || undefined) as ApprovalDecision | undefined;
      const limit = parseOptionalInt(url.searchParams.get('limit'), 'limit');
      const approvals = this.runtime.listApprovals(caller, { decision, limit });
      this.sendJson(res, 200, { approvals });
      return;
    }

    match = /^\/api\/approvals\/([^/]+)\/decide$/.exec(pathname);
    if (match && method === 'POST') {
      const approvalId = decodeURIComponent(match[1]!);
      const body = await this.readJsonObject(req);
      const decision = body.decision as 'APPROVED' | 'REJECTED';
      const resume = body.resume === undefined ? true : Boolean(body.resume);
      const result = await this.runtime.decideApproval(caller, principal, approvalId, decision, { resume });
      this.sendJson(res, 200, result);
      return;
    }

    // --- Memories (static subroutes before :id) ---
    if (method === 'GET' && pathname === '/api/memories/export') {
      const category = (url.searchParams.get('category')?.trim() || undefined) as MemoryCategory | undefined;
      const includeArchived = parseOptionalBool(url.searchParams.get('includeArchived'), 'includeArchived');
      const bundle = this.runtime.memoryService.exportMemories(caller, {
        category,
        includeArchived
      });
      this.sendJson(res, 200, { bundle });
      return;
    }

    if (method === 'POST' && pathname === '/api/memories/import') {
      const body = await this.readJsonObject(req);
      const bundle = (body.bundle ?? body) as MemoryExportBundle;
      const conflictStrategy = body.conflictStrategy as ImportConflictStrategy | undefined;
      const result = this.runtime.memoryService.importMemories(caller, bundle, {
        conflictStrategy
      });
      this.sendJson(res, 200, { result });
      return;
    }

    if (method === 'POST' && pathname === '/api/memories/purge') {
      const body = await this.readJsonObject(req);
      const result = this.runtime.memoryService.purgeArchivedMemories(caller, {
        memoryIds: body.memoryIds as readonly string[] | undefined,
        olderThan: body.olderThan as string | undefined,
        dryRun: body.dryRun as boolean | undefined,
        maxBatchSize: body.maxBatchSize as number | undefined
      });
      this.sendJson(res, 200, { result });
      return;
    }

    if (method === 'GET' && pathname === '/api/memories') {
      const category = (url.searchParams.get('category')?.trim() || undefined) as MemoryCategory | undefined;
      const status = (url.searchParams.get('status')?.trim() || undefined) as MemoryStatus | undefined;
      const limit = parseOptionalInt(url.searchParams.get('limit'), 'limit');
      const offset = parseOptionalInt(url.searchParams.get('offset'), 'offset');
      const memories = this.runtime.memoryService.listMemories(caller, {
        category,
        status,
        limit,
        offset
      });
      this.sendJson(res, 200, { memories });
      return;
    }

    if (method === 'POST' && pathname === '/api/memories') {
      const body = await this.readJsonObject(req);
      if (body.status === 'SUPERSEDED') {
        throw new ValidationError("Direct creation of 'SUPERSEDED' memories is not permitted.");
      }
      if ('version' in body || 'supersedesId' in body || 'supersededBy' in body) {
        throw new ValidationError("Direct specification of lineage metadata ('version', 'supersedesId', 'supersededBy') is not permitted.");
      }
      const input: CreateMemoryInput = {
        category: body.category as MemoryCategory,
        key: body.key as string,
        content: body.content as string,
        tags: body.tags as string[] | undefined,
        priority: body.priority as number | undefined,
        metadata: body.metadata as Record<string, unknown> | undefined,
        scopeType: caller.scope.scopeType,
        scopeId: caller.scope.scopeId,
        ...(body.status !== undefined ? { status: body.status as WritableMemoryStatus } : {})
      };
      const memory = this.runtime.memoryService.createMemory(caller, input);
      this.sendJson(res, 201, { memory });
      return;
    }

    match = /^\/api\/memories\/([^/]+)$/.exec(pathname);
    if (match && method === 'GET') {
      const id = decodeURIComponent(match[1]!);
      const memory = this.runtime.memoryService.getMemoryById(caller, id);
      if (!memory) {
        throw new MemoryNotFoundError(id);
      }
      this.sendJson(res, 200, { memory });
      return;
    }

    if (match && method === 'PATCH') {
      const id = decodeURIComponent(match[1]!);
      const body = await this.readJsonObject(req);
      if (body.status === 'SUPERSEDED') {
        throw new ValidationError("Direct status transition to 'SUPERSEDED' is not permitted via update.");
      }
      if ('version' in body || 'supersedesId' in body || 'supersededBy' in body) {
        throw new ValidationError("Direct modification of lineage metadata ('version', 'supersedesId', 'supersededBy') is not permitted.");
      }
      const input: UpdateMemoryInput = {
        ...(body.content !== undefined ? { content: body.content as string } : {}),
        ...(body.category !== undefined ? { category: body.category as MemoryCategory } : {}),
        ...(body.priority !== undefined ? { priority: body.priority as number } : {}),
        ...(body.tags !== undefined ? { tags: body.tags as string[] } : {}),
        ...(body.metadata !== undefined ? { metadata: body.metadata as Record<string, unknown> } : {}),
        ...(body.status !== undefined ? { status: body.status as WritableMemoryStatus } : {})
      };
      const memory = this.runtime.memoryService.updateMemory(caller, id, input);
      this.sendJson(res, 200, { memory });
      return;
    }

    if (match && method === 'DELETE') {
      const id = decodeURIComponent(match[1]!);
      const deleted = this.runtime.memoryService.deleteMemory(caller, id);
      this.sendJson(res, 200, { deleted });
      return;
    }

    match = /^\/api\/memories\/([^/]+)\/archive$/.exec(pathname);
    if (match && method === 'POST') {
      await this.readOptionalJsonObject(req);
      const id = decodeURIComponent(match[1]!);
      const memory = this.runtime.memoryService.archiveMemory(caller, id);
      this.sendJson(res, 200, { memory });
      return;
    }

    match = /^\/api\/memories\/([^/]+)\/decide$/.exec(pathname);
    if (match && method === 'POST') {
      const id = decodeURIComponent(match[1]!);
      const body = await this.readJsonObject(req);
      const memory = this.runtime.memoryService.decideProposal(caller, {
        memoryId: id,
        decision: body.decision as ProposalDecision,
        reason: typeof body.reason === 'string' ? body.reason : undefined
      });
      this.sendJson(res, 200, { memory });
      return;
    }

    // --- Schedules ---
    if (method === 'POST' && pathname === '/api/schedules') {
      const body = await this.readJsonObject(req);
      const schedule = this.runtime.createSchedule(caller, body as unknown as CreateScheduleInput);
      this.sendJson(res, 201, { schedule });
      return;
    }

    if (method === 'GET' && pathname === '/api/schedules') {
      const status = (url.searchParams.get('status')?.trim() || undefined) as ScheduleStatus | undefined;
      const limit = parseOptionalInt(url.searchParams.get('limit'), 'limit');
      const offset = parseOptionalInt(url.searchParams.get('offset'), 'offset');
      const schedules = this.runtime.listSchedules(caller, { status, limit, offset });
      this.sendJson(res, 200, { schedules });
      return;
    }

    match = /^\/api\/schedules\/([^/]+)$/.exec(pathname);
    if (match && method === 'GET') {
      const scheduleId = decodeURIComponent(match[1]!);
      const schedule = this.runtime.getSchedule(caller, scheduleId);
      this.sendJson(res, 200, { schedule });
      return;
    }

    match = /^\/api\/schedules\/([^/]+)\/occurrences$/.exec(pathname);
    if (match && method === 'GET') {
      const scheduleId = decodeURIComponent(match[1]!);
      const limit = parseOptionalInt(url.searchParams.get('limit'), 'limit') ?? 50;
      const offset = parseOptionalInt(url.searchParams.get('offset'), 'offset') ?? 0;
      const occurrences = this.runtime.listScheduleOccurrences(caller, scheduleId, limit, offset);
      this.sendJson(res, 200, { occurrences });
      return;
    }

    match = /^\/api\/schedules\/([^/]+)\/pause$/.exec(pathname);
    if (match && method === 'POST') {
      const body = await this.readOptionalJsonObject(req);
      const scheduleId = decodeURIComponent(match[1]!);
      const reason = typeof body.reason === 'string' ? body.reason : undefined;
      const schedule = this.runtime.pauseSchedule(caller, scheduleId, reason);
      this.sendJson(res, 200, { schedule });
      return;
    }

    match = /^\/api\/schedules\/([^/]+)\/resume$/.exec(pathname);
    if (match && method === 'POST') {
      await this.readOptionalJsonObject(req);
      const scheduleId = decodeURIComponent(match[1]!);
      const schedule = this.runtime.resumeSchedule(caller, scheduleId);
      this.sendJson(res, 200, { schedule });
      return;
    }

    match = /^\/api\/schedules\/([^/]+)\/cancel$/.exec(pathname);
    if (match && method === 'POST') {
      await this.readOptionalJsonObject(req);
      const scheduleId = decodeURIComponent(match[1]!);
      const schedule = this.runtime.cancelSchedule(caller, scheduleId);
      this.sendJson(res, 200, { schedule });
      return;
    }

    // --- Conversations ---
    if (method === 'POST' && pathname === '/api/conversations') {
      const body = await this.readOptionalJsonObject(req);
      const conversation = this.runtime.createConversation(caller, {
        title: typeof body.title === 'string' ? body.title : undefined,
        agentId: typeof body.agentId === 'string' ? body.agentId : undefined,
        metadata:
          body.metadata && typeof body.metadata === 'object' && !Array.isArray(body.metadata)
            ? (body.metadata as Record<string, unknown>)
            : undefined
      });
      this.sendJson(res, 201, { conversation: toPublicConversationView(conversation) });
      return;
    }

    if (method === 'GET' && pathname === '/api/conversations') {
      const status = (url.searchParams.get('status')?.trim() || undefined) as ConversationStatus | undefined;
      const agentId = url.searchParams.get('agentId')?.trim() || undefined;
      const limit = parseOptionalInt(url.searchParams.get('limit'), 'limit');
      const offset = parseOptionalInt(url.searchParams.get('offset'), 'offset');
      const result = this.runtime.listConversations(caller, { status, agentId, limit, offset });
      this.sendJson(res, 200, {
        conversations: result.conversations.map(toPublicConversationView),
        total: result.total
      });
      return;
    }

    match = /^\/api\/conversations\/([^/]+)\/archive$/.exec(pathname);
    if (match && method === 'POST') {
      await this.readOptionalJsonObject(req);
      const conversationId = decodeURIComponent(match[1]!);
      const conversation = this.runtime.archiveConversation(caller, conversationId);
      this.sendJson(res, 200, { conversation: toPublicConversationView(conversation) });
      return;
    }

    match = /^\/api\/conversations\/([^/]+)\/messages$/.exec(pathname);
    if (match && method === 'POST') {
      const conversationId = decodeURIComponent(match[1]!);
      const body = await this.readJsonObject(req);
      if (!body.content || typeof body.content !== 'string' || (body.content as string).trim() === '') {
        throw new ValidationError("Field 'content' must be a non-empty string.");
      }
      const result = await this.runtime.sendConversationMessage(caller, conversationId, {
        content: body.content as string,
        role: typeof body.role === 'string' ? (body.role as ConversationMessageRole) : undefined,
        name: typeof body.name === 'string' ? (body.name as string) : undefined,
        clientMessageId: typeof body.clientMessageId === 'string' ? (body.clientMessageId as string) : undefined,
        metadata:
          body.metadata && typeof body.metadata === 'object' && !Array.isArray(body.metadata)
            ? (body.metadata as Record<string, unknown>)
            : undefined
      });
      this.sendJson(res, 200, {
        conversation: toPublicConversationView(result.conversation),
        userMessage: toPublicMessageView(result.userMessage),
        ...(result.assistantMessage ? { assistantMessage: toPublicMessageView(result.assistantMessage) } : {}),
        ...(result.usage ? { usage: result.usage } : {})
      });
      return;
    }

    match = /^\/api\/conversations\/([^/]+)\/messages$/.exec(pathname);
    if (match && method === 'GET') {
      const conversationId = decodeURIComponent(match[1]!);
      const limit = parseOptionalInt(url.searchParams.get('limit'), 'limit');
      const offset = parseOptionalInt(url.searchParams.get('offset'), 'offset');
      const orderParam = url.searchParams.get('order')?.trim().toUpperCase();
      const order = orderParam === 'DESC' ? 'DESC' : 'ASC';
      const result = this.runtime.getConversationMessages(caller, conversationId, { limit, offset, order });
      this.sendJson(res, 200, {
        messages: result.messages.map(toPublicMessageView),
        total: result.total
      });
      return;
    }

    match = /^\/api\/conversations\/([^/]+)$/.exec(pathname);
    if (match && method === 'GET') {
      const conversationId = decodeURIComponent(match[1]!);
      const limit = parseOptionalInt(url.searchParams.get('limit'), 'limit');
      const offset = parseOptionalInt(url.searchParams.get('offset'), 'offset');
      const conversation = this.runtime.getConversation(caller, conversationId);
      const messagesResult = this.runtime.getConversationMessages(caller, conversationId, { limit, offset });
      this.sendJson(res, 200, {
        conversation: toPublicConversationView(conversation),
        messages: messagesResult.messages.map(toPublicMessageView),
        totalMessages: messagesResult.total
      });
      return;
    }

    match = /^\/api\/conversations\/([^/]+)$/.exec(pathname);
    if (match && method === 'PATCH') {
      const conversationId = decodeURIComponent(match[1]!);
      const body = await this.readJsonObject(req);
      const conversation = this.runtime.updateConversation(caller, conversationId, {
        title: typeof body.title === 'string' ? body.title : undefined,
        agentId: body.agentId === null ? null : (typeof body.agentId === 'string' ? body.agentId : undefined),
        metadata:
          body.metadata && typeof body.metadata === 'object' && !Array.isArray(body.metadata)
            ? (body.metadata as Record<string, unknown>)
            : undefined
      });
      this.sendJson(res, 200, { conversation: toPublicConversationView(conversation) });
      return;
    }

    match = /^\/api\/conversations\/([^/]+)$/.exec(pathname);
    if (match && method === 'DELETE') {
      const conversationId = decodeURIComponent(match[1]!);
      const hard = parseOptionalBool(url.searchParams.get('hard'), 'hard') === true;
      if (hard) {
        const deleted = this.runtime.deleteConversation(caller, conversationId);
        this.sendJson(res, 200, { deleted });
      } else {
        const conversation = this.runtime.archiveConversation(caller, conversationId);
        this.sendJson(res, 200, { conversation: toPublicConversationView(conversation) });
      }
      return;
    }

    this.sendJson(res, 404, { error: { code: 'NOT_FOUND', message: 'API endpoint not found.' } });
  }

  private async readJsonObject(req: IncomingMessage): Promise<Record<string, unknown>> {
    const raw = await this.readRawBody(req);
    if (raw.trim() === '') {
      throw new ValidationError('Request body must be a valid JSON object.');
    }
    return this.parseJsonObject(raw, req);
  }

  private async readOptionalJsonObject(req: IncomingMessage): Promise<Record<string, unknown>> {
    const raw = await this.readRawBody(req);
    if (raw.trim() === '') {
      return {};
    }
    return this.parseJsonObject(raw, req);
  }

  private parseJsonObject(raw: string, req: IncomingMessage): Record<string, unknown> {
    const contentType = getHeaderSingle(req, 'content-type');
    if (contentType && !contentType.toLowerCase().includes('application/json')) {
      throw new ValidationError("Content-Type must be 'application/json'.");
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      throw new ValidationError('Malformed JSON request body.');
    }

    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new ValidationError('Request body must be a JSON object.');
    }
    return parsed as Record<string, unknown>;
  }

  private readRawBody(req: IncomingMessage): Promise<string> {
    const contentLengthRaw = getHeaderSingle(req, 'content-length');
    if (contentLengthRaw !== undefined) {
      const contentLength = Number(contentLengthRaw);
      if (Number.isFinite(contentLength) && contentLength > this.maxBodyBytes) {
        req.resume();
        return Promise.reject(new PayloadTooLargeError(this.maxBodyBytes));
      }
    }

    return new Promise<string>((resolve, reject) => {
      const chunks: Buffer[] = [];
      let totalBytes = 0;
      let settled = false;

      req.on('data', (chunk: Buffer | string) => {
        if (settled) {
          return;
        }
        const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, 'utf8');
        totalBytes += buf.length;
        if (totalBytes > this.maxBodyBytes) {
          settled = true;
          req.pause();
          reject(new PayloadTooLargeError(this.maxBodyBytes));
          return;
        }
        chunks.push(buf);
      });

      req.on('end', () => {
        if (settled) {
          return;
        }
        settled = true;
        resolve(Buffer.concat(chunks).toString('utf8'));
      });

      req.on('error', (err) => {
        if (settled) {
          return;
        }
        settled = true;
        reject(err);
      });
    });
  }

  private handleError(res: ServerResponse, err: unknown, pathname: string): void {
    if (err instanceof PayloadTooLargeError) {
      this.sendJson(res, 413, {
        error: {
          code: 'PAYLOAD_TOO_LARGE',
          message: err.message,
          maxBodyBytes: err.maxBytes
        }
      });
      return;
    }

    if (err instanceof SecurityViolationError) {
      const isAuth =
        err.violationType === 'UNAUTHENTICATED' ||
        err.violationType === 'MISSING_IDENTITY_INTEGRATION';
      const status = isAuth ? 401 : 403;
      this.sendJson(res, status, {
        error: {
          code: err.code,
          violationType: err.violationType,
          message: defaultSecretScrubber.scrub(err.message)
        }
      });
      return;
    }

    if (err instanceof MemoryScopeViolationError || err instanceof ConversationScopeViolationError) {
      this.sendJson(res, 403, {
        error: {
          code: err.code,
          message: defaultSecretScrubber.scrub(err.message)
        }
      });
      return;
    }

    if (
      err instanceof TaskNotFoundError ||
      err instanceof MemoryNotFoundError ||
      err instanceof ScheduleNotFoundError ||
      err instanceof ConversationNotFoundError ||
      err instanceof AgentNotFoundError
    ) {
      this.sendJson(res, 404, {
        error: {
          code: err.code,
          message: defaultSecretScrubber.scrub(err.message)
        }
      });
      return;
    }

    if (
      err instanceof ConcurrencyConflictError ||
      err instanceof MemoryConflictError ||
      err instanceof ScheduleConflictError
    ) {
      this.sendJson(res, 409, {
        error: {
          code: err.code,
          message: defaultSecretScrubber.scrub(err.message)
        }
      });
      return;
    }

    if (err instanceof BudgetExceededError || err instanceof CircuitBreakerError) {
      this.sendJson(res, 429, {
        error: {
          code: err.code,
          message: defaultSecretScrubber.scrub(err.message)
        }
      });
      return;
    }

    if (err instanceof ValidationError || err instanceof DomainError) {
      this.sendJson(res, 400, {
        error: {
          code: err.code,
          message: defaultSecretScrubber.scrub(err.message)
        }
      });
      return;
    }

    const message = err instanceof Error ? err.message : String(err);
    this.runtime.logger.error('http', 'unhandled_error', {
      pathname,
      message
    });

    this.sendJson(res, 500, {
      error: {
        code: 'INTERNAL_ERROR',
        message: 'Internal server error.'
      }
    });
  }

  private sendJson(res: ServerResponse, statusCode: number, payload: unknown): void {
    if (res.writableEnded) {
      return;
    }
    const safeBody = JSON.stringify(scrubPublicData(payload));
    res.writeHead(statusCode, {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff'
    });
    res.end(safeBody);
  }
}
