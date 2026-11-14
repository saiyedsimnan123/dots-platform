/**
 * Next-Generation Dots AI Platform - Operational Application Runtime (Phase 8C)
 *
 * Architectural Mandate:
 * Single composition root wiring storage, security, model gateway, tool sandbox,
 * coordinator, memory, scheduler, event bus, and structured logging into an
 * operational local backend with strict scope isolation and role enforcement.
 */

import type {
  ApprovalDecision,
  ApprovalRequest,
  AuditEvent,
  CallerContext,
  Conversation,
  ConversationMessage,
  ConversationMessageRole,
  ConversationResponse,
  ConversationStatus,
  CreateConversationInput,
  CreateScheduleInput,
  ListConversationsFilter,
  ListMessagesFilter,
  ListSchedulesFilter,
  Schedule,
  ScheduleOccurrence,
  ScopeIdentifier,
  SendConversationMessageInput,
  Task,
  TaskStatus,
  TaskStep,
  UpdateConversationInput
} from '../domain/types.ts';
import {
  SecurityViolationError,
  TaskNotFoundError,
  ValidationError
} from '../domain/errors.ts';
import { TaskStateMachine } from '../domain/state-machine.ts';
import { DatabaseManager } from '../storage/db.ts';
import { TaskRepository } from '../storage/task-repository.ts';
import { AuditRepository } from '../storage/audit-repository.ts';
import { MemoryRepository } from '../storage/memory-repository.ts';
import { ScheduleRepository } from '../storage/schedule-repository.ts';
import { ConversationRepository } from '../storage/conversation-repository.ts';
import { ConversationService } from '../conversation/conversation-service.ts';
import { CrashRecoveryEngine } from '../storage/recovery.ts';
import type { IModelProvider } from '../model/types.ts';
import { MockModelProvider } from '../model/mock-provider.ts';
import { GeminiProvider } from '../model/gemini-provider.ts';
import { TokenBudgetTracker, type TaskUsageSummary } from '../model/budget-tracker.ts';
import { defaultSecretScrubber } from '../model/secret-scrubber.ts';
import { ToolRegistry } from '../tools/registry.ts';
import { standardTools } from '../tools/sandbox-tools.ts';
import { PolicyEngine } from '../security/policy-engine.ts';
import { ApprovalBroker } from '../security/approval-broker.ts';
import { HostMemoryAuthority } from '../security/host-authority.ts';
import type { AuthenticatedPrincipal, MemoryAuthorizer } from '../security/memory-authorizer.ts';
import { TokenIdentityProvider } from '../security/token-identity-provider.ts';
import { VerificationEngine } from '../verification/verifier.ts';
import { MemoryService } from '../memory/memory-service.ts';
import { TaskCoordinator } from '../orchestrator/coordinator.ts';
import { AgentRegistry } from '../agents/index.ts';
import { TaskScheduler } from '../scheduler/task-scheduler.ts';
import { RuntimeEventBus } from './event-bus.ts';
import { OperationalLogger } from './logger.ts';
import {
  loadRuntimeConfig,
  type DotsRuntimeConfig,
  type LoadRuntimeConfigOverrides
} from './config.ts';

const SYSTEM_SCHEDULER_TASK_ID = '__system_scheduler__';
const SENSITIVE_KEY_PATTERN = /(?:token|secret|password|passphrase|passwd|apikey|api_key|privatekey|authorization|credential|_scopeAttestation|_proof)/i;

export interface PublicTaskView {
  readonly id: string;
  readonly goal: string;
  readonly status: TaskStatus;
  readonly currentStepIndex: number;
  readonly scope: ScopeIdentifier;
  readonly metadata: Record<string, unknown>;
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly completedAt: string | null;
  readonly errorSummary: string | null;
}

export interface PublicApprovalView {
  readonly id: string;
  readonly taskId: string;
  readonly stepId: string;
  readonly riskTier: ApprovalRequest['riskTier'];
  readonly actionSummary: string;
  readonly targetResource: string;
  readonly parameterDiff: Record<string, unknown>;
  readonly decision: ApprovalDecision;
  readonly decidedBy: string | null;
  readonly decidedAt: string | null;
  readonly expiresAt: string;
  readonly createdAt: string;
}

export interface TaskDetailsView {
  readonly task: PublicTaskView;
  readonly steps: readonly Record<string, unknown>[];
  readonly approvals: readonly PublicApprovalView[];
  readonly auditEvents: readonly Record<string, unknown>[];
  readonly usage: TaskUsageSummary;
}

export interface AuthenticatedSession {
  readonly caller: CallerContext;
  readonly principal: AuthenticatedPrincipal;
}

export interface PublicConversationView {
  readonly id: string;
  readonly title: string;
  readonly status: ConversationStatus;
  readonly scope: ScopeIdentifier;
  readonly createdBy: string;
  readonly agentId: string | null;
  readonly metadata: Record<string, unknown>;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface PublicMessageView {
  readonly id: string;
  readonly conversationId: string;
  readonly role: ConversationMessageRole;
  readonly content: string;
  readonly name?: string | null;
  readonly clientMessageId?: string | null;
  readonly metadata?: Record<string, unknown>;
  readonly createdAt: string;
}

export function toPublicConversationView(c: Conversation): PublicConversationView {
  return {
    id: c.id,
    title: defaultSecretScrubber.scrub(c.title),
    status: c.status,
    scope: { scopeType: c.scopeType, scopeId: c.scopeId },
    createdBy: c.createdBy,
    agentId: c.agentId,
    metadata: scrubPublicData(safeJsonParse(c.metadataJson)) as Record<string, unknown>,
    createdAt: c.createdAt,
    updatedAt: c.updatedAt
  };
}

export function toPublicMessageView(m: ConversationMessage): PublicMessageView {
  return {
    id: m.id,
    conversationId: m.conversationId,
    role: m.role,
    content: defaultSecretScrubber.scrub(m.content),
    ...(m.name ? { name: defaultSecretScrubber.scrub(m.name) } : {}),
    ...(m.clientMessageId ? { clientMessageId: m.clientMessageId } : {}),
    metadata: scrubPublicData(safeJsonParse(m.metadataJson ?? null)) as Record<string, unknown>,
    createdAt: m.createdAt
  };
}

export interface DotsRuntimeOptions extends LoadRuntimeConfigOverrides {
  readonly modelProvider?: IModelProvider;
  readonly logger?: OperationalLogger;
  readonly eventBus?: RuntimeEventBus;
  readonly agentRegistry?: AgentRegistry;
}

export function scrubPublicData(value: unknown, depth: number = 0): unknown {
  if (depth > 8) {
    return '[TRUNCATED]';
  }
  if (typeof value === 'string') {
    return defaultSecretScrubber.scrub(value);
  }
  if (Array.isArray(value)) {
    return value.map((item) => scrubPublicData(item, depth + 1));
  }
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (k === '_scopeAttestation' || k === '_proof' || k === 'approvalToken') {
        continue;
      }
      if (SENSITIVE_KEY_PATTERN.test(k)) {
        out[k] = '[REDACTED]';
      } else {
        out[k] = scrubPublicData(v, depth + 1);
      }
    }
    return out;
  }
  return value;
}

function safeJsonParse(raw: string | null): Record<string, unknown> {
  if (!raw) {
    return {};
  }
  try {
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : {};
  } catch {
    return {};
  }
}

export class DotsRuntime {
  public readonly config: DotsRuntimeConfig;
  public readonly logger: OperationalLogger;
  public readonly eventBus: RuntimeEventBus;
  public readonly db: DatabaseManager;
  public readonly taskRepo: TaskRepository;
  public readonly auditRepo: AuditRepository;
  public readonly memoryRepo: MemoryRepository;
  public readonly scheduleRepo: ScheduleRepository;
  public readonly identityProvider: TokenIdentityProvider;
  public readonly authorizer: MemoryAuthorizer;
  public readonly memoryService: MemoryService;
  public readonly toolRegistry: ToolRegistry;
  public readonly policyEngine: PolicyEngine;
  public readonly approvalBroker: ApprovalBroker;
  public readonly verifier: VerificationEngine;
  public readonly budgetTracker: TokenBudgetTracker;
  public readonly modelProvider: IModelProvider;
  public readonly agentRegistry: AgentRegistry;
  public readonly coordinator: TaskCoordinator;
  public readonly crashRecovery: CrashRecoveryEngine;
  public readonly scheduler: TaskScheduler;
  public readonly conversationRepo: ConversationRepository;
  public readonly conversationService: ConversationService;

  private readonly hostAuthority: HostMemoryAuthority;
  private readonly startedAtMs: number = Date.now();
  private started: boolean = false;
  private stopped: boolean = false;

  constructor(options: DotsRuntimeOptions = {}) {
    this.config = loadRuntimeConfig(options);
    this.logger =
      options.logger ??
      new OperationalLogger({
        minLevel: this.config.logLevel,
        silent: this.config.silentLogs
      });
    this.eventBus = options.eventBus ?? new RuntimeEventBus();

    this.db = new DatabaseManager(this.config.dbPath);
    this.taskRepo = new TaskRepository(this.db);
    this.auditRepo = new AuditRepository(this.db);
    this.memoryRepo = new MemoryRepository(this.db);
    this.scheduleRepo = new ScheduleRepository(this.db);

    this.identityProvider = new TokenIdentityProvider(this.config.tokens);
    this.hostAuthority = new HostMemoryAuthority({
      hostSecret: this.config.hostSecret,
      taskRepo: this.taskRepo,
      identityProvider: this.identityProvider
    });
    this.authorizer = this.hostAuthority.authorizer;

    this.memoryService = new MemoryService({
      memoryRepo: this.memoryRepo,
      auditRepo: this.auditRepo,
      taskRepo: this.taskRepo,
      authorizer: this.authorizer,
      hostAuthority: this.hostAuthority
    });

    this.toolRegistry = new ToolRegistry();
    for (const tool of standardTools) {
      this.toolRegistry.register(tool);
    }

    this.policyEngine = new PolicyEngine({
      workspaceRoot: this.config.workspaceRoot,
      autoApproveTier2: this.config.autoApproveTier2
    });
    this.approvalBroker = new ApprovalBroker(this.taskRepo, this.auditRepo);
    this.verifier = new VerificationEngine();
    this.budgetTracker = new TokenBudgetTracker({
      db: this.db,
      maxCostPerTaskUsd: this.config.maxTaskBudgetUsd
    });

    this.modelProvider =
      options.modelProvider ??
      (this.config.provider === 'gemini'
        ? new GeminiProvider({
            apiKey: this.config.geminiApiKey,
            modelId: this.config.geminiModelId
          })
        : new MockModelProvider());

    this.agentRegistry = options.agentRegistry ?? new AgentRegistry();

    this.coordinator = new TaskCoordinator({
      taskRepo: this.taskRepo,
      auditRepo: this.auditRepo,
      modelProvider: this.modelProvider,
      toolRegistry: this.toolRegistry,
      policyEngine: this.policyEngine,
      approvalBroker: this.approvalBroker,
      verifier: this.verifier,
      budgetTracker: this.budgetTracker,
      workspaceRoot: this.config.workspaceRoot,
      memoryService: this.memoryService,
      hostAuthority: this.hostAuthority,
      authorizer: this.authorizer,
      enableDynamicReplan: this.config.enableDynamicReplan,
      enableCompensation: this.config.enableCompensation,
      agentRegistry: this.agentRegistry
    });

    this.crashRecovery = new CrashRecoveryEngine(this.taskRepo, this.auditRepo);
    this.scheduler = new TaskScheduler({
      scheduleRepo: this.scheduleRepo,
      taskRepo: this.taskRepo,
      auditRepo: this.auditRepo,
      coordinator: this.coordinator,
      authorizer: this.authorizer,
      hostAuthority: this.hostAuthority,
      logger: this.logger,
      eventBus: this.eventBus,
      pollIntervalMs: this.config.schedulerPollIntervalMs
    });

    this.conversationRepo = new ConversationRepository(this.db);
    this.conversationService = new ConversationService({
      conversationRepo: this.conversationRepo,
      modelProvider: this.modelProvider,
      agentRegistry: this.agentRegistry,
      coordinator: this.coordinator,
      authorizer: this.authorizer,
      hostAuthority: this.hostAuthority,
      maxHistoryMessages: this.config.maxConversationHistory
    });
  }

  // --- Lifecycle ---

  public async start(): Promise<void> {
    if (this.started || this.stopped) {
      return;
    }
    this.started = true;

    const recovery = this.crashRecovery.reconcileInterruptedTasks();
    if (recovery.scannedCount > 0) {
      this.logger.info('runtime', 'boot_crash_recovery', {
        scannedCount: recovery.scannedCount,
        reconciledCount: recovery.reconciledTasks.length
      });
    }

    if (this.config.enableScheduler) {
      await this.scheduler.start();
    }

    this.logger.info('runtime', 'started', {
      provider: this.modelProvider.name,
      schedulerEnabled: this.config.enableScheduler,
      workspaceRoot: this.config.workspaceRoot
    });
  }

  public async stop(): Promise<void> {
    if (this.stopped) {
      return;
    }
    this.stopped = true;
    this.started = false;

    await this.scheduler.stop();
    this.db.close();

    this.logger.info('runtime', 'stopped');
  }

  public getHealth(): Record<string, unknown> {
    return {
      status: this.stopped ? 'stopped' : 'ok',
      uptimeMs: Date.now() - this.startedAtMs,
      schedulerEnabled: this.config.enableScheduler,
      provider: this.modelProvider.name,
      modelId: this.modelProvider.modelId
    };
  }

  // --- Authentication ---

  public authenticateUser(
    credentials: unknown,
    requestedScope?: ScopeIdentifier
  ): AuthenticatedSession {
    const caller = this.authorizer.authorizeUser({ credentials, requestedScope });
    const principal = this.identityProvider.authenticate(credentials);
    if (!principal) {
      throw new SecurityViolationError('Invalid or unverified authentication credentials.', 'UNAUTHENTICATED');
    }
    return { caller, principal };
  }

  // --- Tasks ---

  public async submitTask(
    caller: CallerContext,
    input: { readonly goal: string; readonly metadata?: Record<string, unknown>; readonly run?: boolean }
  ): Promise<PublicTaskView> {
    const verified = this.requirePermission(caller, 'WRITE');
    const task = await this.coordinator.submitScopedTask({
      goal: input.goal,
      caller: verified,
      metadata: input.metadata
    });

    let publicTask = this.toPublicTask(task, verified.scope);
    this.eventBus.emit({
      type: 'task.created',
      scope: verified.scope,
      taskId: task.id,
      data: { task: publicTask }
    });

    if (input.run) {
      publicTask = await this.runTask(verified, task.id);
    }

    return publicTask;
  }

  public async runTask(caller: CallerContext, taskId: string): Promise<PublicTaskView> {
    const verified = this.requirePermission(caller, 'WRITE');
    const { task, scope } = this.loadScopedTask(taskId, verified);

    if (TaskStateMachine.isTerminal(task.status)) {
      return this.toPublicTask(task, scope);
    }

    const updated = await this.coordinator.runToCompletion(task.id);
    const publicTask = this.toPublicTask(updated, scope);

    this.eventBus.emit({
      type: 'task.updated',
      scope,
      taskId: updated.id,
      data: { task: publicTask }
    });

    if (updated.status === 'AWAITING_APPROVAL') {
      const pending = this.taskRepo
        .getApprovalRequestsByTaskId(updated.id)
        .filter((a) => a.decision === 'PENDING')
        .map((a) => this.toPublicApproval(a));
      this.eventBus.emit({
        type: 'approval.requested',
        scope,
        taskId: updated.id,
        data: { approvals: pending }
      });
    }

    return publicTask;
  }

  public cancelTask(caller: CallerContext, taskId: string, reason?: string): PublicTaskView {
    const verified = this.requirePermission(caller, 'WRITE');
    const { task, scope } = this.loadScopedTask(taskId, verified);

    if (task.status === 'CANCELLED') {
      return this.toPublicTask(task, scope);
    }

    const safeReason = reason ? defaultSecretScrubber.scrub(reason) : 'Cancelled by user.';
    const updated = this.taskRepo.updateTaskStatus(task.id, task.status, 'CANCELLED', safeReason);
    this.auditRepo.appendEvent({
      taskId: task.id,
      eventType: 'STATE_TRANSITION',
      actor: 'USER',
      details: { from: task.status, to: 'CANCELLED', reason: safeReason }
    });

    const publicTask = this.toPublicTask(updated, scope);
    this.eventBus.emit({
      type: 'task.updated',
      scope,
      taskId: updated.id,
      data: { task: publicTask }
    });

    return publicTask;
  }

  public listTasks(
    caller: CallerContext,
    filter: { readonly status?: TaskStatus; readonly limit?: number; readonly offset?: number } = {}
  ): PublicTaskView[] {
    const verified = this.requirePermission(caller, 'READ');
    const limit = Math.min(200, Math.max(1, filter.limit ?? 50));
    const offset = Math.max(0, filter.offset ?? 0);

    const matched: PublicTaskView[] = [];
    const batchSize = 200;
    let scanOffset = 0;

    while (matched.length < offset + limit) {
      const rows = this.taskRepo.listTasks({
        status: filter.status,
        limit: batchSize,
        offset: scanOffset
      });
      if (rows.length === 0) {
        break;
      }
      for (const task of rows) {
        if (task.id === SYSTEM_SCHEDULER_TASK_ID) {
          continue;
        }
        const taskScope = this.tryVerifyTaskScope(task);
        if (
          taskScope &&
          taskScope.scopeType === verified.scope.scopeType &&
          taskScope.scopeId === verified.scope.scopeId
        ) {
          matched.push(this.toPublicTask(task, taskScope));
        }
      }
      if (rows.length < batchSize) {
        break;
      }
      scanOffset += batchSize;
    }

    return matched.slice(offset, offset + limit);
  }

  public getTaskDetails(caller: CallerContext, taskId: string): TaskDetailsView {
    const verified = this.requirePermission(caller, 'READ');
    const { task, scope } = this.loadScopedTask(taskId, verified);

    const steps = this.taskRepo.getStepsByTaskId(task.id).map((s) => this.toPublicStep(s));
    const approvals = this.taskRepo
      .getApprovalRequestsByTaskId(task.id)
      .map((a) => this.toPublicApproval(a));
    const auditEvents = this.auditRepo
      .getEventsByTaskId(task.id)
      .map((e) => this.toPublicAuditEvent(e));
    const usage = this.budgetTracker.getUsageForTask(task.id);

    return {
      task: this.toPublicTask(task, scope),
      steps,
      approvals,
      auditEvents,
      usage
    };
  }

  // --- Approvals ---

  public listApprovals(
    caller: CallerContext,
    filter: { readonly decision?: ApprovalDecision; readonly limit?: number } = {}
  ): PublicApprovalView[] {
    const verified = this.requirePermission(caller, 'READ');
    const limit = Math.min(200, Math.max(1, filter.limit ?? 100));
    const raw = this.taskRepo.listApprovalRequests({
      decision: filter.decision,
      limit: 500
    });

    const out: PublicApprovalView[] = [];
    for (const req of raw) {
      const task = this.taskRepo.getTaskById(req.taskId);
      if (!task) {
        continue;
      }
      const taskScope = this.tryVerifyTaskScope(task);
      if (
        taskScope &&
        taskScope.scopeType === verified.scope.scopeType &&
        taskScope.scopeId === verified.scope.scopeId
      ) {
        out.push(this.toPublicApproval(req));
        if (out.length >= limit) {
          break;
        }
      }
    }
    return out;
  }

  public async decideApproval(
    caller: CallerContext,
    principal: AuthenticatedPrincipal,
    approvalIdOrToken: string,
    decision: 'APPROVED' | 'REJECTED',
    options: { readonly resume?: boolean } = {}
  ): Promise<{ readonly approval: PublicApprovalView; readonly task: PublicTaskView }> {
    const verified = this.requirePermission(caller, 'APPROVE');

    if (decision !== 'APPROVED' && decision !== 'REJECTED') {
      throw new ValidationError("Approval decision must be 'APPROVED' or 'REJECTED'.");
    }

    const existing =
      this.taskRepo.getApprovalRequestById(approvalIdOrToken) ??
      this.taskRepo.getApprovalRequestByToken(approvalIdOrToken);
    if (!existing) {
      throw new ValidationError(`Approval request '${approvalIdOrToken}' was not found.`);
    }

    const { task, scope } = this.loadScopedTask(existing.taskId, verified);
    const updatedApproval = this.approvalBroker.submitDecision(
      existing.approvalToken,
      decision,
      principal.principalId
    );
    const publicApproval = this.toPublicApproval(updatedApproval);

    this.eventBus.emit({
      type: 'approval.decided',
      scope,
      taskId: task.id,
      data: { approval: publicApproval }
    });

    const shouldResume = options.resume ?? true;
    const updatedTask = shouldResume
      ? await this.runTask(verified, task.id)
      : this.toPublicTask(this.taskRepo.getTaskById(task.id)!, scope);

    return {
      approval: publicApproval,
      task: updatedTask
    };
  }

  // --- Schedules ---

  public createSchedule(caller: CallerContext, input: CreateScheduleInput): Schedule {
    return this.scheduler.createSchedule(caller, input);
  }

  public listSchedules(caller: CallerContext, filter: ListSchedulesFilter = {}): Schedule[] {
    return this.scheduler.listSchedules(caller, filter);
  }

  public getSchedule(caller: CallerContext, scheduleId: string): Schedule {
    return this.scheduler.getSchedule(caller, scheduleId);
  }

  public listScheduleOccurrences(
    caller: CallerContext,
    scheduleId: string,
    limit: number = 50,
    offset: number = 0
  ): ScheduleOccurrence[] {
    return this.scheduler.listOccurrences(caller, scheduleId, limit, offset);
  }

  public pauseSchedule(caller: CallerContext, scheduleId: string, reason?: string): Schedule {
    return this.scheduler.pauseSchedule(caller, scheduleId, reason);
  }

  public resumeSchedule(caller: CallerContext, scheduleId: string): Schedule {
    return this.scheduler.resumeSchedule(caller, scheduleId);
  }

  public cancelSchedule(caller: CallerContext, scheduleId: string): Schedule {
    return this.scheduler.cancelSchedule(caller, scheduleId);
  }

  // --- Conversations ---

  public createConversation(caller: CallerContext, input: CreateConversationInput): Conversation {
    return this.conversationService.createConversation(caller, input);
  }

  public getConversation(caller: CallerContext, conversationId: string): Conversation {
    return this.conversationService.getConversation(caller, conversationId);
  }

  public listConversations(
    caller: CallerContext,
    filter: ListConversationsFilter = {}
  ): { conversations: Conversation[]; total: number } {
    return this.conversationService.listConversations(caller, filter);
  }

  public updateConversation(
    caller: CallerContext,
    conversationId: string,
    input: UpdateConversationInput
  ): Conversation {
    return this.conversationService.updateConversation(caller, conversationId, input);
  }

  public archiveConversation(caller: CallerContext, conversationId: string): Conversation {
    return this.conversationService.archiveConversation(caller, conversationId);
  }

  public deleteConversation(caller: CallerContext, conversationId: string): boolean {
    return this.conversationService.deleteConversation(caller, conversationId);
  }

  public getConversationMessages(
    caller: CallerContext,
    conversationId: string,
    filter: ListMessagesFilter = {}
  ): { messages: ConversationMessage[]; total: number } {
    return this.conversationService.getMessages(caller, conversationId, filter);
  }

  public async sendConversationMessage(
    caller: CallerContext,
    conversationId: string,
    input: SendConversationMessageInput
  ): Promise<ConversationResponse> {
    return await this.conversationService.sendMessage(caller, conversationId, input);
  }

  // --- Internal Helpers ---

  private requirePermission(
    caller: CallerContext,
    permission: 'READ' | 'WRITE' | 'DELETE' | 'APPROVE'
  ): CallerContext {
    const verified = this.authorizer.verify(caller);
    const perms =
      verified.permissions instanceof Set ? verified.permissions : new Set(verified.permissions);

    if (!perms.has(permission)) {
      throw new SecurityViolationError(
        `Caller '${verified.actor}' lacks '${permission}' permission.`,
        'PERMISSION_DENIED'
      );
    }
    return verified;
  }

  private tryVerifyTaskScope(task: Task): ScopeIdentifier | null {
    try {
      return this.coordinator.verifyTaskScope(task);
    } catch {
      return null;
    }
  }

  private loadScopedTask(
    taskId: string,
    verifiedCaller: CallerContext
  ): { readonly task: Task; readonly scope: ScopeIdentifier } {
    if (!taskId || taskId === SYSTEM_SCHEDULER_TASK_ID) {
      throw new TaskNotFoundError(taskId || '');
    }

    const task = this.taskRepo.getTaskById(taskId);
    if (!task) {
      throw new TaskNotFoundError(taskId);
    }

    const taskScope = this.tryVerifyTaskScope(task);
    if (
      !taskScope ||
      taskScope.scopeType !== verifiedCaller.scope.scopeType ||
      taskScope.scopeId !== verifiedCaller.scope.scopeId
    ) {
      throw new SecurityViolationError(
        `Task '${taskId}' is not accessible within caller scope '${verifiedCaller.scope.scopeType}:${verifiedCaller.scope.scopeId}'.`,
        'TASK_CALLER_SCOPE_MISMATCH'
      );
    }

    return { task, scope: taskScope };
  }

  private toPublicTask(task: Task, scope: ScopeIdentifier): PublicTaskView {
    const rawMeta = safeJsonParse(task.metadataJson);
    const safeMeta = scrubPublicData(rawMeta) as Record<string, unknown>;
    return {
      id: task.id,
      goal: defaultSecretScrubber.scrub(task.goal),
      status: task.status,
      currentStepIndex: task.currentStepIndex,
      scope,
      metadata: safeMeta,
      createdAt: task.createdAt,
      updatedAt: task.updatedAt,
      completedAt: task.completedAt,
      errorSummary: task.errorSummary ? defaultSecretScrubber.scrub(task.errorSummary) : null
    };
  }

  private toPublicApproval(req: ApprovalRequest): PublicApprovalView {
    return {
      id: req.id,
      taskId: req.taskId,
      stepId: req.stepId,
      riskTier: req.riskTier,
      actionSummary: defaultSecretScrubber.scrub(req.actionSummary),
      targetResource: defaultSecretScrubber.scrub(req.targetResource),
      parameterDiff: scrubPublicData(safeJsonParse(req.parameterDiffJson)) as Record<string, unknown>,
      decision: req.decision,
      decidedBy: req.decidedBy,
      decidedAt: req.decidedAt,
      expiresAt: req.expiresAt,
      createdAt: req.createdAt
    };
  }

  private toPublicStep(step: TaskStep): Record<string, unknown> {
    return {
      id: step.id,
      taskId: step.taskId,
      stepOrder: step.stepOrder,
      description: defaultSecretScrubber.scrub(step.description),
      toolName: step.toolName,
      toolArguments: scrubPublicData(safeJsonParse(step.toolArgumentsJson)),
      status: step.status,
      retryCount: step.retryCount,
      maxRetries: step.maxRetries,
      createdAt: step.createdAt,
      completedAt: step.completedAt
    };
  }

  private toPublicAuditEvent(event: AuditEvent): Record<string, unknown> {
    return {
      id: event.id,
      taskId: event.taskId,
      eventType: event.eventType,
      actor: event.actor,
      details: scrubPublicData(safeJsonParse(event.detailsJson)),
      payloadHash: event.payloadHash,
      timestamp: event.timestamp
    };
  }
}
