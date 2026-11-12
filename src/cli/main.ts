#!/usr/bin/env node
/**
 * Next-Generation Dots AI Platform - CLI Entrypoint (Phase 8A)
 *
 * Architectural Mandate:
 * Provides an ergonomic, local-first terminal interface for task execution,
 * status inspection, human-in-the-loop approvals, memory governance,
 * persistent schedules, and launching the HTTP REST/SSE server.
 */

import { readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import type {
  ApprovalDecision,
  CreateScheduleInput,
  ImportConflictStrategy,
  MemoryCategory,
  MemoryExportBundle,
  MemoryStatus,
  MissedRunPolicy,
  ScheduleStatus,
  ScopeIdentifier,
  TaskStatus
} from '../domain/types.ts';
import { ValidationError } from '../domain/errors.ts';
import { defaultSecretScrubber } from '../model/secret-scrubber.ts';
import { parseScopeSpec } from '../runtime/config.ts';
import { DotsRuntime, scrubPublicData, type DotsRuntimeOptions } from '../runtime/app.ts';
import { DotsHttpServer } from '../api/http-server.ts';

export interface CliIo {
  readonly stdout: (text: string) => void;
  readonly stderr: (text: string) => void;
}

interface ParsedArgs {
  readonly positionals: string[];
  readonly flags: Map<string, string | boolean>;
}

const BOOLEAN_FLAGS: ReadonlySet<string> = new Set([
  'json',
  'help',
  'no-wait',
  'no-resume',
  'reject',
  'include-archived',
  'dry-run'
]);

function parseArgv(argv: readonly string[]): ParsedArgs {
  const positionals: string[] = [];
  const flags = new Map<string, string | boolean>();

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;
    if (arg === '--') {
      positionals.push(...argv.slice(i + 1));
      break;
    }
    if (arg.startsWith('--')) {
      const eqIdx = arg.indexOf('=');
      if (eqIdx !== -1) {
        flags.set(arg.slice(2, eqIdx), arg.slice(eqIdx + 1));
      } else {
        const key = arg.slice(2);
        if (BOOLEAN_FLAGS.has(key)) {
          flags.set(key, true);
        } else {
          const next = argv[i + 1];
          if (next !== undefined && !next.startsWith('--')) {
            flags.set(key, next);
            i++;
          } else {
            flags.set(key, true);
          }
        }
      }
    } else if (arg === '-h') {
      flags.set('help', true);
    } else {
      positionals.push(arg);
    }
  }

  return { positionals, flags };
}

function getStringFlag(flags: Map<string, string | boolean>, key: string): string | undefined {
  const val = flags.get(key);
  return typeof val === 'string' ? val : undefined;
}

function getIntFlag(flags: Map<string, string | boolean>, key: string): number | undefined {
  const raw = getStringFlag(flags, key);
  if (raw === undefined) {
    return undefined;
  }
  const n = Number(raw);
  if (!Number.isInteger(n) || n < 0) {
    throw new ValidationError(`Flag '--${key}' must be a non-negative integer.`);
  }
  return n;
}

function requireArg(val: string | undefined, label: string): string {
  if (!val || val.trim() === '') {
    throw new ValidationError(`Missing required argument: ${label}.`);
  }
  return val;
}

function renderHelp(): string {
  return [
    'Dots AI Platform CLI',
    '',
    'Usage:',
    '  dots <command> [options]',
    '',
    'Global Options:',
    '  --token <token>         API bearer token (or DOTS_API_TOKEN env)',
    '  --scope <scope>         Scope (GLOBAL:default or WORKSPACE:<id>)',
    '  --server <url>          Remote Dots HTTP server URL (or DOTS_SERVER_URL env)',
    '  --db <path>             SQLite database path (local mode, or DOTS_DB_PATH)',
    '  --workspace <path>      Sandboxed workspace root (local mode)',
    '  --json                  Print scrubbed JSON output',
    '  --help, -h              Show this help message',
    '',
    'Commands:',
    '  serve [--host <host>] [--port <port>]',
    '  run <goal> [--no-wait]',
    '  status [taskId] [--status <status>] [--limit <n>]',
    '  cancel <taskId> [--reason <text>]',
    '  approvals [--decision <PENDING|APPROVED|REJECTED|EXPIRED>] [--limit <n>]',
    '  approve <approvalId> [--reject] [--no-resume]',
    '  memory list [--category <cat>] [--status <status>] [--limit <n>]',
    '  memory get <id>',
    '  memory create --category <cat> --key <key> --content <text> [--tags a,b] [--priority <n>]',
    '  memory update <id> [--content <text>] [--category <cat>] [--tags a,b] [--priority <n>]',
    '  memory archive <id>',
    '  memory delete <id>',
    '  memory approve <id> [--reason <text>]',
    '  memory reject <id> [--reason <text>]',
    '  memory export [--category <cat>] [--include-archived] [--out <file>]',
    '  memory import <file> [--strategy <FAIL|SKIP|OVERWRITE>]',
    '  memory purge [--ids a,b | --older-than <iso>] [--dry-run] [--max-batch <n>]',
    '  schedule create --name <name> --goal <goal> (--run-at <iso> | --interval-ms <ms>) [--start-at <iso>] [--missed <SKIP|RUN_ONCE>]',
    '  schedule list [--status <ACTIVE|PAUSED|COMPLETED|CANCELLED>]',
    '  schedule get <id>',
    '  schedule occurrences <id> [--limit <n>]',
    '  schedule pause <id> [--reason <text>]',
    '  schedule resume <id>',
    '  schedule cancel <id>'
  ].join('\n');
}

async function callHttpApi(
  baseUrl: string,
  method: string,
  path: string,
  token: string,
  scopeSpec: string | undefined,
  body?: unknown
): Promise<unknown> {
  const url = `${baseUrl.replace(/\/+$/, '')}${path}`;
  const headers: Record<string, string> = {
    Authorization: `Bearer ${token}`
  };
  if (scopeSpec) {
    headers['X-Dots-Scope'] = scopeSpec;
  }
  if (body !== undefined) {
    headers['Content-Type'] = 'application/json';
  }

  const resp = await fetch(url, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined
  });

  const text = await resp.text();
  let parsed: unknown = {};
  if (text.trim() !== '') {
    try {
      parsed = JSON.parse(text);
    } catch {
      parsed = { raw: defaultSecretScrubber.scrub(text) };
    }
  }

  if (!resp.ok) {
    const errObj = (parsed as { error?: { message?: string; code?: string } })?.error;
    const msg = errObj?.message ?? `HTTP ${resp.status} ${resp.statusText}`;
    throw new Error(defaultSecretScrubber.scrub(msg));
  }

  return parsed;
}

export async function runCli(
  argv: readonly string[],
  io: CliIo = {
    stdout: (text) => process.stdout.write(`${text}\n`),
    stderr: (text) => process.stderr.write(`${text}\n`)
  },
  runtimeOverrides: DotsRuntimeOptions = {}
): Promise<number> {
  const { positionals, flags } = parseArgv(argv);
  const cmd = positionals[0];

  if (!cmd || cmd === 'help' || flags.get('help') === true) {
    io.stdout(renderHelp());
    return 0;
  }

  const asJson = flags.get('json') === true;
  const printResult = (data: unknown) => {
    const safe = scrubPublicData(data);
    io.stdout(JSON.stringify(safe, null, asJson ? 0 : 2));
  };

  try {
    if (cmd === 'serve') {
      const host = getStringFlag(flags, 'host');
      const port = getIntFlag(flags, 'port');
      const runtime = new DotsRuntime({
        ...runtimeOverrides,
        dbPath: getStringFlag(flags, 'db') ?? runtimeOverrides.dbPath,
        workspaceRoot: getStringFlag(flags, 'workspace') ?? runtimeOverrides.workspaceRoot,
        host: host ?? runtimeOverrides.host,
        port: port ?? runtimeOverrides.port
      });
      const server = new DotsHttpServer(runtime);
      const started = await server.start();
      io.stdout(`Dots server listening on ${started.url}`);

      await new Promise<void>((resolve) => {
        const shutdown = async () => {
          process.off('SIGINT', onSignal);
          process.off('SIGTERM', onSignal);
          await server.stop();
          resolve();
        };
        const onSignal = () => {
          void shutdown();
        };
        process.on('SIGINT', onSignal);
        process.on('SIGTERM', onSignal);
      });
      return 0;
    }

    const token = getStringFlag(flags, 'token') ?? process.env.DOTS_API_TOKEN;
    if (!token || token.trim() === '') {
      throw new ValidationError('Authentication token is required. Pass --token <token> or set DOTS_API_TOKEN.');
    }

    const scopeSpec = getStringFlag(flags, 'scope');
    const requestedScope: ScopeIdentifier | undefined = scopeSpec ? parseScopeSpec(scopeSpec) : undefined;
    const serverUrl = getStringFlag(flags, 'server') ?? process.env.DOTS_SERVER_URL;

    if (serverUrl && serverUrl.trim() !== '') {
      const result = await executeRemoteCommand(cmd, positionals, flags, serverUrl, token, scopeSpec);
      if (cmd === 'memory' && positionals[1] === 'export' && getStringFlag(flags, 'out')) {
        const outPath = getStringFlag(flags, 'out')!;
        const bundle = (result as { bundle: unknown }).bundle;
        writeFileSync(outPath, `${JSON.stringify(bundle, null, 2)}\n`, 'utf8');
        io.stdout(`Exported memory bundle to ${outPath}`);
      } else {
        printResult(result);
      }
      return 0;
    }

    // Local direct runtime mode (scheduler loop disabled for one-shot CLI commands)
    const runtime = new DotsRuntime({
      enableScheduler: false,
      silentLogs: true,
      ...runtimeOverrides,
      dbPath: getStringFlag(flags, 'db') ?? runtimeOverrides.dbPath,
      workspaceRoot: getStringFlag(flags, 'workspace') ?? runtimeOverrides.workspaceRoot
    });

    await runtime.start();
    try {
      const session = runtime.authenticateUser(token, requestedScope);
      const result = await executeLocalCommand(runtime, session, cmd, positionals, flags);
      if (cmd === 'memory' && positionals[1] === 'export' && getStringFlag(flags, 'out')) {
        const outPath = getStringFlag(flags, 'out')!;
        const bundle = (result as { bundle: unknown }).bundle;
        writeFileSync(outPath, `${JSON.stringify(bundle, null, 2)}\n`, 'utf8');
        io.stdout(`Exported memory bundle to ${outPath}`);
      } else {
        printResult(result);
      }
      return 0;
    } finally {
      await runtime.stop();
    }
  } catch (err) {
    const msg = defaultSecretScrubber.scrub(err instanceof Error ? err.message : String(err));
    io.stderr(`Error: ${msg}`);
    return 1;
  }
}

async function executeLocalCommand(
  runtime: DotsRuntime,
  session: ReturnType<DotsRuntime['authenticateUser']>,
  cmd: string,
  positionals: readonly string[],
  flags: Map<string, string | boolean>
): Promise<unknown> {
  const { caller, principal } = session;

  if (cmd === 'run') {
    const goal = requireArg(positionals.slice(1).join(' ').trim() || undefined, 'goal');
    const wait = flags.get('no-wait') !== true;
    const task = await runtime.submitTask(caller, { goal, run: wait });
    return { task };
  }

  if (cmd === 'status') {
    const taskId = positionals[1];
    if (taskId) {
      return runtime.getTaskDetails(caller, taskId);
    }
    const status = getStringFlag(flags, 'status') as TaskStatus | undefined;
    const limit = getIntFlag(flags, 'limit');
    const tasks = runtime.listTasks(caller, { status, limit });
    return { tasks };
  }

  if (cmd === 'cancel') {
    const taskId = requireArg(positionals[1], 'taskId');
    const reason = getStringFlag(flags, 'reason');
    return { task: runtime.cancelTask(caller, taskId, reason) };
  }

  if (cmd === 'approvals') {
    const decision = getStringFlag(flags, 'decision') as ApprovalDecision | undefined;
    const limit = getIntFlag(flags, 'limit');
    return { approvals: runtime.listApprovals(caller, { decision, limit }) };
  }

  if (cmd === 'approve') {
    const approvalId = requireArg(positionals[1], 'approvalId');
    const decision = flags.get('reject') === true ? 'REJECTED' : 'APPROVED';
    const resume = flags.get('no-resume') !== true;
    return await runtime.decideApproval(caller, principal, approvalId, decision, { resume });
  }

  if (cmd === 'memory') {
    const sub = requireArg(positionals[1], 'memory subcommand');
    if (sub === 'list') {
      const category = getStringFlag(flags, 'category') as MemoryCategory | undefined;
      const status = getStringFlag(flags, 'status') as MemoryStatus | undefined;
      const limit = getIntFlag(flags, 'limit');
      return { memories: runtime.memoryService.listMemories(caller, { category, status, limit }) };
    }
    if (sub === 'get') {
      const id = requireArg(positionals[2], 'memoryId');
      return { memory: runtime.memoryService.getMemoryById(caller, id) };
    }
    if (sub === 'create') {
      const category = requireArg(getStringFlag(flags, 'category'), '--category') as MemoryCategory;
      const key = requireArg(getStringFlag(flags, 'key'), '--key');
      const content = requireArg(getStringFlag(flags, 'content'), '--content');
      const tagsRaw = getStringFlag(flags, 'tags');
      const priority = getIntFlag(flags, 'priority');
      return {
        memory: runtime.memoryService.createMemory(caller, {
          category,
          key,
          content,
          tags: tagsRaw ? tagsRaw.split(',').map((t) => t.trim()).filter(Boolean) : undefined,
          priority,
          scopeType: caller.scope.scopeType,
          scopeId: caller.scope.scopeId
        })
      };
    }
    if (sub === 'update') {
      const id = requireArg(positionals[2], 'memoryId');
      const content = getStringFlag(flags, 'content');
      const category = getStringFlag(flags, 'category') as MemoryCategory | undefined;
      const tagsRaw = getStringFlag(flags, 'tags');
      const priority = getIntFlag(flags, 'priority');
      return {
        memory: runtime.memoryService.updateMemory(caller, id, {
          ...(content !== undefined ? { content } : {}),
          ...(category !== undefined ? { category } : {}),
          ...(tagsRaw !== undefined ? { tags: tagsRaw.split(',').map((t) => t.trim()).filter(Boolean) } : {}),
          ...(priority !== undefined ? { priority } : {})
        })
      };
    }
    if (sub === 'archive') {
      const id = requireArg(positionals[2], 'memoryId');
      return { memory: runtime.memoryService.archiveMemory(caller, id) };
    }
    if (sub === 'delete') {
      const id = requireArg(positionals[2], 'memoryId');
      return { deleted: runtime.memoryService.deleteMemory(caller, id) };
    }
    if (sub === 'approve' || sub === 'reject') {
      const id = requireArg(positionals[2], 'memoryId');
      const reason = getStringFlag(flags, 'reason');
      return {
        memory: runtime.memoryService.decideProposal(caller, {
          memoryId: id,
          decision: sub === 'approve' ? 'APPROVED' : 'REJECTED',
          reason
        })
      };
    }
    if (sub === 'export') {
      const category = getStringFlag(flags, 'category') as MemoryCategory | undefined;
      const includeArchived = flags.get('include-archived') === true;
      return {
        bundle: runtime.memoryService.exportMemories(caller, { category, includeArchived })
      };
    }
    if (sub === 'import') {
      const file = requireArg(positionals[2], 'bundle file');
      const raw = readFileSync(file, 'utf8');
      const parsed = JSON.parse(raw) as { bundle?: MemoryExportBundle } | MemoryExportBundle;
      const bundle = ('bundle' in parsed && parsed.bundle ? parsed.bundle : parsed) as MemoryExportBundle;
      const conflictStrategy = getStringFlag(flags, 'strategy') as ImportConflictStrategy | undefined;
      return { result: runtime.memoryService.importMemories(caller, bundle, { conflictStrategy }) };
    }
    if (sub === 'purge') {
      const idsRaw = getStringFlag(flags, 'ids');
      const olderThan = getStringFlag(flags, 'older-than');
      const dryRun = flags.get('dry-run') === true;
      const maxBatchSize = getIntFlag(flags, 'max-batch');
      return {
        result: runtime.memoryService.purgeArchivedMemories(caller, {
          memoryIds: idsRaw ? idsRaw.split(',').map((s) => s.trim()).filter(Boolean) : undefined,
          olderThan,
          dryRun,
          maxBatchSize
        })
      };
    }
    throw new ValidationError(`Unknown memory subcommand '${sub}'.`);
  }

  if (cmd === 'schedule') {
    const sub = requireArg(positionals[1], 'schedule subcommand');
    if (sub === 'create') {
      const name = requireArg(getStringFlag(flags, 'name'), '--name');
      const goal = requireArg(getStringFlag(flags, 'goal'), '--goal');
      const runAt = getStringFlag(flags, 'run-at');
      const intervalMs = getIntFlag(flags, 'interval-ms');
      const startAt = getStringFlag(flags, 'start-at');
      const missedRunPolicy = getStringFlag(flags, 'missed') as MissedRunPolicy | undefined;
      const input: CreateScheduleInput = {
        name,
        goal,
        scheduleType: intervalMs !== undefined ? 'INTERVAL' : 'ONE_TIME',
        ...(runAt !== undefined ? { runAt } : {}),
        ...(intervalMs !== undefined ? { intervalMs } : {}),
        ...(startAt !== undefined ? { startAt } : {}),
        ...(missedRunPolicy !== undefined ? { missedRunPolicy } : {})
      };
      return { schedule: runtime.createSchedule(caller, input) };
    }
    if (sub === 'list') {
      const status = getStringFlag(flags, 'status') as ScheduleStatus | undefined;
      const limit = getIntFlag(flags, 'limit');
      return { schedules: runtime.listSchedules(caller, { status, limit }) };
    }
    if (sub === 'get') {
      const id = requireArg(positionals[2], 'scheduleId');
      return { schedule: runtime.getSchedule(caller, id) };
    }
    if (sub === 'occurrences') {
      const id = requireArg(positionals[2], 'scheduleId');
      const limit = getIntFlag(flags, 'limit') ?? 50;
      return { occurrences: runtime.listScheduleOccurrences(caller, id, limit, 0) };
    }
    if (sub === 'pause') {
      const id = requireArg(positionals[2], 'scheduleId');
      const reason = getStringFlag(flags, 'reason');
      return { schedule: runtime.pauseSchedule(caller, id, reason) };
    }
    if (sub === 'resume') {
      const id = requireArg(positionals[2], 'scheduleId');
      return { schedule: runtime.resumeSchedule(caller, id) };
    }
    if (sub === 'cancel') {
      const id = requireArg(positionals[2], 'scheduleId');
      return { schedule: runtime.cancelSchedule(caller, id) };
    }
    throw new ValidationError(`Unknown schedule subcommand '${sub}'.`);
  }

  throw new ValidationError(`Unknown command '${cmd}'. Run 'dots --help' for usage.`);
}

async function executeRemoteCommand(
  cmd: string,
  positionals: readonly string[],
  flags: Map<string, string | boolean>,
  serverUrl: string,
  token: string,
  scopeSpec: string | undefined
): Promise<unknown> {
  if (cmd === 'run') {
    const goal = requireArg(positionals.slice(1).join(' ').trim() || undefined, 'goal');
    const run = flags.get('no-wait') !== true;
    return await callHttpApi(serverUrl, 'POST', '/api/tasks', token, scopeSpec, { goal, run });
  }

  if (cmd === 'status') {
    const taskId = positionals[1];
    if (taskId) {
      return await callHttpApi(serverUrl, 'GET', `/api/tasks/${encodeURIComponent(taskId)}`, token, scopeSpec);
    }
    const qs = new URLSearchParams();
    const status = getStringFlag(flags, 'status');
    const limit = getIntFlag(flags, 'limit');
    if (status) qs.set('status', status);
    if (limit !== undefined) qs.set('limit', String(limit));
    const suffix = qs.toString() ? `?${qs.toString()}` : '';
    return await callHttpApi(serverUrl, 'GET', `/api/tasks${suffix}`, token, scopeSpec);
  }

  if (cmd === 'cancel') {
    const taskId = requireArg(positionals[1], 'taskId');
    const reason = getStringFlag(flags, 'reason');
    return await callHttpApi(
      serverUrl,
      'POST',
      `/api/tasks/${encodeURIComponent(taskId)}/cancel`,
      token,
      scopeSpec,
      reason ? { reason } : {}
    );
  }

  if (cmd === 'approvals') {
    const qs = new URLSearchParams();
    const decision = getStringFlag(flags, 'decision');
    const limit = getIntFlag(flags, 'limit');
    if (decision) qs.set('decision', decision);
    if (limit !== undefined) qs.set('limit', String(limit));
    const suffix = qs.toString() ? `?${qs.toString()}` : '';
    return await callHttpApi(serverUrl, 'GET', `/api/approvals${suffix}`, token, scopeSpec);
  }

  if (cmd === 'approve') {
    const approvalId = requireArg(positionals[1], 'approvalId');
    const decision = flags.get('reject') === true ? 'REJECTED' : 'APPROVED';
    const resume = flags.get('no-resume') !== true;
    return await callHttpApi(
      serverUrl,
      'POST',
      `/api/approvals/${encodeURIComponent(approvalId)}/decide`,
      token,
      scopeSpec,
      { decision, resume }
    );
  }

  if (cmd === 'memory') {
    const sub = requireArg(positionals[1], 'memory subcommand');
    if (sub === 'list') {
      const qs = new URLSearchParams();
      const category = getStringFlag(flags, 'category');
      const status = getStringFlag(flags, 'status');
      const limit = getIntFlag(flags, 'limit');
      if (category) qs.set('category', category);
      if (status) qs.set('status', status);
      if (limit !== undefined) qs.set('limit', String(limit));
      const suffix = qs.toString() ? `?${qs.toString()}` : '';
      return await callHttpApi(serverUrl, 'GET', `/api/memories${suffix}`, token, scopeSpec);
    }
    if (sub === 'get') {
      const id = requireArg(positionals[2], 'memoryId');
      return await callHttpApi(serverUrl, 'GET', `/api/memories/${encodeURIComponent(id)}`, token, scopeSpec);
    }
    if (sub === 'create') {
      const category = requireArg(getStringFlag(flags, 'category'), '--category');
      const key = requireArg(getStringFlag(flags, 'key'), '--key');
      const content = requireArg(getStringFlag(flags, 'content'), '--content');
      const tagsRaw = getStringFlag(flags, 'tags');
      const priority = getIntFlag(flags, 'priority');
      return await callHttpApi(serverUrl, 'POST', '/api/memories', token, scopeSpec, {
        category,
        key,
        content,
        ...(tagsRaw ? { tags: tagsRaw.split(',').map((t) => t.trim()).filter(Boolean) } : {}),
        ...(priority !== undefined ? { priority } : {})
      });
    }
    if (sub === 'update') {
      const id = requireArg(positionals[2], 'memoryId');
      const content = getStringFlag(flags, 'content');
      const category = getStringFlag(flags, 'category');
      const tagsRaw = getStringFlag(flags, 'tags');
      const priority = getIntFlag(flags, 'priority');
      return await callHttpApi(serverUrl, 'PATCH', `/api/memories/${encodeURIComponent(id)}`, token, scopeSpec, {
        ...(content !== undefined ? { content } : {}),
        ...(category !== undefined ? { category } : {}),
        ...(tagsRaw !== undefined ? { tags: tagsRaw.split(',').map((t) => t.trim()).filter(Boolean) } : {}),
        ...(priority !== undefined ? { priority } : {})
      });
    }
    if (sub === 'archive') {
      const id = requireArg(positionals[2], 'memoryId');
      return await callHttpApi(serverUrl, 'POST', `/api/memories/${encodeURIComponent(id)}/archive`, token, scopeSpec, {});
    }
    if (sub === 'delete') {
      const id = requireArg(positionals[2], 'memoryId');
      return await callHttpApi(serverUrl, 'DELETE', `/api/memories/${encodeURIComponent(id)}`, token, scopeSpec);
    }
    if (sub === 'approve' || sub === 'reject') {
      const id = requireArg(positionals[2], 'memoryId');
      const reason = getStringFlag(flags, 'reason');
      return await callHttpApi(serverUrl, 'POST', `/api/memories/${encodeURIComponent(id)}/decide`, token, scopeSpec, {
        decision: sub === 'approve' ? 'APPROVED' : 'REJECTED',
        ...(reason ? { reason } : {})
      });
    }
    if (sub === 'export') {
      const qs = new URLSearchParams();
      const category = getStringFlag(flags, 'category');
      if (category) qs.set('category', category);
      if (flags.get('include-archived') === true) qs.set('includeArchived', 'true');
      const suffix = qs.toString() ? `?${qs.toString()}` : '';
      return await callHttpApi(serverUrl, 'GET', `/api/memories/export${suffix}`, token, scopeSpec);
    }
    if (sub === 'import') {
      const file = requireArg(positionals[2], 'bundle file');
      const raw = readFileSync(file, 'utf8');
      const parsed = JSON.parse(raw) as { bundle?: MemoryExportBundle } | MemoryExportBundle;
      const bundle = 'bundle' in parsed && parsed.bundle ? parsed.bundle : parsed;
      const conflictStrategy = getStringFlag(flags, 'strategy');
      return await callHttpApi(serverUrl, 'POST', '/api/memories/import', token, scopeSpec, {
        bundle,
        ...(conflictStrategy ? { conflictStrategy } : {})
      });
    }
    if (sub === 'purge') {
      const idsRaw = getStringFlag(flags, 'ids');
      const olderThan = getStringFlag(flags, 'older-than');
      const dryRun = flags.get('dry-run') === true;
      const maxBatchSize = getIntFlag(flags, 'max-batch');
      return await callHttpApi(serverUrl, 'POST', '/api/memories/purge', token, scopeSpec, {
        ...(idsRaw ? { memoryIds: idsRaw.split(',').map((s) => s.trim()).filter(Boolean) } : {}),
        ...(olderThan ? { olderThan } : {}),
        dryRun,
        ...(maxBatchSize !== undefined ? { maxBatchSize } : {})
      });
    }
    throw new ValidationError(`Unknown memory subcommand '${sub}'.`);
  }

  if (cmd === 'schedule') {
    const sub = requireArg(positionals[1], 'schedule subcommand');
    if (sub === 'create') {
      const name = requireArg(getStringFlag(flags, 'name'), '--name');
      const goal = requireArg(getStringFlag(flags, 'goal'), '--goal');
      const runAt = getStringFlag(flags, 'run-at');
      const intervalMs = getIntFlag(flags, 'interval-ms');
      const startAt = getStringFlag(flags, 'start-at');
      const missedRunPolicy = getStringFlag(flags, 'missed');
      return await callHttpApi(serverUrl, 'POST', '/api/schedules', token, scopeSpec, {
        name,
        goal,
        scheduleType: intervalMs !== undefined ? 'INTERVAL' : 'ONE_TIME',
        ...(runAt !== undefined ? { runAt } : {}),
        ...(intervalMs !== undefined ? { intervalMs } : {}),
        ...(startAt !== undefined ? { startAt } : {}),
        ...(missedRunPolicy !== undefined ? { missedRunPolicy } : {})
      });
    }
    if (sub === 'list') {
      const qs = new URLSearchParams();
      const status = getStringFlag(flags, 'status');
      const limit = getIntFlag(flags, 'limit');
      if (status) qs.set('status', status);
      if (limit !== undefined) qs.set('limit', String(limit));
      const suffix = qs.toString() ? `?${qs.toString()}` : '';
      return await callHttpApi(serverUrl, 'GET', `/api/schedules${suffix}`, token, scopeSpec);
    }
    if (sub === 'get') {
      const id = requireArg(positionals[2], 'scheduleId');
      return await callHttpApi(serverUrl, 'GET', `/api/schedules/${encodeURIComponent(id)}`, token, scopeSpec);
    }
    if (sub === 'occurrences') {
      const id = requireArg(positionals[2], 'scheduleId');
      const limit = getIntFlag(flags, 'limit') ?? 50;
      return await callHttpApi(
        serverUrl,
        'GET',
        `/api/schedules/${encodeURIComponent(id)}/occurrences?limit=${limit}`,
        token,
        scopeSpec
      );
    }
    if (sub === 'pause') {
      const id = requireArg(positionals[2], 'scheduleId');
      const reason = getStringFlag(flags, 'reason');
      return await callHttpApi(
        serverUrl,
        'POST',
        `/api/schedules/${encodeURIComponent(id)}/pause`,
        token,
        scopeSpec,
        reason ? { reason } : {}
      );
    }
    if (sub === 'resume') {
      const id = requireArg(positionals[2], 'scheduleId');
      return await callHttpApi(serverUrl, 'POST', `/api/schedules/${encodeURIComponent(id)}/resume`, token, scopeSpec, {});
    }
    if (sub === 'cancel') {
      const id = requireArg(positionals[2], 'scheduleId');
      return await callHttpApi(serverUrl, 'POST', `/api/schedules/${encodeURIComponent(id)}/cancel`, token, scopeSpec, {});
    }
    throw new ValidationError(`Unknown schedule subcommand '${sub}'.`);
  }

  throw new ValidationError(`Unknown command '${cmd}'. Run 'dots --help' for usage.`);
}

function isMainEntry(): boolean {
  const invoked = process.argv[1];
  if (!invoked) {
    return false;
  }
  try {
    return import.meta.url === pathToFileURL(realpathSync(invoked)).href;
  } catch {
    return import.meta.url === pathToFileURL(invoked).href;
  }
}

if (isMainEntry()) {
  runCli(process.argv.slice(2)).then((code) => {
    process.exitCode = code;
  });
}
