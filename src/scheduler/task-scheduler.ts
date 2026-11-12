/**
 * Next-Generation Dots AI Platform - Persistent Task Scheduler (Phase 8B)
 *
 * Architectural Mandate:
 * Provides durable, SQLite-backed scheduling for ONE_TIME and INTERVAL tasks.
 * Guarantees:
 * - Database-enforced duplicate prevention via UNIQUE(schedule_id, occurrence_key)
 *   and 1-to-1 task_id uniqueness.
 * - Crash-safe recovery across all 5 interruption points (pre-claim, post-claim,
 *   post-task-create, mid-execution, post-completion).
 * - Overlap prevention (concurrency = 1 per schedule & global single-worker loop).
 * - Missed-run policy enforcement (SKIP vs RUN_ONCE) without backlog storms.
 * - Bounded consecutive failures with automatic pause.
 * - Strict user/workspace scope isolation and human approval non-bypass.
 */

import { randomUUID } from 'node:crypto';
import type {
  CallerContext,
  CreateScheduleInput,
  ListSchedulesFilter,
  MissedRunPolicy,
  Schedule,
  ScheduleOccurrence,
  Task
} from '../domain/types.ts';
import {
  ScheduleConflictError,
  ScheduleNotFoundError,
  SecurityViolationError,
  ValidationError
} from '../domain/errors.ts';
import { TaskStateMachine } from '../domain/state-machine.ts';
import type { TaskRepository } from '../storage/task-repository.ts';
import type { AuditRepository } from '../storage/audit-repository.ts';
import type { ScheduleRepository } from '../storage/schedule-repository.ts';
import type { MemoryAuthorizer } from '../security/memory-authorizer.ts';
import { validateScope } from '../security/memory-authorizer.ts';
import type { HostMemoryAuthority } from '../security/host-authority.ts';
import type { TaskCoordinator } from '../orchestrator/coordinator.ts';
import type { OperationalLogger } from '../runtime/logger.ts';
import type { RuntimeEventBus } from '../runtime/event-bus.ts';
import { CrashRecoveryEngine } from '../storage/recovery.ts';
import { defaultSecretScrubber } from '../model/secret-scrubber.ts';

export interface SchedulerFaultHooks {
  readonly afterClaim?: (occurrence: ScheduleOccurrence) => void;
  readonly afterTaskCreate?: (occurrence: ScheduleOccurrence, task: Task) => void;
  readonly beforeFinalize?: (occurrence: ScheduleOccurrence, task: Task) => void;
}

export interface TaskSchedulerOptions {
  readonly scheduleRepo: ScheduleRepository;
  readonly taskRepo: TaskRepository;
  readonly auditRepo: AuditRepository;
  readonly coordinator: TaskCoordinator;
  readonly authorizer: MemoryAuthorizer;
  readonly hostAuthority: HostMemoryAuthority;
  readonly logger?: OperationalLogger;
  readonly eventBus?: RuntimeEventBus;
  readonly pollIntervalMs?: number;
  readonly oneTimeMissedGraceMs?: number;
  readonly defaultMaxConsecutiveFailures?: number;
  readonly _faultHooks?: SchedulerFaultHooks;
}

const SYSTEM_SCHEDULER_TASK_ID = '__system_scheduler__';
const MIN_INTERVAL_MS = 1000;

export function deterministicTaskIdForOccurrence(occurrenceId: string): string {
  return `sched_${occurrenceId}`;
}

function parseIsoUtc(value: unknown, fieldName: string): Date {
  if (typeof value !== 'string' || value.trim() === '') {
    throw new ValidationError(`${fieldName} must be a non-empty ISO 8601 UTC timestamp.`);
  }
  const date = new Date(value);
  if (isNaN(date.getTime()) || !value.endsWith('Z')) {
    throw new ValidationError(`${fieldName} must be a valid ISO 8601 UTC timestamp ending with 'Z'.`);
  }
  return date;
}

export class TaskScheduler {
  private readonly scheduleRepo: ScheduleRepository;
  private readonly taskRepo: TaskRepository;
  private readonly auditRepo: AuditRepository;
  private readonly coordinator: TaskCoordinator;
  private readonly authorizer: MemoryAuthorizer;
  private readonly hostAuthority: HostMemoryAuthority;
  private readonly logger?: OperationalLogger;
  private readonly eventBus?: RuntimeEventBus;
  private readonly pollIntervalMs: number;
  private readonly oneTimeMissedGraceMs: number;
  private readonly defaultMaxConsecutiveFailures: number;
  private readonly faultHooks?: SchedulerFaultHooks;

  private timer: ReturnType<typeof setInterval> | null = null;
  private isStarted: boolean = false;
  private isStopping: boolean = false;
  private activeTickPromise: Promise<void> | null = null;
  private systemTaskInitialized: boolean = false;

  constructor(options: TaskSchedulerOptions) {
    if (options.scheduleRepo.db !== options.taskRepo.db || options.taskRepo.db !== options.auditRepo.db) {
      throw new ValidationError(
        'ScheduleRepository, TaskRepository, and AuditRepository must share the exact same DatabaseManager instance.'
      );
    }

    this.scheduleRepo = options.scheduleRepo;
    this.taskRepo = options.taskRepo;
    this.auditRepo = options.auditRepo;
    this.coordinator = options.coordinator;
    this.authorizer = options.authorizer;
    this.hostAuthority = options.hostAuthority;
    this.logger = options.logger;
    this.eventBus = options.eventBus;
    this.pollIntervalMs = Math.max(100, options.pollIntervalMs ?? 1000);
    this.oneTimeMissedGraceMs = Math.max(0, options.oneTimeMissedGraceMs ?? 60_000);
    this.defaultMaxConsecutiveFailures = Math.max(1, options.defaultMaxConsecutiveFailures ?? 3);
    this.faultHooks = options._faultHooks;
  }

  // --- Lifecycle ---

  public async start(now: Date = new Date()): Promise<void> {
    if (this.isStarted) {
      return;
    }
    this.isStopping = false;
    this.isStarted = true;

    await this.recoverInterruptedOccurrences(now);

    this.timer = setInterval(() => {
      void this.tick();
    }, this.pollIntervalMs);
    this.timer.unref?.();

    this.logger?.info('scheduler', 'started', {
      pollIntervalMs: this.pollIntervalMs,
      concurrency: 1
    });
  }

  public async stop(): Promise<void> {
    this.isStopping = true;
    this.isStarted = false;

    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }

    if (this.activeTickPromise) {
      await this.activeTickPromise;
    }

    this.logger?.info('scheduler', 'stopped');
  }

  // --- Schedule Management API ---

  public createSchedule(caller: CallerContext, input: CreateScheduleInput): Schedule {
    const verified = this.verifyCaller(caller, 'WRITE');

    if (!input || typeof input !== 'object') {
      throw new ValidationError('CreateScheduleInput must be an object.');
    }
    if (!input.name || typeof input.name !== 'string' || input.name.trim() === '') {
      throw new ValidationError('Schedule name must not be empty.');
    }
    if (!input.goal || typeof input.goal !== 'string' || input.goal.trim() === '') {
      throw new ValidationError('Schedule goal must not be empty.');
    }
    if (input.scheduleType !== 'ONE_TIME' && input.scheduleType !== 'INTERVAL') {
      throw new ValidationError(`Unsupported scheduleType '${String(input.scheduleType)}'. Only ONE_TIME and INTERVAL are supported.`);
    }

    const maxFailures = input.maxConsecutiveFailures ?? this.defaultMaxConsecutiveFailures;
    if (!Number.isInteger(maxFailures) || maxFailures < 1 || maxFailures > 100) {
      throw new ValidationError('maxConsecutiveFailures must be an integer between 1 and 100.');
    }

    let runAt: string | null = null;
    let intervalMs: number | null = null;
    let nextRunAt: string;
    let missedRunPolicy: MissedRunPolicy;

    if (input.scheduleType === 'ONE_TIME') {
      if (input.intervalMs !== undefined) {
        throw new ValidationError('ONE_TIME schedule must not specify intervalMs.');
      }
      const runDate = parseIsoUtc(input.runAt, 'runAt');
      runAt = runDate.toISOString();
      nextRunAt = runAt;
      missedRunPolicy = input.missedRunPolicy ?? 'RUN_ONCE';
    } else {
      if (input.runAt !== undefined) {
        throw new ValidationError('INTERVAL schedule must not specify runAt.');
      }
      if (
        typeof input.intervalMs !== 'number' ||
        !Number.isInteger(input.intervalMs) ||
        input.intervalMs < MIN_INTERVAL_MS
      ) {
        throw new ValidationError(`INTERVAL schedule requires integer intervalMs >= ${MIN_INTERVAL_MS}.`);
      }
      intervalMs = input.intervalMs;
      if (input.startAt !== undefined) {
        nextRunAt = parseIsoUtc(input.startAt, 'startAt').toISOString();
      } else {
        nextRunAt = new Date(Date.now() + intervalMs).toISOString();
      }
      missedRunPolicy = input.missedRunPolicy ?? 'SKIP';
    }

    if (missedRunPolicy !== 'SKIP' && missedRunPolicy !== 'RUN_ONCE') {
      throw new ValidationError(`Invalid missedRunPolicy '${String(missedRunPolicy)}'.`);
    }

    const metadataJson = input.metadata ? JSON.stringify(input.metadata) : null;

    const schedule = this.scheduleRepo.db.transaction(() => {
      const created = this.scheduleRepo.createSchedule({
        id: input.id,
        name: input.name.trim(),
        goal: input.goal.trim(),
        scheduleType: input.scheduleType,
        status: 'ACTIVE',
        runAt,
        intervalMs,
        missedRunPolicy,
        overlapPolicy: 'SKIP',
        maxConsecutiveFailures: maxFailures,
        scopeType: verified.scope.scopeType,
        scopeId: verified.scope.scopeId,
        createdBy: verified.actor,
        metadataJson,
        nextRunAt
      });

      this.appendSchedulerAudit('SCHEDULE_CREATED', verified.actor === 'SYSTEM' ? 'SYSTEM' : 'USER', {
        scheduleId: created.id,
        scheduleType: created.scheduleType,
        scopeType: created.scopeType,
        scopeId: created.scopeId,
        nextRunAt: created.nextRunAt
      });

      return created;
    });

    this.eventBus?.emit({
      type: 'schedule.created',
      scope: verified.scope,
      scheduleId: schedule.id,
      data: { schedule }
    });

    this.logger?.info('scheduler', 'schedule_created', {
      scheduleId: schedule.id,
      scheduleType: schedule.scheduleType,
      scopeType: schedule.scopeType,
      scopeId: schedule.scopeId
    });

    return schedule;
  }

  public getSchedule(caller: CallerContext, scheduleId: string): Schedule {
    const verified = this.verifyCaller(caller, 'READ');
    const schedule = this.scheduleRepo.getScheduleById(scheduleId);
    if (!schedule) {
      throw new ScheduleNotFoundError(scheduleId);
    }
    this.assertScheduleScope(schedule, verified);
    return schedule;
  }

  public listSchedules(caller: CallerContext, filter: ListSchedulesFilter = {}): Schedule[] {
    const verified = this.verifyCaller(caller, 'READ');

    if (filter.scopeType && filter.scopeType !== verified.scope.scopeType) {
      throw new SecurityViolationError(
        `Requested scopeType '${filter.scopeType}' does not match caller scope.`,
        'SCHEDULE_SCOPE_MISMATCH'
      );
    }
    if (filter.scopeId && filter.scopeId !== verified.scope.scopeId) {
      throw new SecurityViolationError(
        `Requested scopeId '${filter.scopeId}' does not match caller scope.`,
        'SCHEDULE_SCOPE_MISMATCH'
      );
    }

    return this.scheduleRepo.listSchedules({
      ...filter,
      scopeType: verified.scope.scopeType,
      scopeId: verified.scope.scopeId
    });
  }

  public listOccurrences(
    caller: CallerContext,
    scheduleId: string,
    limit: number = 50,
    offset: number = 0
  ): ScheduleOccurrence[] {
    this.getSchedule(caller, scheduleId);
    return this.scheduleRepo.listOccurrencesByScheduleId(scheduleId, limit, offset);
  }

  public pauseSchedule(caller: CallerContext, scheduleId: string, reason?: string): Schedule {
    const verified = this.verifyCaller(caller, 'WRITE');
    const existing = this.getSchedule(caller, scheduleId);

    if (existing.status === 'PAUSED') {
      return existing;
    }

    const updated = this.scheduleRepo.db.transaction(() => {
      const next = this.scheduleRepo.updateScheduleStatus(scheduleId, 'ACTIVE', 'PAUSED', {
        pausedReason: reason ?? 'Paused by user'
      });
      this.appendSchedulerAudit('SCHEDULE_PAUSED', verified.actor === 'SYSTEM' ? 'SYSTEM' : 'USER', {
        scheduleId,
        reason: next.pausedReason
      });
      return next;
    });

    this.eventBus?.emit({
      type: 'schedule.updated',
      scope: { scopeType: updated.scopeType, scopeId: updated.scopeId },
      scheduleId: updated.id,
      data: { schedule: updated }
    });

    return updated;
  }

  public resumeSchedule(caller: CallerContext, scheduleId: string, now: Date = new Date()): Schedule {
    const verified = this.verifyCaller(caller, 'WRITE');
    const existing = this.getSchedule(caller, scheduleId);

    if (existing.status === 'ACTIVE') {
      return existing;
    }
    if (existing.status !== 'PAUSED') {
      throw new ScheduleConflictError(
        `Cannot resume schedule '${scheduleId}' from status '${existing.status}'.`,
        scheduleId,
        { currentStatus: existing.status }
      );
    }

    let nextRunAt = existing.nextRunAt;
    if (existing.scheduleType === 'INTERVAL' && existing.intervalMs) {
      const nextMs = nextRunAt ? new Date(nextRunAt).getTime() : 0;
      if (!nextRunAt || nextMs <= now.getTime()) {
        nextRunAt = new Date(now.getTime() + existing.intervalMs).toISOString();
      }
    }

    const updated = this.scheduleRepo.db.transaction(() => {
      const next = this.scheduleRepo.updateScheduleStatus(scheduleId, 'PAUSED', 'ACTIVE', {
        nextRunAt,
        pausedReason: null,
        resetFailures: true,
        updatedAt: now.toISOString()
      });
      this.appendSchedulerAudit('SCHEDULE_RESUMED', verified.actor === 'SYSTEM' ? 'SYSTEM' : 'USER', {
        scheduleId,
        nextRunAt: next.nextRunAt
      });
      return next;
    });

    this.eventBus?.emit({
      type: 'schedule.updated',
      scope: { scopeType: updated.scopeType, scopeId: updated.scopeId },
      scheduleId: updated.id,
      data: { schedule: updated }
    });

    return updated;
  }

  public cancelSchedule(caller: CallerContext, scheduleId: string): Schedule {
    const verified = this.verifyCaller(caller, 'WRITE');
    const existing = this.getSchedule(caller, scheduleId);

    if (existing.status === 'CANCELLED') {
      return existing;
    }

    const updated = this.scheduleRepo.db.transaction(() => {
      const next = this.scheduleRepo.updateScheduleStatus(
        scheduleId,
        ['ACTIVE', 'PAUSED'],
        'CANCELLED',
        { nextRunAt: null }
      );

      // Cancel any unstarted claimed occurrence
      const activeOcc = this.scheduleRepo.getActiveOccurrenceForSchedule(scheduleId);
      if (activeOcc && (activeOcc.status === 'CLAIMED' || activeOcc.status === 'TASK_CREATED')) {
        this.scheduleRepo.updateOccurrenceStatus(activeOcc.id, 'CANCELLED', {
          errorSummary: 'Schedule cancelled before execution.'
        });
        if (activeOcc.taskId) {
          const linkedTask = this.taskRepo.getTaskById(activeOcc.taskId);
          if (linkedTask && linkedTask.status === 'SUBMITTED') {
            this.taskRepo.updateTaskStatus(linkedTask.id, 'SUBMITTED', 'CANCELLED', 'Schedule cancelled.');
          }
        }
      }

      this.appendSchedulerAudit('SCHEDULE_CANCELLED', verified.actor === 'SYSTEM' ? 'SYSTEM' : 'USER', {
        scheduleId
      });
      return next;
    });

    this.eventBus?.emit({
      type: 'schedule.updated',
      scope: { scopeType: updated.scopeType, scopeId: updated.scopeId },
      scheduleId: updated.id,
      data: { schedule: updated }
    });

    return updated;
  }

  // --- Execution & Recovery ---

  /**
   * Executes one scheduler tick with concurrency strictly equal to 1.
   * Accepts an explicit `now` timestamp for deterministic testing.
   */
  public async tick(now: Date = new Date()): Promise<void> {
    if (this.isStopping || this.activeTickPromise) {
      return;
    }

    const promise = this.runTickInternal(now);
    this.activeTickPromise = promise;
    try {
      await promise;
    } finally {
      if (this.activeTickPromise === promise) {
        this.activeTickPromise = null;
      }
    }
  }

  /**
   * Recovers interrupted occurrences after a crash across all 5 interruption points.
   */
  public async recoverInterruptedOccurrences(now: Date = new Date()): Promise<void> {
    const incomplete = this.scheduleRepo.listIncompleteOccurrences();
    for (const occ of incomplete) {
      if (this.isStopping) {
        break;
      }
      await this.reconcileSingleOccurrence(occ, now);
    }
  }

  private async runTickInternal(now: Date): Promise<void> {
    // 1. Reconcile any incomplete occurrences (e.g., tasks whose approvals were decided)
    const incomplete = this.scheduleRepo.listIncompleteOccurrences();
    for (const occ of incomplete) {
      if (this.isStopping) {
        return;
      }
      await this.reconcileSingleOccurrence(occ, now);
    }

    // 2. Process due active schedules sequentially (concurrency = 1)
    const nowIso = now.toISOString();
    const dueSchedules = this.scheduleRepo.listDueSchedules(nowIso, 20);

    for (const schedule of dueSchedules) {
      if (this.isStopping) {
        return;
      }
      await this.processDueSchedule(schedule, now);
    }
  }

  private async reconcileSingleOccurrence(occ: ScheduleOccurrence, now: Date): Promise<void> {
    const schedule = this.scheduleRepo.getScheduleById(occ.scheduleId);
    if (!schedule) {
      return;
    }

    let currentOcc = occ;

    // Crash Case 2 & 3: CLAIMED without task_id
    if (currentOcc.status === 'CLAIMED' && !currentOcc.taskId) {
      const candidateTaskId = deterministicTaskIdForOccurrence(currentOcc.id);
      const existingTask = this.taskRepo.getTaskById(candidateTaskId);

      if (existingTask) {
        // Crash occurred AFTER task creation but BEFORE occurrence update
        currentOcc = this.scheduleRepo.db.transaction(() => {
          const linked = this.scheduleRepo.linkTaskToOccurrence(currentOcc.id, existingTask.id, 'TASK_CREATED', now.toISOString());
          if (schedule.scheduleType === 'ONE_TIME') {
            this.scheduleRepo.advanceNextRunAt(schedule.id, null, now.toISOString());
          } else if (schedule.scheduleType === 'INTERVAL' && schedule.intervalMs) {
            const dueMs = new Date(currentOcc.scheduledFor).getTime();
            if (!schedule.nextRunAt || new Date(schedule.nextRunAt).getTime() <= dueMs) {
              this.scheduleRepo.advanceNextRunAt(
                schedule.id,
                this.computeNextFutureSlot(dueMs, schedule.intervalMs, now.getTime()),
                now.toISOString()
              );
            }
          }
          this.appendSchedulerAudit('SCHEDULE_OCCURRENCE_RECOVERED', 'SYSTEM', {
            scheduleId: schedule.id,
            occurrenceId: currentOcc.id,
            taskId: existingTask.id,
            recoveryCase: 'POST_TASK_CREATE_PRE_OCCURRENCE_LINK'
          }, existingTask.id);
          return linked;
        });
      } else {
        // Crash occurred AFTER claim but BEFORE task creation
        if (schedule.status !== 'ACTIVE') {
          this.scheduleRepo.updateOccurrenceStatus(currentOcc.id, 'CANCELLED', {
            errorSummary: `Schedule was ${schedule.status} during claim recovery.`,
            updatedAt: now.toISOString()
          });
          return;
        }

        currentOcc = this.createTaskAndLinkOccurrence(schedule, currentOcc, now, true);
      }
    }

    if (!currentOcc.taskId) {
      return;
    }

    let task = this.taskRepo.getTaskById(currentOcc.taskId);
    if (!task) {
      this.finalizeOccurrence(schedule, currentOcc, 'FAILED', 'Linked task missing during recovery.', now);
      return;
    }

    // Crash Case 4: Task was interrupted mid-flight (PLANNING / EXECUTING / VERIFYING)
    if (task.status === 'PLANNING' || task.status === 'EXECUTING' || task.status === 'VERIFYING') {
      const recoveryEngine = new CrashRecoveryEngine(this.taskRepo, this.auditRepo);
      recoveryEngine.reconcileInterruptedTasks();
      task = this.taskRepo.getTaskById(currentOcc.taskId)!;
    }

    // Crash Case 5: Task already reached terminal state before occurrence finalization
    if (TaskStateMachine.isTerminal(task.status)) {
      this.finalizeFromTerminalTask(schedule, currentOcc, task, now);
      return;
    }

    // Human Approval Enforcement: NEVER auto-approve AWAITING_APPROVAL
    if (task.status === 'AWAITING_APPROVAL') {
      const approvals = this.taskRepo.getApprovalRequestsByTaskId(task.id);
      const hasPending = approvals.some((a) => a.decision === 'PENDING');
      const hasDecision = approvals.some((a) => a.decision === 'APPROVED' || a.decision === 'REJECTED');
      if (hasPending || !hasDecision) {
        if (currentOcc.status !== 'AWAITING_APPROVAL') {
          this.scheduleRepo.updateOccurrenceStatus(currentOcc.id, 'AWAITING_APPROVAL', {
            updatedAt: now.toISOString()
          });
        }
        return;
      }
      // Decision exists (user approved or rejected) -> resume execution
      await this.executeAndFinalizeOccurrence(schedule, currentOcc, task, now);
      return;
    }

    // Crash Case 4 (continued): Task is SUBMITTED or RECOVERING
    if (task.status === 'SUBMITTED' || task.status === 'RECOVERING') {
      await this.executeAndFinalizeOccurrence(schedule, currentOcc, task, now);
    }
  }

  private async processDueSchedule(schedule: Schedule, now: Date): Promise<void> {
    if (!schedule.nextRunAt) {
      return;
    }

    const nowMs = now.getTime();
    const dueMs = new Date(schedule.nextRunAt).getTime();
    if (dueMs > nowMs) {
      return;
    }

    // Overlap prevention: if an active occurrence exists for this schedule, record skip and advance slot
    const existingActive = this.scheduleRepo.getActiveOccurrenceForSchedule(schedule.id);
    if (existingActive) {
      const skipKey = `overlap:${schedule.nextRunAt}`;
      this.scheduleRepo.db.transaction(() => {
        this.scheduleRepo.recordSkippedOccurrence({
          scheduleId: schedule.id,
          occurrenceKey: skipKey,
          scheduledFor: schedule.nextRunAt!,
          status: 'SKIPPED_OVERLAP',
          reason: `Skipped due to active occurrence '${existingActive.id}' (${existingActive.status}).`,
          nowIso: now.toISOString()
        });

        if (schedule.scheduleType === 'INTERVAL' && schedule.intervalMs) {
          const nextSlot = this.computeNextFutureSlot(dueMs, schedule.intervalMs, nowMs);
          this.scheduleRepo.advanceNextRunAt(schedule.id, nextSlot, now.toISOString());
        } else {
          this.scheduleRepo.advanceNextRunAt(schedule.id, null, now.toISOString());
        }

        this.appendSchedulerAudit('SCHEDULE_OCCURRENCE_SKIPPED', 'SYSTEM', {
          scheduleId: schedule.id,
          occurrenceKey: skipKey,
          reason: 'ACTIVE_OVERLAP',
          activeOccurrenceId: existingActive.id
        });
      });
      return;
    }

    // Determine target occurrence timestamp and nextRunAt (handling missed runs)
    let scheduledFor = schedule.nextRunAt;
    let nextFutureRunAt: string | null = null;

    if (schedule.scheduleType === 'ONE_TIME') {
      const isMissed = nowMs - dueMs > this.oneTimeMissedGraceMs;
      if (isMissed && schedule.missedRunPolicy === 'SKIP') {
        const missKey = `missed:${schedule.nextRunAt}`;
        this.scheduleRepo.db.transaction(() => {
          this.scheduleRepo.recordSkippedOccurrence({
            scheduleId: schedule.id,
            occurrenceKey: missKey,
            scheduledFor: schedule.nextRunAt!,
            status: 'SKIPPED_MISSED',
            reason: 'One-time schedule missed while offline and missedRunPolicy=SKIP.',
            nowIso: now.toISOString()
          });
          this.scheduleRepo.updateScheduleStatus(schedule.id, 'ACTIVE', 'COMPLETED', {
            nextRunAt: null,
            updatedAt: now.toISOString()
          });
          this.appendSchedulerAudit('SCHEDULE_OCCURRENCE_SKIPPED', 'SYSTEM', {
            scheduleId: schedule.id,
            occurrenceKey: missKey,
            reason: 'MISSED_ONE_TIME'
          });
        });
        return;
      }
      nextFutureRunAt = null;
    } else if (schedule.intervalMs) {
      const missedIntervals = Math.floor((nowMs - dueMs) / schedule.intervalMs);
      if (missedIntervals >= 1) {
        if (schedule.missedRunPolicy === 'SKIP') {
          const missKey = `missed:${schedule.nextRunAt}`;
          const nextSlot = this.computeNextFutureSlot(dueMs, schedule.intervalMs, nowMs);
          this.scheduleRepo.db.transaction(() => {
            this.scheduleRepo.recordSkippedOccurrence({
              scheduleId: schedule.id,
              occurrenceKey: missKey,
              scheduledFor: schedule.nextRunAt!,
              status: 'SKIPPED_MISSED',
              reason: `Skipped ${missedIntervals} missed interval(s) under missedRunPolicy=SKIP.`,
              nowIso: now.toISOString()
            });
            this.scheduleRepo.advanceNextRunAt(schedule.id, nextSlot, now.toISOString());
            this.appendSchedulerAudit('SCHEDULE_OCCURRENCE_SKIPPED', 'SYSTEM', {
              scheduleId: schedule.id,
              occurrenceKey: missKey,
              missedIntervals,
              reason: 'MISSED_INTERVAL_SKIP',
              nextRunAt: nextSlot
            });
          });
          return;
        }
        // RUN_ONCE: fire once for the latest due slot and advance nextRunAt past now
        const latestSlotMs = dueMs + missedIntervals * schedule.intervalMs;
        scheduledFor = new Date(latestSlotMs).toISOString();
        nextFutureRunAt = new Date(latestSlotMs + schedule.intervalMs).toISOString();
      } else {
        nextFutureRunAt = new Date(dueMs + schedule.intervalMs).toISOString();
      }
    }

    const occurrenceKey = schedule.scheduleType === 'ONE_TIME'
      ? `once:${scheduledFor}`
      : `slot:${scheduledFor}`;

    // Phase 1: Durable Claim (DB-enforced uniqueness prevents duplicates & overlaps)
    const claimResult = this.scheduleRepo.tryClaimOccurrence({
      scheduleId: schedule.id,
      occurrenceKey,
      scheduledFor,
      claimedAt: now.toISOString()
    });

    if (!claimResult.claimed) {
      if (claimResult.reason === 'ACTIVE_OVERLAP') {
        this.scheduleRepo.recordSkippedOccurrence({
          scheduleId: schedule.id,
          occurrenceKey: `overlap:${scheduledFor}`,
          scheduledFor,
          status: 'SKIPPED_OVERLAP',
          reason: 'Skipped due to DB-enforced active occurrence constraint.',
          nowIso: now.toISOString()
        });
      }
      if (schedule.scheduleType === 'INTERVAL' && schedule.intervalMs) {
        this.scheduleRepo.advanceNextRunAt(
          schedule.id,
          this.computeNextFutureSlot(dueMs, schedule.intervalMs, nowMs),
          now.toISOString()
        );
      } else if (schedule.scheduleType === 'ONE_TIME' && claimResult.reason === 'DUPLICATE_KEY') {
        this.scheduleRepo.advanceNextRunAt(schedule.id, null, now.toISOString());
      }
      return;
    }

    const claimedOcc = claimResult.occurrence;
    this.faultHooks?.afterClaim?.(claimedOcc);

    // Phase 2: Crash-Safe Task Creation + Occurrence Link + NextRunAt Advancement
    const linkedOcc = this.createTaskAndLinkOccurrence(schedule, claimedOcc, now, false, nextFutureRunAt);
    const task = this.taskRepo.getTaskById(linkedOcc.taskId!)!;

    // Phase 3: Execute & Finalize
    await this.executeAndFinalizeOccurrence(schedule, linkedOcc, task, now);
  }

  private createTaskAndLinkOccurrence(
    schedule: Schedule,
    occ: ScheduleOccurrence,
    now: Date,
    isRecovery: boolean,
    nextFutureRunAt?: string | null
  ): ScheduleOccurrence {
    const taskId = deterministicTaskIdForOccurrence(occ.id);
    const extraMeta = schedule.metadataJson
      ? (JSON.parse(schedule.metadataJson) as Record<string, unknown>)
      : {};

    // Step 2a: Idempotent task creation transaction (deterministic task ID prevents duplicates)
    const task = this.scheduleRepo.db.transaction(() => {
      let existing = this.taskRepo.getTaskById(taskId);
      if (!existing) {
        existing = this.hostAuthority.createTask(this.taskRepo, {
          id: taskId,
          goal: schedule.goal,
          scope: {
            scopeType: schedule.scopeType,
            scopeId: schedule.scopeId
          },
          metadata: {
            ...extraMeta,
            scheduleId: schedule.id,
            occurrenceId: occ.id,
            occurrenceKey: occ.occurrenceKey,
            scheduledFor: occ.scheduledFor
          }
        });

        this.auditRepo.appendEvent({
          taskId: existing.id,
          eventType: 'TASK_CREATED',
          actor: 'SYSTEM',
          details: {
            goal: existing.goal,
            scope: { scopeType: schedule.scopeType, scopeId: schedule.scopeId },
            scheduleId: schedule.id,
            occurrenceId: occ.id
          }
        });
      }
      return existing;
    });

    this.faultHooks?.afterTaskCreate?.(occ, task);

    // Step 2b: Link task to occurrence and advance nextRunAt atomically
    return this.scheduleRepo.db.transaction(() => {
      const linked = this.scheduleRepo.linkTaskToOccurrence(occ.id, task.id, 'TASK_CREATED', now.toISOString());

      if (nextFutureRunAt !== undefined) {
        this.scheduleRepo.advanceNextRunAt(schedule.id, nextFutureRunAt, now.toISOString());
      } else if (schedule.scheduleType === 'ONE_TIME') {
        this.scheduleRepo.advanceNextRunAt(schedule.id, null, now.toISOString());
      } else if (schedule.scheduleType === 'INTERVAL' && schedule.intervalMs) {
        const dueMs = new Date(occ.scheduledFor).getTime();
        this.scheduleRepo.advanceNextRunAt(
          schedule.id,
          this.computeNextFutureSlot(dueMs, schedule.intervalMs, now.getTime()),
          now.toISOString()
        );
      }

      this.appendSchedulerAudit(
        isRecovery ? 'SCHEDULE_OCCURRENCE_RECOVERED' : 'SCHEDULE_OCCURRENCE_CLAIMED',
        'SYSTEM',
        {
          scheduleId: schedule.id,
          occurrenceId: occ.id,
          occurrenceKey: occ.occurrenceKey,
          taskId: task.id
        },
        task.id
      );

      return linked;
    });
  }

  private async executeAndFinalizeOccurrence(
    schedule: Schedule,
    occ: ScheduleOccurrence,
    initialTask: Task,
    now: Date
  ): Promise<void> {
    this.scheduleRepo.updateOccurrenceStatus(occ.id, 'RUNNING', {
      startedAt: occ.startedAt ?? now.toISOString(),
      updatedAt: now.toISOString()
    });

    this.eventBus?.emit({
      type: 'occurrence.updated',
      scope: { scopeType: schedule.scopeType, scopeId: schedule.scopeId },
      scheduleId: schedule.id,
      taskId: initialTask.id,
      data: { occurrenceId: occ.id, status: 'RUNNING' }
    });

    let finalTask: Task;
    try {
      finalTask = await this.coordinator.runToCompletion(initialTask.id);
    } catch (err) {
      const msg = defaultSecretScrubber.scrub(err instanceof Error ? err.message : String(err));
      this.finalizeOccurrence(schedule, occ, 'FAILED', msg, new Date());
      return;
    }

    this.faultHooks?.beforeFinalize?.(occ, finalTask);

    if (finalTask.status === 'AWAITING_APPROVAL') {
      // NEVER auto-approve! Hold occurrence in AWAITING_APPROVAL.
      this.scheduleRepo.updateOccurrenceStatus(occ.id, 'AWAITING_APPROVAL', {
        updatedAt: new Date().toISOString()
      });
      this.eventBus?.emit({
        type: 'approval.requested',
        scope: { scopeType: schedule.scopeType, scopeId: schedule.scopeId },
        scheduleId: schedule.id,
        taskId: finalTask.id,
        data: { occurrenceId: occ.id, status: 'AWAITING_APPROVAL' }
      });
      return;
    }

    if (TaskStateMachine.isTerminal(finalTask.status)) {
      this.finalizeFromTerminalTask(schedule, occ, finalTask, new Date());
    }
  }

  private finalizeFromTerminalTask(
    schedule: Schedule,
    occ: ScheduleOccurrence,
    task: Task,
    now: Date
  ): void {
    if (task.status === 'COMPLETED') {
      this.finalizeOccurrence(schedule, occ, 'SUCCEEDED', null, now, task.id);
    } else if (task.status === 'CANCELLED') {
      this.finalizeOccurrence(schedule, occ, 'CANCELLED', task.errorSummary ?? 'Task cancelled.', now, task.id);
    } else {
      this.finalizeOccurrence(
        schedule,
        occ,
        'FAILED',
        task.errorSummary ?? `Task ended with status '${task.status}'.`,
        now,
        task.id
      );
    }
  }

  private finalizeOccurrence(
    schedule: Schedule,
    occ: ScheduleOccurrence,
    outcome: 'SUCCEEDED' | 'FAILED' | 'CANCELLED',
    errorSummary: string | null,
    now: Date,
    taskId: string | null = occ.taskId
  ): void {
    const nowIso = now.toISOString();
    const markCompleted = schedule.scheduleType === 'ONE_TIME';
    const safeError = errorSummary ? defaultSecretScrubber.scrub(errorSummary) : null;

    const { updatedSchedule, updatedOcc } = this.scheduleRepo.db.transaction(() => {
      const updatedOcc = this.scheduleRepo.updateOccurrenceStatus(occ.id, outcome, {
        completedAt: nowIso,
        errorSummary: safeError,
        updatedAt: nowIso
      });

      const updatedSchedule = this.scheduleRepo.recordOccurrenceOutcomeOnSchedule({
        scheduleId: schedule.id,
        taskId,
        succeeded: outcome === 'SUCCEEDED',
        cancelled: outcome === 'CANCELLED',
        ranAt: nowIso,
        markCompleted,
        errorSummary: safeError
      });

      if (outcome === 'SUCCEEDED') {
        this.appendSchedulerAudit('SCHEDULE_OCCURRENCE_SUCCEEDED', 'SYSTEM', {
          scheduleId: schedule.id,
          occurrenceId: occ.id,
          taskId
        }, taskId ?? undefined);
      } else if (outcome === 'FAILED') {
        this.appendSchedulerAudit('SCHEDULE_OCCURRENCE_FAILED', 'SYSTEM', {
          scheduleId: schedule.id,
          occurrenceId: occ.id,
          taskId,
          errorSummary,
          consecutiveFailures: updatedSchedule.consecutiveFailures,
          maxConsecutiveFailures: updatedSchedule.maxConsecutiveFailures
        }, taskId ?? undefined);

        if (schedule.status === 'ACTIVE' && updatedSchedule.status === 'PAUSED') {
          this.appendSchedulerAudit('SCHEDULE_AUTO_PAUSED', 'SYSTEM', {
            scheduleId: schedule.id,
            consecutiveFailures: updatedSchedule.consecutiveFailures,
            reason: updatedSchedule.pausedReason
          });
        }
      }

      if (schedule.status === 'ACTIVE' && updatedSchedule.status === 'COMPLETED') {
        this.appendSchedulerAudit('SCHEDULE_COMPLETED', 'SYSTEM', {
          scheduleId: schedule.id
        });
      }

      return { updatedSchedule, updatedOcc };
    });

    this.eventBus?.emit({
      type: 'occurrence.updated',
      scope: { scopeType: schedule.scopeType, scopeId: schedule.scopeId },
      scheduleId: schedule.id,
      taskId: taskId ?? undefined,
      data: { occurrence: updatedOcc }
    });

    if (updatedSchedule.status !== schedule.status) {
      this.eventBus?.emit({
        type: 'schedule.updated',
        scope: { scopeType: updatedSchedule.scopeType, scopeId: updatedSchedule.scopeId },
        scheduleId: updatedSchedule.id,
        data: { schedule: updatedSchedule }
      });
    }
  }

  private computeNextFutureSlot(dueMs: number, intervalMs: number, nowMs: number): string {
    if (dueMs > nowMs) {
      return new Date(dueMs).toISOString();
    }
    const elapsed = Math.floor((nowMs - dueMs) / intervalMs) + 1;
    return new Date(dueMs + elapsed * intervalMs).toISOString();
  }

  private verifyCaller(caller: CallerContext, permission: 'READ' | 'WRITE'): CallerContext {
    const verified = this.authorizer.verify(caller);
    validateScope(verified.scope.scopeType, verified.scope.scopeId);

    const perms = verified.permissions instanceof Set
      ? verified.permissions
      : new Set(verified.permissions);

    if (!perms.has(permission)) {
      throw new SecurityViolationError(
        `Caller '${verified.actor}' lacks '${permission}' permission for schedule operation.`,
        'PERMISSION_DENIED'
      );
    }

    return verified;
  }

  private assertScheduleScope(schedule: Schedule, caller: CallerContext): void {
    if (schedule.scopeType !== caller.scope.scopeType || schedule.scopeId !== caller.scope.scopeId) {
      throw new SecurityViolationError(
        `Schedule '${schedule.id}' belongs to scope '${schedule.scopeType}:${schedule.scopeId}', not caller scope '${caller.scope.scopeType}:${caller.scope.scopeId}'.`,
        'SCHEDULE_SCOPE_MISMATCH'
      );
    }
  }

  private appendSchedulerAudit(
    eventType:
      | 'SCHEDULE_CREATED'
      | 'SCHEDULE_PAUSED'
      | 'SCHEDULE_RESUMED'
      | 'SCHEDULE_CANCELLED'
      | 'SCHEDULE_COMPLETED'
      | 'SCHEDULE_AUTO_PAUSED'
      | 'SCHEDULE_OCCURRENCE_CLAIMED'
      | 'SCHEDULE_OCCURRENCE_SKIPPED'
      | 'SCHEDULE_OCCURRENCE_SUCCEEDED'
      | 'SCHEDULE_OCCURRENCE_FAILED'
      | 'SCHEDULE_OCCURRENCE_RECOVERED',
    actor: 'USER' | 'SYSTEM',
    details: Record<string, unknown>,
    preferredTaskId?: string
  ): void {
    const taskId = preferredTaskId ?? this.getOrCreateSystemSchedulerTaskId();
    this.auditRepo.appendEvent({
      taskId,
      eventType,
      actor,
      details
    });
  }

  private getOrCreateSystemSchedulerTaskId(): string {
    if (!this.systemTaskInitialized) {
      const existing = this.taskRepo.getTaskById(SYSTEM_SCHEDULER_TASK_ID);
      if (!existing) {
        this.hostAuthority.createTask(this.taskRepo, {
          id: SYSTEM_SCHEDULER_TASK_ID,
          goal: 'System persistent scheduler audit anchor',
          scope: { scopeType: 'GLOBAL', scopeId: 'default' }
        });
      }
      this.systemTaskInitialized = true;
    }
    return SYSTEM_SCHEDULER_TASK_ID;
  }
}
