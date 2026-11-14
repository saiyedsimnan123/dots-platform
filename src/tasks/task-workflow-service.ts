/**
 * Next-Generation Dots AI Platform - Business Task Workflow Service
 * Milestone 2B: Business Task Workflows
 *
 * Architectural Mandate:
 * Dedicated service responsible for:
 * 1. Business task submission with objectives, descriptions, and agent selection.
 * 2. Agent resolution through AgentRegistry with capability verification.
 * 3. Enforcing caller ownership, workspace scope, and role authorization.
 * 4. Coordinating execution through TaskCoordinator without bypassing policies.
 * 5. Lifecycle tracking, result extraction, and safe cancellation.
 * 6. Structured error handling, secret scrubbing, and audit integrity.
 */

import type {
  BusinessTaskResultView,
  CallerContext,
  ListBusinessTasksFilter,
  PublicApprovalView,
  PublicTaskView,
  ScopeIdentifier,
  SubmitBusinessTaskInput,
  Task,
  TaskDetailsView,
  TaskStatus,
  TaskStep
} from '../domain/types.ts';
import {
  AgentCapabilityError,
  AgentNotFoundError,
  InvalidStateTransitionError,
  SecurityViolationError,
  TaskNotFoundError,
  ValidationError
} from '../domain/errors.ts';
import { TaskStateMachine } from '../domain/state-machine.ts';
import { defaultSecretScrubber } from '../model/secret-scrubber.ts';
import type { TaskRepository } from '../storage/task-repository.ts';
import type { AuditRepository } from '../storage/audit-repository.ts';
import type { TaskCoordinator } from '../orchestrator/coordinator.ts';
import type { AgentRegistry } from '../agents/registry.ts';
import { MemoryAuthorizer, validateScope } from '../security/memory-authorizer.ts';
import type { HostMemoryAuthority } from '../security/host-authority.ts';
import type { RuntimeEventBus } from '../runtime/event-bus.ts';
import type { TokenBudgetTracker } from '../model/budget-tracker.ts';

const SYSTEM_SCHEDULER_TASK_ID = '__system_scheduler__';
const MAX_OBJECTIVE_LENGTH = 2048;
const MAX_DESCRIPTION_LENGTH = 32_768;
const SENSITIVE_KEY_PATTERN = /(?:token|secret|password|passphrase|passwd|apikey|api_key|privatekey|authorization|credential|_scopeAttestation|_proof)/i;

export interface TaskWorkflowServiceOptions {
  readonly taskRepo: TaskRepository;
  readonly auditRepo: AuditRepository;
  readonly coordinator: TaskCoordinator;
  readonly agentRegistry: AgentRegistry;
  readonly authorizer?: MemoryAuthorizer;
  readonly hostAuthority?: HostMemoryAuthority;
  readonly eventBus?: RuntimeEventBus;
  readonly budgetTracker?: TokenBudgetTracker;
  readonly defaultAgentId?: string;
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

function scrubPublicValue(value: unknown, depth: number = 0): unknown {
  if (depth > 8) {
    return '[TRUNCATED]';
  }
  if (typeof value === 'string') {
    return defaultSecretScrubber.scrub(value);
  }
  if (Array.isArray(value)) {
    return value.map((item) => scrubPublicValue(item, depth + 1));
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
        out[k] = scrubPublicValue(v, depth + 1);
      }
    }
    return out;
  }
  return value;
}

export class TaskWorkflowService {
  private readonly taskRepo: TaskRepository;
  private readonly auditRepo: AuditRepository;
  private readonly coordinator: TaskCoordinator;
  private readonly agentRegistry: AgentRegistry;
  private readonly authorizer: MemoryAuthorizer;
  private readonly eventBus?: RuntimeEventBus;
  private readonly budgetTracker?: TokenBudgetTracker;
  private readonly defaultAgentId?: string;

  constructor(options: TaskWorkflowServiceOptions) {
    if (!options || typeof options !== 'object') {
      throw new ValidationError('TaskWorkflowServiceOptions must be an object.');
    }
    if (!options.taskRepo) {
      throw new ValidationError('taskRepo is required in TaskWorkflowService.');
    }
    if (!options.auditRepo) {
      throw new ValidationError('auditRepo is required in TaskWorkflowService.');
    }
    if (!options.coordinator) {
      throw new ValidationError('coordinator is required in TaskWorkflowService.');
    }
    if (!options.agentRegistry) {
      throw new ValidationError('agentRegistry is required in TaskWorkflowService.');
    }

    this.taskRepo = options.taskRepo;
    this.auditRepo = options.auditRepo;
    this.coordinator = options.coordinator;
    this.agentRegistry = options.agentRegistry;
    this.authorizer =
      options.authorizer ??
      options.hostAuthority?.authorizer ??
      new MemoryAuthorizer({ taskRepo: options.taskRepo });
    this.eventBus = options.eventBus;
    this.budgetTracker = options.budgetTracker;
    this.defaultAgentId = options.defaultAgentId;
  }

  // --- Core Operations ---

  /**
   * Submits a business task with an objective, optional description, agent selection, and parameters.
   */
  public async submitTask(
    caller: CallerContext,
    input: SubmitBusinessTaskInput
  ): Promise<PublicTaskView> {
    const verified = this.requirePermission(caller, 'WRITE');

    if (!input || typeof input !== 'object') {
      throw new ValidationError('SubmitBusinessTaskInput must be an object.');
    }

    const rawObjective = input.objective ?? input.goal;
    if (!rawObjective || typeof rawObjective !== 'string' || rawObjective.trim() === '') {
      throw new ValidationError("Task 'objective' (or 'goal') must be a non-empty string.");
    }

    const objective = rawObjective.trim();
    if (objective.length > MAX_OBJECTIVE_LENGTH) {
      throw new ValidationError(
        `Task objective length (${objective.length}) exceeds maximum allowed of ${MAX_OBJECTIVE_LENGTH} characters.`
      );
    }

    let description: string | undefined;
    if (input.description !== undefined) {
      if (typeof input.description !== 'string') {
        throw new ValidationError("Task 'description' must be a string.");
      }
      description = input.description.trim();
      if (description.length > MAX_DESCRIPTION_LENGTH) {
        throw new ValidationError(
          `Task description length (${description.length}) exceeds maximum allowed of ${MAX_DESCRIPTION_LENGTH} characters.`
        );
      }
    }

    // Agent resolution & validation
    let effectiveAgentId: string | undefined;
    if (input.agentId !== undefined && input.agentId !== null && input.agentId.trim() !== '') {
      const requestedId = input.agentId.trim();
      if (!this.agentRegistry.has(requestedId)) {
        throw new AgentNotFoundError(requestedId);
      }
      const agent = this.agentRegistry.getOrThrow(requestedId);
      if (agent.capabilities.length === 0) {
        throw new AgentCapabilityError(requestedId, 'general', {
          reason: 'Agent has no supported capabilities.'
        });
      }
      effectiveAgentId = requestedId;
    } else if (this.defaultAgentId && this.agentRegistry.has(this.defaultAgentId)) {
      effectiveAgentId = this.defaultAgentId;
    }

    // Parameters validation
    if (input.parameters !== undefined && (typeof input.parameters !== 'object' || Array.isArray(input.parameters))) {
      throw new ValidationError("Task 'parameters' must be a valid JSON object.");
    }

    // Construct metadata
    const metadata: Record<string, unknown> = {
      ...(input.metadata ?? {}),
      ...(description ? { description: defaultSecretScrubber.scrub(description) } : {}),
      ...(effectiveAgentId ? { agentId: effectiveAgentId } : {}),
      ...(input.parameters ? { parameters: input.parameters } : {})
    };

    // Construct goal passed to coordinator
    const goal = objective;

    const task = await this.coordinator.submitScopedTask({
      goal,
      caller: verified,
      metadata
    });

    let publicTask = this.toPublicTask(task, verified.scope);

    this.eventBus?.emit({
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

  /**
   * Executes a pending or submitted task to completion.
   */
  public async runTask(caller: CallerContext, taskId: string): Promise<PublicTaskView> {
    const verified = this.requirePermission(caller, 'WRITE');
    const { task, scope } = this.loadScopedTask(taskId, verified);

    if (TaskStateMachine.isTerminal(task.status)) {
      return this.toPublicTask(task, scope);
    }

    const updated = await this.coordinator.runToCompletion(task.id);
    const publicTask = this.toPublicTask(updated, scope);

    this.eventBus?.emit({
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
      this.eventBus?.emit({
        type: 'approval.requested',
        scope,
        taskId: updated.id,
        data: { approvals: pending }
      });
    }

    return publicTask;
  }

  /**
   * Cancels a non-terminal task safely.
   */
  public cancelTask(caller: CallerContext, taskId: string, reason?: string): PublicTaskView {
    const verified = this.requirePermission(caller, 'WRITE');
    const { task, scope } = this.loadScopedTask(taskId, verified);

    if (task.status === 'CANCELLED') {
      return this.toPublicTask(task, scope);
    }

    if (TaskStateMachine.isTerminal(task.status)) {
      throw new InvalidStateTransitionError(task.status, 'CANCELLED', task.id);
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
    this.eventBus?.emit({
      type: 'task.updated',
      scope,
      taskId: updated.id,
      data: { task: publicTask }
    });

    return publicTask;
  }

  /**
   * Retrieves full details, plan steps, approvals, and audit events for a task.
   */
  public getTask(caller: CallerContext, taskId: string): TaskDetailsView {
    const verified = this.requirePermission(caller, 'READ');
    const { task, scope } = this.loadScopedTask(taskId, verified);

    const steps = this.taskRepo.getStepsByTaskId(task.id).map((s) => this.toPublicStep(s));
    const approvals = this.taskRepo
      .getApprovalRequestsByTaskId(task.id)
      .map((a) => this.toPublicApproval(a));
    const auditEvents = this.auditRepo
      .getEventsByTaskId(task.id)
      .map((e) => this.toPublicAuditEvent(e));
    const usage = this.budgetTracker
      ? this.budgetTracker.getUsageForTask(task.id)
      : { promptTokens: 0, completionTokens: 0, totalTokens: 0, totalCostUsd: 0 };

    return {
      task: this.toPublicTask(task, scope),
      steps,
      approvals,
      auditEvents,
      usage
    };
  }

  /**
   * Retrieves the structured execution result of a task.
   */
  public getTaskResult(caller: CallerContext, taskId: string): BusinessTaskResultView {
    const verified = this.requirePermission(caller, 'READ');
    const { task } = this.loadScopedTask(taskId, verified);

    const meta = safeJsonParse(task.metadataJson);
    const steps = this.taskRepo.getStepsByTaskId(task.id);
    const usage = this.budgetTracker ? this.budgetTracker.getUsageForTask(task.id) : undefined;

    let output: unknown = meta.output ?? meta.agentOutput ?? null;

    // If no direct agent output is present, collect step tool outputs
    if (output === null && steps.length > 0) {
      const stepOutputs: Record<string, unknown>[] = [];
      for (const step of steps) {
        const execs = this.taskRepo.getToolExecutionsByStepId(step.id);
        const last = execs[execs.length - 1];
        if (last) {
          stepOutputs.push({
            stepOrder: step.stepOrder,
            toolName: step.toolName,
            output: safeJsonParse(last.outputJson)
          });
        }
      }
      if (stepOutputs.length > 0) {
        output = stepOutputs;
      }
    }

    const durationMs = typeof meta.durationMs === 'number' ? meta.durationMs : null;
    const stepsExecuted = typeof meta.stepsExecuted === 'number' ? meta.stepsExecuted : steps.length;
    const summary = typeof meta.summary === 'string' ? defaultSecretScrubber.scrub(meta.summary) : undefined;
    const error = task.errorSummary ?? (typeof meta.error === 'string' ? defaultSecretScrubber.scrub(meta.error) : undefined);
    const agentId = typeof meta.agentId === 'string' ? meta.agentId : undefined;

    return {
      taskId: task.id,
      goal: defaultSecretScrubber.scrub(task.goal),
      status: task.status,
      agentId,
      output: scrubPublicValue(output),
      summary,
      error,
      completedAt: task.completedAt,
      durationMs,
      stepsExecuted,
      usage: usage
        ? {
            promptTokens: usage.promptTokens,
            completionTokens: usage.completionTokens,
            totalTokens: usage.totalTokens,
            totalCostUsd: usage.totalCostUsd,
            totalPromptTokens: usage.promptTokens,
            totalCompletionTokens: usage.completionTokens
          }
        : undefined
    };
  }

  /**
   * Lists tasks within the authorized caller scope with optional filtering and pagination.
   */
  public listTasks(
    caller: CallerContext,
    filter: ListBusinessTasksFilter = {}
  ): { tasks: PublicTaskView[]; total: number } {
    const verified = this.requirePermission(caller, 'READ');
    const limit = Math.min(200, Math.max(1, filter.limit ?? 50));
    const offset = Math.max(0, filter.offset ?? 0);

    const matched: PublicTaskView[] = [];
    const batchSize = 200;
    let scanOffset = 0;

    while (true) {
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
          const publicTask = this.toPublicTask(task, taskScope);
          // Agent filtering if requested
          if (filter.agentId && publicTask.metadata.agentId !== filter.agentId) {
            continue;
          }
          matched.push(publicTask);
        }
      }
      if (rows.length < batchSize) {
        break;
      }
      scanOffset += batchSize;
    }

    const total = matched.length;
    const paged = matched.slice(offset, offset + limit);
    return { tasks: paged, total };
  }

  // --- Internal Helpers ---

  private loadScopedTask(
    taskId: string,
    caller: CallerContext
  ): { task: Task; scope: ScopeIdentifier } {
    if (!taskId || taskId.trim() === '') {
      throw new ValidationError('Task ID must be provided.');
    }
    const task = this.taskRepo.getTaskById(taskId);
    if (!task) {
      throw new TaskNotFoundError(taskId);
    }

    let taskScope: ScopeIdentifier | null = null;
    try {
      taskScope = this.coordinator.verifyTaskScope(task);
    } catch {
      taskScope = null;
    }

    if (!taskScope) {
      throw new SecurityViolationError(
        `Task '${taskId}' has missing or untrusted scope attestation.`,
        'UNATTESTED_TASK_SCOPE'
      );
    }

    if (
      taskScope.scopeType !== caller.scope.scopeType ||
      taskScope.scopeId !== caller.scope.scopeId
    ) {
      throw new SecurityViolationError(
        `Caller scope '${caller.scope.scopeType}:${caller.scope.scopeId}' does not match task scope '${taskScope.scopeType}:${taskScope.scopeId}'.`,
        'TASK_CALLER_SCOPE_MISMATCH'
      );
    }

    return { task, scope: taskScope };
  }

  private tryVerifyTaskScope(task: Task): ScopeIdentifier | null {
    try {
      return this.coordinator.verifyTaskScope(task);
    } catch {
      return null;
    }
  }

  private requirePermission(
    caller: CallerContext,
    permission: 'READ' | 'WRITE'
  ): CallerContext {
    const verified = this.authorizer.verify(caller);
    validateScope(verified.scope.scopeType, verified.scope.scopeId);

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

  private toPublicTask(task: Task, scope: ScopeIdentifier): PublicTaskView {
    return {
      id: task.id,
      goal: defaultSecretScrubber.scrub(task.goal),
      status: task.status,
      currentStepIndex: task.currentStepIndex,
      scope: { scopeType: scope.scopeType, scopeId: scope.scopeId },
      metadata: scrubPublicValue(safeJsonParse(task.metadataJson)) as Record<string, unknown>,
      createdAt: task.createdAt,
      updatedAt: task.updatedAt,
      completedAt: task.completedAt,
      errorSummary: task.errorSummary ? defaultSecretScrubber.scrub(task.errorSummary) : null
    };
  }

  private toPublicStep(step: TaskStep): Record<string, unknown> {
    return {
      id: step.id,
      taskId: step.taskId,
      stepOrder: step.stepOrder,
      description: defaultSecretScrubber.scrub(step.description),
      toolName: step.toolName,
      toolArguments: scrubPublicValue(safeJsonParse(step.toolArgumentsJson)),
      status: step.status,
      retryCount: step.retryCount,
      maxRetries: step.maxRetries,
      createdAt: step.createdAt,
      completedAt: step.completedAt
    };
  }

  private toPublicApproval(req: any): PublicApprovalView {
    return {
      id: req.id,
      taskId: req.taskId,
      stepId: req.stepId,
      riskTier: req.riskTier,
      actionSummary: defaultSecretScrubber.scrub(req.actionSummary),
      targetResource: defaultSecretScrubber.scrub(req.targetResource),
      parameterDiff: scrubPublicValue(safeJsonParse(req.parameterDiffJson)) as Record<string, unknown>,
      decision: req.decision,
      decidedBy: req.decidedBy,
      decidedAt: req.decidedAt,
      expiresAt: req.expiresAt,
      createdAt: req.createdAt
    };
  }

  private toPublicAuditEvent(event: any): Record<string, unknown> {
    return {
      id: event.id,
      taskId: event.taskId,
      eventType: event.eventType,
      actor: event.actor,
      details: scrubPublicValue(safeJsonParse(event.detailsJson)),
      timestamp: event.timestamp
    };
  }
}
