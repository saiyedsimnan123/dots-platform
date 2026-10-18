/**
 * Next-Generation Dots AI Platform - Task Coordinator
 * 
 * Architectural Mandate:
 * Orchestrates the end-to-end task lifecycle across the modular subsystems:
 * Ingestion -> Persistence -> Model Planning -> Policy Evaluation -> Sandboxed Tool Execution ->
 * Closed-Loop Verification -> State Commit -> Multi-Step Variable Chaining -> Bounded Recovery.
 * 
 * Enforces hard loop-prevention circuit breakers, bounded retries with backoff,
 * dynamic replanning on step failure, and automated rollback compensation.
 */

import type { Task, TaskStep, ToolExecution, CallerContext, ScopeIdentifier } from '../domain/types.ts';
import type { TaskRepository } from '../storage/task-repository.ts';
import type { AuditRepository } from '../storage/audit-repository.ts';
import type { IModelProvider } from '../model/types.ts';
import type { ToolRegistry } from '../tools/registry.ts';
import type { PolicyEngine } from '../security/policy-engine.ts';
import type { ApprovalBroker } from '../security/approval-broker.ts';
import type { VerificationEngine } from '../verification/verifier.ts';
import type { TokenBudgetTracker } from '../model/budget-tracker.ts';
import type { StepOutputContext } from './variable-resolver.ts';
import { VariableResolver } from './variable-resolver.ts';
import { CompensationManager } from './compensation.ts';
import { TaskStateMachine } from '../domain/state-machine.ts';
import { TaskNotFoundError, CircuitBreakerError, ValidationError, SecurityViolationError } from '../domain/errors.ts';
import type { MemoryService } from '../memory/memory-service.ts';
import type { HostMemoryAuthority } from '../security/host-authority.ts';
import { MemoryAuthorizer, validateScope } from '../security/memory-authorizer.ts';
import { PromptCompiler } from '../model/prompt-compiler.ts';
import { defaultSecretScrubber } from '../model/secret-scrubber.ts';

const NON_SENSITIVE_PROOF_WORDS = new Set([
  'waterproof',
  'bulletproof',
  'fireproof',
  'soundproof',
  'childproof',
  'foolproof',
  'shatterproof',
  'rustproof',
  'leakproof'
]);

function isSensitiveKey(key: string): boolean {
  if (typeof key !== 'string') {
    return false;
  }
  const trimmed = key.trim();
  if (!trimmed) {
    return false;
  }
  const normalized = trimmed.toLowerCase().replace(/[^a-z0-9]/g, '');
  if (!normalized) {
    return false;
  }

  if (NON_SENSITIVE_PROOF_WORDS.has(normalized)) {
    return false;
  }

  return (
    normalized.endsWith('password') ||
    normalized.endsWith('passphrase') ||
    normalized.endsWith('passwd') ||
    normalized.endsWith('secret') ||
    normalized.endsWith('secrets') ||
    normalized.endsWith('apikey') ||
    normalized.endsWith('privatekey') ||
    normalized.endsWith('token') ||
    normalized.endsWith('tokens') ||
    normalized === 'bearer' ||
    normalized === 'bearertoken' ||
    normalized.endsWith('credential') ||
    normalized.endsWith('credentials') ||
    normalized === 'auth' ||
    normalized === 'authorization' ||
    normalized === 'authtoken' ||
    normalized.endsWith('proof')
  );
}

function sanitizeValue(val: unknown): unknown {
  if (typeof val === 'string') {
    return defaultSecretScrubber.scrub(val);
  }
  if (Array.isArray(val)) {
    return val.map((item) => sanitizeValue(item));
  }
  if (val && typeof val === 'object') {
    const sanitizedObj: Record<string, unknown> = {};
    for (const [key, propVal] of Object.entries(val as Record<string, unknown>)) {
      if (isSensitiveKey(key)) {
        continue; // Never persist authentication credentials
      }
      sanitizedObj[key] = sanitizeValue(propVal);
    }
    return sanitizedObj;
  }
  return val;
}

function sanitizeMetadata(metadata?: Record<string, unknown>): Record<string, unknown> | undefined {
  if (!metadata || typeof metadata !== 'object' || Array.isArray(metadata)) {
    return undefined;
  }
  const sanitized: Record<string, unknown> = {};
  for (const [key, val] of Object.entries(metadata)) {
    if (isSensitiveKey(key)) {
      continue; // Never persist authentication credentials
    }
    sanitized[key] = sanitizeValue(val);
  }
  return sanitized;
}

export interface SubmitScopedTaskInput {
  readonly goal: string;
  readonly caller: CallerContext;
  readonly requestedScope?: ScopeIdentifier;
  readonly metadata?: Record<string, unknown>;
}

export interface CoordinatorOptions {
  readonly taskRepo: TaskRepository;
  readonly auditRepo: AuditRepository;
  readonly modelProvider: IModelProvider;
  readonly toolRegistry: ToolRegistry;
  readonly policyEngine: PolicyEngine;
  readonly approvalBroker: ApprovalBroker;
  readonly verifier: VerificationEngine;
  readonly budgetTracker: TokenBudgetTracker;
  readonly workspaceRoot: string;
  readonly memoryService?: MemoryService;
  readonly hostAuthority?: HostMemoryAuthority;
  readonly authorizer?: MemoryAuthorizer;
  readonly promptCompiler?: PromptCompiler;
  readonly backoffBaseMs?: number;       // Base delay in ms (0 in test environments)
  readonly backoffMaxMs?: number;        // Max retry backoff delay
  readonly enableDynamicReplan?: boolean; // Whether dynamic replanning is enabled on step failure (default: false)
  readonly maxReplans?: number;           // Max dynamic replanning attempts per task
  readonly maxPlanSteps?: number;         // Hard circuit breaker: max steps per plan
  readonly maxTotalRetries?: number;      // Hard circuit breaker: total task retry ceiling
  readonly enableCompensation?: boolean;  // Rollback scratch mutations on failure
}

export class TaskCoordinator {
  private readonly taskRepo: TaskRepository;
  private readonly auditRepo: AuditRepository;
  private readonly modelProvider: IModelProvider;
  private readonly toolRegistry: ToolRegistry;
  private readonly policyEngine: PolicyEngine;
  private readonly approvalBroker: ApprovalBroker;
  private readonly verifier: VerificationEngine;
  private readonly budgetTracker: TokenBudgetTracker;
  private readonly workspaceRoot: string;
  private readonly compensationManager: CompensationManager;
  private readonly backoffBaseMs: number;
  private readonly backoffMaxMs: number;
  private readonly enableDynamicReplan: boolean;
  private readonly maxReplans: number;
  private readonly maxPlanSteps: number;
  private readonly maxTotalRetries: number;
  private readonly enableCompensation: boolean;
  public readonly memoryService?: MemoryService;
  private readonly hostAuthority?: HostMemoryAuthority;
  public readonly authorizer?: MemoryAuthorizer;
  public readonly promptCompiler: PromptCompiler;

  constructor(options: CoordinatorOptions) {
    if (options.memoryService) {
      if (options.taskRepo.db !== options.auditRepo.db) {
        throw new ValidationError(
          'TaskRepository and AuditRepository must share the exact same DatabaseManager instance when memory integration is enabled.'
        );
      }
      if (options.memoryService.db !== options.taskRepo.db) {
        throw new ValidationError(
          'MemoryService, TaskRepository, and AuditRepository must share the exact same DatabaseManager instance.'
        );
      }
    }

    // Authorization boundary consistency: coordinator must bind to exactly one trusted authorization boundary
    if (options.authorizer && options.hostAuthority && options.authorizer !== options.hostAuthority.authorizer) {
      throw new ValidationError(
        'Coordinator authorizer must be the exact authorizer owned by its configured HostMemoryAuthority.'
      );
    }

    if (options.memoryService && options.hostAuthority) {
      if (!options.memoryService.hasAuthorizer(options.hostAuthority.authorizer)) {
        throw new ValidationError(
          'MemoryService and Coordinator must share the exact same MemoryAuthorizer instance owned by HostMemoryAuthority.'
        );
      }
    }

    if (options.memoryService && options.authorizer) {
      if (!options.memoryService.hasAuthorizer(options.authorizer)) {
        throw new ValidationError(
          'MemoryService and Coordinator must share the exact same MemoryAuthorizer instance.'
        );
      }
    }

    this.taskRepo = options.taskRepo;
    this.auditRepo = options.auditRepo;
    this.modelProvider = options.modelProvider;
    this.toolRegistry = options.toolRegistry;
    this.policyEngine = options.policyEngine;
    this.approvalBroker = options.approvalBroker;
    this.verifier = options.verifier;
    this.budgetTracker = options.budgetTracker;
    this.workspaceRoot = options.workspaceRoot;
    this.compensationManager = new CompensationManager(options.taskRepo, options.auditRepo, options.workspaceRoot);
    this.backoffBaseMs = options.backoffBaseMs ?? 0;
    this.backoffMaxMs = options.backoffMaxMs ?? 3000;
    this.enableDynamicReplan = options.enableDynamicReplan ?? false;
    this.maxReplans = options.maxReplans ?? 2;
    this.maxPlanSteps = options.maxPlanSteps ?? 8;
    this.maxTotalRetries = options.maxTotalRetries ?? 5;
    this.enableCompensation = options.enableCompensation ?? false;
    this.memoryService = options.memoryService;
    this.hostAuthority = options.hostAuthority;
    this.authorizer = options.hostAuthority ? options.hostAuthority.authorizer : options.authorizer;
    this.promptCompiler = options.promptCompiler ?? new PromptCompiler();
  }


  /**
   * Ingests a new legacy task, persists it in SUBMITTED state, and writes the audit event.
   * Legacy tasks submitted through this API are unattested and cannot access long-term memory.
   */
  public async submitTask(goal: string, metadata?: Record<string, unknown>): Promise<Task> {
    if (!goal || typeof goal !== 'string' || goal.trim() === '') {
      throw new ValidationError('Task goal must not be empty.');
    }

    const sanitizedMeta = sanitizeMetadata(metadata);
    const task = this.taskRepo.createTask({ goal: goal.trim(), metadata: sanitizedMeta });

    this.auditRepo.appendEvent({
      taskId: task.id,
      eventType: 'TASK_CREATED',
      actor: 'USER',
      details: {
        goal: task.goal,
        metadata: sanitizedMeta
      }
    });

    return task;
  }

  /**
   * Submits a task with authenticated caller context and cryptographically attested scope.
   * Derives authoritative task scope strictly from verified host authority.
   */
  public async submitScopedTask(input: SubmitScopedTaskInput): Promise<Task>;
  public async submitScopedTask(
    goal: string,
    caller: CallerContext,
    metadata?: Record<string, unknown>
  ): Promise<Task>;
  public async submitScopedTask(
    goalOrInput: string | SubmitScopedTaskInput,
    callerArg?: CallerContext,
    metadataArg?: Record<string, unknown>
  ): Promise<Task> {
    let goal: string;
    let caller: CallerContext;
    let requestedScope: ScopeIdentifier | undefined;
    let metadata: Record<string, unknown> | undefined;

    if (typeof goalOrInput === 'object' && goalOrInput !== null) {
      goal = goalOrInput.goal;
      caller = goalOrInput.caller;
      requestedScope = goalOrInput.requestedScope;
      metadata = goalOrInput.metadata;
    } else {
      goal = goalOrInput;
      caller = callerArg!;
      metadata = metadataArg;
    }

    if (!goal || typeof goal !== 'string' || goal.trim() === '') {
      throw new ValidationError('Task goal must not be empty.');
    }

    if (!caller || typeof caller !== 'object') {
      throw new ValidationError('CallerContext must be provided for scoped task submission.');
    }

    if (!this.authorizer || !this.hostAuthority) {
      throw new SecurityViolationError(
        'Host authorization boundary is not configured on coordinator. Cannot submit scoped tasks.',
        'MISSING_HOST_AUTHORITY'
      );
    }

    // 1. Authenticate caller and verify cryptographic proof & WeakSet containment
    const verifiedCaller = this.authorizer.verify(caller);

    // 2. Permission check: caller must have WRITE permission to submit tasks
    const permissions = verifiedCaller.permissions instanceof Set
      ? verifiedCaller.permissions
      : new Set(verifiedCaller.permissions);
    if (!permissions.has('WRITE')) {
      throw new SecurityViolationError(
        `Caller with actor '${verifiedCaller.actor}' lacks WRITE permission to create tasks in scope '${verifiedCaller.scope.scopeType}:${verifiedCaller.scope.scopeId}'.`,
        'PERMISSION_DENIED'
      );
    }

    // 3. Derive authoritative scope and validate
    const effectiveScope = verifiedCaller.scope;
    validateScope(effectiveScope.scopeType, effectiveScope.scopeId);

    // 4. If requestedScope is specified, it must strictly match the verified caller scope
    if (requestedScope) {
      validateScope(requestedScope.scopeType, requestedScope.scopeId);
      if (
        requestedScope.scopeType !== effectiveScope.scopeType ||
        requestedScope.scopeId !== effectiveScope.scopeId
      ) {
        throw new SecurityViolationError(
          `Requested scope '${requestedScope.scopeType}:${requestedScope.scopeId}' does not match authorized caller scope '${effectiveScope.scopeType}:${effectiveScope.scopeId}'.`,
          'TASK_CALLER_SCOPE_MISMATCH'
        );
      }
    }

    // 5. If metadata claims an explicit scope or workspaceId, reject if inconsistent
    if (metadata && typeof metadata === 'object') {
      if ('workspaceId' in metadata && typeof metadata.workspaceId === 'string') {
        if (effectiveScope.scopeType === 'WORKSPACE' && metadata.workspaceId !== effectiveScope.scopeId) {
          throw new SecurityViolationError(
            `Metadata workspaceId '${metadata.workspaceId}' does not match authorized scope '${effectiveScope.scopeId}'.`,
            'TASK_CALLER_SCOPE_MISMATCH'
          );
        }
      }
      if ('scope' in metadata && metadata.scope && typeof metadata.scope === 'object') {
        const metaScope = metadata.scope as ScopeIdentifier;
        if (metaScope.scopeType !== effectiveScope.scopeType || metaScope.scopeId !== effectiveScope.scopeId) {
          throw new SecurityViolationError(
            `Metadata scope '${metaScope.scopeType}:${metaScope.scopeId}' does not match authorized scope '${effectiveScope.scopeType}:${effectiveScope.scopeId}'.`,
            'TASK_CALLER_SCOPE_MISMATCH'
          );
        }
      }
    }

    // 6. Sanitize metadata to strip credentials, passwords, tokens, proofs
    const sanitizedMeta = sanitizeMetadata(metadata);

    // 7. Create task via privileged HostMemoryAuthority (generates cryptographic host attestation)
    const task = this.hostAuthority.createTask(this.taskRepo, {
      goal: goal.trim(),
      scope: effectiveScope,
      metadata: sanitizedMeta
    });

    // 8. Log tamper-evident audit event without credentials
    this.auditRepo.appendEvent({
      taskId: task.id,
      eventType: 'TASK_CREATED',
      actor: verifiedCaller.actor === 'SYSTEM' ? 'SYSTEM' : 'USER',
      details: {
        goal: task.goal,
        scope: effectiveScope,
        metadata: sanitizedMeta
      }
    });

    return task;
  }

  /**
   * Resolves and cryptographically verifies the authoritative scope of a task.
   * - Returns ScopeIdentifier if the task has a valid host attestation.
   * - Returns null if the task is an unattested legacy task (no _scopeAttestation).
   * - Throws SecurityViolationError if the task claims a scope attestation that is forged or tampered.
   */
  public verifyTaskScope(task: Task): ScopeIdentifier | null {
    if (!this.authorizer) {
      return null;
    }
    if (!task.metadataJson) {
      return null;
    }
    let meta: Record<string, unknown>;
    try {
      meta = JSON.parse(task.metadataJson);
    } catch {
      return null;
    }
    if (!meta._scopeAttestation) {
      return null;
    }
    return this.authorizer.verifyTaskScope(task);
  }

  /**
   * Executes the next logical step in the task lifecycle state machine.
   */
  public async step(taskId: string): Promise<Task> {
    const task = this.taskRepo.getTaskById(taskId);
    if (!task) {
      throw new TaskNotFoundError(taskId);
    }

    if (TaskStateMachine.isTerminal(task.status)) {
      return task;
    }

    switch (task.status) {
      case 'SUBMITTED':
        return await this.handleSubmitted(task);

      case 'PLANNING':
        return await this.handlePlanning(task);

      case 'AWAITING_APPROVAL':
        return await this.handleAwaitingApproval(task);

      case 'EXECUTING':
        return await this.handleExecuting(task);

      case 'VERIFYING':
        return await this.handleVerifying(task);

      case 'RECOVERING':
        return await this.handleRecovering(task);

      default:
        return task;
    }
  }

  /**
   * Runs the task lifecycle in a loop until reaching a terminal state or hitting maxIterations.
   */
  public async runToCompletion(taskId: string, maxIterations: number = 50): Promise<Task> {
    let currentTask = this.taskRepo.getTaskById(taskId);
    if (!currentTask) {
      throw new TaskNotFoundError(taskId);
    }

    let iterations = 0;
    while (!TaskStateMachine.isTerminal(currentTask.status) && iterations < maxIterations) {
      const prevStatus = currentTask.status;
      currentTask = await this.step(currentTask.id);
      iterations++;

      // If task remains paused in AWAITING_APPROVAL without an approval decision, stop loop
      if (currentTask.status === 'AWAITING_APPROVAL' && prevStatus === 'AWAITING_APPROVAL') {
        break;
      }
    }

    return currentTask;
  }

  // --- State Handlers ---

  private async handleSubmitted(task: Task): Promise<Task> {
    const updated = this.taskRepo.updateTaskStatus(task.id, 'SUBMITTED', 'PLANNING');
    this.auditRepo.appendEvent({
      taskId: task.id,
      eventType: 'STATE_TRANSITION',
      actor: 'SYSTEM',
      details: { from: 'SUBMITTED', to: 'PLANNING' }
    });
    return updated;
  }

  private async handlePlanning(task: Task): Promise<Task> {
    let steps = this.taskRepo.getStepsByTaskId(task.id);

    // Initial plan formulation if no steps exist yet
    if (steps.length === 0) {
      const availableTools = this.toolRegistry.listDefinitions();
      
      const planResult = await this.modelProvider.generatePlan(task.goal, availableTools);

      this.budgetTracker.recordUsage(
        task.id,
        this.modelProvider.name,
        this.modelProvider.modelId,
        planResult.usage
      );

      if (planResult.steps.length === 0) {
        return this.taskRepo.updateTaskStatus(
          task.id,
          'PLANNING',
          'FAILED',
          'Model generated empty plan with zero actionable steps.'
        );
      }

      // Hard circuit breaker on step count
      if (planResult.steps.length > this.maxPlanSteps) {
        return this.taskRepo.updateTaskStatus(
          task.id,
          'PLANNING',
          'FAILED',
          `Plan exceeded maximum allowed step limit (${planResult.steps.length} > ${this.maxPlanSteps}).`
        );
      }

      // Persist plan steps
      for (const step of planResult.steps) {
        this.taskRepo.createStep({
          taskId: task.id,
          stepOrder: step.stepOrder,
          description: step.description,
          toolName: step.toolName,
          toolArguments: step.arguments
        });
      }

      this.auditRepo.appendEvent({
        taskId: task.id,
        eventType: 'PLAN_GENERATED',
        actor: 'AGENT',
        details: {
          stepCount: planResult.steps.length,
          steps: planResult.steps,
          usage: planResult.usage
        }
      });

      steps = this.taskRepo.getStepsByTaskId(task.id);
    }

    // Identify next step to execute
    const nextStep = steps.find((s) => s.status === 'PENDING');
    if (!nextStep) {
      // All steps are completed or skipped
      return this.taskRepo.updateTaskStatus(task.id, 'PLANNING', 'EXECUTING');
    }

    // Collect completed step outputs for variable interpolation
    const verifiedSteps = steps.filter((s) => s.status === 'VERIFIED');
    const completedContexts: StepOutputContext[] = [];

    for (const vs of verifiedSteps) {
      const execs = this.taskRepo.getToolExecutionsByStepId(vs.id);
      const latest = execs.length > 0 ? execs[execs.length - 1] : null;
      const output = latest ? (JSON.parse(latest.outputJson) as Record<string, unknown>) : {};
      completedContexts.push({
        stepOrder: vs.stepOrder,
        toolName: vs.toolName,
        output
      });
    }

    // Resolve dynamic variables from predecessor step outputs
    const rawArgs = JSON.parse(nextStep.toolArgumentsJson) as Record<string, unknown>;
    let resolvedArgs: Record<string, unknown>;
    try {
      resolvedArgs = VariableResolver.resolve(rawArgs, completedContexts, nextStep.stepOrder);
      this.taskRepo.updateStepArguments(nextStep.id, resolvedArgs);
    } catch (err) {
      return this.taskRepo.updateTaskStatus(
        task.id,
        'PLANNING',
        'FAILED',
        `Step ${nextStep.stepOrder} variable resolution failed: ${err instanceof Error ? err.message : String(err)}`
      );
    }

    // Evaluate host security policy on resolved arguments
    const tool = this.toolRegistry.get(nextStep.toolName);
    const riskTier = tool ? tool.riskTier : 'TIER_1';
    const policy = this.policyEngine.evaluate(nextStep.toolName, resolvedArgs, riskTier);

    if (policy.approvalRequired) {
      this.approvalBroker.requestApproval({
        taskId: task.id,
        stepId: nextStep.id,
        riskTier,
        actionSummary: `Execute tool '${nextStep.toolName}'`,
        targetResource: String(policy.sanitizedArguments.path || nextStep.toolName),
        parameterDiff: policy.sanitizedArguments
      });

      return this.taskRepo.updateTaskStatus(task.id, 'PLANNING', 'AWAITING_APPROVAL');
    }

    return this.taskRepo.updateTaskStatus(task.id, 'PLANNING', 'EXECUTING');
  }

  private async handleAwaitingApproval(task: Task): Promise<Task> {
    const approvals = this.taskRepo.getApprovalRequestsByTaskId(task.id);
    const activeApproval = approvals.find((a) => a.decision === 'APPROVED' && this.approvalBroker.isApproved(a.approvalToken));

    if (activeApproval) {
      return this.taskRepo.updateTaskStatus(task.id, 'AWAITING_APPROVAL', 'EXECUTING');
    }

    const rejected = approvals.find((a) => a.decision === 'REJECTED');
    if (rejected) {
      return this.taskRepo.updateTaskStatus(task.id, 'AWAITING_APPROVAL', 'CANCELLED', 'Task rejected by user.');
    }

    return task;
  }

  private async handleExecuting(task: Task): Promise<Task> {
    const steps = this.taskRepo.getStepsByTaskId(task.id);
    const activeStep = steps.find((s) => s.status === 'PENDING' || s.status === 'EXECUTING');

    if (!activeStep) {
      return this.taskRepo.updateTaskStatus(task.id, 'EXECUTING', 'COMPLETED');
    }

    this.taskRepo.updateStepStatus(activeStep.id, 'EXECUTING');

    const toolArgs = JSON.parse(activeStep.toolArgumentsJson) as Record<string, unknown>;
    const context = {
      taskId: task.id,
      stepId: activeStep.id,
      workspaceRoot: this.workspaceRoot
    };

    try {
      const approvals = this.taskRepo.getApprovalRequestsByTaskId(task.id);
      const stepApproval = approvals.find((a) => a.stepId === activeStep.id && a.decision === 'APPROVED');

      const execResult = await this.toolRegistry.execute(
        activeStep.toolName,
        toolArgs,
        context,
        this.policyEngine,
        this.approvalBroker,
        stepApproval?.approvalToken
      );

      this.taskRepo.recordToolExecution({
        stepId: activeStep.id,
        toolName: activeStep.toolName,
        input: toolArgs,
        output: execResult.output,
        exitCode: execResult.exitCode,
        durationMs: execResult.durationMs
      });

      this.auditRepo.appendEvent({
        taskId: task.id,
        eventType: 'TOOL_EXECUTION_COMPLETED',
        actor: 'SYSTEM',
        details: {
          stepId: activeStep.id,
          toolName: activeStep.toolName,
          exitCode: execResult.exitCode,
          durationMs: execResult.durationMs
        }
      });

      return this.taskRepo.updateTaskStatus(task.id, 'EXECUTING', 'VERIFYING');
    } catch (err) {
      this.taskRepo.updateStepStatus(activeStep.id, 'FAILED');
      return this.taskRepo.updateTaskStatus(
        task.id,
        'EXECUTING',
        'RECOVERING',
        `Step ${activeStep.stepOrder} execution failed: ${err instanceof Error ? err.message : String(err)}`
      );
    }
  }

  private async handleVerifying(task: Task): Promise<Task> {
    const steps = this.taskRepo.getStepsByTaskId(task.id);
    const activeStep = steps.find((s) => s.status === 'EXECUTING');

    if (!activeStep) {
      return this.taskRepo.updateTaskStatus(task.id, 'VERIFYING', 'COMPLETED');
    }

    const execs = this.taskRepo.getToolExecutionsByStepId(activeStep.id);
    const latestExec = execs.length > 0 ? execs[execs.length - 1]! : null;

    if (!latestExec) {
      return this.taskRepo.updateTaskStatus(
        task.id,
        'VERIFYING',
        'RECOVERING',
        `No execution log found for step ${activeStep.stepOrder}`
      );
    }

    const verification = this.verifier.verify(activeStep, latestExec, {
      checkType: 'EXIT_CODE_ZERO',
      target: 'process',
      expectedValue: '0'
    });

    if (verification.passed) {
      this.taskRepo.updateStepStatus(activeStep.id, 'VERIFIED');
      this.auditRepo.appendEvent({
        taskId: task.id,
        eventType: 'EVIDENCE_VERIFIED',
        actor: 'SYSTEM',
        details: {
          stepId: activeStep.id,
          verificationOutcome: verification
        }
      });

      // Check if more pending steps remain
      const remaining = steps.filter((s) => s.id !== activeStep.id && s.status === 'PENDING');
      if (remaining.length > 0) {
        this.taskRepo.updateCurrentStepIndex(task.id, activeStep.stepOrder);
        return this.taskRepo.updateTaskStatus(task.id, 'VERIFYING', 'PLANNING');
      }

      // All plan steps completed and verified
      return this.taskRepo.updateTaskStatus(task.id, 'VERIFYING', 'COMPLETED');
    } else {
      return this.taskRepo.updateTaskStatus(
        task.id,
        'VERIFYING',
        'RECOVERING',
        `Verification assertion failed for step ${activeStep.stepOrder}: expected ${verification.expectedValue}, got ${verification.actualValue}`
      );
    }
  }

  private async handleRecovering(task: Task): Promise<Task> {
    const steps = this.taskRepo.getStepsByTaskId(task.id);
    const failedStep = steps.find((s) => s.status === 'FAILED');

    if (!failedStep) {
      return this.taskRepo.updateTaskStatus(task.id, 'RECOVERING', 'FAILED', 'No recoverable step identified.');
    }

    // Circuit breaker: task-wide total retries ceiling
    const totalRetries = steps.reduce((sum, s) => sum + s.retryCount, 0);
    if (totalRetries >= this.maxTotalRetries) {
      await this.handleTaskFailureCleanup(task);
      return this.taskRepo.updateTaskStatus(
        task.id,
        'RECOVERING',
        'FAILED',
        `Task tripped circuit breaker: exceeded maximum total retry limit (${totalRetries}/${this.maxTotalRetries}).`
      );
    }

    // 1. In-step bounded retry with exponential backoff
    if (failedStep.retryCount < failedStep.maxRetries) {
      const delay = this.calculateBackoffMs(failedStep.retryCount);
      if (delay > 0) {
        await new Promise((r) => setTimeout(r, delay));
      }

      const nextRetry = failedStep.retryCount + 1;
      this.taskRepo.updateStepStatus(failedStep.id, 'PENDING', nextRetry);

      this.auditRepo.appendEvent({
        taskId: task.id,
        eventType: 'RECOVERY_ATTEMPTED',
        actor: 'SYSTEM',
        details: {
          stepId: failedStep.id,
          retryCount: nextRetry,
          maxRetries: failedStep.maxRetries,
          backoffDelayMs: delay
        }
      });

      return this.taskRepo.updateTaskStatus(task.id, 'RECOVERING', 'EXECUTING');
    }

    // 2. Step retries exhausted: attempt Dynamic Replanning if enabled
    const taskMeta = task.metadataJson ? (JSON.parse(task.metadataJson) as Record<string, unknown>) : {};
    const dynamicReplanAllowed = Boolean(taskMeta.enableDynamicReplan ?? taskMeta.dynamicReplan ?? this.enableDynamicReplan);
    const events = this.auditRepo.getEventsByTaskId(task.id);
    const replansAttempted = events.filter((e) => e.eventType === 'DYNAMIC_REPLAN_ATTEMPTED').length;

    if (dynamicReplanAllowed && replansAttempted < this.maxReplans) {
      const verifiedSteps = steps.filter((s) => s.status === 'VERIFIED');

      const availableTools = this.toolRegistry.listDefinitions();

      const recoveryContext = `
Recovery Plan Required:
Task Goal: "${task.goal}"
Step ${failedStep.stepOrder} ('${failedStep.toolName}') failed after ${failedStep.retryCount} retries.
Failure Reason: ${task.errorSummary ?? 'Unknown tool error'}
Verified Predecessors: ${verifiedSteps.map((s) => `Step ${s.stepOrder} (${s.toolName})`).join(', ') || 'None'}
Please generate an alternative plan to complete the goal without repeating the failed action.
`.trim();

      try {
        const replanResult = await this.modelProvider.generatePlan(task.goal, availableTools, recoveryContext);

        this.budgetTracker.recordUsage(
          task.id,
          this.modelProvider.name,
          this.modelProvider.modelId,
          replanResult.usage
        );

        if (replanResult.steps.length > 0) {
          // Verify new steps do not breach maxPlanSteps
          if (steps.length + replanResult.steps.length > this.maxPlanSteps) {
            await this.handleTaskFailureCleanup(task);
            return this.taskRepo.updateTaskStatus(
              task.id,
              'RECOVERING',
              'FAILED',
              `Dynamic replan rejected: total steps would exceed limit (${steps.length + replanResult.steps.length} > ${this.maxPlanSteps}).`
            );
          }

          // Mark failed step as SKIPPED
          this.taskRepo.updateStepStatus(failedStep.id, 'SKIPPED');

          // Append new recovery steps starting after highest existing step order
          const maxOrder = Math.max(...steps.map((s) => s.stepOrder));
          for (let i = 0; i < replanResult.steps.length; i++) {
            const stepProposal = replanResult.steps[i]!;
            this.taskRepo.createStep({
              taskId: task.id,
              stepOrder: maxOrder + i + 1,
              description: stepProposal.description,
              toolName: stepProposal.toolName,
              toolArguments: stepProposal.arguments
            });
          }

          this.auditRepo.appendEvent({
            taskId: task.id,
            eventType: 'DYNAMIC_REPLAN_ATTEMPTED',
            actor: 'AGENT',
            details: {
              failedStepId: failedStep.id,
              replansAttempted: replansAttempted + 1,
              newStepsCount: replanResult.steps.length
            }
          });

          return this.taskRepo.updateTaskStatus(task.id, 'RECOVERING', 'PLANNING');
        }
      } catch (replanErr) {
        // Fall through to failure
      }
    }

    // 3. Recovery budget exhausted: execute rollback/compensation if enabled and fail task
    await this.handleTaskFailureCleanup(task);

    return this.taskRepo.updateTaskStatus(
      task.id,
      'RECOVERING',
      'FAILED',
      `Step ${failedStep.stepOrder} ('${failedStep.toolName}') exhausted retry budget (${failedStep.maxRetries}/${failedStep.maxRetries}) and replanning limit.`
    );
  }

  /**
   * Calculates exponential backoff delay with jitter.
   */
  private calculateBackoffMs(retryCount: number): number {
    if (this.backoffBaseMs === 0) return 0;
    const exponential = this.backoffBaseMs * Math.pow(2, retryCount);
    const capped = Math.min(exponential, this.backoffMaxMs);
    const jitter = capped * (0.8 + Math.random() * 0.4);
    return Math.floor(jitter);
  }

  /**
   * Executes compensation rollback when enabled on task failure.
   */
  private async handleTaskFailureCleanup(task: Task): Promise<void> {
    const meta = task.metadataJson ? (JSON.parse(task.metadataJson) as Record<string, unknown>) : {};
    const shouldCompensate = Boolean(meta.compensateOnFailure ?? meta.enableCompensation ?? this.enableCompensation);

    if (shouldCompensate) {
      try {
        await this.compensationManager.compensate(task.id);
      } catch (err) {
        // Safe guard: compensation error must never hide the original workflow failure
        this.auditRepo.appendEvent({
          taskId: task.id,
          eventType: 'COMPENSATION_EXECUTED',
          actor: 'SYSTEM',
          details: {
            status: 'FAILED',
            error: err instanceof Error ? err.message : String(err)
          }
        });
      }
    }
  }
}

