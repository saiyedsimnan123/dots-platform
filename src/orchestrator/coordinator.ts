/**
 * Next-Generation Dots AI Platform - Task Coordinator
 * 
 * Architectural Mandate:
 * Orchestrates the end-to-end task lifecycle across the modular subsystems:
 * Ingestion -> Persistence -> Model Planning -> Policy Evaluation -> Sandboxed Tool Execution ->
 * Closed-Loop Verification -> State Commit -> Evidence Attachment.
 */

import type { Task, TaskStep, ToolExecution } from '../domain/types.ts';
import type { TaskRepository } from '../storage/task-repository.ts';
import type { AuditRepository } from '../storage/audit-repository.ts';
import type { IModelProvider } from '../model/types.ts';
import type { ToolRegistry } from '../tools/registry.ts';
import type { PolicyEngine } from '../security/policy-engine.ts';
import type { ApprovalBroker } from '../security/approval-broker.ts';
import type { VerificationEngine } from '../verification/verifier.ts';
import type { TokenBudgetTracker } from '../model/budget-tracker.ts';
import { TaskStateMachine } from '../domain/state-machine.ts';
import { TaskNotFoundError } from '../domain/errors.ts';

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

  constructor(options: CoordinatorOptions) {
    this.taskRepo = options.taskRepo;
    this.auditRepo = options.auditRepo;
    this.modelProvider = options.modelProvider;
    this.toolRegistry = options.toolRegistry;
    this.policyEngine = options.policyEngine;
    this.approvalBroker = options.approvalBroker;
    this.verifier = options.verifier;
    this.budgetTracker = options.budgetTracker;
    this.workspaceRoot = options.workspaceRoot;
  }

  /**
   * Ingests a new task, persists it in SUBMITTED state, and writes the audit event.
   */
  public async submitTask(goal: string, metadata?: Record<string, unknown>): Promise<Task> {
    const task = this.taskRepo.createTask({ goal, metadata });

    this.auditRepo.appendEvent({
      taskId: task.id,
      eventType: 'TASK_CREATED',
      actor: 'USER',
      details: { goal, metadata }
    });

    return task;
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
  public async runToCompletion(taskId: string, maxIterations: number = 25): Promise<Task> {
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
    const availableTools = this.toolRegistry.listDefinitions();
    
    // Generate structured plan via model provider
    const planResult = await this.modelProvider.generatePlan(task.goal, availableTools);

    // Track token usage and enforce budget
    this.budgetTracker.recordUsage(
      task.id,
      this.modelProvider.name,
      this.modelProvider.modelId,
      planResult.usage
    );

    // Persist plan steps in task_steps table
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

    const steps = this.taskRepo.getStepsByTaskId(task.id);
    if (steps.length === 0) {
      return this.taskRepo.updateTaskStatus(
        task.id,
        'PLANNING',
        'FAILED',
        'Model generated empty plan with zero actionable steps.'
      );
    }

    // Inspect first step for policy check
    const firstStep = steps[0]!;
    const tool = this.toolRegistry.get(firstStep.toolName);
    const riskTier = tool ? tool.riskTier : 'TIER_1';
    const policy = this.policyEngine.evaluate(firstStep.toolName, JSON.parse(firstStep.toolArgumentsJson), riskTier);

    if (policy.approvalRequired) {
      this.approvalBroker.requestApproval({
        taskId: task.id,
        stepId: firstStep.id,
        riskTier,
        actionSummary: `Execute tool '${firstStep.toolName}'`,
        targetResource: String(policy.sanitizedArguments.path || firstStep.toolName),
        parameterDiff: policy.sanitizedArguments
      });

      return this.taskRepo.updateTaskStatus(task.id, 'PLANNING', 'AWAITING_APPROVAL');
    }

    return this.taskRepo.updateTaskStatus(task.id, 'PLANNING', 'EXECUTING');
  }

  private async handleAwaitingApproval(task: Task): Promise<Task> {
    // Check if pending approvals for this task have been approved
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
      // All steps already completed
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
      // Check if an approved approval token exists for this step
      const approvals = this.taskRepo.getApprovalRequestsByTaskId(task.id);
      const stepApproval = approvals.find((a) => a.stepId === activeStep.id && a.decision === 'APPROVED');

      // Execute through the tool registry and sandbox
      const execResult = await this.toolRegistry.execute(
        activeStep.toolName,
        toolArgs,
        context,
        this.policyEngine,
        this.approvalBroker,
        stepApproval?.approvalToken
      );

      // Record tool execution log
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
      // Step failed
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

    // Default verification: assert exit code was 0
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

      // Check if more steps remain
      const remaining = steps.filter((s) => s.id !== activeStep.id && s.status === 'PENDING');
      if (remaining.length > 0) {
        this.taskRepo.updateCurrentStepIndex(task.id, activeStep.stepOrder);
        return this.taskRepo.updateTaskStatus(task.id, 'VERIFYING', 'PLANNING');
      }

      // All steps verified successfully! Transition to COMPLETED
      return this.taskRepo.updateTaskStatus(task.id, 'VERIFYING', 'COMPLETED');
    } else {
      // Verification failed
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

    // Check bounded retries
    if (failedStep.retryCount < failedStep.maxRetries) {
      const nextRetry = failedStep.retryCount + 1;
      this.taskRepo.updateStepStatus(failedStep.id, 'PENDING', nextRetry);

      this.auditRepo.appendEvent({
        taskId: task.id,
        eventType: 'RECOVERY_ATTEMPTED',
        actor: 'SYSTEM',
        details: {
          stepId: failedStep.id,
          retryCount: nextRetry,
          maxRetries: failedStep.maxRetries
        }
      });

      return this.taskRepo.updateTaskStatus(task.id, 'RECOVERING', 'EXECUTING');
    }

    // Retries exhausted: transition task to FAILED
    return this.taskRepo.updateTaskStatus(
      task.id,
      'RECOVERING',
      'FAILED',
      `Step ${failedStep.stepOrder} ('${failedStep.toolName}') exhausted retry budget (${failedStep.maxRetries}/${failedStep.maxRetries}).`
    );
  }
}
