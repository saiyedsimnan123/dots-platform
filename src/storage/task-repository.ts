/**
 * Next-Generation Dots AI Platform - Task Repository
 * 
 * Architectural Mandate:
 * Implements durable, ACID-compliant persistence for all workflow tasks, steps,
 * tool executions, verifications, and approvals.
 * 
 * Guarantees:
 * 1. 100% parameterized SQL to prevent SQL injection.
 * 2. Optimistic concurrency control via atomic status updates.
 * 3. Application-level validation of FSM state transitions before database write.
 */

import { randomUUID } from 'node:crypto';
import { DatabaseManager } from './db.ts';
import type {
  Task,
  TaskStatus,
  TaskStep,
  TaskStepStatus,
  ToolExecution,
  VerificationRecord,
  ApprovalRequest,
  ApprovalDecision,
  CreateTaskInput,
  CreateStepInput,
  CreateToolExecutionInput,
  CreateVerificationInput,
  CreateApprovalInput
} from '../domain/types.ts';
import { TaskStateMachine } from '../domain/state-machine.ts';
import {
  TaskNotFoundError,
  ConcurrencyConflictError,
  ValidationError
} from '../domain/errors.ts';

interface TaskDbRow {
  id: string;
  goal: string;
  status: string;
  current_step_index: number;
  created_at: string;
  updated_at: string;
  completed_at: string | null;
  error_summary: string | null;
  metadata_json: string | null;
}

interface StepDbRow {
  id: string;
  task_id: string;
  step_order: number;
  description: string;
  tool_name: string;
  tool_arguments_json: string;
  status: string;
  retry_count: number;
  max_retries: number;
  created_at: string;
  completed_at: string | null;
}

interface ToolExecutionDbRow {
  id: string;
  step_id: string;
  tool_name: string;
  input_json: string;
  output_json: string;
  exit_code: number;
  duration_ms: number;
  created_at: string;
}

interface VerificationDbRow {
  id: string;
  step_id: string;
  check_type: string;
  passed: number;
  expected_value: string;
  actual_value: string;
  evidence_data_json: string;
  verified_at: string;
}

interface ApprovalDbRow {
  id: string;
  task_id: string;
  step_id: string;
  risk_tier: string;
  action_summary: string;
  target_resource: string;
  parameter_diff_json: string;
  approval_token: string;
  decision: string;
  decided_by: string | null;
  decided_at: string | null;
  expires_at: string;
  created_at: string;
}

export class TaskRepository {
  private readonly db: DatabaseManager;

  constructor(db: DatabaseManager) {
    this.db = db;
  }

  /**
   * Creates and persists a new task in SUBMITTED state.
   */
  public createTask(input: CreateTaskInput): Task {
    if (!input.goal || input.goal.trim() === '') {
      throw new ValidationError('Task goal must not be empty.');
    }

    const id = input.id ?? randomUUID();
    const now = new Date().toISOString();
    const metadataJson = input.metadata ? JSON.stringify(input.metadata) : null;

    const stmt = this.db.prepare(`
      INSERT INTO tasks (
        id, goal, status, current_step_index, created_at, updated_at,
        completed_at, error_summary, metadata_json
      ) VALUES (?, ?, 'SUBMITTED', 0, ?, ?, NULL, NULL, ?)
    `);

    stmt.run(id, input.goal.trim(), now, now, metadataJson);

    return {
      id,
      goal: input.goal.trim(),
      status: 'SUBMITTED',
      currentStepIndex: 0,
      createdAt: now,
      updatedAt: now,
      completedAt: null,
      errorSummary: null,
      metadataJson
    };
  }

  /**
   * Retrieves a task by its unique ID.
   */
  public getTaskById(id: string): Task | null {
    const stmt = this.db.prepare('SELECT * FROM tasks WHERE id = ?');
    const row = stmt.get(id) as unknown as TaskDbRow | undefined;
    if (!row) {
      return null;
    }
    return this.mapTaskRow(row);
  }

  /**
   * Lists tasks with optional status filter, limit, and offset.
   */
  public listTasks(options: { status?: TaskStatus; limit?: number; offset?: number } = {}): Task[] {
    const limit = options.limit ?? 50;
    const offset = options.offset ?? 0;

    if (options.status) {
      const stmt = this.db.prepare(
        'SELECT * FROM tasks WHERE status = ? ORDER BY created_at DESC LIMIT ? OFFSET ?'
      );
      const rows = stmt.all(options.status, limit, offset) as unknown as TaskDbRow[];
      return rows.map((r) => this.mapTaskRow(r));
    }

    const stmt = this.db.prepare(
      'SELECT * FROM tasks ORDER BY created_at DESC LIMIT ? OFFSET ?'
    );
    const rows = stmt.all(limit, offset) as unknown as TaskDbRow[];
    return rows.map((r) => this.mapTaskRow(r));
  }

  /**
   * Atomically updates a task's status with FSM transition validation and optimistic locking.
   * Throws InvalidStateTransitionError if transition is illegal.
   * Throws ConcurrencyConflictError if task was modified concurrently.
   * Throws TaskNotFoundError if task does not exist.
   */
  public updateTaskStatus(
    taskId: string,
    expectedCurrentStatus: TaskStatus,
    newStatus: TaskStatus,
    errorSummary?: string
  ): Task {
    // 1. Validate state transition in application code
    TaskStateMachine.assertCanTransition(expectedCurrentStatus, newStatus, taskId);

    const now = new Date().toISOString();
    const isTerminal = TaskStateMachine.isTerminal(newStatus);
    const completedAt = isTerminal ? now : null;

    // 2. Execute atomic update conditioned on expected current status (Optimistic Concurrency)
    const stmt = this.db.prepare(`
      UPDATE tasks
      SET status = ?,
          updated_at = ?,
          completed_at = COALESCE(?, completed_at),
          error_summary = COALESCE(?, error_summary)
      WHERE id = ? AND status = ?
    `);

    const result = stmt.run(
      newStatus,
      now,
      completedAt,
      errorSummary ?? null,
      taskId,
      expectedCurrentStatus
    );

    // 3. Handle conflict or non-existence
    if (result.changes === 0) {
      const existing = this.getTaskById(taskId);
      if (!existing) {
        throw new TaskNotFoundError(taskId);
      }
      throw new ConcurrencyConflictError(taskId, expectedCurrentStatus, existing.status);
    }

    const updated = this.getTaskById(taskId);
    if (!updated) {
      throw new TaskNotFoundError(taskId);
    }
    return updated;
  }

  /**
   * Updates currentStepIndex on a task.
   */
  public updateCurrentStepIndex(taskId: string, stepIndex: number): void {
    const now = new Date().toISOString();
    const stmt = this.db.prepare(`
      UPDATE tasks SET current_step_index = ?, updated_at = ? WHERE id = ?
    `);
    const result = stmt.run(stepIndex, now, taskId);
    if (result.changes === 0) {
      throw new TaskNotFoundError(taskId);
    }
  }

  /**
   * Creates and persists a plan step for a task.
   */
  public createStep(input: CreateStepInput): TaskStep {
    const id = input.id ?? randomUUID();
    const now = new Date().toISOString();
    const argsJson = JSON.stringify(input.toolArguments);
    const maxRetries = input.maxRetries ?? 2;

    const stmt = this.db.prepare(`
      INSERT INTO task_steps (
        id, task_id, step_order, description, tool_name, tool_arguments_json,
        status, retry_count, max_retries, created_at, completed_at
      ) VALUES (?, ?, ?, ?, ?, ?, 'PENDING', 0, ?, ?, NULL)
    `);

    stmt.run(
      id,
      input.taskId,
      input.stepOrder,
      input.description,
      input.toolName,
      argsJson,
      maxRetries,
      now
    );

    return {
      id,
      taskId: input.taskId,
      stepOrder: input.stepOrder,
      description: input.description,
      toolName: input.toolName,
      toolArgumentsJson: argsJson,
      status: 'PENDING',
      retryCount: 0,
      maxRetries,
      createdAt: now,
      completedAt: null
    };
  }

  /**
   * Lists all steps for a given task, ordered by step_order.
   */
  public getStepsByTaskId(taskId: string): TaskStep[] {
    const stmt = this.db.prepare(
      'SELECT * FROM task_steps WHERE task_id = ? ORDER BY step_order ASC'
    );
    const rows = stmt.all(taskId) as unknown as StepDbRow[];
    return rows.map((r) => this.mapStepRow(r));
  }

  /**
   * Retrieves a single step by ID.
   */
  public getStepById(stepId: string): TaskStep | null {
    const stmt = this.db.prepare('SELECT * FROM task_steps WHERE id = ?');
    const row = stmt.get(stepId) as unknown as StepDbRow | undefined;
    if (!row) {
      return null;
    }
    return this.mapStepRow(row);
  }

  /**
   * Updates step execution status and optional retry count.
   */
  public updateStepStatus(
    stepId: string,
    status: TaskStepStatus,
    retryCount?: number
  ): TaskStep {
    const isCompleted = status === 'VERIFIED' || status === 'FAILED' || status === 'SKIPPED';
    const completedAt = isCompleted ? new Date().toISOString() : null;

    let stmt: ReturnType<typeof this.db.prepare>;
    let result: { changes: number | bigint };

    if (retryCount !== undefined) {
      stmt = this.db.prepare(`
        UPDATE task_steps
        SET status = ?,
            retry_count = ?,
            completed_at = COALESCE(?, completed_at)
        WHERE id = ?
      `);
      result = stmt.run(status, retryCount, completedAt, stepId);
    } else {
      stmt = this.db.prepare(`
        UPDATE task_steps
        SET status = ?,
            completed_at = COALESCE(?, completed_at)
        WHERE id = ?
      `);
      result = stmt.run(status, completedAt, stepId);
    }

    if (result.changes === 0) {
      throw new ValidationError(`Task step with ID '${stepId}' not found.`);
    }

    const updated = this.getStepById(stepId);
    if (!updated) {
      throw new ValidationError(`Task step with ID '${stepId}' not found.`);
    }
    return updated;
  }

  /**
   * Records a completed tool execution in the audit store.
   */
  public recordToolExecution(input: CreateToolExecutionInput): ToolExecution {
    const id = input.id ?? randomUUID();
    const now = new Date().toISOString();
    const inputJson = JSON.stringify(input.input);
    const outputJson = JSON.stringify(input.output);

    const stmt = this.db.prepare(`
      INSERT INTO tool_executions (
        id, step_id, tool_name, input_json, output_json, exit_code, duration_ms, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      id,
      input.stepId,
      input.toolName,
      inputJson,
      outputJson,
      input.exitCode,
      input.durationMs,
      now
    );

    return {
      id,
      stepId: input.stepId,
      toolName: input.toolName,
      inputJson,
      outputJson,
      exitCode: input.exitCode,
      durationMs: input.durationMs,
      createdAt: now
    };
  }

  /**
   * Retrieves tool executions for a step.
   */
  public getToolExecutionsByStepId(stepId: string): ToolExecution[] {
    const stmt = this.db.prepare(
      'SELECT * FROM tool_executions WHERE step_id = ? ORDER BY created_at ASC'
    );
    const rows = stmt.all(stepId) as unknown as ToolExecutionDbRow[];
    return rows.map((r) => ({
      id: r.id,
      stepId: r.step_id,
      toolName: r.tool_name,
      inputJson: r.input_json,
      outputJson: r.output_json,
      exitCode: r.exit_code,
      durationMs: r.duration_ms,
      createdAt: r.created_at
    }));
  }

  /**
   * Records a verification check.
   */
  public recordVerification(input: CreateVerificationInput): VerificationRecord {
    const id = input.id ?? randomUUID();
    const now = new Date().toISOString();
    const evidenceJson = JSON.stringify(input.evidenceData);

    const stmt = this.db.prepare(`
      INSERT INTO verifications (
        id, step_id, check_type, passed, expected_value, actual_value, evidence_data_json, verified_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      id,
      input.stepId,
      input.checkType,
      input.passed ? 1 : 0,
      input.expectedValue,
      input.actualValue,
      evidenceJson,
      now
    );

    return {
      id,
      stepId: input.stepId,
      checkType: input.checkType,
      passed: input.passed,
      expectedValue: input.expectedValue,
      actualValue: input.actualValue,
      evidenceDataJson: evidenceJson,
      verifiedAt: now
    };
  }

  /**
   * Retrieves verification records for a step.
   */
  public getVerificationsByStepId(stepId: string): VerificationRecord[] {
    const stmt = this.db.prepare(
      'SELECT * FROM verifications WHERE step_id = ? ORDER BY verified_at ASC'
    );
    const rows = stmt.all(stepId) as unknown as VerificationDbRow[];
    return rows.map((r) => ({
      id: r.id,
      stepId: r.step_id,
      checkType: r.check_type,
      passed: r.passed === 1,
      expectedValue: r.expected_value,
      actualValue: r.actual_value,
      evidenceDataJson: r.evidence_data_json,
      verifiedAt: r.verified_at
    }));
  }

  /**
   * Creates a human approval request.
   */
  public createApprovalRequest(input: CreateApprovalInput): ApprovalRequest {
    const id = input.id ?? randomUUID();
    const approvalToken = randomUUID();
    const now = new Date().toISOString();
    const expiresAt = input.expiresAt ?? new Date(Date.now() + 5 * 60 * 1000).toISOString();
    const diffJson = JSON.stringify(input.parameterDiff);

    const stmt = this.db.prepare(`
      INSERT INTO approval_requests (
        id, task_id, step_id, risk_tier, action_summary, target_resource,
        parameter_diff_json, approval_token, decision, decided_by, decided_at, expires_at, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'PENDING', NULL, NULL, ?, ?)
    `);

    stmt.run(
      id,
      input.taskId,
      input.stepId,
      input.riskTier,
      input.actionSummary,
      input.targetResource,
      diffJson,
      approvalToken,
      expiresAt,
      now
    );

    return {
      id,
      taskId: input.taskId,
      stepId: input.stepId,
      riskTier: input.riskTier,
      actionSummary: input.actionSummary,
      targetResource: input.targetResource,
      parameterDiffJson: diffJson,
      approvalToken,
      decision: 'PENDING',
      decidedBy: null,
      decidedAt: null,
      expiresAt,
      createdAt: now
    };
  }

  /**
   * Retrieves an approval request by its token.
   */
  public getApprovalRequestByToken(token: string): ApprovalRequest | null {
    const stmt = this.db.prepare('SELECT * FROM approval_requests WHERE approval_token = ?');
    const row = stmt.get(token) as unknown as ApprovalDbRow | undefined;
    if (!row) {
      return null;
    }
    return this.mapApprovalRow(row);
  }

  /**
   * Retrieves all approval requests for a task.
   */
  public getApprovalRequestsByTaskId(taskId: string): ApprovalRequest[] {
    const stmt = this.db.prepare('SELECT * FROM approval_requests WHERE task_id = ? ORDER BY created_at ASC');
    const rows = stmt.all(taskId) as unknown as ApprovalDbRow[];
    return rows.map((r) => this.mapApprovalRow(r));
  }

  /**
   * Updates an approval request decision.
   */
  public updateApprovalDecision(
    id: string,
    decision: ApprovalDecision,
    decidedBy: string
  ): ApprovalRequest {
    const now = new Date().toISOString();
    const stmt = this.db.prepare(`
      UPDATE approval_requests
      SET decision = ?, decided_by = ?, decided_at = ?
      WHERE id = ? AND decision = 'PENDING'
    `);
    const result = stmt.run(decision, decidedBy, now, id);

    if (result.changes === 0) {
      throw new ValidationError(`Approval request '${id}' is not in PENDING state or does not exist.`);
    }

    const stmtGet = this.db.prepare('SELECT * FROM approval_requests WHERE id = ?');
    const row = stmtGet.get(id) as unknown as ApprovalDbRow;
    return this.mapApprovalRow(row);
  }

  // --- Mapper Utilities ---

  private mapTaskRow(row: TaskDbRow): Task {
    return {
      id: row.id,
      goal: row.goal,
      status: row.status as TaskStatus,
      currentStepIndex: row.current_step_index,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      completedAt: row.completed_at,
      errorSummary: row.error_summary,
      metadataJson: row.metadata_json
    };
  }

  private mapStepRow(row: StepDbRow): TaskStep {
    return {
      id: row.id,
      taskId: row.task_id,
      stepOrder: row.step_order,
      description: row.description,
      toolName: row.tool_name,
      toolArgumentsJson: row.tool_arguments_json,
      status: row.status as TaskStepStatus,
      retryCount: row.retry_count,
      maxRetries: row.max_retries,
      createdAt: row.created_at,
      completedAt: row.completed_at
    };
  }

  private mapApprovalRow(row: ApprovalDbRow): ApprovalRequest {
    return {
      id: row.id,
      taskId: row.task_id,
      stepId: row.step_id,
      riskTier: row.risk_tier as ApprovalRequest['riskTier'],
      actionSummary: row.action_summary,
      targetResource: row.target_resource,
      parameterDiffJson: row.parameter_diff_json,
      approvalToken: row.approval_token,
      decision: row.decision as ApprovalDecision,
      decidedBy: row.decided_by,
      decidedAt: row.decided_at,
      expiresAt: row.expires_at,
      createdAt: row.created_at
    };
  }
}
