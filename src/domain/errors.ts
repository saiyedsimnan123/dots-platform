/**
 * Next-Generation Dots AI Platform - Domain Error Hierarchy
 * 
 * Architectural Mandate:
 * Use explicit, typed errors rather than generic Error instances.
 * Written with standard class fields (compatible with Node.js 24 strip-only mode).
 */

export class DomainError extends Error {
  public readonly code: string;
  public readonly details: Record<string, unknown>;

  constructor(
    message: string,
    code: string,
    details: Record<string, unknown> = {}
  ) {
    super(message);
    this.name = this.constructor.name;
    this.code = code;
    this.details = details;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Thrown when an illegal state transition is attempted on the Task FSM.
 */
export class InvalidStateTransitionError extends DomainError {
  public readonly fromStatus: string;
  public readonly toStatus: string;
  public readonly taskId?: string;

  constructor(
    fromStatus: string,
    toStatus: string,
    taskId?: string
  ) {
    super(
      `Cannot transition task ${taskId ? `'${taskId}' ` : ''}from '${fromStatus}' to '${toStatus}'.`,
      'INVALID_STATE_TRANSITION',
      { fromStatus, toStatus, taskId }
    );
    this.fromStatus = fromStatus;
    this.toStatus = toStatus;
    this.taskId = taskId;
  }
}

/**
 * Thrown when a requested task entity cannot be found.
 */
export class TaskNotFoundError extends DomainError {
  public readonly taskId: string;

  constructor(taskId: string) {
    super(`Task with ID '${taskId}' was not found.`, 'TASK_NOT_FOUND', { taskId });
    this.taskId = taskId;
  }
}

/**
 * Thrown when an optimistic concurrency update fails because the task was
 * mutated concurrently or was in a different state than expected.
 */
export class ConcurrencyConflictError extends DomainError {
  public readonly taskId: string;
  public readonly expectedStatus: string;
  public readonly actualStatus?: string;

  constructor(
    taskId: string,
    expectedStatus: string,
    actualStatus?: string
  ) {
    super(
      `Concurrency conflict on task '${taskId}': expected status '${expectedStatus}', but task state was modified.`,
      'CONCURRENCY_CONFLICT',
      { taskId, expectedStatus, actualStatus }
    );
    this.taskId = taskId;
    this.expectedStatus = expectedStatus;
    this.actualStatus = actualStatus;
  }
}

/**
 * Thrown when an input validation constraint is violated.
 */
export class ValidationError extends DomainError {
  constructor(message: string, details: Record<string, unknown> = {}) {
    super(message, 'VALIDATION_ERROR', details);
  }
}

/**
 * Thrown when a database-level constraint or execution error occurs.
 */
export class DatabaseError extends DomainError {
  constructor(message: string, details: Record<string, unknown> = {}) {
    super(message, 'DATABASE_ERROR', details);
  }
}

/**
 * Thrown when a security perimeter violation is detected (e.g. path traversal, unauthorized tool).
 */
export class SecurityViolationError extends DomainError {
  public readonly violationType: string;

  constructor(message: string, violationType: string, details: Record<string, unknown> = {}) {
    super(message, 'SECURITY_VIOLATION', { ...details, violationType });
    this.violationType = violationType;
  }
}

/**
 * Thrown when a tool execution fails.
 */
export class ToolExecutionError extends DomainError {
  public readonly toolName: string;
  public readonly exitCode: number;

  constructor(toolName: string, message: string, exitCode: number = 1, details: Record<string, unknown> = {}) {
    super(message, 'TOOL_EXECUTION_ERROR', { ...details, toolName, exitCode });
    this.toolName = toolName;
    this.exitCode = exitCode;
  }
}
