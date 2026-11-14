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

/**
 * Thrown when a multi-step workflow dependency resolution or execution fails.
 */
export class WorkflowExecutionError extends DomainError {
  public readonly stepOrder?: number;

  constructor(message: string, stepOrder?: number, details: Record<string, unknown> = {}) {
    super(message, 'WORKFLOW_EXECUTION_ERROR', { ...details, stepOrder });
    this.stepOrder = stepOrder;
  }
}

/**
 * Thrown when an automated safety circuit breaker is tripped (e.g. max retries, max steps, loop limit).
 */
export class CircuitBreakerError extends DomainError {
  public readonly breakerType: string;
  public readonly limit: number;
  public readonly current: number;

  constructor(message: string, breakerType: string, limit: number, current: number, details: Record<string, unknown> = {}) {
    super(message, 'CIRCUIT_BREAKER_TRIPPED', { ...details, breakerType, limit, current });
    this.breakerType = breakerType;
    this.limit = limit;
    this.current = current;
  }
}

/**
 * Thrown when a requested memory entity cannot be found.
 */
export class MemoryNotFoundError extends DomainError {
  public readonly memoryId: string;

  constructor(memoryId: string, details: Record<string, unknown> = {}) {
    super(`Memory with ID '${memoryId}' was not found.`, 'MEMORY_NOT_FOUND', { memoryId, ...details });
    this.memoryId = memoryId;
  }
}

/**
 * Thrown when an active memory key conflict occurs within the same scope.
 */
export class MemoryConflictError extends DomainError {
  public readonly key: string;
  public readonly scopeType: string;
  public readonly scopeId: string;

  constructor(key: string, scopeType: string, scopeId: string, details: Record<string, unknown> = {}) {
    super(
      `Active memory with key '${key}' already exists in scope '${scopeType}:${scopeId}'.`,
      'MEMORY_CONFLICT',
      { key, scopeType, scopeId, ...details }
    );
    this.key = key;
    this.scopeType = scopeType;
    this.scopeId = scopeId;
  }
}

/**
 * Thrown when cross-scope access is attempted on a memory record.
 */
export class MemoryScopeViolationError extends DomainError {
  public readonly expectedScope: string;
  public readonly actualScope: string;
  public readonly memoryId?: string;

  constructor(expectedScope: string, actualScope: string, memoryId?: string, details: Record<string, unknown> = {}) {
    super(
      `Memory scope violation: expected scope '${expectedScope}', but attempted operation in '${actualScope}'.`,
      'MEMORY_SCOPE_VIOLATION',
      { expectedScope, actualScope, memoryId, ...details }
    );
    this.expectedScope = expectedScope;
    this.actualScope = actualScope;
    this.memoryId = memoryId;
  }
}

/**
 * Thrown when a requested schedule entity cannot be found.
 */
export class ScheduleNotFoundError extends DomainError {
  public readonly scheduleId: string;

  constructor(scheduleId: string, details: Record<string, unknown> = {}) {
    super(`Schedule with ID '${scheduleId}' was not found.`, 'SCHEDULE_NOT_FOUND', { scheduleId, ...details });
    this.scheduleId = scheduleId;
  }
}

/**
 * Thrown when a schedule operation conflicts with its current state or uniqueness constraints.
 */
export class ScheduleConflictError extends DomainError {
  public readonly scheduleId: string;

  constructor(message: string, scheduleId: string, details: Record<string, unknown> = {}) {
    super(message, 'SCHEDULE_CONFLICT', { scheduleId, ...details });
    this.scheduleId = scheduleId;
  }
}

/**
 * Thrown when a requested agent cannot be found.
 */
export class AgentNotFoundError extends DomainError {
  public readonly agentId: string;

  constructor(agentId: string, details: Record<string, unknown> = {}) {
    super(`Agent with ID '${agentId}' was not found.`, 'AGENT_NOT_FOUND', { agentId, ...details });
    this.agentId = agentId;
  }
}

/**
 * Thrown when an agent registration conflicts with an already registered agent ID.
 */
export class DuplicateAgentRegistrationError extends DomainError {
  public readonly agentId: string;

  constructor(agentId: string, details: Record<string, unknown> = {}) {
    super(`Agent with ID '${agentId}' is already registered.`, 'DUPLICATE_AGENT_REGISTRATION', { agentId, ...details });
    this.agentId = agentId;
  }
}

/**
 * Thrown when an agent does not support a required capability.
 */
export class AgentCapabilityError extends DomainError {
  public readonly agentId: string;
  public readonly capability: string;

  constructor(agentId: string, capability: string, details: Record<string, unknown> = {}) {
    super(
      `Agent '${agentId}' does not support required capability '${capability}'.`,
      'UNSUPPORTED_CAPABILITY',
      { agentId, capability, ...details }
    );
    this.agentId = agentId;
    this.capability = capability;
  }
}

/**
 * Thrown when an agent execution fails.
 */
export class AgentExecutionError extends DomainError {
  public readonly agentId: string;

  constructor(agentId: string, message: string, details: Record<string, unknown> = {}) {
    super(message, 'AGENT_EXECUTION_ERROR', { agentId, ...details });
    this.agentId = agentId;
  }
}

/**
 * Thrown when an agent execution is cancelled.
 */
export class AgentCancelledError extends DomainError {
  public readonly agentId?: string;

  constructor(message: string = 'Agent execution was cancelled.', details: Record<string, unknown> = {}) {
    super(message, 'AGENT_CANCELLED', details);
    this.agentId = details.agentId as string | undefined;
  }
}

/**
 * Thrown when a requested conversation entity cannot be found.
 */
export class ConversationNotFoundError extends DomainError {
  public readonly conversationId: string;

  constructor(conversationId: string, details: Record<string, unknown> = {}) {
    super(`Conversation with ID '${conversationId}' was not found.`, 'CONVERSATION_NOT_FOUND', { conversationId, ...details });
    this.conversationId = conversationId;
  }
}

/**
 * Thrown when cross-scope access is attempted on a conversation record.
 */
export class ConversationScopeViolationError extends DomainError {
  public readonly expectedScope: string;
  public readonly actualScope: string;
  public readonly conversationId?: string;

  constructor(expectedScope: string, actualScope: string, conversationId?: string, details: Record<string, unknown> = {}) {
    super(
      `Conversation scope violation: expected scope '${expectedScope}', but attempted operation in '${actualScope}'.`,
      'CONVERSATION_SCOPE_VIOLATION',
      { expectedScope, actualScope, conversationId, ...details }
    );
    this.expectedScope = expectedScope;
    this.actualScope = actualScope;
    this.conversationId = conversationId;
  }
}




