/**
 * Next-Generation Dots AI Platform - Core Domain Types
 * 
 * Architectural Mandate:
 * Task state is trusted application data. All entities, transitions, and
 * metadata are strongly typed to prevent model-driven hallucinations from
 * corrupting the state machine or database.
 */

/**
 * High-level lifecycle states of a task.
 * Governed strictly by the TaskStateMachine.
 */
export type TaskStatus =
  | 'SUBMITTED'          // Initial state: recorded and waiting for coordinator
  | 'PLANNING'           // Formulating or dynamically updating the plan
  | 'AWAITING_APPROVAL'  // Paused pending human consent for Tier 3/4 action
  | 'EXECUTING'          // Active tool invocation inside sandbox
  | 'VERIFYING'          // Validating evidence and tangible side effects
  | 'RECOVERING'         // Handling a failed step within bounded retry limits
  | 'COMPLETED'          // Terminal: all plan steps verified successfully
  | 'FAILED'             // Terminal: fatal error or bounded retries exhausted
  | 'CANCELLED'          // Terminal: explicitly aborted by user
  | 'TIMED_OUT';         // Terminal: approval or execution ceiling exceeded

/**
 * Execution status for an individual step within a task plan.
 */
export type TaskStepStatus =
  | 'PENDING'            // Queued for execution
  | 'EXECUTING'          // In progress
  | 'VERIFIED'           // Tool finished and host assertions passed
  | 'FAILED'             // Execution or verification failed
  | 'SKIPPED';           // Bypassed due to plan mutation or prior failure

/**
 * Risk classification tiers for policy evaluation.
 * Enforced in trusted host code before tool execution.
 */
export type RiskTier =
  | 'TIER_0'             // Pure compute (in-memory, math, json format)
  | 'TIER_1'             // Read-only inspection within jailed workspace
  | 'TIER_2'             // Reversible mutation within jailed workspace scratch
  | 'TIER_3'             // Consequential actions (network, scripts, external writes)
  | 'TIER_4';            // High-risk/Destructive (deletions, system config)

/**
 * Human approval decision states.
 */
export type ApprovalDecision =
  | 'PENDING'
  | 'APPROVED'
  | 'REJECTED'
  | 'EXPIRED';

/**
 * Standard audit event categories.
 */
export type AuditEventType =
  | 'TASK_CREATED'
  | 'STATE_TRANSITION'
  | 'PLAN_GENERATED'
  | 'POLICY_EVALUATED'
  | 'APPROVAL_REQUESTED'
  | 'APPROVAL_DECIDED'
  | 'TOOL_EXECUTION_STARTED'
  | 'TOOL_EXECUTION_COMPLETED'
  | 'EVIDENCE_VERIFIED'
  | 'RECOVERY_ATTEMPTED'
  | 'TASK_COMPLETED'
  | 'TASK_FAILED'
  | 'TASK_CANCELLED'
  | 'CRASH_INTERRUPTION_DETECTED';

/**
 * Primary Task Entity.
 */
export interface Task {
  readonly id: string;
  readonly goal: string;
  readonly status: TaskStatus;
  readonly currentStepIndex: number;
  readonly createdAt: string;      // ISO 8601 UTC timestamp
  readonly updatedAt: string;      // ISO 8601 UTC timestamp
  readonly completedAt: string | null;
  readonly errorSummary: string | null;
  readonly metadataJson: string | null;
}

/**
 * Individual plan step within a task.
 */
export interface TaskStep {
  readonly id: string;
  readonly taskId: string;
  readonly stepOrder: number;
  readonly description: string;
  readonly toolName: string;
  readonly toolArgumentsJson: string;
  readonly status: TaskStepStatus;
  readonly retryCount: number;
  readonly maxRetries: number;
  readonly createdAt: string;
  readonly completedAt: string | null;
}

/**
 * Record of an executed tool invocation.
 */
export interface ToolExecution {
  readonly id: string;
  readonly stepId: string;
  readonly toolName: string;
  readonly inputJson: string;
  readonly outputJson: string;
  readonly exitCode: number;
  readonly durationMs: number;
  readonly createdAt: string;
}

/**
 * Tangible evidence record verifying a tool execution.
 */
export interface VerificationRecord {
  readonly id: string;
  readonly stepId: string;
  readonly checkType: string;       // e.g. "FILE_EXISTS", "HASH_MATCH", "SCHEMA_VALID"
  readonly passed: boolean;
  readonly expectedValue: string;
  readonly actualValue: string;
  readonly evidenceDataJson: string;
  readonly verifiedAt: string;
}

/**
 * Human-in-the-loop approval request.
 */
export interface ApprovalRequest {
  readonly id: string;
  readonly taskId: string;
  readonly stepId: string;
  readonly riskTier: RiskTier;
  readonly actionSummary: string;
  readonly targetResource: string;
  readonly parameterDiffJson: string;
  readonly approvalToken: string;   // High-entropy token for verification
  readonly decision: ApprovalDecision;
  readonly decidedBy: string | null;
  readonly decidedAt: string | null;
  readonly expiresAt: string;
  readonly createdAt: string;
}

/**
 * Immutable audit log entry.
 */
export interface AuditEvent {
  readonly id: string;
  readonly taskId: string;
  readonly eventType: AuditEventType;
  readonly actor: 'USER' | 'AGENT' | 'POLICY_ENGINE' | 'SYSTEM';
  readonly detailsJson: string;
  readonly payloadHash: string;     // SHA-256 digest of details
  readonly timestamp: string;
}

/**
 * Input DTO for creating a new Task.
 */
export interface CreateTaskInput {
  readonly id?: string;
  readonly goal: string;
  readonly metadata?: Record<string, unknown>;
}

/**
 * Input DTO for adding a step to a task.
 */
export interface CreateStepInput {
  readonly id?: string;
  readonly taskId: string;
  readonly stepOrder: number;
  readonly description: string;
  readonly toolName: string;
  readonly toolArguments: Record<string, unknown>;
  readonly maxRetries?: number;
}

/**
 * Input DTO for recording a tool execution.
 */
export interface CreateToolExecutionInput {
  readonly id?: string;
  readonly stepId: string;
  readonly toolName: string;
  readonly input: Record<string, unknown>;
  readonly output: Record<string, unknown>;
  readonly exitCode: number;
  readonly durationMs: number;
}

/**
 * Input DTO for recording verification evidence.
 */
export interface CreateVerificationInput {
  readonly id?: string;
  readonly stepId: string;
  readonly checkType: string;
  readonly passed: boolean;
  readonly expectedValue: string;
  readonly actualValue: string;
  readonly evidenceData: Record<string, unknown>;
}

/**
 * Input DTO for requesting human approval.
 */
export interface CreateApprovalInput {
  readonly id?: string;
  readonly taskId: string;
  readonly stepId: string;
  readonly riskTier: RiskTier;
  readonly actionSummary: string;
  readonly targetResource: string;
  readonly parameterDiff: Record<string, unknown>;
  readonly expiresAt?: string;
}

/**
 * Input DTO for appending an audit event.
 */
export interface AppendAuditEventInput {
  readonly id?: string;
  readonly taskId: string;
  readonly eventType: AuditEventType;
  readonly actor: 'USER' | 'AGENT' | 'POLICY_ENGINE' | 'SYSTEM';
  readonly details: Record<string, unknown>;
}
