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
  | 'DYNAMIC_REPLAN_ATTEMPTED'
  | 'COMPENSATION_EXECUTED'
  | 'TASK_COMPLETED'
  | 'TASK_FAILED'
  | 'TASK_CANCELLED'
  | 'CRASH_INTERRUPTION_DETECTED'
  | 'MEMORY_CREATED'
  | 'MEMORY_UPDATED'
  | 'MEMORY_ARCHIVED'
  | 'MEMORY_DELETED'
  | 'MEMORY_RETRIEVED'
  | 'MEMORY_ACCESS_DENIED'
  | 'MEMORY_PROPOSAL_SUBMITTED'
  | 'MEMORY_PROPOSAL_DECIDED'
  | 'MEMORY_EXPORTED'
  | 'MEMORIES_IMPORTED';

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

/**
 * Phase 7 - Long-Term Memory Domain Entities and DTOs
 */

export type MemoryCategory = 'USER_PREFERENCE' | 'PROJECT_FACT' | 'LEARNED_PROCEDURE';
export type MemoryScopeType = 'GLOBAL' | 'WORKSPACE';
export type MemoryStatus = 'ACTIVE' | 'PENDING_APPROVAL' | 'ARCHIVED';

export interface Memory {
  readonly id: string;
  readonly category: MemoryCategory;
  readonly scopeType: MemoryScopeType;
  readonly scopeId: string;
  readonly key: string;
  readonly content: string;
  readonly status: MemoryStatus;
  readonly priority: number;
  readonly tagsJson: string;
  readonly metadataJson: string;
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly lastAccessedAt: string | null;
  readonly accessCount: number;
}

export interface MemoryTaskInjection {
  readonly id: string;
  readonly taskId: string;
  readonly memoryId: string | null;
  readonly charCount: number;
  readonly estimatedTokens: number;
  readonly injectedAt: string;
}

export interface CreateMemoryInput {
  readonly id?: string;
  readonly category: MemoryCategory;
  readonly scopeType: MemoryScopeType;
  readonly scopeId: string;
  readonly key: string;
  readonly content: string;
  readonly status?: MemoryStatus;
  readonly priority?: number;
  readonly tags?: readonly string[];
  readonly metadata?: Record<string, unknown>;
}

export interface UpdateMemoryInput {
  readonly content?: string;
  readonly category?: MemoryCategory;
  readonly priority?: number;
  readonly tags?: readonly string[];
  readonly metadata?: Record<string, unknown>;
  readonly status?: MemoryStatus;
}

export interface ListMemoriesFilter {
  readonly scopeType: MemoryScopeType;
  readonly scopeId: string;
  readonly status?: MemoryStatus;
  readonly category?: MemoryCategory;
  readonly limit?: number;
  readonly offset?: number;
}

export interface RecordMemoryInjectionInput {
  readonly id?: string;
  readonly taskId: string;
  readonly memoryId?: string | null;
  readonly charCount: number;
  readonly estimatedTokens: number;
}

/**
 * Phase 7.2 - Relevance Matching & Context Builder Domain Types
 */

export type MemoryExclusionReason =
  | 'EXCLUDED_NO_RELEVANCE'
  | 'EXCLUDED_BUDGET_CEILING'
  | 'EXCLUDED_INVALID_MEMORY';

export interface RelevanceBreakdown {
  readonly keyMatch: number;
  readonly tagMatch: number;
  readonly wordOverlap: number;
  readonly matchedTags: readonly string[];
  readonly matchedWords: readonly string[];
  readonly keyMatched: boolean;
}

export interface ScoredMemory {
  readonly memory: Memory;
  readonly score: number;
  readonly breakdown: RelevanceBreakdown;
}

export interface IncludedMemoryInfo {
  readonly id: string;
  readonly key: string;
  readonly score: number;
  readonly category: MemoryCategory;
  readonly charCount: number;
  readonly estimatedTokens: number;
}

export interface ExcludedMemoryInfo {
  readonly id: string;
  readonly key?: string;
  readonly reason: MemoryExclusionReason;
  readonly details?: string;
}

export interface SerializedMemoryRecord {
  readonly id: string;
  readonly category: MemoryCategory;
  readonly key: string;
  readonly content: string;
  readonly tags: readonly string[];
  readonly metadata: Record<string, unknown>;
}

export interface SerializedMemoryPayload {
  readonly _boundary: string;
  readonly _securityNotice: string;
  readonly records: readonly SerializedMemoryRecord[];
  readonly _boundaryEnd: string;
}

export interface BuiltMemoryContext {
  readonly serializedContext: string;
  readonly included: readonly IncludedMemoryInfo[];
  readonly excluded: readonly ExcludedMemoryInfo[];
  readonly totalChars: number;
  readonly estimatedTokens: number;
  readonly isTokenCountEstimate: true;
}

/**
 * Phase 7.3 - Permission-Controlled Memory Service Types
 */

export interface ScopeIdentifier {
  readonly scopeType: MemoryScopeType;
  readonly scopeId: string;
}

export type MemoryPermission = 'READ' | 'WRITE' | 'DELETE' | 'APPROVE';
export type MemoryActor = 'USER' | 'AGENT' | 'SYSTEM' | 'POLICY_ENGINE';

export interface CallerContext {
  readonly actor: MemoryActor;
  readonly scope: ScopeIdentifier;
  readonly permissions: ReadonlySet<MemoryPermission> | readonly MemoryPermission[];
  readonly taskId?: string;
  readonly _proof?: {
    readonly signature: string;
    readonly nonce: string;
  };
}

export type ProposalDecision = 'APPROVED' | 'REJECTED';

export interface ProposalDecisionInput {
  readonly memoryId: string;
  readonly decision: ProposalDecision;
  readonly reason?: string;
}

export interface BuildTaskMemoryContextOptions {
  readonly query: string;
  readonly taskId?: string;
  readonly category?: MemoryCategory;
  readonly relevanceThreshold?: number;
  readonly maxBudgetChars?: number;
  readonly recordInjections?: boolean;
}

/**
 * Phase 7.5 - Memory Provenance Inspection & Export DTOs
 */

export interface MemoryExportItem {
  readonly key: string;
  readonly content: string;
  readonly category: MemoryCategory;
  readonly tags: readonly string[];
  readonly priority: number;
  readonly metadata: Record<string, unknown>;
  readonly status: MemoryStatus;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface MemoryExportBundle {
  readonly version: '1.0';
  readonly exportedAt: string;
  readonly sourceScope: ScopeIdentifier;
  readonly count: number;
  readonly checksum: string;
  readonly memories: readonly MemoryExportItem[];
}

export interface ExportMemoriesOptions {
  readonly scopeType?: MemoryScopeType;
  readonly scopeId?: string;
  readonly includeArchived?: boolean;
  readonly category?: MemoryCategory;
}

export interface MemoryUsageHistory {
  readonly memoryId: string;
  readonly scope: ScopeIdentifier;
  readonly totalInjections: number;
  readonly totalChars: number;
  readonly totalEstimatedTokens: number;
  readonly injections: readonly MemoryTaskInjection[];
}

export type ImportConflictStrategy = 'FAIL' | 'SKIP' | 'OVERWRITE';

export interface ImportMemoriesOptions {
  readonly conflictStrategy?: ImportConflictStrategy;
}

export interface MemoryImportResult {
  readonly targetScope: ScopeIdentifier;
  readonly totalInBundle: number;
  readonly importedCount: number;
  readonly skippedCount: number;
  readonly overwrittenCount: number;
  readonly importedKeys: readonly string[];
  readonly skippedKeys: readonly string[];
  readonly overwrittenKeys: readonly string[];
}

