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
  | 'AGENT_EXECUTION_STARTED'
  | 'AGENT_EXECUTION_COMPLETED'
  | 'AGENT_EXECUTION_FAILED'
  | 'MEMORY_CREATED'
  | 'MEMORY_UPDATED'
  | 'MEMORY_ARCHIVED'
  | 'MEMORY_DELETED'
  | 'MEMORY_RETRIEVED'
  | 'MEMORY_ACCESS_DENIED'
  | 'MEMORY_PROPOSAL_SUBMITTED'
  | 'MEMORY_PROPOSAL_DECIDED'
  | 'MEMORY_EXPORTED'
  | 'MEMORIES_IMPORTED'
  | 'MEMORIES_PURGED'
  | 'MEMORY_EMBEDDINGS_SYNCED'
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
  | 'SCHEDULE_OCCURRENCE_RECOVERED'
  | 'CONVERSATION_CREATED'
  | 'CONVERSATION_UPDATED'
  | 'CONVERSATION_ARCHIVED'
  | 'CONVERSATION_DELETED'
  | 'CONVERSATION_MESSAGE_SENT'
  | 'KNOWLEDGE_PROPOSALS_GENERATED'
  | 'CLAIM_EVIDENCE_VERIFIED';

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
export type MemoryStatus = 'ACTIVE' | 'PENDING_APPROVAL' | 'ARCHIVED' | 'SUPERSEDED';

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
  readonly version: number;
  readonly supersedesId: string | null;
  readonly supersededBy: string | null;
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

/**
 * Phase 4D.3D.4B - Structured Evidence Types
 */

export type EvidenceSourceType =
  | 'WEB_RESEARCH'
  | 'CODE_VERIFICATION'
  | 'TOOL_EXECUTION'
  | 'DOCUMENTATION'
  | 'USER_ASSERTION';

export type EvidenceRelationship = 'SUPPORTS' | 'CONTRADICTS' | 'LIMITATION';

export interface CandidateEvidence {
  readonly sourceType: EvidenceSourceType;
  readonly sourceUrl?: string;
  readonly sourceDomain?: string;
  readonly sourceTitle?: string;
  readonly snippet?: string;
  readonly snippetHash?: string;
  readonly relationship: EvidenceRelationship;
  readonly targetClaimIndices?: readonly number[];
  readonly targetClaimIds?: readonly string[];
}

export interface MemoryEvidence {
  readonly id: string;
  readonly memoryId: string;
  readonly sourceType: EvidenceSourceType;
  readonly sourceUrl: string | null;
  readonly sourceDomain: string | null;
  readonly sourceTitle: string | null;
  readonly snippet: string | null;
  readonly snippetHash: string;
  readonly relationship: EvidenceRelationship;
  readonly taskId: string;
  readonly agentId: string;
  readonly createdAt: string;
}

export interface CreateEvidenceInput {
  readonly id?: string;
  readonly memoryId: string;
  readonly sourceType: EvidenceSourceType;
  readonly sourceUrl?: string | null;
  readonly sourceDomain?: string | null;
  readonly sourceTitle?: string | null;
  readonly snippet?: string | null;
  readonly snippetHash?: string;
  readonly relationship: EvidenceRelationship;
  readonly taskId: string;
  readonly agentId: string;
  readonly createdAt?: string;
}

export interface CandidateClaim {
  readonly originalText: string;
  readonly canonicalText?: string;
  readonly claimHash?: string;
  readonly subject?: string | null;
  readonly predicate?: string | null;
  readonly qualifier?: string | null;
}

export interface MemoryClaim {
  readonly id: string;
  readonly memoryId: string | null;
  readonly scopeType: MemoryScopeType;
  readonly scopeId: string;
  readonly originalText: string;
  readonly canonicalText: string;
  readonly claimHash: string;
  readonly subject: string | null;
  readonly predicate: string | null;
  readonly qualifier: string | null;
  readonly taskId: string;
  readonly createdAt: string;
}

export interface CreateClaimInput {
  readonly id?: string;
  readonly memoryId?: string | null;
  readonly scopeType: MemoryScopeType;
  readonly scopeId: string;
  readonly originalText: string;
  readonly canonicalText?: string;
  readonly claimHash?: string;
  readonly subject?: string | null;
  readonly predicate?: string | null;
  readonly qualifier?: string | null;
  readonly taskId: string;
  readonly createdAt?: string;
}

export type ClaimAssociationStatus = 'ACTIVE' | 'INVALIDATED';
export type ClaimVerificationLifecycleStatus = 'CURRENT' | 'STALE';

export interface ListClaimsFilter {
  readonly scopeType: MemoryScopeType;
  readonly scopeId: string;
  readonly taskId?: string;
  readonly memoryId?: string;
  readonly includeInvalidated?: boolean;
  readonly limit?: number;
  readonly offset?: number;
}

export interface ClaimEvidenceAssociation {
  readonly id: string;
  readonly claimId: string;
  readonly evidenceId: string;
  readonly memoryId: string;
  readonly scopeType: MemoryScopeType;
  readonly scopeId: string;
  readonly relationship: EvidenceRelationship;
  readonly status: ClaimAssociationStatus;
  readonly invalidatedAt: string | null;
  readonly invalidationReason: string | null;
  readonly createdAt: string;
}

export interface CreateClaimEvidenceAssociationInput {
  readonly id?: string;
  readonly claimId: string;
  readonly evidenceId: string;
  readonly memoryId: string;
  readonly scopeType: MemoryScopeType;
  readonly scopeId: string;
  readonly relationship?: EvidenceRelationship;
  readonly createdAt?: string;
}

/**
 * Phase 4D.3D.4C.3 - Claim-Evidence Verification Types
 */

export type ClaimVerificationRelationship =
  | 'SUPPORTS'
  | 'CONTRADICTS'
  | 'LIMITATION'
  | 'INSUFFICIENT'
  | 'AMBIGUOUS';

export type ClaimVerificationCandidateOutcome =
  | 'PROPOSED'
  | 'INSUFFICIENT'
  | 'AMBIGUOUS';

export type ClaimVerificationOutcome =
  | ClaimVerificationCandidateOutcome
  | 'UNVERIFIED'
  | 'FAILED';

export interface ClaimEvidenceVerification {
  readonly id: string;
  readonly claimId: string;
  readonly evidenceId: string;
  readonly scopeType: MemoryScopeType;
  readonly scopeId: string;
  readonly proposedRelationship: ClaimVerificationRelationship;
  readonly verificationOutcome: ClaimVerificationCandidateOutcome;
  readonly verifierId: string;
  readonly verifierVersion: string;
  readonly promptPolicyVersion: string;
  readonly promptPolicyHash: string;
  readonly assumptionsHash: string;
  readonly assumptions: readonly string[];
  readonly confidence: number | null;
  readonly explanation: string;
  readonly reviewRecommended: boolean;
  readonly status: ClaimVerificationLifecycleStatus;
  readonly staleAt: string | null;
  readonly staleReason: string | null;
  readonly taskId: string | null;
  readonly createdAt: string;
}

export interface CreateClaimVerificationInput {
  readonly id?: string;
  readonly claimId: string;
  readonly evidenceId: string;
  readonly scopeType: MemoryScopeType;
  readonly scopeId: string;
  readonly proposedRelationship: ClaimVerificationRelationship;
  readonly verificationOutcome: ClaimVerificationCandidateOutcome;
  readonly verifierId: string;
  readonly verifierVersion: string;
  readonly promptPolicyVersion: string;
  readonly promptPolicyHash: string;
  readonly assumptionsHash?: string;
  readonly assumptions?: readonly string[];
  readonly confidence?: number | null;
  readonly explanation: string;
  readonly reviewRecommended?: boolean;
  readonly status?: ClaimVerificationLifecycleStatus;
  readonly staleAt?: string | null;
  readonly staleReason?: string | null;
  readonly taskId?: string | null;
  readonly createdAt?: string;
}

export interface ListClaimVerificationsFilter {
  readonly scopeType: MemoryScopeType;
  readonly scopeId: string;
  readonly claimId?: string;
  readonly evidenceId?: string;
  readonly memoryId?: string;
  readonly proposedRelationship?: ClaimVerificationRelationship;
  readonly status?: ClaimVerificationLifecycleStatus;
  readonly includeStale?: boolean;
  readonly limit?: number;
  readonly offset?: number;
}

/**
 * Phase 4D.3D.4C.4 - Conflict Surfacing Types
 */

export type ClaimConflictType =
  | 'EXPLICIT_CONTRADICTION'
  | 'VERIFIED_CONTRADICTION'
  | 'OPPOSING_VERIFICATIONS';

export interface ConflictMemoryOrigin {
  readonly memoryId: string;
  readonly key: string;
  readonly status: MemoryStatus;
  readonly category: MemoryCategory;
  readonly version: number;
  readonly linkStatus: ClaimAssociationStatus;
  readonly invalidatedAt: string | null;
  readonly invalidationReason: string | null;
  readonly verificationAssumptions: readonly string[];
}

export interface ConflictVerifierPosition {
  readonly verificationId: string;
  readonly verifierId: string;
  readonly verifierVersion: string;
  readonly promptPolicyVersion: string;
  readonly promptPolicyHash: string;
  readonly proposedRelationship: ClaimVerificationRelationship;
  readonly verificationOutcome: ClaimVerificationCandidateOutcome;
  readonly confidence: number | null;
  readonly status: ClaimVerificationLifecycleStatus;
  readonly createdAt: string;
}

export interface ConflictVerifierDisagreement {
  readonly evidenceId: string;
  readonly assumptionsHash: string;
  readonly assumptions: readonly string[];
  readonly positions: readonly ConflictVerifierPosition[];
}

export interface ConflictEvidenceReference {
  readonly evidenceId: string;
  readonly memoryId: string;
  readonly memoryKey: string;
  readonly memoryStatus: MemoryStatus;
  readonly memoryVersion: number;
  readonly sourceType: EvidenceSourceType;
  readonly sourceUrl: string | null;
  readonly sourceDomain: string | null;
  readonly sourceTitle: string | null;
  readonly snippet: string | null;
  readonly snippetHash: string;
  readonly relationship: EvidenceRelationship;
  readonly associationId: string;
  readonly associationStatus: ClaimAssociationStatus;
  readonly invalidatedAt: string | null;
  readonly invalidationReason: string | null;
  readonly taskId: string;
  readonly agentId: string;
  readonly createdAt: string;
  readonly hasVerifierDisagreement: boolean;
  readonly verifications: readonly ClaimEvidenceVerification[];
}

export interface ClaimConflictSummary {
  readonly conflictId: string;
  readonly scopeType: MemoryScopeType;
  readonly scopeId: string;
  readonly conflictType: ClaimConflictType;
  readonly isHistorical: boolean;
  readonly claim: MemoryClaim;
  readonly memories: readonly ConflictMemoryOrigin[];
  readonly supportingEvidence: readonly ConflictEvidenceReference[];
  readonly contradictingEvidence: readonly ConflictEvidenceReference[];
  readonly limitationEvidence: readonly ConflictEvidenceReference[];
  readonly verifierDisagreements: readonly ConflictVerifierDisagreement[];
  readonly assumptions: readonly string[];
  readonly contextualAssumptions: readonly string[];
  readonly detectedAt: string;
}

export interface ListClaimConflictsFilter {
  readonly scopeType: MemoryScopeType;
  readonly scopeId: string;
  readonly claimId?: string;
  readonly memoryId?: string;
  readonly conflictType?: ClaimConflictType;
  readonly includeHistorical?: boolean;
  readonly limit?: number;
  readonly offset?: number;
}

export interface ClaimConflictsResult {
  readonly conflicts: readonly ClaimConflictSummary[];
  readonly total: number;
  readonly includeHistorical: boolean;
}

export type WritableMemoryStatus = Exclude<MemoryStatus, 'SUPERSEDED'>;

export interface CreateMemoryInput {
  readonly id?: string;
  readonly category: MemoryCategory;
  readonly scopeType: MemoryScopeType;
  readonly scopeId: string;
  readonly key: string;
  readonly content: string;
  readonly status?: WritableMemoryStatus;
  readonly priority?: number;
  readonly tags?: readonly string[];
  readonly metadata?: Record<string, unknown>;
  readonly evidence?: readonly CandidateEvidence[];
  readonly claims?: readonly CandidateClaim[];
}

export interface UpdateMemoryInput {
  readonly content?: string;
  readonly category?: MemoryCategory;
  readonly priority?: number;
  readonly tags?: readonly string[];
  readonly metadata?: Record<string, unknown>;
  readonly status?: WritableMemoryStatus;
}

export interface SupersedeMemoryParams {
  readonly previousId: string;
  readonly replacementId: string;
  readonly scope: ScopeIdentifier;
  readonly newVersion?: number;
  readonly replacementStatus?: MemoryStatus;
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
  readonly isInherited?: boolean;
}

export interface IncludedMemoryInfo {
  readonly id: string;
  readonly key: string;
  readonly score: number;
  readonly category: MemoryCategory;
  readonly charCount: number;
  readonly estimatedTokens: number;
  readonly scopeType?: MemoryScopeType;
  readonly scopeId?: string;
  readonly isInherited?: boolean;
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
  readonly scope?: ScopeIdentifier;
  readonly isInherited?: boolean;
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
  readonly principalId?: string;
  readonly agentId?: string;
  readonly permittedScopes?: readonly ScopeIdentifier[];
  readonly _proof?: {
    readonly signature: string;
    readonly nonce: string;
  };
}

export type ProposalDecision =
  | 'APPROVE_NEW'
  | 'APPROVE_AND_SUPERSEDE'
  | 'REJECT'
  | 'APPROVED'
  | 'REJECTED';

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
}

/**
 * Phase 7.5 Substep 3 - Safe Archived Memory Purge Types
 */

export type MemoryPurgeMode = 'CUTOFF' | 'ID_LIST';

export interface PurgeArchivedMemoriesOptions {
  /**
   * Explicit list of memory IDs to purge.
   * Mutually exclusive with `olderThan`. Every ID must belong to caller scope and have status ARCHIVED.
   */
  readonly memoryIds?: readonly string[];

  /**
   * ISO 8601 UTC timestamp cutoff. Purges archived memories whose updatedAt <= olderThan.
   * Mutually exclusive with `memoryIds`.
   */
  readonly olderThan?: string;

  /**
   * If true, previews and reports eligible count without deleting records or emitting mutation audit events.
   * Default: false.
   */
  readonly dryRun?: boolean;

  /**
   * Maximum number of archived records to purge in a single batch.
   * Must be a positive integer if specified.
   */
  readonly maxBatchSize?: number;

  /**
   * Optional scope safety check. If provided, must match caller.scope exactly.
   */
  readonly scopeType?: MemoryScopeType;
  readonly scopeId?: string;
}

export interface MemoryPurgeResult {
  readonly targetScope: ScopeIdentifier;
  readonly purgeMode: MemoryPurgeMode;
  readonly eligibleCount: number;
  readonly purgedCount: number;
  readonly isDryRun: boolean;
  readonly cutoffTimestamp?: string;
  readonly batchSizeLimit?: number;
}

/**
 * Phase 8B - Persistent Scheduler Domain Types
 */

export type ScheduleType = 'ONE_TIME' | 'INTERVAL';
export type ScheduleStatus = 'ACTIVE' | 'PAUSED' | 'COMPLETED' | 'CANCELLED';
export type MissedRunPolicy = 'SKIP' | 'RUN_ONCE';
export type OverlapPolicy = 'SKIP';
export type OccurrenceStatus =
  | 'CLAIMED'
  | 'TASK_CREATED'
  | 'RUNNING'
  | 'AWAITING_APPROVAL'
  | 'SUCCEEDED'
  | 'FAILED'
  | 'CANCELLED'
  | 'SKIPPED_OVERLAP'
  | 'SKIPPED_MISSED';

export interface Schedule {
  readonly id: string;
  readonly name: string;
  readonly goal: string;
  readonly scheduleType: ScheduleType;
  readonly status: ScheduleStatus;
  readonly runAt: string | null;
  readonly intervalMs: number | null;
  readonly missedRunPolicy: MissedRunPolicy;
  readonly overlapPolicy: OverlapPolicy;
  readonly maxConsecutiveFailures: number;
  readonly consecutiveFailures: number;
  readonly scopeType: MemoryScopeType;
  readonly scopeId: string;
  readonly createdBy: string;
  readonly metadataJson: string | null;
  readonly nextRunAt: string | null;
  readonly lastRunAt: string | null;
  readonly lastTaskId: string | null;
  readonly pausedReason: string | null;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface ScheduleOccurrence {
  readonly id: string;
  readonly scheduleId: string;
  readonly occurrenceKey: string;
  readonly scheduledFor: string;
  readonly status: OccurrenceStatus;
  readonly taskId: string | null;
  readonly claimedAt: string;
  readonly startedAt: string | null;
  readonly completedAt: string | null;
  readonly errorSummary: string | null;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface CreateScheduleInput {
  readonly id?: string;
  readonly name: string;
  readonly goal: string;
  readonly scheduleType: ScheduleType;
  readonly runAt?: string;
  readonly intervalMs?: number;
  readonly startAt?: string;
  readonly missedRunPolicy?: MissedRunPolicy;
  readonly overlapPolicy?: OverlapPolicy;
  readonly maxConsecutiveFailures?: number;
  readonly metadata?: Record<string, unknown>;
}

export interface ListSchedulesFilter {
  readonly scopeType?: MemoryScopeType;
  readonly scopeId?: string;
  readonly status?: ScheduleStatus;
  readonly limit?: number;
  readonly offset?: number;
}

/**
 * Milestone 2A - Persistent Conversation Domain Entities and DTOs
 */

export type ConversationStatus = 'ACTIVE' | 'ARCHIVED';

export interface Conversation {
  readonly id: string;
  readonly title: string;
  readonly status: ConversationStatus;
  readonly scopeType: MemoryScopeType;
  readonly scopeId: string;
  readonly createdBy: string;
  readonly agentId: string | null;
  readonly metadataJson: string | null;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export type ConversationMessageRole = 'system' | 'user' | 'assistant' | 'tool';

export interface ConversationMessage {
  readonly id: string;
  readonly conversationId: string;
  readonly role: ConversationMessageRole;
  readonly content: string;
  readonly name?: string | null;
  readonly toolCallId?: string | null;
  readonly toolCallsJson?: string | null;
  readonly clientMessageId?: string | null;
  readonly metadataJson?: string | null;
  readonly createdAt: string;
}

export interface CreateConversationInput {
  readonly id?: string;
  readonly title?: string;
  readonly scope?: ScopeIdentifier;
  readonly agentId?: string;
  readonly metadata?: Record<string, unknown>;
}

export interface UpdateConversationInput {
  readonly title?: string;
  readonly agentId?: string | null;
  readonly metadata?: Record<string, unknown>;
}

export interface ListConversationsFilter {
  readonly status?: ConversationStatus;
  readonly agentId?: string;
  readonly limit?: number;
  readonly offset?: number;
}

export interface ListMessagesFilter {
  readonly limit?: number;
  readonly offset?: number;
  readonly order?: 'ASC' | 'DESC';
}

export interface SendConversationMessageInput {
  readonly content: string;
  readonly role?: ConversationMessageRole;
  readonly name?: string;
  readonly clientMessageId?: string;
  readonly metadata?: Record<string, unknown>;
}

export interface ConversationModelUsage {
  readonly promptTokens: number;
  readonly completionTokens: number;
  readonly totalTokens: number;
  readonly estimatedCostUsd?: number;
}

export interface ConversationResponse {
  readonly conversation: Conversation;
  readonly userMessage: ConversationMessage;
  readonly assistantMessage?: ConversationMessage;
  readonly usage?: ConversationModelUsage;
  readonly error?: string;
}

/**
 * Milestone 2B - Business Task Workflow Types
 */

export interface SubmitBusinessTaskInput {
  readonly objective?: string;
  readonly goal?: string;
  readonly description?: string;
  readonly agentId?: string;
  readonly parameters?: Record<string, unknown>;
  readonly run?: boolean;
  readonly metadata?: Record<string, unknown>;
}

export interface PublicTaskView {
  readonly id: string;
  readonly goal: string;
  readonly status: TaskStatus;
  readonly currentStepIndex: number;
  readonly scope: ScopeIdentifier;
  readonly metadata: Record<string, unknown>;
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly completedAt: string | null;
  readonly errorSummary: string | null;
}

export interface PublicApprovalView {
  readonly id: string;
  readonly taskId: string;
  readonly stepId: string;
  readonly riskTier: RiskTier;
  readonly actionSummary: string;
  readonly targetResource: string;
  readonly parameterDiff: Record<string, unknown>;
  readonly decision: ApprovalDecision;
  readonly decidedBy: string | null;
  readonly decidedAt: string | null;
  readonly expiresAt: string;
  readonly createdAt: string;
}

export interface TaskDetailsView {
  readonly task: PublicTaskView;
  readonly steps: readonly Record<string, unknown>[];
  readonly approvals: readonly PublicApprovalView[];
  readonly auditEvents: readonly Record<string, unknown>[];
  readonly usage: {
    readonly promptTokens: number;
    readonly completionTokens: number;
    readonly totalTokens: number;
    readonly totalCostUsd: number;
  };
}

export interface BusinessTaskResultView {
  readonly taskId: string;
  readonly goal: string;
  readonly status: TaskStatus;
  readonly agentId?: string;
  readonly output: unknown;
  readonly summary?: string;
  readonly error?: string;
  readonly completedAt?: string | null;
  readonly durationMs?: number | null;
  readonly stepsExecuted: number;
  readonly usage?: {
    readonly promptTokens: number;
    readonly completionTokens: number;
    readonly totalTokens: number;
    readonly totalCostUsd: number;
    readonly totalPromptTokens?: number;
    readonly totalCompletionTokens?: number;
  };
}

export interface ListBusinessTasksFilter {
  readonly status?: TaskStatus;
  readonly agentId?: string;
  readonly limit?: number;
  readonly offset?: number;
}



