/**
 * Next-Generation Dots AI Platform - Permission-Controlled Memory Service
 * Phase 7.3: Security Hardening
 * 
 * Architectural Mandate:
 * Implements a trusted service layer over MemoryRepository, RelevanceMatcher,
 * and MemoryContextBuilder. Enforces host-derived caller context, explicit permission
 * gating (READ, WRITE, DELETE, APPROVE), strict scope isolation across workspaces
 * and global boundaries, human approval gating for agent memory proposals,
 * fail-closed injection provenance, and privacy-conscious tamper-evident audit logging.
 * 
 * Hardening & Security Guarantees:
 * 1. Host-Controlled Caller Authorization Boundary:
 *    CallerContext is verified by MemoryAuthorizer using process-private cryptographic
 *    HMAC-SHA256 signatures and host WeakSet containment. Handcrafted object literals,
 *    tampered properties, and forged permissions/scopes are rejected immediately.
 * 2. Strict Approval Path (Zero Approval Bypasses):
 *    updateMemory() strictly forbids status mutations. Proposals can ONLY be activated
 *    through the dedicated decideProposal() path, requiring a verified human USER actor
 *    and explicit APPROVE permission. A caller with WRITE alone cannot approve proposals.
 * 3. Fail-Closed Injection Provenance:
 *    Provenance recording requires authoritative task lookup and trusted task scope derived
 *    strictly from task metadata assigned upon task creation. Never falls back to caller scope.
 *    If task metadata is missing, malformed, or untrusted, or if the memory is inactive
 *    (status !== 'ACTIVE'), provenance recording fails closed. Batch injection uses database
 *    transactions to guarantee zero partial writes.
 * 4. Fail-Closed Audit Logging for State Mutations:
 *    All state-mutating operations (create, update, archive, delete, approve) enforce
 *    mandatory audit logging. If audit persistence fails, the mutation fails closed.
 *    Read telemetry audit remains best-effort. Raw memory content is NEVER recorded in audit.
 * 5. Bounded Context: Memory context building strictly honors the 4,000-character ceiling
 *    and untrusted-data boundary framing from Phase 7.2.
 */

import type {
  Memory,
  MemoryCategory,
  MemoryScopeType,
  MemoryStatus,
  MemoryPermission,
  CallerContext,
  ProposalDecision,
  ProposalDecisionInput,
  BuildTaskMemoryContextOptions,
  BuiltMemoryContext,
  CreateMemoryInput,
  WritableMemoryStatus,
  UpdateMemoryInput,
  ListMemoriesFilter,
  RecordMemoryInjectionInput,
  MemoryTaskInjection,
  ScopeIdentifier,
  AuditEventType,
  Task,
  MemoryExportItem,
  MemoryExportBundle,
  ExportMemoriesOptions,
  MemoryUsageHistory,
  ImportConflictStrategy,
  ImportMemoriesOptions,
  MemoryImportResult,
  MemoryPurgeMode,
  PurgeArchivedMemoriesOptions,
  MemoryPurgeResult,
  ScoredMemory
} from '../domain/types.ts';
import {
  ValidationError,
  SecurityViolationError,
  MemoryScopeViolationError,
  MemoryNotFoundError,
  MemoryConflictError,
  TaskNotFoundError,
  EmbeddingProviderUnavailableError,
  EmbeddingNotFoundError
} from '../domain/errors.ts';
import { MemoryRepository } from '../storage/memory-repository.ts';
import type { MemoryEmbeddingRepository } from '../storage/memory-embedding-repository.ts';
import type { EmbeddingJobRepository } from '../storage/embedding-job-repository.ts';
import type { EmbeddingLifecycleManager } from './embedding-lifecycle-manager.ts';
import type {
  IEmbeddingProvider,
  MemoryEmbedding,
  SyncScopeEmbeddingsOptions,
  SyncScopeEmbeddingsResult,
  BackfillModelRevisionOptions,
  BackfillModelRevisionResult,
  MissingEmbeddingMemoryRecord
} from './embedding-types.ts';
import type { AuditRepository } from '../storage/audit-repository.ts';
import type { TaskRepository } from '../storage/task-repository.ts';
import type { DatabaseManager } from '../storage/db.ts';
import { RelevanceMatcher } from './relevance-matcher.ts';
import { MemoryContextBuilder } from './context-builder.ts';
import { HybridRetriever, type HybridScoredMemory, type RetrievalProvenance } from './hybrid-retriever.ts';
import { validateVector } from './vector-utils.ts';
import { MemoryAuthorizer } from '../security/memory-authorizer.ts';
import type { HostMemoryAuthority } from '../security/host-authority.ts';
import { computeCanonicalSha256, verifyBundleChecksum } from './canonical-json.ts';
import { sanitizeMemoryAuditDetails } from '../storage/audit-policy.ts';

const VALID_SCOPES: ReadonlySet<MemoryScopeType> = new Set([
  'GLOBAL',
  'WORKSPACE'
]);

const VALID_CATEGORIES: ReadonlySet<MemoryCategory> = new Set([
  'USER_PREFERENCE',
  'PROJECT_FACT',
  'LEARNED_PROCEDURE'
]);

const VALID_CONFLICT_STRATEGIES: ReadonlySet<ImportConflictStrategy> = new Set([
  'FAIL',
  'SKIP',
  'OVERWRITE'
]);

export interface SearchMemoriesOptions {
  readonly query: string;
  readonly limit?: number;
  readonly category?: MemoryCategory;
  readonly taskId?: string;
  readonly scopeType?: MemoryScopeType;
  readonly scopeId?: string;
}

export type {
  SyncScopeEmbeddingsOptions,
  SyncScopeEmbeddingsResult,
  BackfillModelRevisionOptions,
  BackfillModelRevisionResult
};

export interface MemoryServiceOptions {
  readonly memoryRepo: MemoryRepository;
  readonly embeddingRepo?: MemoryEmbeddingRepository;
  readonly embeddingProvider?: IEmbeddingProvider;
  readonly embeddingJobRepo?: EmbeddingJobRepository;
  readonly lifecycleManager?: EmbeddingLifecycleManager;
  readonly auditRepo?: AuditRepository;
  readonly taskRepo?: TaskRepository;
  readonly authorizer?: MemoryAuthorizer;
  readonly hostAuthority?: HostMemoryAuthority;
  readonly relevanceMatcher?: RelevanceMatcher;
  readonly contextBuilder?: MemoryContextBuilder;
  readonly hybridRetriever?: HybridRetriever;
  /** Minimum cosine similarity threshold for semantic-only matches (lexicalScore === 0) */
  readonly minSemanticConfidence?: number;
  /** Internal hook for testing transactional failure after audit append */
  readonly _testPostAuditHook?: () => void;
  /** Internal hook for testing transactional failure mid-purge */
  readonly _testMidPurgeHook?: (deletedCount: number) => void;
  /** Internal hook for testing transactional failure after purge audit append */
  readonly _testPostPurgeAuditHook?: () => void;
}

/**
 * Strict ISO 8601 UTC format: YYYY-MM-DDTHH:mm:ss[.sss]Z
 * Explicit 'Z' required. Timezone offsets (+/-HH:mm), date-only values, missing timezone indicators,
 * and fractional precision beyond 3 digits (1–3 fractional digits permitted) are strictly rejected.
 */
const STRICT_ISO_8601_UTC_REGEX = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/;

function validateAndNormalizeUtcTimestamp(timestamp: unknown, fieldName: string): string {
  if (typeof timestamp !== 'string' || timestamp.trim() === '') {
    throw new ValidationError(
      `${fieldName} must be a non-empty ISO 8601 UTC timestamp string ending with 'Z'.`
    );
  }

  if (!STRICT_ISO_8601_UTC_REGEX.test(timestamp)) {
    throw new ValidationError(
      `${fieldName} must be a strict ISO 8601 UTC timestamp ending in 'Z' with up to 3 fractional second digits (e.g. '2026-10-15T12:00:00Z' or '2026-10-15T12:00:00.000Z'). Date-only values, timezone offsets, non-UTC representations, and fractional precision exceeding 3 digits are not permitted. Received: '${timestamp}'.`
    );
  }

  const parsedDate = new Date(timestamp);
  if (isNaN(parsedDate.getTime())) {
    throw new ValidationError(
      `Invalid calendar date/time for ${fieldName}: '${timestamp}'.`
    );
  }

  // Verify that Date parsing did not rollover an invalid calendar date or time
  const [datePart, timePart] = timestamp.slice(0, -1).split('T');
  const [yearStr, monthStr, dayStr] = datePart.split('-');
  const [hourStr, minuteStr, secondPart] = timePart.split(':');
  const [secondStr] = secondPart.split('.');

  const year = Number(yearStr);
  const month = Number(monthStr);
  const day = Number(dayStr);
  const hour = Number(hourStr);
  const minute = Number(minuteStr);
  const second = Number(secondStr);

  if (
    parsedDate.getUTCFullYear() !== year ||
    parsedDate.getUTCMonth() + 1 !== month ||
    parsedDate.getUTCDate() !== day ||
    parsedDate.getUTCHours() !== hour ||
    parsedDate.getUTCMinutes() !== minute ||
    parsedDate.getUTCSeconds() !== second
  ) {
    throw new ValidationError(
      `Invalid calendar date or time values in ${fieldName}: '${timestamp}'.`
    );
  }

  return parsedDate.toISOString();
}

export class MemoryService {
  private readonly memoryRepo: MemoryRepository;
  private readonly embeddingRepo?: MemoryEmbeddingRepository;
  private readonly embeddingProvider?: IEmbeddingProvider;
  private readonly embeddingJobRepo?: EmbeddingJobRepository;
  private readonly lifecycleManager?: EmbeddingLifecycleManager;
  private readonly auditRepo?: AuditRepository;
  private readonly taskRepo?: TaskRepository;
  readonly #authorizer: MemoryAuthorizer;
  readonly #hostAuthority?: HostMemoryAuthority;
  private readonly relevanceMatcher: RelevanceMatcher;
  private readonly contextBuilder: MemoryContextBuilder;
  private readonly hybridRetriever: HybridRetriever;
  private readonly _testPostAuditHook?: () => void;
  private readonly _testMidPurgeHook?: (deletedCount: number) => void;
  private readonly _testPostPurgeAuditHook?: () => void;
  private systemTaskId?: string;

  constructor(options: MemoryServiceOptions) {
    if (!options || typeof options !== 'object') {
      throw new ValidationError('MemoryServiceOptions must be provided.');
    }
    if (!options.memoryRepo) {
      throw new ValidationError('MemoryRepository must be provided to MemoryService.');
    }

    // Transaction boundary invariant: AuditRepository must share the exact same DatabaseManager
    // instance as MemoryRepository to guarantee two-way atomic rollback for memory audit events.
    if (options.auditRepo && options.auditRepo.db !== options.memoryRepo.db) {
      throw new ValidationError(
        'MemoryRepository and AuditRepository must share the exact same DatabaseManager instance to guarantee transactional atomicity.'
      );
    }

    // TaskRepository must also share the same DatabaseManager if provided.
    if (options.taskRepo && options.taskRepo.db !== options.memoryRepo.db) {
      throw new ValidationError(
        'MemoryRepository and TaskRepository must share the exact same DatabaseManager instance.'
      );
    }

    // EmbeddingRepository must also share the same DatabaseManager if provided.
    if (options.embeddingRepo && options.embeddingRepo.db !== options.memoryRepo.db) {
      throw new ValidationError(
        'MemoryRepository and MemoryEmbeddingRepository must share the exact same DatabaseManager instance.'
      );
    }

    // EmbeddingJobRepository must also share the same DatabaseManager if provided.
    if (options.embeddingJobRepo && options.embeddingJobRepo.db !== options.memoryRepo.db) {
      throw new ValidationError(
        'MemoryRepository and EmbeddingJobRepository must share the exact same DatabaseManager instance.'
      );
    }

    // Authorization boundary consistency: if both authorizer and hostAuthority are supplied,
    // authorizer must be the exact authorizer instance owned by hostAuthority.
    if (options.authorizer && options.hostAuthority && options.authorizer !== options.hostAuthority.authorizer) {
      throw new ValidationError(
        'MemoryService authorizer must be the exact authorizer owned by its configured HostMemoryAuthority.'
      );
    }

    this.memoryRepo = options.memoryRepo;
    this.embeddingRepo = options.embeddingRepo;
    this.embeddingProvider = options.embeddingProvider;
    this.embeddingJobRepo = options.embeddingJobRepo ?? options.lifecycleManager?.jobRepo;
    this.lifecycleManager = options.lifecycleManager;
    this.auditRepo = options.auditRepo;
    this.taskRepo = options.taskRepo;
    this.#authorizer = options.authorizer ?? options.hostAuthority?.authorizer ?? new MemoryAuthorizer({ taskRepo: options.taskRepo });
    this.#hostAuthority = options.hostAuthority;
    this._testPostAuditHook = options._testPostAuditHook;
    this._testMidPurgeHook = options._testMidPurgeHook;
    this._testPostPurgeAuditHook = options._testPostPurgeAuditHook;
    this.relevanceMatcher = options.relevanceMatcher ?? new RelevanceMatcher();
    this.contextBuilder = options.contextBuilder ?? new MemoryContextBuilder({ matcher: this.relevanceMatcher });
    this.hybridRetriever =
      options.hybridRetriever ??
      new HybridRetriever({
        matcher: this.relevanceMatcher,
        minSemanticConfidence: options.minSemanticConfidence
      });
  }

  /**
   * Returns the underlying DatabaseManager instance shared by this service's repositories.
   */
  public get db(): DatabaseManager {
    return this.memoryRepo.db;
  }

  /**
   * Validates whether this service shares the exact same authorization boundary as the provided authorizer.
   */
  public hasAuthorizer(authorizer: MemoryAuthorizer): boolean {
    return this.#authorizer === authorizer;
  }

  // --- Public Operations ---

  /**
   * Retrieves a memory by ID, enforcing scope containment, host verification, and READ permission.
   */
  public getMemoryById(caller: CallerContext, id: string): Memory | null {
    this.validateCaller(caller, 'READ');
    if (!id || typeof id !== 'string' || id.trim() === '') {
      throw new ValidationError('Memory ID must be a non-empty string.');
    }

    try {
      const memory = this.memoryRepo.getMemoryById(id, caller.scope);
      if (memory) {
        this.audit(caller, 'MEMORY_RETRIEVED', {
          memoryId: memory.id,
          category: memory.category,
          scopeType: memory.scopeType,
          scopeId: memory.scopeId
        }, false);
      }
      return memory;
    } catch (err) {
      if (err instanceof MemoryScopeViolationError && caller.scope.scopeType === 'WORKSPACE') {
        try {
          const globalMemory = this.memoryRepo.getMemoryById(id, { scopeType: 'GLOBAL', scopeId: 'default' });
          if (globalMemory && this.isMemoryEligibleForCaller(globalMemory, caller)) {
            this.audit(caller, 'MEMORY_RETRIEVED', {
              memoryId: globalMemory.id,
              category: globalMemory.category,
              scopeType: globalMemory.scopeType,
              scopeId: globalMemory.scopeId,
              inherited: true
            }, false);
            return globalMemory;
          }
        } catch {
          // not found or not in global
        }
        this.audit(caller, 'MEMORY_ACCESS_DENIED', {
          reason: 'CROSS_SCOPE_READ_ATTEMPT',
          memoryId: id,
          expectedScope: `${caller.scope.scopeType}:${caller.scope.scopeId}`
        }, false);
      } else if (err instanceof MemoryScopeViolationError) {
        this.audit(caller, 'MEMORY_ACCESS_DENIED', {
          reason: 'CROSS_SCOPE_READ_ATTEMPT',
          memoryId: id,
          expectedScope: `${caller.scope.scopeType}:${caller.scope.scopeId}`
        }, false);
      }
      throw err;
    }
  }

  /**
   * Retrieves an active memory by its exact key within the caller's scope,
   * with inherited global memory fallback for workspace callers.
   */
  public getMemoryByKey(
    caller: CallerContext,
    key: string,
    status: MemoryStatus = 'ACTIVE'
  ): Memory | null {
    this.validateCaller(caller, 'READ');
    let memory = this.memoryRepo.getMemoryByKey(key, caller.scope, status);
    let isInherited = false;
    if (!memory && caller.scope.scopeType === 'WORKSPACE') {
      const globalMem = this.memoryRepo.getMemoryByKey(key, { scopeType: 'GLOBAL', scopeId: 'default' }, status);
      if (globalMem && this.isMemoryEligibleForCaller(globalMem, caller)) {
        memory = globalMem;
        isInherited = true;
      }
    }
    if (memory) {
      this.audit(caller, 'MEMORY_RETRIEVED', {
        memoryId: memory.id,
        category: memory.category,
        scopeType: memory.scopeType,
        scopeId: memory.scopeId,
        inherited: isInherited
      }, false);
    }
    return memory;
  }

  /**
   * Lists memories within the caller's scope, with optional category and status filters.
   */
  public listMemories(
    caller: CallerContext,
    filter: Omit<ListMemoriesFilter, 'scopeType' | 'scopeId'> & {
      scopeType?: MemoryScopeType;
      scopeId?: string;
    } = {}
  ): Memory[] {
    this.validateCaller(caller, 'READ');

    // Reject explicit scope spoofing attempts in filter
    this.assertCallerScopeMatch(caller, filter.scopeType, filter.scopeId, 'listMemories');

    return this.memoryRepo.listMemories({
      ...filter,
      scopeType: caller.scope.scopeType,
      scopeId: caller.scope.scopeId
    });
  }

  /**
   * Creates a memory within the caller's scope.
   * Agent callers are strictly restricted to submitting proposals with status 'PENDING_APPROVAL'.
   * State mutation audit logging is mandatory (fail-closed).
   */
  public createMemory(caller: CallerContext, input: CreateMemoryInput): Memory {
    this.validateCaller(caller, 'WRITE');
    if (!input || typeof input !== 'object') {
      throw new ValidationError('CreateMemoryInput must be provided.');
    }

    // Reject explicit scope spoofing in input
    this.assertCallerScopeMatch(caller, input.scopeType, input.scopeId, 'createMemory');

    let status = (input.status ?? 'ACTIVE') as MemoryStatus;
    if (caller.actor === 'AGENT') {
      // Agents must never directly persist ACTIVE memories
      if (input.status === 'ACTIVE') {
        this.audit(caller, 'MEMORY_ACCESS_DENIED', {
          reason: 'AGENT_DIRECT_ACTIVE_CREATION_DENIED',
          operation: 'createMemory',
          category: input.category
        }, false);
        throw new SecurityViolationError(
          'Agents cannot directly create active memories; proposals must be created with status PENDING_APPROVAL.',
          'AGENT_PROPOSAL_REQUIRED',
          { category: input.category }
        );
      }
      status = 'PENDING_APPROVAL';
    }

    if ((status as string) === 'SUPERSEDED') {
      throw new ValidationError("Direct creation of memories with status 'SUPERSEDED' is not permitted.");
    }

    const metadataWithOwnership = {
      ...(input.metadata ?? {}),
      ...(caller.scope.scopeType === 'GLOBAL' && caller.principalId && !input.metadata?.principalId
        ? { principalId: caller.principalId, ownerId: caller.principalId }
        : {})
    };

    const createdMemory = this.memoryRepo.transaction(() => {
      const memory = this.memoryRepo.createMemory({
        id: input.id,
        key: input.key,
        content: input.content,
        category: input.category,
        scopeType: caller.scope.scopeType,
        scopeId: caller.scope.scopeId,
        metadata: metadataWithOwnership,
        status: status as WritableMemoryStatus,
        priority: input.priority,
        tags: input.tags
      });

      // Mandatory audit write for state creation
      if (status === 'ACTIVE') {
        this.audit(caller, 'MEMORY_CREATED', {
          memoryId: memory.id,
          category: memory.category,
          scopeType: memory.scopeType,
          scopeId: memory.scopeId,
          status: 'ACTIVE'
        }, true);

        // Durable Embedding Automation: Enqueue job for active memory creation
        if (this.embeddingJobRepo) {
          const modelId = this.embeddingProvider?.modelId ?? this.lifecycleManager?.provider.modelId ?? 'default';
          const modelRevision = (this.embeddingProvider as any)?.modelRevision ?? (this.lifecycleManager?.provider as any)?.modelRevision ?? 'main';
          this.embeddingJobRepo.enqueueJob({
            memoryId: memory.id,
            scopeType: memory.scopeType,
            scopeId: memory.scopeId,
            modelId,
            modelRevision
          });
        }
      } else {
        this.audit(caller, 'MEMORY_PROPOSAL_SUBMITTED', {
          memoryId: memory.id,
          category: memory.category,
          scopeType: memory.scopeType,
          scopeId: memory.scopeId,
          status: 'PENDING_APPROVAL',
          proposedBy: caller.actor
        }, true);
      }

      if (this._testPostAuditHook) {
        this._testPostAuditHook();
      }

      return memory;
    });

    if (createdMemory.status === 'ACTIVE') {
      this.lifecycleManager?.trigger();
    }

    return createdMemory;
  }

  /**
   * Updates an existing active memory within the caller's scope.
   * 
   * Strict Lifecycle & Status Gates:
   * 1. The record lookup, scope validation, status validation, mutation, and mandatory
   *    audit write all execute within ONE atomic transaction boundary.
   * 2. Status mutations are strictly forbidden via updateMemory.
   *    Proposals can ONLY be activated through decideProposal with APPROVE permission.
   * 3. Only records in status 'ACTIVE' can be updated.
   *    - 'ARCHIVED' records cannot be updated (preserves immutability and purge retention cutoffs).
   *    - 'PENDING_APPROVAL' proposals cannot be updated directly (proposals must be decided via decideProposal).
   * 4. Agents are strictly forbidden from modifying memories.
   * 5. Discriminated outcome pattern ensures denial audit events are committed to the
   *    database without rollback before the public method throws.
   */
  public updateMemory(caller: CallerContext, id: string, input: UpdateMemoryInput): Memory {
    this.validateCaller(caller, 'WRITE');
    if (!id || typeof id !== 'string' || id.trim() === '') {
      throw new ValidationError('Memory ID must be a non-empty string.');
    }
    if (!input || typeof input !== 'object') {
      throw new ValidationError('UpdateMemoryInput must be provided.');
    }

    type UpdateOutcome =
      | { ok: true; memory: Memory }
      | { ok: false; error: Error };

    const outcome = this.memoryRepo.transaction((): UpdateOutcome => {
      let existing: Memory | null;
      try {
        existing = this.memoryRepo.getMemoryById(id, caller.scope);
      } catch (err) {
        if (err instanceof MemoryScopeViolationError) {
          this.audit(caller, 'MEMORY_ACCESS_DENIED', {
            reason: 'CROSS_SCOPE_UPDATE_ATTEMPT',
            memoryId: id,
            expectedScope: `${caller.scope.scopeType}:${caller.scope.scopeId}`
          }, false);
          return { ok: false, error: err };
        }
        throw err;
      }

      if (!existing) {
        return { ok: false, error: new MemoryNotFoundError(id) };
      }

      // STRICT APPROVAL GATE: updateMemory must never perform status lifecycle transitions
      if (input.status !== undefined && input.status !== existing.status) {
        if (existing.status === 'PENDING_APPROVAL') {
          this.audit(caller, 'MEMORY_ACCESS_DENIED', {
            reason: 'APPROVAL_BYPASS_ATTEMPT',
            operation: 'updateMemory',
            memoryId: id,
            attemptedStatus: input.status
          }, false);
          return {
            ok: false,
            error: new SecurityViolationError(
              'Cannot transition status of a pending proposal via updateMemory. Only the trusted decideProposal path with APPROVE permission may decide proposals.',
              'UNAUTHORIZED_APPROVAL',
              { memoryId: id, attemptedStatus: input.status }
            )
          };
        }

        this.audit(caller, 'MEMORY_ACCESS_DENIED', {
          reason: 'UNAUTHORIZED_STATUS_TRANSITION',
          operation: 'updateMemory',
          memoryId: id,
          currentStatus: existing.status,
          attemptedStatus: input.status
        }, false);
        return {
          ok: false,
          error: new SecurityViolationError(
            `Direct status transitions from '${existing.status}' to '${input.status}' cannot be performed via updateMemory. Use decideProposal for proposals, or archiveMemory to archive.`,
            'UNAUTHORIZED_STATUS_TRANSITION',
            { memoryId: id, currentStatus: existing.status, attemptedStatus: input.status }
          )
        };
      }

      // AGENT RESTRICTION: Agents are strictly forbidden from directly modifying any memories
      if (caller.actor === 'AGENT') {
        this.audit(caller, 'MEMORY_ACCESS_DENIED', {
          reason: 'AGENT_MUTATION_DENIED',
          operation: 'updateMemory',
          memoryId: id
        }, false);
        return {
          ok: false,
          error: new SecurityViolationError(
            'Agents cannot directly modify memories.',
            'AGENT_MUTATION_RESTRICTED',
            { memoryId: id }
          )
        };
      }

      // STRICT APPROVAL GATE: Pending proposals cannot be modified directly via updateMemory
      if (existing.status === 'PENDING_APPROVAL') {
        this.audit(caller, 'MEMORY_ACCESS_DENIED', {
          reason: 'APPROVAL_BYPASS_ATTEMPT',
          operation: 'updateMemory',
          memoryId: id
        }, false);
        return {
          ok: false,
          error: new SecurityViolationError(
            'Cannot modify a pending proposal via updateMemory. Only the trusted decideProposal path with APPROVE permission may decide proposals.',
            'UNAUTHORIZED_APPROVAL',
            { memoryId: id }
          )
        };
      }

      // IMMUTABLE ARCHIVE GATE: Archived records cannot be modified via updateMemory
      if (existing.status === 'ARCHIVED') {
        return {
          ok: false,
          error: new ValidationError(
            `Cannot update memory '${id}': record is archived.`
          )
        };
      }

      const sanitizedInput: UpdateMemoryInput = {
        ...(input.content !== undefined ? { content: input.content } : {}),
        ...(input.category !== undefined ? { category: input.category } : {}),
        ...(input.priority !== undefined ? { priority: input.priority } : {}),
        ...(input.tags !== undefined ? { tags: input.tags } : {}),
        ...(input.metadata !== undefined ? { metadata: input.metadata } : {}),
        ...(input.status !== undefined ? { status: input.status } : {})
      };

      const updated = this.memoryRepo.updateMemory(id, caller.scope, sanitizedInput);

      // Invalidate existing embeddings if embedding-relevant content changes.
      // Priority, tag, category, and metadata updates do not trigger embedding invalidation.
      if (input.content !== undefined) {
        if (this.embeddingRepo) {
          this.embeddingRepo.deleteEmbeddingsByMemoryId(id);
        }
        // Durable Embedding Automation: Enqueue replacement job for content update
        if (this.embeddingJobRepo) {
          const modelId = this.embeddingProvider?.modelId ?? this.lifecycleManager?.provider.modelId ?? 'default';
          const modelRevision = (this.embeddingProvider as any)?.modelRevision ?? (this.lifecycleManager?.provider as any)?.modelRevision ?? 'main';
          this.embeddingJobRepo.enqueueJob({
            memoryId: updated.id,
            scopeType: updated.scopeType,
            scopeId: updated.scopeId,
            modelId,
            modelRevision
          });
        }
      }

      // Mandatory audit write for state update
      this.audit(caller, 'MEMORY_UPDATED', {
        memoryId: updated.id,
        category: updated.category,
        scopeType: updated.scopeType,
        scopeId: updated.scopeId,
        updatedFields: Object.keys(input)
      }, true);

      if (this._testPostAuditHook) {
        this._testPostAuditHook();
      }

      return { ok: true, memory: updated };
    });

    if (!outcome.ok) {
      throw outcome.error;
    }

    if (input.content !== undefined) {
      this.lifecycleManager?.trigger();
    }

    return outcome.memory;
  }

  /**
   * Archives an active memory within the caller's scope, requiring DELETE permission.
   * State mutation audit logging is mandatory (fail-closed).
   * 
   * Atomic Lifecycle & Status Gates:
   * 1. The record lookup, scope validation, status validation, mutation, and mandatory
   *    audit write all execute within ONE atomic transaction boundary.
   * 2. Only records in status 'ACTIVE' can be archived via archiveMemory.
   * 3. Pending proposals ('PENDING_APPROVAL') cannot be archived via archiveMemory;
   *    proposals can only be resolved through decideProposal with APPROVE permission.
   * 4. Already archived memories ('ARCHIVED') cannot be re-archived.
   * 5. Discriminated outcome pattern ensures denial audit events are committed to the
   *    database without rollback before the public method throws.
   */
  public archiveMemory(caller: CallerContext, id: string): Memory {
    this.validateCaller(caller, 'DELETE');
    if (!id || typeof id !== 'string' || id.trim() === '') {
      throw new ValidationError('Memory ID must be a non-empty string.');
    }

    type ArchiveOutcome =
      | { ok: true; memory: Memory }
      | { ok: false; error: Error };

    const outcome = this.memoryRepo.transaction((): ArchiveOutcome => {
      let existing: Memory | null;
      try {
        existing = this.memoryRepo.getMemoryById(id, caller.scope);
      } catch (err) {
        if (err instanceof MemoryScopeViolationError) {
          this.audit(caller, 'MEMORY_ACCESS_DENIED', {
            reason: 'CROSS_SCOPE_ARCHIVE_ATTEMPT',
            memoryId: id,
            expectedScope: `${caller.scope.scopeType}:${caller.scope.scopeId}`
          }, false);
          return { ok: false, error: err };
        }
        throw err;
      }

      if (!existing) {
        return { ok: false, error: new MemoryNotFoundError(id) };
      }

      // STRICT APPROVAL GATE: pending proposals must not be archived via archiveMemory
      if (existing.status === 'PENDING_APPROVAL') {
        this.audit(caller, 'MEMORY_ACCESS_DENIED', {
          reason: 'APPROVAL_BYPASS_ATTEMPT',
          operation: 'archiveMemory',
          memoryId: id,
          attemptedStatus: 'ARCHIVED'
        }, false);
        return {
          ok: false,
          error: new SecurityViolationError(
            'Cannot archive a pending proposal via archiveMemory. Only the trusted decideProposal path with APPROVE permission may decide proposals.',
            'UNAUTHORIZED_APPROVAL',
            { memoryId: id, attemptedStatus: 'ARCHIVED' }
          )
        };
      }

      // INVALID STATUS TRANSITION: cannot re-archive an already archived record
      if (existing.status === 'ARCHIVED') {
        return {
          ok: false,
          error: new ValidationError(
            `Cannot archive memory '${id}': record is already archived.`
          )
        };
      }

      // INVALID STATUS TRANSITION: cannot archive a superseded record
      if (existing.status === 'SUPERSEDED') {
        return {
          ok: false,
          error: new ValidationError(
            `Cannot archive memory '${id}': record is superseded. Superseded memories are immutable historical records.`
          )
        };
      }

      const archived = this.memoryRepo.archiveMemory(id, caller.scope);

      // Phase 4C.6C Archive Lifecycle Cleanup:
      // 1. Remove stored embeddings for this memory
      if (this.embeddingRepo) {
        this.embeddingRepo.deleteEmbeddingsByMemoryId(id);
      }

      // 2. Cancel pending embedding jobs for this memory
      if (this.embeddingJobRepo) {
        this.embeddingJobRepo.cancelPendingJobsByMemoryId(id);
      }

      this.audit(caller, 'MEMORY_ARCHIVED', {
        memoryId: archived.id,
        category: archived.category,
        scopeType: archived.scopeType,
        scopeId: archived.scopeId
      }, true);

      if (this._testPostAuditHook) {
        this._testPostAuditHook();
      }

      return { ok: true, memory: archived };
    });

    if (!outcome.ok) {
      throw outcome.error;
    }

    return outcome.memory;
  }

  /**
   * Hard-deletes a memory record permanently, physically erasing content and nulling
   * foreign keys in injection provenance records. Requires DELETE permission.
   * State mutation audit logging is mandatory (fail-closed).
   * 
   * Atomic Lifecycle Gate:
   * 1. The record lookup, scope validation, status validation, mutation, and mandatory
   *    audit write all execute within ONE atomic transaction boundary.
   * 2. Pending proposals ('PENDING_APPROVAL') cannot be deleted via deleteMemory;
   *    proposals must be decided through the trusted decideProposal path.
   * 3. Discriminated outcome pattern ensures denial audit events are committed to the
   *    database without rollback before the public method throws.
   */
  public deleteMemory(caller: CallerContext, id: string): boolean {
    this.validateCaller(caller, 'DELETE');
    if (!id || typeof id !== 'string' || id.trim() === '') {
      throw new ValidationError('Memory ID must be a non-empty string.');
    }

    type DeleteOutcome =
      | { ok: true; deleted: boolean }
      | { ok: false; error: Error };

    const outcome = this.memoryRepo.transaction((): DeleteOutcome => {
      let existing: Memory | null;
      try {
        existing = this.memoryRepo.getMemoryById(id, caller.scope);
      } catch (err) {
        if (err instanceof MemoryScopeViolationError) {
          this.audit(caller, 'MEMORY_ACCESS_DENIED', {
            reason: 'CROSS_SCOPE_DELETE_ATTEMPT',
            memoryId: id,
            expectedScope: `${caller.scope.scopeType}:${caller.scope.scopeId}`
          }, false);
          return { ok: false, error: err };
        }
        throw err;
      }

      if (!existing) {
        return { ok: false, error: new MemoryNotFoundError(id) };
      }

      // STRICT APPROVAL GATE: pending proposals must not be deleted directly
      if (existing.status === 'PENDING_APPROVAL') {
        this.audit(caller, 'MEMORY_ACCESS_DENIED', {
          reason: 'APPROVAL_BYPASS_ATTEMPT',
          operation: 'deleteMemory',
          memoryId: id
        }, false);
        return {
          ok: false,
          error: new SecurityViolationError(
            'Cannot delete a pending proposal via deleteMemory. Only the trusted decideProposal path with APPROVE permission may decide proposals.',
            'UNAUTHORIZED_APPROVAL',
            { memoryId: id }
          )
        };
      }

      // HISTORICAL LINEAGE GUARD: cannot delete a memory in a supersession chain
      if (existing.status === 'SUPERSEDED' || existing.supersedesId !== null || existing.supersededBy !== null) {
        return {
          ok: false,
          error: new ValidationError(
            `Cannot delete memory '${id}': record is part of a supersession history chain.`
          )
        };
      }

      const deleted = this.memoryRepo.deleteMemory(id, caller.scope);

      // Mandatory audit write for hard deletion
      this.audit(caller, 'MEMORY_DELETED', {
        memoryId: existing.id,
        category: existing.category,
        scopeType: existing.scopeType,
        scopeId: existing.scopeId
      }, true);

      if (this._testPostAuditHook) {
        this._testPostAuditHook();
      }

      return { ok: true, deleted };
    });

    if (!outcome.ok) {
      throw outcome.error;
    }

    return outcome.deleted;
  }

  /**
   * Submits a human decision on a pending memory proposal.
   *
   * Supported strategies:
   * - REJECT / REJECTED: rejects the pending proposal (transitions to ARCHIVED).
   * - APPROVE_NEW / APPROVED: approves the proposal only if no active memory exists with the same key.
   *   If an active memory with the same key exists, throws MemoryConflictError.
   * - APPROVE_AND_SUPERSEDE: explicitly supersedes the existing active memory with the approved proposal.
   *   The active memory becomes SUPERSEDED, and the proposal becomes ACTIVE with incremented version and lineage link.
   *   If no active memory exists with that key, throws ValidationError.
   *
   * Strict Security Gates:
   * 1. Requires verified human USER actor.
   * 2. Requires explicit APPROVE permission.
   * 3. Target memory must be in status 'PENDING_APPROVAL'.
   * 4. State mutation and audit logging are executed atomically inside one SQLite transaction (fail-closed).
   */
  public decideProposal(caller: CallerContext, input: ProposalDecisionInput): Memory {
    if (!input || typeof input !== 'object') {
      throw new ValidationError('ProposalDecisionInput must be provided.');
    }
    if (!input.memoryId || typeof input.memoryId !== 'string' || input.memoryId.trim() === '') {
      throw new ValidationError('Memory ID must be a non-empty string.');
    }
    const VALID_DECISIONS: ReadonlySet<ProposalDecision> = new Set([
      'APPROVE_NEW',
      'APPROVE_AND_SUPERSEDE',
      'REJECT',
      'APPROVED',
      'REJECTED'
    ]);
    if (!VALID_DECISIONS.has(input.decision)) {
      throw new ValidationError(
        `Invalid proposal decision '${String(input.decision)}'. Must be 'APPROVE_NEW', 'APPROVE_AND_SUPERSEDE', 'REJECT', 'APPROVED', or 'REJECTED'.`
      );
    }

    // 1. Verify caller authenticity
    this.validateCaller(caller);

    // 2. Verify caller actor: agents and automated engines are strictly forbidden
    if (caller.actor === 'AGENT') {
      this.audit(caller, 'MEMORY_ACCESS_DENIED', {
        reason: 'AGENT_SELF_APPROVAL_ATTEMPT',
        operation: 'decideProposal',
        memoryId: input.memoryId
      }, false);
      throw new SecurityViolationError(
        'Agents are strictly forbidden from approving memory proposals.',
        'UNAUTHORIZED_APPROVAL',
        { actor: caller.actor, memoryId: input.memoryId }
      );
    }

    if (caller.actor !== 'USER') {
      this.audit(caller, 'MEMORY_ACCESS_DENIED', {
        reason: 'NON_USER_APPROVAL_ATTEMPT',
        operation: 'decideProposal',
        memoryId: input.memoryId
      }, false);
      throw new SecurityViolationError(
        'Only human users can decide memory proposals.',
        'UNAUTHORIZED_APPROVAL',
        { actor: caller.actor, memoryId: input.memoryId }
      );
    }

    // 3. Verify APPROVE permission
    this.validateCaller(caller, 'APPROVE');

    type DecisionOutcome =
      | { ok: true; memory: Memory }
      | { ok: false; error: Error };

    const outcome = this.memoryRepo.transaction((): DecisionOutcome => {
      let existing: Memory | null;
      try {
        existing = this.memoryRepo.getMemoryById(input.memoryId, caller.scope);
      } catch (err) {
        if (err instanceof MemoryScopeViolationError) {
          this.audit(caller, 'MEMORY_ACCESS_DENIED', {
            reason: 'CROSS_SCOPE_DECISION_ATTEMPT',
            memoryId: input.memoryId,
            expectedScope: `${caller.scope.scopeType}:${caller.scope.scopeId}`
          }, false);
          return { ok: false, error: err };
        }
        throw err;
      }

      if (!existing) {
        return { ok: false, error: new MemoryNotFoundError(input.memoryId) };
      }

      if (existing.status !== 'PENDING_APPROVAL') {
        return {
          ok: false,
          error: new ValidationError(
            `Cannot decide memory proposal: memory '${input.memoryId}' is not pending approval (current status: '${existing.status}').`
          )
        };
      }

      // Check if active memory already exists with the exact same key in caller's scope
      const activeExisting = this.memoryRepo.getMemoryByKey(existing.key, caller.scope, 'ACTIVE');

      // Strategy 1: REJECT or REJECTED
      if (input.decision === 'REJECT' || input.decision === 'REJECTED') {
        const updated = this.memoryRepo.updateMemory(input.memoryId, caller.scope, { status: 'ARCHIVED' });

        if (this.embeddingRepo) {
          this.embeddingRepo.deleteEmbeddingsByMemoryId(updated.id);
        }
        if (this.embeddingJobRepo) {
          this.embeddingJobRepo.cancelPendingJobsByMemoryId(updated.id);
        }

        this.audit(caller, 'MEMORY_PROPOSAL_DECIDED', {
          memoryId: updated.id,
          category: updated.category,
          decision: input.decision,
          decidedBy: caller.actor,
          scopeType: updated.scopeType,
          scopeId: updated.scopeId,
          previousStatus: 'PENDING_APPROVAL',
          newStatus: 'ARCHIVED'
        }, true);

        if (this._testPostAuditHook) {
          this._testPostAuditHook();
        }

        return { ok: true, memory: updated };
      }

      // Strategy 2: APPROVE_AND_SUPERSEDE
      if (input.decision === 'APPROVE_AND_SUPERSEDE') {
        if (!activeExisting) {
          return {
            ok: false,
            error: new ValidationError(
              `Cannot approve and supersede: no active memory exists with key '${existing.key}' in scope '${caller.scope.scopeType}:${caller.scope.scopeId}'. Use APPROVE_NEW instead.`
            )
          };
        }

        // Execute atomic supersession transition
        const superseded = this.memoryRepo.supersedeMemory({
          previousId: activeExisting.id,
          replacementId: existing.id,
          scope: caller.scope,
          replacementStatus: 'ACTIVE'
        });

        // Clean up embeddings and pending jobs for superseded memory
        if (this.embeddingRepo) {
          this.embeddingRepo.deleteEmbeddingsByMemoryId(superseded.previous.id);
        }
        if (this.embeddingJobRepo) {
          this.embeddingJobRepo.cancelPendingJobsByMemoryId(superseded.previous.id);
        }

        // Enqueue durable embedding job for newly active replacement memory
        if (this.embeddingJobRepo) {
          const modelId = this.embeddingProvider?.modelId ?? this.lifecycleManager?.provider.modelId ?? 'default';
          const modelRevision = (this.embeddingProvider as any)?.modelRevision ?? (this.lifecycleManager?.provider as any)?.modelRevision ?? 'main';
          this.embeddingJobRepo.enqueueJob({
            memoryId: superseded.replacement.id,
            scopeType: superseded.replacement.scopeType,
            scopeId: superseded.replacement.scopeId,
            modelId,
            modelRevision
          });
        }

        // Mandatory audit write with supersession lineage reference
        this.audit(caller, 'MEMORY_PROPOSAL_DECIDED', {
          memoryId: superseded.replacement.id,
          category: superseded.replacement.category,
          decision: input.decision,
          decidedBy: caller.actor,
          scopeType: superseded.replacement.scopeType,
          scopeId: superseded.replacement.scopeId,
          previousStatus: 'PENDING_APPROVAL',
          newStatus: 'ACTIVE',
          supersededMemoryId: superseded.previous.id
        }, true);

        if (this._testPostAuditHook) {
          this._testPostAuditHook();
        }

        return { ok: true, memory: superseded.replacement };
      }

      // Strategy 3: APPROVE_NEW or APPROVED (legacy)
      // Must NOT supersede an active memory; reject with MemoryConflictError if active conflict exists
      if (activeExisting) {
        return {
          ok: false,
          error: new MemoryConflictError(
            existing.key,
            caller.scope.scopeType,
            caller.scope.scopeId,
            {
              operation: 'decideProposal',
              reason: 'Active memory already exists with key. Use APPROVE_AND_SUPERSEDE to supersede existing memory.',
              existingActiveId: activeExisting.id,
              proposalId: existing.id
            }
          )
        };
      }

      const updated = this.memoryRepo.updateMemory(input.memoryId, caller.scope, { status: 'ACTIVE' });

      // Durable Embedding Automation: Enqueue job when proposal is approved (transitions to ACTIVE)
      if (this.embeddingJobRepo) {
        const modelId = this.embeddingProvider?.modelId ?? this.lifecycleManager?.provider.modelId ?? 'default';
        const modelRevision = (this.embeddingProvider as any)?.modelRevision ?? (this.lifecycleManager?.provider as any)?.modelRevision ?? 'main';
        this.embeddingJobRepo.enqueueJob({
          memoryId: updated.id,
          scopeType: updated.scopeType,
          scopeId: updated.scopeId,
          modelId,
          modelRevision
        });
      }

      // Mandatory audit write for proposal decision
      this.audit(caller, 'MEMORY_PROPOSAL_DECIDED', {
        memoryId: updated.id,
        category: updated.category,
        decision: input.decision,
        decidedBy: caller.actor,
        scopeType: updated.scopeType,
        scopeId: updated.scopeId,
        previousStatus: 'PENDING_APPROVAL',
        newStatus: 'ACTIVE'
      }, true);

      if (this._testPostAuditHook) {
        this._testPostAuditHook();
      }

      return { ok: true, memory: updated };
    });

    if (!outcome.ok) {
      throw outcome.error;
    }

    if (outcome.memory.status === 'ACTIVE') {
      this.lifecycleManager?.trigger();
    }

    return outcome.memory;
  }

  /**
   * Generates and persists a vector embedding for an authorized ACTIVE memory record.
   * 
   * Guarantees:
   * 1. Requires WRITE permission and authoritative memory scope validation.
   * 2. Rejects PENDING_APPROVAL proposals: only ACTIVE memories may receive embeddings.
   * 3. Model inference executes strictly OUTSIDE of database transactions.
   * 4. Safe failure: if provider inference fails, memory records remain uncorrupted.
   * 5. Persists the vector into the persistent SQLite embedding repository.
   */
  public async generateMemoryEmbedding(
    caller: CallerContext,
    memoryId: string,
    provider?: IEmbeddingProvider
  ): Promise<MemoryEmbedding> {
    this.validateCaller(caller, 'WRITE');
    if (!memoryId || typeof memoryId !== 'string' || memoryId.trim() === '') {
      throw new ValidationError('Memory ID must be a non-empty string.');
    }

    if (!this.embeddingRepo) {
      throw new ValidationError('Memory embedding repository is not configured on MemoryService.');
    }

    const effectiveProvider = provider ?? this.embeddingProvider;
    if (!effectiveProvider) {
      throw new EmbeddingProviderUnavailableError(
        'none',
        'No embedding provider configured or supplied for vector generation.'
      );
    }

    // 1. Authoritative lookup of memory within caller scope
    let memory: Memory | null;
    try {
      memory = this.memoryRepo.getMemoryById(memoryId, caller.scope);
    } catch (err) {
      if (err instanceof MemoryScopeViolationError) {
        this.audit(caller, 'MEMORY_ACCESS_DENIED', {
          reason: 'CROSS_SCOPE_EMBEDDING_GENERATE_ATTEMPT',
          memoryId,
          expectedScope: `${caller.scope.scopeType}:${caller.scope.scopeId}`
        }, false);
      }
      throw err;
    }

    if (!memory) {
      throw new MemoryNotFoundError(memoryId);
    }

    // 2. Strict status check: only ACTIVE memories can be embedded
    if (memory.status === 'PENDING_APPROVAL') {
      throw new ValidationError(
        `Cannot generate embedding for proposal '${memoryId}': status is PENDING_APPROVAL. Proposals cannot receive embeddings until approved.`
      );
    }

    if (memory.status !== 'ACTIVE') {
      throw new ValidationError(
        `Cannot generate embedding for memory '${memoryId}': status is '${memory.status}'. Only ACTIVE memories can receive embeddings.`
      );
    }

    // 3. Format text for embedding: combine key and content
    const textToEmbed = `${memory.key}: ${memory.content}`;

    // 4. Model inference executed strictly outside any SQLite transaction!
    const vector = await effectiveProvider.embed(textToEmbed);

    // 5. Persist into embedding repository
    const embedding = this.embeddingRepo.upsertEmbedding({
      memoryId: memory.id,
      modelId: effectiveProvider.modelId,
      modelRevision: 'main',
      dimensions: effectiveProvider.dimensions,
      embedding: vector
    });

    return embedding;
  }

  /**
   * Reconciles missing vector embeddings for active memories within an authorized scope.
   * 
   * Invariants:
   * 1. Requires WRITE permission and strict scope matching (workspace callers cannot sync global scope).
   * 2. Bounded batch size (1-25) and limit (default 100).
   * 3. Model inference executes strictly OUTSIDE SQLite database transactions.
   * 4. Pre-persist revalidation: detects concurrent deletions, archive transitions, or content updates,
   *    discarding stale embeddings without corrupting the database.
   * 5. Safe failure: if provider is unavailable or throws, returns structured result without crashing.
   * 6. Appends a privacy-safe MEMORY_EMBEDDINGS_SYNCED audit event with execution telemetry.
   */
  public async syncScopeEmbeddings(
    caller: CallerContext,
    options?: SyncScopeEmbeddingsOptions
  ): Promise<SyncScopeEmbeddingsResult> {
    if (!this.embeddingRepo) {
      throw new ValidationError('Memory embedding repository is not configured on MemoryService.');
    }

    this.validateCaller(caller, 'WRITE');

    if (options !== undefined && options !== null) {
      if (typeof options !== 'object') {
        throw new ValidationError('SyncScopeEmbeddingsOptions must be an object if provided.');
      }
      this.assertCallerScopeMatch(caller, options.scopeType, options.scopeId, 'syncScopeEmbeddings');
    }

    const targetScopeType = options?.scopeType ?? caller.scope.scopeType;
    const targetScopeId = options?.scopeId ?? caller.scope.scopeId;

    const batchSize = options?.batchSize ?? 25;
    if (
      typeof batchSize !== 'number' ||
      !Number.isInteger(batchSize) ||
      batchSize < 1 ||
      batchSize > 25
    ) {
      throw new ValidationError(
        `batchSize must be an integer between 1 and 25, received '${String(batchSize)}'.`
      );
    }

    const limit = options?.limit ?? 100;
    if (
      typeof limit !== 'number' ||
      !Number.isInteger(limit) ||
      limit < 1
    ) {
      throw new ValidationError(
        `limit must be a positive integer, received '${String(limit)}'.`
      );
    }

    const effectiveProvider = options?.provider ?? this.embeddingProvider;
    if (!effectiveProvider) {
      return {
        success: false,
        scope: { scopeType: targetScopeType, scopeId: targetScopeId },
        modelId: 'none',
        modelRevision: 'main',
        candidatesDiscovered: 0,
        embeddingsGenerated: 0,
        alreadyEmbeddedOrSkipped: 0,
        staleResultsDiscarded: 0,
        failed: 0,
        errors: ['No embedding provider configured or supplied for vector synchronization.']
      };
    }

    const modelId = options?.modelId ?? effectiveProvider.modelId;
    const modelRevision = options?.modelRevision ?? (effectiveProvider as any).modelRevision ?? 'main';

    let isAvailable = false;
    try {
      isAvailable = await effectiveProvider.isAvailable();
    } catch {
      isAvailable = false;
    }

    if (!isAvailable) {
      return {
        success: false,
        scope: { scopeType: targetScopeType, scopeId: targetScopeId },
        modelId,
        modelRevision,
        candidatesDiscovered: 0,
        embeddingsGenerated: 0,
        alreadyEmbeddedOrSkipped: 0,
        staleResultsDiscarded: 0,
        failed: 0,
        errors: [`Embedding provider '${effectiveProvider.name}' is unavailable.`]
      };
    }

    const candidates = this.embeddingRepo.getMemoriesMissingEmbeddings({
      scopeType: targetScopeType,
      scopeId: targetScopeId,
      modelId,
      modelRevision,
      limit
    });

    if (candidates.length === 0) {
      const remaining = this.memoryRepo.countMemoriesMissingEmbeddings(
        targetScopeType,
        targetScopeId,
        modelId,
        modelRevision
      );
      return {
        success: true,
        scope: { scopeType: targetScopeType, scopeId: targetScopeId },
        modelId,
        modelRevision,
        candidatesDiscovered: 0,
        embeddingsGenerated: 0,
        alreadyEmbeddedOrSkipped: 0,
        staleResultsDiscarded: 0,
        failed: 0,
        remaining
      };
    }

    const candidatesDiscovered = candidates.length;
    let embeddingsGenerated = 0;
    let alreadyEmbeddedOrSkipped = 0;
    let staleResultsDiscarded = 0;
    let failed = 0;
    const errors: string[] = [];

    for (let i = 0; i < candidates.length; i += batchSize) {
      const batch = candidates.slice(i, i + batchSize);
      const texts = batch.map((c) => `${c.key}: ${c.content}`);

      let vectors: Float32Array[];
      try {
        // Model inference executed strictly OUTSIDE any SQLite transaction!
        vectors = await effectiveProvider.embedBatch(texts);
      } catch (err) {
        const errorMsg = err instanceof Error ? err.message : String(err);
        errors.push(`Batch inference failed for ${batch.length} items: ${errorMsg}`);
        failed += batch.length;
        continue;
      }

      if (!Array.isArray(vectors) || vectors.length !== batch.length) {
        errors.push(`Provider returned ${vectors ? vectors.length : 0} vectors for ${batch.length} items.`);
        failed += batch.length;
        continue;
      }

      for (let j = 0; j < batch.length; j++) {
        const candidate = batch[j];
        const vector = vectors[j];

        try {
          validateVector(vector, effectiveProvider.dimensions, `embedding for memory ${candidate.id}`);
        } catch (err) {
          const errorMsg = err instanceof Error ? err.message : String(err);
          errors.push(`Vector validation failed for memory '${candidate.id}': ${errorMsg}`);
          failed++;
          continue;
        }

        try {
          this.embeddingRepo.transaction(() => {
            let currentMemory: Memory | null = null;
            try {
              currentMemory = this.memoryRepo.getMemoryById(candidate.id, {
                scopeType: targetScopeType,
                scopeId: targetScopeId
              });
            } catch {
              staleResultsDiscarded++;
              return;
            }

            if (!currentMemory) {
              staleResultsDiscarded++;
              return;
            }

            if (currentMemory.status !== 'ACTIVE') {
              staleResultsDiscarded++;
              return;
            }

            if (
              currentMemory.updatedAt !== candidate.updatedAt ||
              currentMemory.content !== candidate.content
            ) {
              staleResultsDiscarded++;
              return;
            }

            const existing = this.embeddingRepo!.getEmbedding(candidate.id, modelId, modelRevision);
            if (existing) {
              alreadyEmbeddedOrSkipped++;
              return;
            }

            this.embeddingRepo!.insertEmbedding({
              memoryId: candidate.id,
              modelId,
              modelRevision,
              dimensions: effectiveProvider.dimensions,
              embedding: vector
            });
            embeddingsGenerated++;
          });
        } catch (err) {
          const errorMsg = err instanceof Error ? err.message : String(err);
          errors.push(`Failed to persist embedding for memory '${candidate.id}': ${errorMsg}`);
          failed++;
        }
      }
    }

    this.audit(caller, 'MEMORY_EMBEDDINGS_SYNCED', {
      scopeType: targetScopeType,
      scopeId: targetScopeId,
      modelId,
      modelRevision,
      candidatesDiscovered,
      embeddingsGenerated,
      alreadyEmbeddedOrSkipped,
      staleResultsDiscarded,
      failed
    }, false);

    const remaining = this.memoryRepo.countMemoriesMissingEmbeddings(
      targetScopeType,
      targetScopeId,
      modelId,
      modelRevision
    );

    return {
      success: failed === 0,
      scope: { scopeType: targetScopeType, scopeId: targetScopeId },
      modelId,
      modelRevision,
      candidatesDiscovered,
      embeddingsGenerated,
      alreadyEmbeddedOrSkipped,
      staleResultsDiscarded,
      failed,
      remaining,
      ...(errors.length > 0 ? { errors } : {})
    };
  }

  /**
   * Safe, explicit backfill operation to generate embeddings for active memories
   * missing vectors for a specific model ID and revision.
   * 
   * Reuses syncScopeEmbeddings to guarantee:
   * 1. Bounded batching and sequential execution (concurrency = 1).
   * 2. Inference executes strictly OUTSIDE SQLite write transactions.
   * 3. Pre-persist revalidation guarantees stale results are discarded.
   * 4. Multi-tenant scope isolation and authorization boundaries are enforced.
   * 5. Embeddings for other model revisions are preserved untouched.
   */
  public async backfillModelRevision(
    caller: CallerContext,
    options?: BackfillModelRevisionOptions
  ): Promise<BackfillModelRevisionResult> {
    const syncResult = await this.syncScopeEmbeddings(caller, options);
    return {
      success: syncResult.success,
      scope: syncResult.scope,
      modelId: syncResult.modelId,
      modelRevision: syncResult.modelRevision,
      processed: syncResult.candidatesDiscovered,
      generated: syncResult.embeddingsGenerated,
      skipped: syncResult.alreadyEmbeddedOrSkipped + syncResult.staleResultsDiscarded,
      failed: syncResult.failed,
      remaining: syncResult.remaining ?? 0,
      ...(syncResult.errors && syncResult.errors.length > 0 ? { errors: syncResult.errors } : {})
    };
  }

  /**
   * Retrieves the stored embedding for an authorized memory item.
   * Enforces caller authorization, workspace isolation, and global inheritance boundaries.
   */
  public getMemoryEmbedding(
    caller: CallerContext,
    memoryId: string,
    modelId: string,
    modelRevision = 'main'
  ): MemoryEmbedding | null {
    this.validateCaller(caller, 'READ');
    if (!memoryId || typeof memoryId !== 'string' || memoryId.trim() === '') {
      throw new ValidationError('Memory ID must be a non-empty string.');
    }
    if (!modelId || typeof modelId !== 'string' || modelId.trim() === '') {
      throw new ValidationError('Model ID must be a non-empty string.');
    }

    if (!this.embeddingRepo) {
      return null;
    }

    const memory = this.getMemoryById(caller, memoryId);
    if (!memory) {
      throw new MemoryNotFoundError(memoryId);
    }

    if (!this.isMemoryEligibleForCaller(memory, caller)) {
      this.audit(caller, 'MEMORY_ACCESS_DENIED', {
        reason: 'UNAUTHORIZED_PRINCIPAL_EMBEDDING_ACCESS',
        memoryId,
        expectedScope: `${caller.scope.scopeType}:${caller.scope.scopeId}`
      }, false);
      throw new MemoryScopeViolationError(
        `${caller.scope.scopeType}:${caller.scope.scopeId}`,
        `${memory.scopeType}:${memory.scopeId}`,
        memory.id
      );
    }

    return this.embeddingRepo.getEmbedding(memory.id, modelId, modelRevision);
  }

  /**
   * Retrieves embeddings for a list of candidate memory IDs, filtering strictly
   * to those memories authorized for the caller under scope and inheritance rules.
   */
  public getMemoryEmbeddings(
    caller: CallerContext,
    memoryIds: readonly string[],
    modelId: string,
    modelRevision = 'main'
  ): MemoryEmbedding[] {
    this.validateCaller(caller, 'READ');
    if (!memoryIds || !Array.isArray(memoryIds) || memoryIds.length === 0) {
      return [];
    }
    if (!this.embeddingRepo) {
      return [];
    }

    const authorizedMemoryIds: string[] = [];
    for (const memId of memoryIds) {
      if (typeof memId !== 'string' || memId.trim() === '') continue;
      try {
        const mem = this.getMemoryById(caller, memId);
        if (mem && this.isMemoryEligibleForCaller(mem, caller)) {
          authorizedMemoryIds.push(mem.id);
        }
      } catch {
        // Unauthorized or non-existent memories are safely skipped
      }
    }

    if (authorizedMemoryIds.length === 0) {
      return [];
    }

    return this.embeddingRepo.getEmbeddingsForMemories(authorizedMemoryIds, modelId, modelRevision);
  }

  /**
   * Records memory injection provenance for an executed workflow task.
   * 
   * Fail-Closed Guarantees:
   * 1. Requires TaskRepository for authoritative task lookup.
   * 2. Authoritative task scope is derived strictly from immutable task metadata assigned
   *    upon task creation. If task metadata is missing, malformed, or untrusted, fails closed.
   * 3. Memory must exist, reside in the exact same scope as the task, and have status 'ACTIVE'.
   * 4. Inactive memories (proposals, archived) are strictly rejected.
   */
  public recordTaskInjection(
    caller: CallerContext,
    input: RecordMemoryInjectionInput
  ): MemoryTaskInjection {
    this.validateCaller(caller, 'WRITE');
    if (!input || typeof input !== 'object') {
      throw new ValidationError('RecordMemoryInjectionInput must be provided.');
    }
    if (!input.taskId || typeof input.taskId !== 'string' || input.taskId.trim() === '') {
      throw new ValidationError('Task ID must be a non-empty string.');
    }

    if (!this.taskRepo) {
      throw new ValidationError('TaskRepository is required for authoritative task lookup and injection provenance.');
    }

    // 1. Authoritative task lookup and scope validation
    const task = this.taskRepo.getTaskById(input.taskId);
    if (!task) {
      throw new TaskNotFoundError(input.taskId);
    }
    const taskScope = this.extractAuthoritativeTaskScope(task);

    // Verify task scope matches caller scope
    if (
      taskScope.scopeType !== caller.scope.scopeType ||
      taskScope.scopeId !== caller.scope.scopeId
    ) {
      this.audit(caller, 'MEMORY_ACCESS_DENIED', {
        reason: 'TASK_CALLER_SCOPE_MISMATCH',
        taskId: input.taskId,
        callerScope: `${caller.scope.scopeType}:${caller.scope.scopeId}`,
        taskScope: `${taskScope.scopeType}:${taskScope.scopeId}`
      }, false);
      throw new MemoryScopeViolationError(
        `${caller.scope.scopeType}:${caller.scope.scopeId}`,
        `${taskScope.scopeType}:${taskScope.scopeId}`,
        undefined,
        { taskId: input.taskId }
      );
    }

    // 2. Validate memory existence, scope, and ACTIVE status
    if (input.memoryId) {
      let memory: Memory | null = null;
      try {
        memory = this.memoryRepo.getMemoryById(input.memoryId, caller.scope);
      } catch (err) {
        if (!(err instanceof MemoryScopeViolationError)) {
          throw err;
        }
      }

      if (!memory && caller.scope.scopeType === 'WORKSPACE') {
        try {
          const globalMemory = this.memoryRepo.getMemoryById(input.memoryId, {
            scopeType: 'GLOBAL',
            scopeId: 'default'
          });
          if (globalMemory && this.isMemoryEligibleForCaller(globalMemory, caller)) {
            memory = globalMemory;
          }
        } catch {
          // not found or cross scope
        }
      }

      if (!memory) {
        throw new MemoryNotFoundError(input.memoryId);
      }

      // Memory must be ACTIVE to be injected
      if (memory.status !== 'ACTIVE') {
        throw new ValidationError(
          `Cannot record injection provenance for inactive memory '${input.memoryId}' (status: '${memory.status}').`
        );
      }

      const isAllowedScope =
        (memory.scopeType === taskScope.scopeType && memory.scopeId === taskScope.scopeId) ||
        (memory.scopeType === 'GLOBAL' && taskScope.scopeType === 'WORKSPACE' && this.isMemoryEligibleForCaller(memory, caller));

      if (!isAllowedScope) {
        this.audit(caller, 'MEMORY_ACCESS_DENIED', {
          reason: 'TASK_MEMORY_SCOPE_MISMATCH',
          taskId: input.taskId,
          memoryId: input.memoryId,
          taskScope: `${taskScope.scopeType}:${taskScope.scopeId}`,
          memoryScope: `${memory.scopeType}:${memory.scopeId}`
        }, false);
        throw new MemoryScopeViolationError(
          `${taskScope.scopeType}:${taskScope.scopeId}`,
          `${memory.scopeType}:${memory.scopeId}`,
          input.memoryId,
          { taskId: input.taskId }
        );
      }
    }

    return this.memoryRepo.recordInjection(input);
  }

  /**
   * Records a batch of injection provenance records atomically.
   * Uses an immediate database transaction to guarantee zero partial writes if any
   * memory record fails validation.
   */
  public recordTaskInjectionsBatch(
    caller: CallerContext,
    inputs: readonly RecordMemoryInjectionInput[]
  ): MemoryTaskInjection[] {
    this.validateCaller(caller, 'WRITE');
    if (!Array.isArray(inputs)) {
      throw new ValidationError('Inputs must be an array of RecordMemoryInjectionInput.');
    }
    if (inputs.length === 0) {
      return [];
    }

    if (!this.taskRepo) {
      throw new ValidationError('TaskRepository is required for authoritative task lookup and injection provenance.');
    }

    // Pre-validate all inputs and execute atomically within transaction
    return this.memoryRepo.transaction(() => {
      const results: MemoryTaskInjection[] = [];
      for (const input of inputs) {
        results.push(this.recordTaskInjection(caller, input));
      }
      return results;
    });
  }

  /**
   * Retrieves injection provenance records for a given task, enforcing authoritative task scope.
   */
  public getInjectionsByTaskId(caller: CallerContext, taskId: string): MemoryTaskInjection[] {
    this.validateCaller(caller, 'READ');
    if (!taskId || typeof taskId !== 'string' || taskId.trim() === '') {
      throw new ValidationError('Task ID must be a non-empty string.');
    }

    if (!this.taskRepo) {
      throw new ValidationError('TaskRepository is required for authoritative task lookup.');
    }

    const task = this.taskRepo.getTaskById(taskId);
    if (!task) {
      throw new TaskNotFoundError(taskId);
    }
    const taskScope = this.extractAuthoritativeTaskScope(task);
    if (
      taskScope.scopeType !== caller.scope.scopeType ||
      taskScope.scopeId !== caller.scope.scopeId
    ) {
      this.audit(caller, 'MEMORY_ACCESS_DENIED', {
        reason: 'TASK_CALLER_SCOPE_MISMATCH',
        taskId,
        callerScope: `${caller.scope.scopeType}:${caller.scope.scopeId}`,
        taskScope: `${taskScope.scopeType}:${taskScope.scopeId}`
      }, false);
      throw new MemoryScopeViolationError(
        `${caller.scope.scopeType}:${caller.scope.scopeId}`,
        `${taskScope.scopeType}:${taskScope.scopeId}`,
        undefined,
        { taskId }
      );
    }

    return this.memoryRepo.getInjectionsByTaskId(taskId);
  }

  /**
   * Explicitly updates access timestamp and access count for a memory item.
   */
  public recordAccess(caller: CallerContext, id: string): Memory {
    const permissions = this.validateCaller(caller);
    if (!permissions.has('READ') && !permissions.has('WRITE')) {
      this.audit(caller, 'MEMORY_ACCESS_DENIED', {
        reason: 'INSUFFICIENT_PERMISSIONS',
        operation: 'recordAccess',
        actor: caller.actor
      }, false);
      throw new SecurityViolationError(
        `Caller '${caller.actor}' lacks READ or WRITE permission to record memory access.`,
        'INSUFFICIENT_PERMISSIONS',
        { actor: caller.actor }
      );
    }

    if (!id || typeof id !== 'string' || id.trim() === '') {
      throw new ValidationError('Memory ID must be a non-empty string.');
    }

    return this.memoryRepo.recordAccess(id, caller.scope);
  }

  /**
   * Builds a safe, bounded memory context block for task execution using hybrid retrieval.
   * Only ACTIVE memories authorized for the caller (including inherited global memories for workspace tasks)
   * are considered, with deterministic workspace-over-global conflict resolution.
   * Batch injection recording uses a database transaction to prevent partial writes.
   */
  public buildTaskMemoryContext(
    caller: CallerContext,
    options: BuildTaskMemoryContextOptions
  ): BuiltMemoryContext & PromiseLike<BuiltMemoryContext> {
    this.validateCaller(caller, 'READ');
    if (!options || typeof options !== 'object') {
      throw new ValidationError('BuildTaskMemoryContextOptions must be provided.');
    }
    if (typeof options.query !== 'string') {
      throw new ValidationError('Query must be a string.');
    }

    // Reject explicit scope spoofing attempts
    this.assertCallerScopeMatch(caller, (options as any).scopeType, (options as any).scopeId, 'buildTaskMemoryContext');

    // If taskId is provided, verify task exists and authoritative scope is compatible
    if (options.taskId) {
      if (!this.taskRepo) {
        throw new ValidationError('TaskRepository is required for authoritative task lookup.');
      }
      const task = this.taskRepo.getTaskById(options.taskId);
      if (!task) {
        throw new TaskNotFoundError(options.taskId);
      }
      const taskScope = this.extractAuthoritativeTaskScope(task);
      if (
        taskScope.scopeType !== caller.scope.scopeType ||
        taskScope.scopeId !== caller.scope.scopeId
      ) {
        this.audit(caller, 'MEMORY_ACCESS_DENIED', {
          reason: 'TASK_CALLER_SCOPE_MISMATCH',
          taskId: options.taskId,
          callerScope: `${caller.scope.scopeType}:${caller.scope.scopeId}`,
          taskScope: `${taskScope.scopeType}:${taskScope.scopeId}`
        }, false);
        throw new MemoryScopeViolationError(
          `${caller.scope.scopeType}:${caller.scope.scopeId}`,
          `${taskScope.scopeType}:${taskScope.scopeId}`,
          undefined,
          { taskId: options.taskId }
        );
      }
    }

    // Query active memories eligible for caller (with inheritance and conflict resolution)
    const candidates = this.getEligibleCandidateMemories(caller, options.category);

    // Configure context builder
    let builder = this.contextBuilder;
    if (options.maxBudgetChars !== undefined || options.relevanceThreshold !== undefined) {
      builder = new MemoryContextBuilder({
        maxBudgetChars: options.maxBudgetChars,
        relevanceThreshold: options.relevanceThreshold,
        matcher: this.relevanceMatcher
      });
    }

    const syncContext = builder.buildContext(options.query, candidates);

    // If no embedding provider is configured, synchronous lexical is the only result
    if (!this.embeddingProvider || !this.embeddingRepo) {
      if (options.recordInjections && options.taskId) {
        const taskId = options.taskId;
        this.memoryRepo.transaction(() => {
          for (const inc of syncContext.included) {
            this.recordTaskInjection(caller, {
              taskId,
              memoryId: inc.id,
              charCount: syncContext.totalChars,
              estimatedTokens: syncContext.estimatedTokens
            });
          }
        });
      }

      if (syncContext.included.length > 0) {
        this.audit(caller, 'MEMORY_RETRIEVED', {
          memoryIds: syncContext.included.map((m) => m.id),
          count: syncContext.included.length,
          inheritedCount: syncContext.included.filter((m) => m.isInherited).length,
          scopeType: caller.scope.scopeType,
          scopeId: caller.scope.scopeId,
          taskId: options.taskId
        }, false);
      }

      return syncContext as any;
    }

    // When embedding provider is configured, return dual context
    const asyncPromise = this.executeHybridBuildContext(caller, options, candidates, builder);
    return createDualContext(syncContext, asyncPromise);
  }

  /**
   * Explicit asynchronous version of buildTaskMemoryContext returning a Promise.
   * Phase 4D.2A Optimization: Directly executes hybrid build context in a single pass without
   * performing unused synchronous fallback context building upfront.
   */
  public async buildTaskMemoryContextAsync(
    caller: CallerContext,
    options: BuildTaskMemoryContextOptions
  ): Promise<BuiltMemoryContext> {
    if (this.embeddingProvider && this.embeddingRepo) {
      this.validateCaller(caller, 'READ');
      this.assertCallerScopeMatch(caller, (options as any).scopeType, (options as any).scopeId, 'buildTaskMemoryContext');
      const candidates = this.getEligibleCandidateMemories(caller, options.category);
      let builder = this.contextBuilder;
      if (options.maxBudgetChars !== undefined || options.relevanceThreshold !== undefined) {
        builder = new MemoryContextBuilder({
          maxBudgetChars: options.maxBudgetChars,
          relevanceThreshold: options.relevanceThreshold,
          matcher: this.relevanceMatcher
        });
      }
      return this.executeHybridBuildContext(caller, options, candidates, builder);
    }
    return Promise.resolve(this.buildTaskMemoryContext(caller, options));
  }

  private async executeHybridBuildContext(
    caller: CallerContext,
    options: BuildTaskMemoryContextOptions,
    candidates: Memory[],
    builder: MemoryContextBuilder,
    precomputedLexicalScores?: ReadonlyMap<string, ScoredMemory>
  ): Promise<BuiltMemoryContext> {
    const query = options.query.trim();
    let hybridRanked: HybridScoredMemory[] = [];

    if (query && candidates.length > 0) {
      if (!this.embeddingRepo || !this.embeddingProvider) {
        hybridRanked = this.hybridRetriever.rank(query, candidates, null, null, {
          fallbackProvenance: 'LEXICAL_ONLY',
          precomputedLexicalScores
        });
      } else {
        let isAvailable = false;
        try {
          isAvailable = await this.embeddingProvider.isAvailable();
        } catch {
          isAvailable = false;
        }

        if (!isAvailable) {
          hybridRanked = this.hybridRetriever.rank(query, candidates, null, null, {
            fallbackProvenance: 'LEXICAL_FALLBACK',
            precomputedLexicalScores
          });
        } else {
          let queryVec: Float32Array | null = null;
          try {
            queryVec = await this.embeddingProvider.embed(query);
            validateVector(queryVec, this.embeddingProvider.dimensions, 'query embedding');
          } catch {
            queryVec = null;
          }

          if (!queryVec) {
            hybridRanked = this.hybridRetriever.rank(query, candidates, null, null, {
              fallbackProvenance: 'LEXICAL_FALLBACK',
              precomputedLexicalScores
            });
          } else {
            // CRITICAL SECURITY INVARIANT:
            // Fetch embeddings ONLY for the authorized candidates' IDs!
            const candidateIds = candidates.map((c) => c.id);
            const storedEmbeddings = this.embeddingRepo.getEmbeddingsForMemories(
              candidateIds,
              this.embeddingProvider.modelId,
              (this.embeddingProvider as any).modelRevision ?? 'main'
            );

            hybridRanked = this.hybridRetriever.rank(
              query,
              candidates,
              queryVec,
              storedEmbeddings,
              {
                modelId: this.embeddingProvider.modelId,
                modelRevision: (this.embeddingProvider as any).modelRevision ?? 'main',
                modelDimensions: this.embeddingProvider.dimensions,
                fallbackProvenance: 'LEXICAL_FALLBACK',
                precomputedLexicalScores
              }
            );
          }
        }
      }
    }

    const context = builder.buildContext(options.query, candidates, hybridRanked);

    if (options.recordInjections && options.taskId) {
      const taskId = options.taskId;
      this.memoryRepo.transaction(() => {
        for (const inc of context.included) {
          this.recordTaskInjection(caller, {
            taskId,
            memoryId: inc.id,
            charCount: context.totalChars,
            estimatedTokens: context.estimatedTokens
          });
        }
      });
    }

    if (context.included.length > 0) {
      this.audit(caller, 'MEMORY_RETRIEVED', {
        memoryIds: context.included.map((m) => m.id),
        count: context.included.length,
        inheritedCount: context.included.filter((m) => m.isInherited).length,
        scopeType: caller.scope.scopeType,
        scopeId: caller.scope.scopeId,
        taskId: options.taskId
      }, false);
    }

    return context;
  }

  /**
   * Searches active memories within the caller's authorized scope using hybrid semantic and lexical ranking.
   * Enforces caller verification, READ permission, task scope alignment (if taskId provided),
   * same-principal global memory inheritance for workspace callers,
   * strictly excludes zero-relevance results (score <= 0.0), and limits returned records (1-50, default 5).
   */
  public searchMemories(
    caller: CallerContext,
    options: SearchMemoriesOptions
  ): HybridScoredMemory[] & PromiseLike<HybridScoredMemory[]> {
    this.validateCaller(caller, 'READ');
    if (!options || typeof options !== 'object') {
      throw new ValidationError('SearchMemoriesOptions must be provided.');
    }
    if (typeof options.query !== 'string') {
      throw new ValidationError('Query must be a string.');
    }

    // Reject explicit scope spoofing attempts
    this.assertCallerScopeMatch(caller, options.scopeType, options.scopeId, 'searchMemories');

    // Limit validation
    let limit = 5;
    if (options.limit !== undefined) {
      if (
        typeof options.limit !== 'number' ||
        !Number.isInteger(options.limit) ||
        options.limit < 1 ||
        options.limit > 50
      ) {
        throw new ValidationError(
          `Memory search limit must be an integer between 1 and 50, received '${String(options.limit)}'.`
        );
      }
      limit = options.limit;
    }

    // Category validation
    if (options.category !== undefined && !VALID_CATEGORIES.has(options.category)) {
      throw new ValidationError(
        `Invalid memory category '${String(options.category)}'. Must be one of: ${Array.from(VALID_CATEGORIES).join(', ')}.`
      );
    }

    // If taskId is provided, verify task exists and authoritative scope is compatible
    if (options.taskId) {
      if (!this.taskRepo) {
        throw new ValidationError('TaskRepository is required for authoritative task lookup.');
      }
      const task = this.taskRepo.getTaskById(options.taskId);
      if (!task) {
        throw new TaskNotFoundError(options.taskId);
      }
      const taskScope = this.extractAuthoritativeTaskScope(task);
      if (
        taskScope.scopeType !== caller.scope.scopeType ||
        taskScope.scopeId !== caller.scope.scopeId
      ) {
        this.audit(caller, 'MEMORY_ACCESS_DENIED', {
          reason: 'TASK_CALLER_SCOPE_MISMATCH',
          taskId: options.taskId,
          callerScope: `${caller.scope.scopeType}:${caller.scope.scopeId}`,
          taskScope: `${taskScope.scopeType}:${taskScope.scopeId}`
        }, false);
        throw new MemoryScopeViolationError(
          `${caller.scope.scopeType}:${caller.scope.scopeId}`,
          `${taskScope.scopeType}:${taskScope.scopeId}`,
          undefined,
          { taskId: options.taskId }
        );
      }
    }

    // Query active memories eligible for caller (with inheritance and conflict resolution)
    const candidates = this.getEligibleCandidateMemories(caller, options.category);

    const query = options.query.trim();

    // Baseline synchronous lexical ranking
    let syncResults: HybridScoredMemory[] = [];
    let precomputedLexicalScores: Map<string, ScoredMemory> | undefined;

    if (query && candidates.length > 0) {
      const ranked = this.hybridRetriever.rank(query, candidates, null, null, {
        fallbackProvenance: this.embeddingProvider ? 'LEXICAL_FALLBACK' : 'LEXICAL_ONLY'
      });
      precomputedLexicalScores = new Map(ranked.map((s) => [s.memory.id, s]));
      const relevant = ranked.filter((scored) => scored.score > 0);
      syncResults = relevant.slice(0, limit).map((scored) => ({
        ...scored,
        isInherited: Boolean(
          (scored.memory as any)._isInherited ??
          (scored.memory.scopeType === 'GLOBAL' && caller.scope.scopeType === 'WORKSPACE')
        )
      }));
    }

    // If no embedding provider/repo configured, return synchronous lexical results directly
    if (!this.embeddingProvider || !this.embeddingRepo) {
      if (syncResults.length > 0) {
        this.audit(caller, 'MEMORY_RETRIEVED', {
          memoryIds: syncResults.map((m) => m.memory.id),
          count: syncResults.length,
          inheritedCount: syncResults.filter((m) => m.isInherited).length,
          scopeType: caller.scope.scopeType,
          scopeId: caller.scope.scopeId,
          taskId: options.taskId,
          operation: 'searchMemories'
        }, false);
      }
      return syncResults as any;
    }

    // Async hybrid search promise - pass precomputed lexical scores to eliminate duplicate lexical ranking
    const asyncPromise = this.executeHybridSearch(
      caller,
      options,
      candidates,
      query,
      limit,
      precomputedLexicalScores
    );
    return createDualSearchResult(syncResults, asyncPromise);
  }

  /**
   * Explicit asynchronous version of searchMemories returning a Promise.
   * Phase 4D.2A Optimization: Directly executes hybrid search in a single pass without
   * performing unused synchronous fallback evaluations upfront.
   */
  public async searchMemoriesAsync(
    caller: CallerContext,
    options: SearchMemoriesOptions
  ): Promise<HybridScoredMemory[]> {
    this.validateCaller(caller, 'READ');
    if (!options || typeof options !== 'object') {
      throw new ValidationError('SearchMemoriesOptions must be provided.');
    }
    if (typeof options.query !== 'string') {
      throw new ValidationError('Query must be a string.');
    }

    // Reject explicit scope spoofing attempts
    this.assertCallerScopeMatch(caller, options.scopeType, options.scopeId, 'searchMemories');

    // Limit validation
    let limit = 5;
    if (options.limit !== undefined) {
      if (
        typeof options.limit !== 'number' ||
        !Number.isInteger(options.limit) ||
        options.limit < 1 ||
        options.limit > 50
      ) {
        throw new ValidationError(
          `Memory search limit must be an integer between 1 and 50, received '${String(options.limit)}'.`
        );
      }
      limit = options.limit;
    }

    // Category validation
    if (options.category !== undefined && !VALID_CATEGORIES.has(options.category)) {
      throw new ValidationError(
        `Invalid memory category '${String(options.category)}'. Must be one of: ${Array.from(VALID_CATEGORIES).join(', ')}.`
      );
    }

    // If taskId is provided, verify task exists and authoritative scope is compatible
    if (options.taskId) {
      if (!this.taskRepo) {
        throw new ValidationError('TaskRepository is required for authoritative task lookup.');
      }
      const task = this.taskRepo.getTaskById(options.taskId);
      if (!task) {
        throw new TaskNotFoundError(options.taskId);
      }
      const taskScope = this.extractAuthoritativeTaskScope(task);
      if (
        taskScope.scopeType !== caller.scope.scopeType ||
        taskScope.scopeId !== caller.scope.scopeId
      ) {
        this.audit(caller, 'MEMORY_ACCESS_DENIED', {
          reason: 'TASK_CALLER_SCOPE_MISMATCH',
          taskId: options.taskId,
          callerScope: `${caller.scope.scopeType}:${caller.scope.scopeId}`,
          taskScope: `${taskScope.scopeType}:${taskScope.scopeId}`
        }, false);
        throw new MemoryScopeViolationError(
          `${caller.scope.scopeType}:${caller.scope.scopeId}`,
          `${taskScope.scopeType}:${taskScope.scopeId}`,
          undefined,
          { taskId: options.taskId }
        );
      }
    }

    // Query active memories eligible for caller (with inheritance and conflict resolution)
    const candidates = this.getEligibleCandidateMemories(caller, options.category);
    const query = options.query.trim();

    if (!query || candidates.length === 0) {
      return [];
    }

    // If no embedding provider/repo configured, execute single synchronous pass and return
    if (!this.embeddingProvider || !this.embeddingRepo) {
      const ranked = this.hybridRetriever.rank(query, candidates, null, null, {
        fallbackProvenance: 'LEXICAL_ONLY'
      });
      const relevant = ranked.filter((scored) => scored.score > 0);
      const results = relevant.slice(0, limit).map((scored) => ({
        ...scored,
        isInherited: Boolean(
          (scored.memory as any)._isInherited ??
          (scored.memory.scopeType === 'GLOBAL' && caller.scope.scopeType === 'WORKSPACE')
        )
      }));
      if (results.length > 0) {
        this.audit(caller, 'MEMORY_RETRIEVED', {
          memoryIds: results.map((m) => m.memory.id),
          count: results.length,
          inheritedCount: results.filter((m) => m.isInherited).length,
          scopeType: caller.scope.scopeType,
          scopeId: caller.scope.scopeId,
          taskId: options.taskId,
          operation: 'searchMemories'
        }, false);
      }
      return results;
    }

    // Phase 4D.2A: Directly execute single-pass hybrid search without duplicate lexical evaluation
    return this.executeHybridSearch(caller, options, candidates, query, limit);
  }

  private async executeHybridSearch(
    caller: CallerContext,
    options: SearchMemoriesOptions,
    candidates: Memory[],
    query: string,
    limit: number,
    precomputedLexicalScores?: ReadonlyMap<string, ScoredMemory>
  ): Promise<HybridScoredMemory[]> {
    if (!query || candidates.length === 0) {
      return [];
    }

    let hybridResults: HybridScoredMemory[];

    if (!this.embeddingRepo || !this.embeddingProvider) {
      hybridResults = this.hybridRetriever.rank(query, candidates, null, null, {
        fallbackProvenance: 'LEXICAL_ONLY',
        precomputedLexicalScores
      });
    } else {
      let isAvailable = false;
      try {
        isAvailable = await this.embeddingProvider.isAvailable();
      } catch {
        isAvailable = false;
      }

      if (!isAvailable) {
        hybridResults = this.hybridRetriever.rank(query, candidates, null, null, {
          fallbackProvenance: 'LEXICAL_FALLBACK',
          precomputedLexicalScores
        });
      } else {
        let queryVec: Float32Array | null = null;
        try {
          queryVec = await this.embeddingProvider.embed(query);
          validateVector(queryVec, this.embeddingProvider.dimensions, 'query embedding');
        } catch {
          queryVec = null;
        }

        if (!queryVec) {
          hybridResults = this.hybridRetriever.rank(query, candidates, null, null, {
            fallbackProvenance: 'LEXICAL_FALLBACK',
            precomputedLexicalScores
          });
        } else {
          // CRITICAL SECURITY INVARIANT:
          // Fetch embeddings ONLY for the authorized candidates' IDs!
          const candidateIds = candidates.map((c) => c.id);
          const storedEmbeddings = this.embeddingRepo.getEmbeddingsForMemories(
            candidateIds,
            this.embeddingProvider.modelId,
            (this.embeddingProvider as any).modelRevision ?? 'main'
          );

          hybridResults = this.hybridRetriever.rank(
            query,
            candidates,
            queryVec,
            storedEmbeddings,
            {
              modelId: this.embeddingProvider.modelId,
              modelRevision: (this.embeddingProvider as any).modelRevision ?? 'main',
              modelDimensions: this.embeddingProvider.dimensions,
              fallbackProvenance: 'LEXICAL_FALLBACK',
              precomputedLexicalScores
            }
          );
        }
      }
    }

    const relevant = hybridResults.filter((scored) => scored.score > 0);
    const limited = relevant.slice(0, limit);

    const results: HybridScoredMemory[] = limited.map((scored) => ({
      ...scored,
      isInherited: Boolean(
        (scored.memory as any)._isInherited ??
        (scored.memory.scopeType === 'GLOBAL' && caller.scope.scopeType === 'WORKSPACE')
      )
    }));

    if (results.length > 0) {
      this.audit(caller, 'MEMORY_RETRIEVED', {
        memoryIds: results.map((m) => m.memory.id),
        count: results.length,
        inheritedCount: results.filter((m) => m.isInherited).length,
        scopeType: caller.scope.scopeType,
        scopeId: caller.scope.scopeId,
        taskId: options.taskId,
        operation: 'searchMemories'
      }, false);
    }

    return results;
  }

  /**
   * Retrieves active candidate memories eligible for the caller, applying workspace isolation,
   * same-principal global memory inheritance (for workspace callers), active/expiry checks,
   * and deterministic workspace-over-global conflict resolution.
   */
  public getEligibleCandidateMemories(
    caller: CallerContext,
    category?: MemoryCategory
  ): Memory[] {
    if (caller.scope.scopeType === 'WORKSPACE') {
      // 1. Retrieve current workspace candidates
      const workspaceCandidates = this.memoryRepo.listMemories({
        scopeType: 'WORKSPACE',
        scopeId: caller.scope.scopeId,
        status: 'ACTIVE',
        category
      }).filter((m) => this.isMemoryEligibleForCaller(m, caller));

      for (const m of workspaceCandidates) {
        (m as any)._isInherited = false;
      }

      // 2. Check if caller is authorized to inherit GLOBAL memories
      const eligibleGlobal: Memory[] = [];
      const canAccessGlobal =
        !caller.permittedScopes ||
        caller.permittedScopes.length === 0 ||
        caller.permittedScopes.some(
          (s) => s.scopeType === 'GLOBAL' && s.scopeId === 'default'
        );

      if (canAccessGlobal) {
        const rawGlobal = this.memoryRepo.listMemories({
          scopeType: 'GLOBAL',
          scopeId: 'default',
          status: 'ACTIVE',
          category
        });

        for (const gm of rawGlobal) {
          if (this.isMemoryEligibleForCaller(gm, caller)) {
            (gm as any)._isInherited = true;
            eligibleGlobal.push(gm);
          }
        }
      }

      // 3. Conflict resolution: deterministic workspace-over-global precedence.
      // When the same normalized memory key exists in both scopes, the workspace record overrides.
      const workspaceNormalizedKeys = new Set(
        workspaceCandidates.map((m) => m.key.trim().toLowerCase())
      );

      const nonConflictingGlobal = eligibleGlobal.filter(
        (gm) => !workspaceNormalizedKeys.has(gm.key.trim().toLowerCase())
      );

      return [...workspaceCandidates, ...nonConflictingGlobal];
    } else {
      // GLOBAL scope: retrieve authorized GLOBAL memories only. Never workspace memories.
      const rawGlobal = this.memoryRepo.listMemories({
        scopeType: 'GLOBAL',
        scopeId: 'default',
        status: 'ACTIVE',
        category
      });

      const eligibleGlobal: Memory[] = [];
      for (const gm of rawGlobal) {
        if (this.isMemoryEligibleForCaller(gm, caller)) {
          (gm as any)._isInherited = false;
          eligibleGlobal.push(gm);
        }
      }

      return eligibleGlobal;
    }
  }

  /**
   * Lists active global memories eligible for this caller (used by knowledge proposal duplicate suppression).
   */
  public listEligibleGlobalMemories(caller: CallerContext): Memory[] {
    this.validateCaller(caller, 'READ');
    const canAccessGlobal =
      !caller.permittedScopes ||
      caller.permittedScopes.length === 0 ||
      caller.permittedScopes.some(
        (s) => s.scopeType === 'GLOBAL' && s.scopeId === 'default'
      );

    if (!canAccessGlobal) {
      return [];
    }

    const rawGlobal = this.memoryRepo.listMemories({
      scopeType: 'GLOBAL',
      scopeId: 'default',
      status: 'ACTIVE'
    });

    return rawGlobal.filter((gm) => this.isMemoryEligibleForCaller(gm, caller));
  }

  /**
   * Verifies that a memory is active, not expired, and authorized for the caller under
   * strict same-principal and workspace isolation boundaries.
   */
  public isMemoryEligibleForCaller(memory: Memory, caller: CallerContext): boolean {
    if (!memory || memory.status !== 'ACTIVE') {
      return false;
    }

    // Expiry check
    if (memory.metadataJson) {
      try {
        const meta = JSON.parse(memory.metadataJson);
        if (meta && typeof meta === 'object') {
          if (meta.expired === true) {
            return false;
          }
          if (typeof meta.expiresAt === 'string') {
            const expTime = new Date(meta.expiresAt).getTime();
            if (!isNaN(expTime) && expTime <= Date.now()) {
              return false;
            }
          }
        }
      } catch {
        // malformed metadata handled as ineligible
        return false;
      }
    }

    if (memory.scopeType === 'WORKSPACE') {
      return caller.scope.scopeType === 'WORKSPACE' && caller.scope.scopeId === memory.scopeId;
    }

    if (memory.scopeType === 'GLOBAL') {
      // If caller is in WORKSPACE, verify permittedScopes includes GLOBAL
      if (caller.scope.scopeType !== 'GLOBAL') {
        if (caller.permittedScopes && caller.permittedScopes.length > 0) {
          const hasGlobal = caller.permittedScopes.some(
            (s) => s.scopeType === 'GLOBAL' && s.scopeId === 'default'
          );
          if (!hasGlobal) {
            return false;
          }
        }
      }

      // Principal/tenant boundary verification
      const memoryPrincipal = this.extractMemoryPrincipalId(memory);
      const callerPrincipal = caller.principalId;

      if (callerPrincipal) {
        // Authenticated principal: memory must belong to the exact same principal
        return memoryPrincipal === callerPrincipal;
      }

      // Unidentified caller: if memory has an assigned principal, fail closed
      if (memoryPrincipal) {
        return false;
      }

      // Both caller and memory have no principal (single-tenant local fallback)
      return true;
    }

    return false;
  }

  /**
   * Extracts principal or tenant identifier from memory metadata if present.
   */
  public extractMemoryPrincipalId(memory: Memory): string | undefined {
    if (!memory || !memory.metadataJson) {
      return undefined;
    }
    try {
      const meta = JSON.parse(memory.metadataJson);
      if (meta && typeof meta === 'object') {
        const pid = meta.principalId ?? meta.ownerId ?? meta.tenantId ?? meta.userId ?? meta.createdBy;
        if (typeof pid === 'string' && pid.trim() !== '') {
          return pid.trim();
        }
      }
    } catch {
      return undefined;
    }
    return undefined;
  }

  /**
   * Retrieves the task injection provenance history for a memory record within caller scope.
   * Enforces caller verification and READ permissions.
   * Throws MemoryScopeViolationError if the memory exists in a different scope.
   * Throws MemoryNotFoundError if the memory does not exist.
   */
  public getMemoryUsageHistory(caller: CallerContext, memoryId: string): MemoryUsageHistory {
    this.validateCaller(caller, 'READ');
    if (!memoryId || typeof memoryId !== 'string' || memoryId.trim() === '') {
      throw new ValidationError('Memory ID must be a non-empty string.');
    }

    let memory: Memory | null;
    try {
      memory = this.memoryRepo.getMemoryById(memoryId, caller.scope);
    } catch (err) {
      if (err instanceof MemoryScopeViolationError) {
        this.audit(caller, 'MEMORY_ACCESS_DENIED', {
          reason: 'CROSS_SCOPE_READ_ATTEMPT',
          operation: 'getMemoryUsageHistory',
          memoryId,
          expectedScope: `${caller.scope.scopeType}:${caller.scope.scopeId}`
        }, false);
      }
      throw err;
    }

    if (!memory) {
      throw new MemoryNotFoundError(memoryId);
    }

    const injections = this.memoryRepo.getInjectionsByMemoryId(memoryId);
    const totalChars = injections.reduce((sum, inj) => sum + inj.charCount, 0);
    const totalEstimatedTokens = injections.reduce((sum, inj) => sum + inj.estimatedTokens, 0);

    this.audit(caller, 'MEMORY_RETRIEVED', {
      memoryId: memory.id,
      category: memory.category,
      scopeType: memory.scopeType,
      scopeId: memory.scopeId,
      operation: 'getMemoryUsageHistory',
      totalInjections: injections.length
    }, false);

    return {
      memoryId: memory.id,
      scope: {
        scopeType: memory.scopeType,
        scopeId: memory.scopeId
      },
      totalInjections: injections.length,
      totalChars,
      totalEstimatedTokens,
      injections
    };
  }

  /**
   * Exports memories within the caller's authorized scope into a canonical, portable bundle
   * with a SHA-256 integrity checksum.
   * 
   * Safeguards:
   * 1. Authorized scope is derived strictly from verified caller (caller.scope).
   * 2. Any explicit scope in options is validated to match caller.scope; mismatches throw MemoryScopeViolationError.
   * 3. Memory content is preserved lossless (byte-for-byte); no secret scrubbing on backup exports.
   * 4. Excludes internal database UUIDs (id) to allow cross-environment portability without collisions.
   * 5. Items are deterministically sorted by (category, key, createdAt).
   * 6. Appends a privacy-safe MEMORY_EXPORTED audit event with metadata only (no raw content or secrets).
   * 7. The operation is strictly read-only regarding memory and injection tables.
   */
  public exportMemories(
    caller: CallerContext,
    options: ExportMemoriesOptions = {}
  ): MemoryExportBundle {
    this.validateCaller(caller, 'READ');
    if (!options || typeof options !== 'object') {
      throw new ValidationError('ExportMemoriesOptions must be an object if provided.');
    }

    // Verify requested scope matches caller's authorized scope
    this.assertCallerScopeMatch(caller, options.scopeType, options.scopeId, 'exportMemories');

    // List memories within authorized caller scope
    const memories = this.memoryRepo.listMemories({
      scopeType: caller.scope.scopeType,
      scopeId: caller.scope.scopeId,
      category: options.category
    });

    // Filter by status: active memories always; archived only if includeArchived is true.
    // Exclude PENDING_APPROVAL proposals from export bundles.
    const filtered = memories.filter((m) => {
      if (m.status === 'ACTIVE') {
        return true;
      }
      if (options.includeArchived === true && m.status === 'ARCHIVED') {
        return true;
      }
      return false;
    });

    // Map to export items preserving content byte-for-byte
    const items: MemoryExportItem[] = filtered.map((m) => {
      let tags: string[] = [];
      try {
        tags = JSON.parse(m.tagsJson || '[]');
      } catch {
        tags = [];
      }

      let metadata: Record<string, unknown> = {};
      try {
        metadata = JSON.parse(m.metadataJson || '{}');
      } catch {
        metadata = {};
      }

      return {
        key: m.key,
        content: m.content,
        category: m.category,
        tags,
        priority: m.priority,
        metadata,
        status: m.status,
        createdAt: m.createdAt,
        updatedAt: m.updatedAt
      };
    });

    // Deterministic sorting by category ASC, key ASC, createdAt ASC
    items.sort((a, b) => {
      if (a.category !== b.category) {
        return a.category < b.category ? -1 : 1;
      }
      if (a.key !== b.key) {
        return a.key < b.key ? -1 : 1;
      }
      return a.createdAt < b.createdAt ? -1 : a.createdAt > b.createdAt ? 1 : 0;
    });

    const exportedAt = new Date().toISOString();
    const sourceScope: ScopeIdentifier = {
      scopeType: caller.scope.scopeType,
      scopeId: caller.scope.scopeId
    };

    const bundlePayload = {
      version: '1.0' as const,
      exportedAt,
      sourceScope,
      count: items.length,
      memories: items
    };

    const checksum = computeCanonicalSha256(bundlePayload);

    const bundle: MemoryExportBundle = {
      ...bundlePayload,
      checksum
    };

    // Emit MEMORY_EXPORTED audit event with metadata only - no raw content or secret leakage
    this.audit(caller, 'MEMORY_EXPORTED', {
      scopeType: caller.scope.scopeType,
      scopeId: caller.scope.scopeId,
      exportedCount: items.length,
      checksum: bundle.checksum
    }, false);

    return bundle;
  }

  /**
   * Imports memories from a canonical bundle into the caller's authorized scope
   * with atomic conflict resolution and fail-closed audit logging.
   * 
   * Architectural & Security Guarantees:
   * 1. Authorization: Requires verified caller with explicit WRITE permission.
   * 2. Scope Isolation: Destination scope is derived strictly from verified caller (caller.scope).
   *    Never trusts bundle.sourceScope for authorization or destination routing.
   * 3. Pre-flight Validation: Validates bundle structure, version, count, item fields,
   *    checksum (via verifyBundleChecksum), and duplicate active keys BEFORE database transaction.
   * 4. Proposal Isolation: Rejects entries with status 'PENDING_APPROVAL'. Imported entries must be ACTIVE or ARCHIVED.
   * 5. Uniqueness Rule: Uniqueness is enforced on (scope_type, scope_id, key) WHERE status = 'ACTIVE'.
   *    Duplicate active keys in the incoming bundle are rejected regardless of category.
   * 6. Host Field Protection: Imported data cannot override internal IDs, scope, audit identity, or telemetry.
   * 7. Conflict Strategies:
   *    - 'FAIL': Aborts the entire import if any incoming active key conflicts with an existing active memory.
   *    - 'SKIP': Skips conflicting incoming entries and imports non-conflicting entries.
   *    - 'OVERWRITE': Archives the existing active memory and inserts the imported record as new ACTIVE memory.
   *      Preserves the old archived record. Tags and metadata are replaced by imported values (not merged).
   * 8. Transactional Atomicity: All inserts, archives, and the MEMORIES_IMPORTED audit event occur
   *    in a single atomic database transaction. Any failure rolls back the entire operation.
   * 9. Audit Privacy: Logs destination scope, counts, conflict strategy, and checksum.
   *    NEVER includes raw memory content or keys in the audit event.
   */
  public importMemories(
    caller: CallerContext,
    bundle: MemoryExportBundle,
    options: ImportMemoriesOptions = {}
  ): MemoryImportResult {
    // 1. Authorization
    this.validateCaller(caller, 'WRITE');

    if (caller.actor === 'AGENT') {
      this.audit(caller, 'MEMORY_ACCESS_DENIED', {
        reason: 'AGENT_DIRECT_ACTIVE_CREATION_DENIED',
        operation: 'importMemories'
      }, false);
      throw new SecurityViolationError(
        'Agents cannot directly import active memories; memories must be imported by a verified user.',
        'AGENT_PROPOSAL_REQUIRED'
      );
    }

    if (!options || typeof options !== 'object') {
      throw new ValidationError('ImportMemoriesOptions must be an object if provided.');
    }

    const conflictStrategy: ImportConflictStrategy = options.conflictStrategy ?? 'FAIL';
    if (!VALID_CONFLICT_STRATEGIES.has(conflictStrategy)) {
      throw new ValidationError(
        `Invalid conflict strategy '${String(conflictStrategy)}'. Must be 'FAIL', 'SKIP', or 'OVERWRITE'.`
      );
    }

    // 2. Pre-flight Bundle Validation
    if (!bundle || typeof bundle !== 'object') {
      throw new ValidationError('MemoryExportBundle must be provided as an object.');
    }
    if (bundle.version !== '1.0') {
      throw new ValidationError(
        `Unsupported bundle version '${String((bundle as unknown as Record<string, unknown>).version)}'. Only version '1.0' is supported.`
      );
    }
    if (typeof bundle.count !== 'number' || !Number.isInteger(bundle.count) || bundle.count < 0) {
      throw new ValidationError('Bundle count must be a non-negative integer.');
    }
    if (!Array.isArray(bundle.memories)) {
      throw new ValidationError('Bundle memories must be an array.');
    }
    if (bundle.memories.length !== bundle.count) {
      throw new ValidationError(
        `Bundle count mismatch: declared count is ${bundle.count}, but bundle contains ${bundle.memories.length} memories.`
      );
    }
    if (typeof bundle.checksum !== 'string' || bundle.checksum.trim() === '') {
      throw new ValidationError('Bundle checksum must be a non-empty string.');
    }

    // Verify integrity checksum before any database mutation
    if (!verifyBundleChecksum(bundle)) {
      throw new ValidationError(
        'Bundle checksum verification failed: bundle payload does not match checksum (corrupted or tampered).'
      );
    }

    // 3. Item Field Validation & Duplicate Key Prevention
    const seenActiveKeys = new Set<string>();

    for (let i = 0; i < bundle.memories.length; i++) {
      const item = bundle.memories[i];
      if (!item || typeof item !== 'object') {
        throw new ValidationError(`Bundle memory at index ${i} must be an object.`);
      }
      if (typeof item.key !== 'string' || item.key.trim() === '') {
        throw new ValidationError(`Memory key at index ${i} must be a non-empty string.`);
      }
      if (item.key.length > 256) {
        throw new ValidationError(
          `Memory key at index ${i} exceeds limit of 256 characters (${item.key.length} > 256).`
        );
      }
      if (typeof item.content !== 'string' || item.content.trim() === '') {
        throw new ValidationError(`Memory content for key '${item.key}' must be a non-empty string.`);
      }
      if (!item.category || !VALID_CATEGORIES.has(item.category)) {
        throw new ValidationError(
          `Invalid memory category '${String(item.category)}' for key '${item.key}'. Must be one of: ${Array.from(VALID_CATEGORIES).join(', ')}.`
        );
      }
      if (
        item.priority !== undefined &&
        (typeof item.priority !== 'number' ||
          !Number.isInteger(item.priority) ||
          item.priority < 0 ||
          item.priority > 100)
      ) {
        throw new ValidationError(
          `Memory priority for key '${item.key}' must be an integer between 0 and 100, received '${String(item.priority)}'.`
        );
      }
      if (
        item.tags !== undefined &&
        (!Array.isArray(item.tags) || item.tags.some((t: unknown) => typeof t !== 'string'))
      ) {
        throw new ValidationError(`Memory tags for key '${item.key}' must be an array of strings.`);
      }
      if (
        item.metadata !== undefined &&
        (typeof item.metadata !== 'object' || item.metadata === null || Array.isArray(item.metadata))
      ) {
        throw new ValidationError(`Memory metadata for key '${item.key}' must be an object.`);
      }
      if (item.status === 'PENDING_APPROVAL') {
        throw new ValidationError(
          `Cannot import memory with status 'PENDING_APPROVAL' for key '${item.key}'. Only ACTIVE or ARCHIVED memories may be imported.`
        );
      }
      if (item.status !== undefined && item.status !== 'ACTIVE' && item.status !== 'ARCHIVED') {
        throw new ValidationError(
          `Unsupported memory status '${String(item.status)}' for key '${item.key}'. Only ACTIVE or ARCHIVED memories may be imported.`
        );
      }

      // Check for duplicate incoming active keys according to real uniqueness rule (scope_type, scope_id, key)
      const itemStatus = item.status ?? 'ACTIVE';
      if (itemStatus === 'ACTIVE') {
        const trimmedKey = item.key.trim();
        if (seenActiveKeys.has(trimmedKey)) {
          throw new ValidationError(
            `Bundle contains duplicate active memory key '${trimmedKey}'. Duplicate active keys are not permitted within an import bundle regardless of category.`
          );
        }
        seenActiveKeys.add(trimmedKey);
      }
    }

    // Pre-flight check for OVERWRITE: cannot overwrite active memories that belong to a supersession chain
    if (conflictStrategy === 'OVERWRITE') {
      for (const item of bundle.memories) {
        const itemStatus = item.status ?? 'ACTIVE';
        if (itemStatus === 'ACTIVE') {
          const key = item.key.trim();
          const existing = this.memoryRepo.getMemoryByKey(key, caller.scope, 'ACTIVE');
          if (existing && (existing.supersedesId !== null || existing.supersededBy !== null || existing.version > 1)) {
            throw new MemoryConflictError(
              key,
              caller.scope.scopeType,
              caller.scope.scopeId,
              {
                operation: 'importMemories',
                conflictStrategy: 'OVERWRITE',
                memoryId: existing.id,
                reason: `Cannot overwrite active memory '${existing.id}' with key '${key}': record belongs to a supersession history chain (version ${existing.version}). Supersession history must be updated via explicit supersession operations.`
              }
            );
          }
        }
      }
    }

    // 4. Atomic Database Mutation
    let enqueuedActiveCount = 0;

    const importResult = this.memoryRepo.transaction(() => {
      let importedCount = 0;
      let skippedCount = 0;
      let overwrittenCount = 0;

      const modelId = this.embeddingProvider?.modelId ?? this.lifecycleManager?.provider.modelId ?? 'default';
      const modelRevision = (this.embeddingProvider as any)?.modelRevision ?? (this.lifecycleManager?.provider as any)?.modelRevision ?? 'main';

      for (const item of bundle.memories) {
        const status: 'ACTIVE' | 'ARCHIVED' = (item.status ?? 'ACTIVE') as 'ACTIVE' | 'ARCHIVED';
        const key = item.key.trim();

        if (status === 'ACTIVE') {
          // Check for existing active memory in destination scope (derived strictly from caller)
          const existing = this.memoryRepo.getMemoryByKey(key, caller.scope, 'ACTIVE');

          if (existing) {
            if (conflictStrategy === 'FAIL') {
              throw new MemoryConflictError(
                key,
                caller.scope.scopeType,
                caller.scope.scopeId,
                { operation: 'importMemories', conflictStrategy: 'FAIL' }
              );
            } else if (conflictStrategy === 'SKIP') {
              skippedCount++;
              continue;
            } else if (conflictStrategy === 'OVERWRITE') {
              if (existing.supersedesId !== null || existing.supersededBy !== null || existing.version > 1) {
                throw new MemoryConflictError(
                  key,
                  caller.scope.scopeType,
                  caller.scope.scopeId,
                  {
                    operation: 'importMemories',
                    conflictStrategy: 'OVERWRITE',
                    memoryId: existing.id,
                    reason: `Cannot overwrite active memory '${existing.id}' with key '${key}': record belongs to a supersession history chain (version ${existing.version}). Supersession history must be updated via explicit supersession operations.`
                  }
                );
              }

              // Archive existing active record (preserves the old record with status ARCHIVED)
              this.memoryRepo.archiveMemory(existing.id, caller.scope);

              // Phase 4C.6D: Clean up existing embeddings and cancel pending jobs for the archived existing record
              if (this.embeddingRepo) {
                this.embeddingRepo.deleteEmbeddingsByMemoryId(existing.id);
              }
              if (this.embeddingJobRepo) {
                this.embeddingJobRepo.cancelPendingJobsByMemoryId(existing.id);
              }

              // Insert imported record as new ACTIVE record
              // Tags and metadata replace existing values rather than merging
              const created = this.memoryRepo.createMemory({
                key,
                content: item.content.trim(),
                category: item.category,
                scopeType: caller.scope.scopeType,
                scopeId: caller.scope.scopeId,
                status: 'ACTIVE',
                priority: item.priority ?? 50,
                tags: item.tags ?? [],
                metadata: item.metadata ?? {}
              });

              // Durable Embedding Automation: Enqueue job for overwritten active memory
              if (this.embeddingJobRepo) {
                this.embeddingJobRepo.enqueueJob({
                  memoryId: created.id,
                  scopeType: created.scopeType,
                  scopeId: created.scopeId,
                  modelId,
                  modelRevision
                });
                enqueuedActiveCount++;
              }

              overwrittenCount++;
              continue;
            }
          }
        }

        // Non-conflicting insert (new ACTIVE or ARCHIVED)
        const created = this.memoryRepo.createMemory({
          key,
          content: item.content.trim(),
          category: item.category,
          scopeType: caller.scope.scopeType,
          scopeId: caller.scope.scopeId,
          status,
          priority: item.priority ?? 50,
          tags: item.tags ?? [],
          metadata: item.metadata ?? {}
        });

        // Durable Embedding Automation: Enqueue job only if status is ACTIVE
        if (status === 'ACTIVE' && this.embeddingJobRepo) {
          this.embeddingJobRepo.enqueueJob({
            memoryId: created.id,
            scopeType: created.scopeType,
            scopeId: created.scopeId,
            modelId,
            modelRevision
          });
          enqueuedActiveCount++;
        }

        importedCount++;
      }

      // Mandatory audit write for state mutation - metadata only, NO raw content or keys
      this.audit(caller, 'MEMORIES_IMPORTED', {
        targetScopeType: caller.scope.scopeType,
        targetScopeId: caller.scope.scopeId,
        totalInBundle: bundle.count,
        importedCount,
        skippedCount,
        overwrittenCount,
        conflictStrategy,
        checksum: bundle.checksum
      }, true);

      if (this._testPostAuditHook) {
        this._testPostAuditHook();
      }

      return {
        targetScope: {
          scopeType: caller.scope.scopeType,
          scopeId: caller.scope.scopeId
        },
        totalInBundle: bundle.count,
        importedCount,
        skippedCount,
        overwrittenCount
      };
    });

    if (enqueuedActiveCount > 0) {
      this.lifecycleManager?.trigger();
    }

    return importResult;
  }

  /**
   * Permanently purges archived memories within the caller's verified scope
   * with deliberate selection, atomic rollback, and privacy-safe audit logging.
   * 
   * Security & Architectural Guarantees:
   * 1. Authorization: Requires verified caller with explicit DELETE permission.
   * 2. Agent Restriction: Agents are strictly forbidden from performing permanent deletion.
   * 3. Scope Isolation: Scope is derived strictly from verified caller (caller.scope).
   *    Never accepts an arbitrary or untrusted destination scope.
   * 4. Deliberate Selection: Requires explicit memoryIds list OR cutoff timestamp (olderThan).
   *    Purging all archived memories silently by default is strictly rejected.
   * 5. Status Strictness: Only records whose status is exactly 'ARCHIVED' can be purged.
   *    ACTIVE and PENDING_APPROVAL records can NEVER be purged.
   * 6. All-or-Nothing Atomicity: All eligibility checks, deletions, and the MEMORIES_PURGED
   *    audit event occur in a single atomic database transaction. Any failure rolls back completely.
   * 7. Provenance Preservation: Foreign keys in memory_task_injections automatically set
   *    memory_id = NULL on deletion, preserving token and task execution audit history.
   * 8. Privacy Guarantee: Audit events and summary results contain only operational counters
   *    and non-sensitive cutoff metadata. Raw memory content and keys are never logged or returned.
   * 
   * Deletion Guarantee Limitations:
   * Logical deletion removes records from SQLite B-trees and zeroes cells if secure_delete pragma is active.
   * Does NOT claim or guarantee forensic byte erasure from unallocated disk space, WAL frames prior to checkpoint,
   * or external operating system backups.
   */
  public purgeArchivedMemories(
    caller: CallerContext,
    options: PurgeArchivedMemoriesOptions
  ): MemoryPurgeResult {
    // 1. Authorization
    this.validateCaller(caller);

    if (caller.actor === 'AGENT') {
      this.audit(caller, 'MEMORY_ACCESS_DENIED', {
        reason: 'AGENT_PURGE_DENIED',
        operation: 'purgeArchivedMemories'
      }, false);
      throw new SecurityViolationError(
        'Agents cannot directly purge memories; archived memories must be purged by an authorized user.',
        'AGENT_PURGE_RESTRICTED'
      );
    }

    this.validateCaller(caller, 'DELETE');

    // 2. Options validation
    if (!options || typeof options !== 'object' || Array.isArray(options)) {
      throw new ValidationError('PurgeArchivedMemoriesOptions must be an object.');
    }

    // Reject scope spoofing in options if provided
    this.assertCallerScopeMatch(caller, options.scopeType, options.scopeId, 'purgeArchivedMemories');

    const hasIds = options.memoryIds !== undefined;
    const hasCutoff = options.olderThan !== undefined;

    if (hasIds && hasCutoff) {
      throw new ValidationError(
        'Ambiguous purge options: cannot specify both memoryIds and olderThan. Choose either explicit ID list or cutoff timestamp.'
      );
    }

    if (!hasIds && !hasCutoff) {
      throw new ValidationError(
        'Deliberate purge required: must specify either memoryIds or olderThan. Purging all archived memories by default is not permitted.'
      );
    }

    if (options.dryRun !== undefined && typeof options.dryRun !== 'boolean') {
      throw new ValidationError('dryRun must be a boolean if provided.');
    }
    const isDryRun = Boolean(options.dryRun);

    if (options.maxBatchSize !== undefined) {
      if (
        typeof options.maxBatchSize !== 'number' ||
        !Number.isInteger(options.maxBatchSize) ||
        options.maxBatchSize < 1
      ) {
        throw new ValidationError(
          `maxBatchSize must be a positive integer, received '${String(options.maxBatchSize)}'.`
        );
      }
    }

    const purgeMode: MemoryPurgeMode = hasIds ? 'ID_LIST' : 'CUTOFF';

    if (purgeMode === 'ID_LIST') {
      const memoryIds = options.memoryIds!;
      if (!Array.isArray(memoryIds)) {
        throw new ValidationError('memoryIds must be an array of memory ID strings.');
      }

      // Validate each item
      for (let i = 0; i < memoryIds.length; i++) {
        const id = memoryIds[i];
        if (typeof id !== 'string' || id.trim() === '') {
          throw new ValidationError(`Memory ID at index ${i} must be a non-empty string.`);
        }
      }

      const uniqueIds = Array.from(new Set(memoryIds));

      if (uniqueIds.length === 0) {
        // Empty selection behaves safely
        return {
          targetScope: { scopeType: caller.scope.scopeType, scopeId: caller.scope.scopeId },
          purgeMode: 'ID_LIST',
          eligibleCount: 0,
          purgedCount: 0,
          isDryRun,
          ...(options.maxBatchSize !== undefined ? { batchSizeLimit: options.maxBatchSize } : {})
        };
      }

      if (options.maxBatchSize !== undefined && uniqueIds.length > options.maxBatchSize) {
        throw new ValidationError(
          `Requested memory ID count (${uniqueIds.length}) exceeds maximum batch size limit of ${options.maxBatchSize}.`
        );
      }

      // Dry run: read-only eligibility preview (no transaction, no mutation audit event)
      if (isDryRun) {
        for (const id of uniqueIds) {
          let memory: Memory | null;
          try {
            memory = this.memoryRepo.getMemoryById(id, caller.scope);
          } catch (err) {
            if (err instanceof MemoryScopeViolationError) {
              this.audit(caller, 'MEMORY_ACCESS_DENIED', {
                reason: 'CROSS_SCOPE_PURGE_ATTEMPT',
                memoryId: id,
                expectedScope: `${caller.scope.scopeType}:${caller.scope.scopeId}`
              }, false);
            }
            throw err;
          }

          if (!memory) {
            throw new MemoryNotFoundError(id);
          }
          if (memory.status !== 'ARCHIVED') {
            this.audit(caller, 'MEMORY_ACCESS_DENIED', {
              reason: 'NON_ARCHIVED_PURGE_DENIED',
              operation: 'purgeArchivedMemories',
              memoryId: id,
              status: memory.status
            }, false);
            throw new ValidationError(
              `Cannot purge memory '${id}': status is '${memory.status}'. Only records with status 'ARCHIVED' can be purged.`,
              { memoryId: id, status: memory.status }
            );
          }
          if (memory.supersedesId !== null || memory.supersededBy !== null) {
            this.audit(caller, 'MEMORY_ACCESS_DENIED', {
              reason: 'LINEAGE_PURGE_DENIED',
              operation: 'purgeArchivedMemories',
              memoryId: id
            }, false);
            throw new ValidationError(
              `Cannot purge memory '${id}': record is part of a supersession history chain. Archival records in a lineage chain cannot be purged.`,
              { memoryId: id }
            );
          }
        }
        return {
          targetScope: { scopeType: caller.scope.scopeType, scopeId: caller.scope.scopeId },
          purgeMode: 'ID_LIST',
          eligibleCount: uniqueIds.length,
          purgedCount: 0,
          isDryRun: true,
          ...(options.maxBatchSize !== undefined ? { batchSizeLimit: options.maxBatchSize } : {})
        };
      }

      // Non-dry-run: ID lookup, existence/scope validation, ARCHIVED status validation,
      // deletions, and MEMORIES_PURGED audit event all execute within the SAME atomic database transaction.
      let lastAttemptedId: string | undefined;
      let nonArchivedStatusCaught: { id: string; status: string } | null = null;
      let lineageMemoryCaught: { id: string } | null = null;

      try {
        return this.memoryRepo.transaction(() => {
          // Step 1: Preflight entire ID list before deleting anything.
          // If any ID is missing, outside scope, or not archived, abort the entire operation without partial deletion.
          const memoriesToDelete: Memory[] = [];
          for (const id of uniqueIds) {
            lastAttemptedId = id;
            const memory = this.memoryRepo.getMemoryById(id, caller.scope);
            if (!memory) {
              throw new MemoryNotFoundError(id);
            }

            if (memory.status !== 'ARCHIVED') {
              nonArchivedStatusCaught = { id, status: memory.status };
              throw new ValidationError(
                `Cannot purge memory '${id}': status is '${memory.status}'. Only records with status 'ARCHIVED' can be purged.`,
                { memoryId: id, status: memory.status }
              );
            }

            if (memory.supersedesId !== null || memory.supersededBy !== null) {
              lineageMemoryCaught = { id };
              throw new ValidationError(
                `Cannot purge memory '${id}': record is part of a supersession history chain. Archival records in a lineage chain cannot be purged.`,
                { memoryId: id }
              );
            }

            memoriesToDelete.push(memory);
          }

          // Step 2: Delete every preflighted record using deleteArchivedMemory
          let deletedCount = 0;
          for (const memory of memoriesToDelete) {
            const deleted = this.memoryRepo.deleteArchivedMemory(memory.id, caller.scope);
            if (!deleted) {
              throw new ValidationError(
                `Cannot purge memory '${memory.id}': record is no longer archived or does not exist in scope.`
              );
            }
            deletedCount++;
            if (this._testMidPurgeHook) {
              this._testMidPurgeHook(deletedCount);
            }
          }

          // Step 3: Mandatory audit event for state mutation
          const auditDetails: Record<string, unknown> = {
            scopeType: caller.scope.scopeType,
            scopeId: caller.scope.scopeId,
            purgeMode: 'ID_LIST',
            purgedCount: deletedCount
          };
          if (options.maxBatchSize !== undefined) {
            auditDetails.batchSizeLimit = options.maxBatchSize;
          }

          this.audit(caller, 'MEMORIES_PURGED', auditDetails, true);

          if (this._testPostPurgeAuditHook) {
            this._testPostPurgeAuditHook();
          }

          return {
            targetScope: { scopeType: caller.scope.scopeType, scopeId: caller.scope.scopeId },
            purgeMode: 'ID_LIST',
            eligibleCount: memoriesToDelete.length,
            purgedCount: deletedCount,
            isDryRun: false,
            ...(options.maxBatchSize !== undefined ? { batchSizeLimit: options.maxBatchSize } : {})
          };
        });
      } catch (err) {
        if (err instanceof MemoryScopeViolationError) {
          this.audit(caller, 'MEMORY_ACCESS_DENIED', {
            reason: 'CROSS_SCOPE_PURGE_ATTEMPT',
            memoryId: lastAttemptedId,
            expectedScope: `${caller.scope.scopeType}:${caller.scope.scopeId}`
          }, false);
        } else if (lineageMemoryCaught) {
          const lineage = lineageMemoryCaught as { id: string };
          this.audit(caller, 'MEMORY_ACCESS_DENIED', {
            reason: 'LINEAGE_PURGE_DENIED',
            operation: 'purgeArchivedMemories',
            memoryId: lineage.id
          }, false);
        } else {
          const nonArchived = nonArchivedStatusCaught as { id: string; status: string } | null;
          if (nonArchived) {
            this.audit(caller, 'MEMORY_ACCESS_DENIED', {
              reason: 'NON_ARCHIVED_PURGE_DENIED',
              operation: 'purgeArchivedMemories',
              memoryId: nonArchived.id,
              status: nonArchived.status
            }, false);
          }
        }
        throw err;
      }
    } else {
      // CUTOFF mode
      const cutoffIso = validateAndNormalizeUtcTimestamp(options.olderThan, 'olderThan');

      if (isDryRun) {
        const eligibleCount = this.memoryRepo.countArchivedMemoriesOlderThan(caller.scope, cutoffIso);
        return {
          targetScope: { scopeType: caller.scope.scopeType, scopeId: caller.scope.scopeId },
          purgeMode: 'CUTOFF',
          eligibleCount,
          purgedCount: 0,
          isDryRun: true,
          cutoffTimestamp: cutoffIso,
          ...(options.maxBatchSize !== undefined ? { batchSizeLimit: options.maxBatchSize } : {})
        };
      }

      // Atomic mutation transaction
      return this.memoryRepo.transaction(() => {
        const eligibleCount = this.memoryRepo.countArchivedMemoriesOlderThan(caller.scope, cutoffIso);
        const memoriesToDelete = this.memoryRepo.getArchivedMemoriesOlderThan(
          caller.scope,
          cutoffIso,
          options.maxBatchSize
        );

        let deletedCount = 0;
        for (const memory of memoriesToDelete) {
          if (memory.supersedesId !== null || memory.supersededBy !== null) {
            continue;
          }
          const deleted = this.memoryRepo.deleteArchivedMemory(memory.id, caller.scope);
          if (!deleted) {
            throw new ValidationError(
              `Cannot purge memory '${memory.id}': record is no longer archived or does not exist in scope.`
            );
          }
          deletedCount++;
          if (this._testMidPurgeHook) {
            this._testMidPurgeHook(deletedCount);
          }
        }

        const auditDetails: Record<string, unknown> = {
          scopeType: caller.scope.scopeType,
          scopeId: caller.scope.scopeId,
          purgeMode: 'CUTOFF',
          purgedCount: deletedCount,
          cutoffTimestamp: cutoffIso
        };
        if (options.maxBatchSize !== undefined) {
          auditDetails.batchSizeLimit = options.maxBatchSize;
        }

        this.audit(caller, 'MEMORIES_PURGED', auditDetails, true);

        if (this._testPostPurgeAuditHook) {
          this._testPostPurgeAuditHook();
        }

        return {
          targetScope: { scopeType: caller.scope.scopeType, scopeId: caller.scope.scopeId },
          purgeMode: 'CUTOFF',
          eligibleCount,
          purgedCount: deletedCount,
          isDryRun: false,
          cutoffTimestamp: cutoffIso,
          ...(options.maxBatchSize !== undefined ? { batchSizeLimit: options.maxBatchSize } : {})
        };
      });
    }
  }

  // --- Private Helpers ---

  /**
   * Validates caller context via host authorizer and enforces required permission if specified.
   */
  private validateCaller(
    caller: CallerContext,
    requiredPermission?: MemoryPermission
  ): Set<MemoryPermission> {
    // 1. Authoritative verification: caller must be issued and un-tampered by host boundary
    const verified = this.#authorizer.verify(caller);

    this.validateScope(verified.scope.scopeType, verified.scope.scopeId);

    const permissions = verified.permissions instanceof Set
      ? (verified.permissions as Set<MemoryPermission>)
      : new Set(verified.permissions);

    if (requiredPermission && !permissions.has(requiredPermission)) {
      this.audit(verified, 'MEMORY_ACCESS_DENIED', {
        reason: 'INSUFFICIENT_PERMISSIONS',
        requiredPermission,
        actor: verified.actor,
        scopeType: verified.scope.scopeType,
        scopeId: verified.scope.scopeId
      }, false);
      throw new SecurityViolationError(
        `Caller '${verified.actor}' lacks required '${requiredPermission}' permission.`,
        'INSUFFICIENT_PERMISSIONS',
        { actor: verified.actor, requiredPermission, scope: verified.scope }
      );
    }

    if (this.taskRepo && verified.taskId) {
      const task = this.taskRepo.getTaskById(verified.taskId);
      if (!task) {
        throw new TaskNotFoundError(verified.taskId);
      }
      const taskScope = this.extractAuthoritativeTaskScope(task);
      if (
        taskScope.scopeType !== verified.scope.scopeType ||
        taskScope.scopeId !== verified.scope.scopeId
      ) {
        throw new SecurityViolationError(
          `Caller scope '${verified.scope.scopeType}:${verified.scope.scopeId}' does not match task scope '${taskScope.scopeType}:${taskScope.scopeId}'.`,
          'TASK_CALLER_SCOPE_MISMATCH'
        );
      }
    }

    return permissions;
  }

  /**
   * Validates scope identifier fields.
   */
  private validateScope(scopeType: MemoryScopeType, scopeId: string): void {
    if (!VALID_SCOPES.has(scopeType)) {
      throw new ValidationError(
        `Invalid scopeType '${String(scopeType)}'. Must be 'GLOBAL' or 'WORKSPACE'.`
      );
    }
    if (typeof scopeId !== 'string' || scopeId.trim() === '') {
      throw new ValidationError('scopeId must be a non-empty string.');
    }
    if (scopeType === 'GLOBAL' && scopeId !== 'default') {
      throw new ValidationError(`Global scope must have scopeId 'default', received '${scopeId}'.`);
    }
  }

  /**
   * Detects and blocks scope forgery attempts.
   */
  private assertCallerScopeMatch(
    caller: CallerContext,
    targetScopeType?: MemoryScopeType,
    targetScopeId?: string,
    operation: string = 'operation'
  ): void {
    if (!targetScopeType && !targetScopeId) {
      return;
    }

    if (
      (targetScopeType && targetScopeType !== caller.scope.scopeType) ||
      (targetScopeId && targetScopeId !== caller.scope.scopeId)
    ) {
      const attemptedScope = `${targetScopeType ?? 'UNKNOWN'}:${targetScopeId ?? 'UNKNOWN'}`;
      const callerScope = `${caller.scope.scopeType}:${caller.scope.scopeId}`;
      this.audit(caller, 'MEMORY_ACCESS_DENIED', {
        reason: 'SCOPE_FORGERY_ATTEMPT',
        operation,
        attemptedScope,
        callerScope
      }, false);
      throw new MemoryScopeViolationError(
        callerScope,
        attemptedScope,
        undefined,
        { operation, actor: caller.actor }
      );
    }
  }

  /**
   * Extracts authoritative task scope strictly from verified host task attestation.
   * Fails closed if metadata is missing, malformed, or untrusted.
   * NEVER falls back to caller scope.
   */
  private extractAuthoritativeTaskScope(task: Task): ScopeIdentifier {
    return this.#authorizer.verifyTaskScope(task);
  }

  /**
   * Emits privacy-conscious, tamper-evident audit events via AuditRepository.
   * 
   * Policy:
   * - Mandatory (fail-closed) for state mutations and decisions (create, update, archive, delete, approve).
   * - Best-effort for read telemetry.
   */
  private audit(
    caller: CallerContext,
    eventType: AuditEventType,
    details: Record<string, unknown>,
    mandatory: boolean = false
  ): void {
    if (!this.auditRepo) {
      if (mandatory) {
        throw new ValidationError(
          `Audit repository is required to record mandatory audit event '${eventType}'.`
        );
      }
      return;
    }

    const taskId = caller.taskId ?? this.getOrCreateSystemTaskId();
    if (!taskId) {
      if (mandatory) {
        throw new ValidationError(
          `Task ID or system task is required to record mandatory audit event '${eventType}'.`
        );
      }
      return;
    }

    try {
      this.auditRepo.appendEvent({
        taskId,
        eventType,
        actor: caller.actor,
        details: sanitizeMemoryAuditDetails(eventType, details)
      });
    } catch (err) {
      if (mandatory) {
        throw err;
      }
    }
  }

  /**
   * Obtains or creates a system task for operations executed outside a specific task context.
   */
  private getOrCreateSystemTaskId(): string | null {
    if (this.systemTaskId) {
      return this.systemTaskId;
    }
    if (!this.taskRepo) {
      return null;
    }
    try {
      const existing = this.taskRepo.getTaskById('__system_memory__');
      if (existing) {
        this.systemTaskId = existing.id;
        return this.systemTaskId;
      }
      if (this.#hostAuthority) {
        const created = this.#hostAuthority.createTask(this.taskRepo, {
          id: '__system_memory__',
          goal: 'System long-term memory operations',
          scope: { scopeType: 'GLOBAL', scopeId: 'default' }
        });
        this.systemTaskId = created.id;
        return this.systemTaskId;
      }
      return null;
    } catch {
      return null;
    }
  }
}

/**
 * Creates a dual-purpose search result that can be accessed synchronously as an Array
 * or awaited as a Promise resolving to the hybrid results.
 */
function createDualSearchResult<T extends object>(
  syncArray: T[],
  asyncPromise: Promise<T[]>
): T[] & PromiseLike<T[]> {
  const result = [...syncArray] as T[] & PromiseLike<T[]>;
  result.then = function <TResult1 = T[], TResult2 = never>(
    onfulfilled?: ((value: T[]) => TResult1 | PromiseLike<TResult1>) | null,
    onrejected?: ((reason: any) => TResult2 | PromiseLike<TResult2>) | null
  ): Promise<TResult1 | TResult2> {
    return asyncPromise.then(onfulfilled, onrejected);
  };
  return result;
}

/**
 * Creates a dual-purpose context result that can be accessed synchronously as BuiltMemoryContext
 * or awaited as a Promise resolving to the hybrid built context.
 */
function createDualContext<T extends object>(
  syncObj: T,
  asyncPromise: Promise<T>
): T & PromiseLike<T> {
  const result = { ...syncObj } as T & PromiseLike<T>;
  result.then = function <TResult1 = T, TResult2 = never>(
    onfulfilled?: ((value: T) => TResult1 | PromiseLike<TResult1>) | null,
    onrejected?: ((reason: any) => TResult2 | PromiseLike<TResult2>) | null
  ): Promise<TResult1 | TResult2> {
    return asyncPromise.then(onfulfilled, onrejected);
  };
  return result;
}

