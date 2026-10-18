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
  ProposalDecisionInput,
  BuildTaskMemoryContextOptions,
  BuiltMemoryContext,
  CreateMemoryInput,
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
  MemoryUsageHistory
} from '../domain/types.ts';
import {
  ValidationError,
  SecurityViolationError,
  MemoryScopeViolationError,
  MemoryNotFoundError,
  TaskNotFoundError
} from '../domain/errors.ts';
import { MemoryRepository } from '../storage/memory-repository.ts';
import type { AuditRepository } from '../storage/audit-repository.ts';
import type { TaskRepository } from '../storage/task-repository.ts';
import type { DatabaseManager } from '../storage/db.ts';
import { RelevanceMatcher } from './relevance-matcher.ts';
import { MemoryContextBuilder } from './context-builder.ts';
import { MemoryAuthorizer } from '../security/memory-authorizer.ts';
import type { HostMemoryAuthority } from '../security/host-authority.ts';
import { computeCanonicalSha256 } from './canonical-json.ts';

const VALID_SCOPES: ReadonlySet<MemoryScopeType> = new Set([
  'GLOBAL',
  'WORKSPACE'
]);

export interface MemoryServiceOptions {
  readonly memoryRepo: MemoryRepository;
  readonly auditRepo?: AuditRepository;
  readonly taskRepo?: TaskRepository;
  readonly authorizer?: MemoryAuthorizer;
  readonly hostAuthority?: HostMemoryAuthority;
  readonly relevanceMatcher?: RelevanceMatcher;
  readonly contextBuilder?: MemoryContextBuilder;
  /** Internal hook for testing transactional failure after audit append */
  readonly _testPostAuditHook?: () => void;
}

export class MemoryService {
  private readonly memoryRepo: MemoryRepository;
  private readonly auditRepo?: AuditRepository;
  private readonly taskRepo?: TaskRepository;
  readonly #authorizer: MemoryAuthorizer;
  readonly #hostAuthority?: HostMemoryAuthority;
  private readonly relevanceMatcher: RelevanceMatcher;
  private readonly contextBuilder: MemoryContextBuilder;
  private readonly _testPostAuditHook?: () => void;
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

    // Authorization boundary consistency: if both authorizer and hostAuthority are supplied,
    // authorizer must be the exact authorizer instance owned by hostAuthority.
    if (options.authorizer && options.hostAuthority && options.authorizer !== options.hostAuthority.authorizer) {
      throw new ValidationError(
        'MemoryService authorizer must be the exact authorizer owned by its configured HostMemoryAuthority.'
      );
    }

    this.memoryRepo = options.memoryRepo;
    this.auditRepo = options.auditRepo;
    this.taskRepo = options.taskRepo;
    this.#authorizer = options.authorizer ?? options.hostAuthority?.authorizer ?? new MemoryAuthorizer({ taskRepo: options.taskRepo });
    this.#hostAuthority = options.hostAuthority;
    this._testPostAuditHook = options._testPostAuditHook;
    this.relevanceMatcher = options.relevanceMatcher ?? new RelevanceMatcher();
    this.contextBuilder = options.contextBuilder ?? new MemoryContextBuilder({ matcher: this.relevanceMatcher });
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
          key: memory.key,
          category: memory.category,
          scopeType: memory.scopeType,
          scopeId: memory.scopeId
        }, false);
      }
      return memory;
    } catch (err) {
      if (err instanceof MemoryScopeViolationError) {
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
   * Retrieves an active memory by its exact key within the caller's scope.
   */
  public getMemoryByKey(
    caller: CallerContext,
    key: string,
    status: MemoryStatus = 'ACTIVE'
  ): Memory | null {
    this.validateCaller(caller, 'READ');
    const memory = this.memoryRepo.getMemoryByKey(key, caller.scope, status);
    if (memory) {
      this.audit(caller, 'MEMORY_RETRIEVED', {
        memoryId: memory.id,
        key: memory.key,
        category: memory.category,
        scopeType: memory.scopeType,
        scopeId: memory.scopeId
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

    let status: MemoryStatus;
    if (caller.actor === 'AGENT') {
      // Agents must never directly persist ACTIVE memories
      if (input.status === 'ACTIVE') {
        this.audit(caller, 'MEMORY_ACCESS_DENIED', {
          reason: 'AGENT_DIRECT_ACTIVE_CREATION_DENIED',
          operation: 'createMemory',
          attemptedKey: input.key
        }, false);
        throw new SecurityViolationError(
          'Agents cannot directly create active memories; proposals must be created with status PENDING_APPROVAL.',
          'AGENT_PROPOSAL_REQUIRED',
          { key: input.key }
        );
      }
      status = 'PENDING_APPROVAL';
    } else {
      status = input.status ?? 'ACTIVE';
    }

    return this.memoryRepo.transaction(() => {
      const memory = this.memoryRepo.createMemory({
        ...input,
        scopeType: caller.scope.scopeType,
        scopeId: caller.scope.scopeId,
        status
      });

      // Mandatory audit write for state creation
      if (status === 'ACTIVE') {
        this.audit(caller, 'MEMORY_CREATED', {
          memoryId: memory.id,
          key: memory.key,
          category: memory.category,
          scopeType: memory.scopeType,
          scopeId: memory.scopeId,
          status: 'ACTIVE'
        }, true);
      } else {
        this.audit(caller, 'MEMORY_PROPOSAL_SUBMITTED', {
          memoryId: memory.id,
          key: memory.key,
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
  }

  /**
   * Updates an existing memory within the caller's scope.
   * 
   * Strict Security Gates:
   * 1. Status mutations are strictly forbidden via updateMemory.
   *    Proposals can ONLY be activated through decideProposal with APPROVE permission.
   * 2. Agents cannot directly modify active memories or change status.
   * 3. State mutation audit logging is mandatory (fail-closed).
   */
  public updateMemory(caller: CallerContext, id: string, input: UpdateMemoryInput): Memory {
    this.validateCaller(caller, 'WRITE');
    if (!id || typeof id !== 'string' || id.trim() === '') {
      throw new ValidationError('Memory ID must be a non-empty string.');
    }
    if (!input || typeof input !== 'object') {
      throw new ValidationError('UpdateMemoryInput must be provided.');
    }

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
      }
      throw err;
    }

    if (!existing) {
      throw new MemoryNotFoundError(id);
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
        throw new SecurityViolationError(
          'Cannot transition status of a pending proposal via updateMemory. Only the trusted decideProposal path with APPROVE permission may decide proposals.',
          'UNAUTHORIZED_APPROVAL',
          { memoryId: id, attemptedStatus: input.status }
        );
      }

      this.audit(caller, 'MEMORY_ACCESS_DENIED', {
        reason: 'UNAUTHORIZED_STATUS_TRANSITION',
        operation: 'updateMemory',
        memoryId: id,
        currentStatus: existing.status,
        attemptedStatus: input.status
      }, false);
      throw new SecurityViolationError(
        `Direct status transitions from '${existing.status}' to '${input.status}' cannot be performed via updateMemory. Use decideProposal for proposals, or archiveMemory to archive.`,
        'UNAUTHORIZED_STATUS_TRANSITION',
        { memoryId: id, currentStatus: existing.status, attemptedStatus: input.status }
      );
    }

    if (caller.actor === 'AGENT') {
      // Agents cannot directly modify already ACTIVE memories
      if (existing.status === 'ACTIVE') {
        this.audit(caller, 'MEMORY_ACCESS_DENIED', {
          reason: 'AGENT_ACTIVE_MUTATION_DENIED',
          operation: 'updateMemory',
          memoryId: id
        }, false);
        throw new SecurityViolationError(
          'Agents cannot directly modify active memories.',
          'AGENT_MUTATION_RESTRICTED',
          { memoryId: id }
        );
      }
    }

    return this.memoryRepo.transaction(() => {
      const updated = this.memoryRepo.updateMemory(id, caller.scope, input);

      // Mandatory audit write for state update
      this.audit(caller, 'MEMORY_UPDATED', {
        memoryId: updated.id,
        key: updated.key,
        scopeType: updated.scopeType,
        scopeId: updated.scopeId,
        updatedFields: Object.keys(input)
      }, true);

      return updated;
    });
  }

  /**
   * Archives a memory within the caller's scope, requiring DELETE permission.
   * State mutation audit logging is mandatory (fail-closed).
   */
  public archiveMemory(caller: CallerContext, id: string): Memory {
    this.validateCaller(caller, 'DELETE');
    if (!id || typeof id !== 'string' || id.trim() === '') {
      throw new ValidationError('Memory ID must be a non-empty string.');
    }

    return this.memoryRepo.transaction(() => {
      try {
        const archived = this.memoryRepo.archiveMemory(id, caller.scope);
        this.audit(caller, 'MEMORY_ARCHIVED', {
          memoryId: archived.id,
          key: archived.key,
          scopeType: archived.scopeType,
          scopeId: archived.scopeId
        }, true);
        return archived;
      } catch (err) {
        if (err instanceof MemoryScopeViolationError) {
          this.audit(caller, 'MEMORY_ACCESS_DENIED', {
            reason: 'CROSS_SCOPE_ARCHIVE_ATTEMPT',
            memoryId: id,
            expectedScope: `${caller.scope.scopeType}:${caller.scope.scopeId}`
          }, false);
        }
        throw err;
      }
    });
  }

  /**
   * Hard-deletes a memory record permanently, physically erasing content and nulling
   * foreign keys in injection provenance records. Requires DELETE permission.
   * State mutation audit logging is mandatory (fail-closed).
   */
  public deleteMemory(caller: CallerContext, id: string): boolean {
    this.validateCaller(caller, 'DELETE');
    if (!id || typeof id !== 'string' || id.trim() === '') {
      throw new ValidationError('Memory ID must be a non-empty string.');
    }

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
      }
      throw err;
    }

    if (!existing) {
      throw new MemoryNotFoundError(id);
    }

    return this.memoryRepo.transaction(() => {
      const deleted = this.memoryRepo.deleteMemory(id, caller.scope);

      // Mandatory audit write for hard deletion
      this.audit(caller, 'MEMORY_DELETED', {
        memoryId: existing.id,
        key: existing.key,
        scopeType: existing.scopeType,
        scopeId: existing.scopeId
      }, true);

      return deleted;
    });
  }

  /**
   * Submits a human decision (APPROVED or REJECTED) on a pending memory proposal.
   * 
   * Strict Security Gates:
   * 1. Requires verified human USER actor.
   * 2. Requires explicit APPROVE permission.
   * 3. Target memory must be in status 'PENDING_APPROVAL'.
   * 4. State mutation audit logging is mandatory (fail-closed).
   */
  public decideProposal(caller: CallerContext, input: ProposalDecisionInput): Memory {
    if (!input || typeof input !== 'object') {
      throw new ValidationError('ProposalDecisionInput must be provided.');
    }
    if (!input.memoryId || typeof input.memoryId !== 'string' || input.memoryId.trim() === '') {
      throw new ValidationError('Memory ID must be a non-empty string.');
    }
    if (input.decision !== 'APPROVED' && input.decision !== 'REJECTED') {
      throw new ValidationError(
        `Invalid proposal decision '${String(input.decision)}'. Must be 'APPROVED' or 'REJECTED'.`
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

    // 3. Lookup existing proposal within caller scope
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
      }
      throw err;
    }

    if (!existing) {
      throw new MemoryNotFoundError(input.memoryId);
    }

    if (existing.status !== 'PENDING_APPROVAL') {
      throw new ValidationError(
        `Cannot decide memory proposal: memory '${input.memoryId}' is not pending approval (current status: '${existing.status}').`
      );
    }

    return this.memoryRepo.transaction(() => {
      const newStatus: MemoryStatus = input.decision === 'APPROVED' ? 'ACTIVE' : 'ARCHIVED';
      const updated = this.memoryRepo.updateMemory(input.memoryId, caller.scope, { status: newStatus });

      // Mandatory audit write for proposal decision
      this.audit(caller, 'MEMORY_PROPOSAL_DECIDED', {
        memoryId: updated.id,
        key: updated.key,
        category: updated.category,
        decision: input.decision,
        decidedBy: caller.actor,
        scopeType: updated.scopeType,
        scopeId: updated.scopeId,
        previousStatus: 'PENDING_APPROVAL',
        newStatus
      }, true);

      return updated;
    });
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
      let memory: Memory | null;
      try {
        memory = this.memoryRepo.getMemoryById(input.memoryId, caller.scope);
      } catch (err) {
        if (err instanceof MemoryScopeViolationError) {
          this.audit(caller, 'MEMORY_ACCESS_DENIED', {
            reason: 'TASK_MEMORY_SCOPE_MISMATCH',
            taskId: input.taskId,
            memoryId: input.memoryId,
            callerScope: `${caller.scope.scopeType}:${caller.scope.scopeId}`
          }, false);
        }
        throw err;
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

      if (
        memory.scopeType !== taskScope.scopeType ||
        memory.scopeId !== taskScope.scopeId
      ) {
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
   * Builds a safe, bounded memory context block for task execution.
   * Only ACTIVE memories within the caller's scope are considered.
   * Batch injection recording uses a database transaction to prevent partial writes.
   */
  public buildTaskMemoryContext(
    caller: CallerContext,
    options: BuildTaskMemoryContextOptions
  ): BuiltMemoryContext {
    this.validateCaller(caller, 'READ');
    if (!options || typeof options !== 'object') {
      throw new ValidationError('BuildTaskMemoryContextOptions must be provided.');
    }
    if (typeof options.query !== 'string') {
      throw new ValidationError('Query must be a string.');
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

    // Query active memories within caller scope
    const candidates = this.memoryRepo.listMemories({
      scopeType: caller.scope.scopeType,
      scopeId: caller.scope.scopeId,
      status: 'ACTIVE',
      category: options.category
    });

    // Configure context builder
    let builder = this.contextBuilder;
    if (options.maxBudgetChars !== undefined || options.relevanceThreshold !== undefined) {
      builder = new MemoryContextBuilder({
        maxBudgetChars: options.maxBudgetChars,
        relevanceThreshold: options.relevanceThreshold,
        matcher: this.relevanceMatcher
      });
    }

    const context = builder.buildContext(options.query, candidates);

    // Record provenance atomically if requested and taskId is present
    if (options.recordInjections && options.taskId) {
      const taskId = options.taskId;
      this.memoryRepo.transaction(() => {
        for (const inc of context.included) {
          const memory = this.memoryRepo.getMemoryById(inc.id, caller.scope);
          if (!memory || memory.status !== 'ACTIVE') {
            throw new ValidationError(
              `Cannot record injection provenance: memory '${inc.id}' is not active.`
            );
          }
          this.memoryRepo.recordInjection({
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
        scopeType: caller.scope.scopeType,
        scopeId: caller.scope.scopeId,
        taskId: options.taskId
      }, false);
    }

    return context;
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
        details
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
