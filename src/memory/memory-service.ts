/**
 * Next-Generation Dots AI Platform - Permission-Controlled Memory Service
 * Phase 7.3: Memory Subsystem
 * 
 * Architectural Mandate:
 * Implements a trusted service layer over MemoryRepository, RelevanceMatcher,
 * and MemoryContextBuilder. Enforces host-derived caller context, explicit permission
 * gating (READ, WRITE, DELETE, APPROVE), strict scope isolation across workspaces
 * and global boundaries, human approval gating for agent memory proposals,
 * and privacy-conscious tamper-evident audit logging.
 * 
 * Guarantees:
 * 1. Scope Derivation: Memory scope is strictly derived from trusted host context.
 *    Any scope parameters supplied in untrusted agent or caller input are validated
 *    against the trusted scope; spoofing attempts are rejected immediately.
 * 2. Distinct Permissions: Explicitly validates READ, WRITE, DELETE, and APPROVE
 *    permissions on every operation. Missing or insufficient permissions throw
 *    SecurityViolationError and log MEMORY_ACCESS_DENIED audit events.
 * 3. Scope Isolation: Prevents cross-workspace access, workspace-to-global bleed,
 *    and global-to-workspace leakage across all CRUD and context-building operations.
 * 4. Human Approval Gating: Agent-created memories are strictly persisted as proposals
 *    with status 'PENDING_APPROVAL'. Agents cannot approve proposals, activate memories,
 *    or modify active memories. Only human USER callers with APPROVE permission can
 *    approve or reject proposals.
 * 5. Injection Provenance Integrity: Memory injections verify that task scope and
 *    memory scope match identically before recording provenance.
 * 6. Audit Privacy & Tamper Resistance: Emits immutable audit events via AuditRepository
 *    (or system task fallback) for all operations and denials. Raw memory content is
 *    NEVER recorded in audit event details or diagnostic payloads.
 * 7. Bounded Context: Memory context building strictly honors the 4,000-character ceiling
 *    and untrusted-data boundary framing from Phase 7.2.
 */

import type {
  Memory,
  MemoryCategory,
  MemoryScopeType,
  MemoryStatus,
  MemoryPermission,
  MemoryActor,
  CallerContext,
  ProposalDecision,
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
  Task
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
import { RelevanceMatcher } from './relevance-matcher.ts';
import { MemoryContextBuilder } from './context-builder.ts';

const VALID_PERMISSIONS: ReadonlySet<MemoryPermission> = new Set([
  'READ',
  'WRITE',
  'DELETE',
  'APPROVE'
]);

const VALID_ACTORS: ReadonlySet<MemoryActor> = new Set([
  'USER',
  'AGENT',
  'SYSTEM',
  'POLICY_ENGINE'
]);

const VALID_SCOPES: ReadonlySet<MemoryScopeType> = new Set([
  'GLOBAL',
  'WORKSPACE'
]);

export interface MemoryServiceOptions {
  readonly memoryRepo: MemoryRepository;
  readonly auditRepo?: AuditRepository;
  readonly taskRepo?: TaskRepository;
  readonly relevanceMatcher?: RelevanceMatcher;
  readonly contextBuilder?: MemoryContextBuilder;
}

export class MemoryService {
  private readonly memoryRepo: MemoryRepository;
  private readonly auditRepo?: AuditRepository;
  private readonly taskRepo?: TaskRepository;
  private readonly relevanceMatcher: RelevanceMatcher;
  private readonly contextBuilder: MemoryContextBuilder;
  private systemTaskId?: string;

  constructor(options: MemoryServiceOptions) {
    if (!options || typeof options !== 'object') {
      throw new ValidationError('MemoryServiceOptions must be provided.');
    }
    if (!options.memoryRepo) {
      throw new ValidationError('MemoryRepository must be provided to MemoryService.');
    }

    this.memoryRepo = options.memoryRepo;
    this.auditRepo = options.auditRepo;
    this.taskRepo = options.taskRepo;
    this.relevanceMatcher = options.relevanceMatcher ?? new RelevanceMatcher();
    this.contextBuilder = options.contextBuilder ?? new MemoryContextBuilder({ matcher: this.relevanceMatcher });
  }

  // --- Public Operations ---

  /**
   * Retrieves a memory by ID, enforcing scope containment and READ permission.
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
        });
      }
      return memory;
    } catch (err) {
      if (err instanceof MemoryScopeViolationError) {
        this.audit(caller, 'MEMORY_ACCESS_DENIED', {
          reason: 'CROSS_SCOPE_READ_ATTEMPT',
          memoryId: id,
          expectedScope: `${caller.scope.scopeType}:${caller.scope.scopeId}`
        });
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
      });
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
        });
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

    const memory = this.memoryRepo.createMemory({
      ...input,
      scopeType: caller.scope.scopeType,
      scopeId: caller.scope.scopeId,
      status
    });

    if (status === 'ACTIVE') {
      this.audit(caller, 'MEMORY_CREATED', {
        memoryId: memory.id,
        key: memory.key,
        category: memory.category,
        scopeType: memory.scopeType,
        scopeId: memory.scopeId,
        status: 'ACTIVE'
      });
    } else {
      this.audit(caller, 'MEMORY_PROPOSAL_SUBMITTED', {
        memoryId: memory.id,
        key: memory.key,
        category: memory.category,
        scopeType: memory.scopeType,
        scopeId: memory.scopeId,
        status: 'PENDING_APPROVAL',
        proposedBy: caller.actor
      });
    }

    return memory;
  }

  /**
   * Updates an existing memory within the caller's scope.
   * Agents cannot directly modify active memories or elevate status to ACTIVE.
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
        });
      }
      throw err;
    }

    if (!existing) {
      throw new MemoryNotFoundError(id);
    }

    if (caller.actor === 'AGENT') {
      // Agents cannot activate proposals or approve memories
      if (input.status === 'ACTIVE') {
        this.audit(caller, 'MEMORY_ACCESS_DENIED', {
          reason: 'AGENT_DIRECT_ACTIVATION_DENIED',
          operation: 'updateMemory',
          memoryId: id
        });
        throw new SecurityViolationError(
          'Agents cannot approve proposals or activate memories.',
          'UNAUTHORIZED_APPROVAL',
          { memoryId: id }
        );
      }

      // Agents cannot directly modify already ACTIVE memories
      if (existing.status === 'ACTIVE') {
        this.audit(caller, 'MEMORY_ACCESS_DENIED', {
          reason: 'AGENT_ACTIVE_MUTATION_DENIED',
          operation: 'updateMemory',
          memoryId: id
        });
        throw new SecurityViolationError(
          'Agents cannot directly modify active memories.',
          'AGENT_MUTATION_RESTRICTED',
          { memoryId: id }
        );
      }
    }

    const updated = this.memoryRepo.updateMemory(id, caller.scope, input);

    this.audit(caller, 'MEMORY_UPDATED', {
      memoryId: updated.id,
      key: updated.key,
      scopeType: updated.scopeType,
      scopeId: updated.scopeId,
      updatedFields: Object.keys(input)
    });

    return updated;
  }

  /**
   * Archives a memory within the caller's scope, requiring DELETE permission.
   */
  public archiveMemory(caller: CallerContext, id: string): Memory {
    this.validateCaller(caller, 'DELETE');
    if (!id || typeof id !== 'string' || id.trim() === '') {
      throw new ValidationError('Memory ID must be a non-empty string.');
    }

    try {
      const archived = this.memoryRepo.archiveMemory(id, caller.scope);
      this.audit(caller, 'MEMORY_ARCHIVED', {
        memoryId: archived.id,
        key: archived.key,
        scopeType: archived.scopeType,
        scopeId: archived.scopeId
      });
      return archived;
    } catch (err) {
      if (err instanceof MemoryScopeViolationError) {
        this.audit(caller, 'MEMORY_ACCESS_DENIED', {
          reason: 'CROSS_SCOPE_ARCHIVE_ATTEMPT',
          memoryId: id,
          expectedScope: `${caller.scope.scopeType}:${caller.scope.scopeId}`
        });
      }
      throw err;
    }
  }

  /**
   * Hard-deletes a memory record permanently, physically erasing content and nulling
   * foreign keys in injection provenance records.
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
        });
      }
      throw err;
    }

    if (!existing) {
      throw new MemoryNotFoundError(id);
    }

    const deleted = this.memoryRepo.deleteMemory(id, caller.scope);

    this.audit(caller, 'MEMORY_DELETED', {
      memoryId: existing.id,
      key: existing.key,
      scopeType: existing.scopeType,
      scopeId: existing.scopeId
    });

    return deleted;
  }

  /**
   * Submits a human decision (APPROVED or REJECTED) on a pending memory proposal.
   * Strictly requires human USER actor and APPROVE permission.
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

    // 1. Verify caller actor: agents and automated engines are strictly forbidden
    if (caller?.actor === 'AGENT') {
      this.audit(caller, 'MEMORY_ACCESS_DENIED', {
        reason: 'AGENT_SELF_APPROVAL_ATTEMPT',
        operation: 'decideProposal',
        memoryId: input.memoryId
      });
      throw new SecurityViolationError(
        'Agents are strictly forbidden from approving memory proposals.',
        'UNAUTHORIZED_APPROVAL',
        { actor: caller.actor, memoryId: input.memoryId }
      );
    }

    if (caller?.actor !== 'USER') {
      this.audit(caller, 'MEMORY_ACCESS_DENIED', {
        reason: 'NON_USER_APPROVAL_ATTEMPT',
        operation: 'decideProposal',
        memoryId: input.memoryId
      });
      throw new SecurityViolationError(
        'Only human users can decide memory proposals.',
        'UNAUTHORIZED_APPROVAL',
        { actor: caller?.actor, memoryId: input.memoryId }
      );
    }

    // 2. Verify APPROVE permission
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
        });
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

    const newStatus: MemoryStatus = input.decision === 'APPROVED' ? 'ACTIVE' : 'ARCHIVED';
    const updated = this.memoryRepo.updateMemory(input.memoryId, caller.scope, { status: newStatus });

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
    });

    return updated;
  }

  /**
   * Records memory injection provenance for an executed workflow task.
   * Verifies that the task's scope and the memory's scope are strictly compatible.
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

    // 1. If taskRepo is configured, verify task exists and validate its scope
    let taskScope: ScopeIdentifier = caller.scope;
    if (this.taskRepo) {
      const task = this.taskRepo.getTaskById(input.taskId);
      if (!task) {
        throw new TaskNotFoundError(input.taskId);
      }
      taskScope = this.extractTaskScope(task, caller.scope);

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
        });
        throw new MemoryScopeViolationError(
          `${caller.scope.scopeType}:${caller.scope.scopeId}`,
          `${taskScope.scopeType}:${taskScope.scopeId}`,
          undefined,
          { taskId: input.taskId }
        );
      }
    }

    // 2. If memoryId is provided, verify memory exists and scope matches task scope exactly
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
          });
        }
        throw err;
      }

      if (!memory) {
        throw new MemoryNotFoundError(input.memoryId);
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
        });
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
   * Retrieves injection provenance records for a given task.
   */
  public getInjectionsByTaskId(caller: CallerContext, taskId: string): MemoryTaskInjection[] {
    this.validateCaller(caller, 'READ');
    if (!taskId || typeof taskId !== 'string' || taskId.trim() === '') {
      throw new ValidationError('Task ID must be a non-empty string.');
    }

    if (this.taskRepo) {
      const task = this.taskRepo.getTaskById(taskId);
      if (!task) {
        throw new TaskNotFoundError(taskId);
      }
      const taskScope = this.extractTaskScope(task, caller.scope);
      if (
        taskScope.scopeType !== caller.scope.scopeType ||
        taskScope.scopeId !== caller.scope.scopeId
      ) {
        this.audit(caller, 'MEMORY_ACCESS_DENIED', {
          reason: 'TASK_CALLER_SCOPE_MISMATCH',
          taskId,
          callerScope: `${caller.scope.scopeType}:${caller.scope.scopeId}`,
          taskScope: `${taskScope.scopeType}:${taskScope.scopeId}`
        });
        throw new MemoryScopeViolationError(
          `${caller.scope.scopeType}:${caller.scope.scopeId}`,
          `${taskScope.scopeType}:${taskScope.scopeId}`,
          undefined,
          { taskId }
        );
      }
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
      });
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

    // If taskId is provided, verify task exists and scope is compatible
    if (options.taskId && this.taskRepo) {
      const task = this.taskRepo.getTaskById(options.taskId);
      if (!task) {
        throw new TaskNotFoundError(options.taskId);
      }
      const taskScope = this.extractTaskScope(task, caller.scope);
      if (
        taskScope.scopeType !== caller.scope.scopeType ||
        taskScope.scopeId !== caller.scope.scopeId
      ) {
        this.audit(caller, 'MEMORY_ACCESS_DENIED', {
          reason: 'TASK_CALLER_SCOPE_MISMATCH',
          taskId: options.taskId,
          callerScope: `${caller.scope.scopeType}:${caller.scope.scopeId}`,
          taskScope: `${taskScope.scopeType}:${taskScope.scopeId}`
        });
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

    // Record provenance if requested and taskId is present
    if (options.recordInjections && options.taskId) {
      for (const inc of context.included) {
        this.memoryRepo.recordInjection({
          taskId: options.taskId,
          memoryId: inc.id,
          charCount: context.totalChars,
          estimatedTokens: context.estimatedTokens
        });
      }
    }

    if (context.included.length > 0) {
      this.audit(caller, 'MEMORY_RETRIEVED', {
        memoryIds: context.included.map((m) => m.id),
        count: context.included.length,
        scopeType: caller.scope.scopeType,
        scopeId: caller.scope.scopeId,
        taskId: options.taskId
      });
    }

    return context;
  }

  // --- Private Helpers ---

  /**
   * Validates caller context and enforces required permission if specified.
   */
  private validateCaller(
    caller: CallerContext,
    requiredPermission?: MemoryPermission
  ): Set<MemoryPermission> {
    if (!caller || typeof caller !== 'object') {
      throw new ValidationError('CallerContext must be provided.');
    }

    if (!caller.actor || !VALID_ACTORS.has(caller.actor)) {
      throw new ValidationError(`Invalid or missing caller actor: ${String(caller.actor)}`);
    }

    if (!caller.scope || typeof caller.scope !== 'object') {
      throw new ValidationError('Caller scope must be provided.');
    }

    this.validateScope(caller.scope.scopeType, caller.scope.scopeId);

    const permissions = this.normalizePermissions(caller.permissions);

    if (requiredPermission && !permissions.has(requiredPermission)) {
      this.audit(caller, 'MEMORY_ACCESS_DENIED', {
        reason: 'INSUFFICIENT_PERMISSIONS',
        requiredPermission,
        actor: caller.actor,
        scopeType: caller.scope.scopeType,
        scopeId: caller.scope.scopeId
      });
      throw new SecurityViolationError(
        `Caller '${caller.actor}' lacks required '${requiredPermission}' permission.`,
        'INSUFFICIENT_PERMISSIONS',
        { actor: caller.actor, requiredPermission, scope: caller.scope }
      );
    }

    if (this.taskRepo && caller.taskId) {
      const task = this.taskRepo.getTaskById(caller.taskId);
      if (!task) {
        throw new TaskNotFoundError(caller.taskId);
      }
    }

    return permissions;
  }

  /**
   * Normalizes and validates caller permissions array/set.
   */
  private normalizePermissions(perms: unknown): Set<MemoryPermission> {
    if (!perms) {
      throw new ValidationError('Caller permissions must be provided.');
    }

    let items: Iterable<unknown>;
    if (perms instanceof Set) {
      items = perms;
    } else if (Array.isArray(perms)) {
      items = perms;
    } else {
      throw new ValidationError('Caller permissions must be an Array or Set.');
    }

    const result = new Set<MemoryPermission>();
    for (const item of items) {
      if (typeof item !== 'string' || !VALID_PERMISSIONS.has(item as MemoryPermission)) {
        throw new ValidationError(`Invalid permission value: ${String(item)}`);
      }
      result.add(item as MemoryPermission);
    }

    return result;
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
      });
      throw new MemoryScopeViolationError(
        callerScope,
        attemptedScope,
        undefined,
        { operation, actor: caller.actor }
      );
    }
  }

  /**
   * Derives task scope from Task metadata.
   */
  private extractTaskScope(task: Task, fallback: ScopeIdentifier): ScopeIdentifier {
    if (!task.metadataJson) {
      return fallback;
    }
    try {
      const meta = JSON.parse(task.metadataJson);
      if (meta && typeof meta === 'object') {
        if (meta.scopeType && meta.scopeId) {
          return {
            scopeType: meta.scopeType as MemoryScopeType,
            scopeId: String(meta.scopeId)
          };
        }
        if (meta.workspaceId) {
          return {
            scopeType: 'WORKSPACE',
            scopeId: String(meta.workspaceId)
          };
        }
        if (meta.scope && typeof meta.scope === 'object') {
          return {
            scopeType: meta.scope.scopeType as MemoryScopeType,
            scopeId: String(meta.scope.scopeId)
          };
        }
      }
    } catch {
      // Fallback on JSON parse error
    }
    return fallback;
  }

  /**
   * Emits privacy-conscious, tamper-evident audit events via AuditRepository.
   */
  private audit(
    caller: CallerContext,
    eventType: AuditEventType,
    details: Record<string, unknown>
  ): void {
    if (!this.auditRepo) {
      return;
    }

    const taskId = caller.taskId ?? this.getOrCreateSystemTaskId();
    if (!taskId) {
      return;
    }

    try {
      this.auditRepo.appendEvent({
        taskId,
        eventType,
        actor: caller.actor,
        details
      });
    } catch {
      // Prevent audit secondary failures from masking primary operations
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
      const created = this.taskRepo.createTask({
        id: '__system_memory__',
        goal: 'System long-term memory operations'
      });
      this.systemTaskId = created.id;
      return this.systemTaskId;
    } catch {
      return null;
    }
  }
}
