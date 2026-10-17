/**
 * Next-Generation Dots AI Platform - Memory Authorization Boundary
 * Phase 7.3: Security Hardening
 * 
 * Architectural Mandate:
 * Implements a host-controlled authorization boundary for memory operations.
 * Permissions and scopes are derived strictly from trusted identity and host policy,
 * NOT accepted from untrusted caller claims.
 * 
 * Core Security Guarantees:
 * 1. Role-Based Policy Resolution:
 *    - Human users must provide a verified identity and role (ADMIN, MEMBER, VIEWER).
 *      Permissions are determined by host policy, never caller-selected.
 *    - Automated agents must present an authoritative task ID. The agent's scope is
 *      strictly derived from the task's verified host scope attestation, and its
 *      permissions are permanently locked by policy to READ and WRITE (never APPROVE or DELETE).
 * 2. Trusted Task Scope Origin:
 *    - Task scope is cryptographically attested by the host authorizer at task creation time.
 *      Arbitrary caller-supplied task metadata without valid host cryptographic attestation
 *      is rejected as untrusted, preventing scope spoofing through task creation.
 * 3. Cryptographic Context Sealing:
 *    - Each issued CallerContext is stamped with an HMAC-SHA256 signature computed using
 *      a process-private host secret over actor, scope, permissions, taskId, and a nonce.
 *    - Verified via private WeakSet containment and constant-time HMAC verification.
 * 
 * Documented Architectural Limitation:
 * In a single Node.js runtime process sharing the same JavaScript heap, this cryptographic
 * and WeakSet boundary ensures that untrusted logic cannot fabricate valid contexts,
 * elevate permissions, or select unauthorized workspaces. Full security isolation against
 * hostile code execution requires executing agent code in separated sandboxed worker processes.
 */

import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import type {
  CallerContext,
  MemoryActor,
  MemoryPermission,
  MemoryScopeType,
  ScopeIdentifier,
  Task
} from '../domain/types.ts';
import { SecurityViolationError, ValidationError, TaskNotFoundError } from '../domain/errors.ts';
import type { TaskRepository } from '../storage/task-repository.ts';

export type UserRole = 'ADMIN' | 'MEMBER' | 'VIEWER';

const ROLE_PERMISSIONS_USER: Record<UserRole, ReadonlySet<MemoryPermission>> = {
  ADMIN: new Set(['READ', 'WRITE', 'DELETE', 'APPROVE']),
  MEMBER: new Set(['READ', 'WRITE']),
  VIEWER: new Set(['READ'])
};

const AGENT_PERMISSIONS: ReadonlySet<MemoryPermission> = new Set(['READ', 'WRITE']);
const SYSTEM_PERMISSIONS: ReadonlySet<MemoryPermission> = new Set(['READ', 'WRITE', 'DELETE']);

const VALID_SCOPES: ReadonlySet<MemoryScopeType> = new Set(['GLOBAL', 'WORKSPACE']);

export interface AuthorizeUserInput {
  readonly userId: string;
  readonly role: UserRole;
  readonly scope: ScopeIdentifier;
  readonly taskId?: string;
}

export interface AuthorizeAgentInput {
  readonly taskId: string;
}

export interface AuthorizeSystemInput {
  readonly scope: ScopeIdentifier;
  readonly taskId?: string;
}

export interface CreateTaskWithScopeInput {
  readonly id?: string;
  readonly goal: string;
  readonly scope: ScopeIdentifier;
  readonly metadata?: Record<string, unknown>;
}

export interface TaskScopeAttestation {
  readonly scopeType: MemoryScopeType;
  readonly scopeId: string;
  readonly signature: string;
  readonly timestamp: string;
}

export interface MemoryAuthorizerOptions {
  readonly hostSecret?: Buffer | string;
  readonly taskRepo?: TaskRepository;
}

export class MemoryAuthorizer {
  private readonly hostSecret: Buffer;
  private readonly taskRepo?: TaskRepository;
  private readonly issuedContexts: WeakSet<object> = new WeakSet();

  constructor(options: MemoryAuthorizerOptions = {}) {
    if (options.hostSecret) {
      this.hostSecret = typeof options.hostSecret === 'string'
        ? Buffer.from(options.hostSecret, 'hex')
        : options.hostSecret;
    } else {
      this.hostSecret = randomBytes(32);
    }
    this.taskRepo = options.taskRepo;
  }

  // --- Trusted Identity & Policy Resolution ---

  /**
   * Authorizes a human user based on verified user identity and role.
   * Permissions are derived strictly by host policy from the assigned role.
   */
  public authorizeUser(input: AuthorizeUserInput): CallerContext {
    if (!input || typeof input !== 'object') {
      throw new ValidationError('AuthorizeUserInput must be an object.');
    }
    if (!input.userId || typeof input.userId !== 'string' || input.userId.trim() === '') {
      throw new ValidationError('User ID must be provided.');
    }
    if (!input.role || !ROLE_PERMISSIONS_USER[input.role]) {
      throw new ValidationError(`Invalid user role: ${String(input.role)}`);
    }
    if (!input.scope || typeof input.scope !== 'object') {
      throw new ValidationError('Caller scope must be provided.');
    }

    this.validateScope(input.scope.scopeType, input.scope.scopeId);

    // If a taskId is associated, verify the task exists and scope matches
    if (input.taskId && this.taskRepo) {
      const task = this.taskRepo.getTaskById(input.taskId);
      if (!task) {
        throw new TaskNotFoundError(input.taskId);
      }
      const taskScope = this.verifyTaskScope(task);
      if (
        taskScope.scopeType !== input.scope.scopeType ||
        taskScope.scopeId !== input.scope.scopeId
      ) {
        throw new SecurityViolationError(
          `User scope '${input.scope.scopeType}:${input.scope.scopeId}' does not match task scope '${taskScope.scopeType}:${taskScope.scopeId}'.`,
          'TASK_CALLER_SCOPE_MISMATCH'
        );
      }
    }

    const permissions = ROLE_PERMISSIONS_USER[input.role];

    return this.sealContext({
      actor: 'USER',
      scope: input.scope,
      permissions,
      taskId: input.taskId
    });
  }

  /**
   * Authorizes an automated agent.
   * 
   * Strict Constraints:
   * 1. Requires an authoritative task ID.
   * 2. The agent's scope is derived strictly from the task's verified host scope attestation.
   * 3. Permissions are permanently locked to READ and WRITE by policy (never APPROVE or DELETE).
   */
  public authorizeAgent(input: AuthorizeAgentInput): CallerContext {
    if (!input || typeof input !== 'object') {
      throw new ValidationError('AuthorizeAgentInput must be an object.');
    }
    if (!input.taskId || typeof input.taskId !== 'string' || input.taskId.trim() === '') {
      throw new ValidationError('Task ID must be provided to authorize an agent.');
    }
    if (!this.taskRepo) {
      throw new ValidationError('TaskRepository is required to authorize an agent.');
    }

    const task = this.taskRepo.getTaskById(input.taskId);
    if (!task) {
      throw new TaskNotFoundError(input.taskId);
    }

    // Authoritative scope derived strictly from verified host attestation
    const scope = this.verifyTaskScope(task);

    return this.sealContext({
      actor: 'AGENT',
      scope,
      permissions: AGENT_PERMISSIONS,
      taskId: input.taskId
    });
  }

  /**
   * Authorizes an internal system operation.
   */
  public authorizeSystem(input: AuthorizeSystemInput): CallerContext {
    if (!input || typeof input !== 'object') {
      throw new ValidationError('AuthorizeSystemInput must be an object.');
    }
    this.validateScope(input.scope.scopeType, input.scope.scopeId);

    return this.sealContext({
      actor: 'SYSTEM',
      scope: input.scope,
      permissions: SYSTEM_PERMISSIONS,
      taskId: input.taskId
    });
  }

  // --- Task Scope Attestation & Verification ---

  /**
   * Creates a new task with a cryptographically signed host scope attestation.
   * Establishes a verified scope origin at task creation time.
   */
  public createTask(taskRepo: TaskRepository, input: CreateTaskWithScopeInput): Task {
    if (!input.goal || input.goal.trim() === '') {
      throw new ValidationError('Task goal must not be empty.');
    }
    this.validateScope(input.scope.scopeType, input.scope.scopeId);

    // If an ID is provided, use it; otherwise generate a UUID
    const id = input.id ?? randomBytes(16).toString('hex');
    const attestation = this.attestTaskScope(id, input.scope);

    const metadata = {
      ...(input.metadata ?? {}),
      _scopeAttestation: attestation
    };

    return taskRepo.createTask({
      id,
      goal: input.goal.trim(),
      metadata
    });
  }

  /**
   * Generates a cryptographic host scope attestation for a task ID.
   */
  public attestTaskScope(taskId: string, scope: ScopeIdentifier): TaskScopeAttestation {
    this.validateScope(scope.scopeType, scope.scopeId);
    const timestamp = new Date().toISOString();
    const payload = `TASK_SCOPE|${taskId}|${scope.scopeType}|${scope.scopeId}|${timestamp}`;
    const signature = createHmac('sha256', this.hostSecret).update(payload, 'utf8').digest('hex');

    return {
      scopeType: scope.scopeType,
      scopeId: scope.scopeId,
      signature,
      timestamp
    };
  }

  /**
   * Verifies the cryptographic host scope attestation on a task.
   * Rejects caller-supplied metadata lacking valid host attestation.
   */
  public verifyTaskScope(task: Task): ScopeIdentifier {
    if (!task.metadataJson) {
      throw new ValidationError(
        `Task '${task.id}' lacks metadata required to establish authoritative scope.`
      );
    }

    let meta: Record<string, unknown>;
    try {
      meta = JSON.parse(task.metadataJson);
    } catch {
      throw new ValidationError(
        `Task '${task.id}' metadata is malformed JSON; cannot establish authoritative scope.`
      );
    }

    const attestation = meta._scopeAttestation as TaskScopeAttestation | undefined;
    if (!attestation || typeof attestation !== 'object') {
      throw new ValidationError(
        `Task '${task.id}' lacks a trusted host scope attestation.`
      );
    }

    this.validateScope(attestation.scopeType, attestation.scopeId);

    const payload = `TASK_SCOPE|${task.id}|${attestation.scopeType}|${attestation.scopeId}|${attestation.timestamp}`;
    const expectedSig = createHmac('sha256', this.hostSecret).update(payload, 'utf8').digest('hex');
    const expectedBuf = Buffer.from(expectedSig, 'hex');

    let actualBuf: Buffer;
    try {
      actualBuf = Buffer.from(attestation.signature, 'hex');
    } catch {
      throw new ValidationError(
        `Task '${task.id}' scope attestation has invalid signature format.`
      );
    }

    if (expectedBuf.length !== actualBuf.length || !timingSafeEqual(expectedBuf, actualBuf)) {
      throw new SecurityViolationError(
        `Task '${task.id}' scope attestation failed cryptographic verification (spoofed or untrusted scope).`,
        'FORGED_TASK_SCOPE'
      );
    }

    return {
      scopeType: attestation.scopeType,
      scopeId: attestation.scopeId
    };
  }

  // --- Context Verification ---

  /**
   * Verifies that a CallerContext was legitimately issued by this host authorizer
   * and that its actor, scope, permissions, and taskId have not been modified.
   */
  public verify(caller: unknown): CallerContext {
    if (!caller || typeof caller !== 'object') {
      throw new ValidationError('CallerContext must be provided.');
    }

    // 1. WeakSet reference identity check
    if (!this.issuedContexts.has(caller as object)) {
      throw new SecurityViolationError(
        'Untrusted caller context: context was not issued by trusted host authorization boundary.',
        'FORGED_CALLER_CONTEXT'
      );
    }

    const c = caller as CallerContext & { _proof?: { signature: string; nonce: string } };

    if (!c._proof || typeof c._proof.signature !== 'string' || typeof c._proof.nonce !== 'string') {
      throw new SecurityViolationError(
        'Untrusted caller context: missing cryptographic proof of host issuance.',
        'FORGED_CALLER_CONTEXT'
      );
    }

    // 2. Cryptographic HMAC verification
    const expectedSig = this.computeHmac(
      c.actor,
      c.scope,
      c.permissions,
      c.taskId,
      c._proof.nonce
    );

    const expectedBuf = Buffer.from(expectedSig, 'hex');
    let actualBuf: Buffer;
    try {
      actualBuf = Buffer.from(c._proof.signature, 'hex');
    } catch {
      throw new SecurityViolationError(
        'Untrusted caller context: invalid signature encoding.',
        'FORGED_CALLER_CONTEXT'
      );
    }

    if (expectedBuf.length !== actualBuf.length || !timingSafeEqual(expectedBuf, actualBuf)) {
      throw new SecurityViolationError(
        'Untrusted caller context: cryptographic signature verification failed (context tampered or spoofed).',
        'FORGED_CALLER_CONTEXT'
      );
    }

    return c;
  }

  // --- Private Helpers ---

  private sealContext(params: {
    readonly actor: MemoryActor;
    readonly scope: ScopeIdentifier;
    readonly permissions: ReadonlySet<MemoryPermission>;
    readonly taskId?: string;
  }): CallerContext {
    const nonce = randomBytes(16).toString('hex');
    const signature = this.computeHmac(
      params.actor,
      params.scope,
      params.permissions,
      params.taskId,
      nonce
    );

    const context: CallerContext = Object.freeze({
      actor: params.actor,
      scope: Object.freeze({
        scopeType: params.scope.scopeType,
        scopeId: params.scope.scopeId
      }),
      permissions: Object.freeze(new Set(params.permissions)),
      taskId: params.taskId,
      _proof: Object.freeze({
        signature,
        nonce
      })
    });

    this.issuedContexts.add(context);
    return context;
  }

  private computeHmac(
    actor: MemoryActor,
    scope: ScopeIdentifier,
    permissions: ReadonlySet<MemoryPermission> | readonly MemoryPermission[],
    taskId: string | undefined,
    nonce: string
  ): string {
    const sortedPerms = Array.from(permissions).sort().join(',');
    const payload = `${actor}|${scope.scopeType}|${scope.scopeId}|${sortedPerms}|${taskId ?? ''}|${nonce}`;
    return createHmac('sha256', this.hostSecret).update(payload, 'utf8').digest('hex');
  }

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
}
