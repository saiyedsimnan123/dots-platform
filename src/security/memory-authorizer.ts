/**
 * Next-Generation Dots AI Platform - Memory Authorization Boundary
 * Phase 7.3: Security Hardening & Trusted Identity Boundary
 * 
 * Architectural Mandate:
 * Implements a host-controlled authorization boundary for memory operations.
 * Permissions, identities, and scopes are derived strictly from trusted identity providers
 * and process-private host policies, NOT accepted from untrusted caller claims.
 * 
 * In-Heap Security Model & Threat Boundary:
 * In a JavaScript runtime (Node.js/V8), code executing in the same heap with unrestricted
 * module resolution cannot be isolated solely by TypeScript visibility modifiers (private/protected)
 * or naming conventions. If untrusted code could execute arbitrary JavaScript within the host heap,
 * it could import internal modules or inspect process memory.
 * 
 * Consequently:
 * 1. Untrusted agent content, task instructions, and user-supplied prompts MUST NEVER be
 *    evaluated as executable JavaScript in the host heap. They are treated strictly as DATA:
 *    passive text or structured JSON validated against rigid schemas.
 * 2. Any tool execution or code execution requested by agents must occur in sandboxed,
 *    isolated environments (e.g. separate processes, Docker/WASM sandboxes) outside the host Node.js runtime.
 * 3. Privileged host authority construction (HostMemoryAuthority) is isolated to the internal
 *    host bootstrap module (src/security/host-authority.ts) and is NOT exported from the public package
 *    entry point (src/index.ts). Ordinary callers and agents importing the package receive only the
 *    unprivileged MemoryAuthorizer, which cannot mint system authority or create tasks without an
 *    internal HostToken held exclusively by host initialization code.
 * 
 * Core Security Guarantees:
 * 1. Trusted Identity Provider Resolution:
 *    - Human user authorization requires a configured TrustedIdentityProvider.
 *    - If authentication is not implemented or configured on the host authorizer,
 *      it explicitly fails closed with MISSING_IDENTITY_INTEGRATION.
 *    - Untrusted callers cannot pass self-assigned userId, role, or unauthorized scopes.
 *      The principal, role, and permitted scopes are resolved strictly by the IdentityProvider
 *      from authenticated credentials.
 * 2. Privileged Host Capability Boundary:
 *    - Privileged host operations (authorizeSystem, createTask, attestTaskScope) require
 *      a process-private HostToken held exclusively by HostMemoryAuthority during host bootstrap.
 *    - Untrusted callers, agents, and task payloads cannot mint system authority or create
 *      arbitrary tasks in unauthorized workspaces. Unprivileged authorizer instances fail closed.
 * 3. Automated Agent Scope & Permission Binding:
 *    - Agents must present an authoritative taskId. An agent's scope is derived strictly from
 *      the task's verified host cryptographic scope attestation.
 *    - Agent permissions are permanently locked by host policy to READ and WRITE (never APPROVE or DELETE).
 * 4. Cryptographic Context & Task Attestation Sealing:
 *    - Each issued CallerContext and task scope is stamped with an HMAC-SHA256 signature computed
 *      using a process-private host secret. Verified via private WeakSet containment and constant-time HMAC.
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

/**
 * Represents an authenticated principal verified by the trusted identity provider.
 */
export interface AuthenticatedPrincipal {
  readonly principalId: string;
  readonly role: UserRole;
  readonly permittedScopes: readonly ScopeIdentifier[];
}

/**
 * Trusted Identity Provider contract.
 * Resolves an authenticated principal, assigned role, and permitted workspaces from caller credentials.
 */
export interface TrustedIdentityProvider {
  authenticate(credentials: unknown): AuthenticatedPrincipal | null;
}

export interface AuthorizeUserInput {
  /**
   * Authentication credentials (e.g. session token, bearer token, API credential)
   * passed to the trusted identity provider to resolve identity and role.
   */
  readonly credentials?: unknown;
  /**
   * Requested scope for the operation. Must match one of the principal's permitted scopes.
   * If omitted and the principal has exactly one permitted scope, defaults to that scope.
   */
  readonly requestedScope?: ScopeIdentifier;
  /**
   * Optional associated task ID. If supplied, the task's verified scope must match the authorized scope.
   */
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

/**
 * Process-private capability token for trusted host initialization.
 * Only mintable by HostMemoryAuthority.
 */
export class HostToken {
  readonly #secret: symbol;
  constructor(secret: symbol) {
    this.#secret = secret;
  }
}

export interface MemoryAuthorizerOptions {
  readonly hostSecret?: Buffer | string;
  readonly taskRepo?: TaskRepository;
  readonly identityProvider?: TrustedIdentityProvider;
  /** Internal host capability token generated exclusively during host initialization */
  readonly hostToken?: HostToken;
}

export class MemoryAuthorizer {
  private readonly hostSecret: Buffer;
  private readonly taskRepo?: TaskRepository;
  private readonly identityProvider?: TrustedIdentityProvider;
  readonly #hostToken?: HostToken;
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
    this.identityProvider = options.identityProvider;
    this.#hostToken = options.hostToken;
  }

  // --- Trusted Identity & Policy Resolution ---

  /**
   * Authorizes a human user.
   * Resolves the authoritative principal, role, and permitted scope via the trusted IdentityProvider.
   * Callers cannot supply their own userId, role, or arbitrary scope.
   * Fails closed if the identity provider is missing or if credentials are invalid.
   */
  public authorizeUser(input: AuthorizeUserInput): CallerContext {
    if (!input || typeof input !== 'object') {
      throw new ValidationError('AuthorizeUserInput must be an object.');
    }

    if (!this.identityProvider) {
      throw new SecurityViolationError(
        'Authentication integration is not implemented or not configured on host authorizer. Trusted identity cannot be verified.',
        'MISSING_IDENTITY_INTEGRATION'
      );
    }

    if (input.credentials === undefined || input.credentials === null) {
      throw new SecurityViolationError(
        'Authentication credentials are required to authorize a user.',
        'UNAUTHENTICATED'
      );
    }

    const principal = this.identityProvider.authenticate(input.credentials);
    if (!principal) {
      throw new SecurityViolationError(
        'Invalid or unverified authentication credentials.',
        'UNAUTHENTICATED'
      );
    }

    if (!principal.principalId || typeof principal.principalId !== 'string' || principal.principalId.trim() === '') {
      throw new SecurityViolationError(
        'Identity provider returned principal with invalid principalId.',
        'INVALID_PRINCIPAL'
      );
    }

    if (!principal.role || !ROLE_PERMISSIONS_USER[principal.role]) {
      throw new SecurityViolationError(
        `Identity provider returned principal '${principal.principalId}' with invalid role: ${String(principal.role)}.`,
        'INVALID_ROLE'
      );
    }

    let scope: ScopeIdentifier;
    if (input.requestedScope) {
      this.validateScope(input.requestedScope.scopeType, input.requestedScope.scopeId);
      const isAllowed = principal.permittedScopes?.some(
        (s) => s.scopeType === input.requestedScope!.scopeType && s.scopeId === input.requestedScope!.scopeId
      );
      if (!isAllowed) {
        throw new SecurityViolationError(
          `Principal '${principal.principalId}' is not authorized to access scope '${input.requestedScope.scopeType}:${input.requestedScope.scopeId}'.`,
          'UNAUTHORIZED_WORKSPACE'
        );
      }
      scope = input.requestedScope;
    } else {
      if (!principal.permittedScopes || principal.permittedScopes.length === 0) {
        throw new SecurityViolationError(
          `Principal '${principal.principalId}' has no permitted scopes assigned.`,
          'UNAUTHORIZED_WORKSPACE'
        );
      }
      if (principal.permittedScopes.length === 1) {
        scope = principal.permittedScopes[0]!;
      } else {
        throw new ValidationError(
          'Principal has multiple permitted scopes; requestedScope must be explicitly specified.'
        );
      }
    }

    // If a taskId is associated, verify the task exists and scope matches
    if (input.taskId && this.taskRepo) {
      const task = this.taskRepo.getTaskById(input.taskId);
      if (!task) {
        throw new TaskNotFoundError(input.taskId);
      }
      const taskScope = this.verifyTaskScope(task);
      if (
        taskScope.scopeType !== scope.scopeType ||
        taskScope.scopeId !== scope.scopeId
      ) {
        throw new SecurityViolationError(
          `User scope '${scope.scopeType}:${scope.scopeId}' does not match task scope '${taskScope.scopeType}:${taskScope.scopeId}'.`,
          'TASK_CALLER_SCOPE_MISMATCH'
        );
      }
    }

    const permissions = ROLE_PERMISSIONS_USER[principal.role];

    return this.sealContext({
      actor: 'USER',
      scope,
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
   * Internal host capability for system authorization.
   * Requires a valid HostToken held strictly by HostMemoryAuthority during host bootstrap.
   * @internal
   */
  public _authorizeSystem(input: AuthorizeSystemInput, hostToken?: HostToken): CallerContext {
    this.assertHostToken(hostToken, 'authorizeSystem');
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

  /**
   * Fail-closed trap for unauthorized direct calls to authorizeSystem on unprivileged authorizers.
   * Unprivileged MemoryAuthorizer instances cannot mint system authority.
   */
  public authorizeSystem(input?: unknown, hostToken?: unknown): never {
    throw new SecurityViolationError(
      'Privileged host operation \'authorizeSystem\' requires a valid HostToken from trusted host initialization code.',
      'HOST_TOKEN_REQUIRED'
    );
  }

  // --- Task Scope Attestation & Verification ---

  /**
   * Internal host capability for creating a task with cryptographic scope attestation.
   * Requires a valid HostToken held strictly by HostMemoryAuthority during host bootstrap.
   * @internal
   */
  public _createTask(taskRepo: TaskRepository, input: CreateTaskWithScopeInput, hostToken?: HostToken): Task {
    this.assertHostToken(hostToken, 'createTask');
    if (!input.goal || input.goal.trim() === '') {
      throw new ValidationError('Task goal must not be empty.');
    }
    this.validateScope(input.scope.scopeType, input.scope.scopeId);

    // If an ID is provided, use it; otherwise generate a UUID
    const id = input.id ?? randomBytes(16).toString('hex');
    const attestation = this._attestTaskScope(id, input.scope, hostToken);

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
   * Fail-closed trap for unauthorized direct calls to createTask on unprivileged authorizers.
   * Unprivileged MemoryAuthorizer instances cannot create tasks.
   */
  public createTask(taskRepo?: unknown, input?: unknown, hostToken?: unknown): never {
    throw new SecurityViolationError(
      'Privileged host operation \'createTask\' requires a valid HostToken from trusted host initialization code.',
      'HOST_TOKEN_REQUIRED'
    );
  }

  /**
   * Internal host capability for generating a cryptographic host scope attestation for a task ID.
   * Requires a valid HostToken held strictly by HostMemoryAuthority during host bootstrap.
   * @internal
   */
  public _attestTaskScope(taskId: string, scope: ScopeIdentifier, hostToken?: HostToken): TaskScopeAttestation {
    this.assertHostToken(hostToken, 'attestTaskScope');
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
   * Fail-closed trap for unauthorized direct calls to attestTaskScope on unprivileged authorizers.
   * Unprivileged MemoryAuthorizer instances cannot generate host scope attestations.
   */
  public attestTaskScope(taskId?: unknown, scope?: unknown, hostToken?: unknown): never {
    throw new SecurityViolationError(
      'Privileged host operation \'attestTaskScope\' requires a valid HostToken from trusted host initialization code.',
      'HOST_TOKEN_REQUIRED'
    );
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

  private assertHostToken(token: unknown, operation: string): void {
    if (!this.#hostToken || !token || token !== this.#hostToken) {
      throw new SecurityViolationError(
        `Privileged host operation '${operation}' requires a valid HostToken from trusted host initialization code.`,
        'HOST_TOKEN_REQUIRED'
      );
    }
  }

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

