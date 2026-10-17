/**
 * Next-Generation Dots AI Platform - Host Authorization Bootstrap Module
 * Phase 7.3: Trusted Host Boundary Hardening
 * 
 * Architectural Mandate & Threat Model:
 * This module is strictly internal to the trusted host environment (orchestrator,
 * service bootstrap scripts, host infrastructure). It is NEVER re-exported by the
 * public package entry point (src/index.ts) and must never be exposed to untrusted
 * agent or task execution contexts.
 * 
 * In-Heap Security Model:
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
 * 3. Within the host application architecture, this module encapsulates the host authority factory
 *    and privileged operations (createTask, authorizeSystem, attestTaskScope). Ordinary application code
 *    and agent-facing services only receive the unprivileged MemoryAuthorizer, preventing accidental
 *    capability escalation.
 */

import { createHmac, randomBytes } from 'node:crypto';
import type {
  CallerContext,
  MemoryPermission,
  ScopeIdentifier,
  Task
} from '../domain/types.ts';
import { ValidationError, SecurityViolationError } from '../domain/errors.ts';
import type { TaskRepository } from '../storage/task-repository.ts';
import {
  MemoryAuthorizer,
  validateScope,
  type MemoryAuthorizerOptions,
  type AuthorizeSystemInput,
  type CreateTaskWithScopeInput,
  type TaskScopeAttestation
} from './memory-authorizer.ts';

const SYSTEM_PERMISSIONS: ReadonlySet<MemoryPermission> = new Set(['READ', 'WRITE', 'DELETE']);

/**
 * Internal host-bound authorizer subclass.
 * Only constructible within host-authority.ts; never exported.
 * Restricts context registration and secret access to callers holding the private #capabilityKey.
 */
class HostBoundAuthorizer extends MemoryAuthorizer {
  readonly #capabilityKey: symbol;

  constructor(options: MemoryAuthorizerOptions, capabilityKey: symbol) {
    super(options);
    this.#capabilityKey = capabilityKey;
  }

  public registerSystemContext(key: symbol, context: CallerContext): void {
    if (key !== this.#capabilityKey) {
      throw new SecurityViolationError('Unauthorized context registration.', 'HOST_TOKEN_REQUIRED');
    }
    this.issuedContexts.add(context);
  }

  public getHostSecret(key: symbol): Buffer {
    if (key !== this.#capabilityKey) {
      throw new SecurityViolationError('Unauthorized secret access.', 'HOST_TOKEN_REQUIRED');
    }
    return this.hostSecret;
  }
}

export interface HostMemoryAuthorityOptions extends MemoryAuthorizerOptions {}

/**
 * Privileged Host Authorization Control Plane.
 * 
 * Held strictly by trusted host initialization and orchestration bootstrap code.
 * Encapsulates the host capability key and exposes privileged operations:
 * - createTask: creates tasks with verified cryptographic host scope attestations
 * - authorizeSystem: issues system-level CallerContext
 * - attestTaskScope: generates cryptographic scope attestations
 * 
 * The unprivileged authorizer getter provides the unprivileged MemoryAuthorizer instance
 * suitable for distribution to services, callers, and context verifiers.
 */
export class HostMemoryAuthority {
  readonly #authorizer: HostBoundAuthorizer;
  readonly #capabilityKey: symbol;

  constructor(options: HostMemoryAuthorityOptions = {}) {
    const capabilityKey = Symbol('host.capability');
    this.#capabilityKey = capabilityKey;
    this.#authorizer = new HostBoundAuthorizer(options, capabilityKey);
  }

  /**
   * Returns the unprivileged MemoryAuthorizer instance for caller/agent context verification.
   * This instance cannot mint system authority or create tasks.
   */
  public get authorizer(): MemoryAuthorizer {
    return this.#authorizer;
  }

  /**
   * Privileged host operation: creates an attested task in designated workspace.
   */
  public createTask(taskRepo: TaskRepository, input: CreateTaskWithScopeInput): Task {
    if (!input.goal || input.goal.trim() === '') {
      throw new ValidationError('Task goal must not be empty.');
    }
    validateScope(input.scope.scopeType, input.scope.scopeId);

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
   * Privileged host operation: authorizes an internal system operation.
   */
  public authorizeSystem(input: AuthorizeSystemInput): CallerContext {
    if (!input || typeof input !== 'object') {
      throw new ValidationError('AuthorizeSystemInput must be an object.');
    }
    validateScope(input.scope.scopeType, input.scope.scopeId);

    const secret = this.#authorizer.getHostSecret(this.#capabilityKey);
    const nonce = randomBytes(16).toString('hex');
    const sortedPerms = Array.from(SYSTEM_PERMISSIONS).sort().join(',');
    const payload = `SYSTEM|${input.scope.scopeType}|${input.scope.scopeId}|${sortedPerms}|${input.taskId ?? ''}|${nonce}`;
    const signature = createHmac('sha256', secret).update(payload, 'utf8').digest('hex');

    const context: CallerContext = Object.freeze({
      actor: 'SYSTEM',
      scope: Object.freeze({
        scopeType: input.scope.scopeType,
        scopeId: input.scope.scopeId
      }),
      permissions: Object.freeze(new Set(SYSTEM_PERMISSIONS)),
      taskId: input.taskId,
      _proof: Object.freeze({
        signature,
        nonce
      })
    });

    this.#authorizer.registerSystemContext(this.#capabilityKey, context);
    return context;
  }

  /**
   * Privileged host operation: generates a scope attestation.
   */
  public attestTaskScope(taskId: string, scope: ScopeIdentifier): TaskScopeAttestation {
    validateScope(scope.scopeType, scope.scopeId);
    const secret = this.#authorizer.getHostSecret(this.#capabilityKey);
    const timestamp = new Date().toISOString();
    const payload = `TASK_SCOPE|${taskId}|${scope.scopeType}|${scope.scopeId}|${timestamp}`;
    const signature = createHmac('sha256', secret).update(payload, 'utf8').digest('hex');

    return {
      scopeType: scope.scopeType,
      scopeId: scope.scopeId,
      signature,
      timestamp
    };
  }
}

export type { AuthorizeSystemInput, CreateTaskWithScopeInput };
