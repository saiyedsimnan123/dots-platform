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
 * 3. Within the host application architecture, this module establishes a strict encapsulation
 *    boundary: ordinary application code and agent-facing services only receive the unprivileged
 *    MemoryAuthorizer, preventing accidental capability escalation or unauthorized task creation.
 */

import type { CallerContext, ScopeIdentifier, Task } from '../domain/types.ts';
import type { TaskRepository } from '../storage/task-repository.ts';
import {
  MemoryAuthorizer,
  HostToken,
  type MemoryAuthorizerOptions,
  type AuthorizeSystemInput,
  type CreateTaskWithScopeInput,
  type TaskScopeAttestation
} from './memory-authorizer.ts';

export interface HostMemoryAuthorityOptions extends Omit<MemoryAuthorizerOptions, 'hostToken'> {}

/**
 * Privileged Host Authorization Control Plane.
 * 
 * Held strictly by trusted host initialization and orchestration bootstrap code.
 * Encapsulates the process-private HostToken and exposes privileged operations:
 * - createTask: creates tasks with verified cryptographic host scope attestations
 * - authorizeSystem: issues system-level CallerContext
 * - attestTaskScope: generates cryptographic scope attestations
 * 
 * The unprivileged authorizer getter provides the unprivileged MemoryAuthorizer instance
 * suitable for distribution to services, callers, and context verifiers.
 */
export class HostMemoryAuthority {
  readonly #authorizer: MemoryAuthorizer;
  readonly #hostToken: HostToken;

  constructor(options: HostMemoryAuthorityOptions = {}) {
    const hostToken = new HostToken(Symbol('host.capability'));
    this.#hostToken = hostToken;
    this.#authorizer = new MemoryAuthorizer({ ...options, hostToken });
  }

  /**
   * Returns the unprivileged MemoryAuthorizer instance for caller/agent context verification.
   * This instance cannot mint system authority or create tasks without the HostToken.
   */
  public get authorizer(): MemoryAuthorizer {
    return this.#authorizer;
  }

  /**
   * Privileged host operation: creates an attested task in designated workspace.
   */
  public createTask(taskRepo: TaskRepository, input: CreateTaskWithScopeInput): Task {
    return this.#authorizer._createTask(taskRepo, input, this.#hostToken);
  }

  /**
   * Privileged host operation: authorizes an internal system operation.
   */
  public authorizeSystem(input: AuthorizeSystemInput): CallerContext {
    return this.#authorizer._authorizeSystem(input, this.#hostToken);
  }

  /**
   * Privileged host operation: generates a scope attestation.
   */
  public attestTaskScope(taskId: string, scope: ScopeIdentifier): TaskScopeAttestation {
    return this.#authorizer._attestTaskScope(taskId, scope, this.#hostToken);
  }
}

export type { AuthorizeSystemInput, CreateTaskWithScopeInput };
