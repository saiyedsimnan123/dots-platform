/**
 * Next-Generation Dots AI Platform - Memory Authorization Boundary
 * Phase 7.3: Security Hardening
 * 
 * Architectural Mandate:
 * Implements a host-controlled authorization boundary for memory operations.
 * Prevents agents and untrusted execution paths from fabricating or tampering
 * with CallerContext objects (e.g. forging actor identity, escalating permissions,
 * or selecting unauthorized workspace scopes).
 * 
 * Cryptographic & Host-Isolation Design:
 * 1. Process-Private Host Secret: Initialized with a high-entropy 256-bit cryptographically
 *    random secret (crypto.randomBytes(32)) known only to the host authorizer instance.
 * 2. Cryptographic HMAC-SHA256 Signature: Each issued context is stamped with an HMAC
 *    computed over actor, scopeType, scopeId, normalized permissions, taskId, and a unique nonce.
 * 3. Reference Identity Verification: Contexts are registered in a host-held private WeakSet.
 *    Object literals or clones crafted by untrusted callers are immediately rejected.
 * 4. Tamper Resistance: Any mutation of actor, scope, permissions, or taskId invalidates
 *    both the reference identity and the cryptographic MAC.
 * 
 * Documented Architectural Limitation:
 * In a shared Node.js runtime process where untrusted code shares the same JavaScript heap,
 * cryptographic MACs and private WeakSet containment prevent callers from forging tokens,
 * escalating permissions, or spoofing workspaces. However, true process-level security
 * boundaries require executing untrusted agent code in separate sandboxed worker processes.
 * Within the current single-runtime architecture, this host-sealed boundary provides the
 * authoritative, tamper-proof perimeter supported by the runtime.
 */

import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import type {
  CallerContext,
  MemoryActor,
  MemoryPermission,
  ScopeIdentifier
} from '../domain/types.ts';
import { SecurityViolationError, ValidationError } from '../domain/errors.ts';

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

export interface IssueCallerContextInput {
  readonly actor: MemoryActor;
  readonly scope: ScopeIdentifier;
  readonly permissions: readonly MemoryPermission[] | ReadonlySet<MemoryPermission>;
  readonly taskId?: string;
}

export class MemoryAuthorizer {
  private readonly hostSecret: Buffer;
  private readonly issuedContexts: WeakSet<object> = new WeakSet();

  constructor(hostSecret?: Buffer | string) {
    if (hostSecret) {
      this.hostSecret = typeof hostSecret === 'string' ? Buffer.from(hostSecret, 'hex') : hostSecret;
    } else {
      this.hostSecret = randomBytes(32);
    }
  }

  /**
   * Issues an authentic, host-sealed, tamper-evident CallerContext.
   */
  public issueContext(input: IssueCallerContextInput): CallerContext {
    if (!input || typeof input !== 'object') {
      throw new ValidationError('IssueCallerContextInput must be an object.');
    }

    if (!input.actor || !VALID_ACTORS.has(input.actor)) {
      throw new ValidationError(`Invalid or missing caller actor: ${String(input.actor)}`);
    }

    if (!input.scope || typeof input.scope !== 'object') {
      throw new ValidationError('Caller scope must be an object.');
    }

    if (input.scope.scopeType !== 'GLOBAL' && input.scope.scopeType !== 'WORKSPACE') {
      throw new ValidationError(
        `Invalid scopeType '${String(input.scope.scopeType)}'. Must be 'GLOBAL' or 'WORKSPACE'.`
      );
    }

    if (typeof input.scope.scopeId !== 'string' || input.scope.scopeId.trim() === '') {
      throw new ValidationError('scopeId must be a non-empty string.');
    }

    if (input.scope.scopeType === 'GLOBAL' && input.scope.scopeId !== 'default') {
      throw new ValidationError(`Global scope must have scopeId 'default', received '${input.scope.scopeId}'.`);
    }

    if (!input.permissions) {
      throw new ValidationError('Caller permissions must be provided.');
    }

    let permItems: Iterable<unknown>;
    if (input.permissions instanceof Set) {
      permItems = input.permissions;
    } else if (Array.isArray(input.permissions)) {
      permItems = input.permissions;
    } else {
      throw new ValidationError('Caller permissions must be an Array or Set.');
    }

    const normalizedPermissions = new Set<MemoryPermission>();
    for (const item of permItems) {
      if (typeof item !== 'string' || !VALID_PERMISSIONS.has(item as MemoryPermission)) {
        throw new ValidationError(`Invalid permission value: ${String(item)}`);
      }
      normalizedPermissions.add(item as MemoryPermission);
    }

    const nonce = randomBytes(16).toString('hex');
    const signature = this.computeHmac(
      input.actor,
      input.scope,
      normalizedPermissions,
      input.taskId,
      nonce
    );

    const context: CallerContext = Object.freeze({
      actor: input.actor,
      scope: Object.freeze({
        scopeType: input.scope.scopeType,
        scopeId: input.scope.scopeId
      }),
      permissions: Object.freeze(normalizedPermissions),
      taskId: input.taskId,
      _proof: Object.freeze({
        signature,
        nonce
      })
    });

    this.issuedContexts.add(context);
    return context;
  }

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
}
