/**
 * Next-Generation Dots AI Platform - Host Capability Bridge
 * Phase 7.3: Runtime Secret Protection & Internal Trust Boundary
 * 
 * Architectural Mandate & Threat Model:
 * This module is strictly internal to the security subsystem and is NOT exported
 * from the public package entry point (src/index.ts). It is intended exclusively for
 * trusted host bootstrap code.
 * 
 * In-Heap Security Model & Honest Threat Boundaries:
 * In a JavaScript runtime (Node.js/V8), code executing in the same heap with unrestricted
 * module access cannot be isolated solely by module boundaries or naming conventions.
 * If untrusted JavaScript executes in the same process, it can inspect global state or
 * directly import internal modules. Internal module visibility is NOT a security boundary
 * against unrestricted JavaScript executing in the same Node.js process.
 * 
 * Therefore:
 * 1. Untrusted agent content, task instructions, and user prompts must NEVER be evaluated
 *    as executable JavaScript in the host heap; they are treated strictly as DATA.
 * 2. Any tool execution or untrusted script execution must occur in sandboxed, external
 *    isolation environments (separate processes, Docker/WASM).
 * 3. Within the host runtime architecture, this module provides the initialization handshake
 *    between HostMemoryAuthority and MemoryAuthorizer, ensuring host secrets and context
 *    registries are held in ECMAScript #private fields and cannot be inspected through
 *    ordinary property access on authorizer instances.
 * 4. Constructing a separate MemoryAuthorizer instance with its own capability handle
 *    does not grant access to an existing host-owned authorizer's private context registry,
 *    as each authorizer maintains its own isolated instance-private WeakSet and host secret.
 */

import type { CallerContext } from '../domain/types.ts';

/**
 * Capability symbol for host bootstrap initialization.
 * Not exported from the public package entry point; intended exclusively for trusted host bootstrap code.
 * Direct import of this symbol does not allow modifying an existing host authorizer instance.
 */
export const HOST_INIT_CAPABILITY: unique symbol = Symbol('dots.host.init.capability');

/**
 * Internal handshake handle passed during host authority bootstrap.
 * Not exported from the public package entry point; used to connect the host authority's
 * system-context issuer to a MemoryAuthorizer instance at construction time.
 */
export interface HostInitHandle {
  readonly capability: typeof HOST_INIT_CAPABILITY;
  setRegistrar(registrar: (context: CallerContext) => void): void;
}

