/**
 * Next-Generation Dots AI Platform - Host Capability Bridge
 * Phase 7.3: Runtime Secret Protection & Internal Trust Boundary
 * 
 * Architectural Mandate & Threat Model:
 * This module is strictly internal to the security subsystem. It is NEVER re-exported
 * by the public package entry point (src/index.ts) and must never be exposed to
 * untrusted agent or task execution contexts.
 * 
 * In-Heap Security Model & Honest Threat Boundaries:
 * In a JavaScript runtime (Node.js/V8), code executing in the same heap with unrestricted
 * module access cannot be isolated solely by module boundaries or naming conventions.
 * If untrusted JavaScript executes in the same process, it can inspect global state or
 * import internal files.
 * 
 * Therefore:
 * 1. Untrusted agent content, task instructions, and user prompts must NEVER be evaluated
 *    as executable JavaScript in the host heap; they are treated strictly as DATA.
 * 2. Any tool execution or untrusted script execution must occur in sandboxed, external
 *    isolation environments (separate processes, Docker/WASM).
 * 3. Within the host runtime architecture, this module establishes a non-exportable handshake
 *    between HostMemoryAuthority and MemoryAuthorizer, ensuring host secrets and context
 *    registries are held in ECMAScript #private fields and cannot be inspected through
 *    ordinary property access on authorizer instances.
 */

import type { CallerContext } from '../domain/types.ts';

/**
 * Capability symbol for host bootstrap initialization.
 * Non-exportable outside internal host infrastructure.
 */
export const HOST_INIT_CAPABILITY: unique symbol = Symbol('dots.host.init.capability');

/**
 * Internal handshake handle passed exclusively during host authority bootstrap.
 */
export interface HostInitHandle {
  readonly capability: typeof HOST_INIT_CAPABILITY;
  setRegistrar(registrar: (context: CallerContext) => void): void;
}
