/**
 * Next-Generation Dots AI Platform - Memory Audit Privacy Policy & Shared Enforcement Boundary
 * 
 * Architectural Mandate:
 * Centralizes and enforces privacy boundaries for all memory audit events.
 * Strips raw memory keys, content, tags, and arbitrary metadata while preserving
 * safe operational telemetry (identifiers, categories, status transitions, counts,
 * scopes, and failure reasons).
 * 
 * Non-memory audit events are scoped out and passed through unmodified to preserve
 * domain-specific audit semantics across the broader platform.
 */

import type { AuditEventType } from '../domain/types.ts';

export const MEMORY_AUDIT_EVENT_TYPES = [
  'MEMORY_CREATED',
  'MEMORY_UPDATED',
  'MEMORY_ARCHIVED',
  'MEMORY_DELETED',
  'MEMORY_RETRIEVED',
  'MEMORY_ACCESS_DENIED',
  'MEMORY_PROPOSAL_SUBMITTED',
  'MEMORY_PROPOSAL_DECIDED',
  'MEMORY_EXPORTED',
  'MEMORIES_IMPORTED',
  'MEMORIES_PURGED',
] as const;

export type MemoryAuditEventType = (typeof MEMORY_AUDIT_EVENT_TYPES)[number];

const MEMORY_EVENT_SET = new Set<string>(MEMORY_AUDIT_EVENT_TYPES);

/**
 * Type guard to identify if an audit event type is a memory subsystem event.
 */
export function isMemoryAuditEvent(eventType: string): eventType is MemoryAuditEventType {
  return MEMORY_EVENT_SET.has(eventType);
}

/**
 * Explicit allowlist of permissible, privacy-safe fields for each memory audit event type.
 * Any field not explicitly declared in this allowlist is dropped at the shared boundary.
 */
export const MEMORY_AUDIT_ALLOWLIST: Record<MemoryAuditEventType, readonly string[]> = {
  MEMORY_CREATED: [
    'memoryId',
    'category',
    'scopeType',
    'scopeId',
    'status'
  ],
  MEMORY_PROPOSAL_SUBMITTED: [
    'memoryId',
    'category',
    'scopeType',
    'scopeId',
    'status',
    'proposedBy'
  ],
  MEMORY_RETRIEVED: [
    'memoryId',
    'memoryIds',
    'count',
    'category',
    'scopeType',
    'scopeId',
    'taskId',
    'operation',
    'totalInjections'
  ],
  MEMORY_UPDATED: [
    'memoryId',
    'category',
    'scopeType',
    'scopeId',
    'updatedFields'
  ],
  MEMORY_ARCHIVED: [
    'memoryId',
    'category',
    'scopeType',
    'scopeId'
  ],
  MEMORY_DELETED: [
    'memoryId',
    'category',
    'scopeType',
    'scopeId'
  ],
  MEMORY_PROPOSAL_DECIDED: [
    'memoryId',
    'category',
    'decision',
    'decidedBy',
    'scopeType',
    'scopeId',
    'previousStatus',
    'newStatus'
  ],
  MEMORY_EXPORTED: [
    'scopeType',
    'scopeId',
    'exportedCount',
    'checksum'
  ],
  MEMORIES_IMPORTED: [
    'targetScopeType',
    'targetScopeId',
    'totalInBundle',
    'importedCount',
    'skippedCount',
    'overwrittenCount',
    'conflictStrategy',
    'checksum'
  ],
  MEMORIES_PURGED: [
    'scopeType',
    'scopeId',
    'purgeMode',
    'purgedCount',
    'batchSizeLimit',
    'cutoffTimestamp'
  ],
  MEMORY_ACCESS_DENIED: [
    'reason',
    'operation',
    'memoryId',
    'category',
    'expectedScope',
    'callerScope',
    'taskScope',
    'memoryScope',
    'attemptedScope',
    'attemptedStatus',
    'currentStatus',
    'status',
    'requiredPermission',
    'actor',
    'scopeType',
    'scopeId',
    'taskId'
  ]
};

/**
 * Explicitly forbidden sensitive memory fields.
 * Dropped unconditionally across all memory audit events as defense-in-depth.
 */
export const FORBIDDEN_MEMORY_AUDIT_FIELDS: ReadonlySet<string> = new Set([
  'key',
  'content',
  'tags',
  'metadata'
]);

/**
 * Permissible schema field names for `updatedFields` in `MEMORY_UPDATED`.
 */
export const SAFE_UPDATED_FIELD_NAMES: ReadonlySet<string> = new Set([
  'content',
  'category',
  'tags',
  'priority',
  'metadata',
  'status'
]);

/**
 * Permissible finite enums and valid identifiers for memory audit event values.
 */
export const MEMORY_CATEGORIES: ReadonlySet<string> = new Set([
  'USER_PREFERENCE',
  'PROJECT_FACT',
  'LEARNED_PROCEDURE'
]);

export const MEMORY_SCOPES: ReadonlySet<string> = new Set([
  'GLOBAL',
  'WORKSPACE'
]);

export const MEMORY_STATUSES: ReadonlySet<string> = new Set([
  'ACTIVE',
  'PENDING_APPROVAL',
  'ARCHIVED'
]);

export const PROPOSAL_DECISIONS: ReadonlySet<string> = new Set([
  'APPROVED',
  'REJECTED'
]);

export const MEMORY_ACTORS: ReadonlySet<string> = new Set([
  'USER',
  'AGENT',
  'SYSTEM',
  'POLICY_ENGINE'
]);

export const MEMORY_PERMISSIONS: ReadonlySet<string> = new Set([
  'READ',
  'WRITE',
  'DELETE',
  'APPROVE'
]);

export const CONFLICT_STRATEGIES: ReadonlySet<string> = new Set([
  'FAIL',
  'SKIP',
  'OVERWRITE'
]);

export const PURGE_MODES: ReadonlySet<string> = new Set([
  'ID_LIST',
  'CUTOFF'
]);

export const KNOWN_MEMORY_OPERATIONS: ReadonlySet<string> = new Set([
  'createMemory',
  'updateMemory',
  'archiveMemory',
  'deleteMemory',
  'decideProposal',
  'getMemoryById',
  'getMemoryByKey',
  'listMemories',
  'recordAccess',
  'buildTaskMemoryContext',
  'getMemoryUsageHistory',
  'exportMemories',
  'importMemories',
  'purgeArchivedMemories',
  'recordTaskInjection',
  'recordTaskInjectionsBatch',
  'getInjectionsByTaskId',
  'operation'
]);

export const KNOWN_DENIAL_REASONS: ReadonlySet<string> = new Set([
  'AGENT_DIRECT_ACTIVE_CREATION_DENIED',
  'AGENT_MUTATION_DENIED',
  'APPROVAL_BYPASS_ATTEMPT',
  'UNAUTHORIZED_STATUS_TRANSITION',
  'CROSS_SCOPE_UPDATE_ATTEMPT',
  'CROSS_SCOPE_ARCHIVE_ATTEMPT',
  'CROSS_SCOPE_DELETE_ATTEMPT',
  'AGENT_SELF_APPROVAL_ATTEMPT',
  'NON_USER_APPROVAL_ATTEMPT',
  'CROSS_SCOPE_DECISION_ATTEMPT',
  'TASK_CALLER_SCOPE_MISMATCH',
  'TASK_MEMORY_SCOPE_MISMATCH',
  'INSUFFICIENT_PERMISSIONS',
  'SCOPE_FORGERY_ATTEMPT',
  'AGENT_PURGE_DENIED',
  'CROSS_SCOPE_PURGE_ATTEMPT',
  'NON_ARCHIVED_PURGE_DENIED',
  'CROSS_SCOPE_READ_ATTEMPT'
]);

/**
 * Identifier and Scope Safety Contracts:
 *
 * 1. memoryId, taskId, and scopeId:
 *    Validated against ID_PATTERN (/^[a-zA-Z0-9_.-]{1,128}$/).
 *    Aligns with the repository contracts which support standard UUIDs, slug strings,
 *    and prefix-based identifiers (e.g. 'mem-1', 'ws-alpha', 'default').
 *    UUID-only restrictions are intentionally not imposed to preserve public API contracts.
 *
 * 2. Unavoidable Scope Identifier Limitations:
 *    Workspace scope identifiers are opaque strings provided by callers or environment.
 *    Any workspace scope identifier containing characters outside [a-zA-Z0-9_.-] (such as spaces,
 *    colons, slashes, or control characters) or exceeding 128 characters is considered untrusted
 *    at the audit boundary and will be dropped. This constraint is unavoidable to guarantee that
 *    sensitive payload data or log-injection attacks cannot be smuggled through scope fields.
 */
const ID_PATTERN = /^[a-zA-Z0-9_.-]{1,128}$/;
const SCOPE_STRING_PATTERN = /^[a-zA-Z0-9_.-]{1,32}:[a-zA-Z0-9_.-]{1,128}$/;

/**
 * Canonical SHA-256 digest format: strictly 64 lowercase hexadecimal characters.
 * Matches the format generated by `computeCanonicalSha256()` in `src/memory/canonical-json.ts`.
 */
export const STRICT_SHA256_HEX_REGEX = /^[0-9a-f]{64}$/;

const STRICT_ISO_8601_UTC_REGEX = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/;

/**
 * Validates that a string is a strict ISO 8601 UTC timestamp ending in 'Z'
 * with up to 3 fractional digits and valid calendar/time values (no rollover).
 */
export function isValidUtcTimestamp(value: unknown): boolean {
  if (typeof value !== 'string' || !STRICT_ISO_8601_UTC_REGEX.test(value)) {
    return false;
  }
  const date = new Date(value);
  if (isNaN(date.getTime())) {
    return false;
  }

  // Verify that date parsing did not rollover invalid calendar dates or times
  const [datePart, timePart] = value.slice(0, -1).split('T');
  const [yearStr, monthStr, dayStr] = datePart.split('-');
  const [hourStr, minuteStr, secondPart] = timePart.split(':');
  const [secondStr] = secondPart.split('.');

  return (
    date.getUTCFullYear() === Number(yearStr) &&
    date.getUTCMonth() + 1 === Number(monthStr) &&
    date.getUTCDate() === Number(dayStr) &&
    date.getUTCHours() === Number(hourStr) &&
    date.getUTCMinutes() === Number(minuteStr) &&
    date.getUTCSeconds() === Number(secondStr)
  );
}

/**
 * Strictly validates and normalizes an allowlisted property value for a memory audit event.
 * Returns the hardened value if valid, or undefined if the value is invalid, malicious, or malformed.
 */
export function validateMemoryAuditFieldValue(
  eventType: MemoryAuditEventType,
  key: string,
  value: unknown
): unknown | undefined {
  // Reject all non-array objects immediately - memory audit payloads must NEVER contain arbitrary nested objects
  if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
    return undefined;
  }

  // Reject boolean, symbol, function, bigint, undefined, null
  if (
    value === undefined ||
    value === null ||
    typeof value === 'boolean' ||
    typeof value === 'symbol' ||
    typeof value === 'function' ||
    typeof value === 'bigint'
  ) {
    return undefined;
  }

  // Identifiers: adheres to repository contracts (UUIDs, slug strings, prefixed IDs)
  if (key === 'memoryId' || key === 'taskId' || key === 'scopeId' || key === 'targetScopeId') {
    return typeof value === 'string' && ID_PATTERN.test(value) ? value : undefined;
  }

  // Enums and finite allowlists
  if (key === 'category') {
    return typeof value === 'string' && MEMORY_CATEGORIES.has(value) ? value : undefined;
  }

  if (key === 'scopeType' || key === 'targetScopeType') {
    return typeof value === 'string' && MEMORY_SCOPES.has(value) ? value : undefined;
  }

  if (key === 'status' || key === 'previousStatus' || key === 'newStatus' || key === 'currentStatus') {
    return typeof value === 'string' && MEMORY_STATUSES.has(value) ? value : undefined;
  }

  // attemptedStatus must strictly be a known memory status (zero permissive regex fallback)
  if (key === 'attemptedStatus') {
    return typeof value === 'string' && MEMORY_STATUSES.has(value)
      ? value
      : undefined;
  }

  if (key === 'decision') {
    return typeof value === 'string' && PROPOSAL_DECISIONS.has(value) ? value : undefined;
  }

  if (key === 'decidedBy' || key === 'proposedBy' || key === 'actor') {
    return typeof value === 'string' && MEMORY_ACTORS.has(value) ? value : undefined;
  }

  if (key === 'requiredPermission') {
    return typeof value === 'string' && MEMORY_PERMISSIONS.has(value) ? value : undefined;
  }

  if (key === 'conflictStrategy') {
    return typeof value === 'string' && CONFLICT_STRATEGIES.has(value) ? value : undefined;
  }

  if (key === 'purgeMode') {
    return typeof value === 'string' && PURGE_MODES.has(value) ? value : undefined;
  }

  // reason must strictly be a known denial reason (zero permissive regex fallback)
  if (key === 'reason') {
    return typeof value === 'string' && KNOWN_DENIAL_REASONS.has(value)
      ? value
      : undefined;
  }

  // operation must strictly be a known memory operation (zero permissive regex fallback)
  if (key === 'operation') {
    return typeof value === 'string' && KNOWN_MEMORY_OPERATIONS.has(value)
      ? value
      : undefined;
  }

  // Scope strings (formatted as "scopeType:scopeId")
  if (
    key === 'expectedScope' ||
    key === 'callerScope' ||
    key === 'taskScope' ||
    key === 'memoryScope' ||
    key === 'attemptedScope'
  ) {
    return typeof value === 'string' && SCOPE_STRING_PATTERN.test(value) ? value : undefined;
  }

  // Non-negative finite integers
  if (
    key === 'count' ||
    key === 'totalInjections' ||
    key === 'exportedCount' ||
    key === 'totalInBundle' ||
    key === 'importedCount' ||
    key === 'skippedCount' ||
    key === 'overwrittenCount' ||
    key === 'purgedCount'
  ) {
    return typeof value === 'number' && Number.isInteger(value) && Number.isFinite(value) && value >= 0
      ? value
      : undefined;
  }

  // Positive finite integers (>= 1)
  if (key === 'batchSizeLimit') {
    return typeof value === 'number' && Number.isInteger(value) && Number.isFinite(value) && value >= 1
      ? value
      : undefined;
  }

  // Checksums: strictly 64-character lowercase hexadecimal SHA-256 digest
  if (key === 'checksum') {
    return typeof value === 'string' && STRICT_SHA256_HEX_REGEX.test(value) ? value : undefined;
  }

  // UTC ISO timestamps
  if (key === 'cutoffTimestamp') {
    return isValidUtcTimestamp(value) ? (value as string) : undefined;
  }

  // Memory IDs array (only for MEMORY_RETRIEVED)
  if (key === 'memoryIds') {
    if (eventType !== 'MEMORY_RETRIEVED' || !Array.isArray(value) || value.length > 1000) {
      return undefined;
    }
    const filtered = value.filter(
      (id): id is string => typeof id === 'string' && ID_PATTERN.test(id)
    );
    if (value.length > 0 && filtered.length === 0) {
      return undefined;
    }
    return filtered;
  }

  // Updated fields array (only for MEMORY_UPDATED)
  if (key === 'updatedFields') {
    if (eventType !== 'MEMORY_UPDATED' || !Array.isArray(value)) {
      return undefined;
    }
    return value.filter(
      (field): field is string => typeof field === 'string' && SAFE_UPDATED_FIELD_NAMES.has(field)
    );
  }

  return undefined;
}

/**
 * Sanitizes audit payload details for memory audit events according to strict allowlist policy.
 * 
 * Guarantees:
 * 1. Non-memory audit events are returned as-is (unaffected).
 * 2. Memory audit events only retain explicitly allowlisted, privacy-safe fields.
 * 3. Raw memory keys, content, tags, and arbitrary metadata are unconditionally removed.
 * 4. Bounded operational metadata (IDs, categories, status transitions, counts, scopes) are preserved.
 * 5. Values are strictly validated against finite enums, ID patterns, numeric constraints, and UTC ISO timestamps.
 * 6. Nested arbitrary objects and prototype pollution keys are strictly dropped.
 */
export function sanitizeMemoryAuditDetails(
  eventType: AuditEventType,
  details: Record<string, unknown> | undefined | null
): Record<string, unknown> {
  // Non-memory events are not subject to memory privacy filtering
  if (!isMemoryAuditEvent(eventType)) {
    return details ?? {};
  }

  if (!details || typeof details !== 'object' || Array.isArray(details)) {
    return {};
  }

  const allowedKeys = new Set(MEMORY_AUDIT_ALLOWLIST[eventType]);
  const sanitized: Record<string, unknown> = {};

  for (const key of Object.keys(details)) {
    // Defense-in-depth against prototype pollution keys
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
      continue;
    }

    if (!allowedKeys.has(key)) {
      continue;
    }
    if (FORBIDDEN_MEMORY_AUDIT_FIELDS.has(key)) {
      continue;
    }

    const value = details[key];
    if (value === undefined || value === null) {
      continue;
    }

    const validatedValue = validateMemoryAuditFieldValue(eventType, key, value);
    if (validatedValue !== undefined) {
      sanitized[key] = validatedValue;
    }
  }

  return sanitized;
}
