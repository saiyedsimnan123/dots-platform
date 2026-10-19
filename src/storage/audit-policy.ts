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
const SAFE_UPDATED_FIELD_NAMES: ReadonlySet<string> = new Set([
  'content',
  'category',
  'tags',
  'priority',
  'metadata',
  'status'
]);

/**
 * Sanitizes audit payload details for memory audit events according to strict allowlist policy.
 * 
 * Guarantees:
 * 1. Non-memory audit events are returned as-is (unaffected).
 * 2. Memory audit events only retain explicitly allowlisted, privacy-safe fields.
 * 3. Raw memory keys, content, tags, and arbitrary metadata are unconditionally removed.
 * 4. Bounded operational metadata (IDs, categories, status transitions, counts, scopes) are preserved.
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
    if (!allowedKeys.has(key)) {
      continue;
    }
    if (FORBIDDEN_MEMORY_AUDIT_FIELDS.has(key)) {
      continue;
    }

    const value = details[key];
    if (value === undefined) {
      continue;
    }

    // Special validation for updatedFields in MEMORY_UPDATED: only allow known schema property names
    if (eventType === 'MEMORY_UPDATED' && key === 'updatedFields') {
      if (Array.isArray(value)) {
        sanitized[key] = value.filter(
          (field): field is string => typeof field === 'string' && SAFE_UPDATED_FIELD_NAMES.has(field)
        );
      }
      continue;
    }

    // Special validation for memoryIds in MEMORY_RETRIEVED: must be an array of strings
    if (eventType === 'MEMORY_RETRIEVED' && key === 'memoryIds') {
      if (Array.isArray(value)) {
        sanitized[key] = value.filter((id): id is string => typeof id === 'string');
      }
      continue;
    }

    sanitized[key] = value;
  }

  return sanitized;
}
