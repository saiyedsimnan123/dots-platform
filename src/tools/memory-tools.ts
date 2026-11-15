/**
 * Next-Generation Dots AI Platform - Agent Memory Proposal Tool
 * Phase 7.5: Substep 4 - Agent Memory-Proposal Tool Integration
 * 
 * Architectural Mandate:
 * Provides an agent-facing tool ('memory_propose') allowing autonomous workflow tasks
 * to submit candidate memories for long-term storage within their attested scope.
 * 
 * Security and Invariant Boundary:
 * 1. Derives caller identity and scope strictly from the task's verified host cryptographic
 *    scope attestation via MemoryAuthorizer.authorizeAgent({ taskId }).
 *    Caller-supplied scope identifiers are NEVER trusted as authorization.
 * 2. Strict Approval Gate: Proposals are persisted with status 'PENDING_APPROVAL'.
 *    Agents CANNOT directly create active memories, cannot decide (approve/reject) proposals,
 *    cannot modify active memories, and cannot delete memories.
 * 3. Privacy Safeguards: Output returns only a minimal, safe proposal acknowledgement.
 *    Audit records and output objects never leak raw memory content or full proposed keys.
 * 4. Input Sanitization & Bounds: Strictly enforces character and count boundaries
 *    (key <= 256, content <= 8192, tags <= 50, metadata <= 50 keys) and scrubs credentials.
 */

import type { RegisteredTool, ToolContext, ToolExecutionResult } from './types.ts';
import type { MemoryCategory, MemoryScopeType } from '../domain/types.ts';
import {
  ValidationError,
  SecurityViolationError,
  MemoryScopeViolationError,
  AgentCancelledError
} from '../domain/errors.ts';
import type { MemoryService } from '../memory/memory-service.ts';
import type { MemoryAuthorizer } from '../security/memory-authorizer.ts';
import { defaultSecretScrubber } from '../model/secret-scrubber.ts';
import {
  MEMORY_CONTEXT_SECURITY_BOUNDARY,
  MEMORY_CONTEXT_SECURITY_NOTICE
} from '../memory/context-builder.ts';

export const MEMORY_PROPOSE_TOOL_NAME = 'memory_propose';

export const MAX_METADATA_TOP_KEYS = 50;
export const MAX_METADATA_DEPTH = 5;
export const MAX_METADATA_TOTAL_VALUES = 500;
export const MAX_METADATA_ARRAY_ITEMS = 100;
export const MAX_METADATA_STRING_LENGTH = 4096;
export const MAX_METADATA_SERIALIZED_BYTES = 16384; // 16 KiB

const VALID_CATEGORIES: ReadonlySet<MemoryCategory> = new Set([
  'USER_PREFERENCE',
  'PROJECT_FACT',
  'LEARNED_PROCEDURE'
]);

const NON_SENSITIVE_PROOF_WORDS = new Set([
  'waterproof',
  'bulletproof',
  'fireproof',
  'soundproof',
  'childproof',
  'foolproof',
  'shatterproof',
  'rustproof',
  'leakproof'
]);

function isSensitiveKey(key: string): boolean {
  if (typeof key !== 'string') {
    return false;
  }
  const trimmed = key.trim();
  if (!trimmed) {
    return false;
  }
  const normalized = trimmed.toLowerCase().replace(/[^a-z0-9]/g, '');
  if (!normalized) {
    return false;
  }

  if (NON_SENSITIVE_PROOF_WORDS.has(normalized)) {
    return false;
  }

  return (
    normalized.endsWith('password') ||
    normalized.endsWith('passphrase') ||
    normalized.endsWith('passwd') ||
    normalized.endsWith('secret') ||
    normalized.endsWith('secrets') ||
    normalized.endsWith('apikey') ||
    normalized.endsWith('privatekey') ||
    normalized.endsWith('token') ||
    normalized.endsWith('tokens') ||
    normalized === 'bearer' ||
    normalized === 'bearertoken' ||
    normalized.endsWith('credential') ||
    normalized.endsWith('credentials') ||
    normalized === 'auth' ||
    normalized === 'authorization' ||
    normalized === 'authtoken' ||
    normalized.endsWith('proof')
  );
}

function sanitizeValue(val: unknown): unknown {
  if (typeof val === 'string') {
    return defaultSecretScrubber.scrub(val);
  }
  if (Array.isArray(val)) {
    return val.map((item) => sanitizeValue(item));
  }
  if (val && typeof val === 'object') {
    const sanitizedObj: Record<string, unknown> = {};
    for (const [key, propVal] of Object.entries(val as Record<string, unknown>)) {
      if (isSensitiveKey(key)) {
        continue; // Never persist authentication credentials
      }
      sanitizedObj[key] = sanitizeValue(propVal);
    }
    return sanitizedObj;
  }
  return val;
}

export function sanitizeProposalMetadata(metadata?: Record<string, unknown>): Record<string, unknown> | undefined {
  if (!metadata || typeof metadata !== 'object' || Array.isArray(metadata)) {
    return undefined;
  }
  const sanitized: Record<string, unknown> = {};
  for (const [key, val] of Object.entries(metadata)) {
    if (isSensitiveKey(key)) {
      continue; // Exclude credentials and sensitive tokens from metadata
    }
    sanitized[key] = sanitizeValue(val);
  }
  return sanitized;
}

export function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return false;
  }
  const proto = Object.getPrototypeOf(value);
  return proto === null || proto === Object.prototype;
}

export function validateProposalMetadata(metadata: unknown): void {
  if (!isPlainObject(metadata)) {
    throw new ValidationError('Memory metadata must be a plain object.');
  }

  let topEntries: [string, unknown][];
  try {
    topEntries = Object.entries(metadata);
  } catch {
    throw new ValidationError('Memory metadata contains unreadable properties.');
  }

  if (topEntries.length > MAX_METADATA_TOP_KEYS) {
    throw new ValidationError(
      `Memory metadata exceeds maximum limit of ${MAX_METADATA_TOP_KEYS} keys (${topEntries.length} > ${MAX_METADATA_TOP_KEYS}).`
    );
  }

  let visitedCount = 1; // Root object counts as 1 visited value
  const activeAncestors = new Set<object>();
  activeAncestors.add(metadata);

  function validateNode(val: unknown, depth: number): void {
    visitedCount++;
    if (visitedCount > MAX_METADATA_TOTAL_VALUES) {
      throw new ValidationError(
        `Memory metadata exceeds maximum limit of ${MAX_METADATA_TOTAL_VALUES} total visited values.`
      );
    }

    if (val === null || typeof val === 'boolean') {
      return;
    }

    if (typeof val === 'number') {
      if (!Number.isFinite(val)) {
        throw new ValidationError('Memory metadata contains unsupported non-finite number.');
      }
      return;
    }

    if (typeof val === 'string') {
      if (val.length > MAX_METADATA_STRING_LENGTH) {
        throw new ValidationError(
          `Memory metadata string exceeds maximum limit of ${MAX_METADATA_STRING_LENGTH} characters (${val.length} > ${MAX_METADATA_STRING_LENGTH}).`
        );
      }
      return;
    }

    if (typeof val === 'undefined') {
      throw new ValidationError('Memory metadata contains unsupported undefined value.');
    }

    if (typeof val === 'symbol') {
      throw new ValidationError('Memory metadata contains unsupported symbol value.');
    }

    if (typeof val === 'bigint') {
      throw new ValidationError('Memory metadata contains unsupported bigint value.');
    }

    if (typeof val === 'function') {
      throw new ValidationError('Memory metadata contains unsupported function value.');
    }

    if (typeof val === 'object') {
      if (activeAncestors.has(val)) {
        throw new ValidationError('Memory metadata contains cyclic references.');
      }

      if (depth > MAX_METADATA_DEPTH) {
        throw new ValidationError(
          `Memory metadata exceeds maximum nesting depth of ${MAX_METADATA_DEPTH}.`
        );
      }

      if (Array.isArray(val)) {
        if (val.length > MAX_METADATA_ARRAY_ITEMS) {
          throw new ValidationError(
            `Memory metadata array exceeds maximum limit of ${MAX_METADATA_ARRAY_ITEMS} items (${val.length} > ${MAX_METADATA_ARRAY_ITEMS}).`
          );
        }
        activeAncestors.add(val);
        try {
          for (const item of val) {
            validateNode(item, depth + 1);
          }
        } finally {
          activeAncestors.delete(val);
        }
        return;
      }

      if (isPlainObject(val)) {
        activeAncestors.add(val);
        try {
          let childEntries: [string, unknown][];
          try {
            childEntries = Object.entries(val);
          } catch {
            throw new ValidationError('Memory metadata contains unreadable properties.');
          }
          for (const [propKey, propVal] of childEntries) {
            if (typeof propKey !== 'string' || propKey.length > MAX_METADATA_STRING_LENGTH) {
              throw new ValidationError(
                `Memory metadata key exceeds maximum limit of ${MAX_METADATA_STRING_LENGTH} characters.`
              );
            }
            validateNode(propVal, depth + 1);
          }
        } finally {
          activeAncestors.delete(val);
        }
        return;
      }

      throw new ValidationError('Memory metadata contains non-plain object.');
    }

    throw new ValidationError('Memory metadata contains unsupported value.');
  }

  try {
    for (const [key, val] of topEntries) {
      if (typeof key !== 'string' || key.length > MAX_METADATA_STRING_LENGTH) {
        throw new ValidationError(
          `Memory metadata key exceeds maximum limit of ${MAX_METADATA_STRING_LENGTH} characters.`
        );
      }
      validateNode(val, 2);
    }
  } finally {
    activeAncestors.delete(metadata);
  }
}

export function validateSerializedMetadataSize(sanitized: Record<string, unknown>): void {
  const json = JSON.stringify(sanitized);
  const byteLength = Buffer.byteLength(json, 'utf8');
  if (byteLength > MAX_METADATA_SERIALIZED_BYTES) {
    throw new ValidationError(
      `Serialized memory metadata exceeds maximum limit of 16 KiB (16384 bytes) (${byteLength} > ${MAX_METADATA_SERIALIZED_BYTES}).`
    );
  }
}

/**
 * Creates a registered tool definition and execution handler for agent memory proposal.
 */
export function createMemoryProposeTool(
  memoryService: MemoryService,
  authorizer: MemoryAuthorizer
): RegisteredTool {
  if (!memoryService) {
    throw new ValidationError('MemoryService must be provided to createMemoryProposeTool.');
  }
  if (!authorizer) {
    throw new ValidationError('MemoryAuthorizer must be provided to createMemoryProposeTool.');
  }

  return {
    definition: {
      name: MEMORY_PROPOSE_TOOL_NAME,
      description: 'Proposes a candidate memory for long-term storage within the task scope. The proposal remains pending and requires human approval before activation.',
      parameters: {
        key: {
          type: 'string',
          description: 'Unique human-readable identifier for the memory within scope (max 256 characters).'
        },
        content: {
          type: 'string',
          description: 'The memory content to propose (max 8192 characters).'
        },
        category: {
          type: 'string',
          description: 'Category of memory: USER_PREFERENCE, PROJECT_FACT, or LEARNED_PROCEDURE.',
          enum: ['USER_PREFERENCE', 'PROJECT_FACT', 'LEARNED_PROCEDURE']
        },
        priority: {
          type: 'number',
          description: 'Optional priority between 0 and 100 (defaults to 50).'
        },
        tags: {
          type: 'array',
          description: 'Optional list of keyword tags for search and relevance retrieval (max 50 tags, 100 chars each).'
        },
        metadata: {
          type: 'object',
          description: 'Optional key-value metadata dictionary (max 50 top-level keys, max nesting depth 5, max 16 KiB serialized).'
        }
      },
      required: ['key', 'content', 'category']
    },
    riskTier: 'TIER_2',
    handler: async (rawArgs: Record<string, unknown>, context: ToolContext): Promise<ToolExecutionResult> => {
      const start = Date.now();

      // 1. Context verification
      if (!context || !context.taskId || typeof context.taskId !== 'string' || context.taskId.trim() === '') {
        throw new SecurityViolationError(
          'Tool execution context must provide an authoritative taskId.',
          'UNAUTHORIZED_AGENT_EXECUTION'
        );
      }

      // 2. Authorize agent and derive authenticated scope
      // Throws TaskNotFoundError if task is unknown, or SecurityViolationError if scope is unattested.
      const caller = authorizer.authorizeAgent({ taskId: context.taskId });

      // 3. Strict argument validation
      if (!rawArgs || typeof rawArgs !== 'object' || Array.isArray(rawArgs)) {
        throw new ValidationError('Tool arguments must be a non-null object.');
      }

      // Key validation
      const rawKey = rawArgs.key;
      if (typeof rawKey !== 'string' || rawKey.trim() === '') {
        throw new ValidationError('Memory proposal key must be a non-empty string.');
      }
      const key = rawKey.trim();
      if (key.length > 256) {
        throw new ValidationError(`Memory proposal key exceeds limit of 256 characters (${key.length} > 256).`);
      }

      // Content validation
      const rawContent = rawArgs.content;
      if (typeof rawContent !== 'string' || rawContent.trim() === '') {
        throw new ValidationError('Memory proposal content must be a non-empty string.');
      }
      const content = rawContent.trim();
      if (content.length > 8192) {
        throw new ValidationError(`Memory proposal content exceeds limit of 8192 characters (${content.length} > 8192).`);
      }

      // Category validation
      const category = rawArgs.category;
      if (!category || !VALID_CATEGORIES.has(category as MemoryCategory)) {
        throw new ValidationError(
          `Invalid memory category '${String(category)}'. Must be one of: ${Array.from(VALID_CATEGORIES).join(', ')}.`
        );
      }

      // Priority validation
      let priority: number | undefined;
      if (rawArgs.priority !== undefined) {
        if (
          typeof rawArgs.priority !== 'number' ||
          !Number.isInteger(rawArgs.priority) ||
          rawArgs.priority < 0 ||
          rawArgs.priority > 100
        ) {
          throw new ValidationError(
            `Memory priority must be an integer between 0 and 100, received '${String(rawArgs.priority)}'.`
          );
        }
        priority = rawArgs.priority;
      }

      // Tags validation
      let tags: string[] | undefined;
      if (rawArgs.tags !== undefined) {
        if (!Array.isArray(rawArgs.tags)) {
          throw new ValidationError('Memory tags must be an array of strings.');
        }
        if (rawArgs.tags.length > 50) {
          throw new ValidationError(`Memory tags array exceeds maximum limit of 50 items (${rawArgs.tags.length} > 50).`);
        }
        tags = [];
        for (let i = 0; i < rawArgs.tags.length; i++) {
          const tag = rawArgs.tags[i];
          if (typeof tag !== 'string' || tag.trim() === '') {
            throw new ValidationError(`Memory tag at index ${i} must be a non-empty string.`);
          }
          const trimmedTag = tag.trim();
          if (trimmedTag.length > 100) {
            throw new ValidationError(`Memory tag at index ${i} exceeds limit of 100 characters (${trimmedTag.length} > 100).`);
          }
          tags.push(trimmedTag);
        }
      }

      // Metadata validation
      let metadata: Record<string, unknown> | undefined;
      if (rawArgs.metadata !== undefined) {
        validateProposalMetadata(rawArgs.metadata);
        metadata = sanitizeProposalMetadata(rawArgs.metadata as Record<string, unknown>);
        if (metadata !== undefined) {
          validateSerializedMetadataSize(metadata);
        }
      }

      // Status gate: Reject any attempt to propose directly as ACTIVE
      if (rawArgs.status !== undefined && rawArgs.status !== 'PENDING_APPROVAL') {
        throw new SecurityViolationError(
          'Agents cannot directly create active memories; proposals must be created with status PENDING_APPROVAL.',
          'AGENT_PROPOSAL_REQUIRED',
          { attemptedStatus: rawArgs.status }
        );
      }

      // Scope gate: Reject any explicit scope spoofing in args
      if (rawArgs.scopeType !== undefined && rawArgs.scopeType !== caller.scope.scopeType) {
        throw new MemoryScopeViolationError(
          `${caller.scope.scopeType}:${caller.scope.scopeId}`,
          `${String(rawArgs.scopeType)}:${String(rawArgs.scopeId ?? caller.scope.scopeId)}`,
          'proposal'
        );
      }
      if (rawArgs.scopeId !== undefined && rawArgs.scopeId !== caller.scope.scopeId) {
        throw new MemoryScopeViolationError(
          `${caller.scope.scopeType}:${caller.scope.scopeId}`,
          `${String(rawArgs.scopeType ?? caller.scope.scopeType)}:${String(rawArgs.scopeId)}`,
          'proposal'
        );
      }

      // 4. Submit proposal via trusted MemoryService
      // Forces status to 'PENDING_APPROVAL' through agent caller context verification
      const memory = memoryService.createMemory(caller, {
        key,
        content,
        category: category as MemoryCategory,
        scopeType: caller.scope.scopeType,
        scopeId: caller.scope.scopeId,
        status: 'PENDING_APPROVAL',
        ...(priority !== undefined ? { priority } : {}),
        ...(tags !== undefined ? { tags } : {}),
        ...(metadata !== undefined ? { metadata } : {})
      });

      // 5. Minimal, safe acknowledgement (zero raw content or internal row properties leaked)
      return {
        output: {
          success: true,
          proposalId: memory.id,
          status: memory.status,
          category: memory.category,
          scopeType: memory.scopeType,
          scopeId: memory.scopeId,
          message: 'Memory proposal submitted successfully and is pending human approval.'
        },
        exitCode: 0,
        durationMs: Date.now() - start
      };
    }
  };
}

export const MEMORY_SEARCH_TOOL_NAME = 'memory_search';

/**
 * Creates a registered tool definition and execution handler for agent memory search.
 * Read-only safe inspection tool (TIER_1).
 */
export function createMemorySearchTool(
  memoryService: MemoryService,
  authorizer: MemoryAuthorizer
): RegisteredTool {
  if (!memoryService) {
    throw new ValidationError('MemoryService must be provided to createMemorySearchTool.');
  }
  if (!authorizer) {
    throw new ValidationError('MemoryAuthorizer must be provided to createMemorySearchTool.');
  }

  return {
    definition: {
      name: MEMORY_SEARCH_TOOL_NAME,
      description: 'Searches relevant long-term memories within the task scope using lexical and keyword matching. Returns read-only historical memories.',
      parameters: {
        query: {
          type: 'string',
          description: 'Search query or keywords to find relevant stored memories (max 2000 characters).'
        },
        limit: {
          type: 'number',
          description: 'Optional maximum number of memories to return (1-50, default 5).'
        },
        category: {
          type: 'string',
          description: 'Optional category filter: USER_PREFERENCE, PROJECT_FACT, or LEARNED_PROCEDURE.',
          enum: ['USER_PREFERENCE', 'PROJECT_FACT', 'LEARNED_PROCEDURE']
        }
      },
      required: ['query']
    },
    riskTier: 'TIER_1',
    handler: async (rawArgs: Record<string, unknown>, context: ToolContext): Promise<ToolExecutionResult> => {
      const start = Date.now();

      // Early cancellation check
      if (context?.signal?.aborted) {
        throw new AgentCancelledError(
          `Memory search cancelled by signal: ${context.signal.reason ? String(context.signal.reason) : 'aborted'}`
        );
      }

      // 1. Context verification
      if (!context || !context.taskId || typeof context.taskId !== 'string' || context.taskId.trim() === '') {
        throw new SecurityViolationError(
          'Tool execution context must provide an authoritative taskId.',
          'UNAUTHORIZED_AGENT_EXECUTION'
        );
      }

      // 2. Authorize agent and derive authenticated scope
      const caller = authorizer.authorizeAgent({ taskId: context.taskId });

      // 3. Strict argument validation
      if (!rawArgs || typeof rawArgs !== 'object' || Array.isArray(rawArgs)) {
        throw new ValidationError('Tool arguments must be a non-null object.');
      }

      // Query validation
      const rawQuery = rawArgs.query;
      if (typeof rawQuery !== 'string' || rawQuery.trim() === '') {
        throw new ValidationError('Memory search query must be a non-empty string.');
      }
      const query = rawQuery.trim();
      if (query.length > 2000) {
        throw new ValidationError(`Memory search query exceeds limit of 2000 characters (${query.length} > 2000).`);
      }

      // Limit validation
      let limit = 5;
      if (rawArgs.limit !== undefined) {
        if (
          typeof rawArgs.limit !== 'number' ||
          !Number.isInteger(rawArgs.limit) ||
          rawArgs.limit < 1 ||
          rawArgs.limit > 50
        ) {
          throw new ValidationError(
            `Memory search limit must be an integer between 1 and 50, received '${String(rawArgs.limit)}'.`
          );
        }
        limit = rawArgs.limit;
      }

      // Category validation
      let category: MemoryCategory | undefined;
      if (rawArgs.category !== undefined) {
        if (!rawArgs.category || !VALID_CATEGORIES.has(rawArgs.category as MemoryCategory)) {
          throw new ValidationError(
            `Invalid memory category '${String(rawArgs.category)}'. Must be one of: ${Array.from(VALID_CATEGORIES).join(', ')}.`
          );
        }
        category = rawArgs.category as MemoryCategory;
      }

      // Scope gate: Reject any explicit scope spoofing in args
      if (rawArgs.scopeType !== undefined && rawArgs.scopeType !== caller.scope.scopeType) {
        throw new MemoryScopeViolationError(
          `${caller.scope.scopeType}:${caller.scope.scopeId}`,
          `${String(rawArgs.scopeType)}:${String(rawArgs.scopeId ?? caller.scope.scopeId)}`,
          'search'
        );
      }
      if (rawArgs.scopeId !== undefined && rawArgs.scopeId !== caller.scope.scopeId) {
        throw new MemoryScopeViolationError(
          `${caller.scope.scopeType}:${caller.scope.scopeId}`,
          `${String(rawArgs.scopeType ?? caller.scope.scopeType)}:${String(rawArgs.scopeId)}`,
          'search'
        );
      }

      // Cancellation check before search
      if (context?.signal?.aborted) {
        throw new AgentCancelledError(
          `Memory search cancelled by signal: ${context.signal.reason ? String(context.signal.reason) : 'aborted'}`
        );
      }

      // 4. Perform search via MemoryService
      const scoredMemories = memoryService.searchMemories(caller, {
        query,
        limit,
        category,
        taskId: context.taskId
      });

      // Cancellation check after search
      if (context?.signal?.aborted) {
        throw new AgentCancelledError(
          `Memory search cancelled by signal: ${context.signal.reason ? String(context.signal.reason) : 'aborted'}`
        );
      }

      // 5. Format results safely with secret scrubbing and untrusted context boundary
      const formattedMemories = scoredMemories.map((sm) => {
        let tags: string[] = [];
        try {
          const parsed = JSON.parse(sm.memory.tagsJson);
          if (Array.isArray(parsed)) {
            tags = parsed
              .filter((t): t is string => typeof t === 'string')
              .map((t) => defaultSecretScrubber.scrub(t));
          }
        } catch {
          tags = [];
        }

        let metadata: Record<string, unknown> = {};
        try {
          const parsed = JSON.parse(sm.memory.metadataJson);
          if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
            metadata = (sanitizeProposalMetadata(parsed as Record<string, unknown>) ?? {}) as Record<string, unknown>;
          }
        } catch {
          metadata = {};
        }

        return {
          id: sm.memory.id,
          key: defaultSecretScrubber.scrub(sm.memory.key),
          content: defaultSecretScrubber.scrub(sm.memory.content),
          category: sm.memory.category,
          score: sm.score,
          tags,
          metadata,
          createdAt: sm.memory.createdAt
        };
      });

      return {
        output: {
          success: true,
          query: defaultSecretScrubber.scrub(query),
          count: formattedMemories.length,
          memories: formattedMemories,
          _boundary: MEMORY_CONTEXT_SECURITY_BOUNDARY,
          _securityNotice: MEMORY_CONTEXT_SECURITY_NOTICE
        },
        exitCode: 0,
        durationMs: Date.now() - start
      };
    }
  };
}
