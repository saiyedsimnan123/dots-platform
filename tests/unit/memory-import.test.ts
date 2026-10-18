/**
 * Next-Generation Dots AI Platform - Memory Import & Conflict Resolution Tests
 * Phase 7.5: Substep 2
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseManager } from '../../src/storage/db.ts';
import { TaskRepository } from '../../src/storage/task-repository.ts';
import { AuditRepository } from '../../src/storage/audit-repository.ts';
import { MemoryRepository } from '../../src/storage/memory-repository.ts';
import { MemoryService } from '../../src/memory/memory-service.ts';
import { RelevanceMatcher } from '../../src/memory/relevance-matcher.ts';
import { MemoryContextBuilder } from '../../src/memory/context-builder.ts';
import { HostMemoryAuthority } from '../../src/security/host-authority.ts';
import { computeCanonicalSha256 } from '../../src/memory/canonical-json.ts';
import type {
  ScopeIdentifier,
  CallerContext,
  MemoryExportBundle,
  MemoryExportItem
} from '../../src/domain/types.ts';
import {
  ValidationError,
  SecurityViolationError,
  MemoryScopeViolationError,
  MemoryConflictError,
  DatabaseError
} from '../../src/domain/errors.ts';

function setupTestEnvironment(options: { _testPostAuditHook?: () => void } = {}) {
  const db = new DatabaseManager(':memory:');
  const taskRepo = new TaskRepository(db);
  const auditRepo = new AuditRepository(db);
  const memoryRepo = new MemoryRepository(db);

  const scopeAlpha: ScopeIdentifier = { scopeType: 'WORKSPACE', scopeId: 'ws-alpha' };
  const scopeBeta: ScopeIdentifier = { scopeType: 'WORKSPACE', scopeId: 'ws-beta' };
  const scopeGlobal: ScopeIdentifier = { scopeType: 'GLOBAL', scopeId: 'default' };

  const identityProvider = {
    authenticate(credentials: unknown) {
      if (typeof credentials !== 'string') return null;
      if (credentials === 'token-admin-alpha') {
        return {
          principalId: 'admin-alpha',
          role: 'ADMIN' as const,
          permittedScopes: [scopeAlpha, scopeGlobal]
        };
      }
      if (credentials === 'token-readonly-alpha') {
        return {
          principalId: 'ro-alpha',
          role: 'VIEWER' as const,
          permittedScopes: [scopeAlpha]
        };
      }
      if (credentials === 'token-admin-beta') {
        return {
          principalId: 'admin-beta',
          role: 'ADMIN' as const,
          permittedScopes: [scopeBeta]
        };
      }
      return null;
    }
  };

  const hostAuthority = new HostMemoryAuthority({
    taskRepo,
    identityProvider
  });
  const authorizer = hostAuthority.authorizer;

  const memoryService = new MemoryService({
    memoryRepo,
    auditRepo,
    taskRepo,
    authorizer,
    hostAuthority,
    relevanceMatcher: new RelevanceMatcher(),
    contextBuilder: new MemoryContextBuilder(),
    _testPostAuditHook: options._testPostAuditHook
  });

  const adminAlpha = authorizer.authorizeUser({ credentials: 'token-admin-alpha', requestedScope: scopeAlpha });
  const readOnlyAlpha = authorizer.authorizeUser({ credentials: 'token-readonly-alpha', requestedScope: scopeAlpha });
  const adminBeta = authorizer.authorizeUser({ credentials: 'token-admin-beta', requestedScope: scopeBeta });

  return {
    db,
    taskRepo,
    auditRepo,
    memoryRepo,
    hostAuthority,
    authorizer,
    memoryService,
    scopeAlpha,
    scopeBeta,
    scopeGlobal,
    adminAlpha,
    readOnlyAlpha,
    adminBeta
  };
}

/**
 * Helper to construct a valid MemoryExportBundle with valid canonical SHA-256 checksum.
 */
function createValidBundle(
  items: MemoryExportItem[],
  overrides: Partial<MemoryExportBundle> = {}
): MemoryExportBundle {
  const { checksum: customChecksum, ...restOverrides } = overrides;

  const payload = {
    version: '1.0' as const,
    exportedAt: '2026-10-19T02:00:00.000Z',
    sourceScope: { scopeType: 'WORKSPACE' as const, scopeId: 'ws-external-source' },
    count: items.length,
    memories: items,
    ...restOverrides
  };

  const checksum = customChecksum ?? computeCanonicalSha256(payload);

  return {
    ...payload,
    checksum
  };
}

// ============================================================================
// 1. Authorization & Scope Derivation
// ============================================================================

test('importMemories - rejects unverified or forged caller context', () => {
  const env = setupTestEnvironment();
  const bundle = createValidBundle([]);

  const unverifiedCaller: CallerContext = {
    actor: 'USER',
    scope: env.scopeAlpha,
    permissions: ['WRITE']
  };

  assert.throws(
    () => env.memoryService.importMemories(unverifiedCaller, bundle),
    (err: unknown) => err instanceof SecurityViolationError && err.violationType === 'FORGED_CALLER_CONTEXT'
  );
});

test('importMemories - enforces WRITE permission on caller', () => {
  const env = setupTestEnvironment();
  const bundle = createValidBundle([]);

  assert.throws(
    () => env.memoryService.importMemories(env.readOnlyAlpha, bundle),
    (err: unknown) => err instanceof SecurityViolationError && err.violationType === 'INSUFFICIENT_PERMISSIONS'
  );
});

test('importMemories - rejects agent callers from directly importing memories', () => {
  const env = setupTestEnvironment();
  const bundle = createValidBundle([]);

  const agentTask = env.hostAuthority.createTask(env.taskRepo, {
    id: 'task-agent-import',
    goal: 'Agent attempting import',
    scope: env.scopeAlpha
  });
  const agentCaller = env.authorizer.authorizeAgent({ taskId: agentTask.id });

  assert.throws(
    () => env.memoryService.importMemories(agentCaller, bundle),
    (err: unknown) => err instanceof SecurityViolationError && err.violationType === 'AGENT_PROPOSAL_REQUIRED'
  );
});

test('importMemories - derives destination scope strictly from verified caller and ignores bundle.sourceScope', () => {
  const env = setupTestEnvironment();

  // Bundle sourceScope declared as 'ws-external-untrusted'
  const bundle = createValidBundle([
    {
      key: 'routed_fact',
      content: 'Scoped memory content',
      category: 'PROJECT_FACT',
      tags: ['scoped'],
      priority: 60,
      metadata: { env: 'prod' },
      status: 'ACTIVE',
      createdAt: '2026-10-19T00:00:00.000Z',
      updatedAt: '2026-10-19T00:00:00.000Z'
    }
  ], {
    sourceScope: { scopeType: 'WORKSPACE', scopeId: 'ws-external-untrusted' }
  });

  const result = env.memoryService.importMemories(env.adminAlpha, bundle);

  // Result targetScope must be caller's scope
  assert.deepEqual(result.targetScope, env.scopeAlpha);
  assert.equal(result.importedCount, 1);
  assert.equal(result.skippedCount, 0);
  assert.equal(result.overwrittenCount, 0);

  // Memory must exist in ws-alpha
  const inAlpha = env.memoryRepo.getMemoryByKey('routed_fact', env.scopeAlpha, 'ACTIVE');
  assert.ok(inAlpha, 'Memory must exist in caller scope (ws-alpha)');
  assert.equal(inAlpha.scopeType, 'WORKSPACE');
  assert.equal(inAlpha.scopeId, 'ws-alpha');
  assert.equal(inAlpha.content, 'Scoped memory content');

  // Memory must NOT exist in the bundle source scope
  const inExternal = env.memoryRepo.getMemoryByKey(
    'routed_fact',
    { scopeType: 'WORKSPACE', scopeId: 'ws-external-untrusted' },
    'ACTIVE'
  );
  assert.equal(inExternal, null, 'Memory must not exist in bundle source scope');
});

// ============================================================================
// 2. Pre-flight Validation & Tamper Resistance
// ============================================================================

test('importMemories - rejects invalid or tampered bundle checksum without database mutation', () => {
  const env = setupTestEnvironment();

  const validBundle = createValidBundle([
    {
      key: 'unadulterated_key',
      content: 'clean content',
      category: 'PROJECT_FACT',
      tags: [],
      priority: 50,
      metadata: {},
      status: 'ACTIVE',
      createdAt: '2026-10-19T00:00:00.000Z',
      updatedAt: '2026-10-19T00:00:00.000Z'
    }
  ]);

  // Tamper with payload without updating checksum
  const tamperedBundle: MemoryExportBundle = {
    ...validBundle,
    memories: [
      {
        ...validBundle.memories[0],
        content: 'tampered malicious content'
      }
    ]
  };

  assert.throws(
    () => env.memoryService.importMemories(env.adminAlpha, tamperedBundle),
    (err: unknown) => err instanceof ValidationError && err.message.includes('checksum verification failed')
  );

  // Zero records persisted
  const records = env.memoryRepo.listMemories({ scopeType: 'WORKSPACE', scopeId: 'ws-alpha' });
  assert.equal(records.length, 0);
});

test('importMemories - rejects malformed bundle structure, version, and count mismatches', () => {
  const env = setupTestEnvironment();

  // 1. Non-object bundle
  assert.throws(
    () => env.memoryService.importMemories(env.adminAlpha, null as unknown as MemoryExportBundle),
    (err: unknown) => err instanceof ValidationError && err.message.includes('MemoryExportBundle must be provided as an object')
  );

  // 2. Unsupported version
  const badVersionBundle = createValidBundle([]);
  (badVersionBundle as unknown as Record<string, unknown>).version = '2.0';
  assert.throws(
    () => env.memoryService.importMemories(env.adminAlpha, badVersionBundle),
    (err: unknown) => err instanceof ValidationError && err.message.includes('Unsupported bundle version')
  );

  // 3. Count mismatch
  const countMismatchBundle = createValidBundle([
    {
      key: 'mismatch_key',
      content: 'content',
      category: 'PROJECT_FACT',
      tags: [],
      priority: 50,
      metadata: {},
      status: 'ACTIVE',
      createdAt: '2026-10-19T00:00:00.000Z',
      updatedAt: '2026-10-19T00:00:00.000Z'
    }
  ]);
  // Deliberately corrupt count property
  (countMismatchBundle as unknown as Record<string, unknown>).count = 99;
  assert.throws(
    () => env.memoryService.importMemories(env.adminAlpha, countMismatchBundle),
    (err: unknown) => err instanceof ValidationError && err.message.includes('Bundle count mismatch')
  );
});

test('importMemories - rejects invalid item fields and PENDING_APPROVAL status', () => {
  const env = setupTestEnvironment();

  // 1. PENDING_APPROVAL rejected
  const proposalBundle = createValidBundle([
    {
      key: 'unapproved_proposal',
      content: 'draft content',
      category: 'PROJECT_FACT',
      tags: [],
      priority: 50,
      metadata: {},
      status: 'PENDING_APPROVAL',
      createdAt: '2026-10-19T00:00:00.000Z',
      updatedAt: '2026-10-19T00:00:00.000Z'
    }
  ]);

  assert.throws(
    () => env.memoryService.importMemories(env.adminAlpha, proposalBundle),
    (err: unknown) => err instanceof ValidationError && err.message.includes('PENDING_APPROVAL')
  );

  // 2. Empty key rejected
  const emptyKeyBundle = createValidBundle([
    {
      key: '',
      content: 'valid content',
      category: 'PROJECT_FACT',
      tags: [],
      priority: 50,
      metadata: {},
      status: 'ACTIVE',
      createdAt: '2026-10-19T00:00:00.000Z',
      updatedAt: '2026-10-19T00:00:00.000Z'
    }
  ]);

  assert.throws(
    () => env.memoryService.importMemories(env.adminAlpha, emptyKeyBundle),
    (err: unknown) => err instanceof ValidationError && err.message.includes('Memory key')
  );
});

test('importMemories - rejects duplicate active keys in bundle even across different categories', () => {
  const env = setupTestEnvironment();

  // Bundle contains two active entries with key 'shared_config_key', but different categories
  const duplicateBundle = createValidBundle([
    {
      key: 'shared_config_key',
      content: 'First entry as fact',
      category: 'PROJECT_FACT',
      tags: [],
      priority: 50,
      metadata: {},
      status: 'ACTIVE',
      createdAt: '2026-10-19T00:00:00.000Z',
      updatedAt: '2026-10-19T00:00:00.000Z'
    },
    {
      key: 'shared_config_key',
      content: 'Second entry as preference',
      category: 'USER_PREFERENCE',
      tags: [],
      priority: 80,
      metadata: {},
      status: 'ACTIVE',
      createdAt: '2026-10-19T00:00:01.000Z',
      updatedAt: '2026-10-19T00:00:01.000Z'
    }
  ]);

  assert.throws(
    () => env.memoryService.importMemories(env.adminAlpha, duplicateBundle),
    (err: unknown) =>
      err instanceof ValidationError &&
      err.message.includes("Bundle contains duplicate active memory key 'shared_config_key'")
  );

  // Assert zero records inserted
  const records = env.memoryRepo.listMemories({ scopeType: 'WORKSPACE', scopeId: 'ws-alpha' });
  assert.equal(records.length, 0);
});

// ============================================================================
// 3. Conflict Strategies: FAIL, SKIP, OVERWRITE
// ============================================================================

test('importMemories - conflict strategy FAIL aborts import and rolls back all entries', () => {
  const env = setupTestEnvironment();

  // Pre-existing active memory in ws-alpha
  env.memoryService.createMemory(env.adminAlpha, {
    key: 'existing_key',
    content: 'original content',
    category: 'PROJECT_FACT',
    scopeType: 'WORKSPACE',
    scopeId: 'ws-alpha'
  });

  // Incoming bundle has a new key followed by the conflicting key
  const bundle = createValidBundle([
    {
      key: 'fresh_key',
      content: 'fresh content',
      category: 'PROJECT_FACT',
      tags: [],
      priority: 50,
      metadata: {},
      status: 'ACTIVE',
      createdAt: '2026-10-19T00:00:00.000Z',
      updatedAt: '2026-10-19T00:00:00.000Z'
    },
    {
      key: 'existing_key',
      content: 'conflicting incoming content',
      category: 'PROJECT_FACT',
      tags: [],
      priority: 50,
      metadata: {},
      status: 'ACTIVE',
      createdAt: '2026-10-19T00:00:01.000Z',
      updatedAt: '2026-10-19T00:00:01.000Z'
    }
  ]);

  assert.throws(
    () => env.memoryService.importMemories(env.adminAlpha, bundle, { conflictStrategy: 'FAIL' }),
    (err: unknown) => err instanceof MemoryConflictError && err.key === 'existing_key'
  );

  // Transaction rollback guarantee: fresh_key must NOT be inserted!
  const freshMem = env.memoryRepo.getMemoryByKey('fresh_key', env.scopeAlpha, 'ACTIVE');
  assert.equal(freshMem, null, 'fresh_key must be rolled back on conflict');

  // Original existing memory must remain intact
  const existingMem = env.memoryRepo.getMemoryByKey('existing_key', env.scopeAlpha, 'ACTIVE');
  assert.ok(existingMem);
  assert.equal(existingMem.content, 'original content');
});

test('importMemories - conflict strategy SKIP skips existing active memories and imports non-conflicting ones', () => {
  const env = setupTestEnvironment();

  // Pre-existing active memory
  env.memoryService.createMemory(env.adminAlpha, {
    key: 'existing_conflict',
    content: 'original untouched content',
    category: 'PROJECT_FACT',
    scopeType: 'WORKSPACE',
    scopeId: 'ws-alpha'
  });

  const bundle = createValidBundle([
    {
      key: 'existing_conflict',
      content: 'incoming content that should be skipped',
      category: 'PROJECT_FACT',
      tags: ['skipped'],
      priority: 90,
      metadata: {},
      status: 'ACTIVE',
      createdAt: '2026-10-19T00:00:00.000Z',
      updatedAt: '2026-10-19T00:00:00.000Z'
    },
    {
      key: 'non_conflicting_item',
      content: 'imported brand new content',
      category: 'USER_PREFERENCE',
      tags: ['imported'],
      priority: 70,
      metadata: {},
      status: 'ACTIVE',
      createdAt: '2026-10-19T00:00:01.000Z',
      updatedAt: '2026-10-19T00:00:01.000Z'
    }
  ]);

  const result = env.memoryService.importMemories(env.adminAlpha, bundle, { conflictStrategy: 'SKIP' });

  assert.equal(result.totalInBundle, 2);
  assert.equal(result.importedCount, 1);
  assert.equal(result.skippedCount, 1);
  assert.equal(result.overwrittenCount, 0);

  // Conflicting memory was untouched
  const untouched = env.memoryRepo.getMemoryByKey('existing_conflict', env.scopeAlpha, 'ACTIVE');
  assert.ok(untouched);
  assert.equal(untouched.content, 'original untouched content');
  assert.equal(untouched.priority, 50);

  // Non-conflicting memory was imported
  const imported = env.memoryRepo.getMemoryByKey('non_conflicting_item', env.scopeAlpha, 'ACTIVE');
  assert.ok(imported);
  assert.equal(imported.content, 'imported brand new content');
});

test('importMemories - conflict strategy OVERWRITE archives existing active record and replaces tags/metadata without merging', () => {
  const env = setupTestEnvironment();

  // Pre-existing active memory with existing tags and metadata
  const original = env.memoryService.createMemory(env.adminAlpha, {
    key: 'replaceable_key',
    content: 'old original content',
    category: 'PROJECT_FACT',
    priority: 40,
    tags: ['old_tag1', 'old_tag2'],
    metadata: { existingFieldA: 'alpha', sharedField: 'old_val' },
    scopeType: 'WORKSPACE',
    scopeId: 'ws-alpha'
  });

  const bundle = createValidBundle([
    {
      key: 'replaceable_key',
      content: 'brand new replaced content',
      category: 'LEARNED_PROCEDURE',
      priority: 85,
      tags: ['new_tag_only'],
      metadata: { newFieldB: 'beta', sharedField: 'new_val' },
      status: 'ACTIVE',
      createdAt: '2026-10-19T00:00:00.000Z',
      updatedAt: '2026-10-19T00:00:00.000Z'
    }
  ]);

  const result = env.memoryService.importMemories(env.adminAlpha, bundle, { conflictStrategy: 'OVERWRITE' });

  assert.equal(result.totalInBundle, 1);
  assert.equal(result.importedCount, 0);
  assert.equal(result.overwrittenCount, 1);
  assert.equal(result.skippedCount, 0);

  // 1. Verify old record is preserved as ARCHIVED
  const oldRecord = env.memoryRepo.getMemoryById(original.id, env.scopeAlpha);
  assert.ok(oldRecord);
  assert.equal(oldRecord.status, 'ARCHIVED');
  assert.equal(oldRecord.content, 'old original content');
  assert.equal(oldRecord.category, 'PROJECT_FACT');
  assert.deepEqual(JSON.parse(oldRecord.tagsJson), ['old_tag1', 'old_tag2']);

  // 2. Verify new record is created as ACTIVE
  const newRecord = env.memoryRepo.getMemoryByKey('replaceable_key', env.scopeAlpha, 'ACTIVE');
  assert.ok(newRecord);
  assert.notEqual(newRecord.id, original.id, 'New active record must have distinct ID');
  assert.equal(newRecord.status, 'ACTIVE');
  assert.equal(newRecord.content, 'brand new replaced content');
  assert.equal(newRecord.category, 'LEARNED_PROCEDURE');
  assert.equal(newRecord.priority, 85);

  // 3. Mandatory guarantee: Tags and metadata must REPLACE, not merge!
  const newTags = JSON.parse(newRecord.tagsJson);
  assert.deepEqual(newTags, ['new_tag_only']);
  assert.equal(newTags.includes('old_tag1'), false, 'Old tags must not be merged');

  const newMetadata = JSON.parse(newRecord.metadataJson);
  assert.deepEqual(newMetadata, { newFieldB: 'beta', sharedField: 'new_val' });
  assert.equal('existingFieldA' in newMetadata, false, 'Old metadata fields must not be merged');
});

// ============================================================================
// 4. Atomicity & Rollback Guarantees
// ============================================================================

test('importMemories - guarantees full rollback when post-audit failure or exception occurs during transaction', () => {
  let shouldFail = false;
  let hookCalled = false;
  const env = setupTestEnvironment({
    _testPostAuditHook() {
      if (shouldFail) {
        hookCalled = true;
        throw new DatabaseError('Simulated unexpected crash right after audit append');
      }
    }
  });

  // Pre-existing active memory
  const original = env.memoryService.createMemory(env.adminAlpha, {
    key: 'crash_test_key',
    content: 'original unmutated',
    category: 'PROJECT_FACT',
    scopeType: 'WORKSPACE',
    scopeId: 'ws-alpha'
  });

  shouldFail = true;

  const bundle = createValidBundle([
    {
      key: 'crash_test_key',
      content: 'overwriting content that will fail',
      category: 'PROJECT_FACT',
      tags: [],
      priority: 99,
      metadata: {},
      status: 'ACTIVE',
      createdAt: '2026-10-19T00:00:00.000Z',
      updatedAt: '2026-10-19T00:00:00.000Z'
    },
    {
      key: 'brand_new_crash_item',
      content: 'fresh item',
      category: 'PROJECT_FACT',
      tags: [],
      priority: 50,
      metadata: {},
      status: 'ACTIVE',
      createdAt: '2026-10-19T00:00:01.000Z',
      updatedAt: '2026-10-19T00:00:01.000Z'
    }
  ]);

  assert.throws(
    () => env.memoryService.importMemories(env.adminAlpha, bundle, { conflictStrategy: 'OVERWRITE' }),
    (err: unknown) => err instanceof DatabaseError && err.message.includes('Simulated unexpected crash')
  );

  assert.equal(hookCalled, true);

  // Two-way atomic rollback guarantees:
  // 1. Original record remains ACTIVE (NOT archived)
  const restoredOriginal = env.memoryRepo.getMemoryById(original.id, env.scopeAlpha);
  assert.ok(restoredOriginal);
  assert.equal(restoredOriginal.status, 'ACTIVE');
  assert.equal(restoredOriginal.content, 'original unmutated');

  // 2. Brand new item was NOT persisted
  const brandNew = env.memoryRepo.getMemoryByKey('brand_new_crash_item', env.scopeAlpha, 'ACTIVE');
  assert.equal(brandNew, null);

  // 3. No MEMORIES_IMPORTED audit event remains
  const auditEvents = env.auditRepo.getEventsByTaskId('__system_memory__');
  const importAudit = auditEvents.find((e) => e.eventType === 'MEMORIES_IMPORTED');
  assert.equal(importAudit, undefined, 'MEMORIES_IMPORTED audit event must be rolled back');
});

// ============================================================================
// 5. Audit Privacy Guarantee
// ============================================================================

test('importMemories - audit privacy guarantee: records MEMORIES_IMPORTED with metadata only and zero key/content leakage', () => {
  const env = setupTestEnvironment();

  const secretContent = 'super_secret_master_password_99999_confidential';
  const secretKey = 'classified_key_name_secret';

  const bundle = createValidBundle([
    {
      key: secretKey,
      content: secretContent,
      category: 'PROJECT_FACT',
      tags: ['classified'],
      priority: 95,
      metadata: { secretField: 'secret_val' },
      status: 'ACTIVE',
      createdAt: '2026-10-19T00:00:00.000Z',
      updatedAt: '2026-10-19T00:00:00.000Z'
    }
  ]);

  const result = env.memoryService.importMemories(env.adminAlpha, bundle);
  assert.equal(result.importedCount, 1);
  assert.equal(result.skippedCount, 0);
  assert.equal(result.overwrittenCount, 0);
  assert.equal(result.totalInBundle, 1);
  assert.deepEqual(result.targetScope, env.scopeAlpha);

  // Guarantee: Public result must not contain memory keys or content
  assert.equal('importedKeys' in (result as unknown as Record<string, unknown>), false);
  assert.equal('skippedKeys' in (result as unknown as Record<string, unknown>), false);
  assert.equal('overwrittenKeys' in (result as unknown as Record<string, unknown>), false);
  assert.equal(JSON.stringify(result).includes(secretKey), false, 'Result must not contain memory key');
  assert.equal(JSON.stringify(result).includes(secretContent), false, 'Result must not contain memory content');

  const auditEvents = env.auditRepo.getEventsByTaskId('__system_memory__');
  const importEvent = auditEvents.find((e) => e.eventType === 'MEMORIES_IMPORTED');
  assert.ok(importEvent, 'Expected MEMORIES_IMPORTED audit event');

  const details = JSON.parse(importEvent.detailsJson);
  assert.equal(details.targetScopeType, 'WORKSPACE');
  assert.equal(details.targetScopeId, 'ws-alpha');
  assert.equal(details.totalInBundle, 1);
  assert.equal(details.importedCount, 1);
  assert.equal(details.skippedCount, 0);
  assert.equal(details.overwrittenCount, 0);
  assert.equal(details.conflictStrategy, 'FAIL');
  assert.equal(details.checksum, bundle.checksum);

  // Mandatory Privacy Guarantee:
  // 1. Audit event must NOT contain memory key
  assert.equal('key' in details, false);
  assert.equal('importedKeys' in details, false);
  assert.equal('skippedKeys' in details, false);
  assert.equal('overwrittenKeys' in details, false);
  assert.equal(importEvent.detailsJson.includes(secretKey), false, 'Audit event must not contain memory key');

  // 2. Audit event must NOT contain raw memory content or metadata values
  assert.equal(importEvent.detailsJson.includes(secretContent), false, 'Audit event must not contain memory content');
  assert.equal(importEvent.detailsJson.includes('secret_val'), false, 'Audit event must not contain metadata secrets');
});

test('importMemories - result privacy guarantee: public result does not expose memory keys or content across all conflict modes', () => {
  const env = setupTestEnvironment();

  // Create an existing active memory
  env.memoryService.createMemory(env.adminAlpha, {
    key: 'confidential_existing_key',
    content: 'confidential_existing_secret_123',
    category: 'PROJECT_FACT',
    scopeType: 'WORKSPACE',
    scopeId: 'ws-alpha'
  });

  const bundle = createValidBundle([
    {
      key: 'confidential_existing_key',
      content: 'confidential_new_secret_456',
      category: 'PROJECT_FACT',
      tags: [],
      priority: 50,
      metadata: {},
      status: 'ACTIVE',
      createdAt: '2026-10-19T00:00:00.000Z',
      updatedAt: '2026-10-19T00:00:00.000Z'
    },
    {
      key: 'confidential_brand_new_key',
      content: 'confidential_brand_new_secret_789',
      category: 'PROJECT_FACT',
      tags: [],
      priority: 50,
      metadata: {},
      status: 'ACTIVE',
      createdAt: '2026-10-19T00:00:01.000Z',
      updatedAt: '2026-10-19T00:00:01.000Z'
    }
  ]);

  // Test SKIP mode
  const skipResult = env.memoryService.importMemories(env.adminAlpha, bundle, { conflictStrategy: 'SKIP' });
  const skipJson = JSON.stringify(skipResult);
  assert.equal('importedKeys' in (skipResult as unknown as Record<string, unknown>), false);
  assert.equal('skippedKeys' in (skipResult as unknown as Record<string, unknown>), false);
  assert.equal('overwrittenKeys' in (skipResult as unknown as Record<string, unknown>), false);
  assert.equal(skipJson.includes('confidential'), false, 'Result must not leak keys or content');
  assert.equal(skipResult.importedCount, 1);
  assert.equal(skipResult.skippedCount, 1);
  assert.equal(skipResult.overwrittenCount, 0);

  // Test OVERWRITE mode on fresh env
  const env2 = setupTestEnvironment();
  env2.memoryService.createMemory(env2.adminAlpha, {
    key: 'confidential_existing_key',
    content: 'confidential_existing_secret_123',
    category: 'PROJECT_FACT',
    scopeType: 'WORKSPACE',
    scopeId: 'ws-alpha'
  });

  const overwriteResult = env2.memoryService.importMemories(env2.adminAlpha, bundle, { conflictStrategy: 'OVERWRITE' });
  const overwriteJson = JSON.stringify(overwriteResult);
  assert.equal('importedKeys' in (overwriteResult as unknown as Record<string, unknown>), false);
  assert.equal('skippedKeys' in (overwriteResult as unknown as Record<string, unknown>), false);
  assert.equal('overwrittenKeys' in (overwriteResult as unknown as Record<string, unknown>), false);
  assert.equal(overwriteJson.includes('confidential'), false, 'Result must not leak keys or content');
  assert.equal(overwriteResult.importedCount, 1);
  assert.equal(overwriteResult.skippedCount, 0);
  assert.equal(overwriteResult.overwrittenCount, 1);
});

