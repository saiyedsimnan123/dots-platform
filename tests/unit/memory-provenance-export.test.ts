/**
 * Next-Generation Dots AI Platform - Memory Provenance Inspection & Export Tests
 * Phase 7.5: Substep 1
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
import { verifyBundleChecksum } from '../../src/memory/canonical-json.ts';
import type {
  ScopeIdentifier,
  CallerContext,
  MemoryExportBundle
} from '../../src/domain/types.ts';
import {
  ValidationError,
  SecurityViolationError,
  MemoryScopeViolationError,
  MemoryNotFoundError
} from '../../src/domain/errors.ts';

function setupTestEnvironment() {
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
    contextBuilder: new MemoryContextBuilder()
  });

  // Callers
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

// ============================================================================
// Group 1: Memory Provenance Inspection (getMemoryUsageHistory)
// ============================================================================

test('getMemoryUsageHistory - requires READ permission on caller', () => {
  const env = setupTestEnvironment();

  // Create caller with only WRITE permission
  const writeOnlyCaller: CallerContext = {
    actor: 'USER',
    scope: env.scopeAlpha,
    permissions: new Set(['WRITE'])
  };

  // Forged/unverified caller fails authorization
  assert.throws(
    () => env.memoryService.getMemoryUsageHistory(writeOnlyCaller, 'any-id'),
    (err: unknown) => err instanceof SecurityViolationError
  );
});

test('getMemoryUsageHistory - validates memoryId input', () => {
  const env = setupTestEnvironment();

  assert.throws(
    () => env.memoryService.getMemoryUsageHistory(env.adminAlpha, ''),
    (err: unknown) => err instanceof ValidationError && err.message.includes('Memory ID must be a non-empty string')
  );
  assert.throws(
    () => env.memoryService.getMemoryUsageHistory(env.adminAlpha, '   '),
    (err: unknown) => err instanceof ValidationError && err.message.includes('Memory ID must be a non-empty string')
  );
});

test('getMemoryUsageHistory - throws MemoryNotFoundError for non-existent memory ID', () => {
  const env = setupTestEnvironment();

  assert.throws(
    () => env.memoryService.getMemoryUsageHistory(env.adminAlpha, 'non-existent-id'),
    (err: unknown) => err instanceof MemoryNotFoundError && err.memoryId === 'non-existent-id'
  );
});

test('getMemoryUsageHistory - blocks cross-scope access and records MEMORY_ACCESS_DENIED audit', () => {
  const env = setupTestEnvironment();

  // Create a memory in workspace Beta
  const memoryInBeta = env.memoryService.createMemory(env.adminBeta, {
    key: 'beta_secret',
    content: 'Beta secret content',
    category: 'PROJECT_FACT',
    scopeType: 'WORKSPACE',
    scopeId: 'ws-beta'
  });

  // Attempt to inspect usage from workspace Alpha caller
  assert.throws(
    () => env.memoryService.getMemoryUsageHistory(env.adminAlpha, memoryInBeta.id),
    (err: unknown) => err instanceof MemoryScopeViolationError
  );

  // Check that MEMORY_ACCESS_DENIED was audited
  const auditEvents = env.auditRepo.getEventsByTaskId('__system_memory__');
  const deniedEvent = auditEvents.find(
    (e) => e.eventType === 'MEMORY_ACCESS_DENIED' && e.detailsJson.includes('CROSS_SCOPE_READ_ATTEMPT')
  );
  assert.ok(deniedEvent, 'Expected CROSS_SCOPE_READ_ATTEMPT audit event to be recorded');
});

test('getMemoryUsageHistory - returns zero counts for memory with no injections', () => {
  const env = setupTestEnvironment();

  const memory = env.memoryService.createMemory(env.adminAlpha, {
    key: 'api_url',
    content: 'https://api.example.com',
    category: 'PROJECT_FACT',
    scopeType: 'WORKSPACE',
    scopeId: 'ws-alpha'
  });

  const history = env.memoryService.getMemoryUsageHistory(env.adminAlpha, memory.id);

  assert.equal(history.memoryId, memory.id);
  assert.deepEqual(history.scope, env.scopeAlpha);
  assert.equal(history.totalInjections, 0);
  assert.equal(history.totalChars, 0);
  assert.equal(history.totalEstimatedTokens, 0);
  assert.deepEqual(history.injections, []);
});

test('getMemoryUsageHistory - aggregates usage accurately across multiple task injections', () => {
  const env = setupTestEnvironment();

  const memory = env.memoryService.createMemory(env.adminAlpha, {
    key: 'coding_convention',
    content: 'Always use strict TypeScript types and explicit error handling.',
    category: 'LEARNED_PROCEDURE',
    scopeType: 'WORKSPACE',
    scopeId: 'ws-alpha'
  });

  // Create two tasks in ws-alpha
  const task1 = env.hostAuthority.createTask(env.taskRepo, {
    id: 'task-inj-1',
    goal: 'First task using memory',
    scope: env.scopeAlpha
  });
  const task2 = env.hostAuthority.createTask(env.taskRepo, {
    id: 'task-inj-2',
    goal: 'Second task using memory',
    scope: env.scopeAlpha
  });

  // Record injections
  env.memoryRepo.recordInjection({
    taskId: task1.id,
    memoryId: memory.id,
    charCount: 65,
    estimatedTokens: 18
  });

  env.memoryRepo.recordInjection({
    taskId: task2.id,
    memoryId: memory.id,
    charCount: 65,
    estimatedTokens: 18
  });

  const history = env.memoryService.getMemoryUsageHistory(env.readOnlyAlpha, memory.id);

  assert.equal(history.memoryId, memory.id);
  assert.deepEqual(history.scope, env.scopeAlpha);
  assert.equal(history.totalInjections, 2);
  assert.equal(history.totalChars, 130);
  assert.equal(history.totalEstimatedTokens, 36);
  assert.equal(history.injections.length, 2);
  assert.equal(history.injections[0].taskId, task1.id);
  assert.equal(history.injections[1].taskId, task2.id);

  // Check audit telemetry: must not leak memory key or content
  const auditEvents = env.auditRepo.getEventsByTaskId('__system_memory__');
  const retrievedEvent = auditEvents.find(
    (e) => e.eventType === 'MEMORY_RETRIEVED' && e.detailsJson.includes('getMemoryUsageHistory')
  );
  assert.ok(retrievedEvent, 'Expected MEMORY_RETRIEVED audit event for getMemoryUsageHistory');
  assert.equal(retrievedEvent.detailsJson.includes('coding_convention'), false, 'Audit event must not contain memory key');
  assert.equal(retrievedEvent.detailsJson.includes('Always use strict TypeScript types'), false, 'Audit event must not contain raw memory content');
});

test('getMemoryUsageHistory - audit privacy guarantee: does not expose memory key or raw content in audit event', () => {
  const env = setupTestEnvironment();

  const memory = env.memoryService.createMemory(env.adminAlpha, {
    key: 'confidential_server_key',
    content: 'confidential_internal_ip_10.0.0.42_sensitive_host',
    category: 'PROJECT_FACT',
    scopeType: 'WORKSPACE',
    scopeId: 'ws-alpha'
  });

  env.memoryService.getMemoryUsageHistory(env.readOnlyAlpha, memory.id);

  const auditEvents = env.auditRepo.getEventsByTaskId('__system_memory__');
  const retrievedEvent = auditEvents.find(
    (e) => e.eventType === 'MEMORY_RETRIEVED' && e.detailsJson.includes('getMemoryUsageHistory')
  );
  assert.ok(retrievedEvent, 'Expected MEMORY_RETRIEVED audit event for getMemoryUsageHistory');

  const details = JSON.parse(retrievedEvent.detailsJson);
  assert.equal(details.memoryId, memory.id);
  assert.equal(details.operation, 'getMemoryUsageHistory');
  assert.equal(details.scopeType, 'WORKSPACE');
  assert.equal(details.scopeId, 'ws-alpha');
  assert.equal(details.totalInjections, 0);

  // Guarantee: Zero memory key and zero raw content leakage in audit event
  assert.equal('key' in details, false, 'Audit event must not contain memory key');
  assert.equal(retrievedEvent.detailsJson.includes('confidential_server_key'), false);
  assert.equal(retrievedEvent.detailsJson.includes('confidential_internal_ip'), false);
});

// ============================================================================
// Group 2: Memory Export (exportMemories)
// ============================================================================

test('exportMemories - rejects unverified or unauthorized caller', () => {
  const env = setupTestEnvironment();

  const unverifiedCaller: CallerContext = {
    actor: 'USER',
    scope: env.scopeAlpha,
    permissions: ['READ']
  };

  assert.throws(
    () => env.memoryService.exportMemories(unverifiedCaller),
    (err: unknown) => err instanceof SecurityViolationError
  );
});

test('exportMemories - enforces caller READ permission', () => {
  const env = setupTestEnvironment();

  const writeOnly = {
    ...env.adminAlpha,
    permissions: new Set(['WRITE'])
  };

  const origVerify = env.authorizer.verify.bind(env.authorizer);
  env.authorizer.verify = (c: unknown) => {
    if (c === writeOnly) {
      return writeOnly as unknown as CallerContext;
    }
    return origVerify(c);
  };

  try {
    assert.throws(
      () => env.memoryService.exportMemories(writeOnly as unknown as CallerContext),
      (err: unknown) => err instanceof SecurityViolationError && err.violationType === 'INSUFFICIENT_PERMISSIONS'
    );
  } finally {
    env.authorizer.verify = origVerify;
  }
});

test('exportMemories - blocks scope spoofing in options and logs MEMORY_ACCESS_DENIED', () => {
  const env = setupTestEnvironment();

  assert.throws(
    () => env.memoryService.exportMemories(env.adminAlpha, {
      scopeType: 'WORKSPACE',
      scopeId: 'ws-beta' // Attempting to export beta memories while authenticated as alpha
    }),
    (err: unknown) => err instanceof MemoryScopeViolationError
  );

  const auditEvents = env.auditRepo.getEventsByTaskId('__system_memory__');
  const deniedEvent = auditEvents.find(
    (e) => e.eventType === 'MEMORY_ACCESS_DENIED' && e.detailsJson.includes('SCOPE_FORGERY_ATTEMPT')
  );
  assert.ok(deniedEvent, 'Expected SCOPE_FORGERY_ATTEMPT audit event');
});

test('exportMemories - succeeds when matching scope is explicitly passed in options', () => {
  const env = setupTestEnvironment();

  const bundle = env.memoryService.exportMemories(env.adminAlpha, {
    scopeType: 'WORKSPACE',
    scopeId: 'ws-alpha'
  });

  assert.equal(bundle.version, '1.0');
  assert.deepEqual(bundle.sourceScope, env.scopeAlpha);
  assert.equal(bundle.count, 0);
  assert.deepEqual(bundle.memories, []);
});

test('exportMemories - scope isolation: exports only memories within caller scope', () => {
  const env = setupTestEnvironment();

  // Create memories in ws-alpha
  env.memoryService.createMemory(env.adminAlpha, {
    key: 'alpha_key_1',
    content: 'alpha content 1',
    category: 'PROJECT_FACT',
    scopeType: 'WORKSPACE',
    scopeId: 'ws-alpha'
  });
  env.memoryService.createMemory(env.adminAlpha, {
    key: 'alpha_key_2',
    content: 'alpha content 2',
    category: 'USER_PREFERENCE',
    scopeType: 'WORKSPACE',
    scopeId: 'ws-alpha'
  });

  // Create memory in ws-beta
  env.memoryService.createMemory(env.adminBeta, {
    key: 'beta_key_1',
    content: 'beta content 1',
    category: 'PROJECT_FACT',
    scopeType: 'WORKSPACE',
    scopeId: 'ws-beta'
  });

  // Export ws-alpha
  const bundle = env.memoryService.exportMemories(env.adminAlpha);

  assert.equal(bundle.count, 2);
  assert.equal(bundle.memories.length, 2);
  assert.equal(bundle.memories.every((m) => m.key.startsWith('alpha_')), true);
  assert.equal(bundle.memories.some((m) => m.key.includes('beta')), false);
});

test('exportMemories - preserves content losslessly byte-for-byte (zero secret scrubbing on backup exports)', () => {
  const env = setupTestEnvironment();

  // Sensitive content containing API keys, Bearer tokens, private key blocks, and special formatting
  const rawSensitiveContent = [
    'AI_KEY=AIzaSyA_DeterministicTestKey1234567890',
    'SECRET_TOKEN=sk-proj-abc1234567890abcdef1234567890',
    'BEARER=Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9',
    '-----BEGIN PRIVATE KEY-----',
    'MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC6',
    '-----END PRIVATE KEY-----',
    'Unicode: é, €, 日本語, 🚀',
    'Whitespace: \t and \n newlines and   multiple spaces'
  ].join('\n');

  env.memoryService.createMemory(env.adminAlpha, {
    key: 'sensitive_backup_fact',
    content: rawSensitiveContent,
    category: 'PROJECT_FACT',
    scopeType: 'WORKSPACE',
    scopeId: 'ws-alpha'
  });

  const bundle = env.memoryService.exportMemories(env.readOnlyAlpha);

  assert.equal(bundle.count, 1);
  const exportedItem = bundle.memories[0];

  // Mandate: Zero secret scrubbing on backup export content. Must be byte-for-byte exact.
  assert.equal(exportedItem.content, rawSensitiveContent);
  assert.equal(exportedItem.content.includes('[REDACTED]'), false);
  assert.equal(exportedItem.content.includes('AIzaSyA_DeterministicTestKey1234567890'), true);
  assert.equal(exportedItem.content.includes('sk-proj-abc1234567890abcdef1234567890'), true);
});

test('exportMemories - bundle portability: excludes internal UUIDs, parses tags/metadata, valid checksum', () => {
  const env = setupTestEnvironment();

  const created = env.memoryService.createMemory(env.adminAlpha, {
    key: 'portable_item',
    content: 'Portability check',
    category: 'LEARNED_PROCEDURE',
    tags: ['migration', 'portable'],
    priority: 75,
    metadata: { version: '2.1', author: 'admin' },
    scopeType: 'WORKSPACE',
    scopeId: 'ws-alpha'
  });

  const bundle = env.memoryService.exportMemories(env.adminAlpha);

  assert.equal(bundle.version, '1.0');
  assert.equal(typeof bundle.exportedAt, 'string');
  assert.deepEqual(bundle.sourceScope, env.scopeAlpha);
  assert.equal(bundle.count, 1);

  const item = bundle.memories[0];
  // Internal UUID (item.id) MUST NOT exist in portable export item
  assert.equal('id' in item, false);
  assert.equal(item.key, 'portable_item');
  assert.equal(item.content, 'Portability check');
  assert.equal(item.category, 'LEARNED_PROCEDURE');
  assert.deepEqual(item.tags, ['migration', 'portable']);
  assert.equal(item.priority, 75);
  assert.deepEqual(item.metadata, { version: '2.1', author: 'admin' });
  assert.equal(item.status, 'ACTIVE');
  assert.equal(item.createdAt, created.createdAt);
  assert.equal(item.updatedAt, created.updatedAt);

  // SHA-256 checksum verification
  assert.equal(verifyBundleChecksum(bundle), true);
});

test('exportMemories - sorts items deterministically by (category ASC, key ASC, createdAt ASC)', () => {
  const env = setupTestEnvironment();

  // Create items in deliberately scrambled order
  env.memoryService.createMemory(env.adminAlpha, {
    key: 'z_preference',
    content: 'content z',
    category: 'USER_PREFERENCE',
    scopeType: 'WORKSPACE',
    scopeId: 'ws-alpha'
  });
  env.memoryService.createMemory(env.adminAlpha, {
    key: 'a_procedure',
    content: 'content a proc',
    category: 'LEARNED_PROCEDURE',
    scopeType: 'WORKSPACE',
    scopeId: 'ws-alpha'
  });
  env.memoryService.createMemory(env.adminAlpha, {
    key: 'm_fact',
    content: 'content m fact',
    category: 'PROJECT_FACT',
    scopeType: 'WORKSPACE',
    scopeId: 'ws-alpha'
  });
  env.memoryService.createMemory(env.adminAlpha, {
    key: 'a_preference',
    content: 'content a pref',
    category: 'USER_PREFERENCE',
    scopeType: 'WORKSPACE',
    scopeId: 'ws-alpha'
  });

  const bundle = env.memoryService.exportMemories(env.adminAlpha);

  assert.equal(bundle.count, 4);

  // Categories alphabetically: LEARNED_PROCEDURE, PROJECT_FACT, USER_PREFERENCE
  assert.equal(bundle.memories[0].category, 'LEARNED_PROCEDURE');
  assert.equal(bundle.memories[0].key, 'a_procedure');

  assert.equal(bundle.memories[1].category, 'PROJECT_FACT');
  assert.equal(bundle.memories[1].key, 'm_fact');

  assert.equal(bundle.memories[2].category, 'USER_PREFERENCE');
  assert.equal(bundle.memories[2].key, 'a_preference');

  assert.equal(bundle.memories[3].category, 'USER_PREFERENCE');
  assert.equal(bundle.memories[3].key, 'z_preference');
});

test('exportMemories - filtering: active by default, includes archived only on request, never includes proposals', () => {
  const env = setupTestEnvironment();

  // 1. Active memory
  env.memoryService.createMemory(env.adminAlpha, {
    key: 'active_fact',
    content: 'active fact content',
    category: 'PROJECT_FACT',
    scopeType: 'WORKSPACE',
    scopeId: 'ws-alpha'
  });

  // 2. Archived memory
  const archived = env.memoryService.createMemory(env.adminAlpha, {
    key: 'archived_fact',
    content: 'archived fact content',
    category: 'PROJECT_FACT',
    scopeType: 'WORKSPACE',
    scopeId: 'ws-alpha'
  });
  env.memoryService.archiveMemory(env.adminAlpha, archived.id);

  // 3. Agent proposal (PENDING_APPROVAL)
  const agentTask = env.hostAuthority.createTask(env.taskRepo, {
    id: 'task-agent-proposal',
    goal: 'Propose memory as agent',
    scope: env.scopeAlpha
  });
  const agentCaller = env.authorizer.authorizeAgent({
    taskId: agentTask.id
  });
  env.memoryService.createMemory(agentCaller, {
    key: 'pending_proposal_fact',
    content: 'unapproved agent proposal content',
    category: 'PROJECT_FACT',
    scopeType: 'WORKSPACE',
    scopeId: 'ws-alpha'
  });

  // Default export: only ACTIVE
  const defaultBundle = env.memoryService.exportMemories(env.adminAlpha);
  assert.equal(defaultBundle.count, 1);
  assert.equal(defaultBundle.memories[0].key, 'active_fact');

  // Export with includeArchived: true: includes ACTIVE and ARCHIVED, but NOT PENDING_APPROVAL
  const withArchivedBundle = env.memoryService.exportMemories(env.adminAlpha, {
    includeArchived: true
  });
  assert.equal(withArchivedBundle.count, 2);
  const keys = withArchivedBundle.memories.map((m) => m.key);
  assert.ok(keys.includes('active_fact'));
  assert.ok(keys.includes('archived_fact'));
  assert.equal(keys.includes('pending_proposal_fact'), false, 'Proposals must never be exported');

  // Filter by category
  env.memoryService.createMemory(env.adminAlpha, {
    key: 'user_pref_item',
    content: 'preference content',
    category: 'USER_PREFERENCE',
    scopeType: 'WORKSPACE',
    scopeId: 'ws-alpha'
  });

  const categoryBundle = env.memoryService.exportMemories(env.adminAlpha, {
    category: 'USER_PREFERENCE'
  });
  assert.equal(categoryBundle.count, 1);
  assert.equal(categoryBundle.memories[0].key, 'user_pref_item');
});

test('exportMemories - audit privacy guarantee: records MEMORY_EXPORTED without leaking memory content or secrets', () => {
  const env = setupTestEnvironment();

  env.memoryService.createMemory(env.adminAlpha, {
    key: 'super_secret_key',
    content: 'super_secret_password_12345_do_not_leak',
    category: 'PROJECT_FACT',
    scopeType: 'WORKSPACE',
    scopeId: 'ws-alpha'
  });

  const bundle = env.memoryService.exportMemories(env.adminAlpha);

  const auditEvents = env.auditRepo.getEventsByTaskId('__system_memory__');
  const exportEvent = auditEvents.find((e) => e.eventType === 'MEMORY_EXPORTED');
  assert.ok(exportEvent, 'Expected MEMORY_EXPORTED audit event');

  const details = JSON.parse(exportEvent.detailsJson);
  assert.equal(details.scopeType, 'WORKSPACE');
  assert.equal(details.scopeId, 'ws-alpha');
  assert.equal(details.exportedCount, 1);
  assert.equal(details.checksum, bundle.checksum);

  // Guarantee: Zero raw memory content, zero memory keys, zero secrets in audit log
  assert.equal(exportEvent.detailsJson.includes('super_secret_password'), false);
  assert.equal(exportEvent.detailsJson.includes('super_secret_key'), false);
  assert.equal(exportEvent.detailsJson.includes('do_not_leak'), false);
});

test('exportMemories - strictly read-only regarding database records', () => {
  const env = setupTestEnvironment();

  const mem = env.memoryService.createMemory(env.adminAlpha, {
    key: 'readonly_test_key',
    content: 'readonly test content',
    category: 'PROJECT_FACT',
    scopeType: 'WORKSPACE',
    scopeId: 'ws-alpha'
  });

  // Query memory before export
  const memBefore = env.memoryRepo.getMemoryById(mem.id, env.scopeAlpha);
  assert.ok(memBefore);

  // Export
  env.memoryService.exportMemories(env.adminAlpha);

  // Query memory after export
  const memAfter = env.memoryRepo.getMemoryById(mem.id, env.scopeAlpha);
  assert.ok(memAfter);

  // No mutation on memory record
  assert.equal(memBefore.updatedAt, memAfter.updatedAt);
  assert.equal(memBefore.accessCount, memAfter.accessCount);
  assert.equal(memBefore.lastAccessedAt, memAfter.lastAccessedAt);
  assert.equal(memBefore.content, memAfter.content);
});
