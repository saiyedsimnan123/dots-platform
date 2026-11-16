/**
 * Next-Generation Dots AI Platform - Import & Model Revision Backfill Lifecycle Tests
 * Phase 4C.6D: Import Automation & Model Revision Backfill
 * 
 * Verifies all 13 requirements from the Phase 4C.6D specification:
 * 
 * Import:
 * 1. Imported ACTIVE memories enqueue embedding jobs.
 * 2. Imported pending proposals do not enqueue jobs.
 * 3. Archived imported memories do not enqueue jobs.
 * 4. Import and job insertion roll back together.
 * 5. Overwrite imports do not leave stale embeddings.
 * 6. Old jobs cannot regenerate vectors for replaced memories.
 * 7. Imported metadata cannot forge relational ownership.
 * 8. Workspace imports cannot enqueue global-memory jobs.
 * 
 * Model revision backfill:
 * 9. Missing vectors for a new revision are identified correctly.
 * 10. Backfill generates embeddings for new revision without overwriting other revisions.
 * 11. Bounded batching and resumption/progress reporting.
 * 12. Isolation: cross-workspace memories cannot be backfilled.
 * 13. Retrieval uses correct revision and falls back if revision missing.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseManager } from '../../src/storage/db.ts';
import { MemoryRepository } from '../../src/storage/memory-repository.ts';
import { MemoryEmbeddingRepository } from '../../src/storage/memory-embedding-repository.ts';
import { EmbeddingJobRepository } from '../../src/storage/embedding-job-repository.ts';
import { EmbeddingLifecycleManager } from '../../src/memory/embedding-lifecycle-manager.ts';
import { MemoryService } from '../../src/memory/memory-service.ts';
import { TaskRepository } from '../../src/storage/task-repository.ts';
import { AuditRepository } from '../../src/storage/audit-repository.ts';
import { RelevanceMatcher } from '../../src/memory/relevance-matcher.ts';
import { MemoryContextBuilder } from '../../src/memory/context-builder.ts';
import { HostMemoryAuthority } from '../../src/security/host-authority.ts';
import type { TrustedIdentityProvider, AuthenticatedPrincipal } from '../../src/security/memory-authorizer.ts';
import { DeterministicMockEmbeddingProvider } from '../../src/memory/mock-embedding-provider.ts';
import type { IEmbeddingProvider } from '../../src/memory/embedding-types.ts';
import type { ScopeIdentifier, MemoryExportBundle, MemoryExportItem } from '../../src/domain/types.ts';
import { MemoryScopeViolationError, ValidationError } from '../../src/domain/errors.ts';
import { computeCanonicalSha256 } from '../../src/memory/canonical-json.ts';

function createValidBundle(
  items: MemoryExportItem[],
  overrides: Partial<MemoryExportBundle> = {}
): MemoryExportBundle {
  const { checksum: customChecksum, ...restOverrides } = overrides;

  const payload = {
    version: '1.0' as const,
    exportedAt: '2026-11-16T12:00:00.000Z',
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

function setupTestEnvironment() {
  const db = new DatabaseManager(':memory:');
  const taskRepo = new TaskRepository(db);
  const auditRepo = new AuditRepository(db);
  const memoryRepo = new MemoryRepository(db);
  const embeddingRepo = new MemoryEmbeddingRepository(db);
  const embeddingJobRepo = new EmbeddingJobRepository(db);
  const mockProvider = new DeterministicMockEmbeddingProvider({ dimensions: 384 });

  const workspaceA: ScopeIdentifier = { scopeType: 'WORKSPACE', scopeId: 'ws-alpha' };
  const workspaceB: ScopeIdentifier = { scopeType: 'WORKSPACE', scopeId: 'ws-beta' };
  const globalScope: ScopeIdentifier = { scopeType: 'GLOBAL', scopeId: 'default' };

  const identityProvider: TrustedIdentityProvider = {
    authenticate(credentials: unknown): AuthenticatedPrincipal | null {
      if (typeof credentials !== 'string') return null;
      if (credentials === 'token-admin-alpha') {
        return {
          principalId: 'user-alpha',
          role: 'ADMIN',
          permittedScopes: [workspaceA]
        };
      }
      if (credentials === 'token-admin-beta') {
        return {
          principalId: 'user-beta',
          role: 'ADMIN',
          permittedScopes: [workspaceB]
        };
      }
      if (credentials === 'token-global-admin') {
        return {
          principalId: 'user-global-admin',
          role: 'ADMIN',
          permittedScopes: [globalScope, workspaceA, workspaceB]
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

  const relevanceMatcher = new RelevanceMatcher();
  const contextBuilder = new MemoryContextBuilder({ matcher: relevanceMatcher });

  const lifecycleManager = new EmbeddingLifecycleManager({
    db,
    jobRepo: embeddingJobRepo,
    memoryRepo,
    embeddingRepo,
    provider: mockProvider,
    auditRepo,
    pollIntervalMs: 100,
    baseRetryDelayMs: 50,
    maxRetryDelayMs: 500,
    maxAttempts: 3,
    autoStart: false
  });

  const memoryService = new MemoryService({
    memoryRepo,
    embeddingRepo,
    embeddingProvider: mockProvider,
    embeddingJobRepo,
    lifecycleManager,
    auditRepo,
    taskRepo,
    authorizer,
    hostAuthority,
    relevanceMatcher,
    contextBuilder
  });

  return {
    db,
    taskRepo,
    auditRepo,
    memoryRepo,
    embeddingRepo,
    embeddingJobRepo,
    lifecycleManager,
    mockProvider,
    authorizer,
    hostAuthority,
    memoryService,
    workspaceA,
    workspaceB,
    globalScope
  };
}

// ============================================================================
// Group 1: Import Embedding Automation
// ============================================================================

test('1. Imported ACTIVE memories enqueue embedding jobs', () => {
  const env = setupTestEnvironment();
  const caller = env.authorizer.authorizeUser({
    credentials: 'token-admin-alpha',
    requestedScope: env.workspaceA
  });

  const items: MemoryExportItem[] = [
    {
      category: 'PROJECT_FACT',
      key: 'import.fact.1',
      content: 'Imported fact number one',
      status: 'ACTIVE',
      priority: 60,
      tags: ['import', 'alpha'],
      metadata: { source: 'backup' },
      createdAt: '2026-11-16T10:00:00.000Z',
      updatedAt: '2026-11-16T10:00:00.000Z'
    },
    {
      category: 'LEARNED_PROCEDURE',
      key: 'import.proc.2',
      content: 'Imported procedure number two',
      status: 'ACTIVE',
      priority: 80,
      tags: ['import'],
      metadata: {},
      createdAt: '2026-11-16T10:05:00.000Z',
      updatedAt: '2026-11-16T10:05:00.000Z'
    }
  ];

  const bundle = createValidBundle(items);
  const result = env.memoryService.importMemories(caller, bundle);

  assert.equal(result.importedCount, 2);

  // Verify memories exist in memories table
  const mem1 = env.memoryRepo.getMemoryByKey('import.fact.1', env.workspaceA);
  const mem2 = env.memoryRepo.getMemoryByKey('import.proc.2', env.workspaceA);
  assert.ok(mem1);
  assert.ok(mem2);

  // Verify embedding jobs were enqueued for both active memories
  const jobs = env.embeddingJobRepo.listJobs({ status: 'PENDING' });
  assert.equal(jobs.length, 2);

  const job1 = jobs.find((j) => j.memoryId === mem1.id);
  const job2 = jobs.find((j) => j.memoryId === mem2.id);
  assert.ok(job1);
  assert.ok(job2);
  assert.equal(job1.scopeType, env.workspaceA.scopeType);
  assert.equal(job1.scopeId, env.workspaceA.scopeId);
  assert.equal(job2.scopeType, env.workspaceA.scopeType);
  assert.equal(job2.scopeId, env.workspaceA.scopeId);
});

test('2. Imported pending proposals do not enqueue jobs', () => {
  const env = setupTestEnvironment();
  const caller = env.authorizer.authorizeUser({
    credentials: 'token-admin-alpha',
    requestedScope: env.workspaceA
  });

  const items: MemoryExportItem[] = [
    {
      category: 'PROJECT_FACT',
      key: 'unapproved.proposal',
      content: 'Should be rejected by import validation',
      status: 'PENDING_APPROVAL' as any,
      priority: 50,
      tags: [],
      metadata: {},
      createdAt: '2026-11-16T10:00:00.000Z',
      updatedAt: '2026-11-16T10:00:00.000Z'
    }
  ];

  const bundle = createValidBundle(items);

  // Importing PENDING_APPROVAL must be rejected by validator
  assert.throws(
    () => {
      env.memoryService.importMemories(caller, bundle);
    },
    (err: any) => err instanceof ValidationError && /PENDING_APPROVAL/.test(err.message)
  );

  // No jobs must be enqueued
  assert.equal(env.embeddingJobRepo.countJobs(), 0);
});

test('3. Archived imported memories do not enqueue jobs', () => {
  const env = setupTestEnvironment();
  const caller = env.authorizer.authorizeUser({
    credentials: 'token-admin-alpha',
    requestedScope: env.workspaceA
  });

  const items: MemoryExportItem[] = [
    {
      category: 'PROJECT_FACT',
      key: 'active.memory',
      content: 'This memory is active and should get a job',
      status: 'ACTIVE',
      priority: 50,
      tags: [],
      metadata: {},
      createdAt: '2026-11-16T10:00:00.000Z',
      updatedAt: '2026-11-16T10:00:00.000Z'
    },
    {
      category: 'PROJECT_FACT',
      key: 'archived.memory',
      content: 'This memory is archived and must NOT get a job',
      status: 'ARCHIVED',
      priority: 50,
      tags: [],
      metadata: {},
      createdAt: '2026-11-16T10:00:00.000Z',
      updatedAt: '2026-11-16T10:00:00.000Z'
    }
  ];

  const bundle = createValidBundle(items);
  const result = env.memoryService.importMemories(caller, bundle);
  assert.equal(result.importedCount, 2);

  const activeMem = env.memoryRepo.getMemoryByKey('active.memory', env.workspaceA, 'ACTIVE');
  const archivedMem = env.memoryRepo.getMemoryByKey('archived.memory', env.workspaceA, 'ARCHIVED');
  assert.ok(activeMem);
  assert.ok(archivedMem);

  // Active memory MUST have a job
  const activeJobs = env.embeddingJobRepo.listJobs({ memoryId: activeMem.id });
  assert.equal(activeJobs.length, 1);
  assert.equal(activeJobs[0].status, 'PENDING');

  // Archived memory MUST NOT have a job
  const archivedJobs = env.embeddingJobRepo.listJobs({ memoryId: archivedMem.id });
  assert.equal(archivedJobs.length, 0);
});

test('4. Import and job insertion roll back together', () => {
  const env = setupTestEnvironment();
  const caller = env.authorizer.authorizeUser({
    credentials: 'token-admin-alpha',
    requestedScope: env.workspaceA
  });

  const items: MemoryExportItem[] = [
    {
      category: 'PROJECT_FACT',
      key: 'rollback.import.1',
      content: 'Should be rolled back item 1',
      status: 'ACTIVE',
      priority: 50,
      tags: [],
      metadata: {},
      createdAt: '2026-11-16T10:00:00.000Z',
      updatedAt: '2026-11-16T10:00:00.000Z'
    },
    {
      category: 'PROJECT_FACT',
      key: 'rollback.import.2',
      content: 'Should be rolled back item 2',
      status: 'ACTIVE',
      priority: 50,
      tags: [],
      metadata: {},
      createdAt: '2026-11-16T10:00:00.000Z',
      updatedAt: '2026-11-16T10:00:00.000Z'
    }
  ];

  const bundle = createValidBundle(items);

  // Inject failure during second job enqueue
  let callCount = 0;
  const originalEnqueue = env.embeddingJobRepo.enqueueJob.bind(env.embeddingJobRepo);
  env.embeddingJobRepo.enqueueJob = (input) => {
    callCount++;
    if (callCount === 2) {
      throw new Error('Simulated SQLite failure on second import job enqueue');
    }
    return originalEnqueue(input);
  };

  assert.throws(
    () => {
      env.memoryService.importMemories(caller, bundle);
    },
    { message: /Simulated SQLite failure on second import job enqueue/ }
  );

  // Restore
  env.embeddingJobRepo.enqueueJob = originalEnqueue;

  // Complete rollback verification: neither memory must exist
  const mem1 = env.memoryRepo.getMemoryByKey('rollback.import.1', env.workspaceA);
  const mem2 = env.memoryRepo.getMemoryByKey('rollback.import.2', env.workspaceA);
  assert.equal(mem1, null, 'Memory 1 must be rolled back');
  assert.equal(mem2, null, 'Memory 2 must be rolled back');

  // No jobs must exist
  assert.equal(env.embeddingJobRepo.countJobs(), 0, 'All jobs must be rolled back');

  // No audit events must exist
  const auditRows = env.db.prepare("SELECT * FROM audit_events WHERE event_type = 'MEMORIES_IMPORTED'").all();
  assert.equal(auditRows.length, 0, 'Audit event must be rolled back');
});

test('5. Overwrite imports do not leave stale embeddings', async () => {
  const env = setupTestEnvironment();
  const caller = env.authorizer.authorizeUser({
    credentials: 'token-admin-alpha',
    requestedScope: env.workspaceA
  });

  // 1. Create initial active memory
  const initialMem = env.memoryService.createMemory(caller, {
    category: 'PROJECT_FACT',
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    key: 'project.spec',
    content: 'Original Specification Version 1.0'
  });

  // Process job to persist embedding
  await env.lifecycleManager.processPendingJobs();
  const oldEmbedding = env.embeddingRepo.getEmbedding(initialMem.id, env.mockProvider.modelId);
  assert.ok(oldEmbedding, 'Initial embedding must exist');

  // 2. Overwrite via import
  const items: MemoryExportItem[] = [
    {
      category: 'PROJECT_FACT',
      key: 'project.spec',
      content: 'Overwritten Specification Version 2.0 with breaking changes',
      status: 'ACTIVE',
      priority: 90,
      tags: ['v2'],
      metadata: {},
      createdAt: '2026-11-16T12:00:00.000Z',
      updatedAt: '2026-11-16T12:00:00.000Z'
    }
  ];

  const bundle = createValidBundle(items);
  const result = env.memoryService.importMemories(caller, bundle, { conflictStrategy: 'OVERWRITE' });
  assert.equal(result.overwrittenCount, 1);

  // 3. Verify old memory is archived and its embedding was removed
  const archivedOld = env.memoryRepo.getMemoryById(initialMem.id, env.workspaceA);
  assert.equal(archivedOld?.status, 'ARCHIVED');
  const deletedOldEmbedding = env.embeddingRepo.getEmbedding(initialMem.id, env.mockProvider.modelId);
  assert.equal(deletedOldEmbedding, null, 'Old embedding must be deleted on overwrite');

  // 4. Verify new memory is ACTIVE and has a new PENDING job
  const newMem = env.memoryRepo.getMemoryByKey('project.spec', env.workspaceA, 'ACTIVE');
  assert.ok(newMem);
  assert.notEqual(newMem.id, initialMem.id);
  assert.equal(newMem.content, 'Overwritten Specification Version 2.0 with breaking changes');

  const newJobs = env.embeddingJobRepo.listJobs({ memoryId: newMem.id });
  assert.equal(newJobs.length, 1);
  assert.equal(newJobs[0].status, 'PENDING');
});

test('6. Old jobs cannot regenerate vectors for replaced memories', async () => {
  const env = setupTestEnvironment();
  const caller = env.authorizer.authorizeUser({
    credentials: 'token-admin-alpha',
    requestedScope: env.workspaceA
  });

  const initialMem = env.memoryService.createMemory(caller, {
    category: 'PROJECT_FACT',
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    key: 'concurrent.replaced',
    content: 'Initial content to be replaced while job is in-flight'
  });

  // Provider that triggers an overwrite import while the first job is mid-inference
  let didOverwrite = false;
  const concurrentProvider: IEmbeddingProvider = {
    name: 'concurrent-overwrite-mock',
    modelId: env.mockProvider.modelId,
    dimensions: 384,
    async isAvailable() { return true; },
    async embed() {
      if (!didOverwrite) {
        didOverwrite = true;
        const items: MemoryExportItem[] = [
          {
            category: 'PROJECT_FACT',
            key: 'concurrent.replaced',
            content: 'Replacement content from import',
            status: 'ACTIVE',
            priority: 50,
            tags: [],
            metadata: {},
            createdAt: '2026-11-16T12:00:00.000Z',
            updatedAt: '2026-11-16T12:00:00.000Z'
          }
        ];
        const bundle = createValidBundle(items);
        env.memoryService.importMemories(caller, bundle, { conflictStrategy: 'OVERWRITE' });
      }
      return new Float32Array(384).fill(1 / Math.sqrt(384));
    },
    async embedBatch(texts) { return texts.map(() => new Float32Array(384).fill(1 / Math.sqrt(384))); }
  };

  const manager = new EmbeddingLifecycleManager({
    db: env.db,
    jobRepo: env.embeddingJobRepo,
    memoryRepo: env.memoryRepo,
    embeddingRepo: env.embeddingRepo,
    provider: concurrentProvider
  });

  // Process the in-flight job for the old memory
  const processed = await manager.processNextJob();
  assert.equal(processed, true);
  assert.equal(didOverwrite, true);

  // The old memory was archived by the import; the in-flight worker must NOT have persisted an embedding for it!
  const oldEmbedding = env.embeddingRepo.getEmbedding(initialMem.id, env.mockProvider.modelId);
  assert.equal(oldEmbedding, null, 'Old memory must NOT receive an embedding');

  // The new memory's job can now be processed cleanly
  const newMem = env.memoryRepo.getMemoryByKey('concurrent.replaced', env.workspaceA, 'ACTIVE');
  assert.ok(newMem);
  assert.notEqual(newMem.id, initialMem.id);

  const processedNew = await manager.processNextJob();
  assert.equal(processedNew, true);

  const newEmbedding = env.embeddingRepo.getEmbedding(newMem.id, env.mockProvider.modelId);
  assert.ok(newEmbedding, 'New memory receives its own embedding');
});

test('7. Imported metadata cannot forge relational ownership', () => {
  const env = setupTestEnvironment();
  const caller = env.authorizer.authorizeUser({
    credentials: 'token-admin-alpha',
    requestedScope: env.workspaceA
  });

  // Bundle containing forged metadata attempting to claim GLOBAL scope and forged owner
  const items: MemoryExportItem[] = [
    {
      category: 'PROJECT_FACT',
      key: 'forged.ownership',
      content: 'Attempting to forge ownership',
      status: 'ACTIVE',
      priority: 50,
      tags: [],
      metadata: {
        scopeType: 'GLOBAL',
        scopeId: 'default',
        ownerId: 'attacker-id',
        principalId: 'attacker-id'
      },
      createdAt: '2026-11-16T10:00:00.000Z',
      updatedAt: '2026-11-16T10:00:00.000Z'
    }
  ];

  const bundle = createValidBundle(items);
  env.memoryService.importMemories(caller, bundle);

  // Verify memory relational scope is strictly caller's workspace
  const mem = env.memoryRepo.getMemoryByKey('forged.ownership', env.workspaceA);
  assert.ok(mem);
  assert.equal(mem.scopeType, 'WORKSPACE');
  assert.equal(mem.scopeId, 'ws-alpha');

  // Verify job relational scope is strictly caller's workspace
  const jobs = env.embeddingJobRepo.listJobs({ memoryId: mem.id });
  assert.equal(jobs.length, 1);
  assert.equal(jobs[0].scopeType, 'WORKSPACE');
  assert.equal(jobs[0].scopeId, 'ws-alpha');

  // Cannot be retrieved as global memory
  const globalCheck = env.memoryRepo.getMemoryByKey('forged.ownership', env.globalScope);
  assert.equal(globalCheck, null);
});

test('8. Workspace imports cannot enqueue global-memory jobs', () => {
  const env = setupTestEnvironment();
  const caller = env.authorizer.authorizeUser({
    credentials: 'token-admin-alpha',
    requestedScope: env.workspaceA
  });

  const items: MemoryExportItem[] = [
    {
      category: 'PROJECT_FACT',
      key: 'workspace.only',
      content: 'Must remain strictly in workspace',
      status: 'ACTIVE',
      priority: 50,
      tags: [],
      metadata: {},
      createdAt: '2026-11-16T10:00:00.000Z',
      updatedAt: '2026-11-16T10:00:00.000Z'
    }
  ];

  const bundle = createValidBundle(items);
  env.memoryService.importMemories(caller, bundle);

  // Verify zero global jobs were enqueued
  const globalJobs = env.embeddingJobRepo.listJobs({ scopeType: 'GLOBAL' });
  assert.equal(globalJobs.length, 0);

  // All jobs are scoped strictly to ws-alpha
  const wsJobs = env.embeddingJobRepo.listJobs({ scopeType: 'WORKSPACE', scopeId: 'ws-alpha' });
  assert.equal(wsJobs.length, 1);
});

// ============================================================================
// Group 2: Model Revision Backfill
// ============================================================================

test('9. Missing vectors for a new revision are identified correctly', async () => {
  const env = setupTestEnvironment();
  const caller = env.authorizer.authorizeUser({
    credentials: 'token-admin-alpha',
    requestedScope: env.workspaceA
  });

  // Create 3 active memories
  env.memoryService.createMemory(caller, {
    category: 'PROJECT_FACT',
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    key: 'mem.1',
    content: 'Content number one'
  });
  env.memoryService.createMemory(caller, {
    category: 'PROJECT_FACT',
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    key: 'mem.2',
    content: 'Content number two'
  });
  env.memoryService.createMemory(caller, {
    category: 'PROJECT_FACT',
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    key: 'mem.3',
    content: 'Content number three'
  });

  // Reconcile embeddings for model revision 'v1'
  await env.memoryService.syncScopeEmbeddings(caller, {
    modelRevision: 'v1'
  });

  // For revision 'v1', missing count is 0
  assert.equal(
    env.memoryRepo.countMemoriesMissingEmbeddings(
      env.workspaceA.scopeType,
      env.workspaceA.scopeId,
      env.mockProvider.modelId,
      'v1'
    ),
    0
  );

  // For new revision 'v2', missing count is 3!
  assert.equal(
    env.memoryRepo.countMemoriesMissingEmbeddings(
      env.workspaceA.scopeType,
      env.workspaceA.scopeId,
      env.mockProvider.modelId,
      'v2'
    ),
    3
  );

  const missingRecords = env.memoryRepo.getMemoriesMissingEmbeddings({
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    modelId: env.mockProvider.modelId,
    modelRevision: 'v2'
  });

  assert.equal(missingRecords.length, 3);
  const discoveredKeys = missingRecords.map((r) => r.key).sort();
  assert.deepEqual(discoveredKeys, ['mem.1', 'mem.2', 'mem.3']);
});

test('10. Backfill generates embeddings for new revision without overwriting other revisions', async () => {
  const env = setupTestEnvironment();
  const caller = env.authorizer.authorizeUser({
    credentials: 'token-admin-alpha',
    requestedScope: env.workspaceA
  });

  const mem = env.memoryService.createMemory(caller, {
    category: 'PROJECT_FACT',
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    key: 'revision.coexistence',
    content: 'Memory will have both v1 and v2 embeddings'
  });

  // Sync revision 'v1'
  const v1Sync = await env.memoryService.backfillModelRevision(caller, {
    modelRevision: 'v1'
  });
  assert.equal(v1Sync.generated, 1);
  assert.equal(v1Sync.remaining, 0);

  const v1Embedding = env.embeddingRepo.getEmbedding(mem.id, env.mockProvider.modelId, 'v1');
  assert.ok(v1Embedding, 'v1 embedding must exist');

  // Backfill revision 'v2'
  const v2Backfill = await env.memoryService.backfillModelRevision(caller, {
    modelRevision: 'v2'
  });
  assert.equal(v2Backfill.generated, 1);
  assert.equal(v2Backfill.remaining, 0);

  const v2Embedding = env.embeddingRepo.getEmbedding(mem.id, env.mockProvider.modelId, 'v2');
  assert.ok(v2Embedding, 'v2 embedding must exist');

  // Invariant: v1 embedding must still exist untouched!
  const v1Preserved = env.embeddingRepo.getEmbedding(mem.id, env.mockProvider.modelId, 'v1');
  assert.ok(v1Preserved, 'v1 embedding must not be overwritten or deleted');
  assert.notEqual(v1Preserved.id, v2Embedding.id);
});

test('11. Bounded batching and resumption/progress reporting', async () => {
  const env = setupTestEnvironment();
  const caller = env.authorizer.authorizeUser({
    credentials: 'token-admin-alpha',
    requestedScope: env.workspaceA
  });

  // Create 5 active memories
  for (let i = 1; i <= 5; i++) {
    env.memoryService.createMemory(caller, {
      category: 'PROJECT_FACT',
      scopeType: env.workspaceA.scopeType,
      scopeId: env.workspaceA.scopeId,
      key: `batch.mem.${i}`,
      content: `Content for batch memory ${i}`
    });
  }

  // Initial missing count for revision 'v2' is 5
  assert.equal(
    env.memoryRepo.countMemoriesMissingEmbeddings(
      env.workspaceA.scopeType,
      env.workspaceA.scopeId,
      env.mockProvider.modelId,
      'v2'
    ),
    5
  );

  // Slice 1: Process limit 2
  const slice1 = await env.memoryService.backfillModelRevision(caller, {
    modelRevision: 'v2',
    limit: 2,
    batchSize: 2
  });
  assert.equal(slice1.processed, 2);
  assert.equal(slice1.generated, 2);
  assert.equal(slice1.remaining, 3);

  // Slice 2: Process next 2
  const slice2 = await env.memoryService.backfillModelRevision(caller, {
    modelRevision: 'v2',
    limit: 2,
    batchSize: 2
  });
  assert.equal(slice2.processed, 2);
  assert.equal(slice2.generated, 2);
  assert.equal(slice2.remaining, 1);

  // Slice 3: Process remaining 1
  const slice3 = await env.memoryService.backfillModelRevision(caller, {
    modelRevision: 'v2',
    limit: 2,
    batchSize: 2
  });
  assert.equal(slice3.processed, 1);
  assert.equal(slice3.generated, 1);
  assert.equal(slice3.remaining, 0);

  // Slice 4: Calling again reports 0 processed and 0 remaining
  const slice4 = await env.memoryService.backfillModelRevision(caller, {
    modelRevision: 'v2',
    limit: 2
  });
  assert.equal(slice4.processed, 0);
  assert.equal(slice4.generated, 0);
  assert.equal(slice4.remaining, 0);
});

test('12. Isolation: cross-workspace memories cannot be backfilled', async () => {
  const env = setupTestEnvironment();
  const callerA = env.authorizer.authorizeUser({
    credentials: 'token-admin-alpha',
    requestedScope: env.workspaceA
  });
  const callerB = env.authorizer.authorizeUser({
    credentials: 'token-admin-beta',
    requestedScope: env.workspaceB
  });

  // Create memory in Workspace B
  env.memoryService.createMemory(callerB, {
    category: 'PROJECT_FACT',
    scopeType: env.workspaceB.scopeType,
    scopeId: env.workspaceB.scopeId,
    key: 'secret.b',
    content: 'Workspace B sensitive fact'
  });

  // Caller A cannot trigger backfill on Workspace B
  await assert.rejects(
    async () => {
      await env.memoryService.backfillModelRevision(callerA, {
        scopeType: env.workspaceB.scopeType,
        scopeId: env.workspaceB.scopeId,
        modelRevision: 'v2'
      });
    },
    (err: any) => err instanceof MemoryScopeViolationError
  );
});

test('13. Retrieval uses correct revision and falls back if revision missing', async () => {
  const env = setupTestEnvironment();
  const caller = env.authorizer.authorizeUser({
    credentials: 'token-admin-alpha',
    requestedScope: env.workspaceA
  });

  // Memory 1: will have both v1 and v2 embeddings
  const mem1 = env.memoryService.createMemory(caller, {
    category: 'PROJECT_FACT',
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    key: 'retrieval.both',
    content: 'Has embeddings for both model revisions'
  });

  // Memory 2: will have ONLY v1 embedding
  const mem2 = env.memoryService.createMemory(caller, {
    category: 'PROJECT_FACT',
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    key: 'retrieval.v1only',
    content: 'Has embedding only for model revision v1'
  });

  // Sync v1 for both
  await env.memoryService.backfillModelRevision(caller, { modelRevision: 'v1' });

  // Backfill v2 ONLY for mem1
  env.embeddingRepo.insertEmbedding({
    memoryId: mem1.id,
    modelId: env.mockProvider.modelId,
    modelRevision: 'v2',
    dimensions: 384,
    embedding: new Float32Array(384).fill(1 / Math.sqrt(384))
  });

  // Create a provider configured specifically for revision 'v2'
  const v2Provider: IEmbeddingProvider = {
    name: 'mock-v2-provider',
    modelId: env.mockProvider.modelId,
    dimensions: 384,
    // Add modelRevision property
    ...({ modelRevision: 'v2' } as any),
    async isAvailable() { return true; },
    async embed() { return new Float32Array(384).fill(1 / Math.sqrt(384)); },
    async embedBatch(texts) { return texts.map(() => new Float32Array(384).fill(1 / Math.sqrt(384))); }
  };

  const serviceWithV2 = new MemoryService({
    memoryRepo: env.memoryRepo,
    embeddingRepo: env.embeddingRepo,
    embeddingProvider: v2Provider,
    taskRepo: env.taskRepo,
    auditRepo: env.auditRepo,
    authorizer: env.authorizer,
    hostAuthority: env.hostAuthority,
    relevanceMatcher: new RelevanceMatcher(),
    contextBuilder: new MemoryContextBuilder()
  });

  // Search memories with v2Provider
  const results = await serviceWithV2.searchMemories(caller, {
    query: 'model revision search query',
    limit: 5
  });

  assert.equal(results.length, 2);

  // mem1 has v2 embedding -> HYBRID provenance
  const r1 = results.find((r) => r.memory.id === mem1.id);
  assert.ok(r1);
  assert.equal(r1.provenance, 'HYBRID');

  // mem2 has only v1 embedding, missing v2 -> safely falls back to LEXICAL_FALLBACK!
  const r2 = results.find((r) => r.memory.id === mem2.id);
  assert.ok(r2);
  assert.equal(r2.provenance, 'LEXICAL_FALLBACK');
});
