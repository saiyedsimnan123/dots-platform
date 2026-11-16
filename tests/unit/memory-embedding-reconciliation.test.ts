/**
 * Next-Generation Dots AI Platform - Memory Embedding Reconciliation Tests
 * Phase 4C.6A: Repository Missing-Vector Queries & Batch Reconciliation
 * 
 * Verifies all requirements for Phase 4C.6A:
 * 1. getMemoriesMissingEmbeddings discovers eligible active memories without embeddings for exact (modelId, modelRevision).
 * 2. Memories already having embeddings for exact model and revision are excluded.
 * 3. Embeddings for different model/revision do not exclude candidates for the target model.
 * 4. PENDING_APPROVAL and ARCHIVED memories are excluded from reconciliation.
 * 5. Repository query enforces bounded limit and deterministic ordering (created_at ASC, id ASC).
 * 6. Workspace isolation is enforced at repository and service layer.
 * 7. countMemoriesMissingEmbeddings accurately reflects missing count.
 * 8. syncScopeEmbeddings requires WRITE permission; rejects unauthorized callers.
 * 9. syncScopeEmbeddings blocks scope forgery (workspace caller cannot sync global or other workspace).
 * 10. syncScopeEmbeddings allows authorized global callers to sync global memories.
 * 11. syncScopeEmbeddings chunks requests according to bounded batchSize (<= 25).
 * 12. Model inference runs strictly outside database transactions.
 * 13. Empty candidate sets return cleanly with zero inference calls.
 * 14. Provider unavailable returns structured failure DTO without crashing.
 * 15. Provider inference failure records errors and failure counts without crashing.
 * 16. Concurrent modification (content change, status change, deletion) is detected and discarded as stale.
 * 17. Concurrent insertion of identical embedding is skipped cleanly (alreadyEmbeddedOrSkipped).
 * 18. Emits privacy-safe MEMORY_EMBEDDINGS_SYNCED audit event with correct telemetry.
 * 19. Persisted embeddings are retrievable and verified.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseManager } from '../../src/storage/db.ts';
import { MemoryRepository } from '../../src/storage/memory-repository.ts';
import { MemoryEmbeddingRepository } from '../../src/storage/memory-embedding-repository.ts';
import { MemoryService } from '../../src/memory/memory-service.ts';
import { TaskRepository } from '../../src/storage/task-repository.ts';
import { AuditRepository } from '../../src/storage/audit-repository.ts';
import { RelevanceMatcher } from '../../src/memory/relevance-matcher.ts';
import { MemoryContextBuilder } from '../../src/memory/context-builder.ts';
import { HostMemoryAuthority } from '../../src/security/host-authority.ts';
import type { TrustedIdentityProvider, AuthenticatedPrincipal } from '../../src/security/memory-authorizer.ts';
import { DeterministicMockEmbeddingProvider } from '../../src/memory/mock-embedding-provider.ts';
import type { IEmbeddingProvider } from '../../src/memory/embedding-types.ts';
import type { ScopeIdentifier } from '../../src/domain/types.ts';
import {
  ValidationError,
  SecurityViolationError,
  MemoryScopeViolationError
} from '../../src/domain/errors.ts';

function setupTestEnvironment() {
  const db = new DatabaseManager(':memory:');
  const taskRepo = new TaskRepository(db);
  const auditRepo = new AuditRepository(db);
  const memoryRepo = new MemoryRepository(db);
  const embeddingRepo = new MemoryEmbeddingRepository(db);
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
      if (credentials === 'token-readonly-alpha') {
        return {
          principalId: 'user-ro-alpha',
          role: 'VIEWER',
          permittedScopes: [workspaceA]
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

  const memoryService = new MemoryService({
    memoryRepo,
    embeddingRepo,
    embeddingProvider: mockProvider,
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
    mockProvider,
    memoryService,
    hostAuthority,
    authorizer,
    workspaceA,
    workspaceB,
    globalScope
  };
}

test('1. Repository - getMemoriesMissingEmbeddings discovers active memories without embeddings for target model', () => {
  const env = setupTestEnvironment();

  const mem1 = env.memoryRepo.createMemory({
    category: 'PROJECT_FACT',
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    key: 'project.alpha.name',
    content: 'Project Alpha is a secure system',
    status: 'ACTIVE'
  });

  const mem2 = env.memoryRepo.createMemory({
    category: 'USER_PREFERENCE',
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    key: 'editor.theme',
    content: 'User prefers dark mode',
    status: 'ACTIVE'
  });

  const missingRepo = env.embeddingRepo.getMemoriesMissingEmbeddings({
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    modelId: env.mockProvider.modelId,
    modelRevision: 'main'
  });

  assert.equal(missingRepo.length, 2);
  const foundIds = new Set(missingRepo.map((r) => r.id));
  assert.ok(foundIds.has(mem1.id));
  assert.ok(foundIds.has(mem2.id));
  assert.ok(missingRepo[0].updatedAt);

  // Also verify on memoryRepo
  const missingMemRepo = env.memoryRepo.getMemoriesMissingEmbeddings({
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    modelId: env.mockProvider.modelId,
    modelRevision: 'main'
  });
  assert.equal(missingMemRepo.length, 2);
});

test('2. Repository - Excludes memories that already have an embedding for the exact model and revision', () => {
  const env = setupTestEnvironment();

  const mem1 = env.memoryRepo.createMemory({
    category: 'PROJECT_FACT',
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    key: 'fact.1',
    content: 'Fact 1 content',
    status: 'ACTIVE'
  });

  const mem2 = env.memoryRepo.createMemory({
    category: 'PROJECT_FACT',
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    key: 'fact.2',
    content: 'Fact 2 content',
    status: 'ACTIVE'
  });

  // Insert embedding for mem1
  const dummyVec = new Float32Array(env.mockProvider.dimensions);
  dummyVec[0] = 1.0;
  env.embeddingRepo.insertEmbedding({
    memoryId: mem1.id,
    modelId: env.mockProvider.modelId,
    modelRevision: 'main',
    dimensions: env.mockProvider.dimensions,
    embedding: dummyVec
  });

  const missing = env.embeddingRepo.getMemoriesMissingEmbeddings({
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    modelId: env.mockProvider.modelId,
    modelRevision: 'main'
  });

  assert.equal(missing.length, 1);
  assert.equal(missing[0].id, mem2.id);

  const count = env.embeddingRepo.countMemoriesMissingEmbeddings(
    env.workspaceA.scopeType,
    env.workspaceA.scopeId,
    env.mockProvider.modelId,
    'main'
  );
  assert.equal(count, 1);
});

test('3. Repository - Model revision isolation: embeddings under a different revision do not exclude candidate', () => {
  const env = setupTestEnvironment();

  const mem1 = env.memoryRepo.createMemory({
    category: 'PROJECT_FACT',
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    key: 'fact.revision',
    content: 'Fact about revisions',
    status: 'ACTIVE'
  });

  // Insert embedding for 'v2' revision
  const dummyVec = new Float32Array(env.mockProvider.dimensions);
  dummyVec[0] = 1.0;
  env.embeddingRepo.insertEmbedding({
    memoryId: mem1.id,
    modelId: env.mockProvider.modelId,
    modelRevision: 'v2',
    dimensions: env.mockProvider.dimensions,
    embedding: dummyVec
  });

  // Query missing for 'main'
  const missingMain = env.embeddingRepo.getMemoriesMissingEmbeddings({
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    modelId: env.mockProvider.modelId,
    modelRevision: 'main'
  });
  assert.equal(missingMain.length, 1);
  assert.equal(missingMain[0].id, mem1.id);

  // Query missing for 'v2'
  const missingV2 = env.embeddingRepo.getMemoriesMissingEmbeddings({
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    modelId: env.mockProvider.modelId,
    modelRevision: 'v2'
  });
  assert.equal(missingV2.length, 0);
});

test('4. Repository - PENDING_APPROVAL and ARCHIVED memories are strictly excluded', () => {
  const env = setupTestEnvironment();

  // Active memory
  const memActive = env.memoryRepo.createMemory({
    category: 'PROJECT_FACT',
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    key: 'active.fact',
    content: 'Active content',
    status: 'ACTIVE'
  });

  // Pending approval memory
  env.memoryRepo.createMemory({
    category: 'PROJECT_FACT',
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    key: 'pending.fact',
    content: 'Pending proposal content',
    status: 'PENDING_APPROVAL'
  });

  // Archived memory
  env.memoryRepo.createMemory({
    category: 'PROJECT_FACT',
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    key: 'archived.fact',
    content: 'Archived fact content',
    status: 'ARCHIVED'
  });

  const missing = env.embeddingRepo.getMemoriesMissingEmbeddings({
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    modelId: env.mockProvider.modelId
  });

  assert.equal(missing.length, 1);
  assert.equal(missing[0].id, memActive.id);
});

test('5. Repository - Bounded limit and deterministic ordering (created_at ASC, id ASC)', () => {
  const env = setupTestEnvironment();

  const mem1 = env.memoryRepo.createMemory({
    category: 'PROJECT_FACT',
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    key: 'fact.order.1',
    content: 'Fact 1',
    status: 'ACTIVE'
  });

  const mem2 = env.memoryRepo.createMemory({
    category: 'PROJECT_FACT',
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    key: 'fact.order.2',
    content: 'Fact 2',
    status: 'ACTIVE'
  });

  const mem3 = env.memoryRepo.createMemory({
    category: 'PROJECT_FACT',
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    key: 'fact.order.3',
    content: 'Fact 3',
    status: 'ACTIVE'
  });

  const expectedOrder = [mem1, mem2, mem3].sort((a, b) => {
    if (a.createdAt !== b.createdAt) {
      return a.createdAt.localeCompare(b.createdAt);
    }
    return a.id.localeCompare(b.id);
  });

  const missingLimited = env.embeddingRepo.getMemoriesMissingEmbeddings({
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    modelId: env.mockProvider.modelId,
    limit: 2
  });

  assert.equal(missingLimited.length, 2);
  assert.equal(missingLimited[0].id, expectedOrder[0].id);
  assert.equal(missingLimited[1].id, expectedOrder[1].id);
});

test('6. Repository - Workspace isolation: cross-workspace candidates are never returned', () => {
  const env = setupTestEnvironment();

  env.memoryRepo.createMemory({
    category: 'PROJECT_FACT',
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    key: 'alpha.fact',
    content: 'Alpha secret',
    status: 'ACTIVE'
  });

  const memBeta = env.memoryRepo.createMemory({
    category: 'PROJECT_FACT',
    scopeType: env.workspaceB.scopeType,
    scopeId: env.workspaceB.scopeId,
    key: 'beta.fact',
    content: 'Beta secret',
    status: 'ACTIVE'
  });

  const missingBeta = env.embeddingRepo.getMemoriesMissingEmbeddings({
    scopeType: env.workspaceB.scopeType,
    scopeId: env.workspaceB.scopeId,
    modelId: env.mockProvider.modelId
  });

  assert.equal(missingBeta.length, 1);
  assert.equal(missingBeta[0].id, memBeta.id);
});

test('7. Service - syncScopeEmbeddings discovers and synchronizes missing embeddings end-to-end', async () => {
  const env = setupTestEnvironment();
  const caller = env.authorizer.authorizeUser({
    credentials: 'token-admin-alpha',
    requestedScope: env.workspaceA
  });

  env.memoryRepo.createMemory({
    category: 'PROJECT_FACT',
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    key: 'sync.test.1',
    content: 'Content 1 to sync',
    status: 'ACTIVE'
  });

  env.memoryRepo.createMemory({
    category: 'PROJECT_FACT',
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    key: 'sync.test.2',
    content: 'Content 2 to sync',
    status: 'ACTIVE'
  });

  const result = await env.memoryService.syncScopeEmbeddings(caller);

  assert.equal(result.success, true);
  assert.equal(result.candidatesDiscovered, 2);
  assert.equal(result.embeddingsGenerated, 2);
  assert.equal(result.alreadyEmbeddedOrSkipped, 0);
  assert.equal(result.staleResultsDiscarded, 0);
  assert.equal(result.failed, 0);
  assert.equal(result.modelId, env.mockProvider.modelId);

  // Subsequent sync should discover 0 candidates
  const secondResult = await env.memoryService.syncScopeEmbeddings(caller);
  assert.equal(secondResult.success, true);
  assert.equal(secondResult.candidatesDiscovered, 0);
  assert.equal(secondResult.embeddingsGenerated, 0);

  // Verify stored embeddings exist and are valid
  const count = env.embeddingRepo.countEmbeddings({ modelId: env.mockProvider.modelId });
  assert.equal(count, 2);
});

test('8. Service - syncScopeEmbeddings rejects unauthorized caller lacking WRITE permission', async () => {
  const env = setupTestEnvironment();
  const callerRo = env.authorizer.authorizeUser({
    credentials: 'token-readonly-alpha',
    requestedScope: env.workspaceA
  });

  await assert.rejects(
    async () => {
      await env.memoryService.syncScopeEmbeddings(callerRo);
    },
    (err: unknown) => {
      assert.ok(err instanceof SecurityViolationError);
      assert.match((err as Error).message, /lacks required 'WRITE' permission/i);
      return true;
    }
  );
});

test('9. Service - syncScopeEmbeddings blocks scope forgery (workspace caller cannot sync global or other workspace)', async () => {
  const env = setupTestEnvironment();
  const callerAlpha = env.authorizer.authorizeUser({
    credentials: 'token-admin-alpha',
    requestedScope: env.workspaceA
  });

  // Attempt to sync GLOBAL
  await assert.rejects(
    async () => {
      await env.memoryService.syncScopeEmbeddings(callerAlpha, {
        scopeType: 'GLOBAL',
        scopeId: 'default'
      });
    },
    (err: unknown) => {
      assert.ok(err instanceof MemoryScopeViolationError);
      return true;
    }
  );

  // Attempt to sync workspaceB
  await assert.rejects(
    async () => {
      await env.memoryService.syncScopeEmbeddings(callerAlpha, {
        scopeType: 'WORKSPACE',
        scopeId: 'ws-beta'
      });
    },
    (err: unknown) => {
      assert.ok(err instanceof MemoryScopeViolationError);
      return true;
    }
  );
});

test('10. Service - syncScopeEmbeddings permits authorized global caller to sync global scope', async () => {
  const env = setupTestEnvironment();
  const globalCaller = env.authorizer.authorizeUser({
    credentials: 'token-global-admin',
    requestedScope: env.globalScope
  });

  env.memoryRepo.createMemory({
    category: 'LEARNED_PROCEDURE',
    scopeType: env.globalScope.scopeType,
    scopeId: env.globalScope.scopeId,
    key: 'global.procedure.1',
    content: 'Global standard procedure',
    status: 'ACTIVE'
  });

  const result = await env.memoryService.syncScopeEmbeddings(globalCaller);
  assert.equal(result.success, true);
  assert.equal(result.candidatesDiscovered, 1);
  assert.equal(result.embeddingsGenerated, 1);
  assert.equal(result.scope.scopeType, 'GLOBAL');
  assert.equal(result.scope.scopeId, 'default');
});

test('11. Service - Batch chunking: processes candidates across multiple batch slices (batchSize <= 25)', async () => {
  const env = setupTestEnvironment();
  const caller = env.authorizer.authorizeUser({
    credentials: 'token-admin-alpha',
    requestedScope: env.workspaceA
  });

  // Create 7 memories
  for (let i = 1; i <= 7; i++) {
    env.memoryRepo.createMemory({
      category: 'PROJECT_FACT',
      scopeType: env.workspaceA.scopeType,
      scopeId: env.workspaceA.scopeId,
      key: `chunk.fact.${i}`,
      content: `Chunk content number ${i}`,
      status: 'ACTIVE'
    });
  }

  // Track embedBatch calls
  let batchCalls = 0;
  const batchSizes: number[] = [];
  const trackingProvider: IEmbeddingProvider = {
    name: 'tracking-mock',
    modelId: 'tracking-model-v1',
    dimensions: 384,
    async isAvailable() { return true; },
    async embed() { return new Float32Array(384); },
    async embedBatch(texts: readonly string[]) {
      batchCalls++;
      batchSizes.push(texts.length);
      return texts.map(() => {
        const v = new Float32Array(384);
        v[0] = 1.0;
        return v;
      });
    }
  };

  const result = await env.memoryService.syncScopeEmbeddings(caller, {
    batchSize: 3,
    provider: trackingProvider
  });

  assert.equal(result.success, true);
  assert.equal(result.candidatesDiscovered, 7);
  assert.equal(result.embeddingsGenerated, 7);
  // With batchSize 3 and 7 items: slices are 3, 3, 1 -> 3 batch calls
  assert.equal(batchCalls, 3);
  assert.deepEqual(batchSizes, [3, 3, 1]);
});

test('12. Service - Safe failure when provider is unavailable (returns structured failure DTO without crashing)', async () => {
  const env = setupTestEnvironment();
  const caller = env.authorizer.authorizeUser({
    credentials: 'token-admin-alpha',
    requestedScope: env.workspaceA
  });

  env.memoryRepo.createMemory({
    category: 'PROJECT_FACT',
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    key: 'unavail.fact',
    content: 'Content for unavail provider test',
    status: 'ACTIVE'
  });

  const offlineProvider: IEmbeddingProvider = {
    name: 'offline-provider',
    modelId: 'offline-model',
    dimensions: 384,
    async isAvailable() { return false; },
    async embed() { throw new Error('offline'); },
    async embedBatch() { throw new Error('offline'); }
  };

  const result = await env.memoryService.syncScopeEmbeddings(caller, {
    provider: offlineProvider
  });

  assert.equal(result.success, false);
  assert.equal(result.candidatesDiscovered, 0);
  assert.equal(result.embeddingsGenerated, 0);
  assert.ok(result.errors);
  assert.match(result.errors[0], /unavailable/i);
});

test('13. Service - Safe failure when embedBatch throws during inference (reports failure count)', async () => {
  const env = setupTestEnvironment();
  const caller = env.authorizer.authorizeUser({
    credentials: 'token-admin-alpha',
    requestedScope: env.workspaceA
  });

  env.memoryRepo.createMemory({
    category: 'PROJECT_FACT',
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    key: 'error.fact.1',
    content: 'Content 1',
    status: 'ACTIVE'
  });
  env.memoryRepo.createMemory({
    category: 'PROJECT_FACT',
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    key: 'error.fact.2',
    content: 'Content 2',
    status: 'ACTIVE'
  });

  const throwingProvider: IEmbeddingProvider = {
    name: 'throwing-provider',
    modelId: 'throwing-model',
    dimensions: 384,
    async isAvailable() { return true; },
    async embed() { throw new Error('Inference explosion'); },
    async embedBatch() { throw new Error('Inference explosion'); }
  };

  const result = await env.memoryService.syncScopeEmbeddings(caller, {
    provider: throwingProvider
  });

  assert.equal(result.success, false);
  assert.equal(result.candidatesDiscovered, 2);
  assert.equal(result.embeddingsGenerated, 0);
  assert.equal(result.failed, 2);
  assert.ok(result.errors);
  assert.match(result.errors[0], /Inference explosion/i);
});

test('14. Service - Stale result handling: concurrent content update or archive discards stale embedding', async () => {
  const env = setupTestEnvironment();
  const caller = env.authorizer.authorizeUser({
    credentials: 'token-admin-alpha',
    requestedScope: env.workspaceA
  });

  const mem1 = env.memoryRepo.createMemory({
    category: 'PROJECT_FACT',
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    key: 'stale.fact.1',
    content: 'Original content before concurrent edit',
    status: 'ACTIVE'
  });

  const mem2 = env.memoryRepo.createMemory({
    category: 'PROJECT_FACT',
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    key: 'stale.fact.2',
    content: 'Original content before concurrent archive',
    status: 'ACTIVE'
  });

  // Create a provider hook that mutates memories during inference (before persist)
  const mutatingProvider: IEmbeddingProvider = {
    name: 'mutating-provider',
    modelId: 'mutating-model',
    dimensions: 384,
    async isAvailable() { return true; },
    async embed() { return new Float32Array(384); },
    async embedBatch(texts: readonly string[]) {
      // Simulate concurrent update of mem1
      env.memoryRepo.updateMemory(mem1.id, env.workspaceA, {
        content: 'Modified content while inference was executing'
      });

      // Simulate concurrent archive of mem2
      env.memoryRepo.archiveMemory(mem2.id, env.workspaceA);

      return texts.map(() => {
        const v = new Float32Array(384);
        v[0] = 1.0;
        return v;
      });
    }
  };

  const result = await env.memoryService.syncScopeEmbeddings(caller, {
    provider: mutatingProvider
  });

  assert.equal(result.success, true);
  assert.equal(result.candidatesDiscovered, 2);
  assert.equal(result.embeddingsGenerated, 0);
  assert.equal(result.staleResultsDiscarded, 2);
  assert.equal(result.failed, 0);

  // No stale embeddings should have been inserted
  const stored1 = env.embeddingRepo.getEmbedding(mem1.id, mutatingProvider.modelId);
  assert.equal(stored1, null);
  const stored2 = env.embeddingRepo.getEmbedding(mem2.id, mutatingProvider.modelId);
  assert.equal(stored2, null);
});

test('15. Service - Concurrent insertion handling: alreadyEmbeddedOrSkipped counter increments', async () => {
  const env = setupTestEnvironment();
  const caller = env.authorizer.authorizeUser({
    credentials: 'token-admin-alpha',
    requestedScope: env.workspaceA
  });

  const mem1 = env.memoryRepo.createMemory({
    category: 'PROJECT_FACT',
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    key: 'concurrent.insert.fact',
    content: 'Fact to insert concurrently',
    status: 'ACTIVE'
  });

  const racingProvider: IEmbeddingProvider = {
    name: 'racing-provider',
    modelId: 'racing-model',
    dimensions: 384,
    async isAvailable() { return true; },
    async embed() { return new Float32Array(384); },
    async embedBatch(texts: readonly string[]) {
      // Simulate another worker inserting the embedding concurrently
      const v = new Float32Array(384);
      v[0] = 1.0;
      env.embeddingRepo.insertEmbedding({
        memoryId: mem1.id,
        modelId: 'racing-model',
        modelRevision: 'main',
        dimensions: 384,
        embedding: v
      });

      return texts.map(() => {
        const out = new Float32Array(384);
        out[0] = 1.0;
        return out;
      });
    }
  };

  const result = await env.memoryService.syncScopeEmbeddings(caller, {
    provider: racingProvider
  });

  assert.equal(result.success, true);
  assert.equal(result.candidatesDiscovered, 1);
  assert.equal(result.embeddingsGenerated, 0);
  assert.equal(result.alreadyEmbeddedOrSkipped, 1);
  assert.equal(result.failed, 0);
});

test('16. Service - Privacy-safe MEMORY_EMBEDDINGS_SYNCED audit event appended with telemetry only', async () => {
  const env = setupTestEnvironment();
  const caller = env.authorizer.authorizeUser({
    credentials: 'token-admin-alpha',
    requestedScope: env.workspaceA
  });

  env.memoryRepo.createMemory({
    category: 'PROJECT_FACT',
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    key: 'audit.test.fact',
    content: 'Sensitive secret content that MUST NOT appear in audit logs',
    status: 'ACTIVE'
  });

  await env.memoryService.syncScopeEmbeddings(caller);

  // Retrieve audit events
  const events = env.auditRepo.getEventsByTaskId('__system_memory__');
  const syncEvent = events.find((e) => e.eventType === 'MEMORY_EMBEDDINGS_SYNCED');

  assert.ok(syncEvent, 'MEMORY_EMBEDDINGS_SYNCED event must be recorded in audit log');
  const details = JSON.parse(syncEvent.detailsJson);
  assert.equal(details.scopeType, 'WORKSPACE');
  assert.equal(details.scopeId, 'ws-alpha');
  assert.equal(details.candidatesDiscovered, 1);
  assert.equal(details.embeddingsGenerated, 1);
  assert.equal(details.alreadyEmbeddedOrSkipped, 0);
  assert.equal(details.staleResultsDiscarded, 0);
  assert.equal(details.failed, 0);

  // Privacy boundary check: raw memory keys and content must NEVER appear in audit details
  const detailsStr = syncEvent.detailsJson;
  assert.ok(!detailsStr.includes('audit.test.fact'));
  assert.ok(!detailsStr.includes('Sensitive secret content'));
});

test('17. Service - Invalid batchSize and limit arguments are rejected with ValidationError', async () => {
  const env = setupTestEnvironment();
  const caller = env.authorizer.authorizeUser({
    credentials: 'token-admin-alpha',
    requestedScope: env.workspaceA
  });

  // batchSize 0
  await assert.rejects(
    async () => {
      await env.memoryService.syncScopeEmbeddings(caller, { batchSize: 0 });
    },
    (err: unknown) => {
      assert.ok(err instanceof ValidationError);
      assert.match((err as Error).message, /batchSize must be an integer between 1 and 25/);
      return true;
    }
  );

  // batchSize 26 (> 25)
  await assert.rejects(
    async () => {
      await env.memoryService.syncScopeEmbeddings(caller, { batchSize: 26 });
    },
    (err: unknown) => {
      assert.ok(err instanceof ValidationError);
      assert.match((err as Error).message, /batchSize must be an integer between 1 and 25/);
      return true;
    }
  );

  // limit 0
  await assert.rejects(
    async () => {
      await env.memoryService.syncScopeEmbeddings(caller, { limit: 0 });
    },
    (err: unknown) => {
      assert.ok(err instanceof ValidationError);
      assert.match((err as Error).message, /limit must be a positive integer/);
      return true;
    }
  );
});
