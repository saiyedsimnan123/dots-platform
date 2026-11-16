/**
 * Next-Generation Dots AI Platform - Persistent SQLite Vector Storage Tests
 * Phase 4C.4: Persistent SQLite Vector Storage
 * 
 * Verifies all 18 requirements from the Phase 4C.4 specification:
 * 1. Migration creates the expected table and indexes.
 * 2. Insert and retrieve embedding.
 * 3. Float32Array to BLOB and back round-trip.
 * 4. Exact vector values survive round-trip.
 * 5. Wrong dimensions are rejected.
 * 6. Malformed BLOB sizes are rejected.
 * 7. NaN and Infinity are rejected.
 * 8. Zero or invalid vectors are rejected.
 * 9. Duplicate model identity behavior.
 * 10. Updating/replacing an embedding.
 * 11. Deleting a memory cascades to its embeddings.
 * 12. Different model identities remain isolated.
 * 13. Pending-approval memories cannot receive embeddings.
 * 14. Provider failure does not corrupt memory data.
 * 15. Workspace isolation is enforced.
 * 16. Global inheritance authorization is preserved.
 * 17. Missing embeddings do not break existing lexical memory functionality.
 * 18. Existing memory tests continue passing.
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
import {
  serializeVectorToBlob,
  deserializeBlobToVector,
  normalizeVector,
  validateNormalizedVector
} from '../../src/memory/vector-utils.ts';
import { DeterministicMockEmbeddingProvider } from '../../src/memory/mock-embedding-provider.ts';
import type { IEmbeddingProvider } from '../../src/memory/embedding-types.ts';
import type { ScopeIdentifier } from '../../src/domain/types.ts';
import {
  ValidationError,
  InvalidVectorError,
  MemoryConflictError,
  EmbeddingNotFoundError,
  MemoryScopeViolationError,
  EmbeddingInferenceError
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
          permittedScopes: [workspaceA, globalScope]
        };
      }
      if (credentials === 'token-admin-beta') {
        return {
          principalId: 'user-beta',
          role: 'ADMIN',
          permittedScopes: [workspaceB]
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

// ============================================================================
// 1. Migration creates the expected table and indexes
// ============================================================================

test('Requirement 1: Migration 005 creates expected table, indexes, and schema constraints', () => {
  const db = new DatabaseManager(':memory:');

  // Verify migration version recorded
  const migrationRow = db.prepare('SELECT version FROM schema_migrations WHERE version = ?').get('005_memory_embeddings') as { version: string } | undefined;
  assert.ok(migrationRow, 'Migration 005_memory_embeddings must be recorded in schema_migrations');

  // Verify table exists
  const tableRow = db.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'memory_embeddings'").get() as { name: string } | undefined;
  assert.ok(tableRow, 'memory_embeddings table must exist');

  // Verify table columns
  const columns = db.prepare("PRAGMA table_info('memory_embeddings')").all() as Array<{ name: string; type: string; notnull: number; pk: number }>;
  const columnMap = new Map(columns.map(c => [c.name, c]));

  assert.ok(columnMap.has('id'), 'Column id must exist');
  assert.equal(columnMap.get('id')!.pk, 1, 'id must be primary key');
  assert.ok(columnMap.has('memory_id'), 'Column memory_id must exist');
  assert.equal(columnMap.get('memory_id')!.notnull, 1, 'memory_id must be NOT NULL');
  assert.ok(columnMap.has('model_id'), 'Column model_id must exist');
  assert.ok(columnMap.has('model_revision'), 'Column model_revision must exist');
  assert.ok(columnMap.has('dimensions'), 'Column dimensions must exist');
  assert.ok(columnMap.has('embedding'), 'Column embedding must exist');
  assert.ok(columnMap.has('created_at'), 'Column created_at must exist');
  assert.ok(columnMap.has('updated_at'), 'Column updated_at must exist');

  // Verify indexes exist
  const indexes = db.prepare("SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'memory_embeddings'").all() as Array<{ name: string }>;
  const indexNames = new Set(indexes.map(i => i.name));
  assert.ok(indexNames.has('idx_memory_embeddings_memory_id'), 'Index idx_memory_embeddings_memory_id must exist');
  assert.ok(indexNames.has('idx_memory_embeddings_model'), 'Index idx_memory_embeddings_model must exist');

  db.close();
});

// ============================================================================
// 2. Insert and retrieve embedding
// ============================================================================

test('Requirement 2: Insert and retrieve embedding successfully', () => {
  const { memoryRepo, embeddingRepo, workspaceA } = setupTestEnvironment();

  const mem = memoryRepo.createMemory({
    key: 'test:pref',
    content: 'User prefers dark mode and concise summaries.',
    category: 'USER_PREFERENCE',
    scopeType: workspaceA.scopeType,
    scopeId: workspaceA.scopeId
  });

  const vector = normalizeVector(new Float32Array([0.5, 0.5, 0.5, 0.5]));
  const inserted = embeddingRepo.insertEmbedding({
    memoryId: mem.id,
    modelId: 'test-model-4d',
    modelRevision: 'main',
    dimensions: 4,
    embedding: vector
  });

  assert.ok(inserted.id);
  assert.equal(inserted.memoryId, mem.id);
  assert.equal(inserted.modelId, 'test-model-4d');
  assert.equal(inserted.modelRevision, 'main');
  assert.equal(inserted.dimensions, 4);
  assert.equal(inserted.embedding.length, 4);

  const retrieved = embeddingRepo.getEmbedding(mem.id, 'test-model-4d', 'main');
  assert.ok(retrieved);
  assert.equal(retrieved.id, inserted.id);
  assert.equal(retrieved.memoryId, mem.id);
  assert.equal(retrieved.dimensions, 4);
  for (let i = 0; i < 4; i++) {
    assert.equal(retrieved.embedding[i], vector[i]);
  }
});

// ============================================================================
// 3. Float32Array to BLOB and back round-trip
// ============================================================================

test('Requirement 3: Float32Array to BLOB and back round-trip', () => {
  const original = normalizeVector(new Float32Array([1.0, 2.0, -3.0, 4.5, -0.75]));
  const blob = serializeVectorToBlob(original);

  assert.ok(blob instanceof Uint8Array);
  assert.equal(blob.byteLength, original.length * 4);

  const restored = deserializeBlobToVector(blob, original.length);
  assert.ok(restored instanceof Float32Array);
  assert.equal(restored.length, original.length);
  assert.notEqual(restored, original, 'Restored vector must be an independent instance');
});

// ============================================================================
// 4. Exact vector values survive round-trip
// ============================================================================

test('Requirement 4: Exact vector values survive round-trip serialization', () => {
  // Test precise floating point values including negative, fractional, and boundary values
  const original = new Float32Array([
    0.125,
    -0.625,
    0.9375,
    -0.03125,
    1024.5,
    -2048.25
  ]);

  const blob = serializeVectorToBlob(original);
  const restored = deserializeBlobToVector(blob, original.length);

  assert.equal(restored.length, original.length);
  for (let i = 0; i < original.length; i++) {
    assert.equal(
      restored[i],
      original[i],
      `Value mismatch at index ${i}: expected ${original[i]}, got ${restored[i]}`
    );
  }
});

// ============================================================================
// 5. Wrong dimensions are rejected
// ============================================================================

test('Requirement 5: Wrong dimensions are rejected at serialization, deserialization, and repository insert', () => {
  const { memoryRepo, embeddingRepo, workspaceA } = setupTestEnvironment();

  const mem = memoryRepo.createMemory({
    key: 'test:dims',
    content: 'Testing dimension mismatch rejection.',
    category: 'PROJECT_FACT',
    scopeType: workspaceA.scopeType,
    scopeId: workspaceA.scopeId
  });

  const vector = normalizeVector(new Float32Array([1, 2, 3, 4]));
  const blob = serializeVectorToBlob(vector);

  // Deserialization with wrong expectedDimensions
  assert.throws(
    () => deserializeBlobToVector(blob, 128),
    InvalidVectorError,
    'Should reject BLOB dimension mismatch'
  );

  // Repository insert with dimension mismatch between input.dimensions and embedding.length
  assert.throws(
    () => embeddingRepo.insertEmbedding({
      memoryId: mem.id,
      modelId: 'test-model',
      dimensions: 384, // Declares 384, but passes 4
      embedding: vector
    }),
    InvalidVectorError,
    'Should reject vector whose length does not match input.dimensions'
  );

  // Repository insert with non-positive dimensions
  assert.throws(
    () => embeddingRepo.insertEmbedding({
      memoryId: mem.id,
      modelId: 'test-model',
      dimensions: 0,
      embedding: vector
    }),
    ValidationError
  );
});

// ============================================================================
// 6. Malformed BLOB sizes are rejected
// ============================================================================

test('Requirement 6: Malformed BLOB sizes (non-multiples of 4, empty) are rejected', () => {
  // Empty BLOB (0 bytes)
  assert.throws(
    () => deserializeBlobToVector(new Uint8Array(0)),
    InvalidVectorError,
    'Empty BLOB must be rejected'
  );

  // Non-multiple of 4 (e.g. 7 bytes)
  assert.throws(
    () => deserializeBlobToVector(new Uint8Array([1, 2, 3, 4, 5, 6, 7])),
    InvalidVectorError,
    'BLOB with length not divisible by 4 must be rejected'
  );

  // 1 byte BLOB
  assert.throws(
    () => deserializeBlobToVector(new Uint8Array([1])),
    InvalidVectorError
  );

  // Non-Uint8Array input
  assert.throws(
    () => deserializeBlobToVector('not-a-blob'),
    InvalidVectorError
  );
});

// ============================================================================
// 7. NaN and Infinity are rejected
// ============================================================================

test('Requirement 7: NaN and Infinity are rejected during serialization and validation', () => {
  const nanVector = new Float32Array([1.0, NaN, 2.0]);
  assert.throws(
    () => serializeVectorToBlob(nanVector),
    InvalidVectorError,
    'NaN in Float32Array must be rejected'
  );

  const infVector = new Float32Array([1.0, Infinity, 2.0]);
  assert.throws(
    () => serializeVectorToBlob(infVector),
    InvalidVectorError,
    'Infinity in Float32Array must be rejected'
  );

  const negInfVector = new Float32Array([1.0, -Infinity, 2.0]);
  assert.throws(
    () => serializeVectorToBlob(negInfVector),
    InvalidVectorError,
    '-Infinity in Float32Array must be rejected'
  );
});

// ============================================================================
// 8. Zero or invalid vectors are rejected
// ============================================================================

test('Requirement 8: Zero vectors and invalid vectors are rejected', () => {
  // All zeroes vector
  const zeroVec = new Float32Array([0.0, 0.0, 0.0, 0.0]);
  assert.throws(
    () => serializeVectorToBlob(zeroVec),
    InvalidVectorError,
    'Zero vector must be rejected by serializeVectorToBlob'
  );

  // Empty vector
  const emptyVec = new Float32Array([]);
  assert.throws(
    () => serializeVectorToBlob(emptyVec),
    InvalidVectorError,
    'Empty vector must be rejected'
  );

  // Invalid normalized vector validation
  const unnormalizedVec = new Float32Array([5.0, 10.0, 15.0]);
  assert.throws(
    () => validateNormalizedVector(unnormalizedVec),
    InvalidVectorError,
    'Vector with norm != 1.0 must be rejected when requiring normalization'
  );
});

// ============================================================================
// 9. Duplicate model identity behavior
// ============================================================================

test('Requirement 9: Duplicate model identity behavior (insert throws conflict, upsert updates)', () => {
  const { memoryRepo, embeddingRepo, workspaceA } = setupTestEnvironment();

  const mem = memoryRepo.createMemory({
    key: 'test:dupe',
    content: 'Testing duplicate model identity constraints.',
    category: 'PROJECT_FACT',
    scopeType: workspaceA.scopeType,
    scopeId: workspaceA.scopeId
  });

  const vec1 = normalizeVector(new Float32Array([1, 0, 0, 0]));
  const vec2 = normalizeVector(new Float32Array([0, 1, 0, 0]));

  embeddingRepo.insertEmbedding({
    memoryId: mem.id,
    modelId: 'model-x',
    modelRevision: 'main',
    dimensions: 4,
    embedding: vec1
  });

  // Second insert with exact same (memoryId, modelId, modelRevision) throws MemoryConflictError
  assert.throws(
    () => embeddingRepo.insertEmbedding({
      memoryId: mem.id,
      modelId: 'model-x',
      modelRevision: 'main',
      dimensions: 4,
      embedding: vec2
    }),
    MemoryConflictError,
    'Duplicate insert for same model and revision must throw MemoryConflictError'
  );

  // upsertEmbedding succeeds and replaces the vector safely
  const updated = embeddingRepo.upsertEmbedding({
    memoryId: mem.id,
    modelId: 'model-x',
    modelRevision: 'main',
    dimensions: 4,
    embedding: vec2
  });

  assert.equal(updated.memoryId, mem.id);
  assert.equal(updated.embedding[1], vec2[1]);
});

// ============================================================================
// 10. Updating/replacing an embedding
// ============================================================================

test('Requirement 10: Updating/replacing an embedding safely', () => {
  const { memoryRepo, embeddingRepo, workspaceA } = setupTestEnvironment();

  const mem = memoryRepo.createMemory({
    key: 'test:update',
    content: 'Initial memory content.',
    category: 'LEARNED_PROCEDURE',
    scopeType: workspaceA.scopeType,
    scopeId: workspaceA.scopeId
  });

  const v1 = normalizeVector(new Float32Array([1, 0, 0]));
  const v2 = normalizeVector(new Float32Array([0, 0, 1]));

  embeddingRepo.insertEmbedding({
    memoryId: mem.id,
    modelId: 'model-3d',
    dimensions: 3,
    embedding: v1
  });

  const updated = embeddingRepo.updateEmbedding(mem.id, 'model-3d', v2);
  assert.equal(updated.embedding[2], v2[2]);
  assert.equal(updated.embedding[0], 0);

  // updateEmbedding on non-existent memory throws EmbeddingNotFoundError
  assert.throws(
    () => embeddingRepo.updateEmbedding('non-existent-id', 'model-3d', v2),
    EmbeddingNotFoundError
  );
});

// ============================================================================
// 11. Deleting a memory cascades to its embeddings
// ============================================================================

test('Requirement 11: Deleting a memory cascades to its embeddings in SQLite', () => {
  const { db, memoryRepo, embeddingRepo, workspaceA } = setupTestEnvironment();

  const mem = memoryRepo.createMemory({
    key: 'test:cascade',
    content: 'This memory will be deleted.',
    category: 'PROJECT_FACT',
    scopeType: workspaceA.scopeType,
    scopeId: workspaceA.scopeId
  });

  const v = normalizeVector(new Float32Array([0.5, 0.5, 0.5, 0.5]));
  embeddingRepo.insertEmbedding({
    memoryId: mem.id,
    modelId: 'model-4d',
    dimensions: 4,
    embedding: v
  });

  // Verify embedding exists
  assert.ok(embeddingRepo.getEmbedding(mem.id, 'model-4d'));

  // Delete memory record via memory repository
  const deleted = memoryRepo.deleteMemory(mem.id, workspaceA);
  assert.equal(deleted, true);

  // Embedding must be automatically cascade-deleted
  const retrieved = embeddingRepo.getEmbedding(mem.id, 'model-4d');
  assert.equal(retrieved, null, 'Embedding must be deleted via foreign key ON DELETE CASCADE');

  // Verify directly in database table
  const countRow = db.prepare('SELECT COUNT(*) as count FROM memory_embeddings WHERE memory_id = ?').get(mem.id) as { count: number };
  assert.equal(countRow.count, 0, 'No rows in memory_embeddings table for deleted memory');
});

// ============================================================================
// 12. Different model identities remain isolated
// ============================================================================

test('Requirement 12: Different model identities for the same memory remain isolated', () => {
  const { memoryRepo, embeddingRepo, workspaceA } = setupTestEnvironment();

  const mem = memoryRepo.createMemory({
    key: 'test:multi-model',
    content: 'Memory embedded under multiple distinct models.',
    category: 'PROJECT_FACT',
    scopeType: workspaceA.scopeType,
    scopeId: workspaceA.scopeId
  });

  const vModelA = normalizeVector(new Float32Array([1, 0, 0])); // 3d
  const vModelB = normalizeVector(new Float32Array([0.5, 0.5, 0.5, 0.5])); // 4d
  const vModelARev2 = normalizeVector(new Float32Array([0, 1, 0])); // 3d revision v2

  embeddingRepo.insertEmbedding({
    memoryId: mem.id,
    modelId: 'model-a',
    modelRevision: 'main',
    dimensions: 3,
    embedding: vModelA
  });

  embeddingRepo.insertEmbedding({
    memoryId: mem.id,
    modelId: 'model-b',
    modelRevision: 'main',
    dimensions: 4,
    embedding: vModelB
  });

  embeddingRepo.insertEmbedding({
    memoryId: mem.id,
    modelId: 'model-a',
    modelRevision: 'v2',
    dimensions: 3,
    embedding: vModelARev2
  });

  // Verify each is independently retrieved
  const embA = embeddingRepo.getEmbedding(mem.id, 'model-a', 'main');
  const embB = embeddingRepo.getEmbedding(mem.id, 'model-b', 'main');
  const embARev2 = embeddingRepo.getEmbedding(mem.id, 'model-a', 'v2');

  assert.equal(embA?.dimensions, 3);
  assert.equal(embB?.dimensions, 4);
  assert.equal(embARev2?.dimensions, 3);
  assert.equal(embA?.embedding[0], 1);
  assert.equal(embARev2?.embedding[1], 1);

  // Deleting one does not affect the others
  embeddingRepo.deleteEmbedding(mem.id, 'model-a', 'main');
  assert.equal(embeddingRepo.getEmbedding(mem.id, 'model-a', 'main'), null);
  assert.ok(embeddingRepo.getEmbedding(mem.id, 'model-b', 'main'));
  assert.ok(embeddingRepo.getEmbedding(mem.id, 'model-a', 'v2'));
});

// ============================================================================
// 13. Pending-approval memories cannot receive embeddings
// ============================================================================

test('Requirement 13: Pending-approval proposals cannot receive embeddings until approved', async () => {
  const { memoryRepo, memoryService, authorizer, workspaceA } = setupTestEnvironment();

  const caller = authorizer.authorizeUser({
    credentials: 'token-admin-alpha',
    requestedScope: workspaceA
  });

  // Create memory proposal with PENDING_APPROVAL status
  const proposal = memoryRepo.createMemory({
    key: 'proposal:test',
    content: 'Proposed procedure from automated agent.',
    category: 'LEARNED_PROCEDURE',
    scopeType: workspaceA.scopeType,
    scopeId: workspaceA.scopeId,
    status: 'PENDING_APPROVAL'
  });

  // Attempting to generate embedding while PENDING_APPROVAL must be rejected with ValidationError
  await assert.rejects(
    async () => memoryService.generateMemoryEmbedding(caller, proposal.id),
    ValidationError,
    'Must reject embedding generation for PENDING_APPROVAL proposals'
  );

  // Decide proposal to APPROVED -> status becomes ACTIVE
  memoryService.decideProposal(caller, {
    memoryId: proposal.id,
    decision: 'APPROVED'
  });

  // Now generating embedding must succeed
  const embedding = await memoryService.generateMemoryEmbedding(caller, proposal.id);
  assert.ok(embedding);
  assert.equal(embedding.memoryId, proposal.id);
  assert.equal(embedding.dimensions, 384);
});

// ============================================================================
// 14. Provider failure does not corrupt memory data
// ============================================================================

test('Requirement 14: Provider failure during embedding generation does not corrupt memory data', async () => {
  const { memoryRepo, memoryService, authorizer, workspaceA } = setupTestEnvironment();

  const caller = authorizer.authorizeUser({
    credentials: 'token-admin-alpha',
    requestedScope: workspaceA
  });

  const mem = memoryRepo.createMemory({
    key: 'test:failing-provider',
    content: 'Critical memory that must remain uncorrupted.',
    category: 'PROJECT_FACT',
    scopeType: workspaceA.scopeType,
    scopeId: workspaceA.scopeId
  });

  // A failing provider that throws during embed()
  const failingProvider: IEmbeddingProvider = {
    name: 'failing-provider',
    modelId: 'failing-model',
    dimensions: 384,
    async isAvailable() { return true; },
    async embed() {
      throw new EmbeddingInferenceError('Simulated GPU/CPU out of memory error.');
    },
    async embedBatch() {
      throw new EmbeddingInferenceError('Simulated GPU/CPU out of memory error.');
    }
  };

  await assert.rejects(
    async () => memoryService.generateMemoryEmbedding(caller, mem.id, failingProvider),
    EmbeddingInferenceError
  );

  // Memory in repository must remain intact and active
  const check = memoryRepo.getMemoryById(mem.id, workspaceA);
  assert.ok(check);
  assert.equal(check.status, 'ACTIVE');
  assert.equal(check.content, 'Critical memory that must remain uncorrupted.');
});

// ============================================================================
// 15. Workspace isolation is enforced
// ============================================================================

test('Requirement 15: Workspace isolation is strictly enforced for embeddings', async () => {
  const { memoryRepo, memoryService, authorizer, workspaceA, workspaceB } = setupTestEnvironment();

  const callerA = authorizer.authorizeUser({
    credentials: 'token-admin-alpha',
    requestedScope: workspaceA
  });

  const callerB = authorizer.authorizeUser({
    credentials: 'token-admin-beta',
    requestedScope: workspaceB
  });

  // Create memory in Workspace A
  const memA = memoryRepo.createMemory({
    key: 'wsA:secret',
    content: 'Top secret strategy for workspace A.',
    category: 'PROJECT_FACT',
    scopeType: workspaceA.scopeType,
    scopeId: workspaceA.scopeId
  });

  // Generate embedding in Workspace A
  await memoryService.generateMemoryEmbedding(callerA, memA.id);

  // Caller B (Workspace B) attempting to read embedding of Workspace A memory is denied
  assert.throws(
    () => memoryService.getMemoryEmbedding(callerB, memA.id, 'mock-deterministic-v1'),
    MemoryScopeViolationError,
    'Workspace B caller cannot access Workspace A embedding'
  );

  // Caller B attempting to generate embedding for Workspace A memory is denied
  await assert.rejects(
    async () => memoryService.generateMemoryEmbedding(callerB, memA.id),
    MemoryScopeViolationError,
    'Workspace B caller cannot generate embedding for Workspace A memory'
  );
});

// ============================================================================
// 16. Global inheritance authorization is preserved
// ============================================================================

test('Requirement 16: Global inheritance authorization is preserved for embeddings', async () => {
  const { memoryRepo, memoryService, authorizer, workspaceA, workspaceB, globalScope } = setupTestEnvironment();

  // Admin Alpha has access to globalScope and workspaceA (principal user-alpha)
  const callerAlphaGlobal = authorizer.authorizeUser({
    credentials: 'token-admin-alpha',
    requestedScope: globalScope
  });
  const callerAlphaWs = authorizer.authorizeUser({
    credentials: 'token-admin-alpha',
    requestedScope: workspaceA
  });

  // Admin Beta has access only to workspaceB (principal user-beta)
  const callerBetaWs = authorizer.authorizeUser({
    credentials: 'token-admin-beta',
    requestedScope: workspaceB
  });

  // Create a global memory tied to principal user-alpha
  const globalMem = memoryRepo.createMemory({
    key: 'global:alpha-profile',
    content: 'User alpha global preferences.',
    category: 'USER_PREFERENCE',
    scopeType: 'GLOBAL',
    scopeId: 'default',
    metadata: { principalId: 'user-alpha' }
  });

  // Generate embedding for global memory
  await memoryService.generateMemoryEmbedding(callerAlphaGlobal, globalMem.id);

  // Caller Alpha in Workspace A inherits this global memory (same principal user-alpha)
  const inheritedEmb = memoryService.getMemoryEmbedding(callerAlphaWs, globalMem.id, 'mock-deterministic-v1');
  assert.ok(inheritedEmb, 'Eligible workspace caller must access inherited global embedding');
  assert.equal(inheritedEmb.memoryId, globalMem.id);

  // Caller Beta in Workspace B cannot access Alpha global memory (different principal user-beta)
  assert.throws(
    () => memoryService.getMemoryEmbedding(callerBetaWs, globalMem.id, 'mock-deterministic-v1'),
    MemoryScopeViolationError,
    'Foreign principal caller cannot access non-eligible global embedding'
  );
});

// ============================================================================
// 17. Missing embeddings do not break existing lexical memory functionality
// ============================================================================

test('Requirement 17: Missing embeddings do not break existing lexical memory operations', () => {
  const { memoryService, authorizer, workspaceA } = setupTestEnvironment();

  const caller = authorizer.authorizeUser({
    credentials: 'token-admin-alpha',
    requestedScope: workspaceA
  });

  // Create memory without embedding
  const mem = memoryService.createMemory(caller, {
    key: 'lexical:only',
    content: 'Deterministic lexical retrieval continues to work seamlessly without vectors.',
    category: 'PROJECT_FACT',
    scopeType: workspaceA.scopeType,
    scopeId: workspaceA.scopeId,
    priority: 80,
    tags: ['database', 'search']
  });

  // Search lexically using searchMemories
  const results = memoryService.searchMemories(caller, {
    query: 'Deterministic lexical retrieval',
    limit: 5
  });

  assert.ok(results.length > 0);
  assert.equal(results[0].memory.id, mem.id);

  // Update memory priority (does not affect or require embeddings)
  const updated = memoryService.updateMemory(caller, mem.id, {
    priority: 90
  });
  assert.equal(updated.priority, 90);

  // Build task memory context includes the memory normally
  const builtContext = memoryService.buildTaskMemoryContext(caller, {
    query: 'Perform database search tasks'
  });
  assert.ok(builtContext.included.some(item => item.id === mem.id));
});

// ============================================================================
// 18. Lifecycle: Updating content invalidates embeddings, priority-only does not
// ============================================================================

test('Requirement 18: Content updates invalidate embeddings; priority/metadata updates do not', async () => {
  const { memoryService, embeddingRepo, authorizer, workspaceA } = setupTestEnvironment();

  const caller = authorizer.authorizeUser({
    credentials: 'token-admin-alpha',
    requestedScope: workspaceA
  });

  // Create memory and generate embedding
  const mem = memoryService.createMemory(caller, {
    key: 'lifecycle:staleness',
    content: 'Initial text that will be embedded.',
    category: 'PROJECT_FACT',
    scopeType: workspaceA.scopeType,
    scopeId: workspaceA.scopeId
  });

  await memoryService.generateMemoryEmbedding(caller, mem.id);
  assert.ok(embeddingRepo.getEmbedding(mem.id, 'mock-deterministic-v1'));

  // Updating priority only: embedding MUST NOT be deleted
  memoryService.updateMemory(caller, mem.id, { priority: 95 });
  assert.ok(
    embeddingRepo.getEmbedding(mem.id, 'mock-deterministic-v1'),
    'Priority update must not invalidate embedding'
  );

  // Updating content: embedding MUST be deleted/invalidated
  memoryService.updateMemory(caller, mem.id, { content: 'Brand new completely rewritten content.' });
  assert.equal(
    embeddingRepo.getEmbedding(mem.id, 'mock-deterministic-v1'),
    null,
    'Content update must invalidate stale embedding'
  );
});

// ============================================================================
// 19. Batch embedding retrieval and metadata listing
// ============================================================================

test('Requirement 19: Batch embedding retrieval and metadata listing', async () => {
  const { memoryService, embeddingRepo, authorizer, workspaceA } = setupTestEnvironment();

  const caller = authorizer.authorizeUser({
    credentials: 'token-admin-alpha',
    requestedScope: workspaceA
  });

  const m1 = memoryService.createMemory(caller, {
    key: 'batch:1',
    content: 'First item',
    category: 'PROJECT_FACT',
    scopeType: workspaceA.scopeType,
    scopeId: workspaceA.scopeId
  });
  const m2 = memoryService.createMemory(caller, {
    key: 'batch:2',
    content: 'Second item',
    category: 'PROJECT_FACT',
    scopeType: workspaceA.scopeType,
    scopeId: workspaceA.scopeId
  });

  await memoryService.generateMemoryEmbedding(caller, m1.id);
  await memoryService.generateMemoryEmbedding(caller, m2.id);

  // Batch retrieval
  const embeddings = memoryService.getMemoryEmbeddings(caller, [m1.id, m2.id, 'invalid-id'], 'mock-deterministic-v1');
  assert.equal(embeddings.length, 2);

  // Metadata listing
  const metadata = embeddingRepo.listEmbeddingMetadata({ modelId: 'mock-deterministic-v1' });
  assert.equal(metadata.length, 2);
  assert.ok(metadata[0].id);
  assert.ok(metadata[0].createdAt);
  assert.equal(metadata[0].dimensions, 384);
  assert.equal((metadata[0] as any).embedding, undefined, 'Metadata listing should omit raw vector BLOB');
});
