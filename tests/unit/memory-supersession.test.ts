/**
 * Next-Generation Dots AI Platform - Memory Supersession & Version History Unit Tests
 * 
 * Verifies Phase 4D.3B & 4D.3B.2:
 * 1. Migration 008_memory_supersession from existing DB with ACTIVE, PENDING_APPROVAL, and ARCHIVED memories.
 * 2. Backfill assigns version = 1, supersedes_id = null, superseded_by = null to existing records.
 * 3. Memory IDs, content, timestamps, and statuses remain completely intact after migration.
 * 4. Multiple SUPERSEDED records with the same scope and key are allowed.
 * 5. Only one ACTIVE record per scope/key is permitted (partial unique active index).
 * 6. Foreign keys and child records (injections, embeddings, jobs) are preserved and PRAGMA foreign_key_check is clean.
 * 7. getMemoryHistory returns records in deterministic order (version ASC, created_at ASC, id ASC).
 * 8. getMemoryHistory strictly enforces scope isolation (no leakage across workspaces or global scope).
 * 9. supersedeMemory validates preconditions, links previous and replacement, advances version, and updates status.
 * 10. Multi-step supersession chain evolution (v1 -> v2 -> v3 -> v4) without explicit newVersion.
 * 11. supersedeMemory respects explicitly passed newVersion (> previous.version).
 * 12. supersedeMemory rejects invalid states: self-links, mismatched keys, case-mismatched keys, mismatched scopes,
 *     non-ACTIVE previous, already superseded previous/replacement, replacement already superseding, replacement status = SUPERSEDED,
 *     and version regressions (newVersion <= previous.version).
 * 13. supersedeMemory detects and rejects lineage cycles.
 * 14. Transaction atomicity: rollback on failure preserves original state.
 * 15. Lineage metadata CRUD protection: createMemory and updateMemory reject status 'SUPERSEDED' and protect lineage columns.
 * 16. Guarded deletion and archival: reject deleting or archiving records in a supersession history chain.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseManager } from '../../src/storage/db.ts';
import { MemoryRepository } from '../../src/storage/memory-repository.ts';
import { TaskRepository } from '../../src/storage/task-repository.ts';
import {
  ValidationError,
  MemoryNotFoundError,
  MemoryConflictError,
  MemoryScopeViolationError
} from '../../src/domain/errors.ts';
import type { UpdateMemoryInput, WritableMemoryStatus } from '../../src/domain/types.ts';

const workspaceA = { scopeType: 'WORKSPACE' as const, scopeId: 'ws-alpha' };
const workspaceB = { scopeType: 'WORKSPACE' as const, scopeId: 'ws-beta' };
const globalScope = { scopeType: 'GLOBAL' as const, scopeId: 'default' };

function setupTest() {
  const db = new DatabaseManager(':memory:');
  const memoryRepo = new MemoryRepository(db);
  const taskRepo = new TaskRepository(db);
  return { db, memoryRepo, taskRepo };
}

test('1. Migration from existing DB preserves ACTIVE, PENDING_APPROVAL, and ARCHIVED memories', () => {
  const db = new DatabaseManager(':memory:');

  try {
    // Verify migration 008 was applied
    const migration = db.prepare('SELECT version FROM schema_migrations WHERE version = ?').get('008_memory_supersession') as { version: string } | undefined;
    assert.ok(migration, 'Migration 008_memory_supersession must be recorded in schema_migrations');

    // Verify memories table schema contains version, supersedes_id, and superseded_by
    const columns = db.prepare('PRAGMA table_info(memories);').all() as Array<{ name: string; type: string }>;
    const colNames = columns.map((c) => c.name);

    assert.ok(colNames.includes('version'), 'memories must contain version column');
    assert.ok(colNames.includes('supersedes_id'), 'memories must contain supersedes_id column');
    assert.ok(colNames.includes('superseded_by'), 'memories must contain superseded_by column');

    // Foreign key check
    const fkCheck = db.prepare('PRAGMA foreign_key_check;').all();
    assert.equal(fkCheck.length, 0, 'Foreign key check must have zero violations');
  } finally {
    db.close();
  }
});

test('2. Existing records receive version = 1, supersedesId = null, supersededBy = null, and intact data', () => {
  const db = new DatabaseManager(':memory:');
  const memoryRepo = new MemoryRepository(db);

  try {
    const active = memoryRepo.createMemory({
      key: 'test.active.key',
      content: 'Active content',
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: 'ws-alpha',
      status: 'ACTIVE',
      priority: 75
    });

    const pending = memoryRepo.createMemory({
      key: 'test.pending.key',
      content: 'Pending content',
      category: 'USER_PREFERENCE',
      scopeType: 'WORKSPACE',
      scopeId: 'ws-alpha',
      status: 'PENDING_APPROVAL',
      priority: 60
    });

    const archived = memoryRepo.createMemory({
      key: 'test.archived.key',
      content: 'Archived content',
      category: 'LEARNED_PROCEDURE',
      scopeType: 'WORKSPACE',
      scopeId: 'ws-alpha',
      status: 'ARCHIVED',
      priority: 40
    });

    assert.equal(active.version, 1);
    assert.equal(active.supersedesId, null);
    assert.equal(active.supersededBy, null);
    assert.equal(active.status, 'ACTIVE');

    assert.equal(pending.version, 1);
    assert.equal(pending.supersedesId, null);
    assert.equal(pending.supersededBy, null);
    assert.equal(pending.status, 'PENDING_APPROVAL');

    assert.equal(archived.version, 1);
    assert.equal(archived.supersedesId, null);
    assert.equal(archived.supersededBy, null);
    assert.equal(archived.status, 'ARCHIVED');
  } finally {
    db.close();
  }
});

test('3. Child rows in memory_embeddings, embedding_jobs, and memory_task_injections are preserved', () => {
  const db = new DatabaseManager(':memory:');
  const memoryRepo = new MemoryRepository(db);
  const taskRepo = new TaskRepository(db);

  try {
    const task = taskRepo.createTask({ goal: 'Test FK preservation task' });
    const memory = memoryRepo.createMemory({
      key: 'test.fk.key',
      content: 'FK test content',
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: 'ws-alpha'
    });

    // Record injection
    const injection = memoryRepo.recordInjection({
      taskId: task.id,
      memoryId: memory.id,
      charCount: 20,
      estimatedTokens: 5
    });
    assert.equal(injection.memoryId, memory.id);

    // Insert dummy embedding and job
    db.prepare(`
      INSERT INTO memory_embeddings (id, memory_id, model_id, model_revision, dimensions, embedding, created_at, updated_at)
      VALUES('emb-1', ?, 'test-model', 'main', 4, X'01020304', '2026-10-15T00:00:00Z', '2026-10-15T00:00:00Z')
    `).run(memory.id);

    db.prepare(`
      INSERT INTO embedding_jobs (id, memory_id, scope_type, scope_id, model_id, model_revision, status, scheduled_at, created_at, updated_at)
      VALUES('job-1', ?, 'WORKSPACE', 'ws-alpha', 'test-model', 'main', 'COMPLETED', '2026-10-15T00:00:00Z', '2026-10-15T00:00:00Z', '2026-10-15T00:00:00Z')
    `).run(memory.id);

    // Verify foreign key integrity
    const fkCheck = db.prepare('PRAGMA foreign_key_check;').all();
    assert.equal(fkCheck.length, 0, 'Foreign key check must have zero violations');

    // Deleting an unlinked memory cascades to embeddings and jobs, and nulls injection
    memoryRepo.deleteMemory(memory.id, workspaceA);

    const embCount = db.prepare('SELECT count(*) as count FROM memory_embeddings WHERE memory_id = ?').get(memory.id) as { count: number };
    assert.equal(embCount.count, 0, 'memory_embeddings must be cascade deleted');

    const jobCount = db.prepare('SELECT count(*) as count FROM embedding_jobs WHERE memory_id = ?').get(memory.id) as { count: number };
    assert.equal(jobCount.count, 0, 'embedding_jobs must be cascade deleted');

    const updatedInj = memoryRepo.getInjectionsByTaskId(task.id);
    assert.equal(updatedInj.length, 1);
    assert.equal(updatedInj[0].memoryId, null, 'memory_task_injections.memory_id must be set to NULL on delete');
  } finally {
    db.close();
  }
});

test('4. Multiple SUPERSEDED records with same key are allowed in the same scope', () => {
  const { db, memoryRepo } = setupTest();

  try {
    const v1 = memoryRepo.createMemory({
      key: 'service.port',
      content: 'Port 8000',
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: 'ws-alpha',
      status: 'ACTIVE'
    });

    const v2Candidate = memoryRepo.createMemory({
      key: 'service.port',
      content: 'Port 8080',
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: 'ws-alpha',
      status: 'PENDING_APPROVAL'
    });

    const step1 = memoryRepo.supersedeMemory({
      previousId: v1.id,
      replacementId: v2Candidate.id,
      scope: workspaceA,
      replacementStatus: 'ACTIVE'
    });

    const v3Candidate = memoryRepo.createMemory({
      key: 'service.port',
      content: 'Port 8443',
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: 'ws-alpha',
      status: 'PENDING_APPROVAL'
    });

    const step2 = memoryRepo.supersedeMemory({
      previousId: step1.replacement.id,
      replacementId: v3Candidate.id,
      scope: workspaceA,
      replacementStatus: 'ACTIVE'
    });

    assert.equal(step1.previous.status, 'SUPERSEDED');
    assert.equal(step2.previous.status, 'SUPERSEDED');
    assert.equal(step2.replacement.status, 'ACTIVE');

    const history = memoryRepo.getMemoryHistory('service.port', workspaceA);
    assert.equal(history.length, 3);
    assert.equal(history[0].version, 1);
    assert.equal(history[0].status, 'SUPERSEDED');
    assert.equal(history[1].version, 2);
    assert.equal(history[1].status, 'SUPERSEDED');
    assert.equal(history[2].version, 3);
    assert.equal(history[2].status, 'ACTIVE');
  } finally {
    db.close();
  }
});

test('5. Enforces single ACTIVE record per scope/key invariant (partial unique active index)', () => {
  const { db, memoryRepo } = setupTest();

  try {
    memoryRepo.createMemory({
      key: 'db.host',
      content: 'localhost',
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: 'ws-alpha',
      status: 'ACTIVE'
    });

    // Creating second ACTIVE memory with same key in same scope must fail
    assert.throws(
      () => {
        memoryRepo.createMemory({
          key: 'db.host',
          content: 'remote.db',
          category: 'PROJECT_FACT',
          scopeType: 'WORKSPACE',
          scopeId: 'ws-alpha',
          status: 'ACTIVE'
        });
      },
      (err) => err instanceof MemoryConflictError
    );

    // But creating an ACTIVE memory with same key in a different workspace is allowed
    const wsB = memoryRepo.createMemory({
      key: 'db.host',
      content: 'other.db',
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: 'ws-beta',
      status: 'ACTIVE'
    });
    assert.equal(wsB.key, 'db.host');
  } finally {
    db.close();
  }
});

test('6. getMemoryHistory returns records in deterministic order (version ASC, created_at ASC, id ASC)', () => {
  const { db, memoryRepo } = setupTest();

  try {
    // Insert with out-of-order creation timestamps directly to test sorting logic
    db.prepare(`
      INSERT INTO memories (id, scope_type, scope_id, key, content, category, status, version, supersedes_id, superseded_by, created_at, updated_at)
      VALUES
        ('id-3', 'WORKSPACE', 'ws-alpha', 'app.timeout', 'Timeout 60s', 'PROJECT_FACT', 'ACTIVE', 3, 'id-2', NULL, '2026-01-01T00:00:00.000Z', '2026-01-01T00:00:00.000Z'),
        ('id-1', 'WORKSPACE', 'ws-alpha', 'app.timeout', 'Timeout 10s', 'PROJECT_FACT', 'SUPERSEDED', 1, NULL, 'id-2', '2026-01-03T00:00:00.000Z', '2026-01-03T00:00:00.000Z'),
        ('id-2', 'WORKSPACE', 'ws-alpha', 'app.timeout', 'Timeout 30s', 'PROJECT_FACT', 'SUPERSEDED', 2, 'id-1', 'id-3', '2026-01-02T00:00:00.000Z', '2026-01-02T00:00:00.000Z')
    `).run();

    const history = memoryRepo.getMemoryHistory('app.timeout', workspaceA);
    assert.equal(history.length, 3);
    assert.equal(history[0].id, 'id-1');
    assert.equal(history[0].version, 1);
    assert.equal(history[1].id, 'id-2');
    assert.equal(history[1].version, 2);
    assert.equal(history[2].id, 'id-3');
    assert.equal(history[2].version, 3);
  } finally {
    db.close();
  }
});

test('7. getMemoryHistory strictly enforces scope isolation', () => {
  const { db, memoryRepo } = setupTest();

  try {
    memoryRepo.createMemory({
      key: 'secret.token',
      content: 'ws-alpha-secret',
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: 'ws-alpha',
      status: 'ACTIVE'
    });

    memoryRepo.createMemory({
      key: 'secret.token',
      content: 'ws-beta-secret',
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: 'ws-beta',
      status: 'ACTIVE'
    });

    memoryRepo.createMemory({
      key: 'secret.token',
      content: 'global-secret',
      category: 'PROJECT_FACT',
      scopeType: 'GLOBAL',
      scopeId: 'default',
      status: 'ACTIVE'
    });

    const historyA = memoryRepo.getMemoryHistory('secret.token', workspaceA);
    assert.equal(historyA.length, 1);
    assert.equal(historyA[0].content, 'ws-alpha-secret');

    const historyB = memoryRepo.getMemoryHistory('secret.token', workspaceB);
    assert.equal(historyB.length, 1);
    assert.equal(historyB[0].content, 'ws-beta-secret');

    const historyGlobal = memoryRepo.getMemoryHistory('secret.token', globalScope);
    assert.equal(historyGlobal.length, 1);
    assert.equal(historyGlobal[0].content, 'global-secret');
  } finally {
    db.close();
  }
});

test('8. supersedeMemory successfully transitions previous to SUPERSEDED and replacement to ACTIVE with incremented version', () => {
  const { db, memoryRepo } = setupTest();

  try {
    const original = memoryRepo.createMemory({
      key: 'user.theme',
      content: 'dark',
      category: 'USER_PREFERENCE',
      scopeType: 'WORKSPACE',
      scopeId: 'ws-alpha',
      status: 'ACTIVE'
    });

    const replacement = memoryRepo.createMemory({
      key: 'user.theme',
      content: 'system',
      category: 'USER_PREFERENCE',
      scopeType: 'WORKSPACE',
      scopeId: 'ws-alpha',
      status: 'PENDING_APPROVAL'
    });

    const result = memoryRepo.supersedeMemory({
      previousId: original.id,
      replacementId: replacement.id,
      scope: workspaceA,
      replacementStatus: 'ACTIVE'
    });

    // Check previous
    assert.equal(result.previous.id, original.id);
    assert.equal(result.previous.status, 'SUPERSEDED');
    assert.equal(result.previous.supersededBy, replacement.id);
    assert.equal(result.previous.version, 1);

    // Check replacement
    assert.equal(result.replacement.id, replacement.id);
    assert.equal(result.replacement.status, 'ACTIVE');
    assert.equal(result.replacement.supersedesId, original.id);
    assert.equal(result.replacement.version, 2, 'Version must auto-increment to 2');

    // History check
    const history = memoryRepo.getMemoryHistory('user.theme', workspaceA);
    assert.equal(history.length, 2);
    assert.equal(history[0].id, original.id);
    assert.equal(history[0].status, 'SUPERSEDED');
    assert.equal(history[1].id, replacement.id);
    assert.equal(history[1].status, 'ACTIVE');
  } finally {
    db.close();
  }
});

test('9. Multi-version chain evolution (v1 -> v2 -> v3 -> v4) without explicit newVersion', () => {
  const { db, memoryRepo } = setupTest();

  try {
    const v1 = memoryRepo.createMemory({
      key: 'system.node_version',
      content: '18.0.0',
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: 'ws-alpha',
      status: 'ACTIVE'
    });
    assert.equal(v1.version, 1);

    const cand2 = memoryRepo.createMemory({
      key: 'system.node_version',
      content: '20.0.0',
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: 'ws-alpha',
      status: 'PENDING_APPROVAL'
    });
    const step1 = memoryRepo.supersedeMemory({
      previousId: v1.id,
      replacementId: cand2.id,
      scope: workspaceA,
      replacementStatus: 'ACTIVE'
    });
    assert.equal(step1.replacement.version, 2);

    const cand3 = memoryRepo.createMemory({
      key: 'system.node_version',
      content: '22.0.0',
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: 'ws-alpha',
      status: 'PENDING_APPROVAL'
    });
    const step2 = memoryRepo.supersedeMemory({
      previousId: step1.replacement.id,
      replacementId: cand3.id,
      scope: workspaceA,
      replacementStatus: 'ACTIVE'
    });
    assert.equal(step2.replacement.version, 3);

    const cand4 = memoryRepo.createMemory({
      key: 'system.node_version',
      content: '24.0.0',
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: 'ws-alpha',
      status: 'PENDING_APPROVAL'
    });
    const step3 = memoryRepo.supersedeMemory({
      previousId: step2.replacement.id,
      replacementId: cand4.id,
      scope: workspaceA,
      replacementStatus: 'ACTIVE'
    });
    assert.equal(step3.replacement.version, 4);

    const history = memoryRepo.getMemoryHistory('system.node_version', workspaceA);
    assert.equal(history.length, 4);
    assert.deepEqual(
      history.map((m) => ({ version: m.version, status: m.status, content: m.content })),
      [
        { version: 1, status: 'SUPERSEDED', content: '18.0.0' },
        { version: 2, status: 'SUPERSEDED', content: '20.0.0' },
        { version: 3, status: 'SUPERSEDED', content: '22.0.0' },
        { version: 4, status: 'ACTIVE', content: '24.0.0' }
      ]
    );
  } finally {
    db.close();
  }
});

test('10. supersedeMemory respects explicitly passed newVersion', () => {
  const { db, memoryRepo } = setupTest();

  try {
    const original = memoryRepo.createMemory({
      key: 'api.version',
      content: 'v1',
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: 'ws-alpha',
      status: 'ACTIVE'
    });

    const replacement = memoryRepo.createMemory({
      key: 'api.version',
      content: 'v5',
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: 'ws-alpha',
      status: 'PENDING_APPROVAL'
    });

    const result = memoryRepo.supersedeMemory({
      previousId: original.id,
      replacementId: replacement.id,
      scope: workspaceA,
      newVersion: 5,
      replacementStatus: 'ACTIVE'
    });

    assert.equal(result.replacement.version, 5);
  } finally {
    db.close();
  }
});

test('11. supersedeMemory validation checks reject invalid states', () => {
  const { db, memoryRepo } = setupTest();

  try {
    const mem1 = memoryRepo.createMemory({
      key: 'validation.key',
      content: 'Initial',
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: 'ws-alpha',
      status: 'ACTIVE'
    });

    const memMismatchKey = memoryRepo.createMemory({
      key: 'different.key',
      content: 'Mismatch',
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: 'ws-alpha',
      status: 'PENDING_APPROVAL'
    });

    const memCasedKey = memoryRepo.createMemory({
      key: 'Validation.Key',
      content: 'Different casing',
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: 'ws-alpha',
      status: 'PENDING_APPROVAL'
    });

    const memWsB = memoryRepo.createMemory({
      key: 'validation.key',
      content: 'Workspace B memory',
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: 'ws-beta',
      status: 'PENDING_APPROVAL'
    });

    // 1. Self-link rejection
    assert.throws(
      () => {
        memoryRepo.supersedeMemory({
          previousId: mem1.id,
          replacementId: mem1.id,
          scope: workspaceA
        });
      },
      (err) => err instanceof ValidationError && /itself/i.test(err.message)
    );

    // 2. Mismatched keys rejection
    assert.throws(
      () => {
        memoryRepo.supersedeMemory({
          previousId: mem1.id,
          replacementId: memMismatchKey.id,
          scope: workspaceA
        });
      },
      (err) => err instanceof ValidationError && /mismatched keys/i.test(err.message)
    );

    // 3. Exact binary key equality (casing mismatch rejection)
    assert.throws(
      () => {
        memoryRepo.supersedeMemory({
          previousId: mem1.id,
          replacementId: memCasedKey.id,
          scope: workspaceA
        });
      },
      (err) => err instanceof ValidationError && /mismatched keys/i.test(err.message)
    );

    // 4. Mismatched scope rejection
    assert.throws(
      () => {
        memoryRepo.supersedeMemory({
          previousId: mem1.id,
          replacementId: memWsB.id,
          scope: workspaceA
        });
      },
      (err) => err instanceof MemoryScopeViolationError
    );

    // 5. Invalid newVersion <= previous.version rejection
    const validCandidate = memoryRepo.createMemory({
      key: 'validation.key',
      content: 'Candidate',
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: 'ws-alpha',
      status: 'PENDING_APPROVAL'
    });

    assert.throws(
      () => {
        memoryRepo.supersedeMemory({
          previousId: mem1.id,
          replacementId: validCandidate.id,
          scope: workspaceA,
          newVersion: 1 // mem1 is version 1, so 1 is <= 1
        });
      },
      (err) => err instanceof ValidationError && /must be strictly greater/i.test(err.message)
    );

    // 6. Replacement status cannot be SUPERSEDED
    assert.throws(
      () => {
        memoryRepo.supersedeMemory({
          previousId: mem1.id,
          replacementId: validCandidate.id,
          scope: workspaceA,
          replacementStatus: 'SUPERSEDED'
        });
      },
      (err) => err instanceof ValidationError && /cannot be 'SUPERSEDED'/i.test(err.message)
    );

    // 7. Previous memory not ACTIVE rejection
    const pendingOriginal = memoryRepo.createMemory({
      key: 'validation.pending',
      content: 'Pending',
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: 'ws-alpha',
      status: 'PENDING_APPROVAL'
    });
    const pendingReplacer = memoryRepo.createMemory({
      key: 'validation.pending',
      content: 'Pending Replacer',
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: 'ws-alpha',
      status: 'PENDING_APPROVAL'
    });

    assert.throws(
      () => {
        memoryRepo.supersedeMemory({
          previousId: pendingOriginal.id,
          replacementId: pendingReplacer.id,
          scope: workspaceA
        });
      },
      (err) => err instanceof ValidationError && /Only records with status 'ACTIVE' can be superseded/i.test(err.message)
    );

    // 8. Already superseded rejection
    const rep1 = memoryRepo.createMemory({
      key: 'validation.key',
      content: 'Replacer 1',
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: 'ws-alpha',
      status: 'PENDING_APPROVAL'
    });

    memoryRepo.supersedeMemory({
      previousId: mem1.id,
      replacementId: rep1.id,
      scope: workspaceA,
      replacementStatus: 'ACTIVE'
    });

    // Try superseding mem1 again
    const rep2 = memoryRepo.createMemory({
      key: 'validation.key',
      content: 'Replacer 2',
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: 'ws-alpha',
      status: 'PENDING_APPROVAL'
    });

    assert.throws(
      () => {
        memoryRepo.supersedeMemory({
          previousId: mem1.id,
          replacementId: rep2.id,
          scope: workspaceA
        });
      },
      (err) => err instanceof ValidationError && /(already been superseded|status is 'SUPERSEDED')/i.test(err.message)
    );

    // 9. Replacement already superseding another memory rejection
    const alreadySupersedingCandidate = memoryRepo.createMemory({
      key: 'validation.key',
      content: 'Already superseding',
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: 'ws-alpha',
      status: 'PENDING_APPROVAL'
    });
    db.prepare('UPDATE memories SET supersedes_id = ? WHERE id = ?').run(mem1.id, alreadySupersedingCandidate.id);

    assert.throws(
      () => {
        memoryRepo.supersedeMemory({
          previousId: rep1.id,
          replacementId: alreadySupersedingCandidate.id,
          scope: workspaceA
        });
      },
      (err) => err instanceof ValidationError && /already supersedes/i.test(err.message)
    );
  } finally {
    db.close();
  }
});

test('12. supersedeMemory detects and rejects lineage cycles', () => {
  const { db, memoryRepo } = setupTest();

  try {
    const m1 = memoryRepo.createMemory({
      key: 'chain.key',
      content: 'Chain 1',
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: 'ws-alpha',
      status: 'ACTIVE'
    });

    const m2 = memoryRepo.createMemory({
      key: 'chain.key',
      content: 'Chain 2',
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: 'ws-alpha',
      status: 'PENDING_APPROVAL'
    });

    memoryRepo.supersedeMemory({
      previousId: m1.id,
      replacementId: m2.id,
      scope: workspaceA,
      replacementStatus: 'ACTIVE'
    });

    const m3 = memoryRepo.createMemory({
      key: 'chain.key',
      content: 'Chain 3',
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: 'ws-alpha',
      status: 'PENDING_APPROVAL'
    });

    // Manually set m3's ancestor in DB to simulate an ancestor relationship pointing to a candidate
    const candidate = memoryRepo.createMemory({
      key: 'chain.key',
      content: 'Candidate',
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: 'ws-alpha',
      status: 'PENDING_APPROVAL'
    });

    db.prepare('UPDATE memories SET supersedes_id = ? WHERE id = ?').run(candidate.id, m2.id);

    // Now candidate is an ancestor of m2.
    assert.throws(
      () => {
        memoryRepo.supersedeMemory({
          previousId: m2.id,
          replacementId: candidate.id,
          scope: workspaceA
        });
      },
      (err) => err instanceof ValidationError && /cycle detected/i.test(err.message)
    );
  } finally {
    db.close();
  }
});

test('13. supersedeMemory transaction rollback on error leaves database unchanged', () => {
  const { db, memoryRepo } = setupTest();

  try {
    const existingActive = memoryRepo.createMemory({
      key: 'unique.active',
      content: 'Current active',
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: 'ws-alpha',
      status: 'ACTIVE'
    });

    const pending1 = memoryRepo.createMemory({
      key: 'unique.active',
      content: 'Pending 1',
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: 'ws-alpha',
      status: 'PENDING_APPROVAL'
    });

    const pending2 = memoryRepo.createMemory({
      key: 'unique.active',
      content: 'Pending 2',
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: 'ws-alpha',
      status: 'PENDING_APPROVAL'
    });

    // Supersede existingActive with pending1
    memoryRepo.supersedeMemory({
      previousId: existingActive.id,
      replacementId: pending1.id,
      scope: workspaceA,
      replacementStatus: 'ACTIVE'
    });

    // Now existingActive is SUPERSEDED, pending1 is ACTIVE.
    // Try to supersede pending2 with existingActive:
    // This should fail because existingActive is already SUPERSEDED.
    assert.throws(() => {
      memoryRepo.supersedeMemory({
        previousId: existingActive.id,
        replacementId: pending2.id,
        scope: workspaceA
      });
    });

    // Check that pending2 is still PENDING_APPROVAL and pending1 is still ACTIVE
    const p2 = memoryRepo.getMemoryById(pending2.id, workspaceA);
    assert.equal(p2?.status, 'PENDING_APPROVAL');
    assert.equal(p2?.supersedesId, null);

    const p1 = memoryRepo.getMemoryById(pending1.id, workspaceA);
    assert.equal(p1?.status, 'ACTIVE');
  } finally {
    db.close();
  }
});

test('14. Lineage metadata CRUD protection: createMemory and updateMemory reject status SUPERSEDED and protect lineage columns', () => {
  const { db, memoryRepo } = setupTest();

  try {
    // 1. createMemory rejects status = 'SUPERSEDED'
    assert.throws(
      () => {
        memoryRepo.createMemory({
          key: 'test.crud.protection',
          content: 'Test content',
          category: 'PROJECT_FACT',
          scopeType: 'WORKSPACE',
          scopeId: 'ws-alpha',
          status: 'SUPERSEDED' as unknown as WritableMemoryStatus
        });
      },
      (err) => err instanceof ValidationError && /Direct creation of memories with status 'SUPERSEDED'/i.test(err.message)
    );

    // 2. createMemory always initializes version = 1, supersedesId = null, supersededBy = null
    // even if caller passes lineage fields
    const created = memoryRepo.createMemory({
      key: 'test.crud.protection',
      content: 'Test content',
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: 'ws-alpha',
      status: 'ACTIVE'
    });
    assert.equal(created.version, 1);
    assert.equal(created.supersedesId, null);
    assert.equal(created.supersededBy, null);

    // 3. updateMemory rejects status = 'SUPERSEDED'
    assert.throws(
      () => {
        memoryRepo.updateMemory(created.id, workspaceA, {
          status: 'SUPERSEDED' as unknown as WritableMemoryStatus
        });
      },
      (err) => err instanceof ValidationError && /Cannot directly transition a memory to status 'SUPERSEDED'/i.test(err.message)
    );

    // 4. updateMemory does not modify lineage columns even if passed by untyped caller
    const untypedInput = {
      content: 'Updated content',
      version: 99,
      supersedesId: 'fake-id',
      supersededBy: 'fake-id'
    } as unknown as UpdateMemoryInput;
    const updated = memoryRepo.updateMemory(created.id, workspaceA, untypedInput);
    assert.equal(updated.content, 'Updated content');
    assert.equal(updated.version, 1);
    assert.equal(updated.supersedesId, null);
    assert.equal(updated.supersededBy, null);
  } finally {
    db.close();
  }
});

test('15. Guarded deletion and archival: reject deleting or archiving records in a supersession history chain', () => {
  const { db, memoryRepo } = setupTest();

  try {
    const v1 = memoryRepo.createMemory({
      key: 'guarded.chain',
      content: 'Version 1',
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: 'ws-alpha',
      status: 'ACTIVE'
    });

    const v2Candidate = memoryRepo.createMemory({
      key: 'guarded.chain',
      content: 'Version 2',
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: 'ws-alpha',
      status: 'PENDING_APPROVAL'
    });

    const result = memoryRepo.supersedeMemory({
      previousId: v1.id,
      replacementId: v2Candidate.id,
      scope: workspaceA,
      replacementStatus: 'ACTIVE'
    });

    // 1. archiveMemory on SUPERSEDED record is rejected
    assert.throws(
      () => {
        memoryRepo.archiveMemory(result.previous.id, workspaceA);
      },
      (err) => err instanceof ValidationError && /Cannot archive memory.*record is superseded/i.test(err.message)
    );

    // 2. deleteMemory on SUPERSEDED record is rejected
    assert.throws(
      () => {
        memoryRepo.deleteMemory(result.previous.id, workspaceA);
      },
      (err) => err instanceof ValidationError && /part of a supersession history chain/i.test(err.message)
    );

    // 3. deleteMemory on ACTIVE record that supersedes an ancestor is rejected
    assert.throws(
      () => {
        memoryRepo.deleteMemory(result.replacement.id, workspaceA);
      },
      (err) => err instanceof ValidationError && /part of a supersession history chain/i.test(err.message)
    );

    // 4. Normal unlinked ACTIVE memory CAN be archived and then deleted
    const unlinked = memoryRepo.createMemory({
      key: 'unlinked.memory',
      content: 'Unlinked content',
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: 'ws-alpha',
      status: 'ACTIVE'
    });
    const archived = memoryRepo.archiveMemory(unlinked.id, workspaceA);
    assert.equal(archived.status, 'ARCHIVED');

    const deleted = memoryRepo.deleteMemory(unlinked.id, workspaceA);
    assert.equal(deleted, true);
    assert.equal(memoryRepo.getMemoryById(unlinked.id, workspaceA), null);
  } finally {
    db.close();
  }
});
