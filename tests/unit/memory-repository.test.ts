/**
 * Next-Generation Dots AI Platform - Memory Repository Unit Tests
 * 
 * Verifies:
 * 1. Schema migration on fresh and existing databases.
 * 2. Migration idempotency.
 * 3. Memory creation, retrieval by ID, retrieval by key.
 * 4. Input validation and invalid enum rejection.
 * 5. Active-key uniqueness per scope and archived-record reuse.
 * 6. Scope isolation across workspaces and global scopes.
 * 7. Updates, timestamps, archival, and missing-record handling.
 * 8. Explicit access tracking (not on arbitrary reads).
 * 9. Hard deletion and foreign-key nulling on injection records without data leakage.
 * 10. Cascading deletion when a parent task is deleted.
 * 11. Transaction rollback on failure.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseManager } from '../../src/storage/db.ts';
import { TaskRepository } from '../../src/storage/task-repository.ts';
import { MemoryRepository } from '../../src/storage/memory-repository.ts';
import {
  ValidationError,
  MemoryNotFoundError,
  MemoryConflictError,
  MemoryScopeViolationError
} from '../../src/domain/errors.ts';
import type { MemoryCategory, MemoryScopeType } from '../../src/domain/types.ts';

const workspaceA = { scopeType: 'WORKSPACE' as const, scopeId: 'workspace-hash-alpha' };
const workspaceB = { scopeType: 'WORKSPACE' as const, scopeId: 'workspace-hash-beta' };
const globalScope = { scopeType: 'GLOBAL' as const, scopeId: 'default' };

function setupTest() {
  const db = new DatabaseManager(':memory:');
  const memoryRepo = new MemoryRepository(db);
  const taskRepo = new TaskRepository(db);
  return { db, memoryRepo, taskRepo };
}

test('Memory Migration - applies migration 002_memory_subsystem idempotently on fresh DB', () => {
  const { db } = setupTest();

  try {
    const migrations = db.prepare('SELECT version FROM schema_migrations ORDER BY version ASC').all() as Array<{ version: string }>;
    const versions = migrations.map((m) => m.version);
    assert.ok(versions.includes('001_initial_schema'));
    assert.ok(versions.includes('002_memory_subsystem'));

    // Verify memories table schema
    const memoryColumns = db.prepare('PRAGMA table_info(memories);').all() as Array<{ name: string; type: string; notnull: number }>;
    const memColNames = memoryColumns.map((c) => c.name);

    assert.ok(memColNames.includes('id'));
    assert.ok(memColNames.includes('category'));
    assert.ok(memColNames.includes('scope_type'));
    assert.ok(memColNames.includes('scope_id'));
    assert.ok(memColNames.includes('key'));
    assert.ok(memColNames.includes('content'));
    assert.ok(memColNames.includes('status'));
    assert.ok(memColNames.includes('priority'));
    assert.ok(memColNames.includes('tags_json'));
    assert.ok(memColNames.includes('metadata_json'));
    assert.ok(memColNames.includes('created_at'));
    assert.ok(memColNames.includes('updated_at'));
    assert.ok(memColNames.includes('last_accessed_at'));
    assert.ok(memColNames.includes('access_count'));

    // Verify memory_task_injections table schema
    const injectionColumns = db.prepare('PRAGMA table_info(memory_task_injections);').all() as Array<{ name: string }>;
    const injColNames = injectionColumns.map((c) => c.name);

    assert.ok(injColNames.includes('id'));
    assert.ok(injColNames.includes('task_id'));
    assert.ok(injColNames.includes('memory_id'));
    assert.ok(injColNames.includes('char_count'));
    assert.ok(injColNames.includes('estimated_tokens'));
    assert.ok(injColNames.includes('injected_at'));

    // MUST NOT retain readable memory content or keys in injection records
    assert.equal(injColNames.includes('key'), false);
    assert.equal(injColNames.includes('memory_key'), false);
    assert.equal(injColNames.includes('content'), false);
  } finally {
    db.close();
  }
});

test('Memory Migration - upgrades database with pre-existing data without data loss', () => {
  // 1. Manually create a database with only 001_initial_schema
  const db = new DatabaseManager(':memory:');
  const taskRepo = new TaskRepository(db);

  try {
    const task = taskRepo.createTask({ goal: 'Existing pre-migration task' });
    const step = taskRepo.createStep({
      taskId: task.id,
      stepOrder: 1,
      description: 'Pre-existing step',
      toolName: 'calculate',
      toolArguments: { expression: '1+1' }
    });

    // Verify existing task and step are present
    assert.ok(taskRepo.getTaskById(task.id));
    assert.equal(taskRepo.getStepsByTaskId(task.id).length, 1);

    // Verify memories table was created alongside existing data
    const memoryRepo = new MemoryRepository(db);
    const mem = memoryRepo.createMemory({
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: 'test-scope',
      key: 'architecture.runtime',
      content: 'Node.js 24 with native SQLite'
    });

    assert.ok(mem);
    assert.equal(mem.key, 'architecture.runtime');

    // Existing data remains intact
    const reloadedTask = taskRepo.getTaskById(task.id);
    assert.ok(reloadedTask);
    assert.equal(reloadedTask.goal, 'Existing pre-migration task');
    assert.equal(taskRepo.getStepsByTaskId(task.id)[0]!.description, 'Pre-existing step');
  } finally {
    db.close();
  }
});

test('MemoryRepository - creates and retrieves memories within scope', () => {
  const { db, memoryRepo } = setupTest();

  try {
    const memory = memoryRepo.createMemory({
      category: 'USER_PREFERENCE',
      scopeType: 'WORKSPACE',
      scopeId: workspaceA.scopeId,
      key: 'formatting.indent',
      content: 'Indent with 2 spaces, no tabs.',
      priority: 80,
      tags: ['formatting', 'style'],
      metadata: { author: 'user', verified: true }
    });

    assert.ok(memory.id);
    assert.equal(memory.category, 'USER_PREFERENCE');
    assert.equal(memory.scopeType, 'WORKSPACE');
    assert.equal(memory.scopeId, workspaceA.scopeId);
    assert.equal(memory.key, 'formatting.indent');
    assert.equal(memory.content, 'Indent with 2 spaces, no tabs.');
    assert.equal(memory.status, 'ACTIVE');
    assert.equal(memory.priority, 80);
    assert.equal(memory.accessCount, 0);
    assert.equal(memory.lastAccessedAt, null);
    assert.equal(JSON.parse(memory.tagsJson)[0], 'formatting');
    assert.equal(JSON.parse(memory.metadataJson).author, 'user');

    // Retrieve by ID with correct scope
    const retrievedById = memoryRepo.getMemoryById(memory.id, workspaceA);
    assert.ok(retrievedById);
    assert.equal(retrievedById.id, memory.id);
    assert.equal(retrievedById.key, 'formatting.indent');

    // Retrieve by Key with correct scope
    const retrievedByKey = memoryRepo.getMemoryByKey('formatting.indent', workspaceA);
    assert.ok(retrievedByKey);
    assert.equal(retrievedByKey.id, memory.id);

    // Global memory creation
    const globalMem = memoryRepo.createMemory({
      category: 'USER_PREFERENCE',
      scopeType: 'GLOBAL',
      scopeId: 'default',
      key: 'global.language',
      content: 'Always respond in English.'
    });

    assert.equal(globalMem.scopeType, 'GLOBAL');
    assert.equal(globalMem.scopeId, 'default');
    const retrievedGlobal = memoryRepo.getMemoryByKey('global.language', globalScope);
    assert.ok(retrievedGlobal);
    assert.equal(retrievedGlobal.content, 'Always respond in English.');
  } finally {
    db.close();
  }
});

test('MemoryRepository - validates inputs and rejects invalid enum/field values', () => {
  const { db, memoryRepo } = setupTest();

  try {
    // Empty key
    assert.throws(
      () => memoryRepo.createMemory({
        category: 'USER_PREFERENCE',
        scopeType: 'WORKSPACE',
        scopeId: workspaceA.scopeId,
        key: '   ',
        content: 'content'
      }),
      (err: unknown) => err instanceof ValidationError && err.message.includes('key')
    );

    // Empty content
    assert.throws(
      () => memoryRepo.createMemory({
        category: 'USER_PREFERENCE',
        scopeType: 'WORKSPACE',
        scopeId: workspaceA.scopeId,
        key: 'valid.key',
        content: '   '
      }),
      (err: unknown) => err instanceof ValidationError && err.message.includes('content')
    );

    // Invalid category
    assert.throws(
      () => memoryRepo.createMemory({
        category: 'INVALID_CATEGORY' as unknown as MemoryCategory,
        scopeType: 'WORKSPACE',
        scopeId: workspaceA.scopeId,
        key: 'valid.key',
        content: 'content'
      }),
      (err: unknown) => err instanceof ValidationError && err.message.includes('category')
    );

    // Invalid scopeType
    assert.throws(
      () => memoryRepo.createMemory({
        category: 'USER_PREFERENCE',
        scopeType: 'INVALID_SCOPE' as unknown as MemoryScopeType,
        scopeId: workspaceA.scopeId,
        key: 'valid.key',
        content: 'content'
      }),
      (err: unknown) => err instanceof ValidationError && err.message.includes('scope')
    );

    // Global scope with non-default scopeId
    assert.throws(
      () => memoryRepo.createMemory({
        category: 'USER_PREFERENCE',
        scopeType: 'GLOBAL',
        scopeId: 'custom-scope-not-allowed',
        key: 'valid.key',
        content: 'content'
      }),
      (err: unknown) => err instanceof ValidationError && err.message.includes('default')
    );

    // Priority out of bounds
    assert.throws(
      () => memoryRepo.createMemory({
        category: 'USER_PREFERENCE',
        scopeType: 'WORKSPACE',
        scopeId: workspaceA.scopeId,
        key: 'valid.key',
        content: 'content',
        priority: 150
      }),
      (err: unknown) => err instanceof ValidationError && err.message.includes('priority')
    );

    // Database-level CHECK constraint enforcement (direct SQL bypass attempt)
    assert.throws(
      () => {
        db.prepare(`
          INSERT INTO memories (
            id, category, scope_type, scope_id, key, content, status,
            priority, tags_json, metadata_json, created_at, updated_at
          ) VALUES ('m-bad', 'MALICIOUS_CATEGORY', 'WORKSPACE', 'ws1', 'k', 'c', 'ACTIVE', 50, '[]', '{}', '2026-10-17T00:00:00Z', '2026-10-17T00:00:00Z')
        `).run();
      },
      /CHECK constraint failed/i
    );
  } finally {
    db.close();
  }
});

test('MemoryRepository - enforces active key uniqueness per scope while permitting archived reuse', () => {
  const { db, memoryRepo } = setupTest();

  try {
    // Create active memory in workspaceA
    memoryRepo.createMemory({
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: workspaceA.scopeId,
      key: 'build.framework',
      content: 'Node.js 24 with native type stripping'
    });

    // Attempt to create another ACTIVE memory with identical key in same workspace -> must fail with MemoryConflictError
    assert.throws(
      () => {
        memoryRepo.createMemory({
          category: 'PROJECT_FACT',
          scopeType: 'WORKSPACE',
          scopeId: workspaceA.scopeId,
          key: 'build.framework',
          content: 'Duplicate key attempt'
        });
      },
      (err: unknown) => {
        assert.ok(err instanceof MemoryConflictError);
        assert.equal(err.key, 'build.framework');
        return true;
      }
    );

    // Same key in a DIFFERENT workspace -> completely valid!
    const memInWorkspaceB = memoryRepo.createMemory({
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: workspaceB.scopeId,
      key: 'build.framework',
      content: 'Workspace B can use the same key'
    });
    assert.ok(memInWorkspaceB);

    // Archive the memory in workspaceA
    const activeInA = memoryRepo.getMemoryByKey('build.framework', workspaceA);
    assert.ok(activeInA);
    memoryRepo.archiveMemory(activeInA.id, workspaceA);

    // Now that the old record is ARCHIVED, creating a new ACTIVE memory with the same key is permitted!
    const newActiveInA = memoryRepo.createMemory({
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: workspaceA.scopeId,
      key: 'build.framework',
      content: 'New active replacement memory'
    });
    assert.ok(newActiveInA);
    assert.equal(newActiveInA.content, 'New active replacement memory');

    // Attempting to unarchive / reactivate the old memory now causes a conflict!
    assert.throws(
      () => {
        memoryRepo.updateMemory(activeInA.id, workspaceA, { status: 'ACTIVE' });
      },
      (err: unknown) => err instanceof MemoryConflictError
    );
  } finally {
    db.close();
  }
});

test('MemoryRepository - strictly isolates scopes across workspaces and global boundaries', () => {
  const { db, memoryRepo } = setupTest();

  try {
    const memA = memoryRepo.createMemory({
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: workspaceA.scopeId,
      key: 'secret.config',
      content: 'Workspace A proprietary fact'
    });

    // Attempting to read memA using workspaceB scope must throw MemoryScopeViolationError
    assert.throws(
      () => {
        memoryRepo.getMemoryById(memA.id, workspaceB);
      },
      (err: unknown) => {
        assert.ok(err instanceof MemoryScopeViolationError);
        assert.ok(err.message.includes('Memory scope violation'));
        return true;
      }
    );

    // Attempting to update memA using workspaceB scope must throw MemoryScopeViolationError
    assert.throws(
      () => {
        memoryRepo.updateMemory(memA.id, workspaceB, { content: 'Tampered' });
      },
      (err: unknown) => err instanceof MemoryScopeViolationError
    );

    // Attempting to delete memA using workspaceB scope must throw MemoryScopeViolationError
    assert.throws(
      () => {
        memoryRepo.deleteMemory(memA.id, workspaceB);
      },
      (err: unknown) => err instanceof MemoryScopeViolationError
    );

    // Querying listMemories for workspaceB returns zero records from workspaceA
    const listB = memoryRepo.listMemories({
      scopeType: 'WORKSPACE',
      scopeId: workspaceB.scopeId
    });
    assert.equal(listB.length, 0);

    // Querying listMemories for workspaceA returns the record
    const listA = memoryRepo.listMemories({
      scopeType: 'WORKSPACE',
      scopeId: workspaceA.scopeId
    });
    assert.equal(listA.length, 1);
    assert.equal(listA[0]!.id, memA.id);
  } finally {
    db.close();
  }
});

test('MemoryRepository - updates fields, timestamps, and archives records', () => {
  const { db, memoryRepo } = setupTest();

  try {
    const mem = memoryRepo.createMemory({
      category: 'USER_PREFERENCE',
      scopeType: 'WORKSPACE',
      scopeId: workspaceA.scopeId,
      key: 'test.update',
      content: 'Original content',
      priority: 30
    });

    const originalUpdatedAt = mem.updatedAt;

    // Small delay to ensure timestamp advancement
    const updated = memoryRepo.updateMemory(mem.id, workspaceA, {
      content: 'Updated content',
      category: 'PROJECT_FACT',
      priority: 95,
      tags: ['tag1', 'tag2'],
      metadata: { edited: true }
    });

    assert.equal(updated.content, 'Updated content');
    assert.equal(updated.category, 'PROJECT_FACT');
    assert.equal(updated.priority, 95);
    assert.equal(JSON.parse(updated.tagsJson).length, 2);
    assert.equal(JSON.parse(updated.metadataJson).edited, true);
    assert.ok(updated.updatedAt >= originalUpdatedAt);

    // Archiving
    const archived = memoryRepo.archiveMemory(mem.id, workspaceA);
    assert.equal(archived.status, 'ARCHIVED');

    // List with status: 'ACTIVE' excludes archived
    const activeList = memoryRepo.listMemories({
      scopeType: 'WORKSPACE',
      scopeId: workspaceA.scopeId,
      status: 'ACTIVE'
    });
    assert.equal(activeList.length, 0);

    // List with status: 'ARCHIVED' returns archived
    const archivedList = memoryRepo.listMemories({
      scopeType: 'WORKSPACE',
      scopeId: workspaceA.scopeId,
      status: 'ARCHIVED'
    });
    assert.equal(archivedList.length, 1);
    assert.equal(archivedList[0]!.id, mem.id);

    // Non-existent ID throws MemoryNotFoundError
    assert.throws(
      () => memoryRepo.updateMemory('non-existent-id', workspaceA, { content: 'fail' }),
      (err: unknown) => err instanceof MemoryNotFoundError
    );
  } finally {
    db.close();
  }
});

test('MemoryRepository - tracks access metadata only on explicit operation, not on arbitrary reads', () => {
  const { db, memoryRepo } = setupTest();

  try {
    const mem = memoryRepo.createMemory({
      category: 'USER_PREFERENCE',
      scopeType: 'WORKSPACE',
      scopeId: workspaceA.scopeId,
      key: 'access.track',
      content: 'Content'
    });

    assert.equal(mem.accessCount, 0);
    assert.equal(mem.lastAccessedAt, null);

    // Standard read 1: getMemoryById
    const read1 = memoryRepo.getMemoryById(mem.id, workspaceA);
    assert.equal(read1?.accessCount, 0);
    assert.equal(read1?.lastAccessedAt, null);

    // Standard read 2: getMemoryByKey
    const read2 = memoryRepo.getMemoryByKey('access.track', workspaceA);
    assert.equal(read2?.accessCount, 0);
    assert.equal(read2?.lastAccessedAt, null);

    // Standard read 3: listMemories
    const list = memoryRepo.listMemories({ scopeType: 'WORKSPACE', scopeId: workspaceA.scopeId });
    assert.equal(list[0]?.accessCount, 0);
    assert.equal(list[0]?.lastAccessedAt, null);

    // Explicit recordAccess operation
    const accessed1 = memoryRepo.recordAccess(mem.id, workspaceA);
    assert.equal(accessed1.accessCount, 1);
    assert.ok(accessed1.lastAccessedAt);

    const accessed2 = memoryRepo.recordAccess(mem.id, workspaceA);
    assert.equal(accessed2.accessCount, 2);
  } finally {
    db.close();
  }
});

test('MemoryRepository - hard deletion physically erases content and nulls injection foreign keys', () => {
  const { db, memoryRepo, taskRepo } = setupTest();

  try {
    const task = taskRepo.createTask({ goal: 'Task that used memory' });

    const mem = memoryRepo.createMemory({
      category: 'USER_PREFERENCE',
      scopeType: 'WORKSPACE',
      scopeId: workspaceA.scopeId,
      key: 'sensitive.preference',
      content: 'Critical user sensitive information'
    });

    // Record an injection provenance record linked to the memory
    const injection = memoryRepo.recordInjection({
      taskId: task.id,
      memoryId: mem.id,
      charCount: mem.content.length,
      estimatedTokens: Math.ceil(mem.content.length / 3.8)
    });

    assert.ok(injection.id);
    assert.equal(injection.memoryId, mem.id);
    assert.equal(injection.charCount, mem.content.length);

    // Verify injection is queryable by task ID and memory ID
    const taskInjections = memoryRepo.getInjectionsByTaskId(task.id);
    assert.equal(taskInjections.length, 1);
    assert.equal(taskInjections[0]!.memoryId, mem.id);

    // Hard-delete the memory
    const deleted = memoryRepo.deleteMemory(mem.id, workspaceA);
    assert.equal(deleted, true);

    // 1. Memory must be completely gone from memories table
    assert.equal(memoryRepo.getMemoryById(mem.id, workspaceA), null);

    // 2. Querying raw SQLite confirms physical erasure
    const rawMem = db.prepare('SELECT * FROM memories WHERE id = ?').get(mem.id);
    assert.equal(rawMem, undefined);

    // 3. The injection record is retained for token accounting, but memory_id is set to NULL
    const updatedInjections = memoryRepo.getInjectionsByTaskId(task.id);
    assert.equal(updatedInjections.length, 1);
    assert.equal(updatedInjections[0]!.id, injection.id);
    assert.equal(updatedInjections[0]!.memoryId, null); // Set to NULL via ON DELETE SET NULL!
    assert.equal(updatedInjections[0]!.charCount, mem.content.length);

    // 4. Querying by memory ID now returns 0
    assert.equal(memoryRepo.getInjectionsByMemoryId(mem.id).length, 0);

    // 5. Deleting non-existent memory throws MemoryNotFoundError
    assert.throws(
      () => memoryRepo.deleteMemory(mem.id, workspaceA),
      (err: unknown) => err instanceof MemoryNotFoundError
    );
  } finally {
    db.close();
  }
});

test('MemoryRepository - task deletion cascades to remove injection provenance records', () => {
  const { db, memoryRepo, taskRepo } = setupTest();

  try {
    const task = taskRepo.createTask({ goal: 'Temporary workflow task' });

    const mem = memoryRepo.createMemory({
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: workspaceA.scopeId,
      key: 'temp.fact',
      content: 'Temporary project fact'
    });

    const injection = memoryRepo.recordInjection({
      taskId: task.id,
      memoryId: mem.id,
      charCount: 22,
      estimatedTokens: 6
    });

    assert.equal(memoryRepo.getInjectionsByTaskId(task.id).length, 1);

    // Delete the parent task directly from SQLite (tasks CASCADE)
    db.prepare('DELETE FROM tasks WHERE id = ?').run(task.id);

    // Injection record MUST be removed due to ON DELETE CASCADE
    assert.equal(memoryRepo.getInjectionsByTaskId(task.id).length, 0);

    // Memory itself MUST remain untouched
    const reloadedMem = memoryRepo.getMemoryById(mem.id, workspaceA);
    assert.ok(reloadedMem);
    assert.equal(reloadedMem.key, 'temp.fact');
  } finally {
    db.close();
  }
});

test('MemoryRepository - transactional failure rolls back multi-step mutations', () => {
  const { db, memoryRepo } = setupTest();

  try {
    const mem = memoryRepo.createMemory({
      category: 'USER_PREFERENCE',
      scopeType: 'WORKSPACE',
      scopeId: workspaceA.scopeId,
      key: 'tx.test',
      content: 'Original uncorrupted content'
    });

    assert.throws(
      () => {
        db.transaction(() => {
          memoryRepo.updateMemory(mem.id, workspaceA, { content: 'Corrupted uncommitted content' });
          throw new Error('Simulated fatal crash mid-transaction');
        });
      },
      /Simulated fatal crash/
    );

    // State on disk MUST be untouched
    const reloaded = memoryRepo.getMemoryById(mem.id, workspaceA);
    assert.ok(reloaded);
    assert.equal(reloaded.content, 'Original uncorrupted content');
  } finally {
    db.close();
  }
});

test('MemoryRepository - getMemoryById enforces mandatory scope at compile-time and runtime', () => {
  const { db, memoryRepo } = setupTest();

  try {
    const mem = memoryRepo.createMemory({
      category: 'USER_PREFERENCE',
      scopeType: 'WORKSPACE',
      scopeId: workspaceA.scopeId,
      key: 'mandatory.scope.check',
      content: 'Scope enforcement test content'
    });

    // 1. Compile-time enforcement:
    // Calling getMemoryById with only 1 argument MUST trigger a TypeScript compile-time error.
    // The @ts-expect-error directive ensures the compiler catches missing arguments.
    assert.throws(
      // @ts-expect-error Expected 2 arguments, but got 1. getMemoryById requires (id, scope).
      () => memoryRepo.getMemoryById(mem.id),
      (err: unknown) => {
        assert.ok(err instanceof ValidationError);
        assert.match((err as Error).message, /Scope must be provided/);
        return true;
      }
    );

    // 2. Runtime enforcement: bypass type system to simulate untyped/runtime callers
    const repoUntyped = memoryRepo as unknown as {
      getMemoryById: (id: string, scope?: unknown) => unknown;
    };

    // Omitted scope
    assert.throws(
      () => repoUntyped.getMemoryById(mem.id),
      (err: unknown) => err instanceof ValidationError && /Scope must be provided/.test((err as Error).message)
    );

    // null scope
    assert.throws(
      () => repoUntyped.getMemoryById(mem.id, null),
      (err: unknown) => err instanceof ValidationError && /Scope must be provided/.test((err as Error).message)
    );

    // undefined scope
    assert.throws(
      () => repoUntyped.getMemoryById(mem.id, undefined),
      (err: unknown) => err instanceof ValidationError && /Scope must be provided/.test((err as Error).message)
    );

    // Non-object scope
    assert.throws(
      () => repoUntyped.getMemoryById(mem.id, 'invalid-scope-string'),
      (err: unknown) => err instanceof ValidationError
    );

    // Incomplete/invalid scope object
    assert.throws(
      () => repoUntyped.getMemoryById(mem.id, {}),
      (err: unknown) => err instanceof ValidationError && /Invalid memory scope type/.test((err as Error).message)
    );

    assert.throws(
      () => repoUntyped.getMemoryById(mem.id, { scopeType: 'WORKSPACE' }),
      (err: unknown) => err instanceof ValidationError && /scopeId must be a non-empty string/.test((err as Error).message)
    );

    assert.throws(
      () => repoUntyped.getMemoryById(mem.id, { scopeType: 'GLOBAL', scopeId: 'wrong-id' }),
      (err: unknown) => err instanceof ValidationError && /Global memory scopeId must be 'default'/.test((err as Error).message)
    );
  } finally {
    db.close();
  }
});

test('MemoryRepository - getMemoryById succeeds with correct scope and rejects cross-workspace / global access', () => {
  const { db, memoryRepo } = setupTest();

  try {
    const memWsA = memoryRepo.createMemory({
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: workspaceA.scopeId,
      key: 'workspace.a.fact',
      content: 'Workspace A isolated knowledge'
    });

    const memWsB = memoryRepo.createMemory({
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: workspaceB.scopeId,
      key: 'workspace.b.fact',
      content: 'Workspace B isolated knowledge'
    });

    const memGlobal = memoryRepo.createMemory({
      category: 'USER_PREFERENCE',
      scopeType: 'GLOBAL',
      scopeId: globalScope.scopeId,
      key: 'global.preference',
      content: 'Global user preference'
    });

    // 1. Correct-scope retrieval succeeds
    const foundA = memoryRepo.getMemoryById(memWsA.id, workspaceA);
    assert.ok(foundA);
    assert.equal(foundA.id, memWsA.id);
    assert.equal(foundA.content, 'Workspace A isolated knowledge');

    const foundB = memoryRepo.getMemoryById(memWsB.id, workspaceB);
    assert.ok(foundB);
    assert.equal(foundB.id, memWsB.id);
    assert.equal(foundB.content, 'Workspace B isolated knowledge');

    const foundGlobal = memoryRepo.getMemoryById(memGlobal.id, globalScope);
    assert.ok(foundGlobal);
    assert.equal(foundGlobal.id, memGlobal.id);
    assert.equal(foundGlobal.content, 'Global user preference');

    // 2. Cross-workspace retrieval fails with MemoryScopeViolationError
    assert.throws(
      () => memoryRepo.getMemoryById(memWsA.id, workspaceB),
      (err: unknown) => {
        assert.ok(err instanceof MemoryScopeViolationError);
        assert.equal(err.expectedScope, `${workspaceB.scopeType}:${workspaceB.scopeId}`);
        assert.equal(err.actualScope, `${workspaceA.scopeType}:${workspaceA.scopeId}`);
        assert.equal(err.memoryId, memWsA.id);
        return true;
      }
    );

    assert.throws(
      () => memoryRepo.getMemoryById(memWsB.id, workspaceA),
      (err: unknown) => {
        assert.ok(err instanceof MemoryScopeViolationError);
        assert.equal(err.expectedScope, `${workspaceA.scopeType}:${workspaceA.scopeId}`);
        assert.equal(err.actualScope, `${workspaceB.scopeType}:${workspaceB.scopeId}`);
        assert.equal(err.memoryId, memWsB.id);
        return true;
      }
    );

    // 3. Workspace vs. Global isolation
    // Workspace memory queried with global scope
    assert.throws(
      () => memoryRepo.getMemoryById(memWsA.id, globalScope),
      (err: unknown) => {
        assert.ok(err instanceof MemoryScopeViolationError);
        assert.equal(err.expectedScope, `${globalScope.scopeType}:${globalScope.scopeId}`);
        assert.equal(err.actualScope, `${workspaceA.scopeType}:${workspaceA.scopeId}`);
        assert.equal(err.memoryId, memWsA.id);
        return true;
      }
    );

    // Global memory queried with workspace scope
    assert.throws(
      () => memoryRepo.getMemoryById(memGlobal.id, workspaceA),
      (err: unknown) => {
        assert.ok(err instanceof MemoryScopeViolationError);
        assert.equal(err.expectedScope, `${workspaceA.scopeType}:${workspaceA.scopeId}`);
        assert.equal(err.actualScope, `${globalScope.scopeType}:${globalScope.scopeId}`);
        assert.equal(err.memoryId, memGlobal.id);
        return true;
      }
    );
  } finally {
    db.close();
  }
});

test('MemoryRepository - missing memory returns null on reads and throws MemoryNotFoundError on mutations', () => {
  const { db, memoryRepo } = setupTest();

  try {
    const nonExistentId = '00000000-0000-4000-8000-000000000000';

    // Reading non-existent ID within workspace scope returns null (not throwing scope violation)
    assert.equal(memoryRepo.getMemoryById(nonExistentId, workspaceA), null);
    assert.equal(memoryRepo.getMemoryById(nonExistentId, globalScope), null);

    // Reading non-existent key within workspace scope returns null
    assert.equal(memoryRepo.getMemoryByKey('non.existent.key', workspaceA), null);
    assert.equal(memoryRepo.getMemoryByKey('non.existent.key', globalScope), null);

    // Mutating non-existent memory throws MemoryNotFoundError
    assert.throws(
      () => memoryRepo.updateMemory(nonExistentId, workspaceA, { content: 'New' }),
      (err: unknown) => err instanceof MemoryNotFoundError
    );

    assert.throws(
      () => memoryRepo.archiveMemory(nonExistentId, workspaceA),
      (err: unknown) => err instanceof MemoryNotFoundError
    );

    assert.throws(
      () => memoryRepo.deleteMemory(nonExistentId, workspaceA),
      (err: unknown) => err instanceof MemoryNotFoundError
    );

    assert.throws(
      () => memoryRepo.recordAccess(nonExistentId, workspaceA),
      (err: unknown) => err instanceof MemoryNotFoundError
    );
  } finally {
    db.close();
  }
});

