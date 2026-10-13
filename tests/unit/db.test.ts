/**
 * Next-Generation Dots AI Platform - Database Manager Unit Tests
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, unlinkSync } from 'node:fs';
import { DatabaseManager } from '../../src/storage/db.ts';

test('DatabaseManager - initializes schema migrations in memory', () => {
  const db = new DatabaseManager(':memory:');
  assert.equal(db.isOpen, true);

  // Check that migration table was created and recorded
  const migrationRow = db.prepare('SELECT version FROM schema_migrations WHERE version = ?').get('001_initial_schema') as { version: string };
  assert.ok(migrationRow);
  assert.equal(migrationRow.version, '001_initial_schema');

  // Verify all core tables exist
  const tables = db.prepare(`
    SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
  `).all() as Array<{ name: string }>;
  const tableNames = tables.map(t => t.name);

  assert.ok(tableNames.includes('tasks'));
  assert.ok(tableNames.includes('task_steps'));
  assert.ok(tableNames.includes('tool_executions'));
  assert.ok(tableNames.includes('verifications'));
  assert.ok(tableNames.includes('approval_requests'));
  assert.ok(tableNames.includes('audit_events'));
  assert.ok(tableNames.includes('token_usages'));
  assert.ok(tableNames.includes('schema_migrations'));

  db.close();
  assert.equal(db.isOpen, false);
});

test('DatabaseManager - enforces foreign key constraints', () => {
  const db = new DatabaseManager(':memory:');

  // Attempt to insert a task_step with a non-existent task_id
  assert.throws(
    () => {
      db.prepare(`
        INSERT INTO task_steps (
          id, task_id, step_order, description, tool_name, tool_arguments_json,
          status, retry_count, max_retries, created_at, completed_at
        ) VALUES ('step-1', 'non-existent-task-id', 1, 'desc', 'tool', '{}', 'PENDING', 0, 2, '2026-10-13T00:00:00Z', NULL)
      `).run();
    },
    /FOREIGN KEY constraint failed/i
  );

  db.close();
});

test('DatabaseManager - enforces CHECK constraints on status columns', () => {
  const db = new DatabaseManager(':memory:');

  // Attempt to insert a task with an invalid status string
  assert.throws(
    () => {
      db.prepare(`
        INSERT INTO tasks (
          id, goal, status, current_step_index, created_at, updated_at
        ) VALUES ('t1', 'goal', 'INVALID_STATUS', 0, '2026-10-13T00:00:00Z', '2026-10-13T00:00:00Z')
      `).run();
    },
    /CHECK constraint failed/i
  );

  db.close();
});

test('DatabaseManager - rolls back transactions on failure', () => {
  const db = new DatabaseManager(':memory:');

  // Insert a valid task first
  db.prepare(`
    INSERT INTO tasks (
      id, goal, status, current_step_index, created_at, updated_at
    ) VALUES ('task-tx-1', 'Initial goal', 'SUBMITTED', 0, '2026-10-13T00:00:00Z', '2026-10-13T00:00:00Z')
  `).run();

  // Execute a transaction that modifies the task but then fails
  assert.throws(() => {
    db.transaction(() => {
      db.prepare("UPDATE tasks SET goal = 'Modified goal' WHERE id = 'task-tx-1'").run();
      // Deliberately trigger an error
      throw new Error('Simulated transactional failure');
    });
  }, /Simulated transactional failure/);

  // Assert goal was NOT modified due to rollback
  const row = db.prepare('SELECT goal FROM tasks WHERE id = ?').get('task-tx-1') as { goal: string };
  assert.equal(row.goal, 'Initial goal');

  db.close();
});

test('DatabaseManager - configures WAL mode on disk-based databases', () => {
  const testDbFile = 'test_wal_persistence.db';

  // Ensure clean start
  if (existsSync(testDbFile)) unlinkSync(testDbFile);

  try {
    const db = new DatabaseManager(testDbFile);
    const mode = db.prepare('PRAGMA journal_mode;').get() as { journal_mode: string };
    assert.equal(mode.journal_mode.toLowerCase(), 'wal');

    // Insert data and verify persistence
    db.prepare(`
      INSERT INTO tasks (
        id, goal, status, current_step_index, created_at, updated_at
      ) VALUES ('disk-task-1', 'Persisted goal', 'SUBMITTED', 0, '2026-10-13T00:00:00Z', '2026-10-13T00:00:00Z')
    `).run();

    db.close();

    // Reopen the disk database with a brand new connection
    const reopenedDb = new DatabaseManager(testDbFile);
    const row = reopenedDb.prepare('SELECT goal FROM tasks WHERE id = ?').get('disk-task-1') as { goal: string };
    assert.equal(row.goal, 'Persisted goal');
    reopenedDb.close();
  } finally {
    // Teardown
    if (existsSync(testDbFile)) unlinkSync(testDbFile);
    if (existsSync(`${testDbFile}-wal`)) unlinkSync(`${testDbFile}-wal`);
    if (existsSync(`${testDbFile}-shm`)) unlinkSync(`${testDbFile}-shm`);
  }
});
