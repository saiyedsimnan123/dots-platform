/**
 * Next-Generation Dots AI Platform - Database Manager Unit Tests
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, unlinkSync } from 'node:fs';
import { DatabaseManager } from '../../src/storage/db.ts';
import { DatabaseError } from '../../src/domain/errors.ts';

test('DatabaseManager - initializes schema migrations in memory', () => {
  const db = new DatabaseManager(':memory:');
  assert.equal(db.isOpen, true);

  // Check that migration table was created and recorded
  const migrationRow = db.prepare('SELECT version FROM schema_migrations WHERE version = ?').get('001_initial_schema') as { version: string };
  assert.ok(migrationRow);
  assert.equal(migrationRow.version, '001_initial_schema');

  const migrationRow2 = db.prepare('SELECT version FROM schema_migrations WHERE version = ?').get('002_memory_subsystem') as { version: string };
  assert.ok(migrationRow2);
  assert.equal(migrationRow2.version, '002_memory_subsystem');

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
  assert.ok(tableNames.includes('memories'));
  assert.ok(tableNames.includes('memory_task_injections'));
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

test('DatabaseManager - nested transactions succeed using savepoints', () => {
  const db = new DatabaseManager(':memory:');
  assert.equal(db.currentTransactionDepth, 0);

  db.transaction(() => {
    assert.equal(db.currentTransactionDepth, 1);
    db.prepare(`
      INSERT INTO tasks (id, goal, status, current_step_index, created_at, updated_at)
      VALUES ('task-outer', 'Outer goal', 'SUBMITTED', 0, '2026-10-18T00:00:00Z', '2026-10-18T00:00:00Z')
    `).run();

    db.transaction(() => {
      assert.equal(db.currentTransactionDepth, 2);
      db.prepare(`
        INSERT INTO tasks (id, goal, status, current_step_index, created_at, updated_at)
        VALUES ('task-inner', 'Inner goal', 'SUBMITTED', 0, '2026-10-18T00:00:00Z', '2026-10-18T00:00:00Z')
      `).run();
    });

    assert.equal(db.currentTransactionDepth, 1);
  });

  assert.equal(db.currentTransactionDepth, 0);

  const outerTask = db.prepare('SELECT goal FROM tasks WHERE id = ?').get('task-outer') as { goal: string };
  const innerTask = db.prepare('SELECT goal FROM tasks WHERE id = ?').get('task-inner') as { goal: string };
  assert.equal(outerTask.goal, 'Outer goal');
  assert.equal(innerTask.goal, 'Inner goal');

  db.close();
});

test('DatabaseManager - inner savepoint failure rolls back inner writes while outer transaction continues and commits', () => {
  const db = new DatabaseManager(':memory:');

  db.transaction(() => {
    db.prepare(`
      INSERT INTO tasks (id, goal, status, current_step_index, created_at, updated_at)
      VALUES ('task-outer-1', 'Outer goal 1', 'SUBMITTED', 0, '2026-10-18T00:00:00Z', '2026-10-18T00:00:00Z')
    `).run();

    // Inner transaction fails, but outer catches it
    assert.throws(() => {
      db.transaction(() => {
        db.prepare(`
          INSERT INTO tasks (id, goal, status, current_step_index, created_at, updated_at)
          VALUES ('task-inner-fail', 'Inner goal will fail', 'SUBMITTED', 0, '2026-10-18T00:00:00Z', '2026-10-18T00:00:00Z')
        `).run();
        throw new Error('Inner savepoint error');
      });
    }, /Inner savepoint error/);

    // Verify depth restored to 1 after inner failure
    assert.equal(db.currentTransactionDepth, 1);

    // Outer transaction continues and inserts second task
    db.prepare(`
      INSERT INTO tasks (id, goal, status, current_step_index, created_at, updated_at)
      VALUES ('task-outer-2', 'Outer goal 2', 'SUBMITTED', 0, '2026-10-18T00:00:00Z', '2026-10-18T00:00:00Z')
    `).run();
  });

  assert.equal(db.currentTransactionDepth, 0);

  // Outer tasks committed
  const t1 = db.prepare('SELECT goal FROM tasks WHERE id = ?').get('task-outer-1') as { goal: string };
  const t2 = db.prepare('SELECT goal FROM tasks WHERE id = ?').get('task-outer-2') as { goal: string };
  assert.equal(t1.goal, 'Outer goal 1');
  assert.equal(t2.goal, 'Outer goal 2');

  // Inner task rolled back
  const inner = db.prepare('SELECT goal FROM tasks WHERE id = ?').get('task-inner-fail');
  assert.equal(inner, undefined);

  db.close();
});

test('DatabaseManager - outer transaction rollback undoes changes from previously released inner savepoints', () => {
  const db = new DatabaseManager(':memory:');

  assert.throws(() => {
    db.transaction(() => {
      db.prepare(`
        INSERT INTO tasks (id, goal, status, current_step_index, created_at, updated_at)
        VALUES ('task-outer', 'Outer goal', 'SUBMITTED', 0, '2026-10-18T00:00:00Z', '2026-10-18T00:00:00Z')
      `).run();

      // Inner transaction succeeds and releases savepoint
      db.transaction(() => {
        db.prepare(`
          INSERT INTO tasks (id, goal, status, current_step_index, created_at, updated_at)
          VALUES ('task-inner-success', 'Inner goal succeeded', 'SUBMITTED', 0, '2026-10-18T00:00:00Z', '2026-10-18T00:00:00Z')
        `).run();
      });

      // Outer transaction now fails
      throw new Error('Outer crash after inner success');
    });
  }, /Outer crash after inner success/);

  assert.equal(db.currentTransactionDepth, 0);

  // Neither outer nor inner rows should exist
  const outer = db.prepare('SELECT goal FROM tasks WHERE id = ?').get('task-outer');
  const inner = db.prepare('SELECT goal FROM tasks WHERE id = ?').get('task-inner-success');
  assert.equal(outer, undefined);
  assert.equal(inner, undefined);

  db.close();
});

test('DatabaseManager - failure while opening transaction or savepoint preserves depth', () => {
  const db = new DatabaseManager(':memory:');

  // Case A: Top-level transaction open failure on closed connection does not corrupt depth
  db.close();
  assert.equal(db.currentTransactionDepth, 0);
  assert.throws(
    () => db.transaction(() => {}),
    (err: unknown) => {
      assert.ok(err instanceof DatabaseError);
      assert.match((err as DatabaseError).message, /closed database connection/);
      return true;
    }
  );
  assert.equal(db.currentTransactionDepth, 0);

  // Case B: Savepoint creation failure inside outer transaction does not corrupt depth
  const activeDb = new DatabaseManager(':memory:');
  const rawDb = (activeDb as unknown as { db: { exec: (sql: string) => void } }).db;
  const originalExec = rawDb.exec.bind(rawDb);

  activeDb.transaction(() => {
    assert.equal(activeDb.currentTransactionDepth, 1);

    rawDb.exec = (sql: string) => {
      if (sql.includes('SAVEPOINT')) {
        throw new Error('Simulated savepoint creation failure');
      }
      return originalExec(sql);
    };

    assert.throws(
      () => activeDb.transaction(() => {}),
      /Simulated savepoint creation failure/
    );

    // Depth must still be 1 (outer depth not corrupted)
    assert.equal(activeDb.currentTransactionDepth, 1);
    assert.equal(activeDb.isOpen, true);
    assert.equal(activeDb.poisoned, false);

    // Restore exec so outer transaction can complete cleanly
    rawDb.exec = originalExec;
  });

  assert.equal(activeDb.currentTransactionDepth, 0);
  activeDb.close();
});

test('DatabaseManager - rollback failure poisons the connection and rejects subsequent operations safely', () => {
  const db = new DatabaseManager(':memory:');
  const rawDb = (db as unknown as { db: { exec: (sql: string) => void } }).db;
  const originalExec = rawDb.exec.bind(rawDb);

  // Hook exec to throw when executing top-level ROLLBACK
  rawDb.exec = (sql: string) => {
    if (sql.trim() === 'ROLLBACK;') {
      throw new Error('Simulated disk I/O error during ROLLBACK');
    }
    return originalExec(sql);
  };

  assert.throws(
    () => {
      db.transaction(() => {
        throw new Error('Callback business logic error');
      });
    },
    (err: unknown) => {
      assert.ok(err instanceof DatabaseError);
      assert.match((err as DatabaseError).message, /Fatal database rollback failure/);
      assert.match((err as DatabaseError).message, /Simulated disk I\/O error during ROLLBACK/);
      return true;
    }
  );

  // State checks: connection must be poisoned and not open
  assert.equal(db.poisoned, true);
  assert.equal(db.isOpen, false);
  assert.equal(db.currentTransactionDepth, 0);

  // Subsequent operations must fail safely with poisoned message
  assert.throws(
    () => db.prepare('SELECT 1'),
    (err: unknown) => {
      assert.ok(err instanceof DatabaseError);
      assert.match((err as DatabaseError).message, /database connection is poisoned/);
      return true;
    }
  );

  assert.throws(
    () => db.exec('SELECT 1'),
    (err: unknown) => {
      assert.ok(err instanceof DatabaseError);
      assert.match((err as DatabaseError).message, /database connection is poisoned/);
      return true;
    }
  );

  assert.throws(
    () => db.transaction(() => {}),
    (err: unknown) => {
      assert.ok(err instanceof DatabaseError);
      assert.match((err as DatabaseError).message, /database connection is poisoned/);
      return true;
    }
  );

  // Closing an already poisoned connection is safe and idempotent
  assert.doesNotThrow(() => db.close());
});

test('DatabaseManager - nested savepoint cleanup failure poisons the connection', () => {
  const db = new DatabaseManager(':memory:');
  const rawDb = (db as unknown as { db: { exec: (sql: string) => void } }).db;
  const originalExec = rawDb.exec.bind(rawDb);

  assert.throws(
    () => {
      db.transaction(() => {
        rawDb.exec = (sql: string) => {
          if (sql.includes('ROLLBACK TO SAVEPOINT')) {
            throw new Error('Simulated failure during savepoint rollback');
          }
          return originalExec(sql);
        };

        db.transaction(() => {
          throw new Error('Inner error needing savepoint rollback');
        });
      });
    },
    (err: unknown) => {
      assert.ok(err instanceof DatabaseError);
      assert.match((err as DatabaseError).message, /Fatal database rollback failure/);
      assert.match((err as DatabaseError).message, /Simulated failure during savepoint rollback/);
      return true;
    }
  );

  assert.equal(db.poisoned, true);
  assert.equal(db.isOpen, false);
  assert.equal(db.currentTransactionDepth, 0);

  // Subsequent operations rejected
  assert.throws(() => db.prepare('SELECT 1'), /database connection is poisoned/);
});

test('DatabaseManager - savepoint release failure during rollback cleanup poisons connection', () => {
  const db = new DatabaseManager(':memory:');
  const rawDb = (db as unknown as { db: { exec: (sql: string) => void } }).db;
  const originalExec = rawDb.exec.bind(rawDb);

  assert.throws(
    () => {
      db.transaction(() => {
        rawDb.exec = (sql: string) => {
          if (sql.trim().startsWith('RELEASE SAVEPOINT')) {
            throw new Error('Simulated failure during savepoint release');
          }
          return originalExec(sql);
        };

        db.transaction(() => {
          throw new Error('Inner error triggering cleanup');
        });
      });
    },
    (err: unknown) => {
      assert.ok(err instanceof DatabaseError);
      assert.match((err as DatabaseError).message, /Fatal database rollback failure/);
      assert.match((err as DatabaseError).message, /Simulated failure during savepoint release/);
      return true;
    }
  );

  assert.equal(db.poisoned, true);
  assert.equal(db.isOpen, false);
  assert.equal(db.currentTransactionDepth, 0);
  assert.throws(() => db.prepare('SELECT 1'), /database connection is poisoned/);
});

test('DatabaseManager - outer transaction fails without attempting COMMIT when inner transaction poisons connection and callback catches error', () => {
  const db = new DatabaseManager(':memory:');
  const rawDb = (db as unknown as { db: { exec: (sql: string) => void } }).db;
  const originalExec = rawDb.exec.bind(rawDb);
  let commitAttempted = false;

  assert.throws(
    () => {
      db.transaction(() => {
        rawDb.exec = (sql: string) => {
          if (sql.trim().startsWith('COMMIT')) {
            commitAttempted = true;
          }
          if (sql.includes('ROLLBACK TO SAVEPOINT')) {
            throw new Error('Simulated fatal savepoint rollback failure');
          }
          return originalExec(sql);
        };

        try {
          db.transaction(() => {
            throw new Error('Inner error needing savepoint rollback');
          });
        } catch (innerErr) {
          // Swallow inner fatal error and attempt normal return
          assert.ok(innerErr instanceof DatabaseError);
          assert.match(innerErr.message, /Simulated fatal savepoint rollback failure/);
        }
      });
    },
    (err: unknown) => {
      assert.ok(err instanceof DatabaseError);
      assert.match((err as DatabaseError).message, /Fatal database rollback failure/);
      assert.match((err as DatabaseError).message, /Simulated fatal savepoint rollback failure/);
      return true;
    }
  );

  // Commit was never attempted
  assert.equal(commitAttempted, false);

  // Connection remains poisoned and closed, depth restored to 0
  assert.equal(db.poisoned, true);
  assert.equal(db.isOpen, false);
  assert.equal(db.currentTransactionDepth, 0);

  // Subsequent operations rejected safely
  assert.throws(() => db.prepare('SELECT 1'), /database connection is poisoned/);
  assert.throws(() => db.exec('SELECT 1'), /database connection is poisoned/);
  assert.throws(() => db.transaction(() => {}), /database connection is poisoned/);
});


