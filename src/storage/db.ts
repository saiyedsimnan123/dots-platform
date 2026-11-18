/**
 * Next-Generation Dots AI Platform - SQLite Database Manager
 * 
 * Architectural Mandate:
 * Uses Node.js 24's built-in `node:sqlite` API (zero external database libraries).
 * Enforces foreign keys, WAL mode for concurrency, parameterized queries, and
 * transactional migrations.
 */

import { DatabaseSync, StatementSync } from 'node:sqlite';
import { DatabaseError } from '../domain/errors.ts';

export interface Migration {
  readonly version: string;
  readonly up: (db: DatabaseSync) => void;
}

export class DatabaseManager {
  public readonly dbPath: string;
  private readonly db: DatabaseSync;
  private isClosed: boolean = false;
  private isPoisoned: boolean = false;
  private transactionDepth: number = 0;
  private fatalError: DatabaseError | null = null;

  constructor(dbPath: string = ':memory:') {
    this.dbPath = dbPath;
    try {
      this.db = new DatabaseSync(dbPath);
      this.configurePragmas();
      this.runMigrations();
    } catch (err) {
      throw new DatabaseError(
        `Failed to initialize database at '${dbPath}': ${err instanceof Error ? err.message : String(err)}`,
        { dbPath }
      );
    }
  }

  /**
   * Configures essential safety and concurrency pragmas.
   */
  private configurePragmas(): void {
    // Enforce foreign key constraints
    this.db.exec('PRAGMA foreign_keys = ON;');

    // Avoid lock contention with a 5-second wait
    this.db.exec('PRAGMA busy_timeout = 5000;');

    // Optimize synchronous commits
    this.db.exec('PRAGMA synchronous = NORMAL;');

    // Enable WAL mode for disk files (in-memory databases default to memory journal)
    if (this.dbPath !== ':memory:') {
      this.db.exec('PRAGMA journal_mode = WAL;');
    }
  }

  /**
   * Applies schema migrations transactionally.
   */
  private runMigrations(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        version TEXT NOT NULL UNIQUE,
        applied_at TEXT NOT NULL
      );
    `);

    const migrations: Migration[] = [
      {
        version: '001_initial_schema',
        up: (db) => {
          db.exec(`
            -- Tasks table: primary workflow state entity
            CREATE TABLE IF NOT EXISTS tasks (
              id TEXT PRIMARY KEY,
              goal TEXT NOT NULL,
              status TEXT NOT NULL CHECK (
                status IN (
                  'SUBMITTED', 'PLANNING', 'AWAITING_APPROVAL', 'EXECUTING',
                  'VERIFYING', 'RECOVERING', 'COMPLETED', 'FAILED',
                  'CANCELLED', 'TIMED_OUT'
                )
              ),
              current_step_index INTEGER NOT NULL DEFAULT 0,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL,
              completed_at TEXT,
              error_summary TEXT,
              metadata_json TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status);
            CREATE INDEX IF NOT EXISTS idx_tasks_created_at ON tasks(created_at);

            -- Task steps table: bounded execution plan items
            CREATE TABLE IF NOT EXISTS task_steps (
              id TEXT PRIMARY KEY,
              task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
              step_order INTEGER NOT NULL,
              description TEXT NOT NULL,
              tool_name TEXT NOT NULL,
              tool_arguments_json TEXT NOT NULL,
              status TEXT NOT NULL CHECK (
                status IN ('PENDING', 'EXECUTING', 'VERIFIED', 'FAILED', 'SKIPPED')
              ),
              retry_count INTEGER NOT NULL DEFAULT 0,
              max_retries INTEGER NOT NULL DEFAULT 2,
              created_at TEXT NOT NULL,
              completed_at TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_task_steps_task_id ON task_steps(task_id);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_task_steps_order ON task_steps(task_id, step_order);

            -- Tool executions table: raw execution logs from the sandbox
            CREATE TABLE IF NOT EXISTS tool_executions (
              id TEXT PRIMARY KEY,
              step_id TEXT NOT NULL REFERENCES task_steps(id) ON DELETE CASCADE,
              tool_name TEXT NOT NULL,
              input_json TEXT NOT NULL,
              output_json TEXT NOT NULL,
              exit_code INTEGER NOT NULL,
              duration_ms INTEGER NOT NULL,
              created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_tool_executions_step_id ON tool_executions(step_id);

            -- Verifications table: tangible evidence records
            CREATE TABLE IF NOT EXISTS verifications (
              id TEXT PRIMARY KEY,
              step_id TEXT NOT NULL REFERENCES task_steps(id) ON DELETE CASCADE,
              check_type TEXT NOT NULL,
              passed INTEGER NOT NULL CHECK (passed IN (0, 1)),
              expected_value TEXT NOT NULL,
              actual_value TEXT NOT NULL,
              evidence_data_json TEXT NOT NULL,
              verified_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_verifications_step_id ON verifications(step_id);

            -- Human approval requests: permission gates for Tier 3/4 operations
            CREATE TABLE IF NOT EXISTS approval_requests (
              id TEXT PRIMARY KEY,
              task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
              step_id TEXT NOT NULL REFERENCES task_steps(id) ON DELETE CASCADE,
              risk_tier TEXT NOT NULL CHECK (
                risk_tier IN ('TIER_0', 'TIER_1', 'TIER_2', 'TIER_3', 'TIER_4')
              ),
              action_summary TEXT NOT NULL,
              target_resource TEXT NOT NULL,
              parameter_diff_json TEXT NOT NULL,
              approval_token TEXT NOT NULL UNIQUE,
              decision TEXT NOT NULL CHECK (
                decision IN ('PENDING', 'APPROVED', 'REJECTED', 'EXPIRED')
              ),
              decided_by TEXT,
              decided_at TEXT,
              expires_at TEXT NOT NULL,
              created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_approval_requests_task_id ON approval_requests(task_id);
            CREATE INDEX IF NOT EXISTS idx_approval_requests_token ON approval_requests(approval_token);

            -- Audit events table: immutable append-only event store
            CREATE TABLE IF NOT EXISTS audit_events (
              id TEXT PRIMARY KEY,
              task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
              event_type TEXT NOT NULL,
              actor TEXT NOT NULL CHECK (actor IN ('USER', 'AGENT', 'POLICY_ENGINE', 'SYSTEM')),
              details_json TEXT NOT NULL,
              payload_hash TEXT NOT NULL,
              timestamp TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_audit_events_task_id ON audit_events(task_id);
            CREATE INDEX IF NOT EXISTS idx_audit_events_timestamp ON audit_events(timestamp);

            -- Token usages table: token cost and spending metrics
            CREATE TABLE IF NOT EXISTS token_usages (
              id TEXT PRIMARY KEY,
              task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
              provider TEXT NOT NULL,
              model TEXT NOT NULL,
              prompt_tokens INTEGER NOT NULL,
              completion_tokens INTEGER NOT NULL,
              estimated_cost_usd REAL NOT NULL DEFAULT 0.0,
              timestamp TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_token_usages_task_id ON token_usages(task_id);
          `);
        }
      },
      {
        version: '002_memory_subsystem',
        up: (db) => {
          db.exec(`
            -- Memories table: user-controlled long-term memory records
            CREATE TABLE IF NOT EXISTS memories (
              id TEXT PRIMARY KEY,
              category TEXT NOT NULL CHECK (
                category IN ('USER_PREFERENCE', 'PROJECT_FACT', 'LEARNED_PROCEDURE')
              ),
              scope_type TEXT NOT NULL CHECK (
                scope_type IN ('GLOBAL', 'WORKSPACE')
              ),
              scope_id TEXT NOT NULL,
              key TEXT NOT NULL,
              content TEXT NOT NULL,
              status TEXT NOT NULL CHECK (
                status IN ('ACTIVE', 'PENDING_APPROVAL', 'ARCHIVED')
              ),
              priority INTEGER NOT NULL DEFAULT 50 CHECK (priority >= 0 AND priority <= 100),
              tags_json TEXT NOT NULL DEFAULT '[]',
              metadata_json TEXT NOT NULL DEFAULT '{}',
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL,
              last_accessed_at TEXT,
              access_count INTEGER NOT NULL DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_memories_scope ON memories(scope_type, scope_id, status);
            CREATE INDEX IF NOT EXISTS idx_memories_category ON memories(category, status);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_memories_unique_active_key 
              ON memories(scope_type, scope_id, key) 
              WHERE status = 'ACTIVE';

            -- Memory task injections table: provenance tracking
            CREATE TABLE IF NOT EXISTS memory_task_injections (
              id TEXT PRIMARY KEY,
              task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
              memory_id TEXT REFERENCES memories(id) ON DELETE SET NULL,
              char_count INTEGER NOT NULL,
              estimated_tokens INTEGER NOT NULL,
              injected_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_memory_injections_task_id ON memory_task_injections(task_id);
            CREATE INDEX IF NOT EXISTS idx_memory_injections_memory_id ON memory_task_injections(memory_id);
          `);
        }
      },
      {
        version: '003_persistent_scheduler',
        up: (db) => {
          db.exec(`
            -- Schedules table: persistent one-time and recurring interval schedules
            CREATE TABLE IF NOT EXISTS schedules (
              id TEXT PRIMARY KEY,
              name TEXT NOT NULL,
              goal TEXT NOT NULL,
              schedule_type TEXT NOT NULL CHECK (schedule_type IN ('ONE_TIME', 'INTERVAL')),
              status TEXT NOT NULL CHECK (status IN ('ACTIVE', 'PAUSED', 'COMPLETED', 'CANCELLED')),
              run_at TEXT,
              interval_ms INTEGER CHECK (interval_ms IS NULL OR interval_ms >= 1000),
              missed_run_policy TEXT NOT NULL DEFAULT 'SKIP' CHECK (missed_run_policy IN ('SKIP', 'RUN_ONCE')),
              overlap_policy TEXT NOT NULL DEFAULT 'SKIP' CHECK (overlap_policy IN ('SKIP')),
              max_consecutive_failures INTEGER NOT NULL DEFAULT 3 CHECK (max_consecutive_failures >= 1),
              consecutive_failures INTEGER NOT NULL DEFAULT 0 CHECK (consecutive_failures >= 0),
              scope_type TEXT NOT NULL CHECK (scope_type IN ('GLOBAL', 'WORKSPACE')),
              scope_id TEXT NOT NULL,
              created_by TEXT NOT NULL,
              metadata_json TEXT,
              next_run_at TEXT,
              last_run_at TEXT,
              last_task_id TEXT REFERENCES tasks(id) ON DELETE SET NULL,
              paused_reason TEXT,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_schedules_status_next_run ON schedules(status, next_run_at);
            CREATE INDEX IF NOT EXISTS idx_schedules_scope ON schedules(scope_type, scope_id, status);

            -- Schedule occurrences table: durable occurrence identity & DB-enforced duplicate prevention
            CREATE TABLE IF NOT EXISTS schedule_occurrences (
              id TEXT PRIMARY KEY,
              schedule_id TEXT NOT NULL REFERENCES schedules(id) ON DELETE CASCADE,
              occurrence_key TEXT NOT NULL,
              scheduled_for TEXT NOT NULL,
              status TEXT NOT NULL CHECK (
                status IN (
                  'CLAIMED', 'TASK_CREATED', 'RUNNING', 'AWAITING_APPROVAL',
                  'SUCCEEDED', 'FAILED', 'CANCELLED', 'SKIPPED_OVERLAP', 'SKIPPED_MISSED'
                )
              ),
              task_id TEXT UNIQUE REFERENCES tasks(id) ON DELETE SET NULL,
              claimed_at TEXT NOT NULL,
              started_at TEXT,
              completed_at TEXT,
              error_summary TEXT,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL,
              UNIQUE (schedule_id, occurrence_key)
            );

            CREATE INDEX IF NOT EXISTS idx_schedule_occurrences_schedule_status
              ON schedule_occurrences(schedule_id, status);
            CREATE INDEX IF NOT EXISTS idx_schedule_occurrences_status
              ON schedule_occurrences(status);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_schedule_occurrences_one_active
              ON schedule_occurrences(schedule_id)
              WHERE status IN ('CLAIMED', 'TASK_CREATED', 'RUNNING', 'AWAITING_APPROVAL');
          `);
        }
      },
      {
        version: '004_conversation_system',
        up: (db) => {
          db.exec(`
            -- Conversations table: persistent conversation sessions
            CREATE TABLE IF NOT EXISTS conversations (
              id TEXT PRIMARY KEY,
              title TEXT NOT NULL,
              status TEXT NOT NULL CHECK (status IN ('ACTIVE', 'ARCHIVED')),
              scope_type TEXT NOT NULL CHECK (scope_type IN ('GLOBAL', 'WORKSPACE')),
              scope_id TEXT NOT NULL,
              created_by TEXT NOT NULL,
              agent_id TEXT,
              metadata_json TEXT,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_conversations_scope ON conversations(scope_type, scope_id, status);
            CREATE INDEX IF NOT EXISTS idx_conversations_created_at ON conversations(created_at);
            CREATE INDEX IF NOT EXISTS idx_conversations_agent_id ON conversations(agent_id);

            -- Conversation messages table: chronological message store
            CREATE TABLE IF NOT EXISTS conversation_messages (
              id TEXT PRIMARY KEY,
              conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
              role TEXT NOT NULL CHECK (role IN ('system', 'user', 'assistant', 'tool')),
              content TEXT NOT NULL,
              name TEXT,
              tool_call_id TEXT,
              tool_calls_json TEXT,
              client_message_id TEXT,
              metadata_json TEXT,
              created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_conversation_messages_conv_created ON conversation_messages(conversation_id, created_at ASC);
            CREATE INDEX IF NOT EXISTS idx_conversation_messages_created_at ON conversation_messages(created_at);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_conversation_messages_client_id 
              ON conversation_messages(conversation_id, client_message_id) 
              WHERE client_message_id IS NOT NULL;
          `);
        }
      },
      {
        version: '005_memory_embeddings',
        up: (db) => {
          db.exec(`
            -- Memory embeddings table: persistent Float32 vector embeddings for memories
            CREATE TABLE IF NOT EXISTS memory_embeddings (
              id TEXT PRIMARY KEY,
              memory_id TEXT NOT NULL REFERENCES memories(id) ON DELETE CASCADE,
              model_id TEXT NOT NULL,
              model_revision TEXT NOT NULL DEFAULT 'main',
              dimensions INTEGER NOT NULL CHECK (dimensions > 0),
              embedding BLOB NOT NULL,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL,
              UNIQUE (memory_id, model_id, model_revision)
            );

            CREATE INDEX IF NOT EXISTS idx_memory_embeddings_memory_id ON memory_embeddings(memory_id);
            CREATE INDEX IF NOT EXISTS idx_memory_embeddings_model ON memory_embeddings(model_id, model_revision);
          `);
        }
      },
      {
        version: '006_embedding_jobs',
        up: (db) => {
          db.exec(`
            -- Embedding jobs queue: durable SQLite-backed queue for asynchronous embedding generation
            CREATE TABLE IF NOT EXISTS embedding_jobs (
              id TEXT PRIMARY KEY,
              memory_id TEXT NOT NULL REFERENCES memories(id) ON DELETE CASCADE,
              scope_type TEXT NOT NULL CHECK (scope_type IN ('GLOBAL', 'WORKSPACE')),
              scope_id TEXT NOT NULL,
              model_id TEXT NOT NULL,
              model_revision TEXT NOT NULL DEFAULT 'main',
              status TEXT NOT NULL CHECK (status IN ('PENDING', 'RUNNING', 'COMPLETED', 'FAILED', 'CANCELLED')),
              attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
              max_attempts INTEGER NOT NULL DEFAULT 5 CHECK (max_attempts > 0),
              scheduled_at TEXT NOT NULL,
              last_error TEXT,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_embedding_jobs_claim 
              ON embedding_jobs(status, scheduled_at, created_at);

            CREATE INDEX IF NOT EXISTS idx_embedding_jobs_memory 
              ON embedding_jobs(memory_id);

            CREATE UNIQUE INDEX IF NOT EXISTS idx_embedding_jobs_pending_unique 
              ON embedding_jobs(memory_id, model_id, model_revision) 
              WHERE status = 'PENDING';
          `);
        }
      },
      {
        version: '007_embedding_jobs_retention_index',
        up: (db) => {
          db.exec(`
            -- Retention maintenance index: partial index for fast, bounded terminal job pruning
            CREATE INDEX IF NOT EXISTS idx_embedding_jobs_retention 
              ON embedding_jobs (updated_at ASC, id ASC) 
              WHERE status IN ('COMPLETED', 'FAILED', 'CANCELLED');
          `);
        }
      }
    ];

    const checkStmt = this.db.prepare('SELECT version FROM schema_migrations WHERE version = ?');
    const recordStmt = this.db.prepare('INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)');

    for (const migration of migrations) {
      const existing = checkStmt.get(migration.version);
      if (!existing) {
        this.transaction(() => {
          migration.up(this.db);
          recordStmt.run(migration.version, new Date().toISOString());
        });
      }
    }
  }

  /**
   * Executes a callback within a transaction.
   * Supports nested transactions using SQLite savepoints.
   * Commits/releases on success, rolls back on error.
   * If rollback or savepoint cleanup fails, the connection is poisoned to prevent corrupt state.
   */
  public transaction<T>(callback: () => T): T {
    this.assertOpen();
    const depth = this.transactionDepth;
    const isTopLevel = depth === 0;
    const savepointName = `sp_${depth}`;

    if (isTopLevel) {
      this.db.exec('BEGIN IMMEDIATE;');
    } else {
      this.db.exec(`SAVEPOINT ${savepointName};`);
    }
    this.transactionDepth = depth + 1;

    try {
      const result = callback();
      if (this.isPoisoned) {
        throw this.fatalError ?? new DatabaseError('Cannot commit transaction: database connection is poisoned due to a fatal transaction failure.');
      }
      if (this.isClosed) {
        throw new DatabaseError('Cannot commit transaction on closed database connection.');
      }
      if (isTopLevel) {
        this.db.exec('COMMIT;');
      } else {
        this.db.exec(`RELEASE SAVEPOINT ${savepointName};`);
      }
      return result;
    } catch (callbackErr) {
      if (this.isPoisoned) {
        throw this.fatalError ?? callbackErr;
      }
      if (this.isClosed) {
        throw callbackErr;
      }
      try {
        if (isTopLevel) {
          this.db.exec('ROLLBACK;');
        } else {
          this.db.exec(`ROLLBACK TO SAVEPOINT ${savepointName};`);
          this.db.exec(`RELEASE SAVEPOINT ${savepointName};`);
        }
      } catch (cleanupErr) {
        const fatalError = new DatabaseError(
          `Fatal database rollback failure: ${cleanupErr instanceof Error ? cleanupErr.message : String(cleanupErr)}`,
          {
            cleanupError: cleanupErr instanceof Error ? cleanupErr.message : String(cleanupErr),
            originalError: callbackErr instanceof Error ? callbackErr.message : String(callbackErr)
          }
        );
        this.fatalError = fatalError;
        this.isPoisoned = true;
        try {
          this.db.close();
        } catch {
          // Ignore secondary close error during emergency close
        }
        this.isClosed = true;
        throw fatalError;
      }
      throw callbackErr;
    } finally {
      this.transactionDepth = depth;
    }
  }

  /**
   * Executes raw SQL commands (DDL or multi-statements).
   */
  public exec(sql: string): void {
    this.assertOpen();
    this.db.exec(sql);
  }

  /**
   * Prepares a parameterized SQL statement.
   */
  public prepare(sql: string): StatementSync {
    this.assertOpen();
    return this.db.prepare(sql);
  }

  /**
   * Closes the database connection cleanly.
   */
  public close(): void {
    if (!this.isClosed) {
      try {
        this.db.close();
      } finally {
        this.isClosed = true;
      }
    }
  }

  public get isOpen(): boolean {
    return !this.isClosed && !this.isPoisoned;
  }

  public get poisoned(): boolean {
    return this.isPoisoned;
  }

  public get currentTransactionDepth(): number {
    return this.transactionDepth;
  }

  private assertOpen(): void {
    if (this.isPoisoned) {
      throw new DatabaseError('Cannot execute operation: database connection is poisoned due to a fatal transaction failure.');
    }
    if (this.isClosed) {
      throw new DatabaseError('Cannot execute operation on closed database connection.');
    }
  }
}
