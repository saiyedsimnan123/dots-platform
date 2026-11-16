/**
 * Next-Generation Dots AI Platform - Embedding Job Repository
 * Phase 4C.6B: Durable Asynchronous Embedding Lifecycle Manager
 * 
 * Architectural Mandate:
 * Implements persistent SQLite storage and lifecycle management for asynchronous
 * embedding jobs using Node.js 24's built-in `node:sqlite` API.
 * 
 * Guarantees:
 * 1. 100% parameterized SQL to prevent SQL injection.
 * 2. SQLite foreign keys enforce ON DELETE CASCADE from memories table.
 * 3. Idempotent enqueueing: coalesces duplicate pending requests for the same (memoryId, modelId, modelRevision).
 * 4. Atomic claiming: transitions jobs to RUNNING inside immediate transactions while enforcing concurrency = 1.
 * 5. Bounded retry backoff and recovery of interrupted RUNNING jobs on startup.
 * 6. Automatic pruning of completed jobs prevents unbounded table growth.
 * 7. Zero memory content, secrets, or embeddings stored in job records.
 */

import { randomUUID } from 'node:crypto';
import type { DatabaseManager } from './db.ts';
import type {
  EmbeddingJob,
  EmbeddingJobStatus,
  EnqueueEmbeddingJobInput,
  ListEmbeddingJobsFilter
} from '../memory/embedding-types.ts';
import type { MemoryScopeType } from '../domain/types.ts';
import { ValidationError, DatabaseError } from '../domain/errors.ts';

interface EmbeddingJobDbRow {
  id: string;
  memory_id: string;
  scope_type: string;
  scope_id: string;
  model_id: string;
  model_revision: string;
  status: string;
  attempt_count: number;
  max_attempts: number;
  scheduled_at: string;
  last_error: string | null;
  created_at: string;
  updated_at: string;
}

type SqlParam = null | number | bigint | string | Uint8Array;

const VALID_STATUSES: ReadonlySet<EmbeddingJobStatus> = new Set([
  'PENDING',
  'RUNNING',
  'COMPLETED',
  'FAILED'
]);

export class EmbeddingJobRepository {
  public readonly db: DatabaseManager;

  constructor(db: DatabaseManager) {
    if (!db) {
      throw new ValidationError('DatabaseManager must be provided to EmbeddingJobRepository.');
    }
    this.db = db;
  }

  /**
   * Executes a callback within an immediate database transaction.
   */
  public transaction<T>(callback: () => T): T {
    return this.db.transaction(callback);
  }

  /**
   * Enqueues an embedding job idempotently.
   * If a job is already PENDING for the same (memoryId, modelId, modelRevision),
   * its scheduled execution time is updated to now and the existing job is returned.
   */
  public enqueueJob(input: EnqueueEmbeddingJobInput): EmbeddingJob {
    this.validateEnqueueInput(input);

    const modelRevision = input.modelRevision ?? 'main';
    const maxAttempts = input.maxAttempts ?? 5;
    const now = new Date().toISOString();
    const scheduledAt = input.scheduledAt ?? now;

    return this.transaction(() => {
      // Check for existing PENDING job
      const checkSql = `
        SELECT id FROM embedding_jobs
        WHERE memory_id = ? AND model_id = ? AND model_revision = ? AND status = 'PENDING'
        LIMIT 1
      `;
      const existing = this.db.prepare(checkSql).get(
        input.memoryId,
        input.modelId,
        modelRevision
      ) as { id: string } | undefined;

      if (existing) {
        // Update existing pending job's scheduled time and reset failure counter
        const updateSql = `
          UPDATE embedding_jobs
          SET scheduled_at = ?, attempt_count = 0, last_error = NULL, updated_at = ?
          WHERE id = ?
        `;
        this.db.prepare(updateSql).run(scheduledAt, now, existing.id);
        const updated = this.getJobById(existing.id);
        if (!updated) {
          throw new DatabaseError(`Failed to retrieve updated pending embedding job '${existing.id}'.`);
        }
        return updated;
      }

      // Insert new PENDING job
      const id = input.id ?? randomUUID();
      const insertSql = `
        INSERT INTO embedding_jobs (
          id, memory_id, scope_type, scope_id, model_id, model_revision,
          status, attempt_count, max_attempts, scheduled_at, last_error, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, 'PENDING', 0, ?, ?, NULL, ?, ?)
      `;

      try {
        this.db.prepare(insertSql).run(
          id,
          input.memoryId,
          input.scopeType,
          input.scopeId,
          input.modelId,
          modelRevision,
          maxAttempts,
          scheduledAt,
          now,
          now
        );
      } catch (err) {
        // If unique constraint collided concurrently, fetch the existing pending job
        if (err instanceof Error && /UNIQUE constraint failed/i.test(err.message)) {
          const raceExisting = this.db.prepare(checkSql).get(
            input.memoryId,
            input.modelId,
            modelRevision
          ) as { id: string } | undefined;
          if (raceExisting) {
            const job = this.getJobById(raceExisting.id);
            if (job) return job;
          }
        }
        throw err;
      }

      const created = this.getJobById(id);
      if (!created) {
        throw new DatabaseError(`Failed to retrieve newly enqueued embedding job '${id}'.`);
      }
      return created;
    });
  }

  /**
   * Atomically claims the next eligible PENDING job.
   * Enforces strict concurrency = 1 (returns null if any job is already RUNNING).
   */
  public claimNextJob(now = new Date().toISOString(), modelId?: string): EmbeddingJob | null {
    return this.transaction(() => {
      // Concurrency Gate: Concurrency is fixed at 1. If any job is currently RUNNING, do not claim.
      const runningRow = this.db.prepare(
        "SELECT id FROM embedding_jobs WHERE status = 'RUNNING' LIMIT 1"
      ).get() as { id: string } | undefined;

      if (runningRow) {
        return null;
      }

      let selectSql = `
        SELECT id FROM embedding_jobs
        WHERE status = 'PENDING' AND scheduled_at <= ?
      `;
      const selectParams: SqlParam[] = [now];

      if (modelId) {
        selectSql += ' AND model_id = ?';
        selectParams.push(modelId);
      }

      selectSql += ' ORDER BY scheduled_at ASC, created_at ASC, id ASC LIMIT 1';

      const candidate = this.db.prepare(selectSql).get(...selectParams) as { id: string } | undefined;
      if (!candidate) {
        return null;
      }

      const claimSql = `
        UPDATE embedding_jobs
        SET status = 'RUNNING', updated_at = ?
        WHERE id = ? AND status = 'PENDING'
      `;
      const result = this.db.prepare(claimSql).run(now, candidate.id);
      if (Number(result.changes) === 0) {
        return null;
      }

      return this.getJobById(candidate.id);
    });
  }

  /**
   * Marks a job as COMPLETED and automatically prunes older completed jobs
   * for the same memory to prevent unbounded table growth.
   */
  public markJobCompleted(id: string, now = new Date().toISOString()): void {
    if (!id || typeof id !== 'string' || id.trim() === '') {
      throw new ValidationError('Job ID must be a non-empty string.');
    }

    this.transaction(() => {
      const updateSql = `
        UPDATE embedding_jobs
        SET status = 'COMPLETED', updated_at = ?
        WHERE id = ?
      `;
      this.db.prepare(updateSql).run(now, id);

      // Prune older completed jobs for the same memory
      const pruneSql = `
        DELETE FROM embedding_jobs
        WHERE memory_id = (SELECT memory_id FROM embedding_jobs WHERE id = ?)
          AND status = 'COMPLETED'
          AND id != ?
      `;
      this.db.prepare(pruneSql).run(id, id);
    });
  }

  /**
   * Reschedules a job for a future retry attempt.
   */
  public rescheduleJob(
    id: string,
    attemptCount: number,
    nextScheduledAt: string,
    error?: string,
    now = new Date().toISOString()
  ): void {
    if (!id || typeof id !== 'string' || id.trim() === '') {
      throw new ValidationError('Job ID must be a non-empty string.');
    }

    const sql = `
      UPDATE embedding_jobs
      SET status = 'PENDING', attempt_count = ?, scheduled_at = ?, last_error = ?, updated_at = ?
      WHERE id = ?
    `;
    this.db.prepare(sql).run(attemptCount, nextScheduledAt, error ?? null, now, id);
  }

  /**
   * Marks a job as terminally FAILED after retry exhaustion or unrecoverable error.
   */
  public markJobFailed(
    id: string,
    attemptCount: number,
    error: string,
    now = new Date().toISOString()
  ): void {
    if (!id || typeof id !== 'string' || id.trim() === '') {
      throw new ValidationError('Job ID must be a non-empty string.');
    }

    const sql = `
      UPDATE embedding_jobs
      SET status = 'FAILED', attempt_count = ?, last_error = ?, updated_at = ?
      WHERE id = ?
    `;
    this.db.prepare(sql).run(attemptCount, error, now, id);
  }

  /**
   * Recovers jobs left in 'RUNNING' status following process crash or restart.
   * If a job has reached or exceeded maxAttempts, it is marked terminally FAILED.
   * Otherwise it is reset to 'PENDING' with incremented attempt count and scheduled immediately.
   */
  public recoverInterruptedJobs(now = new Date().toISOString()): EmbeddingJob[] {
    return this.transaction(() => {
      const selectSql = `
        SELECT * FROM embedding_jobs
        WHERE status = 'RUNNING'
        ORDER BY created_at ASC, id ASC
      `;
      const rows = this.db.prepare(selectSql).all() as unknown as EmbeddingJobDbRow[];
      const recovered: EmbeddingJob[] = [];

      for (const row of rows) {
        const nextAttempt = row.attempt_count + 1;
        if (nextAttempt >= row.max_attempts) {
          const failSql = `
            UPDATE embedding_jobs
            SET status = 'FAILED', attempt_count = ?, last_error = ?, updated_at = ?
            WHERE id = ?
          `;
          this.db.prepare(failSql).run(
            nextAttempt,
            'Job interrupted by crash exceeded max attempts',
            now,
            row.id
          );
        } else {
          const retrySql = `
            UPDATE embedding_jobs
            SET status = 'PENDING', attempt_count = ?, scheduled_at = ?, last_error = ?, updated_at = ?
            WHERE id = ?
          `;
          this.db.prepare(retrySql).run(
            nextAttempt,
            now,
            'Interrupted by process restart',
            now,
            row.id
          );
        }

        const updated = this.getJobById(row.id);
        if (updated) {
          recovered.push(updated);
        }
      }

      return recovered;
    });
  }

  /**
   * Retrieves an embedding job by unique ID.
   */
  public getJobById(id: string): EmbeddingJob | null {
    if (!id || typeof id !== 'string' || id.trim() === '') {
      return null;
    }

    const sql = 'SELECT * FROM embedding_jobs WHERE id = ?';
    const row = this.db.prepare(sql).get(id) as EmbeddingJobDbRow | undefined;
    return row ? this.mapRow(row) : null;
  }

  /**
   * Lists embedding jobs matching optional filters.
   */
  public listJobs(filter?: ListEmbeddingJobsFilter): EmbeddingJob[] {
    let sql = 'SELECT * FROM embedding_jobs';
    const clauses: string[] = [];
    const params: SqlParam[] = [];

    if (filter) {
      if (filter.memoryId !== undefined) {
        clauses.push('memory_id = ?');
        params.push(filter.memoryId);
      }
      if (filter.scopeType !== undefined) {
        clauses.push('scope_type = ?');
        params.push(filter.scopeType);
      }
      if (filter.scopeId !== undefined) {
        clauses.push('scope_id = ?');
        params.push(filter.scopeId);
      }
      if (filter.modelId !== undefined) {
        clauses.push('model_id = ?');
        params.push(filter.modelId);
      }
      if (filter.modelRevision !== undefined) {
        clauses.push('model_revision = ?');
        params.push(filter.modelRevision);
      }
      if (filter.status !== undefined) {
        clauses.push('status = ?');
        params.push(filter.status);
      }
    }

    if (clauses.length > 0) {
      sql += ` WHERE ${clauses.join(' AND ')}`;
    }

    sql += ' ORDER BY created_at ASC, id ASC';

    if (filter) {
      if (filter.limit !== undefined) {
        if (typeof filter.limit !== 'number' || filter.limit <= 0) {
          throw new ValidationError('Limit must be a positive integer.');
        }
        sql += ' LIMIT ?';
        params.push(filter.limit);
      }
      if (filter.offset !== undefined) {
        if (typeof filter.offset !== 'number' || filter.offset < 0) {
          throw new ValidationError('Offset must be a non-negative integer.');
        }
        sql += ' OFFSET ?';
        params.push(filter.offset);
      }
    }

    const rows = this.db.prepare(sql).all(...params) as unknown as EmbeddingJobDbRow[];
    return rows.map((r) => this.mapRow(r));
  }

  /**
   * Counts embedding jobs matching optional filters.
   */
  public countJobs(filter?: { status?: EmbeddingJobStatus; memoryId?: string }): number {
    let sql = 'SELECT COUNT(*) as count FROM embedding_jobs';
    const clauses: string[] = [];
    const params: SqlParam[] = [];

    if (filter?.status) {
      clauses.push('status = ?');
      params.push(filter.status);
    }
    if (filter?.memoryId) {
      clauses.push('memory_id = ?');
      params.push(filter.memoryId);
    }

    if (clauses.length > 0) {
      sql += ` WHERE ${clauses.join(' AND ')}`;
    }

    const row = this.db.prepare(sql).get(...params) as { count: number } | undefined;
    return Number(row?.count ?? 0);
  }

  /**
   * Prunes completed jobs older than a given retention threshold.
   */
  public pruneCompletedJobs(olderThanMs?: number, now = Date.now()): number {
    let sql = "DELETE FROM embedding_jobs WHERE status = 'COMPLETED'";
    const params: SqlParam[] = [];

    if (olderThanMs !== undefined && olderThanMs >= 0) {
      const cutoff = new Date(now - olderThanMs).toISOString();
      sql += ' AND updated_at <= ?';
      params.push(cutoff);
    }

    const result = this.db.prepare(sql).run(...params);
    return Number(result.changes);
  }

  private mapRow(row: EmbeddingJobDbRow): EmbeddingJob {
    return {
      id: row.id,
      memoryId: row.memory_id,
      scopeType: row.scope_type as MemoryScopeType,
      scopeId: row.scope_id,
      modelId: row.model_id,
      modelRevision: row.model_revision,
      status: row.status as EmbeddingJobStatus,
      attemptCount: row.attempt_count,
      maxAttempts: row.max_attempts,
      scheduledAt: row.scheduled_at,
      lastError: row.last_error,
      createdAt: row.created_at,
      updatedAt: row.updated_at
    };
  }

  private validateEnqueueInput(input: EnqueueEmbeddingJobInput): void {
    if (!input || typeof input !== 'object') {
      throw new ValidationError('EnqueueEmbeddingJobInput must be provided.');
    }
    if (!input.memoryId || typeof input.memoryId !== 'string' || input.memoryId.trim() === '') {
      throw new ValidationError('memoryId must be a non-empty string.');
    }
    if (input.scopeType !== 'GLOBAL' && input.scopeType !== 'WORKSPACE') {
      throw new ValidationError(`Invalid scopeType '${String(input.scopeType)}'. Must be 'GLOBAL' or 'WORKSPACE'.`);
    }
    if (!input.scopeId || typeof input.scopeId !== 'string' || input.scopeId.trim() === '') {
      throw new ValidationError('scopeId must be a non-empty string.');
    }
    if (!input.modelId || typeof input.modelId !== 'string' || input.modelId.trim() === '') {
      throw new ValidationError('modelId must be a non-empty string.');
    }
    if (input.maxAttempts !== undefined) {
      if (typeof input.maxAttempts !== 'number' || !Number.isInteger(input.maxAttempts) || input.maxAttempts <= 0) {
        throw new ValidationError('maxAttempts must be a positive integer.');
      }
    }
  }
}
