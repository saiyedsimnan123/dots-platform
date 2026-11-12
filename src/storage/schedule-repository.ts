/**
 * Next-Generation Dots AI Platform - Persistent Schedule Repository
 *
 * Architectural Mandate:
 * Implements ACID-compliant persistence for schedules and durable occurrences.
 * Enforces database-level uniqueness for occurrence keys, 1-to-1 task mapping,
 * and single active occurrence per schedule (overlap prevention).
 */

import { randomUUID } from 'node:crypto';
import type { DatabaseManager } from './db.ts';
import type {
  Schedule,
  ScheduleOccurrence,
  ScheduleType,
  ScheduleStatus,
  MissedRunPolicy,
  OverlapPolicy,
  OccurrenceStatus,
  MemoryScopeType,
  ListSchedulesFilter
} from '../domain/types.ts';
import {
  ScheduleNotFoundError,
  ScheduleConflictError,
  ValidationError
} from '../domain/errors.ts';

interface ScheduleDbRow {
  id: string;
  name: string;
  goal: string;
  schedule_type: string;
  status: string;
  run_at: string | null;
  interval_ms: number | null;
  missed_run_policy: string;
  overlap_policy: string;
  max_consecutive_failures: number;
  consecutive_failures: number;
  scope_type: string;
  scope_id: string;
  created_by: string;
  metadata_json: string | null;
  next_run_at: string | null;
  last_run_at: string | null;
  last_task_id: string | null;
  paused_reason: string | null;
  created_at: string;
  updated_at: string;
}

interface OccurrenceDbRow {
  id: string;
  schedule_id: string;
  occurrence_key: string;
  scheduled_for: string;
  status: string;
  task_id: string | null;
  claimed_at: string;
  started_at: string | null;
  completed_at: string | null;
  error_summary: string | null;
  created_at: string;
  updated_at: string;
}

export interface PersistScheduleParams {
  readonly id?: string;
  readonly name: string;
  readonly goal: string;
  readonly scheduleType: ScheduleType;
  readonly status: ScheduleStatus;
  readonly runAt: string | null;
  readonly intervalMs: number | null;
  readonly missedRunPolicy: MissedRunPolicy;
  readonly overlapPolicy: OverlapPolicy;
  readonly maxConsecutiveFailures: number;
  readonly scopeType: MemoryScopeType;
  readonly scopeId: string;
  readonly createdBy: string;
  readonly metadataJson: string | null;
  readonly nextRunAt: string | null;
  readonly createdAt?: string;
}

export type ClaimOccurrenceResult =
  | { readonly claimed: true; readonly occurrence: ScheduleOccurrence }
  | { readonly claimed: false; readonly reason: 'DUPLICATE_KEY' | 'ACTIVE_OVERLAP' };

export class ScheduleRepository {
  public readonly db: DatabaseManager;

  constructor(db: DatabaseManager) {
    this.db = db;
  }

  public createSchedule(params: PersistScheduleParams): Schedule {
    const id = params.id ?? randomUUID();
    const now = params.createdAt ?? new Date().toISOString();

    const stmt = this.db.prepare(`
      INSERT INTO schedules (
        id, name, goal, schedule_type, status, run_at, interval_ms,
        missed_run_policy, overlap_policy, max_consecutive_failures, consecutive_failures,
        scope_type, scope_id, created_by, metadata_json, next_run_at,
        last_run_at, last_task_id, paused_reason, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?, NULL, NULL, NULL, ?, ?)
    `);

    stmt.run(
      id,
      params.name,
      params.goal,
      params.scheduleType,
      params.status,
      params.runAt,
      params.intervalMs,
      params.missedRunPolicy,
      params.overlapPolicy,
      params.maxConsecutiveFailures,
      params.scopeType,
      params.scopeId,
      params.createdBy,
      params.metadataJson,
      params.nextRunAt,
      now,
      now
    );

    return this.getScheduleById(id)!;
  }

  public getScheduleById(id: string): Schedule | null {
    const stmt = this.db.prepare('SELECT * FROM schedules WHERE id = ?');
    const row = stmt.get(id) as unknown as ScheduleDbRow | undefined;
    return row ? this.mapScheduleRow(row) : null;
  }

  public listSchedules(filter: ListSchedulesFilter = {}): Schedule[] {
    const limit = filter.limit ?? 50;
    const offset = filter.offset ?? 0;
    const clauses: string[] = [];
    const args: Array<string | number> = [];

    if (filter.scopeType) {
      clauses.push('scope_type = ?');
      args.push(filter.scopeType);
    }
    if (filter.scopeId) {
      clauses.push('scope_id = ?');
      args.push(filter.scopeId);
    }
    if (filter.status) {
      clauses.push('status = ?');
      args.push(filter.status);
    }

    const where = clauses.length > 0 ? `WHERE ${clauses.join(' AND ')}` : '';
    const sql = `SELECT * FROM schedules ${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`;
    args.push(limit, offset);

    const rows = this.db.prepare(sql).all(...args) as unknown as ScheduleDbRow[];
    return rows.map((r) => this.mapScheduleRow(r));
  }

  public listDueSchedules(nowIso: string, limit: number = 20): Schedule[] {
    const stmt = this.db.prepare(`
      SELECT * FROM schedules
      WHERE status = 'ACTIVE'
        AND next_run_at IS NOT NULL
        AND next_run_at <= ?
      ORDER BY next_run_at ASC
      LIMIT ?
    `);
    const rows = stmt.all(nowIso, limit) as unknown as ScheduleDbRow[];
    return rows.map((r) => this.mapScheduleRow(r));
  }

  public updateScheduleStatus(
    id: string,
    expectedStatus: ScheduleStatus | readonly ScheduleStatus[],
    newStatus: ScheduleStatus,
    updates: {
      nextRunAt?: string | null;
      pausedReason?: string | null;
      resetFailures?: boolean;
      updatedAt?: string;
    } = {}
  ): Schedule {
    const allowed = Array.isArray(expectedStatus) ? expectedStatus : [expectedStatus];
    const placeholders = allowed.map(() => '?').join(', ');
    const now = updates.updatedAt ?? new Date().toISOString();

    const setClauses = ['status = ?', 'updated_at = ?'];
    const params: Array<string | number | null> = [newStatus, now];

    if ('nextRunAt' in updates) {
      setClauses.push('next_run_at = ?');
      params.push(updates.nextRunAt ?? null);
    }
    if ('pausedReason' in updates) {
      setClauses.push('paused_reason = ?');
      params.push(updates.pausedReason ?? null);
    }
    if (updates.resetFailures) {
      setClauses.push('consecutive_failures = 0');
    }

    const sql = `UPDATE schedules SET ${setClauses.join(', ')} WHERE id = ? AND status IN (${placeholders})`;
    const result = this.db.prepare(sql).run(...params, id, ...allowed);

    if (result.changes === 0) {
      const existing = this.getScheduleById(id);
      if (!existing) {
        throw new ScheduleNotFoundError(id);
      }
      throw new ScheduleConflictError(
        `Cannot transition schedule '${id}' from '${existing.status}' to '${newStatus}'.`,
        id,
        { currentStatus: existing.status, targetStatus: newStatus }
      );
    }

    return this.getScheduleById(id)!;
  }

  public advanceNextRunAt(id: string, nextRunAt: string | null, updatedAt?: string): Schedule {
    const now = updatedAt ?? new Date().toISOString();
    const result = this.db.prepare(`
      UPDATE schedules SET next_run_at = ?, updated_at = ? WHERE id = ?
    `).run(nextRunAt, now, id);
    if (result.changes === 0) {
      throw new ScheduleNotFoundError(id);
    }
    return this.getScheduleById(id)!;
  }

  public recordOccurrenceOutcomeOnSchedule(params: {
    scheduleId: string;
    taskId: string | null;
    succeeded: boolean;
    cancelled?: boolean;
    ranAt: string;
    nextRunAt?: string | null;
    markCompleted?: boolean;
    errorSummary?: string | null;
  }): Schedule {
    const existing = this.getScheduleById(params.scheduleId);
    if (!existing) {
      throw new ScheduleNotFoundError(params.scheduleId);
    }

    const now = params.ranAt;
    let nextFailures = existing.consecutiveFailures;
    let nextStatus: ScheduleStatus = existing.status;
    let pausedReason: string | null = existing.pausedReason;
    let nextRunAt = params.nextRunAt !== undefined ? params.nextRunAt : existing.nextRunAt;

    if (params.cancelled) {
      // Cancelled occurrence does not increment failure counter
      if (params.markCompleted && existing.status === 'ACTIVE') {
        nextStatus = 'COMPLETED';
        nextRunAt = null;
      }
    } else if (params.succeeded) {
      nextFailures = 0;
      pausedReason = null;
      if (params.markCompleted && existing.status === 'ACTIVE') {
        nextStatus = 'COMPLETED';
        nextRunAt = null;
      }
    } else {
      nextFailures = existing.consecutiveFailures + 1;
      if (params.markCompleted && existing.status === 'ACTIVE') {
        nextStatus = 'COMPLETED';
        nextRunAt = null;
      } else if (
        existing.status === 'ACTIVE' &&
        nextFailures >= existing.maxConsecutiveFailures
      ) {
        nextStatus = 'PAUSED';
        pausedReason = `Automatically paused after ${nextFailures} consecutive failures${params.errorSummary ? `: ${params.errorSummary}` : '.'}`;
      }
    }

    this.db.prepare(`
      UPDATE schedules
      SET status = ?,
          consecutive_failures = ?,
          paused_reason = ?,
          last_run_at = ?,
          last_task_id = COALESCE(?, last_task_id),
          next_run_at = ?,
          updated_at = ?
      WHERE id = ?
    `).run(
      nextStatus,
      nextFailures,
      pausedReason,
      now,
      params.taskId,
      nextRunAt,
      now,
      params.scheduleId
    );

    return this.getScheduleById(params.scheduleId)!;
  }

  // --- Occurrences ---

  public tryClaimOccurrence(input: {
    id?: string;
    scheduleId: string;
    occurrenceKey: string;
    scheduledFor: string;
    claimedAt?: string;
  }): ClaimOccurrenceResult {
    const id = input.id ?? randomUUID();
    const now = input.claimedAt ?? new Date().toISOString();

    try {
      this.db.prepare(`
        INSERT INTO schedule_occurrences (
          id, schedule_id, occurrence_key, scheduled_for, status, task_id,
          claimed_at, started_at, completed_at, error_summary, created_at, updated_at
        ) VALUES (?, ?, ?, ?, 'CLAIMED', NULL, ?, NULL, NULL, NULL, ?, ?)
      `).run(
        id,
        input.scheduleId,
        input.occurrenceKey,
        input.scheduledFor,
        now,
        now,
        now
      );

      return {
        claimed: true,
        occurrence: this.getOccurrenceById(id)!
      };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (msg.includes('UNIQUE constraint failed')) {
        // Distinguish active overlap index vs duplicate (schedule_id, occurrence_key)
        const existingByKey = this.getOccurrenceByScheduleAndKey(input.scheduleId, input.occurrenceKey);
        if (existingByKey) {
          return { claimed: false, reason: 'DUPLICATE_KEY' };
        }
        return { claimed: false, reason: 'ACTIVE_OVERLAP' };
      }
      throw err;
    }
  }

  public recordSkippedOccurrence(input: {
    id?: string;
    scheduleId: string;
    occurrenceKey: string;
    scheduledFor: string;
    status: 'SKIPPED_OVERLAP' | 'SKIPPED_MISSED';
    reason: string;
    nowIso?: string;
  }): ScheduleOccurrence | null {
    const id = input.id ?? randomUUID();
    const now = input.nowIso ?? new Date().toISOString();

    const result = this.db.prepare(`
      INSERT OR IGNORE INTO schedule_occurrences (
        id, schedule_id, occurrence_key, scheduled_for, status, task_id,
        claimed_at, started_at, completed_at, error_summary, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, NULL, ?, NULL, ?, ?, ?, ?)
    `).run(
      id,
      input.scheduleId,
      input.occurrenceKey,
      input.scheduledFor,
      input.status,
      now,
      now,
      input.reason,
      now,
      now
    );

    if (result.changes === 0) {
      return this.getOccurrenceByScheduleAndKey(input.scheduleId, input.occurrenceKey);
    }
    return this.getOccurrenceById(id);
  }

  public linkTaskToOccurrence(
    occurrenceId: string,
    taskId: string,
    status: OccurrenceStatus = 'TASK_CREATED',
    nowIso?: string
  ): ScheduleOccurrence {
    const now = nowIso ?? new Date().toISOString();
    const startedAt = status === 'RUNNING' || status === 'AWAITING_APPROVAL' ? now : null;

    const result = this.db.prepare(`
      UPDATE schedule_occurrences
      SET task_id = ?,
          status = ?,
          started_at = COALESCE(?, started_at),
          updated_at = ?
      WHERE id = ?
    `).run(taskId, status, startedAt, now, occurrenceId);

    if (result.changes === 0) {
      throw new ValidationError(`Schedule occurrence '${occurrenceId}' not found.`);
    }
    return this.getOccurrenceById(occurrenceId)!;
  }

  public updateOccurrenceStatus(
    occurrenceId: string,
    status: OccurrenceStatus,
    updates: {
      startedAt?: string | null;
      completedAt?: string | null;
      errorSummary?: string | null;
      updatedAt?: string;
    } = {}
  ): ScheduleOccurrence {
    const now = updates.updatedAt ?? new Date().toISOString();
    const isTerminal =
      status === 'SUCCEEDED' ||
      status === 'FAILED' ||
      status === 'CANCELLED' ||
      status === 'SKIPPED_OVERLAP' ||
      status === 'SKIPPED_MISSED';

    const startedAt = updates.startedAt !== undefined
      ? updates.startedAt
      : (status === 'RUNNING' ? now : null);
    const completedAt = updates.completedAt !== undefined
      ? updates.completedAt
      : (isTerminal ? now : null);

    const result = this.db.prepare(`
      UPDATE schedule_occurrences
      SET status = ?,
          started_at = COALESCE(?, started_at),
          completed_at = COALESCE(?, completed_at),
          error_summary = COALESCE(?, error_summary),
          updated_at = ?
      WHERE id = ?
    `).run(
      status,
      startedAt,
      completedAt,
      updates.errorSummary ?? null,
      now,
      occurrenceId
    );

    if (result.changes === 0) {
      throw new ValidationError(`Schedule occurrence '${occurrenceId}' not found.`);
    }
    return this.getOccurrenceById(occurrenceId)!;
  }

  public getOccurrenceById(id: string): ScheduleOccurrence | null {
    const row = this.db.prepare('SELECT * FROM schedule_occurrences WHERE id = ?')
      .get(id) as unknown as OccurrenceDbRow | undefined;
    return row ? this.mapOccurrenceRow(row) : null;
  }

  public getOccurrenceByTaskId(taskId: string): ScheduleOccurrence | null {
    const row = this.db.prepare('SELECT * FROM schedule_occurrences WHERE task_id = ?')
      .get(taskId) as unknown as OccurrenceDbRow | undefined;
    return row ? this.mapOccurrenceRow(row) : null;
  }

  public getOccurrenceByScheduleAndKey(scheduleId: string, occurrenceKey: string): ScheduleOccurrence | null {
    const row = this.db.prepare('SELECT * FROM schedule_occurrences WHERE schedule_id = ? AND occurrence_key = ?')
      .get(scheduleId, occurrenceKey) as unknown as OccurrenceDbRow | undefined;
    return row ? this.mapOccurrenceRow(row) : null;
  }

  public listOccurrencesByScheduleId(
    scheduleId: string,
    limit: number = 50,
    offset: number = 0
  ): ScheduleOccurrence[] {
    const rows = this.db.prepare(`
      SELECT * FROM schedule_occurrences
      WHERE schedule_id = ?
      ORDER BY scheduled_for DESC, created_at DESC
      LIMIT ? OFFSET ?
    `).all(scheduleId, limit, offset) as unknown as OccurrenceDbRow[];
    return rows.map((r) => this.mapOccurrenceRow(r));
  }

  public listIncompleteOccurrences(): ScheduleOccurrence[] {
    const rows = this.db.prepare(`
      SELECT * FROM schedule_occurrences
      WHERE status IN ('CLAIMED', 'TASK_CREATED', 'RUNNING', 'AWAITING_APPROVAL')
      ORDER BY claimed_at ASC, created_at ASC
    `).all() as unknown as OccurrenceDbRow[];
    return rows.map((r) => this.mapOccurrenceRow(r));
  }

  public getActiveOccurrenceForSchedule(scheduleId: string): ScheduleOccurrence | null {
    const row = this.db.prepare(`
      SELECT * FROM schedule_occurrences
      WHERE schedule_id = ?
        AND status IN ('CLAIMED', 'TASK_CREATED', 'RUNNING', 'AWAITING_APPROVAL')
      LIMIT 1
    `).get(scheduleId) as unknown as OccurrenceDbRow | undefined;
    return row ? this.mapOccurrenceRow(row) : null;
  }

  private mapScheduleRow(row: ScheduleDbRow): Schedule {
    return {
      id: row.id,
      name: row.name,
      goal: row.goal,
      scheduleType: row.schedule_type as ScheduleType,
      status: row.status as ScheduleStatus,
      runAt: row.run_at,
      intervalMs: row.interval_ms,
      missedRunPolicy: row.missed_run_policy as MissedRunPolicy,
      overlapPolicy: row.overlap_policy as OverlapPolicy,
      maxConsecutiveFailures: row.max_consecutive_failures,
      consecutiveFailures: row.consecutive_failures,
      scopeType: row.scope_type as MemoryScopeType,
      scopeId: row.scope_id,
      createdBy: row.created_by,
      metadataJson: row.metadata_json,
      nextRunAt: row.next_run_at,
      lastRunAt: row.last_run_at,
      lastTaskId: row.last_task_id,
      pausedReason: row.paused_reason,
      createdAt: row.created_at,
      updatedAt: row.updated_at
    };
  }

  private mapOccurrenceRow(row: OccurrenceDbRow): ScheduleOccurrence {
    return {
      id: row.id,
      scheduleId: row.schedule_id,
      occurrenceKey: row.occurrence_key,
      scheduledFor: row.scheduled_for,
      status: row.status as OccurrenceStatus,
      taskId: row.task_id,
      claimedAt: row.claimed_at,
      startedAt: row.started_at,
      completedAt: row.completed_at,
      errorSummary: row.error_summary,
      createdAt: row.created_at,
      updatedAt: row.updated_at
    };
  }
}
