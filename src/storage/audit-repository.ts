/**
 * Next-Generation Dots AI Platform - Audit Repository
 * 
 * Architectural Mandate:
 * Implements an immutable, append-only audit event store.
 * Every authorization check, state transition, tool execution, and human decision
 * is cryptographically hashed with SHA-256 for tamper-evidence and permanent traceability.
 */

import { randomUUID, createHash } from 'node:crypto';
import { DatabaseManager } from './db.ts';
import type { AuditEvent, AppendAuditEventInput } from '../domain/types.ts';
import { ValidationError } from '../domain/errors.ts';

interface AuditDbRow {
  id: string;
  task_id: string;
  event_type: string;
  actor: string;
  details_json: string;
  payload_hash: string;
  timestamp: string;
}

export class AuditRepository {
  public readonly db: DatabaseManager;

  constructor(db: DatabaseManager) {
    this.db = db;
  }

  /**
   * Appends an immutable audit event with a cryptographic SHA-256 digest.
   */
  public appendEvent(input: AppendAuditEventInput): AuditEvent {
    if (!input.taskId) {
      throw new ValidationError('Audit event must be linked to a taskId.');
    }

    const id = input.id ?? randomUUID();
    const now = new Date().toISOString();
    const detailsJson = JSON.stringify(input.details);
    const payloadHash = createHash('sha256').update(detailsJson, 'utf8').digest('hex');

    const stmt = this.db.prepare(`
      INSERT INTO audit_events (
        id, task_id, event_type, actor, details_json, payload_hash, timestamp
      ) VALUES (?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      id,
      input.taskId,
      input.eventType,
      input.actor,
      detailsJson,
      payloadHash,
      now
    );

    return {
      id,
      taskId: input.taskId,
      eventType: input.eventType,
      actor: input.actor,
      detailsJson,
      payloadHash,
      timestamp: now
    };
  }

  /**
   * Retrieves all audit events for a task in strict chronological order.
   */
  public getEventsByTaskId(taskId: string): AuditEvent[] {
    const stmt = this.db.prepare(
      'SELECT * FROM audit_events WHERE task_id = ? ORDER BY timestamp ASC, id ASC'
    );
    const rows = stmt.all(taskId) as unknown as AuditDbRow[];
    return rows.map((r) => this.mapAuditRow(r));
  }

  /**
   * Retrieves a single audit event by ID.
   */
  public getEventById(id: string): AuditEvent | null {
    const stmt = this.db.prepare('SELECT * FROM audit_events WHERE id = ?');
    const row = stmt.get(id) as unknown as AuditDbRow | undefined;
    if (!row) {
      return null;
    }
    return this.mapAuditRow(row);
  }

  private mapAuditRow(row: AuditDbRow): AuditEvent {
    return {
      id: row.id,
      taskId: row.task_id,
      eventType: row.event_type as AuditEvent['eventType'],
      actor: row.actor as AuditEvent['actor'],
      detailsJson: row.details_json,
      payloadHash: row.payload_hash,
      timestamp: row.timestamp
    };
  }
}
