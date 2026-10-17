/**
 * Next-Generation Dots AI Platform - Memory Repository
 * 
 * Architectural Mandate:
 * Implements durable, ACID-compliant persistence for user-controlled long-term memory.
 * 
 * Guarantees:
 * 1. 100% parameterized SQL to prevent SQL injection.
 * 2. Strict scope isolation: validates that workspace and global operations are isolated.
 * 3. Enforces unique active keys per scope, throwing MemoryConflictError on collision.
 * 4. Hard deletion physically erases memory content while safely nulling injection provenance foreign keys.
 * 5. Access counts and access timestamps are only updated through explicit repository operations.
 */

import { randomUUID } from 'node:crypto';
import type { DatabaseManager } from './db.ts';
import type {
  Memory,
  MemoryCategory,
  MemoryScopeType,
  MemoryStatus,
  MemoryTaskInjection,
  CreateMemoryInput,
  UpdateMemoryInput,
  ListMemoriesFilter,
  RecordMemoryInjectionInput
} from '../domain/types.ts';
import {
  ValidationError,
  MemoryNotFoundError,
  MemoryConflictError,
  MemoryScopeViolationError
} from '../domain/errors.ts';

export interface ScopeIdentifier {
  readonly scopeType: MemoryScopeType;
  readonly scopeId: string;
}

interface MemoryDbRow {
  id: string;
  category: string;
  scope_type: string;
  scope_id: string;
  key: string;
  content: string;
  status: string;
  priority: number;
  tags_json: string;
  metadata_json: string;
  created_at: string;
  updated_at: string;
  last_accessed_at: string | null;
  access_count: number;
}

interface InjectionDbRow {
  id: string;
  task_id: string;
  memory_id: string | null;
  char_count: number;
  estimated_tokens: number;
  injected_at: string;
}

type SqlParam = null | number | bigint | string | Uint8Array;

const VALID_CATEGORIES: ReadonlySet<MemoryCategory> = new Set([
  'USER_PREFERENCE',
  'PROJECT_FACT',
  'LEARNED_PROCEDURE'
]);

const VALID_SCOPES: ReadonlySet<MemoryScopeType> = new Set(['GLOBAL', 'WORKSPACE']);

const VALID_STATUSES: ReadonlySet<MemoryStatus> = new Set([
  'ACTIVE',
  'PENDING_APPROVAL',
  'ARCHIVED'
]);

export class MemoryRepository {
  private readonly db: DatabaseManager;

  constructor(db: DatabaseManager) {
    this.db = db;
  }

  /**
   * Persists a new memory entity within the designated scope.
   */
  public createMemory(input: CreateMemoryInput): Memory {
    // 1. Validate fields
    this.validateKey(input.key);
    this.validateContent(input.content);
    this.validateCategory(input.category);
    this.validateScope(input.scopeType, input.scopeId);

    const status: MemoryStatus = input.status ?? 'ACTIVE';
    this.validateStatus(status);

    const priority = input.priority ?? 50;
    this.validatePriority(priority);

    // 2. Enforce active key uniqueness within scope
    if (status === 'ACTIVE') {
      const existing = this.getActiveByKey(input.key, input.scopeType, input.scopeId);
      if (existing) {
        throw new MemoryConflictError(input.key, input.scopeType, input.scopeId);
      }
    }

    const id = input.id ?? randomUUID();
    const now = new Date().toISOString();
    const tagsJson = JSON.stringify(input.tags ?? []);
    const metadataJson = JSON.stringify(input.metadata ?? {});

    const stmt = this.db.prepare(`
      INSERT INTO memories (
        id, category, scope_type, scope_id, key, content, status,
        priority, tags_json, metadata_json, created_at, updated_at,
        last_accessed_at, access_count
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, 0)
    `);

    try {
      stmt.run(
        id,
        input.category,
        input.scopeType,
        input.scopeId,
        input.key.trim(),
        input.content.trim(),
        status,
        priority,
        tagsJson,
        metadataJson,
        now,
        now
      );
    } catch (err) {
      if (err instanceof Error && /UNIQUE constraint failed/i.test(err.message)) {
        throw new MemoryConflictError(input.key, input.scopeType, input.scopeId);
      }
      throw err;
    }

    const created = this.getMemoryById(id);
    if (!created) {
      throw new ValidationError(`Failed to retrieve newly created memory '${id}'.`);
    }
    return created;
  }

  /**
   * Retrieves a memory record by ID.
   * If scope is provided, strictly enforces scope containment.
   */
  public getMemoryById(id: string, scope?: ScopeIdentifier): Memory | null {
    if (!id || typeof id !== 'string' || id.trim() === '') {
      throw new ValidationError('Memory ID must be a non-empty string.');
    }

    const stmt = this.db.prepare('SELECT * FROM memories WHERE id = ?');
    const row = stmt.get(id) as unknown as MemoryDbRow | undefined;
    if (!row) {
      return null;
    }

    // Verify scope isolation if scope was specified
    if (scope) {
      this.assertScopeMatch(row.scope_type as MemoryScopeType, row.scope_id, scope, id);
    }

    return this.mapMemoryRow(row);
  }

  /**
   * Retrieves an active memory by its exact human-readable key within a scope.
   */
  public getMemoryByKey(key: string, scope: ScopeIdentifier, status: MemoryStatus = 'ACTIVE'): Memory | null {
    this.validateKey(key);
    this.validateScope(scope.scopeType, scope.scopeId);
    this.validateStatus(status);

    const stmt = this.db.prepare(`
      SELECT * FROM memories 
      WHERE scope_type = ? AND scope_id = ? AND key = ? AND status = ?
    `);
    const row = stmt.get(scope.scopeType, scope.scopeId, key.trim(), status) as unknown as MemoryDbRow | undefined;
    if (!row) {
      return null;
    }
    return this.mapMemoryRow(row);
  }

  /**
   * Lists memories within an explicit scope, with optional status and category filters.
   */
  public listMemories(filter: ListMemoriesFilter): Memory[] {
    this.validateScope(filter.scopeType, filter.scopeId);

    const conditions: string[] = ['scope_type = ?', 'scope_id = ?'];
    const params: SqlParam[] = [filter.scopeType, filter.scopeId];

    if (filter.status) {
      this.validateStatus(filter.status);
      conditions.push('status = ?');
      params.push(filter.status);
    }

    if (filter.category) {
      this.validateCategory(filter.category);
      conditions.push('category = ?');
      params.push(filter.category);
    }

    let sql = `SELECT * FROM memories WHERE ${conditions.join(' AND ')} ORDER BY priority DESC, created_at DESC, key ASC`;

    if (filter.limit !== undefined) {
      if (typeof filter.limit !== 'number' || filter.limit < 1) {
        throw new ValidationError('Limit must be a positive integer.');
      }
      sql += ' LIMIT ?';
      params.push(filter.limit);

      if (filter.offset !== undefined) {
        if (typeof filter.offset !== 'number' || filter.offset < 0) {
          throw new ValidationError('Offset must be a non-negative integer.');
        }
        sql += ' OFFSET ?';
        params.push(filter.offset);
      }
    }

    const stmt = this.db.prepare(sql);
    const rows = stmt.all(...params) as unknown as MemoryDbRow[];
    return rows.map((r) => this.mapMemoryRow(r));
  }

  /**
   * Updates an existing memory record, verifying scope containment.
   */
  public updateMemory(id: string, scope: ScopeIdentifier, input: UpdateMemoryInput): Memory {
    const existing = this.getMemoryById(id, scope);
    if (!existing) {
      throw new MemoryNotFoundError(id);
    }

    const updates: string[] = [];
    const params: SqlParam[] = [];

    if (input.content !== undefined) {
      this.validateContent(input.content);
      updates.push('content = ?');
      params.push(input.content.trim());
    }

    if (input.category !== undefined) {
      this.validateCategory(input.category);
      updates.push('category = ?');
      params.push(input.category);
    }

    if (input.priority !== undefined) {
      this.validatePriority(input.priority);
      updates.push('priority = ?');
      params.push(input.priority);
    }

    if (input.tags !== undefined) {
      updates.push('tags_json = ?');
      params.push(JSON.stringify(input.tags));
    }

    if (input.metadata !== undefined) {
      updates.push('metadata_json = ?');
      params.push(JSON.stringify(input.metadata));
    }

    if (input.status !== undefined) {
      this.validateStatus(input.status);

      // If status is transitioning to ACTIVE, enforce key uniqueness
      if (input.status === 'ACTIVE' && existing.status !== 'ACTIVE') {
        const activeExisting = this.getActiveByKey(existing.key, existing.scopeType, existing.scopeId);
        if (activeExisting && activeExisting.id !== id) {
          throw new MemoryConflictError(existing.key, existing.scopeType, existing.scopeId);
        }
      }

      updates.push('status = ?');
      params.push(input.status);
    }

    if (updates.length === 0) {
      return existing;
    }

    const now = new Date().toISOString();
    updates.push('updated_at = ?');
    params.push(now);

    params.push(id);
    params.push(scope.scopeType);
    params.push(scope.scopeId);

    const sql = `UPDATE memories SET ${updates.join(', ')} WHERE id = ? AND scope_type = ? AND scope_id = ?`;
    const stmt = this.db.prepare(sql);

    try {
      const result = stmt.run(...params);
      if (result.changes === 0) {
        throw new MemoryNotFoundError(id);
      }
    } catch (err) {
      if (err instanceof Error && /UNIQUE constraint failed/i.test(err.message)) {
        throw new MemoryConflictError(existing.key, existing.scopeType, existing.scopeId);
      }
      throw err;
    }

    const updated = this.getMemoryById(id, scope);
    if (!updated) {
      throw new MemoryNotFoundError(id);
    }
    return updated;
  }

  /**
   * Sets status to 'ARCHIVED' without deleting the record.
   */
  public archiveMemory(id: string, scope: ScopeIdentifier): Memory {
    return this.updateMemory(id, scope, { status: 'ARCHIVED' });
  }

  /**
   * Physically deletes a memory from the database.
   * SQLite foreign keys automatically set memory_id = NULL in memory_task_injections.
   */
  public deleteMemory(id: string, scope: ScopeIdentifier): boolean {
    const existing = this.getMemoryById(id, scope);
    if (!existing) {
      throw new MemoryNotFoundError(id);
    }

    const stmt = this.db.prepare('DELETE FROM memories WHERE id = ? AND scope_type = ? AND scope_id = ?');
    const result = stmt.run(id, scope.scopeType, scope.scopeId);
    return result.changes > 0;
  }

  /**
   * Explicitly updates access timestamp and access count for a memory item.
   * Does NOT run during standard reads.
   */
  public recordAccess(id: string, scope: ScopeIdentifier): Memory {
    const existing = this.getMemoryById(id, scope);
    if (!existing) {
      throw new MemoryNotFoundError(id);
    }

    const now = new Date().toISOString();
    const stmt = this.db.prepare(`
      UPDATE memories 
      SET last_accessed_at = ?, access_count = access_count + 1 
      WHERE id = ? AND scope_type = ? AND scope_id = ?
    `);
    stmt.run(now, id, scope.scopeType, scope.scopeId);

    const updated = this.getMemoryById(id, scope);
    if (!updated) {
      throw new MemoryNotFoundError(id);
    }
    return updated;
  }

  /**
   * Records provenance of a memory injection into a workflow task.
   */
  public recordInjection(input: RecordMemoryInjectionInput): MemoryTaskInjection {
    if (!input.taskId || typeof input.taskId !== 'string' || input.taskId.trim() === '') {
      throw new ValidationError('Task ID must be a non-empty string.');
    }
    if (typeof input.charCount !== 'number' || input.charCount < 0) {
      throw new ValidationError('Char count must be a non-negative integer.');
    }
    if (typeof input.estimatedTokens !== 'number' || input.estimatedTokens < 0) {
      throw new ValidationError('Estimated tokens must be a non-negative integer.');
    }

    const id = input.id ?? randomUUID();
    const now = new Date().toISOString();

    const stmt = this.db.prepare(`
      INSERT INTO memory_task_injections (
        id, task_id, memory_id, char_count, estimated_tokens, injected_at
      ) VALUES (?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      id,
      input.taskId,
      input.memoryId ?? null,
      input.charCount,
      input.estimatedTokens,
      now
    );

    return {
      id,
      taskId: input.taskId,
      memoryId: input.memoryId ?? null,
      charCount: input.charCount,
      estimatedTokens: input.estimatedTokens,
      injectedAt: now
    };
  }

  /**
   * Retrieves injection provenance records for a task.
   */
  public getInjectionsByTaskId(taskId: string): MemoryTaskInjection[] {
    const stmt = this.db.prepare('SELECT * FROM memory_task_injections WHERE task_id = ? ORDER BY injected_at ASC');
    const rows = stmt.all(taskId) as unknown as InjectionDbRow[];
    return rows.map((r) => this.mapInjectionRow(r));
  }

  /**
   * Retrieves injection provenance records referencing a memory ID.
   */
  public getInjectionsByMemoryId(memoryId: string): MemoryTaskInjection[] {
    const stmt = this.db.prepare('SELECT * FROM memory_task_injections WHERE memory_id = ? ORDER BY injected_at ASC');
    const rows = stmt.all(memoryId) as unknown as InjectionDbRow[];
    return rows.map((r) => this.mapInjectionRow(r));
  }

  // --- Private Helpers ---

  private getActiveByKey(key: string, scopeType: MemoryScopeType, scopeId: string): MemoryDbRow | undefined {
    const stmt = this.db.prepare(`
      SELECT * FROM memories 
      WHERE scope_type = ? AND scope_id = ? AND key = ? AND status = 'ACTIVE'
    `);
    return stmt.get(scopeType, scopeId, key.trim()) as unknown as MemoryDbRow | undefined;
  }

  private assertScopeMatch(
    actualType: MemoryScopeType,
    actualId: string,
    expected: ScopeIdentifier,
    memoryId: string
  ): void {
    if (actualType !== expected.scopeType || actualId !== expected.scopeId) {
      throw new MemoryScopeViolationError(
        `${expected.scopeType}:${expected.scopeId}`,
        `${actualType}:${actualId}`,
        memoryId
      );
    }
  }

  private validateKey(key: unknown): void {
    if (typeof key !== 'string' || key.trim() === '') {
      throw new ValidationError('Memory key must be a non-empty string.');
    }
    if (key.length > 256) {
      throw new ValidationError(`Memory key exceeds limit of 256 characters (${key.length} > 256).`);
    }
  }

  private validateContent(content: unknown): void {
    if (typeof content !== 'string' || content.trim() === '') {
      throw new ValidationError('Memory content must be a non-empty string.');
    }
  }

  private validateCategory(category: unknown): void {
    if (!category || !VALID_CATEGORIES.has(category as MemoryCategory)) {
      throw new ValidationError(
        `Invalid memory category '${String(category)}'. Must be one of: ${Array.from(VALID_CATEGORIES).join(', ')}.`
      );
    }
  }

  private validateScope(scopeType: unknown, scopeId: unknown): void {
    if (!scopeType || !VALID_SCOPES.has(scopeType as MemoryScopeType)) {
      throw new ValidationError(
        `Invalid memory scope type '${String(scopeType)}'. Must be one of: ${Array.from(VALID_SCOPES).join(', ')}.`
      );
    }
    if (typeof scopeId !== 'string' || scopeId.trim() === '') {
      throw new ValidationError('Memory scopeId must be a non-empty string.');
    }
    if (scopeType === 'GLOBAL' && scopeId !== 'default') {
      throw new ValidationError(`Global memory scopeId must be 'default', received '${scopeId}'.`);
    }
  }

  private validateStatus(status: unknown): void {
    if (!status || !VALID_STATUSES.has(status as MemoryStatus)) {
      throw new ValidationError(
        `Invalid memory status '${String(status)}'. Must be one of: ${Array.from(VALID_STATUSES).join(', ')}.`
      );
    }
  }

  private validatePriority(priority: unknown): void {
    if (typeof priority !== 'number' || !Number.isInteger(priority) || priority < 0 || priority > 100) {
      throw new ValidationError(`Memory priority must be an integer between 0 and 100, received '${String(priority)}'.`);
    }
  }

  private mapMemoryRow(row: MemoryDbRow): Memory {
    return {
      id: row.id,
      category: row.category as MemoryCategory,
      scopeType: row.scope_type as MemoryScopeType,
      scopeId: row.scope_id,
      key: row.key,
      content: row.content,
      status: row.status as MemoryStatus,
      priority: row.priority,
      tagsJson: row.tags_json,
      metadataJson: row.metadata_json,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      lastAccessedAt: row.last_accessed_at,
      accessCount: row.access_count
    };
  }

  private mapInjectionRow(row: InjectionDbRow): MemoryTaskInjection {
    return {
      id: row.id,
      taskId: row.task_id,
      memoryId: row.memory_id,
      charCount: row.char_count,
      estimatedTokens: row.estimated_tokens,
      injectedAt: row.injected_at
    };
  }
}
