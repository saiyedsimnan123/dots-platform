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
  RecordMemoryInjectionInput,
  ScopeIdentifier,
  SupersedeMemoryParams
} from '../domain/types.ts';
import type {
  MissingEmbeddingMemoryRecord,
  ListMissingEmbeddingsFilter
} from '../memory/embedding-types.ts';
import {
  ValidationError,
  MemoryNotFoundError,
  MemoryConflictError,
  MemoryScopeViolationError
} from '../domain/errors.ts';

export type { ScopeIdentifier, SupersedeMemoryParams };

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
  version: number;
  supersedes_id: string | null;
  superseded_by: string | null;
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
  'ARCHIVED',
  'SUPERSEDED'
]);

export class MemoryRepository {
  public readonly db: DatabaseManager;

  constructor(db: DatabaseManager) {
    this.db = db;
  }

  /**
   * Executes a callback within an immediate database transaction.
   */
  public transaction<T>(callback: () => T): T {
    return this.db.transaction(callback);
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

    const status = (input.status ?? 'ACTIVE') as MemoryStatus;
    this.validateStatus(status);
    if ((status as string) === 'SUPERSEDED') {
      throw new ValidationError("Direct creation of memories with status 'SUPERSEDED' is not permitted. Use supersedeMemory instead.");
    }

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
        priority, tags_json, metadata_json, version, supersedes_id, superseded_by,
        created_at, updated_at, last_accessed_at, access_count
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, NULL, NULL, ?, ?, NULL, 0)
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

    const created = this.getMemoryByIdInternal(id);
    if (!created) {
      throw new ValidationError(`Failed to retrieve newly created memory '${id}'.`);
    }
    return created;
  }

  /**
   * Retrieves a memory record by ID strictly within the designated scope.
   * Throws MemoryScopeViolationError if the memory exists under a different scope.
   * Returns null if no record with this ID exists.
   */
  public getMemoryById(id: string, scope: ScopeIdentifier): Memory | null {
    if (!id || typeof id !== 'string' || id.trim() === '') {
      throw new ValidationError('Memory ID must be a non-empty string.');
    }
    if (!scope || typeof scope !== 'object') {
      throw new ValidationError('Scope must be provided to getMemoryById.');
    }
    this.validateScope(scope.scopeType, scope.scopeId);

    const row = this.getMemoryRowById(id);
    if (!row) {
      return null;
    }

    // Verify scope isolation: must strictly match the expected scope
    this.assertScopeMatch(row.scope_type as MemoryScopeType, row.scope_id, scope, id);

    return this.mapMemoryRow(row);
  }

  /**
   * Retrieves an active memory by its exact human-readable key within a scope.
   */
  public getMemoryByKey(key: string, scope: ScopeIdentifier, status: MemoryStatus = 'ACTIVE'): Memory | null {
    this.validateKey(key);
    if (!scope || typeof scope !== 'object') {
      throw new ValidationError('Scope must be provided to getMemoryByKey.');
    }
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
    if (!filter || typeof filter !== 'object') {
      throw new ValidationError('Filter must be provided to listMemories.');
    }
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
   * Retrieves archived memories within an explicit scope whose updated_at <= cutoffTimestamp.
   * Ordered deterministically by updated_at ASC, id ASC.
   */
  public getArchivedMemoriesOlderThan(
    scope: ScopeIdentifier,
    cutoffTimestamp: string,
    limit?: number
  ): Memory[] {
    if (!scope || typeof scope !== 'object') {
      throw new ValidationError('Scope must be provided to getArchivedMemoriesOlderThan.');
    }
    this.validateScope(scope.scopeType, scope.scopeId);
    if (typeof cutoffTimestamp !== 'string' || cutoffTimestamp.trim() === '') {
      throw new ValidationError('Cutoff timestamp must be a non-empty string.');
    }

    let sql = `
      SELECT * FROM memories 
      WHERE scope_type = ? AND scope_id = ? AND status = 'ARCHIVED' AND updated_at <= ?
      ORDER BY updated_at ASC, id ASC
    `;
    const params: SqlParam[] = [scope.scopeType, scope.scopeId, cutoffTimestamp];

    if (limit !== undefined) {
      if (typeof limit !== 'number' || !Number.isInteger(limit) || limit < 1) {
        throw new ValidationError('Limit must be a positive integer.');
      }
      sql += ' LIMIT ?';
      params.push(limit);
    }

    const stmt = this.db.prepare(sql);
    const rows = stmt.all(...params) as unknown as MemoryDbRow[];
    return rows.map((r) => this.mapMemoryRow(r));
  }

  /**
   * Counts archived memories within an explicit scope whose updated_at <= cutoffTimestamp.
   */
  public countArchivedMemoriesOlderThan(
    scope: ScopeIdentifier,
    cutoffTimestamp: string
  ): number {
    if (!scope || typeof scope !== 'object') {
      throw new ValidationError('Scope must be provided to countArchivedMemoriesOlderThan.');
    }
    this.validateScope(scope.scopeType, scope.scopeId);
    if (typeof cutoffTimestamp !== 'string' || cutoffTimestamp.trim() === '') {
      throw new ValidationError('Cutoff timestamp must be a non-empty string.');
    }

    const stmt = this.db.prepare(`
      SELECT COUNT(*) as count FROM memories 
      WHERE scope_type = ? AND scope_id = ? AND status = 'ARCHIVED' AND updated_at <= ?
    `);
    const row = stmt.get(scope.scopeType, scope.scopeId, cutoffTimestamp) as unknown as { count: number };
    return row.count;
  }

  /**
   * Queries active memories within an authoritative scope that are missing embeddings
   * for an exact (modelId, modelRevision) pair.
   * Deterministically ordered by (created_at ASC, id ASC).
   */
  public getMemoriesMissingEmbeddings(
    filter: ListMissingEmbeddingsFilter
  ): MissingEmbeddingMemoryRecord[] {
    if (!filter || typeof filter !== 'object') {
      throw new ValidationError('ListMissingEmbeddingsFilter must be provided.');
    }
    this.validateScope(filter.scopeType, filter.scopeId);
    if (!filter.modelId || typeof filter.modelId !== 'string' || filter.modelId.trim() === '') {
      throw new ValidationError('modelId must be a non-empty string.');
    }
    if (filter.limit !== undefined) {
      if (typeof filter.limit !== 'number' || !Number.isInteger(filter.limit) || filter.limit <= 0) {
        throw new ValidationError('limit must be a positive integer.');
      }
    }

    const modelRevision = filter.modelRevision ?? 'main';
    let sql = `
      SELECT m.id, m.key, m.content, m.updated_at
      FROM memories m
      LEFT JOIN memory_embeddings me
        ON me.memory_id = m.id
        AND me.model_id = ?
        AND me.model_revision = ?
      WHERE m.scope_type = ?
        AND m.scope_id = ?
        AND m.status = 'ACTIVE'
        AND me.id IS NULL
      ORDER BY m.created_at ASC, m.id ASC
    `;

    const params: SqlParam[] = [
      filter.modelId,
      modelRevision,
      filter.scopeType,
      filter.scopeId
    ];

    if (filter.limit !== undefined) {
      sql += ' LIMIT ?';
      params.push(filter.limit);
    }

    const stmt = this.db.prepare(sql);
    const rows = stmt.all(...params) as unknown as Array<{
      id: string;
      key: string;
      content: string;
      updated_at: string;
    }>;

    return rows.map((r) => ({
      id: r.id,
      key: r.key,
      content: r.content,
      updatedAt: r.updated_at
    }));
  }

  /**
   * Counts active memories within an authoritative scope that are missing embeddings
   * for an exact (modelId, modelRevision) pair.
   */
  public countMemoriesMissingEmbeddings(
    scopeType: MemoryScopeType,
    scopeId: string,
    modelId: string,
    modelRevision = 'main'
  ): number {
    this.validateScope(scopeType, scopeId);
    if (!modelId || typeof modelId !== 'string' || modelId.trim() === '') {
      throw new ValidationError('modelId must be a non-empty string.');
    }

    const sql = `
      SELECT COUNT(*) as count
      FROM memories m
      LEFT JOIN memory_embeddings me
        ON me.memory_id = m.id
        AND me.model_id = ?
        AND me.model_revision = ?
      WHERE m.scope_type = ?
        AND m.scope_id = ?
        AND m.status = 'ACTIVE'
        AND me.id IS NULL
    `;

    const stmt = this.db.prepare(sql);
    const row = stmt.get(modelId, modelRevision, scopeType, scopeId) as unknown as { count: number } | undefined;
    return Number(row?.count ?? 0);
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
      if ((input.status as string) === 'SUPERSEDED') {
        throw new ValidationError("Cannot directly transition a memory to status 'SUPERSEDED'. Use supersedeMemory instead.");
      }

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
    const existing = this.getMemoryById(id, scope);
    if (!existing) {
      throw new MemoryNotFoundError(id);
    }
    if (existing.status === 'SUPERSEDED') {
      throw new ValidationError(`Cannot archive memory '${id}': record is superseded. Superseded memories are immutable historical records.`);
    }
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
    if (existing.status === 'SUPERSEDED' || existing.supersedesId !== null || existing.supersededBy !== null) {
      throw new ValidationError(
        `Cannot delete memory '${id}': record is part of a supersession history chain. Archival should be used instead of hard deletion.`
      );
    }

    const stmt = this.db.prepare('DELETE FROM memories WHERE id = ? AND scope_type = ? AND scope_id = ?');
    const result = stmt.run(id, scope.scopeType, scope.scopeId);
    return result.changes > 0;
  }

  /**
   * Physically deletes an archived memory from the database.
   * Strictly enforces status = 'ARCHIVED' in the DELETE statement to prevent deleting
   * active or pending records even under concurrent status modifications.
   * Verifies that exactly one eligible row was deleted.
   * SQLite foreign keys automatically set memory_id = NULL in memory_task_injections.
   */
  public deleteArchivedMemory(id: string, scope: ScopeIdentifier): boolean {
    if (!id || typeof id !== 'string' || id.trim() === '') {
      throw new ValidationError('Memory ID must be a non-empty string.');
    }
    if (!scope || typeof scope !== 'object') {
      throw new ValidationError('Scope must be provided to deleteArchivedMemory.');
    }
    this.validateScope(scope.scopeType, scope.scopeId);

    const stmt = this.db.prepare(`
      DELETE FROM memories 
      WHERE id = ? AND scope_type = ? AND scope_id = ? AND status = 'ARCHIVED'
    `);
    const result = stmt.run(id, scope.scopeType, scope.scopeId);
    return result.changes === 1;
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

  /**
   * Retrieves the version history of a memory key within a designated scope.
   * Deterministically ordered by version ASC, created_at ASC, id ASC.
   * Returns records across all statuses (ACTIVE, SUPERSEDED, PENDING_APPROVAL, ARCHIVED).
   */
  public getMemoryHistory(key: string, scope: ScopeIdentifier): Memory[] {
    this.validateKey(key);
    if (!scope || typeof scope !== 'object') {
      throw new ValidationError('Scope must be provided to getMemoryHistory.');
    }
    this.validateScope(scope.scopeType, scope.scopeId);

    const stmt = this.db.prepare(`
      SELECT * FROM memories
      WHERE scope_type = ? AND scope_id = ? AND key = ?
      ORDER BY version ASC, created_at ASC, id ASC
    `);
    const rows = stmt.all(scope.scopeType, scope.scopeId, key.trim()) as unknown as MemoryDbRow[];
    return rows.map((r) => this.mapMemoryRow(r));
  }

  /**
   * Atomically supersedes an existing memory with a replacement memory.
   *
   * Pre-conditions & Invariants:
   * 1. Both memories must exist within the designated scope.
   * 2. Memory keys must match (case-insensitive trim).
   * 3. Previous cannot be superseded by itself (self-link rejected).
   * 4. Previous cannot already be superseded (status === 'SUPERSEDED' or supersededBy !== null).
   * 5. Replacement cannot already supersede another memory (supersedesId !== null && supersedesId !== previous.id).
   * 6. Lineage cycle detection: walks ancestors of previous and descendants of replacement.
   * 7. Version ordering: replacement version must be > previous version.
   *    If replacement.version < previous.version and newVersion is omitted, throws ValidationError.
   *    If newVersion is explicitly passed and <= previous.version, throws ValidationError.
   *    Target version defaults to Math.max(replacement.version, previous.version + 1).
   * 8. Atomicity: within an immediate transaction, previous is marked SUPERSEDED with superseded_by = replacement.id,
   *    then replacement is updated with supersedes_id = previous.id, version = targetVersion, and replacementStatus.
   */
  public supersedeMemory(params: SupersedeMemoryParams): { previous: Memory; replacement: Memory } {
    if (!params || typeof params !== 'object') {
      throw new ValidationError('Parameters must be provided to supersedeMemory.');
    }
    if (!params.previousId || typeof params.previousId !== 'string' || params.previousId.trim() === '') {
      throw new ValidationError('previousId must be a non-empty string.');
    }
    if (!params.replacementId || typeof params.replacementId !== 'string' || params.replacementId.trim() === '') {
      throw new ValidationError('replacementId must be a non-empty string.');
    }
    if (!params.scope || typeof params.scope !== 'object') {
      throw new ValidationError('Scope must be provided to supersedeMemory.');
    }
    this.validateScope(params.scope.scopeType, params.scope.scopeId);

    const prevId = params.previousId.trim();
    const repId = params.replacementId.trim();

    if (prevId === repId) {
      throw new ValidationError(`Cannot supersede memory '${prevId}' with itself.`);
    }

    if (params.replacementStatus !== undefined) {
      this.validateStatus(params.replacementStatus);
      if (params.replacementStatus === 'SUPERSEDED') {
        throw new ValidationError("Replacement memory status cannot be 'SUPERSEDED'.");
      }
    }

    if (params.newVersion !== undefined) {
      this.validateVersion(params.newVersion);
    }

    return this.transaction(() => {
      const previous = this.getMemoryById(prevId, params.scope);
      if (!previous) {
        throw new MemoryNotFoundError(prevId);
      }

      const replacement = this.getMemoryById(repId, params.scope);
      if (!replacement) {
        throw new MemoryNotFoundError(repId);
      }

      // Keys must match exactly (binary equality)
      if (previous.key.trim() !== replacement.key.trim()) {
        throw new ValidationError(
          `Cannot supersede memory with mismatched keys: previous key '${previous.key}' vs replacement key '${replacement.key}'.`
        );
      }

      // Previous must be ACTIVE
      if (previous.status !== 'ACTIVE') {
        throw new ValidationError(
          `Cannot supersede memory '${previous.id}': status is '${previous.status}'. Only records with status 'ACTIVE' can be superseded.`
        );
      }

      // Previous must not already be superseded
      if (previous.supersededBy !== null) {
        throw new ValidationError(
          `Memory '${previous.id}' has already been superseded by '${previous.supersededBy}'.`
        );
      }

      // Replacement must not already be superseded
      if (replacement.status === 'SUPERSEDED' || replacement.supersededBy !== null) {
        throw new ValidationError(
          `Replacement memory '${replacement.id}' has already been superseded.`
        );
      }

      // Replacement must not already supersede another record
      if (replacement.supersedesId !== null && replacement.supersedesId !== previous.id) {
        throw new ValidationError(
          `Replacement memory '${replacement.id}' already supersedes '${replacement.supersedesId}'.`
        );
      }

      // Cycle detection: walk supersedes_id chain backwards from previous
      let ancestorId = previous.supersedesId;
      const visitedAncestors = new Set<string>([previous.id, replacement.id]);
      while (ancestorId) {
        if (ancestorId === replacement.id) {
          throw new ValidationError(
            `Supersession cycle detected: replacement '${replacement.id}' is an ancestor of previous '${previous.id}'.`
          );
        }
        if (visitedAncestors.has(ancestorId)) {
          break;
        }
        visitedAncestors.add(ancestorId);
        const ancestor = this.getMemoryById(ancestorId, params.scope);
        ancestorId = ancestor?.supersedesId ?? null;
      }

      // Cycle detection: walk superseded_by chain forwards from replacement
      let descendantId: string | null = replacement.supersededBy;
      const visitedDescendants = new Set<string>([previous.id, replacement.id]);
      while (descendantId) {
        if (descendantId === previous.id) {
          throw new ValidationError(
            `Supersession cycle detected: previous '${previous.id}' is a descendant of replacement '${replacement.id}'.`
          );
        }
        if (visitedDescendants.has(descendantId)) {
          break;
        }
        visitedDescendants.add(descendantId);
        const descendant = this.getMemoryById(descendantId, params.scope);
        descendantId = descendant?.supersededBy ?? null;
      }

      // Determine target version:
      // If newVersion is omitted, always previous.version + 1.
      // If newVersion is supplied, must be strictly greater than previous.version.
      let targetVersion: number;
      if (params.newVersion !== undefined) {
        if (params.newVersion <= previous.version) {
          throw new ValidationError(
            `Replacement version (${params.newVersion}) must be strictly greater than previous version (${previous.version}).`
          );
        }
        targetVersion = params.newVersion;
      } else {
        targetVersion = previous.version + 1;
      }

      const now = new Date().toISOString();

      // 1. Mark previous memory as SUPERSEDED and link forward
      this.db.prepare(`
        UPDATE memories
        SET status = 'SUPERSEDED', superseded_by = ?, updated_at = ?
        WHERE id = ? AND scope_type = ? AND scope_id = ?
      `).run(replacement.id, now, previous.id, params.scope.scopeType, params.scope.scopeId);

      // 2. Link replacement backward, update version, and optionally status
      const finalStatus = params.replacementStatus ?? replacement.status;
      try {
        this.db.prepare(`
          UPDATE memories
          SET supersedes_id = ?, version = ?, status = ?, updated_at = ?
          WHERE id = ? AND scope_type = ? AND scope_id = ?
        `).run(
          previous.id,
          targetVersion,
          finalStatus,
          now,
          replacement.id,
          params.scope.scopeType,
          params.scope.scopeId
        );
      } catch (err) {
        if (err instanceof Error && /UNIQUE constraint failed/i.test(err.message)) {
          throw new MemoryConflictError(replacement.key, params.scope.scopeType, params.scope.scopeId);
        }
        throw err;
      }

      const updatedPrevious = this.getMemoryById(previous.id, params.scope);
      const updatedReplacement = this.getMemoryById(replacement.id, params.scope);

      if (!updatedPrevious || !updatedReplacement) {
        throw new ValidationError('Failed to retrieve updated memories after supersession.');
      }

      return {
        previous: updatedPrevious,
        replacement: updatedReplacement
      };
    });
  }

  // --- Private Helpers ---

  private getMemoryRowById(id: string): MemoryDbRow | undefined {
    const stmt = this.db.prepare('SELECT * FROM memories WHERE id = ?');
    return stmt.get(id) as unknown as MemoryDbRow | undefined;
  }

  private getMemoryByIdInternal(id: string): Memory | null {
    const row = this.getMemoryRowById(id);
    if (!row) {
      return null;
    }
    return this.mapMemoryRow(row);
  }

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

  private validateVersion(version: unknown): void {
    if (typeof version !== 'number' || !Number.isInteger(version) || version < 1) {
      throw new ValidationError(`Memory version must be an integer >= 1, received '${String(version)}'.`);
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
      version: row.version,
      supersedesId: row.supersedes_id,
      supersededBy: row.superseded_by,
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
