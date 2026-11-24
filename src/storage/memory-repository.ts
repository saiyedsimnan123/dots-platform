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

import { randomUUID, createHash } from 'node:crypto';
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
  SupersedeMemoryParams,
  EvidenceSourceType,
  EvidenceRelationship,
  MemoryEvidence,
  CreateEvidenceInput,
  MemoryClaim,
  CreateClaimInput,
  ListClaimsFilter,
  ClaimVerificationRelationship,
  ClaimVerificationCandidateOutcome,
  ClaimEvidenceVerification,
  CreateClaimVerificationInput,
  ListClaimVerificationsFilter,
  ClaimEvidenceAssociation,
  CreateClaimEvidenceAssociationInput,
  ClaimAssociationStatus,
  ClaimVerificationLifecycleStatus
} from '../domain/types.ts';
import {
  canonicalizeClaimText,
  computeClaimHash,
  computeClaimId,
  normalizeVerificationAssumptions,
  computeVerificationAssumptionsHash
} from '../memory/claim-normalizer.ts';
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

export type {
  ScopeIdentifier,
  SupersedeMemoryParams,
  MemoryEvidence,
  CreateEvidenceInput,
  EvidenceSourceType,
  EvidenceRelationship,
  MemoryClaim,
  CreateClaimInput,
  ListClaimsFilter,
  ClaimVerificationRelationship,
  ClaimVerificationCandidateOutcome,
  ClaimEvidenceVerification,
  CreateClaimVerificationInput,
  ListClaimVerificationsFilter,
  ClaimEvidenceAssociation,
  CreateClaimEvidenceAssociationInput
};

export function computeSnippetHash(snippet?: string | null, fallback: string = ''): string {
  const content = (snippet && snippet.trim().length > 0) ? snippet.trim() : fallback.trim();
  return createHash('sha256').update(content, 'utf8').digest('hex');
}

export function computeEvidenceId(memoryId: string, snippetHash: string, relationship: string): string {
  return createHash('sha256').update(`${memoryId}:${snippetHash}:${relationship}`, 'utf8').digest('hex');
}

export function computeClaimVerificationId(
  claimId: string,
  evidenceId: string,
  verifierId: string,
  verifierVersion: string,
  promptPolicyHash: string,
  assumptionsHash: string = ''
): string {
  const base = `${claimId}:${evidenceId}:${verifierId}:${verifierVersion}:${promptPolicyHash}`;
  const material = assumptionsHash ? `${base}:${assumptionsHash}` : base;
  return createHash('sha256')
    .update(material, 'utf8')
    .digest('hex');
}

export function computeClaimEvidenceAssociationId(claimId: string, evidenceId: string): string {
  return createHash('sha256')
    .update(`cea:${claimId}:${evidenceId}`, 'utf8')
    .digest('hex');
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

interface EvidenceDbRow {
  id: string;
  memory_id: string;
  source_type: string;
  source_url: string | null;
  source_domain: string | null;
  source_title: string | null;
  snippet: string | null;
  snippet_hash: string;
  relationship: string;
  task_id: string;
  agent_id: string;
  created_at: string;
}

interface ClaimDbRow {
  id: string;
  memory_id: string | null;
  scope_type: string;
  scope_id: string;
  original_text: string;
  canonical_text: string;
  claim_hash: string;
  subject: string | null;
  predicate: string | null;
  qualifier: string | null;
  task_id: string;
  created_at: string;
}

interface ClaimVerificationDbRow {
  id: string;
  claim_id: string;
  evidence_id: string;
  scope_type: string;
  scope_id: string;
  proposed_relationship: string;
  verification_outcome: string;
  verifier_id: string;
  verifier_version: string;
  prompt_policy_version: string;
  prompt_policy_hash: string;
  assumptions_hash: string;
  assumptions_json: string;
  confidence: number | null;
  explanation: string;
  review_recommended: number;
  status: string;
  stale_at: string | null;
  stale_reason: string | null;
  task_id: string | null;
  created_at: string;
}

interface ClaimEvidenceAssociationDbRow {
  id: string;
  claim_id: string;
  evidence_id: string;
  memory_id: string;
  scope_type: string;
  scope_id: string;
  relationship: string;
  status: string;
  invalidated_at: string | null;
  invalidation_reason: string | null;
  created_at: string;
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

const VALID_EVIDENCE_SOURCE_TYPES: ReadonlySet<EvidenceSourceType> = new Set([
  'WEB_RESEARCH',
  'CODE_VERIFICATION',
  'TOOL_EXECUTION',
  'DOCUMENTATION',
  'USER_ASSERTION'
]);

const VALID_EVIDENCE_RELATIONSHIPS: ReadonlySet<EvidenceRelationship> = new Set([
  'SUPPORTS',
  'CONTRADICTS',
  'LIMITATION'
]);

const VALID_VERIFICATION_RELATIONSHIPS: ReadonlySet<ClaimVerificationRelationship> = new Set([
  'SUPPORTS',
  'CONTRADICTS',
  'LIMITATION',
  'INSUFFICIENT',
  'AMBIGUOUS'
]);

const VALID_VERIFICATION_OUTCOMES: ReadonlySet<ClaimVerificationCandidateOutcome> = new Set([
  'PROPOSED',
  'INSUFFICIENT',
  'AMBIGUOUS'
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
   * Retrieves all pending proposals for an exact key within a scope.
   * Deterministically ordered by created_at ASC, id ASC.
   */
  public getPendingProposalsByKey(key: string, scope: ScopeIdentifier): Memory[] {
    this.validateKey(key);
    if (!scope || typeof scope !== 'object') {
      throw new ValidationError('Scope must be provided to getPendingProposalsByKey.');
    }
    this.validateScope(scope.scopeType, scope.scopeId);

    const stmt = this.db.prepare(`
      SELECT * FROM memories
      WHERE scope_type = ? AND scope_id = ? AND key = ? AND status = 'PENDING_APPROVAL'
      ORDER BY created_at ASC, id ASC
    `);
    const rows = stmt.all(scope.scopeType, scope.scopeId, key.trim()) as unknown as MemoryDbRow[];
    return rows.map((r) => this.mapMemoryRow(r));
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
        AND supersedes_id IS NULL AND superseded_by IS NULL
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
        AND supersedes_id IS NULL AND superseded_by IS NULL
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
    if (existing.status === 'SUPERSEDED') {
      throw new ValidationError(
        `Cannot update memory '${id}': record is superseded. Superseded memories are immutable historical records.`
      );
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
   * Marks any CURRENT claim-evidence verifications backed by this memory's evidence as STALE.
   */
  public archiveMemory(id: string, scope: ScopeIdentifier): Memory {
    const existing = this.getMemoryById(id, scope);
    if (!existing) {
      throw new MemoryNotFoundError(id);
    }
    if (existing.status === 'SUPERSEDED') {
      throw new ValidationError(`Cannot archive memory '${id}': record is superseded. Superseded memories are immutable historical records.`);
    }
    return this.transaction(() => {
      const archived = this.updateMemory(id, scope, { status: 'ARCHIVED' });
      this.markMemoryVerificationsStale(id, scope, 'MEMORY_ARCHIVED', archived.updatedAt);
      return archived;
    });
  }

  /**
   * Invalidates active claim links and claim-evidence associations belonging to a memory
   * and marks any CURRENT verifications backed by that memory's evidence as STALE, preserving history.
   */
  public invalidateMemoryVerificationLifecycle(
    memoryId: string,
    scope: ScopeIdentifier,
    reason: string = 'MEMORY_CONTENT_UPDATED',
    timestamp?: string
  ): {
    readonly invalidatedClaimLinks: number;
    readonly invalidatedAssociations: number;
    readonly staledVerifications: number;
  } {
    if (!memoryId || typeof memoryId !== 'string' || memoryId.trim() === '') {
      throw new ValidationError('Memory ID must be a non-empty string.');
    }
    if (!scope || typeof scope !== 'object') {
      throw new ValidationError('Scope must be provided to invalidateMemoryVerificationLifecycle.');
    }
    this.validateScope(scope.scopeType, scope.scopeId);

    const trimmedMemoryId = memoryId.trim();
    const now = timestamp && timestamp.trim() !== '' ? timestamp.trim() : new Date().toISOString();

    const linkResult = this.db.prepare(`
      UPDATE memory_claim_links
      SET status = 'INVALIDATED', invalidated_at = ?, invalidation_reason = ?
      WHERE memory_id = ?
        AND scope_type = ?
        AND scope_id = ?
        AND status = 'ACTIVE'
    `).run(now, reason, trimmedMemoryId, scope.scopeType, scope.scopeId);

    const assocResult = this.db.prepare(`
      UPDATE claim_evidence_associations
      SET status = 'INVALIDATED', invalidated_at = ?, invalidation_reason = ?
      WHERE memory_id = ?
        AND scope_type = ?
        AND scope_id = ?
        AND status = 'ACTIVE'
    `).run(now, reason, trimmedMemoryId, scope.scopeType, scope.scopeId);

    const staledVerifications = this.markMemoryVerificationsStale(trimmedMemoryId, scope, reason, now);

    return {
      invalidatedClaimLinks: Number(linkResult.changes ?? 0),
      invalidatedAssociations: Number(assocResult.changes ?? 0),
      staledVerifications
    };
  }

  public markMemoryVerificationsStale(
    memoryId: string,
    scope: ScopeIdentifier,
    reason: string,
    timestamp?: string
  ): number {
    this.validateScope(scope.scopeType, scope.scopeId);
    const now = timestamp && timestamp.trim() !== '' ? timestamp.trim() : new Date().toISOString();
    const res = this.db.prepare(`
      UPDATE claim_evidence_verifications
      SET status = 'STALE', stale_at = ?, stale_reason = ?
      WHERE scope_type = ?
        AND scope_id = ?
        AND status = 'CURRENT'
        AND evidence_id IN (
          SELECT id FROM memory_evidence WHERE memory_id = ?
        )
    `).run(now, reason, scope.scopeType, scope.scopeId, memoryId.trim());
    return Number(res.changes ?? 0);
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
        AND supersedes_id IS NULL AND superseded_by IS NULL
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
   * Computes deterministic evidence ID.
   */
  public computeEvidenceId(memoryId: string, snippetHash: string, relationship: string): string {
    return computeEvidenceId(memoryId, snippetHash, relationship);
  }

  /**
   * Persists a structured evidence record associated with a memory or proposal.
   * Deduplicates using deterministic identity and unique constraint checks.
   */
  public addEvidence(input: CreateEvidenceInput): MemoryEvidence {
    this.validateEvidenceInput(input);

    const snippetHash = input.snippetHash && input.snippetHash.trim().length > 0
      ? input.snippetHash.trim()
      : computeSnippetHash(input.snippet, input.sourceUrl ?? input.sourceTitle ?? '');

    const id = input.id && input.id.trim().length > 0
      ? input.id.trim()
      : computeEvidenceId(input.memoryId, snippetHash, input.relationship);

    // Check if identical evidence already exists by id
    const existingById = this.getEvidenceById(id);
    if (existingById) {
      return existingById;
    }

    // Check if identical evidence already exists by (memory_id, snippet_hash, relationship)
    const existingRow = this.db.prepare(`
      SELECT * FROM memory_evidence
      WHERE memory_id = ? AND snippet_hash = ? AND relationship = ?
    `).get(input.memoryId, snippetHash, input.relationship) as unknown as EvidenceDbRow | undefined;

    if (existingRow) {
      return this.mapEvidenceRow(existingRow);
    }

    const now = input.createdAt ?? new Date().toISOString();

    const stmt = this.db.prepare(`
      INSERT INTO memory_evidence (
        id, memory_id, source_type, source_url, source_domain, source_title,
        snippet, snippet_hash, relationship, task_id, agent_id, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    try {
      stmt.run(
        id,
        input.memoryId,
        input.sourceType,
        input.sourceUrl ?? null,
        input.sourceDomain ?? null,
        input.sourceTitle ?? null,
        input.snippet ?? null,
        snippetHash,
        input.relationship,
        input.taskId,
        input.agentId,
        now
      );
    } catch (err: any) {
      if (String(err?.message).includes('UNIQUE constraint failed')) {
        const raceRow = this.db.prepare(`
          SELECT * FROM memory_evidence
          WHERE memory_id = ? AND snippet_hash = ? AND relationship = ?
        `).get(input.memoryId, snippetHash, input.relationship) as unknown as EvidenceDbRow | undefined;
        if (raceRow) {
          return this.mapEvidenceRow(raceRow);
        }
      }
      throw err;
    }

    return {
      id,
      memoryId: input.memoryId,
      sourceType: input.sourceType,
      sourceUrl: input.sourceUrl ?? null,
      sourceDomain: input.sourceDomain ?? null,
      sourceTitle: input.sourceTitle ?? null,
      snippet: input.snippet ?? null,
      snippetHash,
      relationship: input.relationship,
      taskId: input.taskId,
      agentId: input.agentId,
      createdAt: now
    };
  }

  /**
   * Retrieves an evidence record by ID.
   * If scope is provided, verifies that the parent memory belongs to the designated scope.
   * Throws MemoryScopeViolationError if the evidence belongs to another scope.
   */
  public getEvidenceById(id: string, scope?: ScopeIdentifier): MemoryEvidence | null {
    if (!id || typeof id !== 'string' || id.trim() === '') {
      throw new ValidationError('Evidence ID must be a non-empty string.');
    }
    if (scope) {
      this.validateScope(scope.scopeType, scope.scopeId);
      const row = this.db.prepare(`
        SELECT e.*, m.scope_type AS memory_scope_type, m.scope_id AS memory_scope_id
        FROM memory_evidence e
        INNER JOIN memories m ON e.memory_id = m.id
        WHERE e.id = ?
      `).get(id.trim()) as unknown as (EvidenceDbRow & { memory_scope_type: string; memory_scope_id: string }) | undefined;
      if (!row) {
        return null;
      }
      this.assertScopeMatch(
        row.memory_scope_type as MemoryScopeType,
        row.memory_scope_id,
        scope,
        row.memory_id
      );
      return this.mapEvidenceRow(row);
    }

    const row = this.db.prepare('SELECT * FROM memory_evidence WHERE id = ?').get(id.trim()) as unknown as EvidenceDbRow | undefined;
    return row ? this.mapEvidenceRow(row) : null;
  }

  /**
   * Retrieves structured evidence associated with a memory or proposal.
   * If scope is provided, enforces that the memory belongs to the designated scope.
   */
  public getEvidenceByMemoryId(memoryId: string, scope?: ScopeIdentifier): MemoryEvidence[] {
    if (!memoryId || typeof memoryId !== 'string' || memoryId.trim() === '') {
      throw new ValidationError('Memory ID must be a non-empty string.');
    }

    if (scope) {
      this.validateScope(scope.scopeType, scope.scopeId);
      const rows = this.db.prepare(`
        SELECT e.*
        FROM memory_evidence e
        INNER JOIN memories m ON e.memory_id = m.id
        WHERE e.memory_id = ?
          AND m.scope_type = ?
          AND m.scope_id = ?
        ORDER BY e.created_at ASC, e.id ASC
      `).all(memoryId.trim(), scope.scopeType, scope.scopeId) as unknown as EvidenceDbRow[];

      return rows.map((r) => this.mapEvidenceRow(r));
    }

    const rows = this.db.prepare(`
      SELECT *
      FROM memory_evidence
      WHERE memory_id = ?
      ORDER BY created_at ASC, id ASC
    `).all(memoryId.trim()) as unknown as EvidenceDbRow[];

    return rows.map((r) => this.mapEvidenceRow(r));
  }

  /**
   * Persists a deterministic, scope-aware atomic claim.
   * If an identical claim exists in this scope, returns the existing claim (and updates memoryId if newly linked).
   */
  public addClaim(input: CreateClaimInput): MemoryClaim {
    if (!input || typeof input !== 'object') {
      throw new ValidationError('CreateClaimInput must be provided.');
    }

    const originalText = typeof input.originalText === 'string' ? input.originalText.trim() : '';
    if (originalText === '') {
      throw new ValidationError('Original claim text must be a non-empty string.');
    }

    this.validateScope(input.scopeType, input.scopeId);

    const taskId = typeof input.taskId === 'string' ? input.taskId.trim() : '';
    if (taskId === '') {
      throw new ValidationError('Claim taskId must be a non-empty string.');
    }

    const canonicalText = input.canonicalText && input.canonicalText.trim() !== ''
      ? input.canonicalText.trim()
      : canonicalizeClaimText(originalText);

    if (canonicalText === '') {
      throw new ValidationError('Claim text cannot be empty or consist solely of citation markers.');
    }

    const subject = typeof input.subject === 'string' && input.subject.trim() !== '' ? input.subject.trim() : null;
    const predicate = typeof input.predicate === 'string' && input.predicate.trim() !== '' ? input.predicate.trim() : null;
    const qualifier = typeof input.qualifier === 'string' && input.qualifier.trim() !== '' ? input.qualifier.trim() : null;

    const claimHash = input.claimHash && input.claimHash.trim() !== ''
      ? input.claimHash.trim()
      : computeClaimHash(canonicalText, { subject, predicate, qualifier });

    const id = input.id && input.id.trim() !== ''
      ? input.id.trim()
      : computeClaimId(input.scopeType, input.scopeId, claimHash);

    const now = input.createdAt ?? new Date().toISOString();
    let memoryId: string | null = null;
    if (input.memoryId !== undefined && input.memoryId !== null) {
      const trimmedMemoryId = typeof input.memoryId === 'string' ? input.memoryId.trim() : '';
      if (trimmedMemoryId === '') {
        throw new ValidationError('Claim memoryId cannot be an empty string when provided.');
      }
      const targetMemory = this.getMemoryById(trimmedMemoryId, {
        scopeType: input.scopeType,
        scopeId: input.scopeId
      });
      if (!targetMemory) {
        throw new MemoryNotFoundError(trimmedMemoryId);
      }
      memoryId = trimmedMemoryId;
    }

    // 1. Check if identical claim already exists by id
    const existingById = this.getClaimById(id);
    if (existingById) {
      this.assertScopeMatch(existingById.scopeType, existingById.scopeId, {
        scopeType: input.scopeType,
        scopeId: input.scopeId
      }, id);
      if (memoryId) {
        this.linkMemoryToClaim(memoryId, existingById.id, input.scopeType, input.scopeId, now);
        if (!existingById.memoryId) {
          this.db.prepare('UPDATE memory_claims SET memory_id = ? WHERE id = ?').run(memoryId, id);
          return { ...existingById, memoryId };
        }
      }
      return existingById;
    }

    // 2. Check if identical claim already exists by (scope_type, scope_id, claim_hash)
    const existingByHash = this.getClaimByHash(claimHash, { scopeType: input.scopeType, scopeId: input.scopeId });
    if (existingByHash) {
      if (memoryId) {
        this.linkMemoryToClaim(memoryId, existingByHash.id, input.scopeType, input.scopeId, now);
        if (!existingByHash.memoryId) {
          this.db.prepare('UPDATE memory_claims SET memory_id = ? WHERE id = ?').run(memoryId, existingByHash.id);
          return { ...existingByHash, memoryId };
        }
      }
      return existingByHash;
    }

    const stmt = this.db.prepare(`
      INSERT INTO memory_claims (
        id, memory_id, scope_type, scope_id, original_text, canonical_text,
        claim_hash, subject, predicate, qualifier, task_id, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    try {
      stmt.run(
        id,
        memoryId,
        input.scopeType,
        input.scopeId,
        originalText,
        canonicalText,
        claimHash,
        subject,
        predicate,
        qualifier,
        taskId,
        now
      );
    } catch (err: any) {
      if (String(err?.message).includes('UNIQUE constraint failed')) {
        const raceClaim = this.getClaimByHash(claimHash, { scopeType: input.scopeType, scopeId: input.scopeId });
        if (raceClaim) {
          if (memoryId) {
            this.linkMemoryToClaim(memoryId, raceClaim.id, input.scopeType, input.scopeId, now);
            if (!raceClaim.memoryId) {
              this.db.prepare('UPDATE memory_claims SET memory_id = ? WHERE id = ?').run(memoryId, raceClaim.id);
              return { ...raceClaim, memoryId };
            }
          }
          return raceClaim;
        }
      }
      throw err;
    }

    if (memoryId) {
      this.linkMemoryToClaim(memoryId, id, input.scopeType, input.scopeId, now);
    }

    return {
      id,
      memoryId,
      scopeType: input.scopeType,
      scopeId: input.scopeId,
      originalText,
      canonicalText,
      claimHash,
      subject,
      predicate,
      qualifier,
      taskId,
      createdAt: now
    };
  }

  /**
   * Retrieves an atomic claim by ID.
   * If scope is provided, verifies that the claim belongs to the designated scope.
   * Throws MemoryScopeViolationError if the claim belongs to another scope.
   */
  public getClaimById(id: string, scope?: ScopeIdentifier): MemoryClaim | null {
    if (!id || typeof id !== 'string' || id.trim() === '') {
      throw new ValidationError('Claim ID must be a non-empty string.');
    }
    const row = this.db.prepare('SELECT * FROM memory_claims WHERE id = ?').get(id.trim()) as unknown as ClaimDbRow | undefined;
    if (!row) {
      return null;
    }

    if (scope) {
      this.validateScope(scope.scopeType, scope.scopeId);
      this.assertScopeMatch(row.scope_type as MemoryScopeType, row.scope_id, scope, id);
    }

    return this.mapClaimRow(row);
  }

  /**
   * Retrieves a claim by its canonical SHA-256 hash strictly within a designated scope.
   */
  public getClaimByHash(claimHash: string, scope: ScopeIdentifier): MemoryClaim | null {
    if (!claimHash || typeof claimHash !== 'string' || claimHash.trim() === '') {
      throw new ValidationError('Claim hash must be a non-empty string.');
    }
    if (!scope || typeof scope !== 'object') {
      throw new ValidationError('Scope must be provided to getClaimByHash.');
    }
    this.validateScope(scope.scopeType, scope.scopeId);

    const row = this.db.prepare(`
      SELECT * FROM memory_claims
      WHERE scope_type = ? AND scope_id = ? AND claim_hash = ?
    `).get(scope.scopeType, scope.scopeId, claimHash.trim()) as unknown as ClaimDbRow | undefined;

    return row ? this.mapClaimRow(row) : null;
  }

  /**
   * Retrieves all atomic claims linked to a memory or proposal.
   * If scope is provided, verifies that the memory belongs to the designated scope.
   */
  public getClaimsByMemoryId(
    memoryId: string,
    scope?: ScopeIdentifier,
    options?: { readonly includeInvalidated?: boolean }
  ): MemoryClaim[] {
    if (!memoryId || typeof memoryId !== 'string' || memoryId.trim() === '') {
      throw new ValidationError('Memory ID must be a non-empty string.');
    }

    const trimmedMemoryId = memoryId.trim();
    const activeClause = options?.includeInvalidated ? '' : " AND mcl.status = 'ACTIVE'";
    if (scope) {
      this.validateScope(scope.scopeType, scope.scopeId);
      const rows = this.db.prepare(`
        SELECT c.*
        FROM memory_claims c
        INNER JOIN memory_claim_links mcl ON mcl.claim_id = c.id
        INNER JOIN memories m ON mcl.memory_id = m.id
        WHERE mcl.memory_id = ?
          AND m.scope_type = ?
          AND m.scope_id = ?
          AND mcl.scope_type = ?
          AND mcl.scope_id = ?
          AND c.scope_type = ?
          AND c.scope_id = ?${activeClause}
        ORDER BY c.created_at ASC, c.id ASC
      `).all(
        trimmedMemoryId,
        scope.scopeType,
        scope.scopeId,
        scope.scopeType,
        scope.scopeId,
        scope.scopeType,
        scope.scopeId
      ) as unknown as ClaimDbRow[];

      return rows.map((r) => this.mapClaimRow(r));
    }

    const rows = this.db.prepare(`
      SELECT c.*
      FROM memory_claims c
      INNER JOIN memory_claim_links mcl ON mcl.claim_id = c.id
      WHERE mcl.memory_id = ?${activeClause}
      ORDER BY c.created_at ASC, c.id ASC
    `).all(trimmedMemoryId) as unknown as ClaimDbRow[];

    return rows.map((r) => this.mapClaimRow(r));
  }

  /**
   * Lists atomic claims within an explicit scope, with optional filtering.
   */
  public listClaims(filter: ListClaimsFilter): MemoryClaim[] {
    if (!filter || typeof filter !== 'object') {
      throw new ValidationError('Filter must be provided to listClaims.');
    }
    this.validateScope(filter.scopeType, filter.scopeId);

    const conditions: string[] = ['scope_type = ?', 'scope_id = ?'];
    const params: SqlParam[] = [filter.scopeType, filter.scopeId];

    if (filter.taskId) {
      conditions.push('task_id = ?');
      params.push(filter.taskId.trim());
    }

    if (filter.memoryId) {
      const linkStatusClause = filter.includeInvalidated ? '' : " AND mcl.status = 'ACTIVE'";
      conditions.push(
        `EXISTS (SELECT 1 FROM memory_claim_links mcl WHERE mcl.claim_id = memory_claims.id AND mcl.memory_id = ? AND mcl.scope_type = memory_claims.scope_type AND mcl.scope_id = memory_claims.scope_id${linkStatusClause})`
      );
      params.push(filter.memoryId.trim());
    }

    let sql = `SELECT * FROM memory_claims WHERE ${conditions.join(' AND ')} ORDER BY created_at ASC, id ASC`;

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
    const rows = stmt.all(...params) as unknown as ClaimDbRow[];
    return rows.map((r) => this.mapClaimRow(r));
  }

  /**
   * Computes deterministic claim-evidence verification ID.
   */
  public computeClaimVerificationId(
    claimId: string,
    evidenceId: string,
    verifierId: string,
    verifierVersion: string,
    promptPolicyHash: string
  ): string {
    return computeClaimVerificationId(claimId, evidenceId, verifierId, verifierVersion, promptPolicyHash);
  }

  /**
   * Persists a proposed claim-evidence verification record within the designated scope.
   * Deduplicates deterministically by (claim_id, evidence_id, verifier_id, verifier_version, prompt_policy_hash).
   * Never mutates memory status or existing human approval decisions.
   */
  public addClaimVerification(input: CreateClaimVerificationInput): ClaimEvidenceVerification {
    this.validateClaimVerificationInput(input);

    const claimId = input.claimId.trim();
    const evidenceId = input.evidenceId.trim();
    const verifierId = input.verifierId.trim();
    const verifierVersion = input.verifierVersion.trim();
    const promptPolicyVersion = input.promptPolicyVersion.trim();
    const promptPolicyHash = input.promptPolicyHash.trim();
    const assumptions = normalizeVerificationAssumptions(input.assumptions);
    const assumptionsHash = input.assumptionsHash !== undefined
      ? input.assumptionsHash.trim()
      : computeVerificationAssumptionsHash(assumptions);
    const assumptionsJson = JSON.stringify(assumptions);
    const status: ClaimVerificationLifecycleStatus = input.status ?? 'CURRENT';
    const staleAt = status === 'STALE' ? (input.staleAt ?? input.createdAt ?? new Date().toISOString()) : null;
    const staleReason = status === 'STALE' ? (input.staleReason ?? 'INVALIDATED') : null;
    const scope: ScopeIdentifier = { scopeType: input.scopeType, scopeId: input.scopeId };

    // Verify both claim and evidence exist strictly inside this scope
    const claim = this.getClaimById(claimId, scope);
    if (!claim) {
      throw new ValidationError(`Claim '${claimId}' was not found in scope '${scope.scopeType}:${scope.scopeId}'.`);
    }
    const evidence = this.getEvidenceById(evidenceId, scope);
    if (!evidence) {
      throw new ValidationError(`Evidence '${evidenceId}' was not found in scope '${scope.scopeType}:${scope.scopeId}'.`);
    }

    if (status === 'CURRENT') {
      const existingByKey = this.findClaimVerification({
        claimId,
        evidenceId,
        verifierId,
        verifierVersion,
        promptPolicyHash,
        assumptionsHash,
        scope
      });
      if (existingByKey) {
        return existingByKey;
      }
    }

    const baseId = input.id && input.id.trim() !== ''
      ? input.id.trim()
      : computeClaimVerificationId(claimId, evidenceId, verifierId, verifierVersion, promptPolicyHash, assumptionsHash);
    const existingById = this.getClaimVerificationById(baseId, scope);
    const id = existingById ? randomUUID() : baseId;
    if (existingById && existingById.status === 'CURRENT' && status === 'CURRENT') {
      return existingById;
    }

    const confidence = input.confidence === undefined || input.confidence === null ? null : input.confidence;
    const explanation = input.explanation.trim();
    const reviewRecommended = Boolean(input.reviewRecommended);
    const taskId = typeof input.taskId === 'string' && input.taskId.trim() !== '' ? input.taskId.trim() : null;
    const now = input.createdAt && input.createdAt.trim() !== '' ? input.createdAt.trim() : new Date().toISOString();

    const stmt = this.db.prepare(`
      INSERT INTO claim_evidence_verifications (
        id, claim_id, evidence_id, scope_type, scope_id,
        proposed_relationship, verification_outcome,
        verifier_id, verifier_version, prompt_policy_version, prompt_policy_hash,
        assumptions_hash, assumptions_json,
        confidence, explanation, review_recommended,
        status, stale_at, stale_reason,
        task_id, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    try {
      stmt.run(
        id,
        claimId,
        evidenceId,
        input.scopeType,
        input.scopeId,
        input.proposedRelationship,
        input.verificationOutcome,
        verifierId,
        verifierVersion,
        promptPolicyVersion,
        promptPolicyHash,
        assumptionsHash,
        assumptionsJson,
        confidence,
        explanation,
        reviewRecommended ? 1 : 0,
        status,
        staleAt,
        staleReason,
        taskId,
        now
      );
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      if (/UNIQUE constraint failed/i.test(msg)) {
        const raceRow = this.findClaimVerification({
          claimId,
          evidenceId,
          verifierId,
          verifierVersion,
          promptPolicyHash,
          assumptionsHash,
          scope
        });
        if (raceRow) {
          return raceRow;
        }
      }
      throw err;
    }

    return {
      id,
      claimId,
      evidenceId,
      scopeType: input.scopeType,
      scopeId: input.scopeId,
      proposedRelationship: input.proposedRelationship,
      verificationOutcome: input.verificationOutcome,
      verifierId,
      verifierVersion,
      promptPolicyVersion,
      promptPolicyHash,
      assumptionsHash,
      assumptions,
      confidence,
      explanation,
      reviewRecommended,
      status,
      staleAt,
      staleReason,
      taskId,
      createdAt: now
    };
  }

  /**
   * Retrieves a proposed claim verification record by ID.
   * If scope is provided, enforces scope containment.
   */
  public getClaimVerificationById(id: string, scope?: ScopeIdentifier): ClaimEvidenceVerification | null {
    if (!id || typeof id !== 'string' || id.trim() === '') {
      throw new ValidationError('Verification ID must be a non-empty string.');
    }
    const row = this.db
      .prepare('SELECT * FROM claim_evidence_verifications WHERE id = ?')
      .get(id.trim()) as unknown as ClaimVerificationDbRow | undefined;
    if (!row) {
      return null;
    }
    if (scope) {
      this.validateScope(scope.scopeType, scope.scopeId);
      this.assertScopeMatch(row.scope_type as MemoryScopeType, row.scope_id, scope, id);
    }
    return this.mapClaimVerificationRow(row);
  }

  /**
   * Finds an existing deduplicated verification record by exact provenance tuple within scope.
   */
  public findClaimVerification(params: {
    readonly claimId: string;
    readonly evidenceId: string;
    readonly verifierId: string;
    readonly verifierVersion: string;
    readonly promptPolicyHash: string;
    readonly assumptionsHash?: string;
    readonly scope: ScopeIdentifier;
  }): ClaimEvidenceVerification | null {
    this.validateScope(params.scope.scopeType, params.scope.scopeId);
    const assumptionsHash = params.assumptionsHash !== undefined ? params.assumptionsHash.trim() : '';
    const row = this.db.prepare(`
      SELECT * FROM claim_evidence_verifications
      WHERE claim_id = ?
        AND evidence_id = ?
        AND verifier_id = ?
        AND verifier_version = ?
        AND prompt_policy_hash = ?
        AND assumptions_hash = ?
        AND status = 'CURRENT'
        AND scope_type = ?
        AND scope_id = ?
    `).get(
      params.claimId.trim(),
      params.evidenceId.trim(),
      params.verifierId.trim(),
      params.verifierVersion.trim(),
      params.promptPolicyHash.trim(),
      assumptionsHash,
      params.scope.scopeType,
      params.scope.scopeId
    ) as unknown as ClaimVerificationDbRow | undefined;

    return row ? this.mapClaimVerificationRow(row) : null;
  }

  /**
   * Persists an explicit, validated claim-to-evidence association within a single scope and memory.
   * Rejects cross-scope, cross-memory, missing-entity, or conflicting-relationship inputs.
   */
  public addClaimEvidenceAssociation(
    input: CreateClaimEvidenceAssociationInput
  ): ClaimEvidenceAssociation {
    if (!input || typeof input !== 'object') {
      throw new ValidationError('CreateClaimEvidenceAssociationInput must be provided.');
    }
    this.validateScope(input.scopeType, input.scopeId);

    const claimId = typeof input.claimId === 'string' ? input.claimId.trim() : '';
    const evidenceId = typeof input.evidenceId === 'string' ? input.evidenceId.trim() : '';
    const memoryId = typeof input.memoryId === 'string' ? input.memoryId.trim() : '';
    if (!claimId) {
      throw new ValidationError('Association claimId must be a non-empty string.');
    }
    if (!evidenceId) {
      throw new ValidationError('Association evidenceId must be a non-empty string.');
    }
    if (!memoryId) {
      throw new ValidationError('Association memoryId must be a non-empty string.');
    }

    const scope: ScopeIdentifier = { scopeType: input.scopeType, scopeId: input.scopeId };
    const memory = this.getMemoryById(memoryId, scope);
    if (!memory) {
      throw new MemoryNotFoundError(memoryId);
    }

    const claim = this.getClaimById(claimId, scope);
    if (!claim) {
      throw new ValidationError(`Claim '${claimId}' does not exist in scope ${scope.scopeType}:${scope.scopeId}.`);
    }

    const evidence = this.getEvidenceById(evidenceId, scope);
    if (!evidence) {
      throw new ValidationError(`Evidence '${evidenceId}' does not exist in scope ${scope.scopeType}:${scope.scopeId}.`);
    }

    if (evidence.memoryId !== memory.id) {
      throw new ValidationError(
        `Evidence '${evidence.id}' belongs to memory '${evidence.memoryId}', not '${memory.id}'.`
      );
    }

    const linked = this.db.prepare(`
      SELECT 1 AS present
      FROM memory_claim_links
      WHERE memory_id = ? AND claim_id = ? AND scope_type = ? AND scope_id = ? AND status = 'ACTIVE'
    `).get(memory.id, claim.id, scope.scopeType, scope.scopeId) as { present: number } | undefined;
    if (!linked) {
      throw new ValidationError(
        `Claim '${claim.id}' does not have an active link to memory '${memory.id}' in scope ${scope.scopeType}:${scope.scopeId}.`
      );
    }

    if (input.relationship !== undefined) {
      if (!VALID_EVIDENCE_RELATIONSHIPS.has(input.relationship)) {
        throw new ValidationError(`Invalid association relationship '${String(input.relationship)}'.`);
      }
      if (input.relationship !== evidence.relationship) {
        throw new ValidationError(
          `Association relationship '${input.relationship}' conflicts with evidence relationship '${evidence.relationship}'.`
        );
      }
    }

    const relationship = evidence.relationship;
    const existing = this.db.prepare(`
      SELECT * FROM claim_evidence_associations
      WHERE claim_id = ? AND evidence_id = ? AND status = 'ACTIVE'
    `).get(claim.id, evidence.id) as unknown as ClaimEvidenceAssociationDbRow | undefined;

    if (existing) {
      this.assertScopeMatch(existing.scope_type as MemoryScopeType, existing.scope_id, scope, existing.id);
      if (existing.memory_id !== memory.id || existing.relationship !== relationship) {
        throw new ValidationError(
          `Conflicting existing association for claim '${claim.id}' and evidence '${evidence.id}'.`
        );
      }
      return this.mapClaimEvidenceAssociationRow(existing);
    }

    const existingAny = this.db.prepare(`
      SELECT id FROM claim_evidence_associations WHERE id = ?
    `).get(
      input.id && input.id.trim() !== '' ? input.id.trim() : computeClaimEvidenceAssociationId(claim.id, evidence.id)
    ) as { id: string } | undefined;
    const id = input.id && input.id.trim() !== ''
      ? input.id.trim()
      : existingAny
        ? randomUUID()
        : computeClaimEvidenceAssociationId(claim.id, evidence.id);
    const now = input.createdAt ?? new Date().toISOString();

    try {
      this.db.prepare(`
        INSERT INTO claim_evidence_associations (
          id, claim_id, evidence_id, memory_id, scope_type, scope_id, relationship, status, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, 'ACTIVE', ?)
      `).run(
        id,
        claim.id,
        evidence.id,
        memory.id,
        scope.scopeType,
        scope.scopeId,
        relationship,
        now
      );
    } catch (err: any) {
      if (String(err?.message).includes('UNIQUE constraint failed')) {
        const raceRow = this.db.prepare(`
          SELECT * FROM claim_evidence_associations WHERE claim_id = ? AND evidence_id = ? AND status = 'ACTIVE'
        `).get(claim.id, evidence.id) as unknown as ClaimEvidenceAssociationDbRow | undefined;
        if (raceRow) {
          this.assertScopeMatch(raceRow.scope_type as MemoryScopeType, raceRow.scope_id, scope, raceRow.id);
          return this.mapClaimEvidenceAssociationRow(raceRow);
        }
      }
      throw err;
    }

    return {
      id,
      claimId: claim.id,
      evidenceId: evidence.id,
      memoryId: memory.id,
      scopeType: scope.scopeType,
      scopeId: scope.scopeId,
      relationship,
      status: 'ACTIVE',
      invalidatedAt: null,
      invalidationReason: null,
      createdAt: now
    };
  }

  /**
   * Retrieves explicit claim-evidence associations for a memory, enforcing scope isolation.
   */
  public getClaimEvidenceAssociationsByMemoryId(
    memoryId: string,
    scope?: ScopeIdentifier,
    options?: { readonly includeInvalidated?: boolean }
  ): ClaimEvidenceAssociation[] {
    if (!memoryId || typeof memoryId !== 'string' || memoryId.trim() === '') {
      throw new ValidationError('Memory ID must be a non-empty string.');
    }
    const trimmedMemoryId = memoryId.trim();
    const activeCea = options?.includeInvalidated ? '' : " AND cea.status = 'ACTIVE'";
    const activeMcl = options?.includeInvalidated ? '' : " AND mcl.status = 'ACTIVE'";

    if (scope) {
      this.validateScope(scope.scopeType, scope.scopeId);
      const mem = this.getMemoryById(trimmedMemoryId, scope);
      if (!mem) {
        return [];
      }
      const rows = this.db.prepare(`
        SELECT cea.*
        FROM claim_evidence_associations cea
        INNER JOIN memory_claim_links mcl
          ON mcl.claim_id = cea.claim_id
          AND mcl.memory_id = cea.memory_id
          AND mcl.scope_type = cea.scope_type
          AND mcl.scope_id = cea.scope_id${activeMcl}
        INNER JOIN memory_evidence ev
          ON ev.id = cea.evidence_id
          AND ev.memory_id = cea.memory_id
        WHERE cea.memory_id = ?
          AND cea.scope_type = ?
          AND cea.scope_id = ?${activeCea}
        ORDER BY cea.created_at ASC, cea.id ASC
      `).all(trimmedMemoryId, scope.scopeType, scope.scopeId) as unknown as ClaimEvidenceAssociationDbRow[];
      return rows.map((r) => this.mapClaimEvidenceAssociationRow(r));
    }

    const rows = this.db.prepare(`
      SELECT * FROM claim_evidence_associations cea
      WHERE cea.memory_id = ?${activeCea}
      ORDER BY cea.created_at ASC, cea.id ASC
    `).all(trimmedMemoryId) as unknown as ClaimEvidenceAssociationDbRow[];
    return rows.map((r) => this.mapClaimEvidenceAssociationRow(r));
  }

  /**
   * Retrieves explicit claim-evidence associations for a claim within scope.
   */
  public getClaimEvidenceAssociationsByClaimId(
    claimId: string,
    scope?: ScopeIdentifier,
    options?: { readonly includeInvalidated?: boolean }
  ): ClaimEvidenceAssociation[] {
    if (!claimId || typeof claimId !== 'string' || claimId.trim() === '') {
      throw new ValidationError('Claim ID must be a non-empty string.');
    }
    const trimmedClaimId = claimId.trim();
    const statusClause = options?.includeInvalidated ? '' : " AND status = 'ACTIVE'";

    if (scope) {
      this.validateScope(scope.scopeType, scope.scopeId);
      this.getClaimById(trimmedClaimId, scope);
      const rows = this.db.prepare(`
        SELECT * FROM claim_evidence_associations
        WHERE claim_id = ? AND scope_type = ? AND scope_id = ?${statusClause}
        ORDER BY created_at ASC, id ASC
      `).all(trimmedClaimId, scope.scopeType, scope.scopeId) as unknown as ClaimEvidenceAssociationDbRow[];
      return rows.map((r) => this.mapClaimEvidenceAssociationRow(r));
    }

    const rows = this.db.prepare(`
      SELECT * FROM claim_evidence_associations
      WHERE claim_id = ?${statusClause}
      ORDER BY created_at ASC, id ASC
    `).all(trimmedClaimId) as unknown as ClaimEvidenceAssociationDbRow[];
    return rows.map((r) => this.mapClaimEvidenceAssociationRow(r));
  }

  /**
   * Retrieves explicit claim-evidence associations for an evidence record within scope.
   */
  public getClaimEvidenceAssociationsByEvidenceId(
    evidenceId: string,
    scope?: ScopeIdentifier,
    options?: { readonly includeInvalidated?: boolean }
  ): ClaimEvidenceAssociation[] {
    if (!evidenceId || typeof evidenceId !== 'string' || evidenceId.trim() === '') {
      throw new ValidationError('Evidence ID must be a non-empty string.');
    }
    const trimmedEvidenceId = evidenceId.trim();
    const statusClause = options?.includeInvalidated ? '' : " AND status = 'ACTIVE'";

    if (scope) {
      this.validateScope(scope.scopeType, scope.scopeId);
      this.getEvidenceById(trimmedEvidenceId, scope);
      const rows = this.db.prepare(`
        SELECT * FROM claim_evidence_associations
        WHERE evidence_id = ? AND scope_type = ? AND scope_id = ?${statusClause}
        ORDER BY created_at ASC, id ASC
      `).all(trimmedEvidenceId, scope.scopeType, scope.scopeId) as unknown as ClaimEvidenceAssociationDbRow[];
      return rows.map((r) => this.mapClaimEvidenceAssociationRow(r));
    }

    const rows = this.db.prepare(`
      SELECT * FROM claim_evidence_associations
      WHERE evidence_id = ?${statusClause}
      ORDER BY created_at ASC, id ASC
    `).all(trimmedEvidenceId) as unknown as ClaimEvidenceAssociationDbRow[];
    return rows.map((r) => this.mapClaimEvidenceAssociationRow(r));
  }

  private linkMemoryToClaim(
    memoryId: string,
    claimId: string,
    scopeType: MemoryScopeType,
    scopeId: string,
    createdAt: string
  ): void {
    this.db.prepare(`
      INSERT INTO memory_claim_links (
        memory_id, claim_id, scope_type, scope_id, status, created_at
      ) VALUES (?, ?, ?, ?, 'ACTIVE', ?)
      ON CONFLICT(memory_id, claim_id) DO UPDATE SET
        status = 'ACTIVE',
        invalidated_at = NULL,
        invalidation_reason = NULL,
        created_at = excluded.created_at
      WHERE memory_claim_links.status = 'INVALIDATED'
    `).run(memoryId, claimId, scopeType, scopeId, createdAt);
  }

  private mapClaimEvidenceAssociationRow(row: ClaimEvidenceAssociationDbRow): ClaimEvidenceAssociation {
    return {
      id: row.id,
      claimId: row.claim_id,
      evidenceId: row.evidence_id,
      memoryId: row.memory_id,
      scopeType: row.scope_type as MemoryScopeType,
      scopeId: row.scope_id,
      relationship: row.relationship as EvidenceRelationship,
      status: (row.status as ClaimAssociationStatus) ?? 'ACTIVE',
      invalidatedAt: row.invalidated_at ?? null,
      invalidationReason: row.invalidation_reason ?? null,
      createdAt: row.created_at
    };
  }

  /**
   * Retrieves verification records for a claim, enforcing scope if provided.
   * Defaults to CURRENT verifications unless includeStale or explicit status is requested.
   */
  public getVerificationsByClaimId(
    claimId: string,
    scope?: ScopeIdentifier,
    options?: { readonly includeStale?: boolean; readonly status?: ClaimVerificationLifecycleStatus }
  ): ClaimEvidenceVerification[] {
    if (!claimId || typeof claimId !== 'string' || claimId.trim() === '') {
      throw new ValidationError('Claim ID must be a non-empty string.');
    }
    const statusClause = options?.status
      ? ' AND status = ?'
      : options?.includeStale
        ? ''
        : " AND status = 'CURRENT'";
    const statusParams: SqlParam[] = options?.status ? [options.status] : [];

    if (scope) {
      this.validateScope(scope.scopeType, scope.scopeId);
      // Also enforce claim scope check if claim exists in another scope
      this.getClaimById(claimId.trim(), scope);
      const rows = this.db.prepare(`
        SELECT * FROM claim_evidence_verifications
        WHERE claim_id = ? AND scope_type = ? AND scope_id = ?${statusClause}
        ORDER BY created_at ASC, id ASC
      `).all(claimId.trim(), scope.scopeType, scope.scopeId, ...statusParams) as unknown as ClaimVerificationDbRow[];
      return rows.map((r) => this.mapClaimVerificationRow(r));
    }

    const rows = this.db.prepare(`
      SELECT * FROM claim_evidence_verifications
      WHERE claim_id = ?${statusClause}
      ORDER BY created_at ASC, id ASC
    `).all(claimId.trim(), ...statusParams) as unknown as ClaimVerificationDbRow[];
    return rows.map((r) => this.mapClaimVerificationRow(r));
  }

  /**
   * Retrieves verification records for an evidence item, enforcing scope if provided.
   * Defaults to CURRENT verifications unless includeStale or explicit status is requested.
   */
  public getVerificationsByEvidenceId(
    evidenceId: string,
    scope?: ScopeIdentifier,
    options?: { readonly includeStale?: boolean; readonly status?: ClaimVerificationLifecycleStatus }
  ): ClaimEvidenceVerification[] {
    if (!evidenceId || typeof evidenceId !== 'string' || evidenceId.trim() === '') {
      throw new ValidationError('Evidence ID must be a non-empty string.');
    }
    const statusClause = options?.status
      ? ' AND status = ?'
      : options?.includeStale
        ? ''
        : " AND status = 'CURRENT'";
    const statusParams: SqlParam[] = options?.status ? [options.status] : [];

    if (scope) {
      this.validateScope(scope.scopeType, scope.scopeId);
      // Also enforce evidence scope check if evidence exists in another scope
      this.getEvidenceById(evidenceId.trim(), scope);
      const rows = this.db.prepare(`
        SELECT * FROM claim_evidence_verifications
        WHERE evidence_id = ? AND scope_type = ? AND scope_id = ?${statusClause}
        ORDER BY created_at ASC, id ASC
      `).all(evidenceId.trim(), scope.scopeType, scope.scopeId, ...statusParams) as unknown as ClaimVerificationDbRow[];
      return rows.map((r) => this.mapClaimVerificationRow(r));
    }

    const rows = this.db.prepare(`
      SELECT * FROM claim_evidence_verifications
      WHERE evidence_id = ?${statusClause}
      ORDER BY created_at ASC, id ASC
    `).all(evidenceId.trim(), ...statusParams) as unknown as ClaimVerificationDbRow[];
    return rows.map((r) => this.mapClaimVerificationRow(r));
  }

  /**
   * Lists verification records within an explicit scope.
   * Defaults to CURRENT verifications unless includeStale or explicit status is requested.
   */
  public listClaimVerifications(filter: ListClaimVerificationsFilter): ClaimEvidenceVerification[] {
    if (!filter || typeof filter !== 'object') {
      throw new ValidationError('Filter must be provided to listClaimVerifications.');
    }
    this.validateScope(filter.scopeType, filter.scopeId);

    const conditions: string[] = ['scope_type = ?', 'scope_id = ?'];
    const params: SqlParam[] = [filter.scopeType, filter.scopeId];

    if (filter.status !== undefined) {
      if (filter.status !== 'CURRENT' && filter.status !== 'STALE') {
        throw new ValidationError(`Invalid verification status '${String(filter.status)}'.`);
      }
      conditions.push('status = ?');
      params.push(filter.status);
    } else if (!filter.includeStale) {
      conditions.push("status = 'CURRENT'");
    }

    if (filter.claimId) {
      conditions.push('claim_id = ?');
      params.push(filter.claimId.trim());
    }
    if (filter.evidenceId) {
      conditions.push('evidence_id = ?');
      params.push(filter.evidenceId.trim());
    }
    if (filter.memoryId) {
      conditions.push('evidence_id IN (SELECT id FROM memory_evidence WHERE memory_id = ?)');
      params.push(filter.memoryId.trim());
    }
    if (filter.proposedRelationship) {
      if (!VALID_VERIFICATION_RELATIONSHIPS.has(filter.proposedRelationship)) {
        throw new ValidationError(
          `Invalid proposedRelationship '${String(filter.proposedRelationship)}'.`
        );
      }
      conditions.push('proposed_relationship = ?');
      params.push(filter.proposedRelationship);
    }

    let sql = `SELECT * FROM claim_evidence_verifications WHERE ${conditions.join(' AND ')} ORDER BY created_at ASC, id ASC`;

    if (filter.limit !== undefined) {
      if (typeof filter.limit !== 'number' || !Number.isInteger(filter.limit) || filter.limit < 1) {
        throw new ValidationError('Limit must be a positive integer.');
      }
      sql += ' LIMIT ?';
      params.push(filter.limit);

      if (filter.offset !== undefined) {
        if (typeof filter.offset !== 'number' || !Number.isInteger(filter.offset) || filter.offset < 0) {
          throw new ValidationError('Offset must be a non-negative integer.');
        }
        sql += ' OFFSET ?';
        params.push(filter.offset);
      }
    }

    const rows = this.db.prepare(sql).all(...params) as unknown as ClaimVerificationDbRow[];
    return rows.map((r) => this.mapClaimVerificationRow(r));
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

      // Mark any CURRENT verifications on the superseded memory's evidence as historical STALE
      this.markMemoryVerificationsStale(previous.id, params.scope, 'MEMORY_SUPERSEDED', now);

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

  private mapEvidenceRow(row: EvidenceDbRow): MemoryEvidence {
    return {
      id: row.id,
      memoryId: row.memory_id,
      sourceType: row.source_type as EvidenceSourceType,
      sourceUrl: row.source_url,
      sourceDomain: row.source_domain,
      sourceTitle: row.source_title,
      snippet: row.snippet,
      snippetHash: row.snippet_hash,
      relationship: row.relationship as EvidenceRelationship,
      taskId: row.task_id,
      agentId: row.agent_id,
      createdAt: row.created_at
    };
  }

  private mapClaimRow(row: ClaimDbRow): MemoryClaim {
    return {
      id: row.id,
      memoryId: row.memory_id,
      scopeType: row.scope_type as MemoryScopeType,
      scopeId: row.scope_id,
      originalText: row.original_text,
      canonicalText: row.canonical_text,
      claimHash: row.claim_hash,
      subject: row.subject,
      predicate: row.predicate,
      qualifier: row.qualifier,
      taskId: row.task_id,
      createdAt: row.created_at
    };
  }

  private mapClaimVerificationRow(row: ClaimVerificationDbRow): ClaimEvidenceVerification {
    let parsedAssumptions: string[] = [];
    if (row.assumptions_json) {
      try {
        const parsed = JSON.parse(row.assumptions_json);
        if (Array.isArray(parsed)) {
          parsedAssumptions = parsed.filter((item): item is string => typeof item === 'string');
        }
      } catch {
        parsedAssumptions = [];
      }
    }
    return {
      id: row.id,
      claimId: row.claim_id,
      evidenceId: row.evidence_id,
      scopeType: row.scope_type as MemoryScopeType,
      scopeId: row.scope_id,
      proposedRelationship: row.proposed_relationship as ClaimVerificationRelationship,
      verificationOutcome: row.verification_outcome as ClaimVerificationCandidateOutcome,
      verifierId: row.verifier_id,
      verifierVersion: row.verifier_version,
      promptPolicyVersion: row.prompt_policy_version,
      promptPolicyHash: row.prompt_policy_hash,
      assumptionsHash: row.assumptions_hash ?? '',
      assumptions: parsedAssumptions,
      confidence: row.confidence,
      explanation: row.explanation,
      reviewRecommended: row.review_recommended === 1,
      status: (row.status as ClaimVerificationLifecycleStatus) ?? 'CURRENT',
      staleAt: row.stale_at ?? null,
      staleReason: row.stale_reason ?? null,
      taskId: row.task_id,
      createdAt: row.created_at
    };
  }

  private validateClaimVerificationInput(input: CreateClaimVerificationInput): void {
    if (!input || typeof input !== 'object') {
      throw new ValidationError('CreateClaimVerificationInput must be provided.');
    }
    this.validateScope(input.scopeType, input.scopeId);
    if (!input.claimId || typeof input.claimId !== 'string' || input.claimId.trim() === '') {
      throw new ValidationError('Verification claimId must be a non-empty string.');
    }
    if (!input.evidenceId || typeof input.evidenceId !== 'string' || input.evidenceId.trim() === '') {
      throw new ValidationError('Verification evidenceId must be a non-empty string.');
    }
    if (!input.proposedRelationship || !VALID_VERIFICATION_RELATIONSHIPS.has(input.proposedRelationship)) {
      throw new ValidationError(
        `Invalid proposedRelationship '${String(input.proposedRelationship)}'.`
      );
    }
    if (!input.verificationOutcome || !VALID_VERIFICATION_OUTCOMES.has(input.verificationOutcome)) {
      throw new ValidationError(
        `Invalid verificationOutcome '${String(input.verificationOutcome)}'.`
      );
    }
    if (!input.verifierId || typeof input.verifierId !== 'string' || input.verifierId.trim() === '') {
      throw new ValidationError('Verification verifierId must be a non-empty string.');
    }
    if (!input.verifierVersion || typeof input.verifierVersion !== 'string' || input.verifierVersion.trim() === '') {
      throw new ValidationError('Verification verifierVersion must be a non-empty string.');
    }
    if (!input.promptPolicyVersion || typeof input.promptPolicyVersion !== 'string' || input.promptPolicyVersion.trim() === '') {
      throw new ValidationError('Verification promptPolicyVersion must be a non-empty string.');
    }
    if (!input.promptPolicyHash || typeof input.promptPolicyHash !== 'string' || input.promptPolicyHash.trim() === '') {
      throw new ValidationError('Verification promptPolicyHash must be a non-empty string.');
    }
    if (
      input.confidence !== undefined &&
      input.confidence !== null &&
      (typeof input.confidence !== 'number' || !Number.isFinite(input.confidence) || input.confidence < 0 || input.confidence > 1)
    ) {
      throw new ValidationError(`Verification confidence must be a finite number in [0, 1], received '${String(input.confidence)}'.`);
    }
    if (typeof input.explanation !== 'string' || input.explanation.trim() === '') {
      throw new ValidationError('Verification explanation must be a non-empty string.');
    }
    if (input.explanation.length > 1000) {
      throw new ValidationError(`Verification explanation exceeds limit of 1000 characters (${input.explanation.length}).`);
    }
  }

  private validateEvidenceInput(input: CreateEvidenceInput): void {
    if (!input || typeof input !== 'object') {
      throw new ValidationError('CreateEvidenceInput must be provided.');
    }
    if (!input.memoryId || typeof input.memoryId !== 'string' || input.memoryId.trim() === '') {
      throw new ValidationError('Evidence memoryId must be a non-empty string.');
    }
    if (!input.sourceType || !VALID_EVIDENCE_SOURCE_TYPES.has(input.sourceType)) {
      throw new ValidationError(
        `Invalid evidence sourceType '${String(input.sourceType)}'. Must be one of: ${Array.from(VALID_EVIDENCE_SOURCE_TYPES).join(', ')}.`
      );
    }
    if (!input.relationship || !VALID_EVIDENCE_RELATIONSHIPS.has(input.relationship)) {
      throw new ValidationError(
        `Invalid evidence relationship '${String(input.relationship)}'. Must be one of: ${Array.from(VALID_EVIDENCE_RELATIONSHIPS).join(', ')}.`
      );
    }
    if (!input.taskId || typeof input.taskId !== 'string' || input.taskId.trim() === '') {
      throw new ValidationError('Evidence taskId must be a non-empty string.');
    }
    if (!input.agentId || typeof input.agentId !== 'string' || input.agentId.trim() === '') {
      throw new ValidationError('Evidence agentId must be a non-empty string.');
    }
  }
}
