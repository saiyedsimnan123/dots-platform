/**
 * Next-Generation Dots AI Platform - Memory Embedding Repository
 * Phase 4C.4: Persistent SQLite Vector Storage
 * 
 * Architectural Mandate:
 * Implements persistent SQLite storage and lifecycle management for memory vector embeddings
 * using Node.js 24's built-in `node:sqlite` API.
 * 
 * Guarantees:
 * 1. 100% parameterized SQL to prevent SQL injection.
 * 2. SQLite foreign keys enforce ON DELETE CASCADE from memories table.
 * 3. Model identity isolation: embeddings are unique per (memory_id, model_id, model_revision).
 * 4. Safe Float32Array to BLOB serialization and deserialization with 4-byte memory alignment handling.
 * 5. Rejects zero-vectors, non-finite values (NaN, Infinity), and dimension mismatches.
 * 6. Defensive copies: never returns or retains mutable references to internal database buffers.
 * 7. Zero model inference inside database transactions.
 */

import { randomUUID } from 'node:crypto';
import type { DatabaseManager } from './db.ts';
import type {
  MemoryEmbedding,
  InsertMemoryEmbeddingInput,
  MemoryEmbeddingMetadata,
  ListEmbeddingMetadataFilter
} from '../memory/embedding-types.ts';
import {
  serializeVectorToBlob,
  deserializeBlobToVector,
  validateVector
} from '../memory/vector-utils.ts';
import {
  ValidationError,
  MemoryConflictError,
  EmbeddingNotFoundError,
  DatabaseError
} from '../domain/errors.ts';

interface MemoryEmbeddingDbRow {
  id: string;
  memory_id: string;
  model_id: string;
  model_revision: string;
  dimensions: number;
  embedding: Uint8Array;
  created_at: string;
  updated_at: string;
}

interface MemoryEmbeddingMetadataDbRow {
  id: string;
  memory_id: string;
  model_id: string;
  model_revision: string;
  dimensions: number;
  created_at: string;
  updated_at: string;
}

type SqlParam = null | number | bigint | string | Uint8Array;

export interface RepositoryEmbeddingOptions {
  /**
   * If true, validates that the vector is unit-normalized (L2 norm ~1.0).
   * Defaults to true to guarantee embedding consistency across the platform.
   */
  readonly validateNormalized?: boolean;
}

export class MemoryEmbeddingRepository {
  public readonly db: DatabaseManager;

  constructor(db: DatabaseManager) {
    if (!db) {
      throw new ValidationError('DatabaseManager must be provided to MemoryEmbeddingRepository.');
    }
    this.db = db;
  }

  /**
   * Executes a callback within a database transaction.
   */
  public transaction<T>(callback: () => T): T {
    return this.db.transaction(callback);
  }

  /**
   * Inserts a new vector embedding for an eligible memory.
   * Throws MemoryConflictError if an embedding already exists for the same
   * memory_id, model_id, and model_revision.
   * Throws DatabaseError if the foreign key reference to memories(id) fails.
   */
  public insertEmbedding(
    input: InsertMemoryEmbeddingInput,
    options?: RepositoryEmbeddingOptions
  ): MemoryEmbedding {
    this.validateInsertInput(input);

    const validateNormalized = options?.validateNormalized ?? true;
    const blob = serializeVectorToBlob(input.embedding, {
      requireNormalized: validateNormalized
    });

    const id = input.id ?? randomUUID();
    const modelRevision = input.modelRevision ?? 'main';
    const now = new Date().toISOString();

    const sql = `
      INSERT INTO memory_embeddings (
        id, memory_id, model_id, model_revision, dimensions, embedding, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `;

    try {
      const stmt = this.db.prepare(sql);
      stmt.run(
        id,
        input.memoryId,
        input.modelId,
        modelRevision,
        input.dimensions,
        blob,
        now,
        now
      );
    } catch (err) {
      if (err instanceof Error) {
        if (/UNIQUE constraint failed/i.test(err.message)) {
          throw new MemoryConflictError(
            `${input.memoryId}:${input.modelId}:${modelRevision}`,
            'WORKSPACE',
            'memory_embeddings'
          );
        }
        if (/FOREIGN KEY constraint failed/i.test(err.message)) {
          throw new DatabaseError(
            `Foreign key constraint failed: parent memory '${input.memoryId}' does not exist.`,
            { memoryId: input.memoryId }
          );
        }
      }
      throw err;
    }

    const created = this.getEmbedding(input.memoryId, input.modelId, modelRevision);
    if (!created) {
      throw new DatabaseError('Failed to read back newly inserted memory embedding.');
    }
    return created;
  }

  /**
   * Inserts or replaces a vector embedding for a memory.
   * If an embedding exists for (memory_id, model_id, model_revision), it is safely updated.
   */
  public upsertEmbedding(
    input: InsertMemoryEmbeddingInput,
    options?: RepositoryEmbeddingOptions
  ): MemoryEmbedding {
    this.validateInsertInput(input);

    return this.transaction(() => {
      const modelRevision = input.modelRevision ?? 'main';
      const existing = this.getEmbedding(input.memoryId, input.modelId, modelRevision);

      if (existing) {
        return this.updateEmbedding(
          input.memoryId,
          input.modelId,
          input.embedding,
          modelRevision,
          options
        );
      }

      return this.insertEmbedding(input, options);
    });
  }

  /**
   * Updates an existing embedding vector for a memory and model identity.
   * Throws EmbeddingNotFoundError if no matching embedding exists.
   */
  public updateEmbedding(
    memoryId: string,
    modelId: string,
    embedding: Float32Array,
    modelRevision = 'main',
    options?: RepositoryEmbeddingOptions
  ): MemoryEmbedding {
    if (!memoryId || typeof memoryId !== 'string' || memoryId.trim() === '') {
      throw new ValidationError('Memory ID must be a non-empty string.');
    }
    if (!modelId || typeof modelId !== 'string' || modelId.trim() === '') {
      throw new ValidationError('Model ID must be a non-empty string.');
    }

    const validateNormalized = options?.validateNormalized ?? true;
    validateVector(embedding);

    const blob = serializeVectorToBlob(embedding, {
      requireNormalized: validateNormalized
    });

    const now = new Date().toISOString();
    const sql = `
      UPDATE memory_embeddings
      SET embedding = ?, dimensions = ?, updated_at = ?
      WHERE memory_id = ? AND model_id = ? AND model_revision = ?
    `;

    const stmt = this.db.prepare(sql);
    const result = stmt.run(blob, embedding.length, now, memoryId, modelId, modelRevision);

    if (result.changes === 0) {
      throw new EmbeddingNotFoundError(memoryId, modelId);
    }

    const updated = this.getEmbedding(memoryId, modelId, modelRevision);
    if (!updated) {
      throw new EmbeddingNotFoundError(memoryId, modelId);
    }
    return updated;
  }

  /**
   * Retrieves an embedding by memory ID and model identity.
   * Returns null if not found.
   */
  public getEmbedding(
    memoryId: string,
    modelId: string,
    modelRevision = 'main'
  ): MemoryEmbedding | null {
    if (!memoryId || typeof memoryId !== 'string' || memoryId.trim() === '') {
      throw new ValidationError('Memory ID must be a non-empty string.');
    }
    if (!modelId || typeof modelId !== 'string' || modelId.trim() === '') {
      throw new ValidationError('Model ID must be a non-empty string.');
    }

    const sql = `
      SELECT id, memory_id, model_id, model_revision, dimensions, embedding, created_at, updated_at
      FROM memory_embeddings
      WHERE memory_id = ? AND model_id = ? AND model_revision = ?
    `;

    const stmt = this.db.prepare(sql);
    const row = stmt.get(memoryId, modelId, modelRevision) as unknown as MemoryEmbeddingDbRow | undefined;
    if (!row) {
      return null;
    }

    return this.mapRow(row);
  }

  /**
   * Retrieves embeddings for a list of authorized memory IDs and model identity.
   * Guarantees deterministic ordering by created_at ASC, id ASC.
   */
  public getEmbeddingsForMemories(
    memoryIds: readonly string[],
    modelId: string,
    modelRevision = 'main'
  ): MemoryEmbedding[] {
    if (!memoryIds || !Array.isArray(memoryIds) || memoryIds.length === 0) {
      return [];
    }
    if (!modelId || typeof modelId !== 'string' || modelId.trim() === '') {
      throw new ValidationError('Model ID must be a non-empty string.');
    }

    const validIds = Array.from(
      new Set(
        memoryIds.filter((id) => typeof id === 'string' && id.trim() !== '')
      )
    );

    if (validIds.length === 0) {
      return [];
    }

    const placeholders = validIds.map(() => '?').join(', ');
    const sql = `
      SELECT id, memory_id, model_id, model_revision, dimensions, embedding, created_at, updated_at
      FROM memory_embeddings
      WHERE model_id = ? AND model_revision = ? AND memory_id IN (${placeholders})
      ORDER BY created_at ASC, id ASC
    `;

    const params: SqlParam[] = [modelId, modelRevision, ...validIds];
    const stmt = this.db.prepare(sql);
    const rows = stmt.all(...params) as unknown as MemoryEmbeddingDbRow[];

    return rows.map((r) => this.mapRow(r));
  }

  /**
   * Deletes a specific embedding by memory ID, model ID, and revision.
   */
  public deleteEmbedding(
    memoryId: string,
    modelId: string,
    modelRevision = 'main'
  ): boolean {
    if (!memoryId || typeof memoryId !== 'string' || memoryId.trim() === '') {
      throw new ValidationError('Memory ID must be a non-empty string.');
    }
    if (!modelId || typeof modelId !== 'string' || modelId.trim() === '') {
      throw new ValidationError('Model ID must be a non-empty string.');
    }

    const sql = `
      DELETE FROM memory_embeddings
      WHERE memory_id = ? AND model_id = ? AND model_revision = ?
    `;

    const stmt = this.db.prepare(sql);
    const result = stmt.run(memoryId, modelId, modelRevision);
    return Number(result.changes) > 0;
  }

  /**
   * Deletes all embeddings associated with a memory ID (across all models/revisions).
   * Returns the count of deleted embedding records.
   */
  public deleteEmbeddingsByMemoryId(memoryId: string): number {
    if (!memoryId || typeof memoryId !== 'string' || memoryId.trim() === '') {
      throw new ValidationError('Memory ID must be a non-empty string.');
    }

    const sql = 'DELETE FROM memory_embeddings WHERE memory_id = ?';
    const stmt = this.db.prepare(sql);
    const result = stmt.run(memoryId);
    return Number(result.changes);
  }

  /**
   * Lists lightweight embedding metadata records (omitting raw vector BLOBs)
   * for backfill, inspection, or diagnostics.
   */
  public listEmbeddingMetadata(
    filter?: ListEmbeddingMetadataFilter
  ): MemoryEmbeddingMetadata[] {
    let sql = `
      SELECT id, memory_id, model_id, model_revision, dimensions, created_at, updated_at
      FROM memory_embeddings
    `;
    const clauses: string[] = [];
    const params: SqlParam[] = [];

    if (filter) {
      if (filter.memoryId !== undefined) {
        clauses.push('memory_id = ?');
        params.push(filter.memoryId);
      }
      if (filter.modelId !== undefined) {
        clauses.push('model_id = ?');
        params.push(filter.modelId);
      }
      if (filter.modelRevision !== undefined) {
        clauses.push('model_revision = ?');
        params.push(filter.modelRevision);
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

    const stmt = this.db.prepare(sql);
    const rows = stmt.all(...params) as unknown as MemoryEmbeddingMetadataDbRow[];

    return rows.map((r) => this.mapMetadataRow(r));
  }

  /**
   * Counts stored embeddings, optionally filtered by model identity or memory ID.
   */
  public countEmbeddings(filter?: {
    memoryId?: string;
    modelId?: string;
    modelRevision?: string;
  }): number {
    let sql = 'SELECT COUNT(*) as count FROM memory_embeddings';
    const clauses: string[] = [];
    const params: SqlParam[] = [];

    if (filter) {
      if (filter.memoryId) {
        clauses.push('memory_id = ?');
        params.push(filter.memoryId);
      }
      if (filter.modelId) {
        clauses.push('model_id = ?');
        params.push(filter.modelId);
      }
      if (filter.modelRevision) {
        clauses.push('model_revision = ?');
        params.push(filter.modelRevision);
      }
    }

    if (clauses.length > 0) {
      sql += ` WHERE ${clauses.join(' AND ')}`;
    }

    const stmt = this.db.prepare(sql);
    const row = stmt.get(...params) as unknown as { count: number };
    return row.count;
  }

  /**
   * Maps a raw SQLite database row to a typed MemoryEmbedding entity.
   */
  private mapRow(row: MemoryEmbeddingDbRow): MemoryEmbedding {
    const vector = deserializeBlobToVector(row.embedding, row.dimensions);

    return {
      id: row.id,
      memoryId: row.memory_id,
      modelId: row.model_id,
      modelRevision: row.model_revision,
      dimensions: row.dimensions,
      embedding: vector,
      createdAt: row.created_at,
      updatedAt: row.updated_at
    };
  }

  /**
   * Maps a lightweight metadata database row.
   */
  private mapMetadataRow(row: MemoryEmbeddingMetadataDbRow): MemoryEmbeddingMetadata {
    return {
      id: row.id,
      memoryId: row.memory_id,
      modelId: row.model_id,
      modelRevision: row.model_revision,
      dimensions: row.dimensions,
      createdAt: row.created_at,
      updatedAt: row.updated_at
    };
  }

  /**
   * Validates insertion input parameters.
   */
  private validateInsertInput(input: InsertMemoryEmbeddingInput): void {
    if (!input || typeof input !== 'object') {
      throw new ValidationError('InsertMemoryEmbeddingInput must be provided.');
    }
    if (!input.memoryId || typeof input.memoryId !== 'string' || input.memoryId.trim() === '') {
      throw new ValidationError('Memory ID must be a non-empty string.');
    }
    if (!input.modelId || typeof input.modelId !== 'string' || input.modelId.trim() === '') {
      throw new ValidationError('Model ID must be a non-empty string.');
    }
    if (typeof input.dimensions !== 'number' || !Number.isInteger(input.dimensions) || input.dimensions <= 0) {
      throw new ValidationError('Dimensions must be a positive integer.');
    }
    validateVector(input.embedding, input.dimensions);
  }
}
