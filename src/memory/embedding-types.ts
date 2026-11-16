/**
 * Next-Generation Dots AI Platform - Embedding Provider Contracts
 * Phase 4C.2: Embedding Provider Interface and Deterministic Test Provider
 * 
 * Architectural Mandate:
 * Provider-independent embedding interface. Downstream memory and vector retrieval
 * interacts solely with these contracts, allowing zero-code-change switching between
 * deterministic offline mock, local CPU ONNX / Transformers.js, and local external engines.
 * 
 * Invariants:
 * 1. All returned vectors are Float32Array instances.
 * 2. All returned vectors MUST be L2-normalized (unit length: ||v|| = 1.0).
 * 3. Vectors must strictly match the provider's advertised dimensionality.
 * 4. Returned vectors are defensive copies; providers never leak internal mutable buffers.
 * 5. Input text and batch sizes are strictly bounded to prevent memory exhaustion.
 * 6. Cancellation via AbortSignal is respected before and during operations.
 */

import type { MemoryScopeType } from '../domain/types.ts';

/**
 * Maximum character length permitted for a single embedding text input.
 */
export const MAX_EMBEDDING_TEXT_LENGTH = 8192;

/**
 * Maximum number of texts permitted in a single batch embedding request.
 */
export const MAX_EMBEDDING_BATCH_SIZE = 100;

/**
 * Execution options for embedding operations.
 */
export interface EmbeddingOptions {
  /**
   * Optional AbortSignal to cancel embedding inference cooperatively.
   */
  readonly signal?: AbortSignal;
}

/**
 * Provider-independent contract for generating text vector embeddings.
 */
export interface IEmbeddingProvider {
  /**
   * Unique name or identifier of the provider (e.g. 'mock-embedding-provider', 'transformers-local').
   */
  readonly name: string;

  /**
   * Model identifier and version used for vector generation (e.g. 'mock-deterministic-v1', 'all-MiniLM-L6-v2').
   */
  readonly modelId: string;

  /**
   * Fixed vector dimensionality produced by this provider (e.g. 384).
   */
  readonly dimensions: number;

  /**
   * Reports whether the provider is currently online, initialized, and available for inference.
   */
  isAvailable(): Promise<boolean>;

  /**
   * Generates a unit-normalized Float32Array vector embedding for the given text.
   * 
   * @param text The input text string to embed.
   * @param options Optional execution options (cancellation signal).
   * @returns A promise resolving to a cloned unit-normalized Float32Array.
   */
  embed(text: string, options?: EmbeddingOptions): Promise<Float32Array>;

  /**
   * Generates unit-normalized Float32Array vector embeddings for a batch of text inputs.
   * Equivalent in output to mapping single `embed()` calls, but allows providers to optimize throughput.
   * 
   * @param texts Array of input text strings to embed.
   * @param options Optional execution options (cancellation signal).
   * @returns A promise resolving to an array of cloned unit-normalized Float32Arrays.
   */
  embedBatch(texts: readonly string[], options?: EmbeddingOptions): Promise<Float32Array[]>;
}

/**
 * Domain entity representing a persisted vector embedding for a memory record.
 */
export interface MemoryEmbedding {
  /** Unique primary key ID of the embedding record */
  readonly id: string;
  /** Foreign key referencing the parent memory record */
  readonly memoryId: string;
  /** Identifier of the model that generated this embedding (e.g. 'all-MiniLM-L6-v2') */
  readonly modelId: string;
  /** Model revision/version string (defaults to 'main') */
  readonly modelRevision: string;
  /** Vector dimensionality (e.g. 384) */
  readonly dimensions: number;
  /** The unit-normalized Float32Array embedding vector */
  readonly embedding: Float32Array;
  /** ISO 8601 UTC creation timestamp */
  readonly createdAt: string;
  /** ISO 8601 UTC update timestamp */
  readonly updatedAt: string;
}

/**
 * Input DTO for persisting or updating a memory embedding.
 */
export interface InsertMemoryEmbeddingInput {
  /** Optional custom ID; generates UUID v4 if omitted */
  readonly id?: string;
  /** Target memory ID */
  readonly memoryId: string;
  /** Model identifier */
  readonly modelId: string;
  /** Model revision (defaults to 'main') */
  readonly modelRevision?: string;
  /** Vector dimensionality */
  readonly dimensions: number;
  /** The unit-normalized Float32Array vector */
  readonly embedding: Float32Array;
}

/**
 * Lightweight metadata summary of a persisted memory embedding (omits the raw vector).
 */
export interface MemoryEmbeddingMetadata {
  readonly id: string;
  readonly memoryId: string;
  readonly modelId: string;
  readonly modelRevision: string;
  readonly dimensions: number;
  readonly createdAt: string;
  readonly updatedAt: string;
}

/**
 * Filtering options for listing embedding metadata.
 */
export interface ListEmbeddingMetadataFilter {
  readonly memoryId?: string;
  readonly modelId?: string;
  readonly modelRevision?: string;
  readonly limit?: number;
  readonly offset?: number;
}

/**
 * Lightweight representation of an active memory record lacking an embedding vector.
 */
export interface MissingEmbeddingMemoryRecord {
  readonly id: string;
  readonly key: string;
  readonly content: string;
  readonly updatedAt: string;
}

/**
 * Filtering parameters for querying memories missing vector embeddings.
 */
export interface ListMissingEmbeddingsFilter {
  readonly scopeType: MemoryScopeType;
  readonly scopeId: string;
  readonly modelId: string;
  readonly modelRevision?: string;
  readonly limit?: number;
}

/**
 * Execution options for batch memory embedding reconciliation across a scope.
 */
export interface SyncScopeEmbeddingsOptions {
  readonly scopeType?: MemoryScopeType;
  readonly scopeId?: string;
  readonly batchSize?: number;
  readonly limit?: number;
  readonly provider?: IEmbeddingProvider;
}

/**
 * Structured outcome DTO from a batch memory embedding synchronization operation.
 */
export interface SyncScopeEmbeddingsResult {
  readonly success: boolean;
  readonly scope: {
    readonly scopeType: MemoryScopeType;
    readonly scopeId: string;
  };
  readonly modelId: string;
  readonly modelRevision: string;
  readonly candidatesDiscovered: number;
  readonly embeddingsGenerated: number;
  readonly alreadyEmbeddedOrSkipped: number;
  readonly staleResultsDiscarded: number;
  readonly failed: number;
  readonly errors?: readonly string[];
}


