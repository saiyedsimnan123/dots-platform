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
