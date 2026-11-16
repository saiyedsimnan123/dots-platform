/**
 * Next-Generation Dots AI Platform - Vector Utilities
 * Phase 4C.2: Embedding Provider Interface and Deterministic Test Provider
 * 
 * Architectural Mandate:
 * Small, robust, dependency-free mathematical helpers for working with Float32Array vectors.
 * Enforces strict input validation, rejects non-finite values (NaN, Infinity), detects
 * zero vectors, handles L2 normalization, defensive copying, and computes exact cosine
 * similarity and dot products.
 */

import { InvalidVectorError } from '../domain/errors.ts';

/**
 * Validates that the provided input is a valid, non-empty Float32Array with finite values.
 * Throws InvalidVectorError on any violation.
 */
export function validateVector(
  vector: unknown,
  expectedDimensions?: number,
  vectorName = 'vector'
): asserts vector is Float32Array {
  if (!vector || !(vector instanceof Float32Array)) {
    throw new InvalidVectorError(`${vectorName} must be an instance of Float32Array.`);
  }

  if (vector.length === 0) {
    throw new InvalidVectorError(`${vectorName} must not be empty (dimensions must be > 0).`);
  }

  if (expectedDimensions !== undefined && vector.length !== expectedDimensions) {
    throw new InvalidVectorError(
      `${vectorName} dimension mismatch: expected ${expectedDimensions}, received ${vector.length}.`,
      { expectedDimensions, actualDimensions: vector.length }
    );
  }

  for (let i = 0; i < vector.length; i++) {
    const val = vector[i]!;
    if (!Number.isFinite(val)) {
      throw new InvalidVectorError(
        `${vectorName} contains non-finite value (${String(val)}) at index ${i}.`,
        { index: i, value: String(val) }
      );
    }
  }
}

/**
 * Validates that a vector matches the expected dimensionality.
 */
export function validateVectorDimensions(
  vector: Float32Array,
  expectedDimensions: number,
  vectorName = 'vector'
): void {
  validateVector(vector, expectedDimensions, vectorName);
}

/**
 * Computes the Euclidean (L2) norm of a vector: ||v|| = sqrt(sum(v_i^2)).
 */
export function l2Norm(vector: Float32Array): number {
  validateVector(vector);
  let sumSq = 0;
  for (let i = 0; i < vector.length; i++) {
    const val = vector[i]!;
    sumSq += val * val;
  }
  return Math.sqrt(sumSq);
}

/**
 * Returns true if the vector's L2 norm is effectively zero within epsilon tolerance.
 */
export function isZeroVector(vector: Float32Array, epsilon = 1e-9): boolean {
  validateVector(vector);
  return l2Norm(vector) < epsilon;
}

/**
 * Returns a new unit-length (L2-normalized) Float32Array such that ||v|| = 1.0.
 * Throws InvalidVectorError if the vector is a zero vector.
 */
export function normalizeVector(vector: Float32Array): Float32Array {
  validateVector(vector);
  const norm = l2Norm(vector);
  if (norm < 1e-12) {
    throw new InvalidVectorError('Cannot normalize a zero-magnitude vector.');
  }

  const normalized = new Float32Array(vector.length);
  for (let i = 0; i < vector.length; i++) {
    normalized[i] = vector[i]! / norm;
  }
  return normalized;
}

/**
 * Returns true if the vector is L2-normalized within the given tolerance.
 */
export function isNormalized(vector: Float32Array, tolerance = 1e-4): boolean {
  validateVector(vector);
  const norm = l2Norm(vector);
  return Math.abs(norm - 1.0) <= tolerance;
}

/**
 * Creates a defensive copy of a Float32Array.
 */
export function cloneVector(vector: Float32Array): Float32Array {
  validateVector(vector);
  return new Float32Array(vector);
}

/**
 * Computes the dot product of two vectors: sum(a_i * b_i).
 * Throws InvalidVectorError if dimensions do not match or vectors contain non-finite values.
 */
export function dotProduct(a: Float32Array, b: Float32Array): number {
  validateVector(a, undefined, 'vector a');
  validateVector(b, undefined, 'vector b');

  if (a.length !== b.length) {
    throw new InvalidVectorError(
      `Dimension mismatch in dot product: vector a has ${a.length} dimensions, vector b has ${b.length} dimensions.`,
      { dimensionsA: a.length, dimensionsB: b.length }
    );
  }

  let dot = 0;
  for (let i = 0; i < a.length; i++) {
    dot += a[i]! * b[i]!;
  }
  return dot;
}

/**
 * Computes the cosine similarity between two vectors:
 * cos(theta) = (a . b) / (||a|| * ||b||)
 * 
 * Guarantees:
 * - Returns 1.0 for identical vectors.
 * - Returns -1.0 for opposite vectors.
 * - Returns 0.0 for orthogonal vectors.
 * - Output is strictly clamped to [-1.0, 1.0] to protect against floating-point rounding.
 * - Throws InvalidVectorError for zero vectors, dimension mismatches, or non-finite inputs.
 */
export function cosineSimilarity(a: Float32Array, b: Float32Array): number {
  validateVector(a, undefined, 'vector a');
  validateVector(b, undefined, 'vector b');

  if (a.length !== b.length) {
    throw new InvalidVectorError(
      `Dimension mismatch in cosine similarity: vector a has ${a.length} dimensions, vector b has ${b.length} dimensions.`,
      { dimensionsA: a.length, dimensionsB: b.length }
    );
  }

  const normA = l2Norm(a);
  const normB = l2Norm(b);

  if (normA < 1e-12 || normB < 1e-12) {
    throw new InvalidVectorError('Cannot compute cosine similarity with a zero-magnitude vector.');
  }

  let dot = 0;
  for (let i = 0; i < a.length; i++) {
    dot += a[i]! * b[i]!;
  }

  const similarity = dot / (normA * normB);
  // Clamp between -1.0 and 1.0 to guard against floating-point drift
  return Math.max(-1.0, Math.min(1.0, similarity));
}

/**
 * Validates that a vector is L2-normalized within the given tolerance.
 * Throws InvalidVectorError if not normalized, contains non-finite values, or is empty.
 */
export function validateNormalizedVector(
  vector: Float32Array,
  tolerance = 1e-3,
  vectorName = 'vector'
): void {
  validateVector(vector, undefined, vectorName);
  if (!isNormalized(vector, tolerance)) {
    const norm = l2Norm(vector);
    throw new InvalidVectorError(
      `${vectorName} is not L2-normalized: expected norm ~1.0, received ${norm.toFixed(6)}.`,
      { norm }
    );
  }
}

/**
 * Serialization options for converting Float32Array vectors to SQLite BLOBs.
 */
export interface SerializeVectorOptions {
  /**
   * If true, validates that the vector is unit-normalized (L2 norm ~1.0) before serializing.
   */
  readonly requireNormalized?: boolean;
  /**
   * Tolerance for L2 normalization check (defaults to 1e-3).
   */
  readonly tolerance?: number;
}

/**
 * Serializes a Float32Array vector into a raw Uint8Array BLOB for SQLite storage.
 * 
 * Guarantees:
 * 1. Validates that the input is a Float32Array with non-zero dimensions and finite numbers.
 * 2. Rejects zero-magnitude vectors.
 * 3. Optionally validates L2 normalization if requested.
 * 4. Returns a defensive copy in a fresh ArrayBuffer, preventing external mutations.
 * 5. Preserves exact bitwise Float32 values (standard IEEE 754 little-endian representation).
 */
export function serializeVectorToBlob(
  vector: Float32Array,
  options?: SerializeVectorOptions
): Uint8Array {
  validateVector(vector);

  if (isZeroVector(vector)) {
    throw new InvalidVectorError('Cannot serialize a zero-magnitude vector.');
  }

  if (options?.requireNormalized) {
    validateNormalizedVector(vector, options.tolerance);
  }

  // Defensive copy into an independent ArrayBuffer to avoid leaking references
  const buffer = new ArrayBuffer(vector.byteLength);
  new Uint8Array(buffer).set(
    new Uint8Array(vector.buffer, vector.byteOffset, vector.byteLength)
  );
  return new Uint8Array(buffer);
}

/**
 * Deserialization options for converting SQLite BLOBs to Float32Array vectors.
 */
export interface DeserializeVectorOptions {
  /**
   * If true, validates that the vector is unit-normalized (L2 norm ~1.0) after deserializing.
   */
  readonly requireNormalized?: boolean;
  /**
   * Tolerance for L2 normalization check (defaults to 1e-3).
   */
  readonly tolerance?: number;
}

/**
 * Deserializes a SQLite BLOB (Uint8Array) into an independent Float32Array vector.
 * 
 * Guarantees:
 * 1. Validates that input is a Uint8Array with positive byteLength divisible by 4.
 * 2. Rejects malformed BLOB sizes (e.g. not a multiple of 4 bytes).
 * 3. Rejects dimension mismatches if expectedDimensions is provided.
 * 4. Ensures safe 4-byte memory alignment by copying into a fresh ArrayBuffer,
 *    protecting against RangeErrors from unaligned node:sqlite internal buffers.
 * 5. Validates that all deserialized float values are finite (no NaN, Infinity).
 * 6. Rejects zero-magnitude vectors.
 * 7. Optionally validates L2 normalization if requested.
 * 8. Returns a completely independent Float32Array instance.
 */
export function deserializeBlobToVector(
  blob: unknown,
  expectedDimensions?: number,
  options?: DeserializeVectorOptions
): Float32Array {
  if (!blob || !(blob instanceof Uint8Array)) {
    throw new InvalidVectorError('Vector BLOB must be an instance of Uint8Array.');
  }

  if (blob.byteLength === 0) {
    throw new InvalidVectorError('Vector BLOB must not be empty (byteLength must be > 0).');
  }

  if (blob.byteLength % 4 !== 0) {
    throw new InvalidVectorError(
      `Malformed vector BLOB: byteLength (${blob.byteLength}) must be a multiple of 4 for Float32Array.`,
      { byteLength: blob.byteLength }
    );
  }

  const dimensions = blob.byteLength / 4;
  if (expectedDimensions !== undefined && dimensions !== expectedDimensions) {
    throw new InvalidVectorError(
      `Vector dimension mismatch: expected ${expectedDimensions}, but BLOB contains ${dimensions} dimensions (${blob.byteLength} bytes).`,
      { expectedDimensions, actualDimensions: dimensions, byteLength: blob.byteLength }
    );
  }

  // Ensure 4-byte alignment and defensive copying
  const alignedBuffer = new ArrayBuffer(blob.byteLength);
  new Uint8Array(alignedBuffer).set(
    new Uint8Array(blob.buffer, blob.byteOffset, blob.byteLength)
  );
  const vector = new Float32Array(alignedBuffer);

  // Validate values (no NaN, no Infinity)
  validateVector(vector, expectedDimensions);

  if (isZeroVector(vector)) {
    throw new InvalidVectorError('Deserialized vector cannot be a zero-magnitude vector.');
  }

  if (options?.requireNormalized) {
    validateNormalizedVector(vector, options.tolerance, 'deserialized vector');
  }

  return vector;
}

