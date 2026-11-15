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
