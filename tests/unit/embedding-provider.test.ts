/**
 * Next-Generation Dots AI Platform - Embedding Provider & Vector Utility Tests
 * Phase 4C.2: Embedding Provider Interface and Deterministic Test Provider
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  validateVector,
  validateVectorDimensions,
  l2Norm,
  isZeroVector,
  normalizeVector,
  isNormalized,
  cloneVector,
  dotProduct,
  cosineSimilarity
} from '../../src/memory/vector-utils.ts';
import {
  DeterministicMockEmbeddingProvider
} from '../../src/memory/mock-embedding-provider.ts';
import {
  MAX_EMBEDDING_TEXT_LENGTH,
  MAX_EMBEDDING_BATCH_SIZE
} from '../../src/memory/embedding-types.ts';
import {
  ValidationError,
  InvalidVectorError,
  EmbeddingProviderUnavailableError,
  EmbeddingInferenceError,
  AgentCancelledError
} from '../../src/domain/errors.ts';

// ============================================================================
// 1. Vector Utilities Unit Tests
// ============================================================================

test('validateVector - accepts valid Float32Array with finite values', () => {
  const vec = new Float32Array([0.1, -0.5, 0.8, 1.2]);
  assert.doesNotThrow(() => validateVector(vec));
  assert.doesNotThrow(() => validateVector(vec, 4));
});

test('validateVector - rejects non-Float32Array inputs', () => {
  assert.throws(() => validateVector(null), InvalidVectorError);
  assert.throws(() => validateVector(undefined), InvalidVectorError);
  assert.throws(() => validateVector([1, 2, 3]), InvalidVectorError);
  assert.throws(() => validateVector('not-a-vector'), InvalidVectorError);
  assert.throws(() => validateVector({ length: 3 }), InvalidVectorError);
});

test('validateVector - rejects empty vector (length 0)', () => {
  const empty = new Float32Array(0);
  assert.throws(
    () => validateVector(empty),
    (err: unknown) => err instanceof InvalidVectorError && err.message.includes('must not be empty')
  );
});

test('validateVector - rejects dimension mismatch when expected dimension is supplied', () => {
  const vec = new Float32Array([1, 2, 3]);
  assert.throws(
    () => validateVector(vec, 4),
    (err: unknown) => err instanceof InvalidVectorError && err.message.includes('dimension mismatch')
  );
  assert.throws(
    () => validateVectorDimensions(vec, 2),
    (err: unknown) => err instanceof InvalidVectorError && err.message.includes('dimension mismatch')
  );
});

test('validateVector - rejects non-finite values (NaN, +Infinity, -Infinity)', () => {
  const withNaN = new Float32Array([1.0, NaN, 3.0]);
  assert.throws(
    () => validateVector(withNaN),
    (err: unknown) => err instanceof InvalidVectorError && err.message.includes('non-finite')
  );

  const withInf = new Float32Array([1.0, Infinity, 3.0]);
  assert.throws(
    () => validateVector(withInf),
    (err: unknown) => err instanceof InvalidVectorError && err.message.includes('non-finite')
  );

  const withNegInf = new Float32Array([1.0, -Infinity, 3.0]);
  assert.throws(
    () => validateVector(withNegInf),
    (err: unknown) => err instanceof InvalidVectorError && err.message.includes('non-finite')
  );
});

test('l2Norm - correctly computes Euclidean norm', () => {
  // 3-4-5 right triangle
  const vec1 = new Float32Array([3, 4]);
  assert.equal(l2Norm(vec1), 5);

  // Unit vector
  const vec2 = new Float32Array([0, 1, 0]);
  assert.equal(l2Norm(vec2), 1);

  // 1-1-1-1 vector: sqrt(4) = 2
  const vec3 = new Float32Array([1, 1, 1, 1]);
  assert.equal(l2Norm(vec3), 2);
});

test('isZeroVector - correctly identifies zero vectors and non-zero vectors', () => {
  const zero1 = new Float32Array([0, 0, 0]);
  assert.equal(isZeroVector(zero1), true);

  const zeroTiny = new Float32Array([1e-11, -1e-11]);
  assert.equal(isZeroVector(zeroTiny), true);

  const nonZero = new Float32Array([0, 0.001, 0]);
  assert.equal(isZeroVector(nonZero), false);
});

test('normalizeVector - normalizes unnormalized vectors to unit length', () => {
  const vec = new Float32Array([3, 4]);
  const norm = normalizeVector(vec);

  assert.equal(norm.length, 2);
  assert.ok(Math.abs(norm[0]! - 0.6) < 1e-6);
  assert.ok(Math.abs(norm[1]! - 0.8) < 1e-6);
  assert.ok(Math.abs(l2Norm(norm) - 1.0) < 1e-6);
  assert.equal(isNormalized(norm), true);

  // Original vector is not mutated
  assert.equal(vec[0], 3);
  assert.equal(vec[1], 4);
});

test('normalizeVector - rejects zero vectors', () => {
  const zero = new Float32Array([0, 0, 0]);
  assert.throws(
    () => normalizeVector(zero),
    (err: unknown) => err instanceof InvalidVectorError && err.message.includes('zero-magnitude')
  );
});

test('cloneVector - creates independent defensive copy', () => {
  const original = new Float32Array([1.5, 2.5, 3.5]);
  const clone = cloneVector(original);

  assert.deepEqual(clone, original);
  assert.notEqual(clone, original);

  clone[0] = 99.0;
  assert.equal(original[0], 1.5);
  assert.equal(clone[0], 99.0);
});

test('dotProduct - correctly calculates dot product', () => {
  const a = new Float32Array([1, 2, 3]);
  const b = new Float32Array([4, 5, 6]);
  // 1*4 + 2*5 + 3*6 = 4 + 10 + 18 = 32
  assert.equal(dotProduct(a, b), 32);
});

test('dotProduct - rejects dimension mismatch and invalid vectors', () => {
  const a = new Float32Array([1, 2]);
  const b = new Float32Array([1, 2, 3]);
  assert.throws(
    () => dotProduct(a, b),
    (err: unknown) => err instanceof InvalidVectorError && err.message.includes('Dimension mismatch')
  );

  const invalid = new Float32Array([1, NaN]);
  assert.throws(() => dotProduct(a, invalid), InvalidVectorError);
});

test('cosineSimilarity - returns 1.0 for identical vectors', () => {
  const a = new Float32Array([1, 2, 3]);
  const b = new Float32Array([1, 2, 3]);
  const sim = cosineSimilarity(a, b);
  assert.ok(Math.abs(sim - 1.0) < 1e-6, `Expected ~1.0, received ${sim}`);

  // Scaled identical direction
  const c = new Float32Array([2, 4, 6]);
  const simScaled = cosineSimilarity(a, c);
  assert.ok(Math.abs(simScaled - 1.0) < 1e-6, `Expected ~1.0, received ${simScaled}`);
});

test('cosineSimilarity - returns -1.0 for opposite vectors', () => {
  const a = new Float32Array([1, 2, 3]);
  const b = new Float32Array([-1, -2, -3]);
  const sim = cosineSimilarity(a, b);
  assert.ok(Math.abs(sim - (-1.0)) < 1e-6, `Expected ~-1.0, received ${sim}`);
});

test('cosineSimilarity - returns 0.0 for orthogonal vectors', () => {
  const a = new Float32Array([1, 0, 0]);
  const b = new Float32Array([0, 1, 0]);
  const sim = cosineSimilarity(a, b);
  assert.ok(Math.abs(sim - 0.0) < 1e-6, `Expected ~0.0, received ${sim}`);
});

test('cosineSimilarity - handles zero vectors and dimension mismatch safely', () => {
  const a = new Float32Array([1, 2, 3]);
  const zero = new Float32Array([0, 0, 0]);
  assert.throws(
    () => cosineSimilarity(a, zero),
    (err: unknown) => err instanceof InvalidVectorError && err.message.includes('zero-magnitude')
  );

  const diffDim = new Float32Array([1, 2]);
  assert.throws(
    () => cosineSimilarity(a, diffDim),
    (err: unknown) => err instanceof InvalidVectorError && err.message.includes('Dimension mismatch')
  );
});

// ============================================================================
// 2. Deterministic Mock Embedding Provider Unit Tests
// ============================================================================

test('DeterministicMockEmbeddingProvider - initializes with clean defaults', async () => {
  const provider = new DeterministicMockEmbeddingProvider();
  assert.equal(provider.name, 'mock-embedding-provider');
  assert.equal(provider.modelId, 'mock-deterministic-v1');
  assert.equal(provider.dimensions, 384);
  assert.equal(await provider.isAvailable(), true);
});

test('DeterministicMockEmbeddingProvider - validates custom constructor options', () => {
  const provider = new DeterministicMockEmbeddingProvider({
    name: 'custom-mock',
    modelId: 'custom-model-v2',
    dimensions: 128,
    available: false
  });
  assert.equal(provider.name, 'custom-mock');
  assert.equal(provider.modelId, 'custom-model-v2');
  assert.equal(provider.dimensions, 128);

  assert.throws(
    () => new DeterministicMockEmbeddingProvider({ dimensions: 0 }),
    ValidationError
  );
  assert.throws(
    () => new DeterministicMockEmbeddingProvider({ dimensions: -10 }),
    ValidationError
  );
  assert.throws(
    () => new DeterministicMockEmbeddingProvider({ dimensions: 384.5 }),
    ValidationError
  );
});

test('DeterministicMockEmbeddingProvider - generates deterministic repeatable vectors', async () => {
  const provider = new DeterministicMockEmbeddingProvider({ dimensions: 256 });
  const text = 'The quick brown fox jumps over the lazy dog';

  const vec1 = await provider.embed(text);
  const vec2 = await provider.embed(text);
  const vec3 = await provider.embed(text);

  assert.equal(vec1.length, 256);
  assert.equal(vec2.length, 256);
  assert.equal(vec3.length, 256);

  // Exact float32 equality across all dimensions
  assert.deepEqual(vec1, vec2);
  assert.deepEqual(vec2, vec3);

  // Verify L2 normalization
  assert.ok(isNormalized(vec1));
  assert.ok(Math.abs(l2Norm(vec1) - 1.0) < 1e-4);

  // Different texts produce distinct vectors
  const vecOther = await provider.embed('A completely unrelated string of text');
  assert.notDeepEqual(vec1, vecOther);
});

test('DeterministicMockEmbeddingProvider - embedBatch produces results identical to embed', async () => {
  const provider = new DeterministicMockEmbeddingProvider({ dimensions: 128 });
  const texts = [
    'First document to embed',
    'Second document with distinct keywords',
    'Third technical procedure note'
  ];

  const batchResults = await provider.embedBatch(texts);
  assert.equal(batchResults.length, 3);

  for (let i = 0; i < texts.length; i++) {
    const singleResult = await provider.embed(texts[i]!);
    assert.deepEqual(batchResults[i], singleResult);
    assert.ok(isNormalized(batchResults[i]!));
  }
});

test('DeterministicMockEmbeddingProvider - returns defensive copies (immutable buffers)', async () => {
  const provider = new DeterministicMockEmbeddingProvider({ dimensions: 64 });
  const text = 'Immutable vector test text';

  const vec1 = await provider.embed(text);
  const originalFirstValue = vec1[0]!;

  // Mutate returned buffer
  vec1[0] = 999.0;

  // Next call for same text returns pristine original
  const vec2 = await provider.embed(text);
  assert.equal(vec2[0], originalFirstValue);
  assert.notEqual(vec2[0], 999.0);
});

test('DeterministicMockEmbeddingProvider - rejects empty, blank, or invalid text inputs', async () => {
  const provider = new DeterministicMockEmbeddingProvider();

  await assert.rejects(() => provider.embed(''), ValidationError);
  await assert.rejects(() => provider.embed('   \n\t  '), ValidationError);
  await assert.rejects(() => provider.embed(null as any), ValidationError);
  await assert.rejects(() => provider.embed(undefined as any), ValidationError);
  await assert.rejects(() => provider.embed(12345 as any), ValidationError);
});

test('DeterministicMockEmbeddingProvider - rejects oversized text exceeding MAX_EMBEDDING_TEXT_LENGTH', async () => {
  const provider = new DeterministicMockEmbeddingProvider();
  const oversized = 'a'.repeat(MAX_EMBEDDING_TEXT_LENGTH + 1);

  await assert.rejects(
    () => provider.embed(oversized),
    (err: unknown) => err instanceof ValidationError && err.message.includes('exceeds maximum length')
  );

  // Text exactly at boundary is accepted
  const atBoundary = 'a'.repeat(MAX_EMBEDDING_TEXT_LENGTH);
  const result = await provider.embed(atBoundary);
  assert.equal(result.length, 384);
});

test('DeterministicMockEmbeddingProvider - rejects invalid batch inputs and sizes', async () => {
  const provider = new DeterministicMockEmbeddingProvider();

  await assert.rejects(() => provider.embedBatch([]), ValidationError);
  await assert.rejects(() => provider.embedBatch(null as any), ValidationError);
  await assert.rejects(() => provider.embedBatch(['valid', '', 'another']), ValidationError);

  const oversizedBatch = Array.from({ length: MAX_EMBEDDING_BATCH_SIZE + 1 }, (_, i) => `item-${i}`);
  await assert.rejects(
    () => provider.embedBatch(oversizedBatch),
    (err: unknown) => err instanceof ValidationError && err.message.includes('exceeds maximum allowed limit')
  );
});

test('DeterministicMockEmbeddingProvider - supports controlled predefined vectors for exact similarity tests', async () => {
  const dimensions = 4;
  const provider = new DeterministicMockEmbeddingProvider({ dimensions });

  // Define 3 controlled vectors: reference, orthogonal, and opposite
  const refVec = new Float32Array([1, 0, 0, 0]);
  const orthoVec = new Float32Array([0, 1, 0, 0]);
  const oppoVec = new Float32Array([-1, 0, 0, 0]);

  provider.registerPredefinedVector('reference query', refVec);
  provider.registerPredefinedVector('orthogonal concept', orthoVec);
  provider.registerPredefinedVector('opposite polarity', oppoVec);

  const vRef = await provider.embed('reference query');
  const vIdentical = await provider.embed('reference query');
  const vOrtho = await provider.embed('orthogonal concept');
  const vOppo = await provider.embed('opposite polarity');

  assert.ok(Math.abs(cosineSimilarity(vRef, vIdentical) - 1.0) < 1e-6);
  assert.ok(Math.abs(cosineSimilarity(vRef, vOrtho) - 0.0) < 1e-6);
  assert.ok(Math.abs(cosineSimilarity(vRef, vOppo) - (-1.0)) < 1e-6);

  // Clearing predefined vectors returns to hash-based generation
  provider.clearPredefinedVectors();
  const vReset = await provider.embed('reference query');
  // Different from the manually registered [1, 0, 0, 0]
  assert.notDeepEqual(vReset, refVec);
});

test('DeterministicMockEmbeddingProvider - enforces provider availability', async () => {
  const provider = new DeterministicMockEmbeddingProvider();
  assert.equal(await provider.isAvailable(), true);

  provider.setAvailable(false);
  assert.equal(await provider.isAvailable(), false);

  await assert.rejects(
    () => provider.embed('any query'),
    (err: unknown) => err instanceof EmbeddingProviderUnavailableError && err.code === 'EMBEDDING_PROVIDER_UNAVAILABLE'
  );

  await assert.rejects(
    () => provider.embedBatch(['query a', 'query b']),
    (err: unknown) => err instanceof EmbeddingProviderUnavailableError && err.code === 'EMBEDDING_PROVIDER_UNAVAILABLE'
  );

  provider.setAvailable(true);
  const vec = await provider.embed('any query');
  assert.equal(vec.length, 384);
});

test('DeterministicMockEmbeddingProvider - simulates transient and persistent inference failures', async () => {
  const provider = new DeterministicMockEmbeddingProvider();

  // Transient queued failure
  provider.enqueueFailure(new EmbeddingInferenceError('Model OOM test failure'));
  await assert.rejects(
    () => provider.embed('test query'),
    (err: unknown) => err instanceof EmbeddingInferenceError && err.message === 'Model OOM test failure'
  );

  // Next call succeeds normally
  const recovered = await provider.embed('test query');
  assert.equal(recovered.length, 384);

  // Persistent simulated failure
  provider.setSimulatedFailure(new EmbeddingInferenceError('Continuous engine stall'));
  await assert.rejects(() => provider.embed('call 1'), EmbeddingInferenceError);
  await assert.rejects(() => provider.embedBatch(['call 2']), EmbeddingInferenceError);

  // Clearing persistent failure restores functionality
  provider.setSimulatedFailure(null);
  const backToNormal = await provider.embed('call 3');
  assert.equal(backToNormal.length, 384);
});

test('DeterministicMockEmbeddingProvider - respects cooperative cancellation signal', async () => {
  const provider = new DeterministicMockEmbeddingProvider();
  const controller = new AbortController();

  controller.abort('User cancelled task');

  await assert.rejects(
    () => provider.embed('cancellation test', { signal: controller.signal }),
    (err: unknown) => err instanceof AgentCancelledError && err.message.includes('User cancelled task')
  );

  await assert.rejects(
    () => provider.embedBatch(['item 1', 'item 2'], { signal: controller.signal }),
    (err: unknown) => err instanceof AgentCancelledError && err.message.includes('User cancelled task')
  );
});

test('DeterministicMockEmbeddingProvider - records call history accurately', async () => {
  const provider = new DeterministicMockEmbeddingProvider();
  assert.equal(provider.getRecordedCalls().length, 0);

  await provider.embed('single query');
  await provider.embedBatch(['batch 1', 'batch 2']);

  const history = provider.getRecordedCalls();
  assert.equal(history.length, 2);
  assert.equal(history[0]!.method, 'embed');
  assert.deepEqual(history[0]!.texts, ['single query']);
  assert.equal(history[1]!.method, 'embedBatch');
  assert.deepEqual(history[1]!.texts, ['batch 1', 'batch 2']);

  provider.clearHistory();
  assert.equal(provider.getRecordedCalls().length, 0);
});
