/**
 * Next-Generation Dots AI Platform - Local Embedding Provider Tests
 * Phase 4C.3: Optional Local Embedding Provider
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  LocalEmbeddingProvider,
  DEFAULT_LOCAL_EMBEDDING_MODEL,
  DEFAULT_LOCAL_EMBEDDING_DIMENSIONS,
  DEFAULT_LOCAL_RUNTIME_VERSION,
  type FeatureExtractorFn,
  type PipelineLoaderFn
} from '../../src/memory/local-embedding-provider.ts';
import {
  MAX_EMBEDDING_TEXT_LENGTH,
  MAX_EMBEDDING_BATCH_SIZE
} from '../../src/memory/embedding-types.ts';
import {
  isNormalized,
  l2Norm
} from '../../src/memory/vector-utils.ts';
import {
  ValidationError,
  InvalidVectorError,
  EmbeddingProviderUnavailableError,
  EmbeddingInferenceError,
  AgentCancelledError
} from '../../src/domain/errors.ts';

/**
 * Creates a deterministic fake feature extractor producing valid unit vectors.
 */
function createFakeExtractor(dimensions = 384): FeatureExtractorFn {
  return async (texts: string | readonly string[]) => {
    const isBatch = Array.isArray(texts);
    const count = isBatch ? texts.length : 1;
    const data = new Float32Array(count * dimensions);

    for (let i = 0; i < count; i++) {
      const text = isBatch ? texts[i]! : (texts as string);
      // Deterministically set components based on string length and index
      const offset = i * dimensions;
      for (let j = 0; j < dimensions; j++) {
        data[offset + j] = Math.sin(text.length * 10 + j);
      }
      // Normalize in place
      let sumSq = 0;
      for (let j = 0; j < dimensions; j++) {
        sumSq += data[offset + j]! * data[offset + j]!;
      }
      const norm = Math.sqrt(sumSq) || 1.0;
      for (let j = 0; j < dimensions; j++) {
        data[offset + j] = data[offset + j]! / norm;
      }
    }

    return {
      data,
      dims: [count, dimensions]
    };
  };
}

// ============================================================================
// 1. Instantiation and Model Descriptor Tests
// ============================================================================

test('LocalEmbeddingProvider - initializes with documented defaults and stable model identity', () => {
  const provider = new LocalEmbeddingProvider({
    pipelineLoader: async () => createFakeExtractor(384)
  });

  assert.equal(provider.name, 'transformers-local');
  assert.equal(provider.modelId, DEFAULT_LOCAL_EMBEDDING_MODEL);
  assert.equal(provider.modelRevision, 'main');
  assert.equal(provider.dimensions, DEFAULT_LOCAL_EMBEDDING_DIMENSIONS);
  assert.equal(provider.allowRemoteModels, false);
  assert.equal(provider.device, 'cpu');
  assert.equal(provider.runtimeVersion, DEFAULT_LOCAL_RUNTIME_VERSION);

  const descriptor = provider.getModelDescriptor();
  assert.equal(descriptor.providerName, 'transformers-local');
  assert.equal(descriptor.modelId, 'onnx-community/all-MiniLM-L6-v2-ONNX');
  assert.equal(descriptor.modelRevision, 'main');
  assert.equal(descriptor.dimensions, 384);
  assert.equal(descriptor.allowRemoteModels, false);
  assert.equal(descriptor.canonicalId, 'transformers-local:onnx-community/all-MiniLM-L6-v2-ONNX@main:d384');
});

test('LocalEmbeddingProvider - validates custom constructor dimensions', () => {
  assert.throws(
    () => new LocalEmbeddingProvider({ dimensions: 0 }),
    ValidationError
  );
  assert.throws(
    () => new LocalEmbeddingProvider({ dimensions: -384 }),
    ValidationError
  );
  assert.throws(
    () => new LocalEmbeddingProvider({ dimensions: 384.5 }),
    ValidationError
  );
});

// ============================================================================
// 2. Lazy Initialization and Concurrency Protection
// ============================================================================

test('LocalEmbeddingProvider - model initialization is lazy and executes on demand', async () => {
  let loadCallCount = 0;
  const loader: PipelineLoaderFn = async () => {
    loadCallCount++;
    return createFakeExtractor(384);
  };

  const provider = new LocalEmbeddingProvider({ pipelineLoader: loader });
  assert.equal(loadCallCount, 0, 'Loader must not be called upon provider construction');

  const vec = await provider.embed('Lazy loading verification');
  assert.equal(loadCallCount, 1, 'Loader must be called on first embed call');
  assert.equal(vec.length, 384);

  // Subsequent embed calls reuse cached pipeline instance
  await provider.embed('Second query using cached extractor');
  assert.equal(loadCallCount, 1, 'Loader must not be re-called when pipeline is already initialized');
});

test('LocalEmbeddingProvider - protects against concurrent duplicate initialization', async () => {
  let loadCallCount = 0;
  const loader: PipelineLoaderFn = async () => {
    loadCallCount++;
    // Simulate realistic asynchronous model loading delay
    await new Promise((resolve) => setTimeout(resolve, 25));
    return createFakeExtractor(384);
  };

  const provider = new LocalEmbeddingProvider({ pipelineLoader: loader });

  // Fire 10 concurrent embedding calls simultaneously
  const promises = Array.from({ length: 10 }, (_, i) =>
    provider.embed(`Concurrent query #${i}`)
  );

  const results = await Promise.all(promises);
  assert.equal(loadCallCount, 1, 'Concurrent requests must share single pipeline initialization');
  assert.equal(results.length, 10);
  for (const vec of results) {
    assert.equal(vec.length, 384);
    assert.ok(isNormalized(vec));
  }
});

// ============================================================================
// 3. Single and Batch Embedding Tests
// ============================================================================

test('LocalEmbeddingProvider - generates valid unit-normalized vectors for single texts', async () => {
  const provider = new LocalEmbeddingProvider({
    pipelineLoader: async () => createFakeExtractor(384)
  });

  const vector = await provider.embed('Vector embedding test for local provider');
  assert.ok(vector instanceof Float32Array);
  assert.equal(vector.length, 384);
  assert.ok(isNormalized(vector));
  assert.ok(Math.abs(l2Norm(vector) - 1.0) < 1e-4);
});

test('LocalEmbeddingProvider - returns defensive copies that protect internal buffers', async () => {
  const provider = new LocalEmbeddingProvider({
    pipelineLoader: async () => createFakeExtractor(384)
  });

  const vec1 = await provider.embed('Immutable buffer validation');
  const originalFirstVal = vec1[0]!;

  // Mutate returned buffer externally
  vec1[0] = 999.0;

  const vec2 = await provider.embed('Immutable buffer validation');
  assert.equal(vec2[0], originalFirstVal);
  assert.notEqual(vec2[0], 999.0);
});

test('LocalEmbeddingProvider - handles batch embeddings within size limits', async () => {
  const provider = new LocalEmbeddingProvider({
    pipelineLoader: async () => createFakeExtractor(384)
  });

  const batch = [
    'Document one on security architecture',
    'Document two on database transaction semantics',
    'Document three on agent memory context'
  ];

  const vectors = await provider.embedBatch(batch);
  assert.equal(vectors.length, 3);
  for (const v of vectors) {
    assert.equal(v.length, 384);
    assert.ok(isNormalized(v));
  }
});

test('LocalEmbeddingProvider - normalizes unnormalized model outputs automatically', async () => {
  // Fake extractor that returns unnormalized vector: [3, 4, 0, ...]
  const unnormalizedExtractor: FeatureExtractorFn = async () => {
    const data = new Float32Array(384);
    data[0] = 3.0;
    data[1] = 4.0;
    return { data, dims: [1, 384] };
  };

  const provider = new LocalEmbeddingProvider({
    pipelineLoader: async () => unnormalizedExtractor
  });

  const vector = await provider.embed('Text requiring normalization');
  assert.equal(vector.length, 384);
  assert.ok(Math.abs(vector[0]! - 0.6) < 1e-6);
  assert.ok(Math.abs(vector[1]! - 0.8) < 1e-6);
  assert.ok(isNormalized(vector));
});

// ============================================================================
// 4. Input and Output Validation Tests
// ============================================================================

test('LocalEmbeddingProvider - rejects empty, blank, or invalid input texts', async () => {
  const provider = new LocalEmbeddingProvider({
    pipelineLoader: async () => createFakeExtractor(384)
  });

  await assert.rejects(() => provider.embed(''), ValidationError);
  await assert.rejects(() => provider.embed('   \n\t  '), ValidationError);
  await assert.rejects(() => provider.embed(null as any), ValidationError);
  await assert.rejects(() => provider.embed(undefined as any), ValidationError);
  await assert.rejects(() => provider.embed(12345 as any), ValidationError);
});

test('LocalEmbeddingProvider - rejects oversized text exceeding MAX_EMBEDDING_TEXT_LENGTH', async () => {
  const provider = new LocalEmbeddingProvider({
    pipelineLoader: async () => createFakeExtractor(384)
  });

  const oversized = 'x'.repeat(MAX_EMBEDDING_TEXT_LENGTH + 1);
  await assert.rejects(
    () => provider.embed(oversized),
    (err: unknown) => err instanceof ValidationError && err.message.includes('exceeds maximum length')
  );

  // Exact boundary is accepted
  const atBoundary = 'x'.repeat(MAX_EMBEDDING_TEXT_LENGTH);
  const result = await provider.embed(atBoundary);
  assert.equal(result.length, 384);
});

test('LocalEmbeddingProvider - rejects empty or oversized batch requests', async () => {
  const provider = new LocalEmbeddingProvider({
    pipelineLoader: async () => createFakeExtractor(384)
  });

  await assert.rejects(() => provider.embedBatch([]), ValidationError);
  await assert.rejects(() => provider.embedBatch(null as any), ValidationError);

  const oversizedBatch = Array.from({ length: MAX_EMBEDDING_BATCH_SIZE + 1 }, (_, i) => `text-${i}`);
  await assert.rejects(
    () => provider.embedBatch(oversizedBatch),
    (err: unknown) => err instanceof ValidationError && err.message.includes('exceeds maximum allowed limit')
  );
});

test('LocalEmbeddingProvider - rejects invalid model outputs (NaN, wrong dimensions, empty)', async () => {
  // 1. Output containing NaN
  const nanExtractor: FeatureExtractorFn = async () => ({
    data: new Float32Array([1.0, NaN, 0.0]),
    dims: [1, 3]
  });
  const nanProvider = new LocalEmbeddingProvider({
    dimensions: 3,
    pipelineLoader: async () => nanExtractor
  });
  await assert.rejects(() => nanProvider.embed('test'), InvalidVectorError);

  // 2. Output dimension mismatch (advertised 384, model returned 128)
  const wrongDimExtractor: FeatureExtractorFn = async () => ({
    data: new Float32Array(128),
    dims: [1, 128]
  });
  const wrongDimProvider = new LocalEmbeddingProvider({
    dimensions: 384,
    pipelineLoader: async () => wrongDimExtractor
  });
  await assert.rejects(
    () => wrongDimProvider.embed('test'),
    (err: unknown) => err instanceof InvalidVectorError && err.message.includes('mismatch')
  );

  // 3. Null tensor output
  const nullExtractor: FeatureExtractorFn = async () => null as any;
  const nullProvider = new LocalEmbeddingProvider({
    pipelineLoader: async () => nullExtractor
  });
  await assert.rejects(() => nullProvider.embed('test'), InvalidVectorError);
});

// ============================================================================
// 5. Offline and Local-Only Enforcement Tests
// ============================================================================

test('LocalEmbeddingProvider - enforces local-only mode and disables remote downloads by default', async () => {
  let passedOptions: Record<string, unknown> | undefined;
  const loader: PipelineLoaderFn = async (_task, _modelId, options) => {
    passedOptions = options;
    return createFakeExtractor(384);
  };

  const provider = new LocalEmbeddingProvider({
    localModelPath: '/models/all-minilm',
    pipelineLoader: loader
  });

  await provider.embed('Verify local configuration');
  assert.ok(passedOptions);
  assert.equal(passedOptions.allowRemoteModels, false, 'allowRemoteModels must default to false');
  assert.equal(passedOptions.localModelPath, '/models/all-minilm');
});

test('LocalEmbeddingProvider - throws EmbeddingProviderUnavailableError when local model is missing and remote is disabled', async () => {
  const missingModelLoader: PipelineLoaderFn = async (_task, modelId, options) => {
    if (!options?.allowRemoteModels) {
      throw new EmbeddingProviderUnavailableError(
        'transformers-local',
        `Local embedding model '${modelId}' was not found. Remote downloads are disabled.`
      );
    }
    return createFakeExtractor(384);
  };

  const provider = new LocalEmbeddingProvider({
    pipelineLoader: missingModelLoader
  });

  assert.equal(await provider.isAvailable(), false);
  await assert.rejects(
    () => provider.embed('Query with missing model'),
    (err: unknown) => err instanceof EmbeddingProviderUnavailableError && err.code === 'EMBEDDING_PROVIDER_UNAVAILABLE'
  );
});

test('LocalEmbeddingProvider - throws EmbeddingProviderUnavailableError when optional package is not installed', async () => {
  const missingPackageLoader: PipelineLoaderFn = async () => {
    throw new EmbeddingProviderUnavailableError(
      'transformers-local',
      "Optional package '@huggingface/transformers' is not installed."
    );
  };

  const provider = new LocalEmbeddingProvider({
    pipelineLoader: missingPackageLoader
  });

  assert.equal(await provider.isAvailable(), false);
  await assert.rejects(
    () => provider.embed('Query with missing package'),
    (err: unknown) => err instanceof EmbeddingProviderUnavailableError && err.message.includes('@huggingface/transformers')
  );
});

test('LocalEmbeddingProvider - default pipeline loader throws EmbeddingProviderUnavailableError when package is not installed', async (t) => {
  let isPackageInstalled = false;
  try {
    // @ts-ignore
    await import('@huggingface/transformers');
    isPackageInstalled = true;
  } catch {
    isPackageInstalled = false;
  }

  if (isPackageInstalled) {
    t.skip('Package @huggingface/transformers is installed in environment.');
    return;
  }

  // Construct provider without injecting custom loader (using defaultTransformersPipelineLoader)
  const provider = new LocalEmbeddingProvider();
  assert.equal(await provider.isAvailable(), false);
  await assert.rejects(
    () => provider.embed('Real uninstalled package invocation'),
    (err: unknown) =>
      err instanceof EmbeddingProviderUnavailableError &&
      err.message.includes('@huggingface/transformers')
  );
});


// ============================================================================
// 6. Error Handling and Cancellation Tests
// ============================================================================

test('LocalEmbeddingProvider - wraps runtime inference failures into EmbeddingInferenceError', async () => {
  const failingExtractor: FeatureExtractorFn = async () => {
    throw new Error('WASM memory allocation ceiling exceeded during inference');
  };

  const provider = new LocalEmbeddingProvider({
    pipelineLoader: async () => failingExtractor
  });

  await assert.rejects(
    () => provider.embed('Query causing inference failure'),
    (err: unknown) => err instanceof EmbeddingInferenceError && err.message.includes('WASM memory allocation')
  );

  await assert.rejects(
    () => provider.embedBatch(['Query 1', 'Query 2']),
    (err: unknown) => err instanceof EmbeddingInferenceError && err.message.includes('WASM memory allocation')
  );
});

test('LocalEmbeddingProvider - respects cooperative cancellation signal', async () => {
  const provider = new LocalEmbeddingProvider({
    pipelineLoader: async () => createFakeExtractor(384)
  });

  const controller = new AbortController();
  controller.abort('Embedding aborted by workflow coordinator');

  await assert.rejects(
    () => provider.embed('Cancelled query', { signal: controller.signal }),
    (err: unknown) => err instanceof AgentCancelledError && err.message.includes('Embedding aborted')
  );

  await assert.rejects(
    () => provider.embedBatch(['Item 1', 'Item 2'], { signal: controller.signal }),
    (err: unknown) => err instanceof AgentCancelledError && err.message.includes('Embedding aborted')
  );
});
