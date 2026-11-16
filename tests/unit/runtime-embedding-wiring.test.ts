/**
 * Next-Generation Dots AI Platform - Runtime Embedding Wiring & Configuration Tests
 * Phase 4C.8: Production Runtime Wiring & Embedding Configuration
 * 
 * Verifies:
 * 1. Runtime configuration loading, environment variables, validation, and defaults.
 * 2. Dependency instantiation and retention on DotsRuntime / DotsApp.
 * 3. Consistent modelId, revision, and dimensions across jobs, vectors, and hybrid retrieval.
 * 4. Automatic job enqueueing upon active memory creation.
 * 5. Lifecycle worker startup, recovery, and job processing through runtime.start().
 * 6. Hybrid retrieval in the integrated runtime environment.
 * 7. Safe shutdown ordering and SQLite closure protection during in-flight operations.
 * 8. Backward compatibility and full usability in 'none' provider mode.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DotsRuntime, DotsApp } from '../../src/runtime/app.ts';
import { loadRuntimeConfig } from '../../src/runtime/config.ts';
import { ValidationError } from '../../src/domain/errors.ts';
import { DeterministicMockEmbeddingProvider } from '../../src/memory/mock-embedding-provider.ts';
import { LocalEmbeddingProvider } from '../../src/memory/local-embedding-provider.ts';
import { MemoryEmbeddingRepository } from '../../src/storage/memory-embedding-repository.ts';
import { EmbeddingJobRepository } from '../../src/storage/embedding-job-repository.ts';
import { EmbeddingLifecycleManager } from '../../src/memory/embedding-lifecycle-manager.ts';
import type { CallerContext } from '../../src/domain/types.ts';

const TEST_TOKENS = [
  {
    token: 'test-admin-token-12345',
    principalId: 'test-admin',
    role: 'ADMIN' as const,
    permittedScopes: [{ scopeType: 'WORKSPACE' as const, scopeId: 'ws-runtime' }]
  }
];

function getCaller(runtime: DotsRuntime, scopeId = 'ws-runtime'): CallerContext {
  const session = runtime.authenticateUser('test-admin-token-12345', { scopeType: 'WORKSPACE', scopeId });
  return session.caller;
}

test('1. Config: Defaults to embeddingProvider none with valid defaults', () => {
  const config = loadRuntimeConfig({
    requireTokens: false,
    tokens: TEST_TOKENS,
    env: {}
  });

  assert.equal(config.embeddingProvider, 'none');
  assert.equal(config.embeddingModelRevision, 'main');
  assert.equal(config.embeddingPollIntervalMs, 1000);
  assert.equal(config.embeddingDimensions, 384);
  assert.ok(config.embeddingModelId.length > 0);
});

test('2. Config: Parses DOTS_EMBEDDING_PROVIDER and model settings from env', () => {
  const configMock = loadRuntimeConfig({
    requireTokens: false,
    tokens: TEST_TOKENS,
    env: {
      DOTS_EMBEDDING_PROVIDER: 'mock',
      DOTS_EMBEDDING_MODEL_ID: 'custom-mock-v2',
      DOTS_EMBEDDING_MODEL_REVISION: 'v2.1',
      DOTS_EMBEDDING_POLL_INTERVAL_MS: '250',
      DOTS_EMBEDDING_LOCAL_MODEL_PATH: '/tmp/models'
    }
  });

  assert.equal(configMock.embeddingProvider, 'mock');
  assert.equal(configMock.embeddingModelId, 'custom-mock-v2');
  assert.equal(configMock.embeddingModelRevision, 'v2.1');
  assert.equal(configMock.embeddingPollIntervalMs, 250);
  assert.equal(configMock.embeddingLocalModelPath, '/tmp/models');

  const configLocal = loadRuntimeConfig({
    requireTokens: false,
    tokens: TEST_TOKENS,
    env: {
      DOTS_EMBEDDING_PROVIDER: 'local'
    }
  });
  assert.equal(configLocal.embeddingProvider, 'local');
  assert.equal(configLocal.embeddingModelId, 'onnx-community/all-MiniLM-L6-v2-ONNX');
});

test('3. Config: Validates invalid provider, poll interval, and model strings', () => {
  // Invalid provider name
  assert.throws(
    () => loadRuntimeConfig({ requireTokens: false, env: { DOTS_EMBEDDING_PROVIDER: 'openai' } }),
    (err: unknown) => err instanceof ValidationError && err.message.includes("Invalid embedding provider 'openai'")
  );

  // Invalid poll interval
  assert.throws(
    () => loadRuntimeConfig({ requireTokens: false, env: { DOTS_EMBEDDING_POLL_INTERVAL_MS: '-50' } }),
    (err: unknown) => err instanceof ValidationError && err.message.includes("DOTS_EMBEDDING_POLL_INTERVAL_MS")
  );

  // Empty model ID
  assert.throws(
    () => loadRuntimeConfig({ requireTokens: false, env: { DOTS_EMBEDDING_MODEL_ID: '   ' } }),
    (err: unknown) => err instanceof ValidationError && err.message.includes("DOTS_EMBEDDING_MODEL_ID")
  );

  // Empty revision
  assert.throws(
    () => loadRuntimeConfig({ requireTokens: false, env: { DOTS_EMBEDDING_MODEL_REVISION: '' } }),
    (err: unknown) => err instanceof ValidationError && err.message.includes("DOTS_EMBEDDING_MODEL_REVISION")
  );
});

test('4. Runtime: Instantiates and retains required dependencies on DotsRuntime and DotsApp', () => {
  assert.equal(DotsApp, DotsRuntime);

  const runtime = new DotsRuntime({
    dbPath: ':memory:',
    tokens: TEST_TOKENS,
    embeddingProvider: 'mock',
    embeddingModelId: 'mock-model-app',
    embeddingModelRevision: 'rev-app',
    silentLogs: true
  });

  assert.ok(runtime.embeddingRepo instanceof MemoryEmbeddingRepository);
  assert.ok(runtime.embeddingJobRepo instanceof EmbeddingJobRepository);
  assert.ok(runtime.embeddingProvider instanceof DeterministicMockEmbeddingProvider);
  assert.ok(runtime.lifecycleManager instanceof EmbeddingLifecycleManager);
  assert.equal(runtime.embeddingProvider.modelId, 'mock-model-app');
  assert.equal((runtime.embeddingProvider as any).modelRevision, 'rev-app');

  // Verify repositories share the exact same db
  assert.equal(runtime.embeddingRepo.db, runtime.db);
  assert.equal(runtime.embeddingJobRepo.db, runtime.db);
  assert.equal(runtime.memoryService.db, runtime.db);

  // Health endpoint reflects embedding configuration
  const health = runtime.getHealth();
  assert.equal(health.embeddingProvider, 'mock-embedding-provider');
  assert.equal(health.embeddingEnabled, true);
  assert.equal(health.embeddingWorkerActive, false);
});

test('5. Runtime: Dependency injection of custom provider overrides config', () => {
  const customProvider = new DeterministicMockEmbeddingProvider({
    modelId: 'injected-provider-v1',
    modelRevision: 'custom-rev'
  });

  const runtime = new DotsRuntime({
    dbPath: ':memory:',
    tokens: TEST_TOKENS,
    embeddingProvider: customProvider,
    silentLogs: true
  });

  assert.equal(runtime.embeddingProvider, customProvider);
  assert.equal(runtime.lifecycleManager?.provider, customProvider);
  assert.equal(runtime.config.embeddingProvider, 'none'); // config default untouched
});

test('6. Memory Mutation: Active memory creation automatically enqueues durable embedding job', () => {
  const runtime = new DotsRuntime({
    dbPath: ':memory:',
    tokens: TEST_TOKENS,
    embeddingProvider: 'mock',
    embeddingModelId: 'model-durable-1',
    embeddingModelRevision: 'rev-durable-1',
    silentLogs: true
  });

  const caller = getCaller(runtime);

  // Create active memory
  const memory = runtime.memoryService.createMemory(caller, {
    category: 'PROJECT_FACT',
    scopeType: caller.scope.scopeType,
    scopeId: caller.scope.scopeId,
    key: 'runtime.arch',
    content: 'Dots AI Platform runtime architecture and memory wiring',
    status: 'ACTIVE'
  });

  // Verify job is enqueued in SQLite embedding_jobs table with exact model identity
  const jobs = runtime.embeddingJobRepo.listJobs({ memoryId: memory.id });
  assert.equal(jobs.length, 1);
  assert.equal(jobs[0].status, 'PENDING');
  assert.equal(jobs[0].modelId, 'model-durable-1');
  assert.equal(jobs[0].modelRevision, 'rev-durable-1');
  assert.equal(jobs[0].scopeType, 'WORKSPACE');
  assert.equal(jobs[0].scopeId, 'ws-runtime');
});

test('7. Lifecycle Worker: runtime.start() recovers and processes durable jobs', async () => {
  const runtime = new DotsRuntime({
    dbPath: ':memory:',
    tokens: TEST_TOKENS,
    embeddingProvider: 'mock',
    embeddingModelId: 'model-proc-1',
    embeddingModelRevision: 'rev-proc-1',
    embeddingPollIntervalMs: 20,
    silentLogs: true
  });

  const caller = getCaller(runtime);

  // Create memory before start
  const memory = runtime.memoryService.createMemory(caller, {
    category: 'PROJECT_FACT',
    scopeType: caller.scope.scopeType,
    scopeId: caller.scope.scopeId,
    key: 'worker.fact',
    content: 'Autonomous worker processing verified embedding jobs',
    status: 'ACTIVE'
  });

  // Start runtime
  await runtime.start();
  assert.equal(runtime.lifecycleManager?.active, true);
  assert.equal(runtime.getHealth().embeddingWorkerActive, true);

  // Calling start again is idempotent
  await runtime.start();
  assert.equal(runtime.lifecycleManager?.active, true);

  // Wait for background worker to process job
  let attempts = 0;
  while (attempts < 50) {
    const embedding = runtime.embeddingRepo.getEmbedding(
      memory.id,
      'model-proc-1',
      'rev-proc-1'
    );
    if (embedding) {
      break;
    }
    await new Promise((r) => setTimeout(r, 20));
    attempts++;
  }

  // Vector is persisted
  const embedding = runtime.embeddingRepo.getEmbedding(
    memory.id,
    'model-proc-1',
    'rev-proc-1'
  );
  assert.ok(embedding);
  assert.equal(embedding.dimensions, 384);

  // Job is marked COMPLETED
  const completedJobs = runtime.embeddingJobRepo.listJobs({ memoryId: memory.id, status: 'COMPLETED' });
  assert.equal(completedJobs.length, 1);

  await runtime.stop();
});

test('8. Hybrid Retrieval: Integrated search uses semantic vector similarity in runtime', async () => {
  const mockProvider = new DeterministicMockEmbeddingProvider({
    modelId: 'model-hybrid-rt',
    modelRevision: 'main'
  });

  // Register predefined vector with high semantic similarity
  const targetVector = new Float32Array(384).fill(0);
  targetVector[0] = 1.0; // unit vector along dim 0
  mockProvider.registerPredefinedVector('auth.fact: Authentication and authorization policies', targetVector);
  mockProvider.registerPredefinedVector('security guidelines', targetVector);

  const runtime = new DotsRuntime({
    dbPath: ':memory:',
    tokens: TEST_TOKENS,
    embeddingProvider: mockProvider,
    silentLogs: true
  });

  const caller = getCaller(runtime);

  // Create active memory
  const memory = runtime.memoryService.createMemory(caller, {
    category: 'PROJECT_FACT',
    scopeType: caller.scope.scopeType,
    scopeId: caller.scope.scopeId,
    key: 'auth.fact',
    content: 'Authentication and authorization policies',
    status: 'ACTIVE'
  });

  // Process embedding job
  await runtime.lifecycleManager?.processPendingJobs();

  // Execute search via runtime.memoryService
  const results = await runtime.memoryService.searchMemories(caller, {
    query: 'security guidelines'
  });

  assert.equal(results.length, 1);
  assert.equal(results[0].memory.id, memory.id);
  // Provenance is HYBRID or SEMANTIC_ONLY
  assert.ok(results[0].provenance === 'HYBRID' || results[0].provenance === 'SEMANTIC_ONLY');
  assert.ok(results[0].score > 0);
  assert.equal(results[0].cosineSimilarity, 1.0);

  await runtime.stop();
});

test('9. Safe Shutdown: Drains in-flight operations and protects SQLite from premature closure', async () => {
  const runtime = new DotsRuntime({
    dbPath: ':memory:',
    tokens: TEST_TOKENS,
    embeddingProvider: 'mock',
    embeddingPollIntervalMs: 50,
    silentLogs: true
  });

  await runtime.start();
  assert.equal(runtime.lifecycleManager?.active, true);

  // Stop runtime cleanly
  await runtime.stop();

  assert.equal(runtime.lifecycleManager?.active, false);
  assert.equal(runtime.db.isOpen, false);
});

test('10. Safe Shutdown: When in-flight operation exceeds stop timeout, stop() awaits completion before db.close()', async () => {
  let finishInference!: () => void;
  const inferenceBlocker = new Promise<void>((resolve) => {
    finishInference = resolve;
  });

  class SlowEmbeddingProvider extends DeterministicMockEmbeddingProvider {
    public override async embed(text: string): Promise<Float32Array> {
      await inferenceBlocker;
      return super.embed(text);
    }
  }

  const slowProvider = new SlowEmbeddingProvider({
    modelId: 'slow-model',
    modelRevision: 'main'
  });

  const runtime = new DotsRuntime({
    dbPath: ':memory:',
    tokens: TEST_TOKENS,
    embeddingProvider: slowProvider,
    silentLogs: true
  });

  const caller = getCaller(runtime);
  runtime.memoryService.createMemory(caller, {
    category: 'PROJECT_FACT',
    scopeType: caller.scope.scopeType,
    scopeId: caller.scope.scopeId,
    key: 'slow.mem',
    content: 'Memory being embedded very slowly during shutdown',
    status: 'ACTIVE'
  });

  // Trigger one job processing in the background
  const processPromise = runtime.lifecycleManager?.processNextJob();

  // Verify in-flight work is active
  await new Promise((r) => setTimeout(r, 20));
  assert.equal(runtime.lifecycleManager?.hasInFlightWork, true);

  // Initiate runtime stop with a short timeout
  let dbClosedPrematurely = false;
  const stopPromise = (async () => {
    // Override lifecycleManager.stop with a tiny 10ms timeout to simulate timeout expiration
    const origStop = runtime.lifecycleManager!.stop.bind(runtime.lifecycleManager!);
    runtime.lifecycleManager!.stop = async () => origStop(10);
    await runtime.stop();
  })();

  // While stop is waiting for the worker to drain, release inference
  await new Promise((r) => setTimeout(r, 50));
  // DB should NOT be closed yet because in-flight work hasn't finished!
  if (!runtime.db.isOpen) {
    dbClosedPrematurely = true;
  }

  finishInference();
  await processPromise;
  await stopPromise;

  assert.equal(dbClosedPrematurely, false, 'Database must not be closed while in-flight worker is active');
  assert.equal(runtime.db.isOpen, false, 'Database closed cleanly after worker drain');
});

test('11. None Mode: Functions normally in lexical-only mode without worker', async () => {
  const runtime = new DotsRuntime({
    dbPath: ':memory:',
    tokens: TEST_TOKENS,
    embeddingProvider: 'none',
    silentLogs: true
  });

  assert.equal(runtime.embeddingProvider, null);
  assert.equal(runtime.lifecycleManager, null);
  assert.equal(runtime.getHealth().embeddingEnabled, false);
  assert.equal(runtime.getHealth().embeddingWorkerActive, false);

  const caller = getCaller(runtime);

  // Create active memory
  const memory = runtime.memoryService.createMemory(caller, {
    category: 'PROJECT_FACT',
    scopeType: caller.scope.scopeType,
    scopeId: caller.scope.scopeId,
    key: 'lexical.mem',
    content: 'Strictly lexical memory retrieval without embeddings',
    status: 'ACTIVE'
  });

  await runtime.start();

  // Lexical search works immediately
  const results = await runtime.memoryService.searchMemories(caller, {
    query: 'lexical memory retrieval'
  });

  assert.equal(results.length, 1);
  assert.equal(results[0].memory.id, memory.id);
  assert.equal(results[0].provenance, 'LEXICAL_ONLY');

  await runtime.stop();
  assert.equal(runtime.db.isOpen, false);
});
