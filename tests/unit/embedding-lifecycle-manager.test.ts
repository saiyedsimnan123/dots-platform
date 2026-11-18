/**
 * Next-Generation Dots AI Platform - Embedding Lifecycle Manager Tests
 * Phase 4C.6B: Durable Asynchronous Embedding Lifecycle Manager
 * 
 * Verifies all 18 requirements from the Phase 4C.6B specification:
 * 1. Active memory creation enqueues a job.
 * 2. Agent proposals do not enqueue jobs.
 * 3. Content updates enqueue replacement jobs.
 * 4. Metadata-only updates do not enqueue jobs.
 * 5. Human approval enqueues a job.
 * 6. Proposal rejection does not enqueue jobs.
 * 7. Job enqueueing is idempotent.
 * 8. Pending jobs survive runtime restart.
 * 9. Interrupted RUNNING jobs recover safely.
 * 10. Only one worker processes jobs at a time.
 * 11. Stale content results are discarded.
 * 12. Deleted or archived memories are skipped.
 * 13. Provider failures trigger bounded retry.
 * 14. Retry exhaustion marks jobs terminally failed.
 * 15. Forged scope and cross-workspace jobs cannot generate embeddings.
 * 16. Global memory ownership restrictions remain intact.
 * 17. Shutdown prevents new job claims.
 * 18. End-to-end asynchronous processing and existing compatibility.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseManager } from '../../src/storage/db.ts';
import { MemoryRepository } from '../../src/storage/memory-repository.ts';
import { MemoryEmbeddingRepository } from '../../src/storage/memory-embedding-repository.ts';
import { EmbeddingJobRepository } from '../../src/storage/embedding-job-repository.ts';
import { EmbeddingLifecycleManager } from '../../src/memory/embedding-lifecycle-manager.ts';
import { MemoryService } from '../../src/memory/memory-service.ts';
import { TaskRepository } from '../../src/storage/task-repository.ts';
import { AuditRepository } from '../../src/storage/audit-repository.ts';
import { RelevanceMatcher } from '../../src/memory/relevance-matcher.ts';
import { MemoryContextBuilder } from '../../src/memory/context-builder.ts';
import { HostMemoryAuthority } from '../../src/security/host-authority.ts';
import type { TrustedIdentityProvider, AuthenticatedPrincipal } from '../../src/security/memory-authorizer.ts';
import { DeterministicMockEmbeddingProvider } from '../../src/memory/mock-embedding-provider.ts';
import type { IEmbeddingProvider } from '../../src/memory/embedding-types.ts';
import type { ScopeIdentifier } from '../../src/domain/types.ts';

function setupTestEnvironment() {
  const db = new DatabaseManager(':memory:');
  const taskRepo = new TaskRepository(db);
  const auditRepo = new AuditRepository(db);
  const memoryRepo = new MemoryRepository(db);
  const embeddingRepo = new MemoryEmbeddingRepository(db);
  const embeddingJobRepo = new EmbeddingJobRepository(db);
  const mockProvider = new DeterministicMockEmbeddingProvider({ dimensions: 384 });

  const workspaceA: ScopeIdentifier = { scopeType: 'WORKSPACE', scopeId: 'ws-alpha' };
  const workspaceB: ScopeIdentifier = { scopeType: 'WORKSPACE', scopeId: 'ws-beta' };
  const globalScope: ScopeIdentifier = { scopeType: 'GLOBAL', scopeId: 'default' };

  const identityProvider: TrustedIdentityProvider = {
    authenticate(credentials: unknown): AuthenticatedPrincipal | null {
      if (typeof credentials !== 'string') return null;
      if (credentials === 'token-admin-alpha') {
        return {
          principalId: 'user-alpha',
          role: 'ADMIN',
          permittedScopes: [workspaceA]
        };
      }
      if (credentials === 'token-admin-beta') {
        return {
          principalId: 'user-beta',
          role: 'ADMIN',
          permittedScopes: [workspaceB]
        };
      }
      if (credentials === 'token-global-admin') {
        return {
          principalId: 'user-global-admin',
          role: 'ADMIN',
          permittedScopes: [globalScope, workspaceA, workspaceB]
        };
      }
      return null;
    }
  };

  const hostAuthority = new HostMemoryAuthority({
    taskRepo,
    identityProvider
  });
  const authorizer = hostAuthority.authorizer;

  const relevanceMatcher = new RelevanceMatcher();
  const contextBuilder = new MemoryContextBuilder({ matcher: relevanceMatcher });

  const lifecycleManager = new EmbeddingLifecycleManager({
    db,
    jobRepo: embeddingJobRepo,
    memoryRepo,
    embeddingRepo,
    provider: mockProvider,
    auditRepo,
    pollIntervalMs: 100,
    baseRetryDelayMs: 50,
    maxRetryDelayMs: 500,
    maxAttempts: 3,
    autoStart: false
  });

  const memoryService = new MemoryService({
    memoryRepo,
    embeddingRepo,
    embeddingProvider: mockProvider,
    embeddingJobRepo,
    lifecycleManager,
    auditRepo,
    taskRepo,
    authorizer,
    hostAuthority,
    relevanceMatcher,
    contextBuilder
  });

  return {
    db,
    taskRepo,
    auditRepo,
    memoryRepo,
    embeddingRepo,
    embeddingJobRepo,
    lifecycleManager,
    mockProvider,
    memoryService,
    hostAuthority,
    authorizer,
    workspaceA,
    workspaceB,
    globalScope
  };
}

test('1. Active memory creation enqueues an embedding job', () => {
  const env = setupTestEnvironment();
  const caller = env.authorizer.authorizeUser({
    credentials: 'token-admin-alpha',
    requestedScope: env.workspaceA
  });

  const memory = env.memoryService.createMemory(caller, {
    category: 'PROJECT_FACT',
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    key: 'project.name',
    content: 'Project Apollo Architecture',
    status: 'ACTIVE'
  });

  const jobs = env.embeddingJobRepo.listJobs({ memoryId: memory.id });
  assert.equal(jobs.length, 1);
  assert.equal(jobs[0].memoryId, memory.id);
  assert.equal(jobs[0].status, 'PENDING');
  assert.equal(jobs[0].scopeType, env.workspaceA.scopeType);
  assert.equal(jobs[0].scopeId, env.workspaceA.scopeId);
  assert.equal(jobs[0].modelId, env.mockProvider.modelId);
  assert.equal(jobs[0].attemptCount, 0);
});

test('2. Agent proposals do not enqueue jobs', () => {
  const env = setupTestEnvironment();
  const task = env.hostAuthority.createTask(env.taskRepo, {
    goal: 'Research task',
    scope: env.workspaceA
  });

  const agentCaller = env.authorizer.authorizeAgent({
    taskId: task.id
  });

  const proposal = env.memoryService.createMemory(agentCaller, {
    category: 'PROJECT_FACT',
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    key: 'agent.discovered.fact',
    content: 'Agent unverified hypothesis'
  });

  assert.equal(proposal.status, 'PENDING_APPROVAL');

  const jobs = env.embeddingJobRepo.listJobs({ memoryId: proposal.id });
  assert.equal(jobs.length, 0, 'PENDING_APPROVAL proposals must not enqueue embedding jobs');
});

test('3. Content updates enqueue replacement jobs', () => {
  const env = setupTestEnvironment();
  const caller = env.authorizer.authorizeUser({
    credentials: 'token-admin-alpha',
    requestedScope: env.workspaceA
  });

  const memory = env.memoryService.createMemory(caller, {
    category: 'PROJECT_FACT',
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    key: 'project.plan',
    content: 'Initial project plan v1',
    status: 'ACTIVE'
  });

  // Clear initial job to isolate update behavior
  env.embeddingJobRepo.markJobCompleted(env.embeddingJobRepo.listJobs({ memoryId: memory.id })[0].id);

  // Update content
  env.memoryService.updateMemory(caller, memory.id, {
    content: 'Updated project plan v2 with new requirements'
  });

  const pendingJobs = env.embeddingJobRepo.listJobs({ memoryId: memory.id, status: 'PENDING' });
  assert.equal(pendingJobs.length, 1, 'Content update must enqueue a replacement pending job');
  assert.equal(pendingJobs[0].attemptCount, 0);
});

test('4. Metadata-only updates do not enqueue jobs', () => {
  const env = setupTestEnvironment();
  const caller = env.authorizer.authorizeUser({
    credentials: 'token-admin-alpha',
    requestedScope: env.workspaceA
  });

  const memory = env.memoryService.createMemory(caller, {
    category: 'PROJECT_FACT',
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    key: 'config.setting',
    content: 'Immutable content string',
    status: 'ACTIVE',
    priority: 5,
    tags: ['initial']
  });

  // Mark initial job completed
  const initialJob = env.embeddingJobRepo.listJobs({ memoryId: memory.id })[0];
  env.embeddingJobRepo.markJobCompleted(initialJob.id);

  // Update priority and tags only (no content change)
  env.memoryService.updateMemory(caller, memory.id, {
    priority: 10,
    tags: ['initial', 'updated']
  });

  const pendingJobs = env.embeddingJobRepo.listJobs({ memoryId: memory.id, status: 'PENDING' });
  assert.equal(pendingJobs.length, 0, 'Metadata/priority/tag updates must NOT enqueue embedding jobs');
});

test('5. Human approval enqueues a job', () => {
  const env = setupTestEnvironment();
  const task = env.hostAuthority.createTask(env.taskRepo, {
    goal: 'Research proposal task',
    scope: env.workspaceA
  });

  const agentCaller = env.authorizer.authorizeAgent({
    taskId: task.id
  });

  const proposal = env.memoryService.createMemory(agentCaller, {
    category: 'PROJECT_FACT',
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    key: 'proposal.candidate',
    content: 'Proposed fact awaiting human review'
  });

  assert.equal(env.embeddingJobRepo.countJobs({ memoryId: proposal.id }), 0);

  const humanCaller = env.authorizer.authorizeUser({
    credentials: 'token-admin-alpha',
    requestedScope: env.workspaceA
  });

  // Human approves proposal
  env.memoryService.decideProposal(humanCaller, {
    memoryId: proposal.id,
    decision: 'APPROVED'
  });

  const jobs = env.embeddingJobRepo.listJobs({ memoryId: proposal.id, status: 'PENDING' });
  assert.equal(jobs.length, 1, 'Approving proposal must enqueue an embedding job');
  assert.equal(jobs[0].status, 'PENDING');
});

test('6. Proposal rejection does not enqueue jobs', () => {
  const env = setupTestEnvironment();
  const task = env.hostAuthority.createTask(env.taskRepo, {
    goal: 'Research rejection task',
    scope: env.workspaceA
  });

  const agentCaller = env.authorizer.authorizeAgent({
    taskId: task.id
  });

  const proposal = env.memoryService.createMemory(agentCaller, {
    category: 'PROJECT_FACT',
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    key: 'proposal.reject.me',
    content: 'Proposed fact that will be rejected'
  });

  const humanCaller = env.authorizer.authorizeUser({
    credentials: 'token-admin-alpha',
    requestedScope: env.workspaceA
  });

  // Human rejects proposal
  env.memoryService.decideProposal(humanCaller, {
    memoryId: proposal.id,
    decision: 'REJECTED'
  });

  const jobs = env.embeddingJobRepo.listJobs({ memoryId: proposal.id });
  assert.equal(jobs.length, 0, 'Rejecting proposal must NEVER enqueue an embedding job');
});

test('7. Job enqueueing is idempotent', () => {
  const env = setupTestEnvironment();

  const mem = env.memoryRepo.createMemory({
    category: 'PROJECT_FACT',
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    key: 'idempotent.fact',
    content: 'Idempotent content',
    status: 'ACTIVE'
  });

  // Enqueue 3 times
  const job1 = env.embeddingJobRepo.enqueueJob({
    memoryId: mem.id,
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    modelId: env.mockProvider.modelId
  });

  const job2 = env.embeddingJobRepo.enqueueJob({
    memoryId: mem.id,
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    modelId: env.mockProvider.modelId
  });

  const job3 = env.embeddingJobRepo.enqueueJob({
    memoryId: mem.id,
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    modelId: env.mockProvider.modelId
  });

  assert.equal(job1.id, job2.id);
  assert.equal(job2.id, job3.id);

  const pendingJobs = env.embeddingJobRepo.listJobs({ memoryId: mem.id, status: 'PENDING' });
  assert.equal(pendingJobs.length, 1, 'Only one PENDING job must exist for the same (memoryId, modelId, modelRevision)');
});

test('8. Pending jobs survive runtime restart', () => {
  const env = setupTestEnvironment();

  const mem = env.memoryRepo.createMemory({
    category: 'PROJECT_FACT',
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    key: 'restart.fact',
    content: 'Survives restart',
    status: 'ACTIVE'
  });

  const enqueued = env.embeddingJobRepo.enqueueJob({
    memoryId: mem.id,
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    modelId: env.mockProvider.modelId
  });

  // Re-instantiate repository using the exact same underlying DB instance
  const rebootedJobRepo = new EmbeddingJobRepository(env.db);
  const retrieved = rebootedJobRepo.getJobById(enqueued.id);

  assert.ok(retrieved);
  assert.equal(retrieved.id, enqueued.id);
  assert.equal(retrieved.status, 'PENDING');
});

test('9. Interrupted RUNNING jobs recover safely', () => {
  const env = setupTestEnvironment();

  const mem = env.memoryRepo.createMemory({
    category: 'PROJECT_FACT',
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    key: 'interrupted.fact',
    content: 'Interrupted during previous crash',
    status: 'ACTIVE'
  });

  const job = env.embeddingJobRepo.enqueueJob({
    memoryId: mem.id,
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    modelId: env.mockProvider.modelId
  });

  // Claim job to transition it to RUNNING
  const claimed = env.embeddingJobRepo.claimNextJob();
  assert.ok(claimed);
  assert.equal(claimed.status, 'RUNNING');

  // Simulate recovery on startup
  const recovered = env.embeddingJobRepo.recoverInterruptedJobs();
  assert.equal(recovered.length, 1);
  assert.equal(recovered[0].id, job.id);
  assert.equal(recovered[0].status, 'PENDING');
  assert.equal(recovered[0].attemptCount, 1);
  assert.match(recovered[0].lastError ?? '', /interrupted/i);
});

test('10. Only one worker processes jobs at a time (concurrency = 1)', async () => {
  const env = setupTestEnvironment();

  const mem1 = env.memoryRepo.createMemory({
    category: 'PROJECT_FACT',
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    key: 'concurrency.1',
    content: 'Content 1',
    status: 'ACTIVE'
  });

  const mem2 = env.memoryRepo.createMemory({
    category: 'PROJECT_FACT',
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    key: 'concurrency.2',
    content: 'Content 2',
    status: 'ACTIVE'
  });

  env.embeddingJobRepo.enqueueJob({
    memoryId: mem1.id,
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    modelId: env.mockProvider.modelId
  });

  env.embeddingJobRepo.enqueueJob({
    memoryId: mem2.id,
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    modelId: env.mockProvider.modelId
  });

  // First claim succeeds
  const jobA = env.embeddingJobRepo.claimNextJob();
  assert.ok(jobA);
  assert.equal(jobA.status, 'RUNNING');

  // Second claim must return null while a job is RUNNING
  const jobB = env.embeddingJobRepo.claimNextJob();
  assert.equal(jobB, null, 'Cannot claim another job while one is currently RUNNING');

  // Complete jobA
  env.embeddingJobRepo.markJobCompleted(jobA.id);

  // Now claim succeeds
  const jobC = env.embeddingJobRepo.claimNextJob();
  assert.ok(jobC);
  assert.equal(jobC.status, 'RUNNING');
});

test('11. Stale content results are discarded without corrupting database', async () => {
  const env = setupTestEnvironment();

  const mem = env.memoryRepo.createMemory({
    category: 'PROJECT_FACT',
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    key: 'stale.detection.fact',
    content: 'Initial content v1',
    status: 'ACTIVE'
  });

  env.embeddingJobRepo.enqueueJob({
    memoryId: mem.id,
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    modelId: 'mutating-provider-model'
  });

  // Provider that mutates the memory in DB while embed() is executing
  const mutatingProvider: IEmbeddingProvider = {
    name: 'mutating-provider',
    modelId: 'mutating-provider-model',
    dimensions: 384,
    async isAvailable() { return true; },
    async embed() {
      // Simulate concurrent edit during inference
      env.memoryRepo.updateMemory(mem.id, env.workspaceA, {
        content: 'Modified content v2 while inference was running'
      });
      const v = new Float32Array(384);
      v[0] = 1.0;
      return v;
    },
    async embedBatch(texts) { return texts.map(() => new Float32Array(384)); }
  };

  const manager = new EmbeddingLifecycleManager({
    db: env.db,
    jobRepo: env.embeddingJobRepo,
    memoryRepo: env.memoryRepo,
    embeddingRepo: env.embeddingRepo,
    provider: mutatingProvider
  });

  const processed = await manager.processNextJob();
  assert.equal(processed, true);

  // Stale vector must NOT have been saved
  const stored = env.embeddingRepo.getEmbedding(mem.id, mutatingProvider.modelId);
  assert.equal(stored, null, 'Stale embedding must not be written to database');
});

test('12. Deleted or archived memories are skipped', async () => {
  const env = setupTestEnvironment();

  // Test Case A: Archived memory is skipped
  const memArchived = env.memoryRepo.createMemory({
    category: 'PROJECT_FACT',
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    key: 'will.be.archived',
    content: 'Archive me',
    status: 'ACTIVE'
  });

  const jobArchived = env.embeddingJobRepo.enqueueJob({
    memoryId: memArchived.id,
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    modelId: env.mockProvider.modelId
  });

  // Archive memory before worker runs
  env.memoryRepo.archiveMemory(memArchived.id, env.workspaceA);

  const processedArchived = await env.lifecycleManager.processNextJob();
  assert.equal(processedArchived, true);

  const completedJob = env.embeddingJobRepo.getJobById(jobArchived.id);
  assert.equal(completedJob?.status, 'COMPLETED');
  assert.equal(env.embeddingRepo.getEmbedding(memArchived.id, env.mockProvider.modelId), null);

  // Test Case B: Memory deleted during inference is discarded
  const memDeleted = env.memoryRepo.createMemory({
    category: 'PROJECT_FACT',
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    key: 'deleted.during.inference',
    content: 'Delete me during inference',
    status: 'ACTIVE'
  });

  const deletingProvider: IEmbeddingProvider = {
    name: 'deleting-provider',
    modelId: 'deleting-model',
    dimensions: 384,
    async isAvailable() { return true; },
    async embed() {
      // Simulate memory deleted during inference
      env.memoryRepo.deleteMemory(memDeleted.id, env.workspaceA);
      const v = new Float32Array(384);
      v[0] = 1.0;
      return v;
    },
    async embedBatch(texts) { return texts.map(() => new Float32Array(384)); }
  };

  const deletingManager = new EmbeddingLifecycleManager({
    db: env.db,
    jobRepo: env.embeddingJobRepo,
    memoryRepo: env.memoryRepo,
    embeddingRepo: env.embeddingRepo,
    provider: deletingProvider
  });

  const jobDeleted = env.embeddingJobRepo.enqueueJob({
    memoryId: memDeleted.id,
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    modelId: deletingProvider.modelId
  });

  const processedDeleted = await deletingManager.processNextJob();
  assert.equal(processedDeleted, true);
  assert.equal(env.embeddingRepo.getEmbedding(memDeleted.id, deletingProvider.modelId), null);
});

test('13. Provider failures trigger bounded retry with backoff', async () => {
  const env = setupTestEnvironment();

  const mem = env.memoryRepo.createMemory({
    category: 'PROJECT_FACT',
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    key: 'retry.fact',
    content: 'Retry content',
    status: 'ACTIVE'
  });

  const failingProvider: IEmbeddingProvider = {
    name: 'failing-provider',
    modelId: 'failing-model',
    dimensions: 384,
    async isAvailable() { return true; },
    async embed() { throw new Error('Temporary inference glitch'); },
    async embedBatch() { throw new Error('Temporary inference glitch'); }
  };

  const manager = new EmbeddingLifecycleManager({
    db: env.db,
    jobRepo: env.embeddingJobRepo,
    memoryRepo: env.memoryRepo,
    embeddingRepo: env.embeddingRepo,
    provider: failingProvider,
    baseRetryDelayMs: 200,
    maxAttempts: 3
  });

  const job = env.embeddingJobRepo.enqueueJob({
    memoryId: mem.id,
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    modelId: failingProvider.modelId,
    maxAttempts: 3
  });

  await manager.processNextJob();

  const retried = env.embeddingJobRepo.getJobById(job.id);
  assert.ok(retried);
  assert.equal(retried.status, 'PENDING');
  assert.equal(retried.attemptCount, 1);
  assert.match(retried.lastError ?? '', /Temporary inference glitch/);
  // Verify scheduled_at was pushed to future
  assert.ok(retried.scheduledAt > retried.createdAt);
});

test('14. Retry exhaustion marks jobs terminally failed', async () => {
  const env = setupTestEnvironment();

  const mem = env.memoryRepo.createMemory({
    category: 'PROJECT_FACT',
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    key: 'exhaust.fact',
    content: 'Exhaust attempts',
    status: 'ACTIVE'
  });

  const failingProvider: IEmbeddingProvider = {
    name: 'failing-provider',
    modelId: 'failing-model-terminal',
    dimensions: 384,
    async isAvailable() { return true; },
    async embed() { throw new Error('Permanent model crash'); },
    async embedBatch() { throw new Error('Permanent model crash'); }
  };

  const manager = new EmbeddingLifecycleManager({
    db: env.db,
    jobRepo: env.embeddingJobRepo,
    memoryRepo: env.memoryRepo,
    embeddingRepo: env.embeddingRepo,
    provider: failingProvider,
    baseRetryDelayMs: 0,
    maxAttempts: 2
  });

  const job = env.embeddingJobRepo.enqueueJob({
    memoryId: mem.id,
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    modelId: failingProvider.modelId,
    maxAttempts: 2
  });

  // Attempt 1: reschedules
  await manager.processNextJob();
  const jobAttempt1 = env.embeddingJobRepo.getJobById(job.id);
  assert.equal(jobAttempt1?.status, 'PENDING');
  assert.equal(jobAttempt1?.attemptCount, 1);

  // Attempt 2: exhausts retry budget
  await manager.processNextJob(new Date(Date.now() + 10000).toISOString());
  const jobAttempt2 = env.embeddingJobRepo.getJobById(job.id);
  assert.equal(jobAttempt2?.status, 'FAILED');
  assert.equal(jobAttempt2?.attemptCount, 2);
  assert.match(jobAttempt2?.lastError ?? '', /exhausted attempts/i);
});

test('15. Forged scope and cross-workspace jobs cannot generate embeddings', async () => {
  const env = setupTestEnvironment();

  // Create memory in workspace B
  const memBeta = env.memoryRepo.createMemory({
    category: 'PROJECT_FACT',
    scopeType: env.workspaceB.scopeType,
    scopeId: env.workspaceB.scopeId,
    key: 'beta.secret',
    content: 'Confidential beta content',
    status: 'ACTIVE'
  });

  // Inject a forged job asserting scope is workspace A for memory in workspace B
  const forgedJob = env.embeddingJobRepo.enqueueJob({
    memoryId: memBeta.id,
    scopeType: env.workspaceA.scopeType, // Forged!
    scopeId: env.workspaceA.scopeId,
    modelId: env.mockProvider.modelId
  });

  await env.lifecycleManager.processNextJob();

  const failedJob = env.embeddingJobRepo.getJobById(forgedJob.id);
  assert.equal(failedJob?.status, 'FAILED');
  assert.match(failedJob?.lastError ?? '', /MemoryScopeViolation/i);

  // Assert NO embedding was written under workspace A or for the memory
  assert.equal(env.embeddingRepo.getEmbedding(memBeta.id, env.mockProvider.modelId), null);
});

test('16. Global memory ownership restrictions remain intact', async () => {
  const env = setupTestEnvironment();

  // Create global memory
  const globalMem = env.memoryRepo.createMemory({
    category: 'LEARNED_PROCEDURE',
    scopeType: env.globalScope.scopeType,
    scopeId: env.globalScope.scopeId,
    key: 'global.rule',
    content: 'Global platform protocol',
    status: 'ACTIVE'
  });

  // Attempt to process with forged WORKSPACE scope
  const forgedJob = env.embeddingJobRepo.enqueueJob({
    memoryId: globalMem.id,
    scopeType: 'WORKSPACE',
    scopeId: 'ws-alpha',
    modelId: env.mockProvider.modelId
  });

  await env.lifecycleManager.processNextJob();

  const failedJob = env.embeddingJobRepo.getJobById(forgedJob.id);
  assert.equal(failedJob?.status, 'FAILED');

  // Now process with legitimate GLOBAL scope
  const legitimateJob = env.embeddingJobRepo.enqueueJob({
    memoryId: globalMem.id,
    scopeType: 'GLOBAL',
    scopeId: 'default',
    modelId: env.mockProvider.modelId
  });

  await env.lifecycleManager.processNextJob();

  const completedJob = env.embeddingJobRepo.getJobById(legitimateJob.id);
  assert.equal(completedJob?.status, 'COMPLETED');

  const storedEmbedding = env.embeddingRepo.getEmbedding(globalMem.id, env.mockProvider.modelId);
  assert.ok(storedEmbedding);
});

test('17. Worker shutdown prevents new job claims', async () => {
  const env = setupTestEnvironment();

  const mem = env.memoryRepo.createMemory({
    category: 'PROJECT_FACT',
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    key: 'shutdown.test',
    content: 'Shutdown content',
    status: 'ACTIVE'
  });

  env.embeddingJobRepo.enqueueJob({
    memoryId: mem.id,
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    modelId: env.mockProvider.modelId
  });

  await env.lifecycleManager.start();
  assert.equal(env.lifecycleManager.active, true);

  await env.lifecycleManager.stop();
  assert.equal(env.lifecycleManager.active, false);

  // Calling processNextJob after stop returns false
  const processed = await env.lifecycleManager.processNextJob();
  assert.equal(processed, false);
});

test('18. End-to-end asynchronous processing creates queryable vector embeddings', async () => {
  const env = setupTestEnvironment();
  const caller = env.authorizer.authorizeUser({
    credentials: 'token-admin-alpha',
    requestedScope: env.workspaceA
  });

  // Create active memory
  const memory = env.memoryService.createMemory(caller, {
    category: 'PROJECT_FACT',
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    key: 'e2e.fact',
    content: 'Full end-to-end asynchronous embedding reconciliation',
    status: 'ACTIVE'
  });

  // Verify job was enqueued
  assert.equal(env.embeddingJobRepo.countJobs({ memoryId: memory.id, status: 'PENDING' }), 1);

  // Process job
  const processedCount = await env.lifecycleManager.processPendingJobs();
  assert.equal(processedCount, 1);

  // Verify job is now COMPLETED
  const job = env.embeddingJobRepo.listJobs({ memoryId: memory.id })[0];
  assert.equal(job.status, 'COMPLETED');

  // Verify vector was persisted in SQLite and can be retrieved
  const embedding = env.embeddingRepo.getEmbedding(memory.id, env.mockProvider.modelId);
  assert.ok(embedding);
  assert.equal(embedding.memoryId, memory.id);
  assert.equal(embedding.dimensions, 384);
});

// ============================================================================
// Phase 4D.2B: Embedding Job Retention & Queue Maintenance Regression Tests
// ============================================================================

function createJobWithStatus(
  env: ReturnType<typeof setupTestEnvironment>,
  status: 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'CANCELLED',
  updatedAtIso: string | null | undefined,
  memoryKey = 'test.mem'
) {
  const mem = env.memoryRepo.createMemory({
    category: 'PROJECT_FACT',
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    key: `${memoryKey}.${Date.now()}.${Math.random().toString(36).slice(2, 6)}`,
    content: 'Memory content for queue maintenance testing',
    status: 'ACTIVE'
  });

  const job = env.embeddingJobRepo.enqueueJob({
    memoryId: mem.id,
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    modelId: env.mockProvider.modelId
  });

  if (status !== 'PENDING' || updatedAtIso !== undefined) {
    env.db.prepare('UPDATE embedding_jobs SET status = ?, updated_at = ? WHERE id = ?').run(
      status,
      updatedAtIso ?? null,
      job.id
    );
  }

  return env.embeddingJobRepo.getJobById(job.id)!;
}

test('19. Old COMPLETED jobs are deleted by queue maintenance', async () => {
  const env = setupTestEnvironment();
  const now = Date.now();
  const fifteenDaysAgoIso = new Date(now - 15 * 86_400_000).toISOString();

  const oldCompleted = createJobWithStatus(env, 'COMPLETED', fifteenDaysAgoIso, 'old.completed');
  assert.ok(env.embeddingJobRepo.getJobById(oldCompleted.id));

  const result = env.embeddingJobRepo.pruneTerminalJobs({
    olderThanMs: 14 * 86_400_000,
    now
  });

  assert.deepEqual(result, { completed: 1, failed: 0, cancelled: 0, total: 1 });
  assert.equal(env.embeddingJobRepo.getJobById(oldCompleted.id), null);
});

test('20. Old FAILED jobs are deleted by queue maintenance', async () => {
  const env = setupTestEnvironment();
  const now = Date.now();
  const twentyDaysAgoIso = new Date(now - 20 * 86_400_000).toISOString();

  const oldFailed = createJobWithStatus(env, 'FAILED', twentyDaysAgoIso, 'old.failed');
  assert.ok(env.embeddingJobRepo.getJobById(oldFailed.id));

  const result = env.embeddingJobRepo.pruneTerminalJobs({
    olderThanMs: 14 * 86_400_000,
    now
  });

  assert.deepEqual(result, { completed: 0, failed: 1, cancelled: 0, total: 1 });
  assert.equal(env.embeddingJobRepo.getJobById(oldFailed.id), null);
});

test('21. Old CANCELLED jobs are deleted by queue maintenance', async () => {
  const env = setupTestEnvironment();
  const now = Date.now();
  const sixteenDaysAgoIso = new Date(now - 16 * 86_400_000).toISOString();

  const oldCancelled = createJobWithStatus(env, 'CANCELLED', sixteenDaysAgoIso, 'old.cancelled');
  assert.ok(env.embeddingJobRepo.getJobById(oldCancelled.id));

  const result = env.embeddingJobRepo.pruneTerminalJobs({
    olderThanMs: 14 * 86_400_000,
    now
  });

  assert.deepEqual(result, { completed: 0, failed: 0, cancelled: 1, total: 1 });
  assert.equal(env.embeddingJobRepo.getJobById(oldCancelled.id), null);
});

test('22. Recent terminal jobs remain untouched', async () => {
  const env = setupTestEnvironment();
  const now = Date.now();
  const fiveDaysAgoIso = new Date(now - 5 * 86_400_000).toISOString();
  const oneDayAgoIso = new Date(now - 1 * 86_400_000).toISOString();
  const twoHoursAgoIso = new Date(now - 2 * 3600_000).toISOString();

  const recentCompleted = createJobWithStatus(env, 'COMPLETED', fiveDaysAgoIso, 'recent.completed');
  const recentFailed = createJobWithStatus(env, 'FAILED', oneDayAgoIso, 'recent.failed');
  const recentCancelled = createJobWithStatus(env, 'CANCELLED', twoHoursAgoIso, 'recent.cancelled');

  const result = env.embeddingJobRepo.pruneTerminalJobs({
    olderThanMs: 14 * 86_400_000,
    now
  });

  assert.deepEqual(result, { completed: 0, failed: 0, cancelled: 0, total: 0 });
  assert.ok(env.embeddingJobRepo.getJobById(recentCompleted.id));
  assert.ok(env.embeddingJobRepo.getJobById(recentFailed.id));
  assert.ok(env.embeddingJobRepo.getJobById(recentCancelled.id));
});

test('23. PENDING jobs remain regardless of age', async () => {
  const env = setupTestEnvironment();
  const now = Date.now();
  const hundredDaysAgoIso = new Date(now - 100 * 86_400_000).toISOString();

  const oldPending = createJobWithStatus(env, 'PENDING', hundredDaysAgoIso, 'old.pending');

  const result = env.embeddingJobRepo.pruneTerminalJobs({
    olderThanMs: 14 * 86_400_000,
    now
  });

  assert.deepEqual(result, { completed: 0, failed: 0, cancelled: 0, total: 0 });
  const retrieved = env.embeddingJobRepo.getJobById(oldPending.id);
  assert.ok(retrieved);
  assert.equal(retrieved.status, 'PENDING');
});

test('24. RUNNING jobs remain regardless of age', async () => {
  const env = setupTestEnvironment();
  const now = Date.now();
  const sixtyDaysAgoIso = new Date(now - 60 * 86_400_000).toISOString();

  const oldRunning = createJobWithStatus(env, 'RUNNING', sixtyDaysAgoIso, 'old.running');

  const result = env.embeddingJobRepo.pruneTerminalJobs({
    olderThanMs: 14 * 86_400_000,
    now
  });

  assert.deepEqual(result, { completed: 0, failed: 0, cancelled: 0, total: 0 });
  const retrieved = env.embeddingJobRepo.getJobById(oldRunning.id);
  assert.ok(retrieved);
  assert.equal(retrieved.status, 'RUNNING');
});

test('25. Missing or invalid terminal timestamps are not pruned', async () => {
  const env = setupTestEnvironment();
  const now = Date.now();

  const emptyTimestampJob = createJobWithStatus(env, 'COMPLETED', '', 'empty.ts');
  const whitespaceTimestampJob = createJobWithStatus(env, 'FAILED', '   ', 'whitespace.ts');
  const invalidTimestampJob = createJobWithStatus(env, 'CANCELLED', 'not-a-valid-date', 'invalid.ts');

  const result = env.embeddingJobRepo.pruneTerminalJobs({
    olderThanMs: 14 * 86_400_000,
    now
  });

  assert.deepEqual(result, { completed: 0, failed: 0, cancelled: 0, total: 0 });
  assert.ok(env.embeddingJobRepo.getJobById(emptyTimestampJob.id));
  assert.ok(env.embeddingJobRepo.getJobById(whitespaceTimestampJob.id));
  assert.ok(env.embeddingJobRepo.getJobById(invalidTimestampJob.id));
});

test('26. Deletion limit is respected (batch size constraint)', async () => {
  const env = setupTestEnvironment();
  const now = Date.now();
  const twentyDaysAgoIso = new Date(now - 20 * 86_400_000).toISOString();

  const jobIds: string[] = [];
  for (let i = 0; i < 10; i++) {
    const job = createJobWithStatus(env, 'COMPLETED', twentyDaysAgoIso, `batch.${i}`);
    jobIds.push(job.id);
  }

  const result = env.embeddingJobRepo.pruneTerminalJobs({
    limit: 3,
    olderThanMs: 14 * 86_400_000,
    now
  });

  assert.deepEqual(result, { completed: 3, failed: 0, cancelled: 0, total: 3 });
  const remainingCount = jobIds.filter((id) => env.embeddingJobRepo.getJobById(id) !== null).length;
  assert.equal(remainingCount, 7);
});

test('27. Multiple maintenance passes eventually remove eligible jobs', async () => {
  const env = setupTestEnvironment();
  const now = Date.now();
  const twentyDaysAgoIso = new Date(now - 20 * 86_400_000).toISOString();

  const manager = new EmbeddingLifecycleManager({
    db: env.db,
    jobRepo: env.embeddingJobRepo,
    memoryRepo: env.memoryRepo,
    embeddingRepo: env.embeddingRepo,
    provider: env.mockProvider,
    retentionMs: 14 * 86_400_000,
    maxPruneBatchSize: 3,
    autoStart: false
  });

  const jobIds: string[] = [];
  for (let i = 0; i < 7; i++) {
    const status = i % 3 === 0 ? 'COMPLETED' : i % 3 === 1 ? 'FAILED' : 'CANCELLED';
    const job = createJobWithStatus(env, status, twentyDaysAgoIso, `multi.${i}`);
    jobIds.push(job.id);
  }

  // Pass 1: prunes 3
  const pass1 = await manager.runMaintenance(now);
  assert.ok(pass1);
  assert.equal(pass1.total, 3);

  // Pass 2: prunes 3
  const pass2 = await manager.runMaintenance(now);
  assert.ok(pass2);
  assert.equal(pass2.total, 3);

  // Pass 3: prunes remaining 1
  const pass3 = await manager.runMaintenance(now);
  assert.ok(pass3);
  assert.equal(pass3.total, 1);

  // Pass 4: no more eligible jobs
  const pass4 = await manager.runMaintenance(now);
  assert.ok(pass4);
  assert.equal(pass4.total, 0);

  const remaining = jobIds.filter((id) => env.embeddingJobRepo.getJobById(id) !== null);
  assert.equal(remaining.length, 0);
});

test('28. Repeated passes are idempotent', async () => {
  const env = setupTestEnvironment();
  const now = Date.now();

  const firstPass = await env.lifecycleManager.runMaintenance(now);
  assert.deepEqual(firstPass, { completed: 0, failed: 0, cancelled: 0, total: 0 });

  const secondPass = await env.lifecycleManager.runMaintenance(now);
  assert.deepEqual(secondPass, { completed: 0, failed: 0, cancelled: 0, total: 0 });
});

test('29. Maintenance failure does not stop the embedding worker', async () => {
  const env = setupTestEnvironment();
  const loggedErrors: Array<Record<string, unknown> | undefined> = [];

  const manager = new EmbeddingLifecycleManager({
    db: env.db,
    jobRepo: env.embeddingJobRepo,
    memoryRepo: env.memoryRepo,
    embeddingRepo: env.embeddingRepo,
    provider: env.mockProvider,
    logger: {
      error: (_domain, _event, details) => {
        loggedErrors.push(details);
      }
    },
    autoStart: false
  });

  // Force jobRepo.pruneTerminalJobs to throw
  const originalPrune = env.embeddingJobRepo.pruneTerminalJobs.bind(env.embeddingJobRepo);
  (env.embeddingJobRepo as any).pruneTerminalJobs = () => {
    throw new Error('Simulated SQLite disk error during prune');
  };

  try {
    const result = await manager.runMaintenance();
    assert.equal(result, null);
    assert.equal(loggedErrors.length, 1);
    assert.ok(String(loggedErrors[0]?.error).includes('Simulated SQLite disk error'));

    // Worker remains functional: restore method and process pending job
    (env.embeddingJobRepo as any).pruneTerminalJobs = originalPrune;

    const mem = env.memoryRepo.createMemory({
      category: 'PROJECT_FACT',
      scopeType: env.workspaceA.scopeType,
      scopeId: env.workspaceA.scopeId,
      key: 'survive.failure',
      content: 'Memory created after maintenance failure',
      status: 'ACTIVE'
    });
    env.embeddingJobRepo.enqueueJob({
      memoryId: mem.id,
      scopeType: env.workspaceA.scopeType,
      scopeId: env.workspaceA.scopeId,
      modelId: env.mockProvider.modelId
    });

    const didProcess = await manager.processNextJob();
    assert.equal(didProcess, true);
  } finally {
    (env.embeddingJobRepo as any).pruneTerminalJobs = originalPrune;
  }
});

test('30. Startup and shutdown do not leak timers or race with database closure', async () => {
  const env = setupTestEnvironment();

  const manager = new EmbeddingLifecycleManager({
    db: env.db,
    jobRepo: env.embeddingJobRepo,
    memoryRepo: env.memoryRepo,
    embeddingRepo: env.embeddingRepo,
    provider: env.mockProvider,
    pollIntervalMs: 50,
    maintenanceIntervalMs: 1000,
    autoStart: false
  });

  await manager.start();
  assert.equal(manager.active, true);

  const stopped = await manager.stop(1000);
  assert.equal(stopped, true);
  assert.equal(manager.active, false);

  // Close database cleanly
  env.db.close();
  assert.equal(env.db.isOpen, false);

  // Wait 100ms to verify that unref'd or cleared timers do not fire or access closed database
  await new Promise((r) => setTimeout(r, 100));
});

test('31. Maintenance does not alter retry, recovery, or job-claim behavior', async () => {
  const env = setupTestEnvironment();
  const now = Date.now();
  const twentyDaysAgoIso = new Date(now - 20 * 86_400_000).toISOString();

  // Create terminal jobs older than retention
  createJobWithStatus(env, 'COMPLETED', twentyDaysAgoIso, 'old.comp');
  createJobWithStatus(env, 'FAILED', twentyDaysAgoIso, 'old.fail');

  // Create active pending job
  const pendingJob = createJobWithStatus(env, 'PENDING', undefined, 'active.pending');

  // Run maintenance pass
  const pruneResult = await env.lifecycleManager.runMaintenance(now);
  assert.ok(pruneResult);
  assert.equal(pruneResult.total, 2);

  // Claim next job: active pending job is claimed normally
  const claimTime = new Date(Date.now() + 1000).toISOString();
  const claimed = env.embeddingJobRepo.claimNextJob(claimTime, env.mockProvider.modelId);
  assert.ok(claimed);
  assert.equal(claimed.id, pendingJob.id);
  assert.equal(claimed.status, 'RUNNING');
});
