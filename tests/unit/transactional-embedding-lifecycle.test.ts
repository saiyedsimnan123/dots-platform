/**
 * Next-Generation Dots AI Platform - Transactional Embedding Lifecycle Tests
 * Phase 4C.6C: Transactional Embedding Lifecycle Consistency
 * 
 * Verifies all 13 requirements from the Phase 4C.6C specification:
 * 1. Memory creation and job insertion commit together.
 * 2. Job insertion failure rolls back the memory creation.
 * 3. Content update and job insertion commit together.
 * 4. Job insertion failure rolls back the content update.
 * 5. Proposal approval and job insertion commit together.
 * 6. Job insertion failure rolls back proposal approval.
 * 7. Archival removes existing embeddings.
 * 8. Archival cancels pending jobs.
 * 9. An in-flight job cannot recreate an archived memory's embedding.
 * 10. Cancelled jobs cannot be claimed or retried.
 * 11. Deleted memories still cascade correctly.
 * 12. Existing workspace/global authorization remains intact.
 * 13. Existing reconciliation and hybrid retrieval behavior remains intact.
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
import { SecurityViolationError, MemoryScopeViolationError } from '../../src/domain/errors.ts';

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
    authorizer,
    hostAuthority,
    memoryService,
    workspaceA,
    workspaceB,
    globalScope
  };
}

test('1. Memory creation and job insertion commit together', () => {
  const env = setupTestEnvironment();
  const caller = env.authorizer.authorizeUser({
    credentials: 'token-admin-alpha',
    requestedScope: env.workspaceA
  });

  const mem = env.memoryService.createMemory(caller, {
    category: 'PROJECT_FACT',
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    key: 'project.name',
    content: 'Dots AI Platform'
  });

  // Verify memory exists in database
  const storedMem = env.memoryRepo.getMemoryById(mem.id, env.workspaceA);
  assert.ok(storedMem);
  assert.equal(storedMem.key, 'project.name');

  // Verify job exists in database with status PENDING
  const jobs = env.embeddingJobRepo.listJobs({ memoryId: mem.id });
  assert.equal(jobs.length, 1);
  assert.equal(jobs[0].status, 'PENDING');
  assert.equal(jobs[0].modelId, env.mockProvider.modelId);
  assert.equal(jobs[0].scopeType, env.workspaceA.scopeType);
  assert.equal(jobs[0].scopeId, env.workspaceA.scopeId);
});

test('2. Job insertion failure rolls back the memory creation', () => {
  const env = setupTestEnvironment();
  const caller = env.authorizer.authorizeUser({
    credentials: 'token-admin-alpha',
    requestedScope: env.workspaceA
  });

  // Simulate a database job insertion failure inside the transaction
  const originalEnqueue = env.embeddingJobRepo.enqueueJob.bind(env.embeddingJobRepo);
  env.embeddingJobRepo.enqueueJob = () => {
    throw new Error('Simulated SQLite job table failure during enqueue');
  };

  assert.throws(
    () => {
      env.memoryService.createMemory(caller, {
        category: 'PROJECT_FACT',
        scopeType: env.workspaceA.scopeType,
        scopeId: env.workspaceA.scopeId,
        key: 'rollback.key',
        content: 'This memory must be rolled back'
      });
    },
    { message: /Simulated SQLite job table failure/ }
  );

  // Restore
  env.embeddingJobRepo.enqueueJob = originalEnqueue;

  // Verify memory was ROLLED BACK and does NOT exist in SQLite memories table
  const row = env.db.prepare("SELECT * FROM memories WHERE key = 'rollback.key'").get();
  assert.equal(row, undefined, 'Memory must not exist in database after rollback');

  // Verify job was also NOT inserted
  const jobCount = env.embeddingJobRepo.countJobs();
  assert.equal(jobCount, 0, 'No jobs must exist after rollback');

  // Verify audit event was also rolled back
  const auditRow = env.db.prepare("SELECT * FROM audit_events WHERE event_type = 'MEMORY_CREATED'").get();
  assert.equal(auditRow, undefined, 'Audit event must not exist after rollback');
});

test('3. Content update and job insertion commit together', () => {
  const env = setupTestEnvironment();
  const caller = env.authorizer.authorizeUser({
    credentials: 'token-admin-alpha',
    requestedScope: env.workspaceA
  });

  const mem = env.memoryService.createMemory(caller, {
    category: 'PROJECT_FACT',
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    key: 'project.mission',
    content: 'Initial mission statement'
  });

  // Mark the initial job as COMPLETED
  const initialJobs = env.embeddingJobRepo.listJobs({ memoryId: mem.id });
  assert.equal(initialJobs.length, 1);
  env.embeddingJobRepo.markJobCompleted(initialJobs[0].id);

  // Update content
  const updated = env.memoryService.updateMemory(caller, mem.id, {
    content: 'Updated mission statement with new vision'
  });

  assert.equal(updated.content, 'Updated mission statement with new vision');

  // Verify a new PENDING job was enqueued atomically
  const activeJobs = env.embeddingJobRepo.listJobs({ memoryId: mem.id, status: 'PENDING' });
  assert.equal(activeJobs.length, 1);
  assert.equal(activeJobs[0].status, 'PENDING');
});

test('4. Job insertion failure rolls back the content update', () => {
  const env = setupTestEnvironment();
  const caller = env.authorizer.authorizeUser({
    credentials: 'token-admin-alpha',
    requestedScope: env.workspaceA
  });

  const mem = env.memoryService.createMemory(caller, {
    category: 'PROJECT_FACT',
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    key: 'project.budget',
    content: 'Original budget $10,000'
  });

  // Inject failure on job enqueue
  const originalEnqueue = env.embeddingJobRepo.enqueueJob.bind(env.embeddingJobRepo);
  env.embeddingJobRepo.enqueueJob = () => {
    throw new Error('Simulated enqueue failure during updateMemory');
  };

  assert.throws(
    () => {
      env.memoryService.updateMemory(caller, mem.id, {
        content: 'Modified budget $50,000'
      });
    },
    { message: /Simulated enqueue failure during updateMemory/ }
  );

  // Restore
  env.embeddingJobRepo.enqueueJob = originalEnqueue;

  // Verify memory content in database is STILL original content!
  const currentMem = env.memoryRepo.getMemoryById(mem.id, env.workspaceA);
  assert.equal(currentMem?.content, 'Original budget $10,000', 'Content must be rolled back to original');
});

test('5. Proposal approval and job insertion commit together', () => {
  const env = setupTestEnvironment();
  const task = env.hostAuthority.createTask(env.taskRepo, {
    goal: 'Analyze dependencies',
    scope: env.workspaceA
  });
  const agentCaller = env.authorizer.authorizeAgent({ taskId: task.id });
  const userCaller = env.authorizer.authorizeUser({
    credentials: 'token-admin-alpha',
    requestedScope: env.workspaceA
  });

  // Agent submits proposal (must NOT enqueue an embedding job)
  const proposal = env.memoryService.createMemory(agentCaller, {
    category: 'LEARNED_PROCEDURE',
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    key: 'deployment.procedure',
    content: 'Run npm build then verify'
  });

  assert.equal(proposal.status, 'PENDING_APPROVAL');
  assert.equal(env.embeddingJobRepo.countJobs({ memoryId: proposal.id }), 0);

  // Human approves proposal
  const approved = env.memoryService.decideProposal(userCaller, {
    memoryId: proposal.id,
    decision: 'APPROVED'
  });

  assert.equal(approved.status, 'ACTIVE');

  // Verify job now exists and is PENDING
  const jobs = env.embeddingJobRepo.listJobs({ memoryId: proposal.id });
  assert.equal(jobs.length, 1);
  assert.equal(jobs[0].status, 'PENDING');
});

test('6. Job insertion failure rolls back proposal approval', () => {
  const env = setupTestEnvironment();
  const task = env.hostAuthority.createTask(env.taskRepo, {
    goal: 'Analyze architecture',
    scope: env.workspaceA
  });
  const agentCaller = env.authorizer.authorizeAgent({ taskId: task.id });
  const userCaller = env.authorizer.authorizeUser({
    credentials: 'token-admin-alpha',
    requestedScope: env.workspaceA
  });

  const proposal = env.memoryService.createMemory(agentCaller, {
    category: 'LEARNED_PROCEDURE',
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    key: 'rollback.procedure',
    content: 'Procedure that should not be approved if job fails'
  });

  // Inject failure on job enqueue
  const originalEnqueue = env.embeddingJobRepo.enqueueJob.bind(env.embeddingJobRepo);
  env.embeddingJobRepo.enqueueJob = () => {
    throw new Error('Simulated enqueue failure during decideProposal');
  };

  assert.throws(
    () => {
      env.memoryService.decideProposal(userCaller, {
        memoryId: proposal.id,
        decision: 'APPROVED'
      });
    },
    { message: /Simulated enqueue failure during decideProposal/ }
  );

  // Restore
  env.embeddingJobRepo.enqueueJob = originalEnqueue;

  // Verify memory status in database is STILL PENDING_APPROVAL!
  const currentMem = env.memoryRepo.getMemoryById(proposal.id, env.workspaceA);
  assert.equal(currentMem?.status, 'PENDING_APPROVAL', 'Proposal status must remain PENDING_APPROVAL after rollback');

  // Verify no job was persisted
  assert.equal(env.embeddingJobRepo.countJobs({ memoryId: proposal.id }), 0);
});

test('7. Archival removes existing embeddings', async () => {
  const env = setupTestEnvironment();
  const caller = env.authorizer.authorizeUser({
    credentials: 'token-admin-alpha',
    requestedScope: env.workspaceA
  });

  const mem = env.memoryService.createMemory(caller, {
    category: 'PROJECT_FACT',
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    key: 'archival.target',
    content: 'Memory to be archived'
  });

  // Process job to create stored embedding
  await env.lifecycleManager.processPendingJobs();

  // Verify embedding exists
  const existingEmbedding = env.embeddingRepo.getEmbedding(mem.id, env.mockProvider.modelId);
  assert.ok(existingEmbedding, 'Embedding must exist before archival');

  // Archive memory
  const archived = env.memoryService.archiveMemory(caller, mem.id);
  assert.equal(archived.status, 'ARCHIVED');

  // Verify embedding was removed
  const deletedEmbedding = env.embeddingRepo.getEmbedding(mem.id, env.mockProvider.modelId);
  assert.equal(deletedEmbedding, null, 'Embedding must be deleted upon memory archival');
});

test('8. Archival cancels pending jobs', () => {
  const env = setupTestEnvironment();
  const caller = env.authorizer.authorizeUser({
    credentials: 'token-admin-alpha',
    requestedScope: env.workspaceA
  });

  const mem = env.memoryService.createMemory(caller, {
    category: 'PROJECT_FACT',
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    key: 'archival.jobs',
    content: 'Pending jobs to be cancelled'
  });

  // Verify job is PENDING before archival
  const pendingBefore = env.embeddingJobRepo.listJobs({ memoryId: mem.id, status: 'PENDING' });
  assert.equal(pendingBefore.length, 1);

  // Archive memory
  env.memoryService.archiveMemory(caller, mem.id);

  // Verify job status is now CANCELLED
  const jobAfter = env.embeddingJobRepo.getJobById(pendingBefore[0].id);
  assert.equal(jobAfter?.status, 'CANCELLED', 'Pending job must be transitioned to CANCELLED');

  // Verify count of pending jobs for this memory is 0
  const pendingAfter = env.embeddingJobRepo.listJobs({ memoryId: mem.id, status: 'PENDING' });
  assert.equal(pendingAfter.length, 0);
});

test("9. An in-flight job cannot recreate an archived memory's embedding", async () => {
  const env = setupTestEnvironment();
  const caller = env.authorizer.authorizeUser({
    credentials: 'token-admin-alpha',
    requestedScope: env.workspaceA
  });

  const mem = env.memoryService.createMemory(caller, {
    category: 'PROJECT_FACT',
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    key: 'concurrent.archive',
    content: 'Memory will be archived while job is in-flight'
  });

  // Custom provider that archives the memory mid-inference
  let inferenceRan = false;
  const concurrentProvider: IEmbeddingProvider = {
    name: 'concurrent-mock',
    modelId: env.mockProvider.modelId,
    dimensions: 384,
    async isAvailable() { return true; },
    async embed() {
      inferenceRan = true;
      // Memory is archived while inference is executing!
      env.memoryService.archiveMemory(caller, mem.id);
      return new Float32Array(384);
    },
    async embedBatch(texts) { return texts.map(() => new Float32Array(384)); }
  };

  const manager = new EmbeddingLifecycleManager({
    db: env.db,
    jobRepo: env.embeddingJobRepo,
    memoryRepo: env.memoryRepo,
    embeddingRepo: env.embeddingRepo,
    provider: concurrentProvider
  });

  const processed = await manager.processNextJob();
  assert.equal(processed, true);
  assert.equal(inferenceRan, true);

  // Verify memory is ARCHIVED
  const currentMem = env.memoryRepo.getMemoryById(mem.id, env.workspaceA);
  assert.equal(currentMem?.status, 'ARCHIVED');

  // The in-flight job MUST NOT have recreated an embedding for the archived memory!
  const storedEmbedding = env.embeddingRepo.getEmbedding(mem.id, env.mockProvider.modelId);
  assert.equal(storedEmbedding, null, 'In-flight worker must discard result and not persist embedding for archived memory');
});

test('10. Cancelled jobs cannot be claimed or retried', () => {
  const env = setupTestEnvironment();
  const caller = env.authorizer.authorizeUser({
    credentials: 'token-admin-alpha',
    requestedScope: env.workspaceA
  });

  const mem = env.memoryService.createMemory(caller, {
    category: 'PROJECT_FACT',
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    key: 'cancelled.test',
    content: 'Testing cancellation invariants'
  });

  const jobs = env.embeddingJobRepo.listJobs({ memoryId: mem.id });
  assert.equal(jobs.length, 1);
  const jobId = jobs[0].id;

  // Mark job CANCELLED
  env.embeddingJobRepo.markJobCancelled(jobId);
  const cancelledJob = env.embeddingJobRepo.getJobById(jobId);
  assert.equal(cancelledJob?.status, 'CANCELLED');

  // Invariant 1: Cancelled job cannot be claimed
  const claimed = env.embeddingJobRepo.claimNextJob();
  assert.equal(claimed, null, 'Cancelled job must never be claimed');

  // Invariant 2: rescheduleJob cannot revive cancelled job
  env.embeddingJobRepo.rescheduleJob(jobId, 1, new Date().toISOString(), 'Retry attempt');
  const afterReschedule = env.embeddingJobRepo.getJobById(jobId);
  assert.equal(afterReschedule?.status, 'CANCELLED', 'rescheduleJob must not revive CANCELLED jobs');

  // Invariant 3: recoverInterruptedJobs cannot revive cancelled job
  const recovered = env.embeddingJobRepo.recoverInterruptedJobs();
  assert.equal(recovered.length, 0);
  const afterRecovery = env.embeddingJobRepo.getJobById(jobId);
  assert.equal(afterRecovery?.status, 'CANCELLED', 'recoverInterruptedJobs must not revive CANCELLED jobs');
});

test('11. Deleted memories still cascade correctly', () => {
  const env = setupTestEnvironment();
  const caller = env.authorizer.authorizeUser({
    credentials: 'token-admin-alpha',
    requestedScope: env.workspaceA
  });

  const mem = env.memoryService.createMemory(caller, {
    category: 'PROJECT_FACT',
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    key: 'cascade.test',
    content: 'Memory to test foreign key cascades'
  });

  // Insert an embedding and verify job exists
  env.embeddingRepo.insertEmbedding({
    memoryId: mem.id,
    modelId: env.mockProvider.modelId,
    modelRevision: 'main',
    dimensions: 384,
    embedding: new Float32Array(384).fill(1 / Math.sqrt(384))
  });

  assert.ok(env.embeddingRepo.getEmbedding(mem.id, env.mockProvider.modelId));
  assert.equal(env.embeddingJobRepo.countJobs({ memoryId: mem.id }), 1);

  // Delete memory
  const deleted = env.memoryService.deleteMemory(caller, mem.id);
  assert.equal(deleted, true);

  // SQLite foreign key cascade must automatically delete embedding and job
  const embeddingCount = env.db.prepare('SELECT COUNT(*) as c FROM memory_embeddings WHERE memory_id = ?').get(mem.id) as { c: number };
  assert.equal(embeddingCount.c, 0, 'Embeddings must be cascaded on memory deletion');

  const jobCount = env.db.prepare('SELECT COUNT(*) as c FROM embedding_jobs WHERE memory_id = ?').get(mem.id) as { c: number };
  assert.equal(jobCount.c, 0, 'Embedding jobs must be cascaded on memory deletion');
});

test('12. Existing workspace/global authorization remains intact', () => {
  const env = setupTestEnvironment();
  const callerA = env.authorizer.authorizeUser({
    credentials: 'token-admin-alpha',
    requestedScope: env.workspaceA
  });
  const callerB = env.authorizer.authorizeUser({
    credentials: 'token-admin-beta',
    requestedScope: env.workspaceB
  });

  const memA = env.memoryService.createMemory(callerA, {
    category: 'PROJECT_FACT',
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    key: 'workspace.a.fact',
    content: 'Workspace A secret fact'
  });

  // Caller B cannot update Caller A's memory
  assert.throws(
    () => {
      env.memoryService.updateMemory(callerB, memA.id, {
        content: 'Tampered content'
      });
    },
    (err: any) => err instanceof MemoryScopeViolationError
  );

  // Caller B cannot archive Caller A's memory
  assert.throws(
    () => {
      env.memoryService.archiveMemory(callerB, memA.id);
    },
    (err: any) => err instanceof MemoryScopeViolationError
  );

  // Caller B cannot delete Caller A's memory
  assert.throws(
    () => {
      env.memoryService.deleteMemory(callerB, memA.id);
    },
    (err: any) => err instanceof MemoryScopeViolationError
  );

  // Agents cannot directly create active memories
  const task = env.hostAuthority.createTask(env.taskRepo, {
    goal: 'Run tests',
    scope: env.workspaceA
  });
  const agentCaller = env.authorizer.authorizeAgent({ taskId: task.id });

  assert.throws(
    () => {
      env.memoryService.createMemory(agentCaller, {
        category: 'PROJECT_FACT',
        scopeType: env.workspaceA.scopeType,
        scopeId: env.workspaceA.scopeId,
        key: 'agent.direct.active',
        content: 'Agent trying direct active creation',
        status: 'ACTIVE'
      });
    },
    (err: any) => err instanceof SecurityViolationError
  );
});

test('13. Existing reconciliation and hybrid retrieval behavior remains intact', async () => {
  const env = setupTestEnvironment();
  const caller = env.authorizer.authorizeUser({
    credentials: 'token-admin-alpha',
    requestedScope: env.workspaceA
  });

  // Create memories without processing jobs immediately
  const mem1 = env.memoryService.createMemory(caller, {
    category: 'PROJECT_FACT',
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    key: 'arch.pattern',
    content: 'Hexagonal clean architecture pattern with dependency inversion'
  });

  const mem2 = env.memoryService.createMemory(caller, {
    category: 'PROJECT_FACT',
    scopeType: env.workspaceA.scopeType,
    scopeId: env.workspaceA.scopeId,
    key: 'db.sqlite',
    content: 'Zero dependency native SQLite database manager using Node 24'
  });

  // Verify missing embeddings count
  const missingCount = env.memoryRepo.countMemoriesMissingEmbeddings(
    env.workspaceA.scopeType,
    env.workspaceA.scopeId,
    env.mockProvider.modelId
  );
  assert.equal(missingCount, 2);

  // Manual reconciliation via syncScopeEmbeddings
  const result = await env.memoryService.syncScopeEmbeddings(caller, {
    provider: env.mockProvider
  });
  assert.equal(result.candidatesDiscovered, 2);
  assert.equal(result.embeddingsGenerated, 2);
  assert.equal(result.failed, 0);

  // Search memories using hybrid retriever
  const searchResults = await env.memoryService.searchMemories(caller, {
    query: 'architecture clean pattern',
    limit: 5
  });

  assert.ok(searchResults.length > 0);
  assert.equal(searchResults[0].memory.id, mem1.id);
  assert.ok(searchResults[0].score > 0);

  // Archiving mem1 removes its embedding and keeps system consistent
  env.memoryService.archiveMemory(caller, mem1.id);
  assert.equal(env.embeddingRepo.getEmbedding(mem1.id, env.mockProvider.modelId), null);
});
