/**
 * Next-Generation Dots AI Platform - Verification Lifecycle Integrity Tests
 * Phase 4D.3D.4C.3D: Content-Edit Invalidation, Supersession Immutability,
 * and Qualifier/Assumption Preservation
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseManager } from '../../src/storage/db.ts';
import { TaskRepository } from '../../src/storage/task-repository.ts';
import { AuditRepository } from '../../src/storage/audit-repository.ts';
import { MemoryRepository } from '../../src/storage/memory-repository.ts';
import { MemoryEmbeddingRepository } from '../../src/storage/memory-embedding-repository.ts';
import { EmbeddingJobRepository } from '../../src/storage/embedding-job-repository.ts';
import { DeterministicMockEmbeddingProvider } from '../../src/memory/mock-embedding-provider.ts';
import { MemoryService } from '../../src/memory/memory-service.ts';
import { HostMemoryAuthority } from '../../src/security/host-authority.ts';
import { MockModelProvider } from '../../src/model/mock-provider.ts';
import { KnowledgeProposalPipeline } from '../../src/memory/knowledge-pipeline.ts';
import { EvidenceVerificationEngine } from '../../src/memory/evidence-verifier.ts';
import type { AgentOutput } from '../../src/agents/types.ts';
import type { ScopeIdentifier } from '../../src/domain/types.ts';
import {
  MemoryScopeViolationError,
  SecurityViolationError,
  ValidationError
} from '../../src/domain/errors.ts';

function setupLifecycleTestEnv() {
  const db = new DatabaseManager(':memory:');
  const taskRepo = new TaskRepository(db);
  const auditRepo = new AuditRepository(db);
  const memoryRepo = new MemoryRepository(db);
  const embeddingRepo = new MemoryEmbeddingRepository(db);
  const embeddingJobRepo = new EmbeddingJobRepository(db);
  const embeddingProvider = new DeterministicMockEmbeddingProvider({
    modelId: 'test-embed-v1',
    modelRevision: 'rev1',
    dimensions: 8
  });

  const scopeAlpha: ScopeIdentifier = { scopeType: 'WORKSPACE', scopeId: 'ws-alpha' };
  const scopeBeta: ScopeIdentifier = { scopeType: 'WORKSPACE', scopeId: 'ws-beta' };

  const identityProvider = {
    authenticate(credentials: unknown) {
      if (typeof credentials !== 'string') return null;
      if (credentials === 'token-admin-alpha') {
        return {
          principalId: 'admin-alpha',
          role: 'ADMIN' as const,
          permittedScopes: [scopeAlpha]
        };
      }
      if (credentials === 'token-viewer-alpha') {
        return {
          principalId: 'viewer-alpha',
          role: 'VIEWER' as const,
          permittedScopes: [scopeAlpha]
        };
      }
      if (credentials === 'token-admin-beta') {
        return {
          principalId: 'admin-beta',
          role: 'ADMIN' as const,
          permittedScopes: [scopeBeta]
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

  const memoryService = new MemoryService({
    memoryRepo,
    auditRepo,
    taskRepo,
    authorizer,
    hostAuthority,
    embeddingRepo,
    embeddingJobRepo,
    embeddingProvider
  });

  const adminAlpha = authorizer.authorizeUser({
    credentials: 'token-admin-alpha',
    requestedScope: scopeAlpha
  });
  const viewerAlpha = authorizer.authorizeUser({
    credentials: 'token-viewer-alpha',
    requestedScope: scopeAlpha
  });
  const adminBeta = authorizer.authorizeUser({
    credentials: 'token-admin-beta',
    requestedScope: scopeBeta
  });

  const taskAlpha = hostAuthority.createTask(taskRepo, {
    goal: 'Lifecycle integrity testing',
    scope: scopeAlpha,
    principalId: 'admin-alpha'
  });
  const taskBeta = hostAuthority.createTask(taskRepo, {
    goal: 'Beta workspace verification',
    scope: scopeBeta,
    principalId: 'admin-beta'
  });

  const agentAlpha = authorizer.authorizeAgent({
    taskId: taskAlpha.id,
    agentId: 'research-agent'
  });

  const mockProvider = new MockModelProvider('mock-lifecycle-verifier');
  const engine = new EvidenceVerificationEngine({
    modelProvider: mockProvider,
    memoryRepo,
    authorizer,
    auditRepo,
    taskRepo,
    timeoutMs: 250,
    maxConcurrency: 2,
    maxBatchSize: 10
  });

  return {
    db,
    taskRepo,
    auditRepo,
    memoryRepo,
    embeddingRepo,
    embeddingJobRepo,
    embeddingProvider,
    hostAuthority,
    authorizer,
    memoryService,
    scopeAlpha,
    scopeBeta,
    adminAlpha,
    viewerAlpha,
    adminBeta,
    taskAlpha,
    taskBeta,
    agentAlpha,
    mockProvider,
    engine
  };
}

// ============================================================================
// 1. Editing an ACTIVE memory invalidates old claim links, associations, and verifications
// ============================================================================
test('1. Editing ACTIVE memory content invalidates old claim links and associations while preserving historical verifications as STALE', async () => {
  const env = setupLifecycleTestEnv();

  // Create and approve memory with verified claim + evidence
  const proposal = env.memoryService.createMemory(env.agentAlpha, {
    key: 'service.timeout.policy',
    content: 'Default HTTP request timeout is 10 seconds.',
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    status: 'PENDING_APPROVAL',
    claims: [{ originalText: 'Default HTTP request timeout is 10 seconds.' }],
    evidence: [
      {
        sourceType: 'DOCUMENTATION',
        sourceUrl: 'https://docs.example.org/timeouts',
        snippet: 'Service defaults HTTP timeout to 10s in v1.',
        relationship: 'SUPPORTS',
        targetClaimIndices: [0]
      }
    ]
  });

  const claimsBefore = env.memoryService.getClaimsByMemoryId(env.adminAlpha, proposal.id);
  const evidenceBefore = env.memoryService.getEvidenceByMemoryId(env.adminAlpha, proposal.id);
  assert.equal(claimsBefore.length, 1);
  assert.equal(evidenceBefore.length, 1);

  env.mockProvider.enqueueCompletion(
    JSON.stringify({
      claimId: claimsBefore[0]!.id,
      evidenceId: evidenceBefore[0]!.id,
      proposedRelationship: 'SUPPORTS',
      outcome: 'PROPOSED',
      confidence: 0.94,
      explanation: 'Confirmed 10s timeout in v1 docs.'
    })
  );
  const verifyRes = await env.engine.verifyProposalClaims(env.agentAlpha, proposal.id);
  assert.equal(verifyRes.length, 1);
  assert.equal(verifyRes[0]!.ok, true);
  assert.equal(verifyRes[0]!.record?.status, 'CURRENT');

  const active = env.memoryService.decideProposal(env.adminAlpha, {
    memoryId: proposal.id,
    decision: 'APPROVE_NEW'
  });
  assert.equal(active.status, 'ACTIVE');

  // Seed embedding so we can assert embedding invalidation stays consistent alongside lifecycle invalidation
  env.embeddingRepo.upsertEmbedding({
    memoryId: active.id,
    modelId: env.embeddingProvider.modelId,
    modelRevision: env.embeddingProvider.modelRevision,
    dimensions: env.embeddingProvider.dimensions,
    embedding: new Float32Array(env.embeddingProvider.dimensions).fill(1 / Math.sqrt(env.embeddingProvider.dimensions))
  });

  // Non-content update (priority/tags) MUST preserve ACTIVE links, associations, and CURRENT verification
  env.memoryService.updateMemory(env.adminAlpha, active.id, {
    priority: 90,
    tags: ['timeout', 'http']
  });
  assert.equal(env.memoryService.getClaimsByMemoryId(env.adminAlpha, active.id).length, 1);
  assert.equal(env.memoryService.getClaimEvidenceAssociationsByMemoryId(env.adminAlpha, active.id).length, 1);
  assert.equal(env.memoryService.listClaimVerifications(env.adminAlpha, { memoryId: active.id }).length, 1);
  assert.ok(env.embeddingRepo.getEmbedding(active.id, env.embeddingProvider.modelId, env.embeddingProvider.modelRevision));

  // Content update MUST invalidate old claim links, associations, embeddings, and mark verification STALE atomically
  const edited = env.memoryService.updateMemory(env.adminAlpha, active.id, {
    content: 'Default HTTP request timeout was increased to 60 seconds in v2.'
  });
  assert.equal(edited.content, 'Default HTTP request timeout was increased to 60 seconds in v2.');

  // Current queries MUST NOT return old claims, associations, or verifications for edited memory
  assert.deepEqual(env.memoryService.getClaimsByMemoryId(env.adminAlpha, active.id), []);
  assert.deepEqual(env.memoryService.getClaimEvidenceAssociationsByMemoryId(env.adminAlpha, active.id), []);
  assert.deepEqual(env.memoryService.listClaimVerifications(env.adminAlpha, { memoryId: active.id }), []);
  assert.deepEqual(env.memoryService.getClaimVerificationsByClaimId(env.adminAlpha, claimsBefore[0]!.id), []);
  assert.deepEqual(env.memoryService.getClaimVerificationsByEvidenceId(env.adminAlpha, evidenceBefore[0]!.id), []);

  // Re-running verifyProposalClaims on edited memory does NOT reuse or re-verify invalidated associations
  const reverify = await env.engine.verifyProposalClaims(env.agentAlpha, active.id);
  assert.deepEqual(reverify, []);
  assert.equal(env.mockProvider.getRecordedCalls().length, 1);

  // Embeddings were deleted and replacement job enqueued cleanly
  assert.equal(env.embeddingRepo.getEmbedding(active.id, env.embeddingProvider.modelId, env.embeddingProvider.modelRevision), null);
  const claimedJob = env.embeddingJobRepo.claimNextJob();
  assert.equal(claimedJob?.memoryId, active.id);

  // Historical inspection clearly shows INVALIDATED links/associations and STALE verification with exact reason
  const histClaims = env.memoryService.getClaimsByMemoryId(env.adminAlpha, active.id, { includeInvalidated: true });
  assert.equal(histClaims.length, 1);

  const histAssocs = env.memoryService.getClaimEvidenceAssociationsByMemoryId(env.adminAlpha, active.id, { includeInvalidated: true });
  assert.equal(histAssocs.length, 1);
  assert.equal(histAssocs[0]!.status, 'INVALIDATED');
  assert.equal(histAssocs[0]!.invalidationReason, 'MEMORY_CONTENT_UPDATED');
  assert.ok(histAssocs[0]!.invalidatedAt);

  const staleVerifs = env.memoryService.listClaimVerifications(env.adminAlpha, {
    memoryId: active.id,
    status: 'STALE'
  });
  assert.equal(staleVerifs.length, 1);
  assert.equal(staleVerifs[0]!.status, 'STALE');
  assert.equal(staleVerifs[0]!.staleReason, 'MEMORY_CONTENT_UPDATED');
  assert.ok(staleVerifs[0]!.staleAt);
  assert.equal(staleVerifs[0]!.proposedRelationship, 'SUPPORTS');

  const withHistorical = env.memoryService.getClaimVerificationsByEvidenceId(
    env.adminAlpha,
    evidenceBefore[0]!.id,
    { includeStale: true }
  );
  assert.equal(withHistorical.length, 1);
  assert.equal(withHistorical[0]!.status, 'STALE');
});

// ============================================================================
// 2. Shared claim edited on M1 leaves M2's current verification untouched, and supersession/archival marks STALE
// ============================================================================
test('2. Editing M1 or superseding/archiving memory only stales that memory’s verifications while preserving shared claim on M2', async () => {
  const env = setupLifecycleTestEnv();

  const sharedClaimText = 'PostgreSQL MVCC does not block readers during writes.';

  const p1 = env.memoryService.createMemory(env.agentAlpha, {
    key: 'pg.mvcc.m1',
    content: 'Initial MVCC fact in memory 1.',
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    status: 'PENDING_APPROVAL',
    claims: [{ originalText: sharedClaimText }],
    evidence: [
      {
        sourceType: 'DOCUMENTATION',
        snippet: 'PostgreSQL readers see consistent snapshot.',
        relationship: 'SUPPORTS',
        targetClaimIndices: [0]
      }
    ]
  });
  const p2 = env.memoryService.createMemory(env.agentAlpha, {
    key: 'pg.mvcc.m2',
    content: 'Independent MVCC fact in memory 2.',
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    status: 'PENDING_APPROVAL',
    claims: [{ originalText: sharedClaimText }],
    evidence: [
      {
        sourceType: 'WEB_RESEARCH',
        snippet: 'Concurrent SELECT queries never wait for row locks from UPDATE.',
        relationship: 'SUPPORTS',
        targetClaimIndices: [0]
      }
    ]
  });

  const c1 = env.memoryService.getClaimsByMemoryId(env.adminAlpha, p1.id)[0]!;
  const e1 = env.memoryService.getEvidenceByMemoryId(env.adminAlpha, p1.id)[0]!;
  const c2 = env.memoryService.getClaimsByMemoryId(env.adminAlpha, p2.id)[0]!;
  const e2 = env.memoryService.getEvidenceByMemoryId(env.adminAlpha, p2.id)[0]!;
  assert.equal(c1.id, c2.id);

  env.mockProvider.enqueueCompletion(JSON.stringify({
    claimId: c1.id, evidenceId: e1.id, proposedRelationship: 'SUPPORTS', outcome: 'PROPOSED', confidence: 0.9, explanation: 'M1 confirmed.'
  }));
  env.mockProvider.enqueueCompletion(JSON.stringify({
    claimId: c2.id, evidenceId: e2.id, proposedRelationship: 'SUPPORTS', outcome: 'PROPOSED', confidence: 0.91, explanation: 'M2 confirmed.'
  }));

  await env.engine.verifyProposalClaims(env.agentAlpha, p1.id);
  await env.engine.verifyProposalClaims(env.agentAlpha, p2.id);

  const m1 = env.memoryService.decideProposal(env.adminAlpha, { memoryId: p1.id, decision: 'APPROVE_NEW' });
  const m2 = env.memoryService.decideProposal(env.adminAlpha, { memoryId: p2.id, decision: 'APPROVE_NEW' });

  // Edit M1 content -> M1 verifications become STALE, M2 stays ACTIVE & CURRENT!
  env.memoryService.updateMemory(env.adminAlpha, m1.id, { content: 'Completely revised M1 statement.' });

  assert.equal(env.memoryService.getClaimsByMemoryId(env.adminAlpha, m1.id).length, 0);
  assert.equal(env.memoryService.getClaimsByMemoryId(env.adminAlpha, m2.id).length, 1);

  const currentForClaim = env.memoryService.getClaimVerificationsByClaimId(env.adminAlpha, c1.id);
  assert.equal(currentForClaim.length, 1);
  assert.equal(currentForClaim[0]!.evidenceId, e2.id);
  assert.equal(currentForClaim[0]!.status, 'CURRENT');

  const allForClaim = env.memoryService.getClaimVerificationsByClaimId(env.adminAlpha, c1.id, { includeStale: true });
  assert.equal(allForClaim.length, 2);
  const m1Hist = allForClaim.find((v) => v.evidenceId === e1.id)!;
  assert.equal(m1Hist.status, 'STALE');
  assert.equal(m1Hist.staleReason, 'MEMORY_CONTENT_UPDATED');

  // Supersede M2 -> M2's CURRENT verification transitions to STALE with MEMORY_SUPERSEDED
  const updateP2 = env.memoryService.createMemory(env.agentAlpha, {
    key: 'pg.mvcc.m2',
    content: 'Updated M2 v2 content.',
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    status: 'PENDING_APPROVAL',
    metadata: {
      proposalType: 'UPDATE',
      targetMemoryId: m2.id,
      targetVersion: m2.version
    }
  });
  const m2v2 = env.memoryService.decideProposal(env.adminAlpha, {
    memoryId: updateP2.id,
    decision: 'APPROVE_AND_SUPERSEDE'
  });
  assert.equal(m2v2.status, 'ACTIVE');
  assert.equal(m2v2.version, 2);

  assert.equal(env.memoryService.getClaimVerificationsByEvidenceId(env.adminAlpha, e2.id).length, 0);
  const e2Stale = env.memoryService.getClaimVerificationsByEvidenceId(env.adminAlpha, e2.id, { includeStale: true });
  assert.equal(e2Stale.length, 1);
  assert.equal(e2Stale[0]!.status, 'STALE');
  assert.equal(e2Stale[0]!.staleReason, 'MEMORY_SUPERSEDED');
});

// ============================================================================
// 3. SUPERSEDED memories are strictly immutable against updateMemory
// ============================================================================
test('3. SUPERSEDED memories reject content and metadata updates via MemoryService and MemoryRepository', () => {
  const env = setupLifecycleTestEnv();

  const v1 = env.memoryService.createMemory(env.adminAlpha, {
    key: 'immutable.superseded.key',
    content: 'Original v1 content.',
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId
  });
  const v2Proposal = env.memoryService.createMemory(env.agentAlpha, {
    key: 'immutable.superseded.key',
    content: 'Replacement v2 content.',
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    status: 'PENDING_APPROVAL',
    metadata: {
      proposalType: 'UPDATE',
      targetMemoryId: v1.id,
      targetVersion: v1.version
    }
  });
  env.memoryService.decideProposal(env.adminAlpha, {
    memoryId: v2Proposal.id,
    decision: 'APPROVE_AND_SUPERSEDE'
  });

  const supersededV1 = env.memoryService.getMemoryById(env.adminAlpha, v1.id)!;
  assert.equal(supersededV1.status, 'SUPERSEDED');
  const originalUpdatedAt = supersededV1.updatedAt;

  // Content update rejected
  assert.throws(
    () =>
      env.memoryService.updateMemory(env.adminAlpha, supersededV1.id, {
        content: 'Attempted overwrite of superseded content.'
      }),
    (err) => err instanceof ValidationError && err.message.includes('superseded')
  );

  // Metadata / priority / tags update rejected
  assert.throws(
    () =>
      env.memoryService.updateMemory(env.adminAlpha, supersededV1.id, {
        metadata: { tampered: true },
        priority: 99,
        tags: ['tampered']
      }),
    (err) => err instanceof ValidationError && err.message.includes('superseded')
  );

  // Direct repository updateMemory also rejects SUPERSEDED
  assert.throws(
    () =>
      env.memoryRepo.updateMemory(supersededV1.id, env.scopeAlpha, {
        content: 'Direct repo overwrite attempt.'
      }),
    (err) => err instanceof ValidationError && err.message.includes('superseded')
  );

  // Superseded record remains completely untouched
  const afterAttempts = env.memoryService.getMemoryById(env.adminAlpha, supersededV1.id)!;
  assert.equal(afterAttempts.content, 'Original v1 content.');
  assert.equal(afterAttempts.status, 'SUPERSEDED');
  assert.equal(afterAttempts.updatedAt, originalUpdatedAt);
});

// ============================================================================
// 4. Distinct qualifiers preserved across claim deduplication & pipeline extraction
// ============================================================================
test('4. Different claim qualifiers remain distinct through deduplication and pipeline extraction preserves qualifiers and limitations', async () => {
  const env = setupLifecycleTestEnv();

  const mem1 = env.memoryService.createMemory(env.agentAlpha, {
    key: 'bench.duckdb.olap',
    content: 'DuckDB throughput benchmark on server OLAP.',
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    status: 'PENDING_APPROVAL',
    claims: [
      {
        originalText: 'DuckDB achieves higher throughput than SQLite.',
        qualifier: 'TPC-H 100GB OLAP scan on 32-core NVMe server'
      }
    ]
  });

  const mem2 = env.memoryService.createMemory(env.agentAlpha, {
    key: 'bench.duckdb.oltp',
    content: 'DuckDB throughput benchmark on embedded OLTP.',
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    status: 'PENDING_APPROVAL',
    claims: [
      {
        originalText: 'DuckDB achieves higher throughput than SQLite.',
        qualifier: 'Single-row OLTP lookup on mobile flash storage'
      }
    ]
  });

  const mem3 = env.memoryService.createMemory(env.agentAlpha, {
    key: 'bench.duckdb.olap.dup',
    content: 'Same OLAP benchmark with normalized qualifier whitespace/casing.',
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    status: 'PENDING_APPROVAL',
    claims: [
      {
        originalText: 'DuckDB achieves higher throughput than SQLite.',
        qualifier: '  tpc-h   100gb olap scan on 32-core nvme server.  '
      }
    ]
  });

  const claims1 = env.memoryService.getClaimsByMemoryId(env.adminAlpha, mem1.id);
  const claims2 = env.memoryService.getClaimsByMemoryId(env.adminAlpha, mem2.id);
  const claims3 = env.memoryService.getClaimsByMemoryId(env.adminAlpha, mem3.id);

  assert.equal(claims1.length, 1);
  assert.equal(claims2.length, 1);
  assert.equal(claims3.length, 1);
  assert.notEqual(claims1[0]!.id, claims2[0]!.id, 'Different qualifiers MUST produce distinct claim records');
  assert.notEqual(claims1[0]!.claimHash, claims2[0]!.claimHash);
  assert.equal(claims1[0]!.qualifier, 'TPC-H 100GB OLAP scan on 32-core NVMe server');
  assert.equal(claims2[0]!.qualifier, 'Single-row OLTP lookup on mobile flash storage');
  assert.equal(claims3[0]!.id, claims1[0]!.id, 'Normalized equivalent qualifiers deduplicate cleanly');

  // Research pipeline preserves structured finding qualifiers, assumptions, and limitations into verifier prompt
  const output: AgentOutput = {
    agentId: 'research-agent',
    status: 'COMPLETED',
    result: {
      report: {
        completionStatus: 'COMPLETED',
        researchQuestion: 'Columnar scan throughput comparison',
        keyFindings: [
          {
            claim: 'DuckDB outperforms row-oriented engines on vectorized scans.',
            qualifier: 'Cold cache 50GB Parquet aggregation workload'
          }
        ],
        assumptions: ['Warm JVM/OS page cache disabled', 'Single-node execution'],
        limitationsAndUncertainty: ['Evaluated only on analytical Parquet scans, not concurrent writes.'],
        evidenceAndSources: [
          {
            id: 'src-duckdb-bench',
            title: 'Columnar Execution Study',
            url: 'https://bench.example.org/parquet',
            domain: 'bench.example.org',
            relationship: 'LIMITATION',
            targetFindingIndex: 0,
            relevantEvidence: [
              'Vectorized columnar processing accelerates aggregations but relies on batch memory budgets.'
            ]
          }
        ]
      }
    },
    summary: 'Completed qualified research',
    stepsExecuted: 1,
    durationMs: 20
  };

  // Use mockProvider with expected IDs computed via echo or single completion inspection
  const pipeline = new KnowledgeProposalPipeline();
  const observedPrompts: string[] = [];
  const captureEngine = new EvidenceVerificationEngine({
    verifier: {
      verifierId: 'capture-verifier',
      verifierVersion: '1.0',
      promptPolicyVersion: 'v1',
      promptPolicyHash: 'h1',
      async evaluate({ claim, evidence, qualifiersAndAssumptions }) {
        observedPrompts.push(qualifiersAndAssumptions.join(' | '));
        return {
          claimId: claim.id,
          evidenceId: evidence.id,
          proposedRelationship: 'LIMITATION',
          outcome: 'PROPOSED',
          confidence: 0.87,
          explanation: 'Captured qualifier and limitations during verification.',
          verifierId: 'capture-verifier',
          verifierVersion: '1.0'
        };
      }
    },
    memoryRepo: env.memoryRepo,
    authorizer: env.authorizer,
    auditRepo: env.auditRepo,
    taskRepo: env.taskRepo
  });

  const submitted = await pipeline.processCompletedTask({
    task: env.taskAlpha,
    agentId: 'research-agent',
    output,
    caller: env.agentAlpha,
    memoryService: env.memoryService,
    verificationEngine: captureEngine
  });

  const findingProposal = submitted.find((m) => m.key.startsWith('research.finding.'))!;
  assert.ok(findingProposal);

  const persistedClaims = env.memoryService.getClaimsByMemoryId(env.adminAlpha, findingProposal.id);
  assert.equal(persistedClaims.length, 1);
  assert.equal(persistedClaims[0]!.qualifier, 'Cold cache 50GB Parquet aggregation workload');

  assert.equal(observedPrompts.length, 1);
  assert.ok(observedPrompts[0]!.includes('Cold cache 50GB Parquet aggregation workload'));
  assert.ok(observedPrompts[0]!.includes('Warm JVM/OS page cache disabled'));
  assert.ok(observedPrompts[0]!.includes('Limitation: Evaluated only on analytical Parquet scans'));
});

// ============================================================================
// 5. Different assumptions never reuse cached verification results
// ============================================================================
test('5. Distinct verification assumptions produce separate verifications while equivalent normalized assumptions deduplicate', async () => {
  const env = setupLifecycleTestEnv();

  const proposal = env.memoryService.createMemory(env.agentAlpha, {
    key: 'redis.eviction.hitrate',
    content: 'LFU policy improves cache hit ratio.',
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    status: 'PENDING_APPROVAL',
    claims: [{ originalText: 'LFU eviction improves cache hit rate over LRU.' }],
    evidence: [
      {
        sourceType: 'DOCUMENTATION',
        snippet: 'Under skewed Zipfian access distributions, LFU outperforms LRU.',
        relationship: 'LIMITATION',
        targetClaimIndices: [0]
      }
    ]
  });

  const claim = env.memoryService.getClaimsByMemoryId(env.adminAlpha, proposal.id)[0]!;
  const evidence = env.memoryService.getEvidenceByMemoryId(env.adminAlpha, proposal.id)[0]!;

  env.mockProvider.enqueueCompletion(JSON.stringify({
    claimId: claim.id,
    evidenceId: evidence.id,
    proposedRelationship: 'SUPPORTS',
    outcome: 'PROPOSED',
    confidence: 0.9,
    explanation: 'Supports claim under skewed Zipfian workload assumption.'
  }));
  env.mockProvider.enqueueCompletion(JSON.stringify({
    claimId: claim.id,
    evidenceId: evidence.id,
    proposedRelationship: 'LIMITATION',
    outcome: 'PROPOSED',
    confidence: 0.85,
    explanation: 'Under uniform random workload assumption, Zipfian evidence narrows applicability.'
  }));

  const resZipf = await env.engine.verifyClaimAgainstEvidence(env.agentAlpha, {
    claimId: claim.id,
    evidenceId: evidence.id,
    assumptions: ['Skewed Zipfian key distribution']
  });
  assert.equal(resZipf.ok, true);
  assert.equal(resZipf.deduplicated, false);
  assert.equal(resZipf.proposedRelationship, 'SUPPORTS');
  assert.deepEqual(resZipf.record?.assumptions, ['Skewed Zipfian key distribution']);

  // Equivalent normalized assumptions MUST deduplicate cleanly (zero extra model calls)
  const resZipfDup = await env.engine.verifyClaimAgainstEvidence(env.agentAlpha, {
    claimId: claim.id,
    evidenceId: evidence.id,
    assumptions: ['  skewed   zipfian key distribution  ']
  });
  assert.equal(resZipfDup.ok, true);
  assert.equal(resZipfDup.deduplicated, true);
  assert.equal(resZipfDup.record?.id, resZipf.record?.id);
  assert.equal(env.mockProvider.getRecordedCalls().length, 1);

  // Different assumptions MUST trigger fresh verification instead of reusing cached result
  const resUniform = await env.engine.verifyClaimAgainstEvidence(env.agentAlpha, {
    claimId: claim.id,
    evidenceId: evidence.id,
    assumptions: ['Uniform random key access']
  });
  assert.equal(resUniform.ok, true);
  assert.equal(resUniform.deduplicated, false);
  assert.equal(resUniform.proposedRelationship, 'LIMITATION');
  assert.notEqual(resUniform.record?.id, resZipf.record?.id);
  assert.equal(env.mockProvider.getRecordedCalls().length, 2);

  const allCurrent = env.memoryService.getClaimVerificationsByClaimId(env.adminAlpha, claim.id);
  assert.equal(allCurrent.length, 2);
});

// ============================================================================
// 6. Transaction rollback preserves consistency if update lifecycle fails
// ============================================================================
test('6. Transaction rollback restores content, active claim links, associations, embeddings, and CURRENT verification on failure', async () => {
  const env = setupLifecycleTestEnv();

  const proposal = env.memoryService.createMemory(env.agentAlpha, {
    key: 'rollback.lifecycle.key',
    content: 'Original verified memory content.',
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    status: 'PENDING_APPROVAL',
    claims: [{ originalText: 'Original verified proposition.' }],
    evidence: [
      {
        sourceType: 'DOCUMENTATION',
        snippet: 'Supporting spec snippet.',
        relationship: 'SUPPORTS',
        targetClaimIndices: [0]
      }
    ]
  });

  const claim = env.memoryService.getClaimsByMemoryId(env.adminAlpha, proposal.id)[0]!;
  const evidence = env.memoryService.getEvidenceByMemoryId(env.adminAlpha, proposal.id)[0]!;
  env.mockProvider.enqueueCompletion(JSON.stringify({
    claimId: claim.id,
    evidenceId: evidence.id,
    proposedRelationship: 'SUPPORTS',
    outcome: 'PROPOSED',
    confidence: 0.9,
    explanation: 'Confirmed original proposition.'
  }));
  await env.engine.verifyProposalClaims(env.agentAlpha, proposal.id);

  const active = env.memoryService.decideProposal(env.adminAlpha, {
    memoryId: proposal.id,
    decision: 'APPROVE_NEW'
  });

  env.embeddingRepo.upsertEmbedding({
    memoryId: active.id,
    modelId: env.embeddingProvider.modelId,
    modelRevision: env.embeddingProvider.modelRevision,
    dimensions: env.embeddingProvider.dimensions,
    embedding: new Float32Array(env.embeddingProvider.dimensions).fill(1 / Math.sqrt(env.embeddingProvider.dimensions))
  });

  // Simulate failure after mandatory audit / inside updateMemory transaction
  const failingService = new MemoryService({
    memoryRepo: env.memoryRepo,
    auditRepo: env.auditRepo,
    taskRepo: env.taskRepo,
    authorizer: env.authorizer,
    hostAuthority: env.hostAuthority,
    embeddingRepo: env.embeddingRepo,
    embeddingJobRepo: env.embeddingJobRepo,
    embeddingProvider: env.embeddingProvider,
    _testPostAuditHook: () => {
      throw new Error('Simulated crash after update audit');
    }
  });

  assert.throws(
    () =>
      failingService.updateMemory(env.adminAlpha, active.id, {
        content: 'Uncommitted new content that must roll back.'
      }),
    /Simulated crash/
  );

  // Memory content, embeddings, ACTIVE links/associations, and CURRENT verification must all remain intact
  const currentMem = env.memoryService.getMemoryById(env.adminAlpha, active.id)!;
  assert.equal(currentMem.content, 'Original verified memory content.');
  assert.ok(env.embeddingRepo.getEmbedding(active.id, env.embeddingProvider.modelId, env.embeddingProvider.modelRevision));
  assert.equal(env.memoryService.getClaimsByMemoryId(env.adminAlpha, active.id).length, 1);
  assert.equal(env.memoryService.getClaimEvidenceAssociationsByMemoryId(env.adminAlpha, active.id).length, 1);
  const currentVerifs = env.memoryService.listClaimVerifications(env.adminAlpha, { memoryId: active.id });
  assert.equal(currentVerifs.length, 1);
  assert.equal(currentVerifs[0]!.status, 'CURRENT');
});

// ============================================================================
// 7. Authorization & cross-workspace isolation on historical/lifecycle APIs
// ============================================================================
test('7. Authorization and cross-workspace isolation hold for historical/stale verification and updateMemory guards', async () => {
  const env = setupLifecycleTestEnv();

  const alphaMem = env.memoryService.createMemory(env.agentAlpha, {
    key: 'alpha.scoped.lifecycle',
    content: 'Alpha confidential assertion.',
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    status: 'PENDING_APPROVAL',
    claims: [{ originalText: 'Alpha confidential assertion.' }],
    evidence: [
      {
        sourceType: 'DOCUMENTATION',
        snippet: 'Alpha spec evidence.',
        relationship: 'SUPPORTS',
        targetClaimIndices: [0]
      }
    ]
  });

  const claim = env.memoryService.getClaimsByMemoryId(env.adminAlpha, alphaMem.id)[0]!;
  const evidence = env.memoryService.getEvidenceByMemoryId(env.adminAlpha, alphaMem.id)[0]!;
  env.mockProvider.enqueueCompletion(JSON.stringify({
    claimId: claim.id,
    evidenceId: evidence.id,
    proposedRelationship: 'SUPPORTS',
    outcome: 'PROPOSED',
    confidence: 0.9,
    explanation: 'Alpha verified.'
  }));
  await env.engine.verifyProposalClaims(env.agentAlpha, alphaMem.id);
  const active = env.memoryService.decideProposal(env.adminAlpha, {
    memoryId: alphaMem.id,
    decision: 'APPROVE_NEW'
  });
  env.memoryService.updateMemory(env.adminAlpha, active.id, { content: 'Alpha updated content.' });

  // Cross-workspace historical reads must throw MemoryScopeViolationError
  assert.throws(
    () => env.memoryService.getClaimVerificationsByClaimId(env.adminBeta, claim.id, { includeStale: true }),
    (err) => err instanceof MemoryScopeViolationError
  );
  assert.throws(
    () => env.memoryService.getClaimVerificationsByEvidenceId(env.adminBeta, evidence.id, { includeStale: true }),
    (err) => err instanceof MemoryScopeViolationError
  );
  assert.throws(
    () => env.memoryService.getClaimEvidenceAssociationsByMemoryId(env.adminBeta, active.id, { includeInvalidated: true }),
    (err) => err instanceof MemoryScopeViolationError
  );

  // READ-only viewer cannot verify or updateMemory; AGENT cannot updateMemory
  await assert.rejects(
    () => env.engine.verifyProposalClaims(env.viewerAlpha, active.id),
    (err) => err instanceof SecurityViolationError
  );
  assert.throws(
    () => env.memoryService.updateMemory(env.agentAlpha, active.id, { content: 'Agent edit attempt.' }),
    (err) => err instanceof SecurityViolationError
  );

  // Viewer in Alpha CAN read historical stale verifications in Alpha safely
  const viewerStale = env.memoryService.getClaimVerificationsByEvidenceId(env.viewerAlpha, evidence.id, {
    includeStale: true
  });
  assert.equal(viewerStale.length, 1);
  assert.equal(viewerStale[0]!.status, 'STALE');
});
