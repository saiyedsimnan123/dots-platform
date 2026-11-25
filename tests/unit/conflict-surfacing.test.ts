/**
 * Next-Generation Dots AI Platform - Conflict Surfacing Tests
 * Phase 4D.3D.4C.4: Claim/Evidence Conflict Detection, Lifecycle Integrity,
 * Qualifier/Assumption Isolation, HTTP REST API & CLI Integration
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
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
import { EvidenceVerificationEngine } from '../../src/memory/evidence-verifier.ts';
import { DotsRuntime, DotsHttpServer, runCli } from '../../src/index.ts';
import type { ClaimConflictSummary, ScopeIdentifier } from '../../src/domain/types.ts';
import {
  MemoryNotFoundError,
  MemoryScopeViolationError,
  ValidationError
} from '../../src/domain/errors.ts';

function setupConflictTestEnv() {
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
    goal: 'Conflict surfacing verification',
    scope: scopeAlpha,
    principalId: 'admin-alpha'
  });
  const taskBeta = hostAuthority.createTask(taskRepo, {
    goal: 'Beta conflict isolation',
    scope: scopeBeta,
    principalId: 'admin-beta'
  });

  const agentAlpha = authorizer.authorizeAgent({
    taskId: taskAlpha.id,
    agentId: 'research-agent-alpha'
  });
  const agentBeta = authorizer.authorizeAgent({
    taskId: taskBeta.id,
    agentId: 'research-agent-beta'
  });

  const mockProvider = new MockModelProvider('mock-conflict-verifier');
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
    agentBeta,
    mockProvider,
    engine
  };
}

// ============================================================================
// 1. Explicit CONTRADICTS relationship surfacing & provenance preservation
// ============================================================================
test('1. Explicit CONTRADICTS surfaces conflict with provenance and never mutates memory states', () => {
  const env = setupConflictTestEnv();

  const claimText = 'PostgreSQL connection pool maxConnections defaults to 20 in production.';

  const proposal1 = env.memoryService.createMemory(env.agentAlpha, {
    key: 'db.pool.v1',
    content: claimText,
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    status: 'PENDING_APPROVAL',
    claims: [{ originalText: claimText }],
    evidence: [
      {
        sourceType: 'DOCUMENTATION',
        sourceUrl: 'https://docs.example.org/db/v1',
        sourceTitle: 'DB Docs v1',
        snippet: 'Default maxConnections is set to 20.',
        relationship: 'SUPPORTS',
        targetClaimIndices: [0]
      }
    ]
  });
  const activeMem = env.memoryService.decideProposal(env.adminAlpha, {
    memoryId: proposal1.id,
    decision: 'APPROVE_NEW'
  });

  const pendingContradicting = env.memoryService.createMemory(env.agentAlpha, {
    key: 'db.pool.audit',
    content: 'Production config uses maxConnections = 50 rather than 20.',
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    status: 'PENDING_APPROVAL',
    claims: [{ originalText: claimText }],
    evidence: [
      {
        sourceType: 'TOOL_EXECUTION',
        sourceUrl: 'https://ops.example.org/runtime-config',
        sourceTitle: 'Runtime Pool Dump',
        snippet: 'Observed active production pool size configured to 50 connections.',
        relationship: 'CONTRADICTS',
        targetClaimIndices: [0]
      }
    ]
  });

  const claims = env.memoryService.getClaimsByMemoryId(env.adminAlpha, activeMem.id);
  assert.equal(claims.length, 1);
  const claimId = claims[0]!.id;

  const listResult = env.memoryService.listClaimConflicts(env.adminAlpha);
  assert.equal(listResult.includeHistorical, false);
  assert.equal(listResult.total, 1);
  assert.equal(listResult.conflicts.length, 1);

  const conflict = listResult.conflicts[0]!;
  assert.ok(conflict.conflictId.length > 0);
  assert.equal(conflict.conflictType, 'EXPLICIT_CONTRADICTION');
  assert.equal(conflict.isHistorical, false);
  assert.equal(conflict.claim.id, claimId);
  assert.equal(conflict.claim.originalText, claimText);
  assert.equal(conflict.memories.length, 2);
  assert.equal(conflict.supportingEvidence.length, 1);
  assert.equal(conflict.contradictingEvidence.length, 1);
  assert.equal(conflict.limitationEvidence.length, 0);
  assert.equal(conflict.supportingEvidence[0]!.memoryId, activeMem.id);
  assert.equal(conflict.supportingEvidence[0]!.relationship, 'SUPPORTS');
  assert.equal(conflict.contradictingEvidence[0]!.memoryId, pendingContradicting.id);
  assert.equal(conflict.contradictingEvidence[0]!.relationship, 'CONTRADICTS');
  assert.ok(conflict.detectedAt);

  // Per-memory and per-claim helpers match
  const byMem1 = env.memoryService.getConflictsByMemoryId(env.adminAlpha, activeMem.id);
  assert.equal(byMem1.total, 1);
  assert.equal(byMem1.conflicts[0]!.conflictId, conflict.conflictId);

  const byClaim = env.memoryService.getConflictByClaimId(env.adminAlpha, claimId);
  assert.ok(byClaim);
  assert.equal(byClaim.conflictId, conflict.conflictId);

  // Filter by conflictType works
  assert.equal(
    env.memoryService.listClaimConflicts(env.adminAlpha, { conflictType: 'EXPLICIT_CONTRADICTION' }).total,
    1
  );
  assert.equal(
    env.memoryService.listClaimConflicts(env.adminAlpha, { conflictType: 'VERIFIED_CONTRADICTION' }).total,
    0
  );

  // Lifecycle states were NOT mutated automatically
  assert.equal(env.memoryService.getMemoryById(env.adminAlpha, activeMem.id)?.status, 'ACTIVE');
  assert.equal(env.memoryService.getMemoryById(env.adminAlpha, pendingContradicting.id)?.status, 'PENDING_APPROVAL');
});

// ============================================================================
// 2. Structured verifier CONTRADICTS and opposing verifications surface conflicts
// ============================================================================
test('2. Structured verifier CONTRADICTS and opposing CURRENT verifications surface conflicts cleanly', async () => {
  const env = setupConflictTestEnv();

  // Case A: Only SUPPORTS evidence links, verified by structured engine as SUPPORTS vs CONTRADICTS
  const propA = env.memoryService.createMemory(env.agentAlpha, {
    key: 'latency.slo.claim',
    content: 'P99 API latency stays under 50ms at 1k RPS.',
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    status: 'PENDING_APPROVAL',
    claims: [{ originalText: 'P99 API latency stays under 50ms at 1k RPS.' }],
    evidence: [
      {
        sourceType: 'TOOL_EXECUTION',
        sourceUrl: 'https://bench.example.org/run-1',
        snippet: 'Run 1 observed P99 = 38ms at 1000 RPS.',
        relationship: 'SUPPORTS',
        targetClaimIndices: [0]
      },
      {
        sourceType: 'TOOL_EXECUTION',
        sourceUrl: 'https://bench.example.org/run-2',
        snippet: 'Run 2 observed P99 = 140ms at 1000 RPS under identical cluster config.',
        relationship: 'SUPPORTS',
        targetClaimIndices: [0]
      }
    ]
  });

  const claim = env.memoryService.getClaimsByMemoryId(env.adminAlpha, propA.id)[0]!;
  const evList = env.memoryService.getEvidenceByMemoryId(env.adminAlpha, propA.id);
  assert.equal(evList.length, 2);

  env.mockProvider.enqueueCompletion(
    JSON.stringify({
      claimId: claim.id,
      evidenceId: evList[0]!.id,
      proposedRelationship: 'SUPPORTS',
      outcome: 'PROPOSED',
      confidence: 0.91,
      explanation: 'Run 1 confirms P99 < 50ms.'
    })
  );
  await env.engine.verifyClaimAgainstEvidence(env.agentAlpha, {
    claimId: claim.id,
    evidenceId: evList[0]!.id,
    assumptions: ['Cluster v2 at 1000 RPS']
  });

  env.mockProvider.enqueueCompletion(
    JSON.stringify({
      claimId: claim.id,
      evidenceId: evList[1]!.id,
      proposedRelationship: 'CONTRADICTS',
      outcome: 'PROPOSED',
      confidence: 0.93,
      explanation: 'Run 2 directly contradicts P99 < 50ms with 140ms measurement.'
    })
  );
  await env.engine.verifyClaimAgainstEvidence(env.agentAlpha, {
    claimId: claim.id,
    evidenceId: evList[1]!.id,
    assumptions: ['  cluster  v2 at 1000 rps ']
  });

  const conflicts = env.memoryService.listClaimConflicts(env.adminAlpha);
  assert.equal(conflicts.total, 1);
  const c = conflicts.conflicts[0]!;
  assert.equal(c.conflictType, 'OPPOSING_VERIFICATIONS');
  assert.equal(c.supportingEvidence.length, 1);
  assert.equal(c.contradictingEvidence.length, 1);
  assert.equal(c.supportingEvidence[0]!.verifications[0]!.proposedRelationship, 'SUPPORTS');
  assert.equal(c.contradictingEvidence[0]!.verifications[0]!.proposedRelationship, 'CONTRADICTS');
  assert.ok(c.assumptions.length >= 1);

  // Case B: Single evidence verified CONTRADICTS without opposing SUPPORTS -> VERIFIED_CONTRADICTION
  const envB = setupConflictTestEnv();
  const propB = envB.memoryService.createMemory(envB.agentAlpha, {
    key: 'single.verified.contradict',
    content: 'Retry backoff disables jitter.',
    category: 'PROJECT_FACT',
    scopeType: envB.scopeAlpha.scopeType,
    scopeId: envB.scopeAlpha.scopeId,
    status: 'PENDING_APPROVAL',
    claims: [{ originalText: 'Retry backoff disables jitter.' }],
    evidence: [
      {
        sourceType: 'DOCUMENTATION',
        sourceUrl: 'https://docs.example.org/retries',
        snippet: 'Backoff multiplies random jitter in [0.8, 1.2].',
        relationship: 'SUPPORTS',
        targetClaimIndices: [0]
      }
    ]
  });
  const claimB = envB.memoryService.getClaimsByMemoryId(envB.adminAlpha, propB.id)[0]!;
  const evB = envB.memoryService.getEvidenceByMemoryId(envB.adminAlpha, propB.id)[0]!;
  envB.mockProvider.enqueueCompletion(
    JSON.stringify({
      claimId: claimB.id,
      evidenceId: evB.id,
      proposedRelationship: 'CONTRADICTS',
      outcome: 'PROPOSED',
      confidence: 0.95,
      explanation: 'Evidence shows jitter is enabled.'
    })
  );
  await envB.engine.verifyProposalClaims(envB.agentAlpha, propB.id);

  const resB = envB.memoryService.listClaimConflicts(envB.adminAlpha);
  assert.equal(resB.total, 1);
  assert.equal(resB.conflicts[0]!.conflictType, 'VERIFIED_CONTRADICTION');
});

// ============================================================================
// 3. LIMITATION, INSUFFICIENT, AMBIGUOUS, and negation wording do NOT create conflicts
// ============================================================================
test('3. LIMITATION, INSUFFICIENT, AMBIGUOUS, and keyword negation never produce false-positive conflicts', async () => {
  const env = setupConflictTestEnv();

  const prop = env.memoryService.createMemory(env.agentAlpha, {
    key: 'no.false.positives',
    content: 'TLS verification does not fail under rotated certificates and never ignores expiry.',
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    status: 'PENDING_APPROVAL',
    claims: [{ originalText: 'TLS verification never ignores certificate expiry.' }],
    evidence: [
      {
        sourceType: 'DOCUMENTATION',
        sourceUrl: 'https://docs.example.org/tls',
        snippet: 'Does not bypass checks; refutes earlier rumors and never disables validation.',
        relationship: 'SUPPORTS',
        targetClaimIndices: [0]
      },
      {
        sourceType: 'DOCUMENTATION',
        sourceUrl: 'https://docs.example.org/tls-limits',
        snippet: 'OCSP stapling offline cache window is bounded to 1 hour.',
        relationship: 'LIMITATION',
        targetClaimIndices: [0]
      },
      {
        sourceType: 'WEB_RESEARCH',
        sourceUrl: 'https://blog.example.org/tls-notes',
        snippet: 'No mention of clock skew handling in staging logs.',
        relationship: 'SUPPORTS',
        targetClaimIndices: [0]
      },
      {
        sourceType: 'WEB_RESEARCH',
        sourceUrl: 'https://blog.example.org/tls-ambig',
        snippet: 'Unclear whether dev container uses mock cert store.',
        relationship: 'SUPPORTS',
        targetClaimIndices: [0]
      }
    ]
  });

  const claim = env.memoryService.getClaimsByMemoryId(env.adminAlpha, prop.id)[0]!;
  const ev = env.memoryService.getEvidenceByMemoryId(env.adminAlpha, prop.id);
  assert.equal(ev.length, 4);

  // Verify the 4 evidence entries with SUPPORTS, LIMITATION, INSUFFICIENT, AMBIGUOUS
  const verifierOutcomes = [
    { evidenceId: ev[0]!.id, proposedRelationship: 'SUPPORTS', outcome: 'PROPOSED' },
    { evidenceId: ev[1]!.id, proposedRelationship: 'LIMITATION', outcome: 'PROPOSED' },
    { evidenceId: ev[2]!.id, proposedRelationship: 'INSUFFICIENT', outcome: 'INSUFFICIENT' },
    { evidenceId: ev[3]!.id, proposedRelationship: 'AMBIGUOUS', outcome: 'AMBIGUOUS' }
  ];
  for (const item of verifierOutcomes) {
    env.mockProvider.enqueueCompletion(
      JSON.stringify({
        claimId: claim.id,
        evidenceId: item.evidenceId,
        proposedRelationship: item.proposedRelationship,
        outcome: item.outcome,
        confidence: 0.75,
        explanation: `Classified as ${item.proposedRelationship}`
      })
    );
  }
  await env.engine.verifyProposalClaims(env.agentAlpha, prop.id);

  const conflicts = env.memoryService.listClaimConflicts(env.adminAlpha);
  assert.equal(conflicts.total, 0);
  assert.deepEqual(conflicts.conflicts, []);
  assert.equal(env.memoryService.getConflictByClaimId(env.adminAlpha, claim.id), null);
});

// ============================================================================
// 4. Qualifier isolation & assumption mismatch checks prevent cross-condition conflicts
// ============================================================================
test('4. Differing qualifiers stay distinct and mismatched experimental assumptions do not cross-conflict', async () => {
  const env = setupConflictTestEnv();

  // Same original text, different qualifiers -> distinct claim identities
  const propPg = env.memoryService.createMemory(env.agentAlpha, {
    key: 'throughput.pg',
    content: 'Throughput exceeds 10k ops/sec (PostgreSQL 16).',
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    status: 'PENDING_APPROVAL',
    claims: [{ originalText: 'Throughput exceeds 10k ops/sec', qualifier: 'PostgreSQL 16, NVMe SSD' }],
    evidence: [
      {
        sourceType: 'TOOL_EXECUTION',
        snippet: 'Measured 12k ops/sec on PostgreSQL 16.',
        relationship: 'SUPPORTS',
        targetClaimIndices: [0]
      }
    ]
  });

  const propSqlite = env.memoryService.createMemory(env.agentAlpha, {
    key: 'throughput.sqlite',
    content: 'Throughput exceeds 10k ops/sec (SQLite single writer).',
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    status: 'PENDING_APPROVAL',
    claims: [{ originalText: 'Throughput exceeds 10k ops/sec', qualifier: 'SQLite single writer' }],
    evidence: [
      {
        sourceType: 'TOOL_EXECUTION',
        snippet: 'Only valid for read-heavy workload.',
        relationship: 'LIMITATION',
        targetClaimIndices: [0]
      }
    ]
  });

  const pgClaims = env.memoryService.getClaimsByMemoryId(env.adminAlpha, propPg.id);
  const sqliteClaims = env.memoryService.getClaimsByMemoryId(env.adminAlpha, propSqlite.id);
  assert.notEqual(pgClaims[0]!.id, sqliteClaims[0]!.id);
  assert.equal(env.memoryService.listClaimConflicts(env.adminAlpha).total, 0);

  // Explicit CONTRADICTS downgraded to LIMITATION with a different condition on another claim?
  // Note: If two SUPPORTS associations have opposing verifications (one SUPPORTS, one LIMITATION)
  // under differing assumptions, ZERO conflict surfaces.
  // And even if one verifies SUPPORTS under Assumption A while another verifies LIMITATION under Assumption B,
  // zero conflict surfaces and assumption metadata is retained when a real conflict exists.
  const propAssump = env.memoryService.createMemory(env.agentAlpha, {
    key: 'cache.skew',
    content: 'Read cache avoids DB saturation.',
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    status: 'PENDING_APPROVAL',
    claims: [{ originalText: 'Read cache avoids DB saturation.', qualifier: 'Tier-1 API' }],
    evidence: [
      {
        sourceType: 'TOOL_EXECUTION',
        snippet: 'Zipfian reads achieve 97% cache hit rate.',
        relationship: 'SUPPORTS',
        targetClaimIndices: [0]
      },
      {
        sourceType: 'TOOL_EXECUTION',
        snippet: 'Uniform random reads exceed cache budget at scale.',
        relationship: 'LIMITATION',
        targetClaimIndices: [0]
      }
    ]
  });
  const skewClaim = env.memoryService.getClaimsByMemoryId(env.adminAlpha, propAssump.id)[0]!;
  const skewEv = env.memoryService.getEvidenceByMemoryId(env.adminAlpha, propAssump.id);
  env.mockProvider.enqueueCompletion(
    JSON.stringify({
      claimId: skewClaim.id,
      evidenceId: skewEv[0]!.id,
      proposedRelationship: 'SUPPORTS',
      outcome: 'PROPOSED',
      confidence: 0.9,
      explanation: 'Holds for Zipfian reads.'
    })
  );
  await env.engine.verifyClaimAgainstEvidence(env.agentAlpha, {
    claimId: skewClaim.id,
    evidenceId: skewEv[0]!.id,
    assumptions: ['Zipfian access distribution']
  });
  env.mockProvider.enqueueCompletion(
    JSON.stringify({
      claimId: skewClaim.id,
      evidenceId: skewEv[1]!.id,
      proposedRelationship: 'LIMITATION',
      outcome: 'PROPOSED',
      confidence: 0.88,
      explanation: 'Scoped limitation for uniform random keys.'
    })
  );
  await env.engine.verifyClaimAgainstEvidence(env.agentAlpha, {
    claimId: skewClaim.id,
    evidenceId: skewEv[1]!.id,
    assumptions: ['Uniform random key access']
  });

  assert.equal(env.memoryService.listClaimConflicts(env.adminAlpha).total, 0);
});

// ============================================================================
// 5. Edited ACTIVE memory invalidates old conflict in current view & keeps historical view
// ============================================================================
test('5. Editing ACTIVE memory content clears stale current conflict while includeHistorical exposes history', async () => {
  const env = setupConflictTestEnv();
  const claimText = 'Session cookies expire after 24 hours.';

  const p1 = env.memoryService.createMemory(env.agentAlpha, {
    key: 'session.ttl.spec',
    content: claimText,
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    status: 'PENDING_APPROVAL',
    claims: [{ originalText: claimText }],
    evidence: [
      {
        sourceType: 'DOCUMENTATION',
        snippet: 'Auth spec sets maxAge = 86400s.',
        relationship: 'SUPPORTS',
        targetClaimIndices: [0]
      }
    ]
  });
  const m1 = env.memoryService.decideProposal(env.adminAlpha, { memoryId: p1.id, decision: 'APPROVE_NEW' });

  const p2 = env.memoryService.createMemory(env.agentAlpha, {
    key: 'session.ttl.impl',
    content: 'Auth middleware actually expires cookies after 1 hour.',
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    status: 'PENDING_APPROVAL',
    claims: [{ originalText: claimText }],
    evidence: [
      {
        sourceType: 'TOOL_EXECUTION',
        snippet: 'Cookie header returned Max-Age=3600.',
        relationship: 'CONTRADICTS',
        targetClaimIndices: [0]
      }
    ]
  });
  const m2 = env.memoryService.decideProposal(env.adminAlpha, { memoryId: p2.id, decision: 'APPROVE_NEW' });

  const claimId = env.memoryService.getClaimsByMemoryId(env.adminAlpha, m1.id)[0]!.id;
  assert.equal(env.memoryService.listClaimConflicts(env.adminAlpha).total, 1);

  // Edit m2 content -> invalidates m2's claim link & CONTRADICTS association atomically
  env.memoryService.updateMemory(env.adminAlpha, m2.id, {
    content: 'Auth middleware now updated to match 24h TTL.'
  });

  // Current view must NOT surface stale conflict
  const current = env.memoryService.listClaimConflicts(env.adminAlpha);
  assert.equal(current.total, 0);
  assert.equal(env.memoryService.getConflictsByMemoryId(env.adminAlpha, m1.id).total, 0);
  assert.equal(env.memoryService.getConflictByClaimId(env.adminAlpha, claimId), null);

  // Historical view surfaces invalidated conflict with explicit provenance
  const hist = env.memoryService.listClaimConflicts(env.adminAlpha, { includeHistorical: true });
  assert.equal(hist.includeHistorical, true);
  assert.equal(hist.total, 1);
  assert.equal(hist.conflicts[0]!.isHistorical, true);
  const mem2Origin = hist.conflicts[0]!.memories.find((m) => m.memoryId === m2.id);
  assert.ok(mem2Origin);
  assert.equal(mem2Origin.linkStatus, 'INVALIDATED');
  assert.equal(mem2Origin.invalidationReason, 'MEMORY_CONTENT_UPDATED');
});

// ============================================================================
// 6. ARCHIVED (rejected proposal) and SUPERSEDED memories excluded from current conflicts
// ============================================================================
test('6. Rejected ARCHIVED proposals and SUPERSEDED memories are excluded from current conflicts but shown historically', () => {
  const env = setupConflictTestEnv();
  const claimText = 'Queue worker concurrency defaults to 8.';

  const pActive = env.memoryService.createMemory(env.agentAlpha, {
    key: 'queue.concurrency.active',
    content: claimText,
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    status: 'PENDING_APPROVAL',
    claims: [{ originalText: claimText }],
    evidence: [
      {
        sourceType: 'DOCUMENTATION',
        snippet: 'Worker defaults to 8 threads.',
        relationship: 'SUPPORTS',
        targetClaimIndices: [0]
      }
    ]
  });
  const mActive = env.memoryService.decideProposal(env.adminAlpha, {
    memoryId: pActive.id,
    decision: 'APPROVE_NEW'
  });

  const pRejected = env.memoryService.createMemory(env.agentAlpha, {
    key: 'queue.concurrency.bad',
    content: 'Unverified report claiming concurrency is 2.',
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    status: 'PENDING_APPROVAL',
    claims: [{ originalText: claimText }],
    evidence: [
      {
        sourceType: 'WEB_RESEARCH',
        snippet: 'Old forum post mentions concurrency=2.',
        relationship: 'CONTRADICTS',
        targetClaimIndices: [0]
      }
    ]
  });

  // Before rejection, active + pending contradict -> surfaced in current view
  assert.equal(env.memoryService.listClaimConflicts(env.adminAlpha).total, 1);

  // Reject -> becomes ARCHIVED
  const rejected = env.memoryService.decideProposal(env.adminAlpha, {
    memoryId: pRejected.id,
    decision: 'REJECT',
    reason: 'Outdated forum post'
  });
  assert.equal(rejected.status, 'ARCHIVED');

  // Current view no longer reports conflict
  assert.equal(env.memoryService.listClaimConflicts(env.adminAlpha).total, 0);
  assert.equal(env.memoryService.getConflictsByMemoryId(env.adminAlpha, mActive.id).total, 0);

  // Historical view surfaces it
  const histRejected = env.memoryService.listClaimConflicts(env.adminAlpha, { includeHistorical: true });
  assert.equal(histRejected.total, 1);
  assert.equal(histRejected.conflicts[0]!.isHistorical, true);

  // Now supersede mOld with a fresh contradiction-free memory & test SUPERSEDED exclusion
  const claim2 = 'Batch flush interval is 500ms.';
  const pOld = env.memoryService.createMemory(env.agentAlpha, {
    key: 'batch.flush.policy',
    content: claim2,
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    status: 'PENDING_APPROVAL',
    claims: [{ originalText: claim2 }],
    evidence: [
      {
        sourceType: 'TOOL_EXECUTION',
        snippet: 'Old telemetry showed 5000ms.',
        relationship: 'CONTRADICTS',
        targetClaimIndices: [0]
      }
    ]
  });
  const mOld = env.memoryService.decideProposal(env.adminAlpha, { memoryId: pOld.id, decision: 'APPROVE_NEW' });
  const claim2Id = env.memoryService.getClaimsByMemoryId(env.adminAlpha, mOld.id)[0]!.id;
  assert.ok(env.memoryService.getConflictByClaimId(env.adminAlpha, claim2Id));

  const pNew = env.memoryService.createMemory(env.agentAlpha, {
    key: 'batch.flush.policy',
    content: 'Batch flush interval confirmed at 500ms.',
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    status: 'PENDING_APPROVAL',
    claims: [{ originalText: claim2 }],
    evidence: [
      {
        sourceType: 'DOCUMENTATION',
        snippet: 'Confirmed 500ms flush timer in v2.',
        relationship: 'SUPPORTS',
        targetClaimIndices: [0]
      }
    ]
  });
  const mNew = env.memoryService.decideProposal(env.adminAlpha, {
    memoryId: pNew.id,
    decision: 'APPROVE_AND_SUPERSEDE'
  });
  assert.equal(mNew.status, 'ACTIVE');
  assert.equal(env.memoryService.getMemoryById(env.adminAlpha, mOld.id)?.status, 'SUPERSEDED');

  // Current view has zero conflict on claim2 because mOld is SUPERSEDED
  assert.equal(env.memoryService.getConflictByClaimId(env.adminAlpha, claim2Id), null);
  const histAll = env.memoryService.listClaimConflicts(env.adminAlpha, { includeHistorical: true });
  const histClaim2 = histAll.conflicts.find((c) => c.claim.id === claim2Id);
  assert.ok(histClaim2);
  assert.equal(histClaim2.isHistorical, true);
});

// ============================================================================
// 7. Duplicate evidence & repeated verifications group cleanly per evidenceId
// ============================================================================
test('7. Repeated verifications on the same evidence group without duplicate ConflictEvidenceReference entries', async () => {
  const env = setupConflictTestEnv();
  const claimText = 'Eviction policy uses LRU.';

  const prop = env.memoryService.createMemory(env.agentAlpha, {
    key: 'cache.eviction',
    content: claimText,
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    status: 'PENDING_APPROVAL',
    claims: [{ originalText: claimText }],
    evidence: [
      {
        sourceType: 'DOCUMENTATION',
        sourceUrl: 'https://docs.example.org/cache-lru',
        snippet: 'Configured FIFO instead of LRU.',
        relationship: 'CONTRADICTS',
        targetClaimIndices: [0]
      }
    ]
  });

  const claim = env.memoryService.getClaimsByMemoryId(env.adminAlpha, prop.id)[0]!;
  const evidence = env.memoryService.getEvidenceByMemoryId(env.adminAlpha, prop.id)[0]!;

  env.mockProvider.enqueueCompletion(
    JSON.stringify({
      claimId: claim.id,
      evidenceId: evidence.id,
      proposedRelationship: 'CONTRADICTS',
      outcome: 'PROPOSED',
      confidence: 0.92,
      explanation: 'Verified FIFO under L1 cache.'
    })
  );
  await env.engine.verifyClaimAgainstEvidence(env.agentAlpha, {
    claimId: claim.id,
    evidenceId: evidence.id,
    assumptions: ['L1 cache tier']
  });

  env.mockProvider.enqueueCompletion(
    JSON.stringify({
      claimId: claim.id,
      evidenceId: evidence.id,
      proposedRelationship: 'CONTRADICTS',
      outcome: 'PROPOSED',
      confidence: 0.89,
      explanation: 'Verified FIFO under L2 cache.'
    })
  );
  await env.engine.verifyClaimAgainstEvidence(env.agentAlpha, {
    claimId: claim.id,
    evidenceId: evidence.id,
    assumptions: ['L2 cache tier']
  });

  const res = env.memoryService.listClaimConflicts(env.adminAlpha);
  assert.equal(res.total, 1);
  assert.equal(res.conflicts[0]!.contradictingEvidence.length, 1);
  assert.equal(res.conflicts[0]!.contradictingEvidence[0]!.evidenceId, evidence.id);
  assert.equal(res.conflicts[0]!.contradictingEvidence[0]!.verifications.length, 2);
  assert.deepEqual([...res.conflicts[0]!.assumptions].sort(), ['L1 cache tier', 'L2 cache tier']);
});

// ============================================================================
// 8. Security, scope isolation, READ authorization, and validation failures
// ============================================================================
test('8. Enforces READ authorization, workspace isolation, audit denial logs, and input validation', () => {
  const env = setupConflictTestEnv();

  const propAlpha = env.memoryService.createMemory(env.agentAlpha, {
    key: 'alpha.conflict',
    content: 'Feature flag X is enabled.',
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    status: 'PENDING_APPROVAL',
    claims: [{ originalText: 'Feature flag X is enabled.' }],
    evidence: [
      {
        sourceType: 'TOOL_EXECUTION',
        snippet: 'Flag X read as false in staging.',
        relationship: 'CONTRADICTS',
        targetClaimIndices: [0]
      }
    ]
  });
  const alphaClaimId = env.memoryService.getClaimsByMemoryId(env.adminAlpha, propAlpha.id)[0]!.id;

  // VIEWER with READ access in ws-alpha succeeds
  const viewerRes = env.memoryService.listClaimConflicts(env.viewerAlpha);
  assert.equal(viewerRes.total, 1);

  // Cross-workspace callers (human adminBeta and task-bound agentBeta) cannot inspect ws-alpha conflicts
  assert.equal(env.memoryService.listClaimConflicts(env.adminBeta).total, 0);
  assert.throws(
    () => env.memoryService.getConflictsByMemoryId(env.adminBeta, propAlpha.id),
    MemoryScopeViolationError
  );
  assert.throws(
    () => env.memoryService.getConflictByClaimId(env.adminBeta, alphaClaimId),
    MemoryScopeViolationError
  );
  assert.throws(
    () => env.memoryService.getConflictsByMemoryId(env.agentBeta, propAlpha.id),
    MemoryScopeViolationError
  );
  assert.throws(
    () => env.memoryService.getConflictByClaimId(env.agentBeta, alphaClaimId),
    MemoryScopeViolationError
  );

  // Missing memory throws MemoryNotFoundError
  assert.throws(
    () => env.memoryService.getConflictsByMemoryId(env.adminAlpha, 'missing-mem-id'),
    MemoryNotFoundError
  );

  const denialLogs = env.auditRepo
    .getEventsByTaskId(env.taskBeta.id)
    .filter((ev) => ev.eventType === 'MEMORY_ACCESS_DENIED');
  assert.ok(denialLogs.length >= 2);

  // Validation failures fail closed
  assert.throws(
    () => env.memoryService.listClaimConflicts(env.adminAlpha, { limit: 0 }),
    ValidationError
  );
  assert.throws(
    () => env.memoryService.listClaimConflicts(env.adminAlpha, { limit: 201 }),
    ValidationError
  );
  assert.throws(
    () => env.memoryService.listClaimConflicts(env.adminAlpha, { offset: -1 }),
    ValidationError
  );
  assert.throws(
    () => env.memoryService.listClaimConflicts(env.adminAlpha, { conflictType: 'INVALID' as never }),
    ValidationError
  );
  assert.throws(
    () => env.memoryService.listClaimConflicts(env.adminAlpha, { includeHistorical: 'true' as never }),
    ValidationError
  );
});

// ============================================================================
// 9. End-to-end HTTP REST API & CLI integration (local + remote)
// ============================================================================
test('9. HTTP REST API and CLI memory conflicts work end-to-end with scope/validation enforcement', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'dots-conflicts-'));
  const dbPath = join(dir, 'dots.db');
  const ADMIN_ALPHA = 'admin-alpha-secret-token-12345';
  const VIEWER_ALPHA = 'viewer-alpha-secret-token-12345';
  const ADMIN_BETA = 'admin-beta-secret-token-12345';

  const tokens = [
    {
      token: ADMIN_ALPHA,
      principalId: 'alice-alpha',
      role: 'ADMIN' as const,
      permittedScopes: [{ scopeType: 'WORKSPACE' as const, scopeId: 'ws-alpha' }]
    },
    {
      token: VIEWER_ALPHA,
      principalId: 'carol-alpha',
      role: 'VIEWER' as const,
      permittedScopes: [{ scopeType: 'WORKSPACE' as const, scopeId: 'ws-alpha' }]
    },
    {
      token: ADMIN_BETA,
      principalId: 'dave-beta',
      role: 'ADMIN' as const,
      permittedScopes: [{ scopeType: 'WORKSPACE' as const, scopeId: 'ws-beta' }]
    }
  ];

  const runtime = new DotsRuntime({
    dbPath,
    workspaceRoot: dir,
    host: '127.0.0.1',
    port: 0,
    silentLogs: true,
    enableScheduler: false,
    autoApproveTier2: false,
    modelProvider: new MockModelProvider(),
    tokens
  });

  const server = new DotsHttpServer(runtime);
  let startedUrl = '';

  try {
    const adminCtx = runtime.authorizer.authorizeUser({
      credentials: ADMIN_ALPHA,
      requestedScope: { scopeType: 'WORKSPACE', scopeId: 'ws-alpha' }
    });

    const p1 = runtime.memoryService.createMemory(adminCtx, {
      key: 'api.rate.limit',
      content: 'Public API rate limit is 100 req/min.',
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: 'ws-alpha',
      status: 'PENDING_APPROVAL',
      claims: [{ originalText: 'Public API rate limit is 100 req/min.' }],
      evidence: [
        {
          sourceType: 'DOCUMENTATION',
          snippet: 'API gateway enforces 25 req/min per token.',
          relationship: 'CONTRADICTS',
          targetClaimIndices: [0]
        }
      ]
    });

    const started = await server.start();
    startedUrl = started.url;

    // 1. Viewer GET /api/memories/conflicts succeeds
    const listRes = await fetch(`${startedUrl}/api/memories/conflicts`, {
      headers: { Authorization: `Bearer ${VIEWER_ALPHA}` }
    });
    assert.equal(listRes.status, 200);
    const listBody = (await listRes.json()) as {
      conflicts: ClaimConflictSummary[];
      total: number;
      includeHistorical: boolean;
    };
    assert.equal(listBody.total, 1);
    assert.equal(listBody.includeHistorical, false);
    assert.equal(listBody.conflicts[0]!.conflictType, 'EXPLICIT_CONTRADICTION');

    // 2. GET /api/memories/:id/conflicts succeeds for ws-alpha and rejects ws-beta with 403
    const byMemRes = await fetch(`${startedUrl}/api/memories/${p1.id}/conflicts`, {
      headers: { Authorization: `Bearer ${ADMIN_ALPHA}` }
    });
    assert.equal(byMemRes.status, 200);
    const byMemBody = (await byMemRes.json()) as { memoryId: string; total: number };
    assert.equal(byMemBody.memoryId, p1.id);
    assert.equal(byMemBody.total, 1);

    const crossScopeRes = await fetch(`${startedUrl}/api/memories/${p1.id}/conflicts`, {
      headers: { Authorization: `Bearer ${ADMIN_BETA}` }
    });
    assert.equal(crossScopeRes.status, 403);

    const notFoundRes = await fetch(`${startedUrl}/api/memories/does-not-exist/conflicts`, {
      headers: { Authorization: `Bearer ${ADMIN_ALPHA}` }
    });
    assert.equal(notFoundRes.status, 404);

    // 3. Invalid query params return 400
    const badLimitRes = await fetch(`${startedUrl}/api/memories/conflicts?limit=999`, {
      headers: { Authorization: `Bearer ${ADMIN_ALPHA}` }
    });
    assert.equal(badLimitRes.status, 400);

    const badTypeRes = await fetch(`${startedUrl}/api/memories/conflicts?conflictType=INVALID`, {
      headers: { Authorization: `Bearer ${ADMIN_ALPHA}` }
    });
    assert.equal(badTypeRes.status, 400);

    // 4. Reject proposal -> disappears from current HTTP endpoint, present with ?includeHistorical=true
    runtime.memoryService.decideProposal(adminCtx, {
      memoryId: p1.id,
      decision: 'REJECT',
      reason: 'Superseded by gateway audit'
    });

    const curAfterReject = await fetch(`${startedUrl}/api/memories/conflicts`, {
      headers: { Authorization: `Bearer ${ADMIN_ALPHA}` }
    });
    assert.equal(curAfterReject.status, 200);
    assert.equal(((await curAfterReject.json()) as { total: number }).total, 0);

    const histHttp = await fetch(`${startedUrl}/api/memories/conflicts?includeHistorical=true`, {
      headers: { Authorization: `Bearer ${ADMIN_ALPHA}` }
    });
    assert.equal(histHttp.status, 200);
    const histBody = (await histHttp.json()) as {
      total: number;
      includeHistorical: boolean;
      conflicts: ClaimConflictSummary[];
    };
    assert.equal(histBody.total, 1);
    assert.equal(histBody.includeHistorical, true);
    assert.equal(histBody.conflicts[0]!.isHistorical, true);

    // 5. CLI remote mode
    const remoteOut: string[] = [];
    const remoteErr: string[] = [];
    const remoteCode = await runCli(
      [
        '--server',
        startedUrl,
        '--token',
        VIEWER_ALPHA,
        '--json',
        'memory',
        'conflicts',
        '--memory-id',
        p1.id,
        '--include-historical'
      ],
      {
        stdout: (line) => remoteOut.push(line),
        stderr: (line) => remoteErr.push(line)
      }
    );
    assert.equal(remoteCode, 0, remoteErr.join('\n'));
    const remoteParsed = JSON.parse(remoteOut.join('\n')) as {
      conflicts: ClaimConflictSummary[];
      total: number;
      includeHistorical: boolean;
    };
    assert.equal(remoteParsed.total, 1);
    assert.equal(remoteParsed.includeHistorical, true);
    assert.ok(remoteParsed.conflicts[0]!.memories.some((m) => m.memoryId === p1.id));

    // 6. Stop server cleanly before opening local CLI DB against the same dbPath
    await server.stop();

    const localOut: string[] = [];
    const localErr: string[] = [];
    const localCode = await runCli(
      [
        '--db',
        dbPath,
        '--workspace',
        dir,
        '--token',
        ADMIN_ALPHA,
        '--scope-type',
        'WORKSPACE',
        '--scope-id',
        'ws-alpha',
        '--json',
        'memory',
        'conflicts',
        '--include-historical',
        '--limit',
        '10',
        '--offset',
        '0'
      ],
      {
        stdout: (line) => localOut.push(line),
        stderr: (line) => localErr.push(line)
      },
      { tokens, modelProvider: new MockModelProvider() }
    );
    assert.equal(localCode, 0, localErr.join('\n'));
    const localParsed = JSON.parse(localOut.join('\n')) as {
      total: number;
      includeHistorical: boolean;
      conflicts: ClaimConflictSummary[];
    };
    assert.equal(localParsed.total, 1);
    assert.equal(localParsed.includeHistorical, true);
    assert.equal(localParsed.conflicts[0]!.isHistorical, true);
  } finally {
    await server.stop().catch(() => undefined);
    rmSync(dir, { recursive: true, force: true });
  }
});
