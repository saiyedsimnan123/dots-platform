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

// ============================================================================
// 10. Regression (MEDIUM-01): Same-evidence verifier disagreement vs independent sources
// ============================================================================
test('10. Two verifiers disagreeing on the same evidence do not classify as OPPOSING_VERIFICATIONS', async () => {
  const env = setupConflictTestEnv();

  const prop = env.memoryService.createMemory(env.agentAlpha, {
    key: 'verifier.disagreement.single',
    content: 'Worker pool size of 16 avoids thread starvation.',
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    status: 'PENDING_APPROVAL',
    claims: [{ originalText: 'Worker pool size of 16 avoids thread starvation.' }],
    evidence: [
      {
        sourceType: 'TOOL_EXECUTION',
        sourceUrl: 'https://bench.example.org/pool-16',
        snippet: 'Observed 0 queued tasks with intermittent tail spikes.',
        relationship: 'SUPPORTS',
        targetClaimIndices: [0]
      }
    ]
  });

  const claim = env.memoryService.getClaimsByMemoryId(env.adminAlpha, prop.id)[0]!;
  const evidence = env.memoryService.getEvidenceByMemoryId(env.adminAlpha, prop.id)[0]!;

  const engineV1 = new EvidenceVerificationEngine({
    verifier: {
      verifierId: 'verifier-alpha',
      verifierVersion: '1.0',
      promptPolicyVersion: 'v1',
      promptPolicyHash: 'policy-1',
      async evaluate() {
        return {
          claimId: claim.id,
          evidenceId: evidence.id,
          proposedRelationship: 'SUPPORTS',
          outcome: 'PROPOSED',
          confidence: 0.88,
          explanation: 'Verifier v1 treats zero queued tasks as supporting.',
          verifierId: 'verifier-alpha',
          verifierVersion: '1.0'
        };
      }
    },
    memoryRepo: env.memoryRepo,
    authorizer: env.authorizer,
    auditRepo: env.auditRepo,
    taskRepo: env.taskRepo
  });

  const engineV2 = new EvidenceVerificationEngine({
    verifier: {
      verifierId: 'verifier-beta',
      verifierVersion: '2.0',
      promptPolicyVersion: 'v1',
      promptPolicyHash: 'policy-2',
      async evaluate() {
        return {
          claimId: claim.id,
          evidenceId: evidence.id,
          proposedRelationship: 'CONTRADICTS',
          outcome: 'PROPOSED',
          confidence: 0.86,
          explanation: 'Verifier v2 treats tail spikes as contradicting starvation avoidance.',
          verifierId: 'verifier-beta',
          verifierVersion: '2.0'
        };
      }
    },
    memoryRepo: env.memoryRepo,
    authorizer: env.authorizer,
    auditRepo: env.auditRepo,
    taskRepo: env.taskRepo
  });

  await engineV1.verifyClaimAgainstEvidence(env.agentAlpha, {
    claimId: claim.id,
    evidenceId: evidence.id,
    assumptions: ['CPU-bound service load']
  });
  await engineV2.verifyClaimAgainstEvidence(env.agentAlpha, {
    claimId: claim.id,
    evidenceId: evidence.id,
    assumptions: ['CPU-bound service load']
  });

  // Must NOT classify as OPPOSING_VERIFICATIONS or VERIFIED_CONTRADICTION
  assert.equal(
    env.memoryService.listClaimConflicts(env.adminAlpha, { conflictType: 'OPPOSING_VERIFICATIONS' }).total,
    0
  );
  assert.equal(
    env.memoryService.listClaimConflicts(env.adminAlpha, { conflictType: 'VERIFIED_CONTRADICTION' }).total,
    0
  );
  assert.equal(
    env.memoryService.listClaimConflicts(env.adminAlpha, { conflictType: 'VERIFIER_DISAGREEMENT' }).total,
    1
  );

  const res = env.memoryService.listClaimConflicts(env.adminAlpha);
  assert.equal(res.total, 1);
  const conflict = res.conflicts[0]!;
  assert.equal(conflict.conflictType, 'VERIFIER_DISAGREEMENT');
  assert.deepEqual(conflict.supportingEvidence, []);
  assert.deepEqual(conflict.contradictingEvidence, []);
  assert.deepEqual(conflict.limitationEvidence, []);
  assert.deepEqual(conflict.incomparableEvidence, []);
  assert.equal(conflict.disputedEvidence.length, 1);
  assert.equal(conflict.disputedEvidence[0]!.evidenceId, evidence.id);
  assert.equal(conflict.disputedEvidence[0]!.relationship, 'SUPPORTS');
  assert.equal(conflict.disputedEvidence[0]!.hasVerifierDisagreement, true);
  assert.equal(conflict.disputedEvidence[0]!.verifications.length, 2);
  assert.equal(conflict.verifierDisagreements.length, 1);
  assert.equal(conflict.verifierDisagreements[0]!.evidenceId, evidence.id);
  assert.equal(conflict.verifierDisagreements[0]!.positions.length, 2);
  assert.deepEqual(conflict.verifierDisagreements[0]!.assumptions, ['CPU-bound service load']);

  // Same evidence evaluated under DIFFERENT assumptions is incomparable conditions (not contradiction or disagreement)
  const propDiffEnv = env.memoryService.createMemory(env.agentAlpha, {
    key: 'verifier.diff.assumptions.same.ev',
    content: 'Batch write latency stays under 15ms.',
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    status: 'PENDING_APPROVAL',
    claims: [{ originalText: 'Batch write latency stays under 15ms.' }],
    evidence: [
      {
        sourceType: 'TOOL_EXECUTION',
        snippet: 'NVMe SSD benchmark shows 10ms; HDD benchmark shows 95ms.',
        relationship: 'SUPPORTS',
        targetClaimIndices: [0]
      }
    ]
  });
  const dcDiff = env.memoryService.getClaimsByMemoryId(env.adminAlpha, propDiffEnv.id)[0]!;
  const deDiff = env.memoryService.getEvidenceByMemoryId(env.adminAlpha, propDiffEnv.id)[0]!;
  env.mockProvider.enqueueCompletion(JSON.stringify({
    claimId: dcDiff.id, evidenceId: deDiff.id, proposedRelationship: 'SUPPORTS', outcome: 'PROPOSED', confidence: 0.9, explanation: 'Holds on NVMe.'
  }));
  await env.engine.verifyClaimAgainstEvidence(env.agentAlpha, {
    claimId: dcDiff.id, evidenceId: deDiff.id, assumptions: ['NVMe SSD']
  });
  env.mockProvider.enqueueCompletion(JSON.stringify({
    claimId: dcDiff.id, evidenceId: deDiff.id, proposedRelationship: 'CONTRADICTS', outcome: 'PROPOSED', confidence: 0.9, explanation: 'Fails on spinning HDD.'
  }));
  await env.engine.verifyClaimAgainstEvidence(env.agentAlpha, {
    claimId: dcDiff.id, evidenceId: deDiff.id, assumptions: ['Spinning HDD']
  });
  const diffAssumpConflict = env.memoryService.getConflictByClaimId(env.adminAlpha, dcDiff.id)!;
  assert.equal(diffAssumpConflict.conflictType, 'INCOMPARABLE_CONDITIONS');
  assert.deepEqual(diffAssumpConflict.verifierDisagreements, []);
  assert.deepEqual(diffAssumpConflict.contradictingEvidence, []);
  assert.deepEqual(diffAssumpConflict.disputedEvidence, []);
  assert.equal(diffAssumpConflict.incomparableEvidence.length, 1);
  assert.equal(diffAssumpConflict.incomparableEvidence[0]!.evidenceId, deDiff.id);
  assert.equal(diffAssumpConflict.incomparableEvidence[0]!.hasVerifierDisagreement, false);

  // Distinct independent evidence sources under matching assumptions DO still classify as OPPOSING_VERIFICATIONS
  const propDistinct = env.memoryService.createMemory(env.agentAlpha, {
    key: 'verifier.independent.opposing',
    content: 'Async flush finishes within 5ms.',
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    status: 'PENDING_APPROVAL',
    claims: [{ originalText: 'Async flush finishes within 5ms.' }],
    evidence: [
      {
        sourceType: 'TOOL_EXECUTION',
        snippet: 'Run A measured 3ms flush.',
        relationship: 'SUPPORTS',
        targetClaimIndices: [0]
      },
      {
        sourceType: 'TOOL_EXECUTION',
        snippet: 'Run B measured 28ms flush.',
        relationship: 'SUPPORTS',
        targetClaimIndices: [0]
      }
    ]
  });
  const dc = env.memoryService.getClaimsByMemoryId(env.adminAlpha, propDistinct.id)[0]!;
  const de = env.memoryService.getEvidenceByMemoryId(env.adminAlpha, propDistinct.id);
  env.mockProvider.enqueueCompletion(JSON.stringify({
    claimId: dc.id, evidenceId: de[0]!.id, proposedRelationship: 'SUPPORTS', outcome: 'PROPOSED', confidence: 0.9, explanation: '3ms < 5ms.'
  }));
  const resSup = await env.engine.verifyClaimAgainstEvidence(env.agentAlpha, {
    claimId: dc.id,
    evidenceId: de[0]!.id,
    assumptions: ['Shared async benchmark cluster']
  });
  assert.equal(resSup.ok, true);

  env.mockProvider.enqueueCompletion(JSON.stringify({
    claimId: dc.id, evidenceId: de[1]!.id, proposedRelationship: 'CONTRADICTS', outcome: 'PROPOSED', confidence: 0.9, explanation: '28ms > 5ms.'
  }));
  const resCon = await env.engine.verifyClaimAgainstEvidence(env.agentAlpha, {
    claimId: dc.id,
    evidenceId: de[1]!.id,
    assumptions: ['Shared async benchmark cluster']
  });
  assert.equal(resCon.ok, true);

  const distinctConflict = env.memoryService.getConflictByClaimId(env.adminAlpha, dc.id)!;
  assert.equal(distinctConflict.conflictType, 'OPPOSING_VERIFICATIONS');
  assert.deepEqual(distinctConflict.verifierDisagreements, []);
  assert.equal(distinctConflict.supportingEvidence[0]!.hasVerifierDisagreement, false);
  assert.equal(distinctConflict.contradictingEvidence[0]!.hasVerifierDisagreement, false);
});

// ============================================================================
// 11. Regression (MEDIUM-02): Explicit CONTRADICTS verified as SUPPORTS vs unresolved outcomes
// ============================================================================
test('11. Explicit CONTRADICTS resolved as SUPPORTS clears contradiction while preserving unresolved AMBIGUOUS/INSUFFICIENT cases', async () => {
  const env = setupConflictTestEnv();

  // Subcase A: Single explicit CONTRADICTS verified cleanly as SUPPORTS -> resolved, NOT a conflict
  const propResolved = env.memoryService.createMemory(env.agentAlpha, {
    key: 'explicit.contradict.resolved.supports',
    content: 'Write-ahead log syncs before ACK.',
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    status: 'PENDING_APPROVAL',
    claims: [{ originalText: 'Write-ahead log syncs before ACK.' }],
    evidence: [
      {
        sourceType: 'DOCUMENTATION',
        snippet: 'fsync(wal_fd) runs prior to returning RPC response.',
        relationship: 'CONTRADICTS',
        targetClaimIndices: [0]
      }
    ]
  });
  const cRes = env.memoryService.getClaimsByMemoryId(env.adminAlpha, propResolved.id)[0]!;
  const eRes = env.memoryService.getEvidenceByMemoryId(env.adminAlpha, propResolved.id)[0]!;
  env.mockProvider.enqueueCompletion(JSON.stringify({
    claimId: cRes.id,
    evidenceId: eRes.id,
    proposedRelationship: 'SUPPORTS',
    outcome: 'PROPOSED',
    confidence: 0.95,
    explanation: 'Snippet directly confirms fsync before ACK, contradicting initial label.'
  }));
  await env.engine.verifyProposalClaims(env.agentAlpha, propResolved.id);
  assert.equal(env.memoryService.getConflictByClaimId(env.adminAlpha, cRes.id), null);

  // Subcase B: When paired with another unverified CONTRADICTS, resolved item is placed in supportingEvidence with original provenance
  const propMixed = env.memoryService.createMemory(env.agentAlpha, {
    key: 'explicit.contradict.mixed.supports',
    content: 'Lock timeout defaults to 3s.',
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    status: 'PENDING_APPROVAL',
    claims: [{ originalText: 'Lock timeout defaults to 3s.' }],
    evidence: [
      {
        sourceType: 'DOCUMENTATION',
        snippet: 'Config constant LOCK_TIMEOUT_MS = 3000.',
        relationship: 'CONTRADICTS',
        targetClaimIndices: [0]
      },
      {
        sourceType: 'TOOL_EXECUTION',
        snippet: 'Observed lock timeout after 15000ms.',
        relationship: 'CONTRADICTS',
        targetClaimIndices: [0]
      }
    ]
  });
  const cMixed = env.memoryService.getClaimsByMemoryId(env.adminAlpha, propMixed.id)[0]!;
  const evMixed = env.memoryService.getEvidenceByMemoryId(env.adminAlpha, propMixed.id);
  env.mockProvider.enqueueCompletion(JSON.stringify({
    claimId: cMixed.id,
    evidenceId: evMixed[0]!.id,
    proposedRelationship: 'SUPPORTS',
    outcome: 'PROPOSED',
    confidence: 0.94,
    explanation: 'Verified constant matches 3s claim.'
  }));
  await env.engine.verifyClaimAgainstEvidence(env.agentAlpha, {
    claimId: cMixed.id,
    evidenceId: evMixed[0]!.id
  });

  const mixedConflict = env.memoryService.getConflictByClaimId(env.adminAlpha, cMixed.id)!;
  assert.ok(mixedConflict);
  assert.equal(mixedConflict.conflictType, 'EXPLICIT_CONTRADICTION');
  assert.equal(mixedConflict.supportingEvidence.length, 1);
  assert.equal(mixedConflict.supportingEvidence[0]!.evidenceId, evMixed[0]!.id);
  assert.equal(mixedConflict.supportingEvidence[0]!.relationship, 'CONTRADICTS');
  assert.equal(mixedConflict.supportingEvidence[0]!.verifications[0]!.proposedRelationship, 'SUPPORTS');
  assert.equal(mixedConflict.contradictingEvidence.length, 1);
  assert.equal(mixedConflict.contradictingEvidence[0]!.evidenceId, evMixed[1]!.id);

  // Subcase C: Explicit CONTRADICTS verified as AMBIGUOUS or INSUFFICIENT is NOT silently discarded
  const propUnresolved = env.memoryService.createMemory(env.agentAlpha, {
    key: 'explicit.contradict.ambiguous',
    content: 'GC pause stays below 10ms.',
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    status: 'PENDING_APPROVAL',
    claims: [{ originalText: 'GC pause stays below 10ms.' }],
    evidence: [
      {
        sourceType: 'WEB_RESEARCH',
        snippet: 'Partial trace suggests periodic 40ms stalls.',
        relationship: 'CONTRADICTS',
        targetClaimIndices: [0]
      }
    ]
  });
  const cUnres = env.memoryService.getClaimsByMemoryId(env.adminAlpha, propUnresolved.id)[0]!;
  const eUnres = env.memoryService.getEvidenceByMemoryId(env.adminAlpha, propUnresolved.id)[0]!;
  env.mockProvider.enqueueCompletion(JSON.stringify({
    claimId: cUnres.id,
    evidenceId: eUnres.id,
    proposedRelationship: 'AMBIGUOUS',
    outcome: 'AMBIGUOUS',
    confidence: 0.4,
    explanation: 'Unclear if stall came from GC or disk I/O.'
  }));
  await env.engine.verifyProposalClaims(env.agentAlpha, propUnresolved.id);

  const unresolvedConflict = env.memoryService.getConflictByClaimId(env.adminAlpha, cUnres.id)!;
  assert.ok(unresolvedConflict);
  assert.equal(unresolvedConflict.conflictType, 'EXPLICIT_CONTRADICTION');
  assert.equal(unresolvedConflict.contradictingEvidence.length, 1);
  assert.equal(unresolvedConflict.contradictingEvidence[0]!.verifications[0]!.verificationOutcome, 'AMBIGUOUS');
});

// ============================================================================
// 12. Regression (MEDIUM-03): Multi-claim SQL scaling, composite indexes, deterministic paging
// ============================================================================
test('12. listClaimConflicts uses constant bounded SQL queries across N claims with deterministic SQL pagination', () => {
  const env = setupConflictTestEnv();

  const createdClaimIds: string[] = [];
  for (let i = 0; i < 8; i++) {
    const m = env.memoryService.createMemory(env.agentAlpha, {
      key: `scale.claim.${i}`,
      content: `Service limit rule #${i} fails check.`,
      category: 'PROJECT_FACT',
      scopeType: env.scopeAlpha.scopeType,
      scopeId: env.scopeAlpha.scopeId,
      status: 'PENDING_APPROVAL',
      claims: [{ originalText: `Scaled claim proposition #${i}.` }],
      evidence: [
        {
          sourceType: 'TOOL_EXECUTION',
          snippet: `Contradicting observation for item #${i}.`,
          relationship: 'CONTRADICTS',
          targetClaimIndices: [0]
        }
      ]
    });
    createdClaimIds.push(env.memoryService.getClaimsByMemoryId(env.adminAlpha, m.id)[0]!.id);
  }

  // Verify composite indexes exist in SQLite schema
  const indexRows = env.db
    .prepare("SELECT name FROM sqlite_master WHERE type = 'index' AND name LIKE 'idx_%'")
    .all() as Array<{ name: string }>;
  const indexNames = new Set(indexRows.map((r) => r.name));
  assert.ok(indexNames.has('idx_mcl_claim_scope_status'));
  assert.ok(indexNames.has('idx_cea_claim_scope_status_rel'));
  assert.ok(indexNames.has('idx_cev_claim_scope_status'));

  // Count SQL prepares during paged query over N=8 claims (must be bounded O(1), NOT 1 + 3*8 = 25)
  let prepareCount = 0;
  const origPrepare = env.db.prepare.bind(env.db);
  (env.db as { prepare: typeof env.db.prepare }).prepare = (sql: string) => {
    prepareCount += 1;
    return origPrepare(sql);
  };

  let page1, page2, page3, pastEnd;
  try {
    page1 = env.memoryService.listClaimConflicts(env.adminAlpha, { limit: 3, offset: 0 });
    const countForPage1 = prepareCount;
    assert.ok(countForPage1 <= 6, `Expected <= 6 SQL queries for page1 over 8 claims, got ${countForPage1}`);

    prepareCount = 0;
    page2 = env.memoryService.listClaimConflicts(env.adminAlpha, { limit: 3, offset: 3 });
    assert.ok(prepareCount <= 6, `Expected <= 6 SQL queries for page2, got ${prepareCount}`);

    prepareCount = 0;
    page3 = env.memoryService.listClaimConflicts(env.adminAlpha, { limit: 3, offset: 6 });
    assert.ok(prepareCount <= 6, `Expected <= 6 SQL queries for page3, got ${prepareCount}`);

    prepareCount = 0;
    pastEnd = env.memoryService.listClaimConflicts(env.adminAlpha, { limit: 3, offset: 20 });
    assert.ok(prepareCount <= 2, `Expected <= 2 SQL queries for out-of-range offset, got ${prepareCount}`);
  } finally {
    (env.db as { prepare: typeof env.db.prepare }).prepare = origPrepare;
  }

  assert.equal(page1.total, 8);
  assert.equal(page1.conflicts.length, 3);
  assert.equal(page2.total, 8);
  assert.equal(page2.conflicts.length, 3);
  assert.equal(page3.total, 8);
  assert.equal(page3.conflicts.length, 2);
  assert.equal(pastEnd.total, 8);
  assert.equal(pastEnd.conflicts.length, 0);

  const pagedIds = [
    ...page1.conflicts.map((c) => c.claim.id),
    ...page2.conflicts.map((c) => c.claim.id),
    ...page3.conflicts.map((c) => c.claim.id)
  ];
  assert.equal(new Set(pagedIds).size, 8);
  assert.deepEqual(new Set(pagedIds), new Set(createdClaimIds));
});

// ============================================================================
// 13. Regression (LOW-01): Accurate historical link/association/verification status on archive, reject, supersede
// ============================================================================
test('13. Archived, rejected, and superseded memories record INVALIDATED links/associations and STALE verifications cleanly', async () => {
  const env = setupConflictTestEnv();

  // Case 1: Active memory archived via archiveMemory
  const propArch = env.memoryService.createMemory(env.agentAlpha, {
    key: 'lifecycle.archive.verified',
    content: 'Archive test assertion.',
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    status: 'PENDING_APPROVAL',
    claims: [{ originalText: 'Archive test assertion.' }],
    evidence: [
      {
        sourceType: 'DOCUMENTATION',
        snippet: 'Contradicting doc for archive test.',
        relationship: 'CONTRADICTS',
        targetClaimIndices: [0]
      }
    ]
  });
  const cArch = env.memoryService.getClaimsByMemoryId(env.adminAlpha, propArch.id)[0]!;
  const eArch = env.memoryService.getEvidenceByMemoryId(env.adminAlpha, propArch.id)[0]!;
  env.mockProvider.enqueueCompletion(JSON.stringify({
    claimId: cArch.id, evidenceId: eArch.id, proposedRelationship: 'CONTRADICTS', outcome: 'PROPOSED', confidence: 0.9, explanation: 'Contradicts.'
  }));
  await env.engine.verifyProposalClaims(env.agentAlpha, propArch.id);
  const mArchActive = env.memoryService.decideProposal(env.adminAlpha, { memoryId: propArch.id, decision: 'APPROVE_NEW' });
  env.memoryService.archiveMemory(env.adminAlpha, mArchActive.id);

  // Current view hides archived memory conflict; historical view preserves INVALIDATED + STALE status
  assert.equal(env.memoryService.getConflictByClaimId(env.adminAlpha, cArch.id), null);
  const histArch = env.memoryService.getConflictByClaimId(env.adminAlpha, cArch.id, { includeHistorical: true })!;
  assert.equal(histArch.isHistorical, true);
  assert.equal(histArch.memories[0]!.status, 'ARCHIVED');
  assert.equal(histArch.memories[0]!.linkStatus, 'INVALIDATED');
  assert.equal(histArch.memories[0]!.invalidationReason, 'MEMORY_ARCHIVED');
  assert.equal(histArch.contradictingEvidence[0]!.associationStatus, 'INVALIDATED');
  assert.equal(histArch.contradictingEvidence[0]!.verifications[0]!.status, 'STALE');
  assert.equal(histArch.contradictingEvidence[0]!.verifications[0]!.staleReason, 'MEMORY_ARCHIVED');

  // Case 2: Pending proposal rejected via decideProposal('REJECT')
  const propRej = env.memoryService.createMemory(env.agentAlpha, {
    key: 'lifecycle.reject.verified',
    content: 'Reject test assertion.',
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    status: 'PENDING_APPROVAL',
    claims: [{ originalText: 'Reject test assertion.' }],
    evidence: [
      {
        sourceType: 'WEB_RESEARCH',
        snippet: 'Contradicting snippet on rejected proposal.',
        relationship: 'CONTRADICTS',
        targetClaimIndices: [0]
      }
    ]
  });
  const cRej = env.memoryService.getClaimsByMemoryId(env.adminAlpha, propRej.id)[0]!;
  const eRej = env.memoryService.getEvidenceByMemoryId(env.adminAlpha, propRej.id)[0]!;
  env.mockProvider.enqueueCompletion(JSON.stringify({
    claimId: cRej.id, evidenceId: eRej.id, proposedRelationship: 'CONTRADICTS', outcome: 'PROPOSED', confidence: 0.85, explanation: 'Contradicts.'
  }));
  await env.engine.verifyProposalClaims(env.agentAlpha, propRej.id);
  env.memoryService.decideProposal(env.adminAlpha, { memoryId: propRej.id, decision: 'REJECT', reason: 'Rejected' });

  assert.equal(env.memoryService.getConflictByClaimId(env.adminAlpha, cRej.id), null);
  const histRej = env.memoryService.getConflictByClaimId(env.adminAlpha, cRej.id, { includeHistorical: true })!;
  assert.equal(histRej.memories[0]!.status, 'ARCHIVED');
  assert.equal(histRej.memories[0]!.linkStatus, 'INVALIDATED');
  assert.equal(histRej.memories[0]!.invalidationReason, 'PROPOSAL_REJECTED');
  assert.equal(histRej.contradictingEvidence[0]!.associationStatus, 'INVALIDATED');
  assert.equal(histRej.contradictingEvidence[0]!.verifications[0]!.status, 'STALE');
  assert.equal(histRej.contradictingEvidence[0]!.verifications[0]!.staleReason, 'PROPOSAL_REJECTED');

  // Case 3: Active memory superseded via APPROVE_AND_SUPERSEDE
  const propOld = env.memoryService.createMemory(env.agentAlpha, {
    key: 'lifecycle.supersede.key',
    content: 'Old claim assertion v1.',
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    status: 'PENDING_APPROVAL',
    claims: [{ originalText: 'Old claim assertion v1.' }],
    evidence: [
      {
        sourceType: 'TOOL_EXECUTION',
        snippet: 'Old runtime trace contradicted v1.',
        relationship: 'CONTRADICTS',
        targetClaimIndices: [0]
      }
    ]
  });
  const cOld = env.memoryService.getClaimsByMemoryId(env.adminAlpha, propOld.id)[0]!;
  const mOld = env.memoryService.decideProposal(env.adminAlpha, { memoryId: propOld.id, decision: 'APPROVE_NEW' });
  const propRep = env.memoryService.createMemory(env.agentAlpha, {
    key: 'lifecycle.supersede.key',
    content: 'Replacement assertion v2.',
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    status: 'PENDING_APPROVAL'
  });
  env.memoryService.decideProposal(env.adminAlpha, { memoryId: propRep.id, decision: 'APPROVE_AND_SUPERSEDE' });

  assert.equal(env.memoryService.getConflictByClaimId(env.adminAlpha, cOld.id), null);
  const histSup = env.memoryService.getConflictByClaimId(env.adminAlpha, cOld.id, { includeHistorical: true })!;
  const oldOrigin = histSup.memories.find((m) => m.memoryId === mOld.id)!;
  assert.equal(oldOrigin.status, 'SUPERSEDED');
  assert.equal(oldOrigin.linkStatus, 'INVALIDATED');
  assert.equal(oldOrigin.invalidationReason, 'MEMORY_SUPERSEDED');
  assert.equal(histSup.contradictingEvidence[0]!.associationStatus, 'INVALIDATED');
});

// ============================================================================
// 14. Regression (LOW-02 & LOW-03): CLI nonexistent --memory-id not-found & missing flag values
// ============================================================================
test('14. Local and remote CLI fail cleanly on nonexistent --memory-id and missing flag values', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'dots-cli-conflicts-'));
  const dbPath = join(dir, 'dots.db');
  const ADMIN_ALPHA = 'admin-alpha-cli-secret-12345';
  const tokens = [
    {
      token: ADMIN_ALPHA,
      principalId: 'alice-alpha',
      role: 'ADMIN' as const,
      permittedScopes: [{ scopeType: 'WORKSPACE' as const, scopeId: 'ws-alpha' }]
    }
  ];

  const runtime = new DotsRuntime({
    dbPath,
    workspaceRoot: dir,
    host: '127.0.0.1',
    port: 0,
    silentLogs: true,
    enableScheduler: false,
    modelProvider: new MockModelProvider(),
    tokens
  });
  const server = new DotsHttpServer(runtime);

  const runWithCapture = async (argv: string[], useRemoteUrl?: string) => {
    const out: string[] = [];
    const err: string[] = [];
    const fullArgv = useRemoteUrl
      ? ['--server', useRemoteUrl, '--token', ADMIN_ALPHA, '--json', ...argv]
      : ['--db', dbPath, '--workspace', dir, '--token', ADMIN_ALPHA, '--json', ...argv];
    const code = await runCli(
      fullArgv,
      { stdout: (l) => out.push(l), stderr: (l) => err.push(l) },
      useRemoteUrl ? {} : { tokens, modelProvider: new MockModelProvider() }
    );
    return { code, out: out.join('\n'), err: err.join('\n') };
  };

  try {
    const started = await server.start();

    // Nonexistent --memory-id in remote mode -> exit 1 with not-found message
    const remoteMissingMem = await runWithCapture(['memory', 'conflicts', '--memory-id', 'no-such-mem-123'], started.url);
    assert.equal(remoteMissingMem.code, 1);
    assert.match(remoteMissingMem.err, /not found/i);

    // Valueless flags in remote mode -> exit 1 with ValidationError message
    for (const badArgs of [
      ['memory', 'conflicts', '--memory-id'],
      ['memory', 'conflicts', '--claim-id'],
      ['memory', 'conflicts', '--conflict-type'],
      ['memory', 'conflicts', '--conflict-type=']
    ]) {
      const r = await runWithCapture(badArgs, started.url);
      assert.equal(r.code, 1, `Expected failure for remote args: ${badArgs.join(' ')}`);
      assert.match(r.err, /requires a non-empty value/i);
    }

    await server.stop();

    // Nonexistent --memory-id in local mode -> exit 1 with not-found message
    const localMissingMem = await runWithCapture(['memory', 'conflicts', '--memory-id', 'no-such-mem-123']);
    assert.equal(localMissingMem.code, 1);
    assert.match(localMissingMem.err, /not found/i);

    // Valueless flags in local mode -> exit 1 with ValidationError message
    for (const badArgs of [
      ['memory', 'conflicts', '--memory-id'],
      ['memory', 'conflicts', '--claim-id'],
      ['memory', 'conflicts', '--conflict-type'],
      ['memory', 'conflicts', '--limit']
    ]) {
      const r = await runWithCapture(badArgs);
      assert.equal(r.code, 1, `Expected failure for local args: ${badArgs.join(' ')}`);
    }
  } finally {
    await server.stop().catch(() => undefined);
    rmSync(dir, { recursive: true, force: true });
  }
});

// ============================================================================
// 15. Regression (LOW-04): Verifier assumptions kept distinct from caller-editable metadata
// ============================================================================
test('15. Caller-editable metadata.verificationAssumptions does not pollute authoritative verifier assumptions', async () => {
  const env = setupConflictTestEnv();

  const prop = env.memoryService.createMemory(env.agentAlpha, {
    key: 'provenance.assumptions.isolation',
    content: 'Connection retry caps at 3 attempts.',
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    status: 'PENDING_APPROVAL',
    metadata: {
      verificationAssumptions: ['Caller-editable contextual note', 'Staging region context']
    },
    claims: [{ originalText: 'Connection retry caps at 3 attempts.' }],
    evidence: [
      {
        sourceType: 'DOCUMENTATION',
        snippet: 'Configured maxRetries = 5.',
        relationship: 'CONTRADICTS',
        targetClaimIndices: [0]
      }
    ]
  });

  const claim = env.memoryService.getClaimsByMemoryId(env.adminAlpha, prop.id)[0]!;
  const evidence = env.memoryService.getEvidenceByMemoryId(env.adminAlpha, prop.id)[0]!;

  env.mockProvider.enqueueCompletion(JSON.stringify({
    claimId: claim.id,
    evidenceId: evidence.id,
    proposedRelationship: 'CONTRADICTS',
    outcome: 'PROPOSED',
    confidence: 0.91,
    explanation: 'Verified maxRetries = 5 contradicts 3.'
  }));
  await env.engine.verifyClaimAgainstEvidence(env.agentAlpha, {
    claimId: claim.id,
    evidenceId: evidence.id,
    assumptions: ['Authoritative verifier condition']
  });

  const conflict = env.memoryService.getConflictByClaimId(env.adminAlpha, claim.id)!;
  assert.ok(conflict);
  // Verifier-recorded assumptions only
  assert.deepEqual(conflict.assumptions, ['Authoritative verifier condition']);
  // Contextual memory metadata kept separate and never merged into summary.assumptions
  assert.deepEqual([...conflict.contextualAssumptions].sort(), [
    'Caller-editable contextual note',
    'Staging region context'
  ]);
  assert.deepEqual([...conflict.memories[0]!.verificationAssumptions].sort(), [
    'Caller-editable contextual note',
    'Staging region context'
  ]);
});

// ============================================================================
// 16. Regression: Equal-timestamp deterministic ordering & pagination tie-breaking
// ============================================================================
test('16. Equal detectedAt timestamps paginate deterministically in claim.id ASC order without duplicates', () => {
  const env = setupConflictTestEnv();
  const equalTs = '2026-11-25T10:00:00.000Z';
  const claimIds: string[] = [];

  for (let i = 0; i < 5; i++) {
    const m = env.memoryRepo.createMemory({
      key: `tie.order.${i}`,
      content: `Equal timestamp fact #${i}`,
      category: 'PROJECT_FACT',
      scopeType: env.scopeAlpha.scopeType,
      scopeId: env.scopeAlpha.scopeId,
      status: 'ACTIVE'
    });
    const c = env.memoryRepo.addClaim({
      memoryId: m.id,
      scopeType: env.scopeAlpha.scopeType,
      scopeId: env.scopeAlpha.scopeId,
      originalText: `Deterministic tie proposition #${i}.`,
      taskId: env.taskAlpha.id,
      createdAt: equalTs
    });
    const e = env.memoryRepo.addEvidence({
      memoryId: m.id,
      sourceType: 'DOCUMENTATION',
      snippet: `Contradiction snippet #${i}.`,
      relationship: 'CONTRADICTS',
      taskId: env.taskAlpha.id,
      agentId: 'research-agent-alpha',
      createdAt: equalTs
    });
    env.memoryRepo.addClaimEvidenceAssociation({
      claimId: c.id,
      evidenceId: e.id,
      memoryId: m.id,
      scopeType: env.scopeAlpha.scopeType,
      scopeId: env.scopeAlpha.scopeId,
      createdAt: equalTs
    });
    claimIds.push(c.id);
  }

  const expectedOrderedIds = [...claimIds].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  const p1 = env.memoryService.listClaimConflicts(env.adminAlpha, { limit: 2, offset: 0 });
  const p2 = env.memoryService.listClaimConflicts(env.adminAlpha, { limit: 2, offset: 2 });
  const p3 = env.memoryService.listClaimConflicts(env.adminAlpha, { limit: 2, offset: 4 });

  assert.equal(p1.total, 5);
  assert.equal(p2.total, 5);
  assert.equal(p3.total, 5);
  assert.deepEqual(
    [
      ...p1.conflicts.map((c) => c.claim.id),
      ...p2.conflicts.map((c) => c.claim.id),
      ...p3.conflicts.map((c) => c.claim.id)
    ],
    expectedOrderedIds
  );
  for (const c of [...p1.conflicts, ...p2.conflicts, ...p3.conflicts]) {
    assert.equal(c.detectedAt, equalTs);
  }
});

// ============================================================================
// 17. Regression: HTTP out-of-range offset & VERIFIER_DISAGREEMENT filtering via HTTP/CLI
// ============================================================================
test('17. HTTP out-of-range offset returns empty page with total, and HTTP/CLI filter VERIFIER_DISAGREEMENT cleanly', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'dots-http-disagreement-'));
  const dbPath = join(dir, 'dots.db');
  const ADMIN_TOKEN = 'admin-http-disagreement-12345';
  const tokens = [
    {
      token: ADMIN_TOKEN,
      principalId: 'alice-alpha',
      role: 'ADMIN' as const,
      permittedScopes: [{ scopeType: 'WORKSPACE' as const, scopeId: 'ws-alpha' }]
    }
  ];

  const runtime = new DotsRuntime({
    dbPath,
    workspaceRoot: dir,
    host: '127.0.0.1',
    port: 0,
    silentLogs: true,
    enableScheduler: false,
    modelProvider: new MockModelProvider(),
    tokens
  });
  const server = new DotsHttpServer(runtime);

  try {
    const admin = runtime.authorizer.authorizeUser({
      credentials: ADMIN_TOKEN,
      requestedScope: { scopeType: 'WORKSPACE', scopeId: 'ws-alpha' }
    });

    const p1 = runtime.memoryService.createMemory(admin, {
      key: 'http.disagreement.fact',
      content: 'Read timeout defaults to 2s.',
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: 'ws-alpha',
      status: 'PENDING_APPROVAL',
      claims: [{ originalText: 'Read timeout defaults to 2s.' }],
      evidence: [
        {
          sourceType: 'DOCUMENTATION',
          snippet: 'Config doc mentions 2000ms under retry handler.',
          relationship: 'SUPPORTS',
          targetClaimIndices: [0]
        }
      ]
    });
    const c1 = runtime.memoryService.getClaimsByMemoryId(admin, p1.id)[0]!;
    const e1 = runtime.memoryService.getEvidenceByMemoryId(admin, p1.id)[0]!;

    const vSup = new EvidenceVerificationEngine({
      verifier: {
        verifierId: 'v-http-1',
        verifierVersion: '1.0',
        promptPolicyVersion: 'v1',
        promptPolicyHash: 'ph-1',
        async evaluate() {
          return {
            claimId: c1.id,
            evidenceId: e1.id,
            proposedRelationship: 'SUPPORTS',
            outcome: 'PROPOSED',
            confidence: 0.84,
            explanation: 'Supports 2s default.',
            verifierId: 'v-http-1',
            verifierVersion: '1.0'
          };
        }
      },
      memoryRepo: runtime.memoryRepo,
      authorizer: runtime.authorizer,
      auditRepo: runtime.auditRepo,
      taskRepo: runtime.taskRepo
    });
    const vCon = new EvidenceVerificationEngine({
      verifier: {
        verifierId: 'v-http-2',
        verifierVersion: '2.0',
        promptPolicyVersion: 'v1',
        promptPolicyHash: 'ph-2',
        async evaluate() {
          return {
            claimId: c1.id,
            evidenceId: e1.id,
            proposedRelationship: 'CONTRADICTS',
            outcome: 'PROPOSED',
            confidence: 0.81,
            explanation: 'Retry handler may not set default timeout.',
            verifierId: 'v-http-2',
            verifierVersion: '2.0'
          };
        }
      },
      memoryRepo: runtime.memoryRepo,
      authorizer: runtime.authorizer,
      auditRepo: runtime.auditRepo,
      taskRepo: runtime.taskRepo
    });

    await vSup.verifyClaimAgainstEvidence(admin, { claimId: c1.id, evidenceId: e1.id });
    await vCon.verifyClaimAgainstEvidence(admin, { claimId: c1.id, evidenceId: e1.id });

    const started = await server.start();

    // Out-of-range offset returns 200 with conflicts: [] and total: 1
    const oobRes = await fetch(`${started.url}/api/memories/conflicts?offset=50&limit=10`, {
      headers: { Authorization: `Bearer ${ADMIN_TOKEN}` }
    });
    assert.equal(oobRes.status, 200);
    const oobBody = (await oobRes.json()) as { conflicts: ClaimConflictSummary[]; total: number; includeHistorical: boolean };
    assert.equal(oobBody.total, 1);
    assert.deepEqual(oobBody.conflicts, []);

    const oobMemRes = await fetch(`${started.url}/api/memories/${p1.id}/conflicts?offset=25&limit=5`, {
      headers: { Authorization: `Bearer ${ADMIN_TOKEN}` }
    });
    assert.equal(oobMemRes.status, 200);
    const oobMemBody = (await oobMemRes.json()) as { memoryId: string; conflicts: ClaimConflictSummary[]; total: number };
    assert.equal(oobMemBody.memoryId, p1.id);
    assert.equal(oobMemBody.total, 1);
    assert.deepEqual(oobMemBody.conflicts, []);

    // HTTP conflictType=VERIFIER_DISAGREEMENT returns 1, while VERIFIED_CONTRADICTION returns 0
    const vdHttp = await fetch(`${started.url}/api/memories/conflicts?conflictType=VERIFIER_DISAGREEMENT`, {
      headers: { Authorization: `Bearer ${ADMIN_TOKEN}` }
    });
    assert.equal(vdHttp.status, 200);
    const vdBody = (await vdHttp.json()) as { total: number; conflicts: ClaimConflictSummary[] };
    assert.equal(vdBody.total, 1);
    assert.equal(vdBody.conflicts[0]!.conflictType, 'VERIFIER_DISAGREEMENT');
    assert.equal(vdBody.conflicts[0]!.verifierDisagreements.length, 1);
    assert.equal(vdBody.conflicts[0]!.disputedEvidence.length, 1);
    assert.deepEqual(vdBody.conflicts[0]!.limitationEvidence, []);

    const vcHttp = await fetch(`${started.url}/api/memories/conflicts?conflictType=VERIFIED_CONTRADICTION`, {
      headers: { Authorization: `Bearer ${ADMIN_TOKEN}` }
    });
    assert.equal(vcHttp.status, 200);
    assert.equal(((await vcHttp.json()) as { total: number }).total, 0);

    // Remote CLI filtering with --conflict-type VERIFIER_DISAGREEMENT
    const cliOut: string[] = [];
    const cliErr: string[] = [];
    const cliCode = await runCli(
      [
        '--server',
        started.url,
        '--token',
        ADMIN_TOKEN,
        '--json',
        'memory',
        'conflicts',
        '--conflict-type',
        'VERIFIER_DISAGREEMENT'
      ],
      { stdout: (l) => cliOut.push(l), stderr: (l) => cliErr.push(l) }
    );
    assert.equal(cliCode, 0, cliErr.join('\n'));
    const cliParsed = JSON.parse(cliOut.join('\n')) as { total: number; conflicts: ClaimConflictSummary[] };
    assert.equal(cliParsed.total, 1);
    assert.equal(cliParsed.conflicts[0]!.conflictType, 'VERIFIER_DISAGREEMENT');
    assert.equal(cliParsed.conflicts[0]!.disputedEvidence.length, 1);
    assert.deepEqual(cliParsed.conflicts[0]!.limitationEvidence, []);
  } finally {
    await server.stop().catch(() => undefined);
    rmSync(dir, { recursive: true, force: true });
  }
});

// ============================================================================
// 18. Regression: Deduplicated shared claims across multiple memories do not inflate total
// ============================================================================
test('18. Deduplicated shared claim linked by multiple memories counts once in total', () => {
  const env = setupConflictTestEnv();
  const sharedText = 'Connection keepalive timeout defaults to 65 seconds.';

  const m1 = env.memoryService.createMemory(env.agentAlpha, {
    key: 'shared.keepalive.m1',
    content: sharedText,
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    status: 'PENDING_APPROVAL',
    claims: [{ originalText: sharedText }],
    evidence: [
      {
        sourceType: 'DOCUMENTATION',
        snippet: 'Server keepalive configured to 65s.',
        relationship: 'SUPPORTS',
        targetClaimIndices: [0]
      }
    ]
  });

  const m2 = env.memoryService.createMemory(env.agentAlpha, {
    key: 'shared.keepalive.m2',
    content: 'Load balancer terminates idle keepalive at 30 seconds.',
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    status: 'PENDING_APPROVAL',
    claims: [{ originalText: `  ${sharedText.toLowerCase()}  ` }],
    evidence: [
      {
        sourceType: 'TOOL_EXECUTION',
        snippet: 'Observed FIN packet after 30s idle.',
        relationship: 'CONTRADICTS',
        targetClaimIndices: [0]
      }
    ]
  });

  const m3 = env.memoryService.createMemory(env.agentAlpha, {
    key: 'shared.keepalive.m3',
    content: 'Third independent reference to keepalive.',
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    status: 'PENDING_APPROVAL',
    claims: [{ originalText: sharedText }],
    evidence: [
      {
        sourceType: 'WEB_RESEARCH',
        snippet: 'Gateway documentation lists 65s default.',
        relationship: 'SUPPORTS',
        targetClaimIndices: [0]
      }
    ]
  });

  const c1 = env.memoryService.getClaimsByMemoryId(env.adminAlpha, m1.id)[0]!;
  const c2 = env.memoryService.getClaimsByMemoryId(env.adminAlpha, m2.id)[0]!;
  const c3 = env.memoryService.getClaimsByMemoryId(env.adminAlpha, m3.id)[0]!;
  assert.equal(c1.id, c2.id);
  assert.equal(c2.id, c3.id);

  const res = env.memoryService.listClaimConflicts(env.adminAlpha, { limit: 10, offset: 0 });
  assert.equal(res.total, 1);
  assert.equal(res.conflicts.length, 1);
  assert.equal(res.conflicts[0]!.memories.length, 3);
  assert.equal(res.conflicts[0]!.supportingEvidence.length, 2);
  assert.equal(res.conflicts[0]!.contradictingEvidence.length, 1);
});

// ============================================================================
// 19. Regression: Explicit CONTRADICTS with INSUFFICIENT verification and LIMITATION override
// ============================================================================
test('19. Explicit CONTRADICTS remains unresolved under INSUFFICIENT and resolves cleanly under LIMITATION', async () => {
  const env = setupConflictTestEnv();

  // Case A: Explicit CONTRADICTS verified as INSUFFICIENT stays unresolved EXPLICIT_CONTRADICTION
  const propInsuff = env.memoryService.createMemory(env.agentAlpha, {
    key: 'explicit.contradict.insufficient',
    content: 'Replica lag remains below 100ms.',
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    status: 'PENDING_APPROVAL',
    claims: [{ originalText: 'Replica lag remains below 100ms.' }],
    evidence: [
      {
        sourceType: 'WEB_RESEARCH',
        snippet: 'One screenshot without timestamps showed higher lag.',
        relationship: 'CONTRADICTS',
        targetClaimIndices: [0]
      }
    ]
  });
  const cInsuff = env.memoryService.getClaimsByMemoryId(env.adminAlpha, propInsuff.id)[0]!;
  const eInsuff = env.memoryService.getEvidenceByMemoryId(env.adminAlpha, propInsuff.id)[0]!;
  env.mockProvider.enqueueCompletion(JSON.stringify({
    claimId: cInsuff.id,
    evidenceId: eInsuff.id,
    proposedRelationship: 'INSUFFICIENT',
    outcome: 'INSUFFICIENT',
    confidence: 0.35,
    explanation: 'Screenshot lacks timestamps and region metadata.'
  }));
  await env.engine.verifyProposalClaims(env.agentAlpha, propInsuff.id);

  const insuffConflict = env.memoryService.getConflictByClaimId(env.adminAlpha, cInsuff.id)!;
  assert.ok(insuffConflict);
  assert.equal(insuffConflict.conflictType, 'EXPLICIT_CONTRADICTION');
  assert.equal(insuffConflict.contradictingEvidence.length, 1);
  assert.equal(insuffConflict.contradictingEvidence[0]!.verifications[0]!.verificationOutcome, 'INSUFFICIENT');

  // Case B: Explicit CONTRADICTS verified cleanly as LIMITATION resolves out of contradictingEvidence
  const propLim = env.memoryService.createMemory(env.agentAlpha, {
    key: 'explicit.contradict.limitation',
    content: 'Snapshot isolation prevents dirty reads.',
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    status: 'PENDING_APPROVAL',
    claims: [{ originalText: 'Snapshot isolation prevents dirty reads.' }],
    evidence: [
      {
        sourceType: 'DOCUMENTATION',
        snippet: 'Write skew remains possible under snapshot isolation.',
        relationship: 'CONTRADICTS',
        targetClaimIndices: [0]
      },
      {
        sourceType: 'TOOL_EXECUTION',
        snippet: 'Explicit counterexample claims dirty uncommitted row observed.',
        relationship: 'CONTRADICTS',
        targetClaimIndices: [0]
      }
    ]
  });
  const cLim = env.memoryService.getClaimsByMemoryId(env.adminAlpha, propLim.id)[0]!;
  const eLim = env.memoryService.getEvidenceByMemoryId(env.adminAlpha, propLim.id);
  env.mockProvider.enqueueCompletion(JSON.stringify({
    claimId: cLim.id,
    evidenceId: eLim[0]!.id,
    proposedRelationship: 'LIMITATION',
    outcome: 'PROPOSED',
    confidence: 0.9,
    explanation: 'Write skew narrows isolation guarantees without refuting dirty-read prevention.'
  }));
  await env.engine.verifyClaimAgainstEvidence(env.agentAlpha, {
    claimId: cLim.id,
    evidenceId: eLim[0]!.id
  });

  const limConflict = env.memoryService.getConflictByClaimId(env.adminAlpha, cLim.id)!;
  assert.equal(limConflict.conflictType, 'EXPLICIT_CONTRADICTION');
  assert.equal(limConflict.limitationEvidence.length, 1);
  assert.equal(limConflict.limitationEvidence[0]!.evidenceId, eLim[0]!.id);
  assert.equal(limConflict.limitationEvidence[0]!.relationship, 'CONTRADICTS');
  assert.equal(limConflict.limitationEvidence[0]!.verifications[0]!.proposedRelationship, 'LIMITATION');
  assert.equal(limConflict.contradictingEvidence.length, 1);
  assert.equal(limConflict.contradictingEvidence[0]!.evidenceId, eLim[1]!.id);
});

// ============================================================================
// 20. Regression: Mixed ACTIVE and STALE/INVALIDATED associations in shared historical claim
// ============================================================================
test('20. Shared historical claim mixes ACTIVE M2 and STALE/INVALIDATED M1 only when includeHistorical is true', async () => {
  const env = setupConflictTestEnv();
  const claimText = 'Worker heartbeat interval is 5 seconds.';

  const p1 = env.memoryService.createMemory(env.agentAlpha, {
    key: 'shared.hist.m1',
    content: 'Worker heartbeat contradicts 5s spec.',
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    status: 'PENDING_APPROVAL',
    claims: [{ originalText: claimText }],
    evidence: [
      {
        sourceType: 'TOOL_EXECUTION',
        snippet: 'Trace observed 15s heartbeat.',
        relationship: 'CONTRADICTS',
        targetClaimIndices: [0]
      }
    ]
  });
  const c1 = env.memoryService.getClaimsByMemoryId(env.adminAlpha, p1.id)[0]!;
  const e1 = env.memoryService.getEvidenceByMemoryId(env.adminAlpha, p1.id)[0]!;
  env.mockProvider.enqueueCompletion(JSON.stringify({
    claimId: c1.id, evidenceId: e1.id, proposedRelationship: 'CONTRADICTS', outcome: 'PROPOSED', confidence: 0.92, explanation: '15s != 5s.'
  }));
  await env.engine.verifyProposalClaims(env.agentAlpha, p1.id);
  const m1 = env.memoryService.decideProposal(env.adminAlpha, { memoryId: p1.id, decision: 'APPROVE_NEW' });

  const p2 = env.memoryService.createMemory(env.agentAlpha, {
    key: 'shared.hist.m2',
    content: 'Heartbeat specification v2 confirms 5s.',
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    status: 'PENDING_APPROVAL',
    claims: [{ originalText: claimText }],
    evidence: [
      {
        sourceType: 'DOCUMENTATION',
        snippet: 'Spec defines HEARTBEAT_SEC=5.',
        relationship: 'SUPPORTS',
        targetClaimIndices: [0]
      }
    ]
  });
  const m2 = env.memoryService.decideProposal(env.adminAlpha, { memoryId: p2.id, decision: 'APPROVE_NEW' });

  // Archive M1 -> M1's link/assoc become INVALIDATED and verification becomes STALE, while M2 stays ACTIVE
  env.memoryService.archiveMemory(env.adminAlpha, m1.id);

  assert.equal(env.memoryService.getConflictByClaimId(env.adminAlpha, c1.id), null);
  assert.equal(env.memoryService.getConflictsByMemoryId(env.adminAlpha, m2.id).total, 0);

  const hist = env.memoryService.getConflictByClaimId(env.adminAlpha, c1.id, { includeHistorical: true })!;
  assert.ok(hist);
  assert.equal(hist.isHistorical, true);
  assert.equal(hist.memories.length, 2);
  const o1 = hist.memories.find((m) => m.memoryId === m1.id)!;
  const o2 = hist.memories.find((m) => m.memoryId === m2.id)!;
  assert.equal(o1.status, 'ARCHIVED');
  assert.equal(o1.linkStatus, 'INVALIDATED');
  assert.equal(o2.status, 'ACTIVE');
  assert.equal(o2.linkStatus, 'ACTIVE');
  assert.equal(hist.supportingEvidence.length, 1);
  assert.equal(hist.supportingEvidence[0]!.memoryId, m2.id);
  assert.equal(hist.supportingEvidence[0]!.associationStatus, 'ACTIVE');
  assert.equal(hist.contradictingEvidence.length, 1);
  assert.equal(hist.contradictingEvidence[0]!.memoryId, m1.id);
  assert.equal(hist.contradictingEvidence[0]!.associationStatus, 'INVALIDATED');
  assert.equal(hist.contradictingEvidence[0]!.verifications[0]!.status, 'STALE');
});

// ============================================================================
// 21. Regression: Co-occurring same-evidence verifier disagreement + explicit CONTRADICTS
// ============================================================================
test('21. Co-occurring verifier disagreement and unverified explicit CONTRADICTS surfaces EXPLICIT_CONTRADICTION while keeping disagreement provenance', async () => {
  const env = setupConflictTestEnv();

  const prop = env.memoryService.createMemory(env.agentAlpha, {
    key: 'cooccurring.disagreement.and.explicit',
    content: 'Token revocation propagates in under 1 second.',
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    status: 'PENDING_APPROVAL',
    claims: [{ originalText: 'Token revocation propagates in under 1 second.' }],
    evidence: [
      {
        sourceType: 'DOCUMENTATION',
        snippet: 'Local cache invalidation runs immediately on primary node.',
        relationship: 'SUPPORTS',
        targetClaimIndices: [0]
      },
      {
        sourceType: 'TOOL_EXECUTION',
        snippet: 'Cross-region replica still accepts revoked token for 30s.',
        relationship: 'CONTRADICTS',
        targetClaimIndices: [0]
      }
    ]
  });

  const claim = env.memoryService.getClaimsByMemoryId(env.adminAlpha, prop.id)[0]!;
  const ev = env.memoryService.getEvidenceByMemoryId(env.adminAlpha, prop.id);
  const disputedEv = ev.find((item) => item.relationship === 'SUPPORTS')!;
  const explicitContradictEv = ev.find((item) => item.relationship === 'CONTRADICTS')!;

  const makeEngine = (id: string, rel: 'SUPPORTS' | 'CONTRADICTS', hash: string) =>
    new EvidenceVerificationEngine({
      verifier: {
        verifierId: id,
        verifierVersion: '1.0',
        promptPolicyVersion: 'v1',
        promptPolicyHash: hash,
        async evaluate() {
          return {
            claimId: claim.id,
            evidenceId: disputedEv.id,
            proposedRelationship: rel,
            outcome: 'PROPOSED',
            confidence: 0.85,
            explanation: `${id} says ${rel}`,
            verifierId: id,
            verifierVersion: '1.0'
          };
        }
      },
      memoryRepo: env.memoryRepo,
      authorizer: env.authorizer,
      auditRepo: env.auditRepo,
      taskRepo: env.taskRepo
    });

  await makeEngine('v-co-1', 'SUPPORTS', 'p1').verifyClaimAgainstEvidence(env.agentAlpha, {
    claimId: claim.id,
    evidenceId: disputedEv.id
  });
  await makeEngine('v-co-2', 'CONTRADICTS', 'p2').verifyClaimAgainstEvidence(env.agentAlpha, {
    claimId: claim.id,
    evidenceId: disputedEv.id
  });

  const conflict = env.memoryService.getConflictByClaimId(env.adminAlpha, claim.id)!;
  assert.ok(conflict);
  // Genuine unverified explicit CONTRADICTS takes precedence over same-evidence verifier disagreement
  assert.equal(conflict.conflictType, 'EXPLICIT_CONTRADICTION');
  assert.deepEqual(conflict.supportingEvidence, []);
  assert.deepEqual(conflict.limitationEvidence, []);
  assert.deepEqual(conflict.incomparableEvidence, []);
  assert.equal(conflict.contradictingEvidence.length, 1);
  assert.equal(conflict.contradictingEvidence[0]!.evidenceId, explicitContradictEv.id);
  assert.equal(conflict.disputedEvidence.length, 1);
  assert.equal(conflict.disputedEvidence[0]!.evidenceId, disputedEv.id);
  assert.equal(conflict.disputedEvidence[0]!.hasVerifierDisagreement, true);
  assert.equal(conflict.verifierDisagreements.length, 1);
  assert.equal(conflict.verifierDisagreements[0]!.evidenceId, disputedEv.id);
});

// ============================================================================
// 22. Regression (4F): Empty assumptions hashes across independent evidence are incomparable
// ============================================================================
test('22. Empty assumptions across unrelated evidence sources classify as INCOMPARABLE_CONDITIONS rather than VERIFIED_CONTRADICTION or OPPOSING_VERIFICATIONS', async () => {
  const env = setupConflictTestEnv();

  const propEmpty = env.memoryService.createMemory(env.agentAlpha, {
    key: 'comparability.empty.assumptions',
    content: 'Vector index query p95 is under 12ms.',
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    status: 'PENDING_APPROVAL',
    claims: [{ originalText: 'Vector index query p95 is under 12ms.' }],
    evidence: [
      {
        sourceType: 'TOOL_EXECUTION',
        snippet: 'Dataset 1 run observed 9ms p95.',
        relationship: 'SUPPORTS',
        targetClaimIndices: [0]
      },
      {
        sourceType: 'WEB_RESEARCH',
        snippet: 'External blog reported 45ms p95 on unspecified setup.',
        relationship: 'SUPPORTS',
        targetClaimIndices: [0]
      }
    ]
  });

  const claim = env.memoryService.getClaimsByMemoryId(env.adminAlpha, propEmpty.id)[0]!;
  const ev = env.memoryService.getEvidenceByMemoryId(env.adminAlpha, propEmpty.id);

  env.mockProvider.enqueueCompletion(JSON.stringify({
    claimId: claim.id, evidenceId: ev[0]!.id, proposedRelationship: 'SUPPORTS', outcome: 'PROPOSED', confidence: 0.89, explanation: 'Dataset 1 supports < 12ms.'
  }));
  await env.engine.verifyClaimAgainstEvidence(env.agentAlpha, { claimId: claim.id, evidenceId: ev[0]!.id });

  env.mockProvider.enqueueCompletion(JSON.stringify({
    claimId: claim.id, evidenceId: ev[1]!.id, proposedRelationship: 'CONTRADICTS', outcome: 'PROPOSED', confidence: 0.87, explanation: 'External blog shows 45ms.'
  }));
  await env.engine.verifyClaimAgainstEvidence(env.agentAlpha, { claimId: claim.id, evidenceId: ev[1]!.id });

  assert.equal(env.memoryService.listClaimConflicts(env.adminAlpha, { conflictType: 'OPPOSING_VERIFICATIONS' }).total, 0);
  assert.equal(env.memoryService.listClaimConflicts(env.adminAlpha, { conflictType: 'VERIFIED_CONTRADICTION' }).total, 0);
  assert.equal(env.memoryService.listClaimConflicts(env.adminAlpha, { conflictType: 'VERIFIER_DISAGREEMENT' }).total, 0);

  const summary = env.memoryService.getConflictByClaimId(env.adminAlpha, claim.id)!;
  assert.ok(summary);
  assert.equal(summary.conflictType, 'INCOMPARABLE_CONDITIONS');
  assert.deepEqual(summary.supportingEvidence, []);
  assert.deepEqual(summary.contradictingEvidence, []);
  assert.deepEqual(summary.limitationEvidence, []);
  assert.deepEqual(summary.disputedEvidence, []);
  assert.equal(summary.incomparableEvidence.length, 2);

  // Supplying matching non-empty assumptions on distinct evidence DOES establish OPPOSING_VERIFICATIONS
  const propComp = env.memoryService.createMemory(env.agentAlpha, {
    key: 'comparability.explicit.matching',
    content: 'Column store scan finishes within 3 seconds.',
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    status: 'PENDING_APPROVAL',
    claims: [{ originalText: 'Column store scan finishes within 3 seconds.' }],
    evidence: [
      { sourceType: 'TOOL_EXECUTION', snippet: 'Run 1 = 2.1s', relationship: 'SUPPORTS', targetClaimIndices: [0] },
      { sourceType: 'TOOL_EXECUTION', snippet: 'Run 2 = 6.8s', relationship: 'SUPPORTS', targetClaimIndices: [0] }
    ]
  });
  const cComp = env.memoryService.getClaimsByMemoryId(env.adminAlpha, propComp.id)[0]!;
  const eComp = env.memoryService.getEvidenceByMemoryId(env.adminAlpha, propComp.id);
  env.mockProvider.enqueueCompletion(JSON.stringify({
    claimId: cComp.id, evidenceId: eComp[0]!.id, proposedRelationship: 'SUPPORTS', outcome: 'PROPOSED', confidence: 0.9, explanation: '2.1s < 3s'
  }));
  await env.engine.verifyClaimAgainstEvidence(env.agentAlpha, {
    claimId: cComp.id, evidenceId: eComp[0]!.id, assumptions: ['c7g.4xlarge NVMe 100GB parquet']
  });
  env.mockProvider.enqueueCompletion(JSON.stringify({
    claimId: cComp.id, evidenceId: eComp[1]!.id, proposedRelationship: 'CONTRADICTS', outcome: 'PROPOSED', confidence: 0.9, explanation: '6.8s > 3s'
  }));
  await env.engine.verifyClaimAgainstEvidence(env.agentAlpha, {
    claimId: cComp.id, evidenceId: eComp[1]!.id, assumptions: ['  C7G.4XLARGE NVMe 100GB Parquet ']
  });
  const compSummary = env.memoryService.getConflictByClaimId(env.adminAlpha, cComp.id)!;
  assert.equal(compSummary.conflictType, 'OPPOSING_VERIFICATIONS');
  assert.equal(compSummary.supportingEvidence.length, 1);
  assert.equal(compSummary.contradictingEvidence.length, 1);
  assert.deepEqual(compSummary.incomparableEvidence, []);
});

// ============================================================================
// 23. Regression (4F): Different non-empty assumptions across distinct evidence -> INCOMPARABLE_CONDITIONS
// ============================================================================
test('23. Distinct evidence under different non-empty assumptions classifies as INCOMPARABLE_CONDITIONS and preserves provenance', async () => {
  const env = setupConflictTestEnv();

  const prop = env.memoryService.createMemory(env.agentAlpha, {
    key: 'comparability.distinct.diff.assumptions',
    content: 'Cold start latency stays below 200ms.',
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    status: 'PENDING_APPROVAL',
    claims: [{ originalText: 'Cold start latency stays below 200ms.' }],
    evidence: [
      { sourceType: 'TOOL_EXECUTION', snippet: 'ARM64 snapshot cold start = 140ms.', relationship: 'SUPPORTS', targetClaimIndices: [0] },
      { sourceType: 'TOOL_EXECUTION', snippet: 'Legacy JVM no-JIT warmups = 890ms.', relationship: 'SUPPORTS', targetClaimIndices: [0] }
    ]
  });

  const claim = env.memoryService.getClaimsByMemoryId(env.adminAlpha, prop.id)[0]!;
  const ev = env.memoryService.getEvidenceByMemoryId(env.adminAlpha, prop.id);

  env.mockProvider.enqueueCompletion(JSON.stringify({
    claimId: claim.id, evidenceId: ev[0]!.id, proposedRelationship: 'SUPPORTS', outcome: 'PROPOSED', confidence: 0.91, explanation: '140ms on ARM64 snapshot.'
  }));
  await env.engine.verifyClaimAgainstEvidence(env.agentAlpha, {
    claimId: claim.id, evidenceId: ev[0]!.id, assumptions: ['ARM64 snapshot runtime']
  });

  env.mockProvider.enqueueCompletion(JSON.stringify({
    claimId: claim.id, evidenceId: ev[1]!.id, proposedRelationship: 'CONTRADICTS', outcome: 'PROPOSED', confidence: 0.89, explanation: '890ms on legacy JVM.'
  }));
  await env.engine.verifyClaimAgainstEvidence(env.agentAlpha, {
    claimId: claim.id, evidenceId: ev[1]!.id, assumptions: ['x86_64 unoptimized JVM']
  });

  const summary = env.memoryService.getConflictByClaimId(env.adminAlpha, claim.id)!;
  assert.equal(summary.conflictType, 'INCOMPARABLE_CONDITIONS');
  assert.deepEqual(summary.supportingEvidence, []);
  assert.deepEqual(summary.contradictingEvidence, []);
  assert.deepEqual(summary.limitationEvidence, []);
  assert.deepEqual(summary.disputedEvidence, []);
  assert.equal(summary.incomparableEvidence.length, 2);
  assert.deepEqual([...summary.assumptions].sort(), ['ARM64 snapshot runtime', 'x86_64 unoptimized JVM']);
});

// ============================================================================
// 24. Regression (4F): Explicit CONTRADICTS + opposing verifiers on same evidence preserves both cleanly
// ============================================================================
test('24. Explicit CONTRADICTS with opposing same-evidence verifiers stays VERIFIER_DISAGREEMENT in disputedEvidence and preserves relationship', async () => {
  const env = setupConflictTestEnv();

  const prop = env.memoryService.createMemory(env.agentAlpha, {
    key: 'explicit.contradicts.with.opposing.verifiers',
    content: 'Failover promotes secondary within 5 seconds.',
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    status: 'PENDING_APPROVAL',
    claims: [{ originalText: 'Failover promotes secondary within 5 seconds.' }],
    evidence: [
      {
        sourceType: 'TOOL_EXECUTION',
        snippet: 'Chaos run showed 4.8s promotion plus 1.5s DNS TTL.',
        relationship: 'CONTRADICTS',
        targetClaimIndices: [0]
      }
    ]
  });

  const claim = env.memoryService.getClaimsByMemoryId(env.adminAlpha, prop.id)[0]!;
  const ev = env.memoryService.getEvidenceByMemoryId(env.adminAlpha, prop.id)[0]!;

  const mkVerifier = (id: string, rel: 'SUPPORTS' | 'CONTRADICTS', hash: string) =>
    new EvidenceVerificationEngine({
      verifier: {
        verifierId: id,
        verifierVersion: '1.0',
        promptPolicyVersion: 'v1',
        promptPolicyHash: hash,
        async evaluate() {
          return {
            claimId: claim.id,
            evidenceId: ev.id,
            proposedRelationship: rel,
            outcome: 'PROPOSED',
            confidence: 0.85,
            explanation: `${id}: ${rel}`,
            verifierId: id,
            verifierVersion: '1.0'
          };
        }
      },
      memoryRepo: env.memoryRepo,
      authorizer: env.authorizer,
      auditRepo: env.auditRepo,
      taskRepo: env.taskRepo
    });

  await mkVerifier('v-exp-1', 'SUPPORTS', 'p1').verifyClaimAgainstEvidence(env.agentAlpha, {
    claimId: claim.id, evidenceId: ev.id, assumptions: ['Primary quorum intact']
  });
  await mkVerifier('v-exp-2', 'CONTRADICTS', 'p2').verifyClaimAgainstEvidence(env.agentAlpha, {
    claimId: claim.id, evidenceId: ev.id, assumptions: ['Primary quorum intact']
  });

  const conflict = env.memoryService.getConflictByClaimId(env.adminAlpha, claim.id)!;
  assert.equal(conflict.conflictType, 'VERIFIER_DISAGREEMENT');
  assert.deepEqual(conflict.supportingEvidence, []);
  assert.deepEqual(conflict.contradictingEvidence, []);
  assert.deepEqual(conflict.limitationEvidence, []);
  assert.deepEqual(conflict.incomparableEvidence, []);
  assert.equal(conflict.disputedEvidence.length, 1);
  assert.equal(conflict.disputedEvidence[0]!.evidenceId, ev.id);
  assert.equal(conflict.disputedEvidence[0]!.relationship, 'CONTRADICTS');
  assert.equal(conflict.disputedEvidence[0]!.hasVerifierDisagreement, true);
  assert.equal(conflict.disputedEvidence[0]!.verifications.length, 2);
  assert.equal(conflict.verifierDisagreements.length, 1);
  assert.equal(conflict.verifierDisagreements[0]!.positions.length, 2);
});

// ============================================================================
// 25. Regression (4F): Same-evidence disagreement co-occurring with independent VERIFIED_CONTRADICTION & bucket exclusivity
// ============================================================================
test('25. Co-occurring same-evidence disagreement and independent verified CONTRADICTS classify as VERIFIED_CONTRADICTION with exclusive buckets', async () => {
  const env = setupConflictTestEnv();

  const prop = env.memoryService.createMemory(env.agentAlpha, {
    key: 'cooccurring.disagreement.and.verified.contradict',
    content: 'Compression always reduces JSON payload size.',
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    status: 'PENDING_APPROVAL',
    claims: [{ originalText: 'Compression always reduces JSON payload size.' }],
    evidence: [
      {
        sourceType: 'DOCUMENTATION',
        snippet: 'Middleware compresses bodies >= 1KB.',
        relationship: 'SUPPORTS',
        targetClaimIndices: [0]
      },
      {
        sourceType: 'TOOL_EXECUTION',
        snippet: 'Small 30-byte JSON responses expand to 48 bytes with gzip framing.',
        relationship: 'SUPPORTS',
        targetClaimIndices: [0]
      },
      {
        sourceType: 'DOCUMENTATION',
        snippet: 'Clients without Accept-Encoding skip compression.',
        relationship: 'LIMITATION',
        targetClaimIndices: [0]
      }
    ]
  });

  const claim = env.memoryService.getClaimsByMemoryId(env.adminAlpha, prop.id)[0]!;
  const evs = env.memoryService.getEvidenceByMemoryId(env.adminAlpha, prop.id);
  const disputedEv = evs.find((e) => e.snippet?.includes('Middleware'))!;
  const verifiedContradictEv = evs.find((e) => e.snippet?.includes('Small 30-byte'))!;
  const limitationEv = evs.find((e) => e.relationship === 'LIMITATION')!;

  const mkVerifier = (id: string, rel: 'SUPPORTS' | 'CONTRADICTS', hash: string) =>
    new EvidenceVerificationEngine({
      verifier: {
        verifierId: id,
        verifierVersion: '1.0',
        promptPolicyVersion: 'v1',
        promptPolicyHash: hash,
        async evaluate() {
          return {
            claimId: claim.id,
            evidenceId: disputedEv.id,
            proposedRelationship: rel,
            outcome: 'PROPOSED',
            confidence: 0.85,
            explanation: `${id}: ${rel}`,
            verifierId: id,
            verifierVersion: '1.0'
          };
        }
      },
      memoryRepo: env.memoryRepo,
      authorizer: env.authorizer,
      auditRepo: env.auditRepo,
      taskRepo: env.taskRepo
    });

  await mkVerifier('v-cov-1', 'SUPPORTS', 'p1').verifyClaimAgainstEvidence(env.agentAlpha, {
    claimId: claim.id, evidenceId: disputedEv.id, assumptions: ['API responses']
  });
  await mkVerifier('v-cov-2', 'CONTRADICTS', 'p2').verifyClaimAgainstEvidence(env.agentAlpha, {
    claimId: claim.id, evidenceId: disputedEv.id, assumptions: ['API responses']
  });

  env.mockProvider.enqueueCompletion(JSON.stringify({
    claimId: claim.id,
    evidenceId: verifiedContradictEv.id,
    proposedRelationship: 'CONTRADICTS',
    outcome: 'PROPOSED',
    confidence: 0.94,
    explanation: 'Small payloads expand under gzip framing.'
  }));
  await env.engine.verifyClaimAgainstEvidence(env.agentAlpha, {
    claimId: claim.id,
    evidenceId: verifiedContradictEv.id,
    assumptions: ['API responses']
  });

  const conflict = env.memoryService.getConflictByClaimId(env.adminAlpha, claim.id)!;
  assert.equal(conflict.conflictType, 'VERIFIED_CONTRADICTION');
  assert.equal(conflict.supportingEvidence.length, 0);
  assert.equal(conflict.contradictingEvidence.map((e) => e.evidenceId).join(','), verifiedContradictEv.id);
  assert.equal(conflict.disputedEvidence.map((e) => e.evidenceId).join(','), disputedEv.id);
  assert.equal(conflict.limitationEvidence.map((e) => e.evidenceId).join(','), limitationEv.id);
  assert.equal(conflict.incomparableEvidence.length, 0);
  assert.equal(conflict.verifierDisagreements.length, 1);

  // Strict bucket exclusivity: every evidence ID belongs to at most one bucket
  const allBucketIds = [
    ...conflict.supportingEvidence.map((e) => e.evidenceId),
    ...conflict.contradictingEvidence.map((e) => e.evidenceId),
    ...conflict.limitationEvidence.map((e) => e.evidenceId),
    ...conflict.disputedEvidence.map((e) => e.evidenceId),
    ...conflict.incomparableEvidence.map((e) => e.evidenceId)
  ];
  assert.equal(allBucketIds.length, new Set(allBucketIds).size);
  assert.equal(allBucketIds.length, 3);
});

// ============================================================================
// 26. Regression (4F): HTTP & CLI serialization of INCOMPARABLE_CONDITIONS & CLI --help types
// ============================================================================
test('26. HTTP and CLI expose INCOMPARABLE_CONDITIONS filtering, incomparableEvidence DTO, and complete --help types', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'dots-incomp-cli-'));
  const dbPath = join(dir, 'dots.db');
  const ADMIN_TOKEN = 'admin-incomp-secret-12345';
  const tokens = [
    {
      token: ADMIN_TOKEN,
      principalId: 'alice-alpha',
      role: 'ADMIN' as const,
      permittedScopes: [{ scopeType: 'WORKSPACE' as const, scopeId: 'ws-alpha' }]
    }
  ];

  // Verify --help lists all 5 supported conflict types
  const helpOut: string[] = [];
  const helpCode = await runCli(['--help'], {
    stdout: (l) => helpOut.push(l),
    stderr: () => undefined
  });
  assert.equal(helpCode, 0);
  const helpText = helpOut.join('\n');
  for (const t of [
    'EXPLICIT_CONTRADICTION',
    'VERIFIED_CONTRADICTION',
    'OPPOSING_VERIFICATIONS',
    'VERIFIER_DISAGREEMENT',
    'INCOMPARABLE_CONDITIONS'
  ]) {
    assert.ok(helpText.includes(t), `CLI --help missing conflict type ${t}`);
  }

  const runtime = new DotsRuntime({
    dbPath,
    workspaceRoot: dir,
    host: '127.0.0.1',
    port: 0,
    silentLogs: true,
    enableScheduler: false,
    modelProvider: new MockModelProvider(),
    tokens
  });
  const server = new DotsHttpServer(runtime);

  try {
    const admin = runtime.authorizer.authorizeUser({
      credentials: ADMIN_TOKEN,
      requestedScope: { scopeType: 'WORKSPACE', scopeId: 'ws-alpha' }
    });
    const prop = runtime.memoryService.createMemory(admin, {
      key: 'http.incomparable.item',
      content: 'Cache hit ratio exceeds 95%.',
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: 'ws-alpha',
      status: 'PENDING_APPROVAL',
      claims: [{ originalText: 'Cache hit ratio exceeds 95%.' }],
      evidence: [
        { sourceType: 'TOOL_EXECUTION', snippet: 'Zipf load = 98%.', relationship: 'SUPPORTS', targetClaimIndices: [0] },
        { sourceType: 'TOOL_EXECUTION', snippet: 'Uniform load = 32%.', relationship: 'SUPPORTS', targetClaimIndices: [0] }
      ]
    });
    const claim = runtime.memoryService.getClaimsByMemoryId(admin, prop.id)[0]!;
    const ev = runtime.memoryService.getEvidenceByMemoryId(admin, prop.id);

    const engine = new EvidenceVerificationEngine({
      verifier: {
        verifierId: 'v-http-incomp',
        verifierVersion: '1.0',
        promptPolicyVersion: 'v1',
        promptPolicyHash: 'ph-incomp',
        async evaluate({ evidence }) {
          const isSup = evidence.id === ev[0]!.id;
          return {
            claimId: claim.id,
            evidenceId: evidence.id,
            proposedRelationship: isSup ? 'SUPPORTS' : 'CONTRADICTS',
            outcome: 'PROPOSED',
            confidence: 0.9,
            explanation: isSup ? 'Supports on Zipf.' : 'Fails on uniform.',
            verifierId: 'v-http-incomp',
            verifierVersion: '1.0'
          };
        }
      },
      memoryRepo: runtime.memoryRepo,
      authorizer: runtime.authorizer,
      auditRepo: runtime.auditRepo,
      taskRepo: runtime.taskRepo
    });
    await engine.verifyClaimAgainstEvidence(admin, { claimId: claim.id, evidenceId: ev[0]!.id, assumptions: ['Zipf'] });
    await engine.verifyClaimAgainstEvidence(admin, { claimId: claim.id, evidenceId: ev[1]!.id, assumptions: ['Uniform'] });

    const started = await server.start();

    const httpRes = await fetch(`${started.url}/api/memories/conflicts?conflictType=INCOMPARABLE_CONDITIONS`, {
      headers: { Authorization: `Bearer ${ADMIN_TOKEN}` }
    });
    assert.equal(httpRes.status, 200);
    const httpBody = (await httpRes.json()) as { total: number; conflicts: ClaimConflictSummary[] };
    assert.equal(httpBody.total, 1);
    assert.equal(httpBody.conflicts[0]!.conflictType, 'INCOMPARABLE_CONDITIONS');
    assert.equal(httpBody.conflicts[0]!.incomparableEvidence.length, 2);
    assert.deepEqual(httpBody.conflicts[0]!.disputedEvidence, []);
    assert.deepEqual(httpBody.conflicts[0]!.contradictingEvidence, []);

    const cliOut: string[] = [];
    const cliErr: string[] = [];
    const cliCode = await runCli(
      [
        '--server',
        started.url,
        '--token',
        ADMIN_TOKEN,
        '--json',
        'memory',
        'conflicts',
        '--conflict-type',
        'INCOMPARABLE_CONDITIONS'
      ],
      { stdout: (l) => cliOut.push(l), stderr: (l) => cliErr.push(l) }
    );
    assert.equal(cliCode, 0, cliErr.join('\n'));
    const cliParsed = JSON.parse(cliOut.join('\n')) as { total: number; conflicts: ClaimConflictSummary[] };
    assert.equal(cliParsed.total, 1);
    assert.equal(cliParsed.conflicts[0]!.conflictType, 'INCOMPARABLE_CONDITIONS');
    assert.equal(cliParsed.conflicts[0]!.incomparableEvidence.length, 2);
  } finally {
    await server.stop().catch(() => undefined);
    rmSync(dir, { recursive: true, force: true });
  }
});
