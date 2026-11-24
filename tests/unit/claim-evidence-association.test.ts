/**
 * Next-Generation Dots AI Platform - Claim-Evidence Association & Linkage Tests
 * Phase 4D.3D.4C.3B: Explicit Claim-to-Evidence Associations and Shared Claim Links
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseManager } from '../../src/storage/db.ts';
import { TaskRepository } from '../../src/storage/task-repository.ts';
import { AuditRepository } from '../../src/storage/audit-repository.ts';
import { MemoryRepository } from '../../src/storage/memory-repository.ts';
import { MemoryService } from '../../src/memory/memory-service.ts';
import { HostMemoryAuthority } from '../../src/security/host-authority.ts';
import { MockModelProvider } from '../../src/model/mock-provider.ts';
import {
  KnowledgeProposalPipeline,
  extractResearchProposals
} from '../../src/memory/knowledge-pipeline.ts';
import {
  EvidenceVerificationEngine,
  VERIFICATION_PROMPT_POLICY_HASH,
  VERIFICATION_PROMPT_POLICY_VERSION,
  type IEvidenceVerifier
} from '../../src/memory/evidence-verifier.ts';
import type { AgentOutput } from '../../src/agents/types.ts';
import type { ScopeIdentifier } from '../../src/domain/types.ts';
import {
  MemoryScopeViolationError,
  ValidationError
} from '../../src/domain/errors.ts';

function setupAssociationTestEnv() {
  const db = new DatabaseManager(':memory:');
  const taskRepo = new TaskRepository(db);
  const auditRepo = new AuditRepository(db);
  const memoryRepo = new MemoryRepository(db);

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
    hostAuthority
  });

  const adminAlpha = authorizer.authorizeUser({
    credentials: 'token-admin-alpha',
    requestedScope: scopeAlpha
  });
  const adminBeta = authorizer.authorizeUser({
    credentials: 'token-admin-beta',
    requestedScope: scopeBeta
  });

  const taskAlpha = hostAuthority.createTask(taskRepo, {
    goal: 'Research and verify architectural claims',
    scope: scopeAlpha,
    principalId: 'admin-alpha'
  });
  const taskBeta = hostAuthority.createTask(taskRepo, {
    goal: 'Research beta workspace claims',
    scope: scopeBeta,
    principalId: 'admin-beta'
  });

  const agentAlpha = authorizer.authorizeAgent({
    taskId: taskAlpha.id,
    agentId: 'research-agent'
  });
  const agentBeta = authorizer.authorizeAgent({
    taskId: taskBeta.id,
    agentId: 'research-agent'
  });

  const mockProvider = new MockModelProvider('mock-assoc-verifier');
  const engine = new EvidenceVerificationEngine({
    modelProvider: mockProvider,
    memoryRepo,
    authorizer,
    auditRepo,
    taskRepo,
    timeoutMs: 250,
    maxConcurrency: 2,
    maxBatchSize: 10,
    confidenceThreshold: 0.7
  });

  return {
    db,
    taskRepo,
    auditRepo,
    memoryRepo,
    hostAuthority,
    authorizer,
    memoryService,
    scopeAlpha,
    scopeBeta,
    adminAlpha,
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
// 1. Two claims & two distinct targeted sources never generate 4 requests
// ============================================================================
test('1. Two claims and two separately associated sources verify only the 2 explicit pairs (no 2x2 Cartesian product)', async () => {
  const env = setupAssociationTestEnv();

  const proposal = env.memoryService.createMemory(env.agentAlpha, {
    key: 'db.and.cache.facts',
    content: 'SQLite WAL improves read concurrency and Redis pipelines reduce RTT.',
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    status: 'PENDING_APPROVAL',
    claims: [
      { originalText: 'SQLite WAL allows concurrent readers alongside one writer.' },
      { originalText: 'Redis pipelining batches commands to reduce network round trips.' }
    ],
    evidence: [
      {
        sourceType: 'DOCUMENTATION',
        sourceUrl: 'https://sqlite.org/wal.html',
        sourceDomain: 'sqlite.org',
        snippet: 'WAL allows readers to proceed concurrently with a single writer.',
        relationship: 'SUPPORTS',
        targetClaimIndices: [0]
      },
      {
        sourceType: 'DOCUMENTATION',
        sourceUrl: 'https://redis.io/docs/pipelining',
        sourceDomain: 'redis.io',
        snippet: 'Pipelining sends multiple commands without waiting for each reply.',
        relationship: 'SUPPORTS',
        targetClaimIndices: [1]
      }
    ]
  });

  const claims = env.memoryService.getClaimsByMemoryId(env.adminAlpha, proposal.id);
  const evidence = env.memoryService.getEvidenceByMemoryId(env.adminAlpha, proposal.id);
  const associations = env.memoryService.getClaimEvidenceAssociationsByMemoryId(env.adminAlpha, proposal.id);

  assert.equal(claims.length, 2);
  assert.equal(evidence.length, 2);
  assert.equal(associations.length, 2, 'Only 2 explicit associations should be persisted, never 4');

  const walClaim = claims.find((c) => c.originalText.includes('SQLite WAL'))!;
  const redisClaim = claims.find((c) => c.originalText.includes('Redis pipelining'))!;
  const walEv = evidence.find((e) => e.sourceDomain === 'sqlite.org')!;
  const redisEv = evidence.find((e) => e.sourceDomain === 'redis.io')!;

  assert.ok(associations.some((a) => a.claimId === walClaim.id && a.evidenceId === walEv.id));
  assert.ok(associations.some((a) => a.claimId === redisClaim.id && a.evidenceId === redisEv.id));

  // Enqueue completions in persisted association order so MockModelProvider returns matching IDs
  for (const assoc of associations) {
    env.mockProvider.enqueueCompletion(
      JSON.stringify({
        claimId: assoc.claimId,
        evidenceId: assoc.evidenceId,
        proposedRelationship: 'SUPPORTS',
        outcome: 'PROPOSED',
        confidence: 0.92,
        explanation: 'Documentation directly confirms associated claim.'
      })
    );
  }

  const results = await env.engine.verifyProposalClaims(env.agentAlpha, proposal.id);
  assert.equal(results.length, 2);
  assert.ok(results.every((r) => r.ok));
  assert.equal(
    env.mockProvider.getRecordedCalls().length,
    2,
    'Provider must be invoked exactly twice, never 4 times'
  );

  // Confirm cross-pair verifications do not exist
  const verifications = env.memoryService.listClaimVerifications(env.adminAlpha);
  assert.equal(verifications.length, 2);
  assert.ok(verifications.some((v) => v.claimId === walClaim.id && v.evidenceId === walEv.id));
  assert.ok(verifications.some((v) => v.claimId === redisClaim.id && v.evidenceId === redisEv.id));
  assert.equal(
    verifications.some((v) => v.claimId === walClaim.id && v.evidenceId === redisEv.id),
    false
  );
  assert.equal(
    verifications.some((v) => v.claimId === redisClaim.id && v.evidenceId === walEv.id),
    false
  );
});

// ============================================================================
// 2. One claim with multiple explicitly associated sources (1:N) & provenance
// ============================================================================
test('2. One claim with multiple explicitly associated sources (SUPPORTS, CONTRADICTS, LIMITATION) preserves all associations and provenance', async () => {
  const env = setupAssociationTestEnv();

  const proposal = env.memoryService.createMemory(env.agentAlpha, {
    key: 'consensus.raft.safety',
    content: 'Raft guarantees linearizability with leader leases.',
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    status: 'PENDING_APPROVAL',
    claims: [
      { originalText: 'Raft leader leases guarantee linearizable reads without quorum round trips.' }
    ],
    evidence: [
      {
        sourceType: 'DOCUMENTATION',
        sourceUrl: 'https://raft.github.io/raft.pdf',
        sourceDomain: 'raft.github.io',
        snippet: 'Leader leases avoid heartbeat quorum overhead when clock drift is bounded.',
        relationship: 'SUPPORTS',
        targetClaimIndices: [0]
      },
      {
        sourceType: 'WEB_RESEARCH',
        sourceUrl: 'https://jepsen.io/clock-skew',
        sourceDomain: 'jepsen.io',
        snippet: 'Unbounded clock jumps or VM pauses break leader lease linearizability.',
        relationship: 'CONTRADICTS',
        targetClaimIndices: [0]
      },
      {
        sourceType: 'WEB_RESEARCH',
        sourceUrl: 'https://systems.example.org/leases',
        sourceDomain: 'systems.example.org',
        snippet: 'Safe only when monotonic clock drift remains strictly below election timeout.',
        relationship: 'LIMITATION',
        targetClaimIndices: [0]
      }
    ]
  });

  const claims = env.memoryService.getClaimsByMemoryId(env.adminAlpha, proposal.id);
  const evidence = env.memoryService.getEvidenceByMemoryId(env.adminAlpha, proposal.id);
  const associations = env.memoryService.getClaimEvidenceAssociationsByClaimId(env.adminAlpha, claims[0]!.id);

  assert.equal(claims.length, 1);
  assert.equal(evidence.length, 3);
  assert.equal(associations.length, 3);
  assert.deepEqual(
    associations.map((a) => a.relationship).sort(),
    ['CONTRADICTS', 'LIMITATION', 'SUPPORTS']
  );

  const relPreservingVerifier: IEvidenceVerifier = {
    verifierId: 'rel-preserving-verifier',
    verifierVersion: '1.0',
    promptPolicyVersion: VERIFICATION_PROMPT_POLICY_VERSION,
    promptPolicyHash: VERIFICATION_PROMPT_POLICY_HASH,
    async evaluate({ claim, evidence: ev }) {
      const stored = env.memoryRepo.getEvidenceById(ev.id, env.scopeAlpha)!;
      return {
        claimId: claim.id,
        evidenceId: ev.id,
        proposedRelationship: stored.relationship,
        outcome: 'PROPOSED',
        confidence: 0.88,
        explanation: `Evaluated ${stored.relationship} provenance.`,
        verifierId: 'rel-preserving-verifier',
        verifierVersion: '1.0'
      };
    }
  };
  const relEngine = new EvidenceVerificationEngine({
    verifier: relPreservingVerifier,
    memoryRepo: env.memoryRepo,
    authorizer: env.authorizer,
    auditRepo: env.auditRepo,
    taskRepo: env.taskRepo,
    maxConcurrency: 2,
    maxBatchSize: 10
  });

  const results = await relEngine.verifyProposalClaims(env.agentAlpha, proposal.id);
  assert.equal(results.length, 3);
  assert.ok(results.every((r) => r.ok));

  const verifications = env.memoryService.getClaimVerificationsByClaimId(env.adminAlpha, claims[0]!.id);
  assert.equal(verifications.length, 3);
  assert.deepEqual(
    verifications.map((v) => v.proposedRelationship).sort(),
    ['CONTRADICTS', 'LIMITATION', 'SUPPORTS']
  );
});

// ============================================================================
// 3. One source explicitly associated with multiple claims (N:1) & composite safety
// ============================================================================
test('3. One source explicitly associated with multiple claims evaluates only targeted claims in direct createMemory and research pipeline', async () => {
  const env = setupAssociationTestEnv();

  // Part A: Direct createMemory with 3 claims and 1 source explicitly targeting [0, 2]
  const multiClaimMem = env.memoryService.createMemory(env.agentAlpha, {
    key: 'tls.13.properties',
    content: 'TLS 1.3 handshake latency and cipher rules.',
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    status: 'PENDING_APPROVAL',
    claims: [
      { originalText: 'TLS 1.3 reduces full handshake latency to 1-RTT.' },
      { originalText: 'TLS 1.3 0-RTT early data is susceptible to replay attacks.' },
      { originalText: 'TLS 1.3 removes legacy RSA key transport.' }
    ],
    evidence: [
      {
        sourceType: 'DOCUMENTATION',
        sourceUrl: 'https://rfc-editor.org/rfc/rfc8446',
        sourceDomain: 'rfc-editor.org',
        snippet: 'RFC 8446 mandates 1-RTT handshakes and removes static RSA key exchange.',
        relationship: 'SUPPORTS',
        targetClaimIndices: [0, 2]
      }
    ]
  });

  const claims = env.memoryService.getClaimsByMemoryId(env.adminAlpha, multiClaimMem.id);
  const evidence = env.memoryService.getEvidenceByMemoryId(env.adminAlpha, multiClaimMem.id);
  const associations = env.memoryService.getClaimEvidenceAssociationsByMemoryId(env.adminAlpha, multiClaimMem.id);

  assert.equal(claims.length, 3);
  assert.equal(evidence.length, 1);
  assert.equal(associations.length, 2);

  const rttClaim = claims.find((c) => c.originalText.includes('1-RTT'))!;
  const zeroRttClaim = claims.find((c) => c.originalText.includes('0-RTT'))!;
  const rsaClaim = claims.find((c) => c.originalText.includes('removes legacy RSA'))!;

  assert.equal(associations.some((a) => a.claimId === rttClaim.id), true);
  assert.equal(associations.some((a) => a.claimId === zeroRttClaim.id), false, 'Untargeted middle claim must NOT be associated');
  assert.equal(associations.some((a) => a.claimId === rsaClaim.id), true);

  for (const assoc of associations) {
    env.mockProvider.enqueueCompletion(
      JSON.stringify({
        claimId: assoc.claimId,
        evidenceId: assoc.evidenceId,
        proposedRelationship: 'SUPPORTS',
        outcome: 'PROPOSED',
        confidence: 0.93,
        explanation: 'RFC 8446 confirms targeted TLS 1.3 requirement.'
      })
    );
  }

  const directResults = await env.engine.verifyProposalClaims(env.agentAlpha, multiClaimMem.id);
  assert.equal(directResults.length, 2);
  assert.equal(env.memoryService.getClaimVerificationsByClaimId(env.adminAlpha, zeroRttClaim.id).length, 0);

  // Part B: Research pipeline with 1 source targeting findings [0, 1] and 1 untargeted general source
  const output: AgentOutput = {
    agentId: 'research-agent',
    status: 'COMPLETED',
    result: {
      report: {
        completionStatus: 'COMPLETED',
        researchQuestion: 'HTTP/3 QUIC transport characteristics',
        keyFindings: [
          'QUIC multiplexes streams independently over UDP.',
          'QUIC encrypts transport headers by default.',
          'Some enterprise firewalls throttle UDP port 443 traffic.'
        ],
        evidenceAndSources: [
          {
            id: 'src-rfc9000',
            title: 'RFC 9000',
            url: 'https://rfc-editor.org/rfc/rfc9000',
            domain: 'rfc-editor.org',
            relationship: 'SUPPORTS',
            targetFindingIndices: [0, 1],
            relevantEvidence: [
              'QUIC streams are independent and transport headers are authenticated and encrypted.'
            ]
          },
          {
            id: 'src-general-overview',
            title: 'General HTTP/3 Survey',
            url: 'https://example.org/http3-survey',
            domain: 'example.org',
            relationship: 'SUPPORTS',
            relevantEvidence: ['Broad adoption across major CDNs occurred by 2024.']
          }
        ]
      }
    },
    summary: 'Completed HTTP/3 research',
    stepsExecuted: 2,
    durationMs: 40
  };

  // Enqueue 2 verifications: individual finding 0 and individual finding 1 ONLY
  const callsBeforePipeline = env.mockProvider.getRecordedCalls().length;
  env.mockProvider.enqueueCompletion(
    JSON.stringify({
      proposedRelationship: 'SUPPORTS',
      outcome: 'PROPOSED',
      confidence: 0.9,
      explanation: 'Confirmed independent streams.'
    })
  );
  env.mockProvider.enqueueCompletion(
    JSON.stringify({
      proposedRelationship: 'SUPPORTS',
      outcome: 'PROPOSED',
      confidence: 0.9,
      explanation: 'Confirmed header encryption.'
    })
  );

  // Use custom verifier that echoes input claimId/evidenceId so we don't have to precompute proposal evidence UUIDs
  const echoVerifier: IEvidenceVerifier = {
    verifierId: 'echo-verifier',
    verifierVersion: '1.0',
    promptPolicyVersion: VERIFICATION_PROMPT_POLICY_VERSION,
    promptPolicyHash: VERIFICATION_PROMPT_POLICY_HASH,
    async evaluate({ claim, evidence: ev }) {
      const stored = env.memoryRepo.getEvidenceById(ev.id, env.scopeAlpha)!;
      return {
        claimId: claim.id,
        evidenceId: ev.id,
        proposedRelationship: stored.relationship,
        outcome: 'PROPOSED',
        confidence: 0.9,
        explanation: `Verified ${stored.relationship} provenance cleanly.`,
        verifierId: 'echo-verifier',
        verifierVersion: '1.0'
      };
    }
  };
  const echoEngine = new EvidenceVerificationEngine({
    verifier: echoVerifier,
    memoryRepo: env.memoryRepo,
    authorizer: env.authorizer,
    auditRepo: env.auditRepo,
    taskRepo: env.taskRepo
  });

  const pipeline = new KnowledgeProposalPipeline();
  const submitted = await pipeline.processCompletedTask({
    task: env.taskAlpha,
    agentId: 'research-agent',
    output,
    caller: env.agentAlpha,
    memoryService: env.memoryService,
    verificationEngine: echoEngine
  });

  // 3 individual proposals + 1 composite proposal
  assert.equal(submitted.length, 4);
  assert.equal(env.mockProvider.getRecordedCalls().length, callsBeforePipeline);

  const finding0Mem = submitted[0]!;
  const finding1Mem = submitted[1]!;
  const finding2Mem = submitted[2]!;
  const compositeMem = submitted[3]!;

  assert.equal(env.memoryService.getClaimEvidenceAssociationsByMemoryId(env.adminAlpha, finding0Mem.id).length, 1);
  assert.equal(env.memoryService.getClaimEvidenceAssociationsByMemoryId(env.adminAlpha, finding1Mem.id).length, 1);
  assert.equal(env.memoryService.getClaimEvidenceAssociationsByMemoryId(env.adminAlpha, finding2Mem.id).length, 0);
  // Composite proposal carries generalEvidence for archival provenance, but zero fabricated claim associations!
  assert.equal(env.memoryService.getEvidenceByMemoryId(env.adminAlpha, compositeMem.id).length, 1);
  assert.equal(env.memoryService.getClaimEvidenceAssociationsByMemoryId(env.adminAlpha, compositeMem.id).length, 0);
  assert.equal(env.memoryService.getClaimsByMemoryId(env.adminAlpha, compositeMem.id).length, 3);

  const allVerifications = env.memoryService
    .listClaimVerifications(env.adminAlpha)
    .filter((v) => v.verifierId === 'echo-verifier');
  assert.equal(allVerifications.length, 2, 'Only finding 0 and finding 1 must be verified');
});

// ============================================================================
// 4. Missing, invalid, and ambiguous associations fail closed
// ============================================================================
test('4. Missing, invalid, out-of-bounds, and ambiguous associations fail closed cleanly', async () => {
  const env = setupAssociationTestEnv();

  // Missing association on direct createMemory: no fabricated association & verifyProposalClaims returns []
  const untargetedMem = env.memoryService.createMemory(env.agentAlpha, {
    key: 'untargeted.proposal',
    content: 'Cache invalidation requires bounded TTLs.',
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    status: 'PENDING_APPROVAL',
    claims: [{ originalText: 'Cache invalidation requires bounded TTLs.' }],
    evidence: [
      {
        sourceType: 'DOCUMENTATION',
        sourceUrl: 'https://docs.example.org/cache',
        snippet: 'Bounded TTLs prevent stale entry accumulation.',
        relationship: 'SUPPORTS'
      }
    ]
  });
  assert.equal(env.memoryService.getClaimEvidenceAssociationsByMemoryId(env.adminAlpha, untargetedMem.id).length, 0);
  const missingAssocResults = await env.engine.verifyProposalClaims(env.agentAlpha, untargetedMem.id);
  assert.deepEqual(missingAssocResults, []);
  assert.equal(env.mockProvider.getRecordedCalls().length, 0);

  // Invalid targetClaimIndices fail closed and roll back memory creation atomically
  const invalidCases: Array<{ label: string; evidence: Record<string, unknown>; claims?: Array<{ originalText: string }> }> = [
    {
      label: 'empty targetClaimIndices',
      claims: [{ originalText: 'Claim zero.' }],
      evidence: { sourceType: 'DOCUMENTATION', snippet: 'Snippet.', relationship: 'SUPPORTS', targetClaimIndices: [] }
    },
    {
      label: 'negative targetClaimIndices',
      claims: [{ originalText: 'Claim zero.' }],
      evidence: { sourceType: 'DOCUMENTATION', snippet: 'Snippet.', relationship: 'SUPPORTS', targetClaimIndices: [-1] }
    },
    {
      label: 'out-of-bounds targetClaimIndices',
      claims: [{ originalText: 'Claim zero.' }],
      evidence: { sourceType: 'DOCUMENTATION', snippet: 'Snippet.', relationship: 'SUPPORTS', targetClaimIndices: [1] }
    },
    {
      label: 'duplicate targetClaimIndices',
      claims: [{ originalText: 'Claim zero.' }],
      evidence: { sourceType: 'DOCUMENTATION', snippet: 'Snippet.', relationship: 'SUPPORTS', targetClaimIndices: [0, 0] }
    },
    {
      label: 'targetClaimIndices when claims array omitted',
      evidence: { sourceType: 'DOCUMENTATION', snippet: 'Snippet.', relationship: 'SUPPORTS', targetClaimIndices: [0] }
    },
    {
      label: 'empty targetClaimIds',
      claims: [{ originalText: 'Claim zero.' }],
      evidence: { sourceType: 'DOCUMENTATION', snippet: 'Snippet.', relationship: 'SUPPORTS', targetClaimIds: [] }
    },
    {
      label: 'non-existent targetClaimId',
      claims: [{ originalText: 'Claim zero.' }],
      evidence: { sourceType: 'DOCUMENTATION', snippet: 'Snippet.', relationship: 'SUPPORTS', targetClaimIds: ['claim-does-not-exist'] }
    }
  ];

  for (let i = 0; i < invalidCases.length; i++) {
    const testCase = invalidCases[i]!;
    const badKey = `invalid.assoc.${i}`;
    assert.throws(
      () =>
        env.memoryService.createMemory(env.agentAlpha, {
          key: badKey,
          content: `Invalid association test ${testCase.label}`,
          category: 'PROJECT_FACT',
          scopeType: env.scopeAlpha.scopeType,
          scopeId: env.scopeAlpha.scopeId,
          status: 'PENDING_APPROVAL',
          claims: testCase.claims,
          evidence: [testCase.evidence as any]
        }),
      (err) => err instanceof ValidationError,
      `Expected ValidationError for ${testCase.label}`
    );
    // Verify rollback left zero memory rows behind
    assert.equal(env.memoryRepo.getMemoryByKey(badKey, env.scopeAlpha, 'PENDING_APPROVAL'), null);
  }

  // Pipeline: malformed partial array [0, 99], conflicting fields, ambiguous text target, and unknown string target fail closed
  const badOutput: AgentOutput = {
    agentId: 'research-agent',
    status: 'COMPLETED',
    result: {
      report: {
        completionStatus: 'COMPLETED',
        researchQuestion: 'Target validation edge cases',
        keyFindings: [
          'Identical ambiguous statement',
          'Identical ambiguous statement',
          'Distinct third finding'
        ],
        evidenceAndSources: [
          {
            id: 'src-valid-anchor',
            url: 'https://example.org/valid',
            domain: 'example.org',
            relationship: 'SUPPORTS',
            targetFindingIndex: 2,
            relevantEvidence: ['Supports distinct third finding only.']
          },
          {
            id: 'src-partial-oob',
            url: 'https://example.org/oob',
            domain: 'example.org',
            relationship: 'SUPPORTS',
            targetFindingIndices: [0, 99],
            relevantEvidence: ['Should fail closed rather than attaching to finding 0 or composite.']
          },
          {
            id: 'src-conflicting',
            url: 'https://example.org/conflict',
            domain: 'example.org',
            relationship: 'SUPPORTS',
            targetFindingIndex: 0,
            targetFinding: 'finding-3',
            relevantEvidence: ['Conflicting specifiers must fail closed.']
          },
          {
            id: 'src-ambiguous-text',
            url: 'https://example.org/ambiguous',
            domain: 'example.org',
            relationship: 'SUPPORTS',
            targetFinding: 'Identical ambiguous statement',
            relevantEvidence: ['Ambiguous string target matching 2 findings must fail closed.']
          },
          {
            id: 'src-nonexistent-text',
            url: 'https://example.org/unknown',
            domain: 'example.org',
            relationship: 'SUPPORTS',
            targetFinding: 'No such finding exists',
            relevantEvidence: ['Unknown targetFinding must not leak into composite generalSources.']
          }
        ]
      }
    },
    summary: 'Edge-case attribution check',
    stepsExecuted: 1,
    durationMs: 10
  };

  const proposals = extractResearchProposals(badOutput, 'Target validation edge cases');
  // Because src-valid-anchor succeeded on index 2, we get 3 individual + 1 composite
  assert.equal(proposals.length, 4);
  assert.equal(proposals[0]!.evidence, undefined);
  assert.equal(proposals[1]!.evidence, undefined);
  assert.equal(proposals[2]!.evidence?.length, 1);
  assert.deepEqual(proposals[2]!.evidence![0]!.targetClaimIndices, [0]);
  // Composite summary MUST NOT absorb malformed/conflicting/ambiguous/unknown targeted sources
  assert.equal(proposals[3]!.evidence, undefined);
});

// ============================================================================
// 5. Shared canonical claim text linked across multiple memories & proposals
// ============================================================================
test('5. Shared claim text deduplicates canonical row while preserving links and associations across multiple memories', () => {
  const env = setupAssociationTestEnv();

  const sharedClaimText = 'Node 24 strips TypeScript types natively without transpilation.';

  const mem1 = env.memoryService.createMemory(env.agentAlpha, {
    key: 'node.ts.finding.1',
    content: 'Finding 1 on Node 24 TypeScript.',
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    status: 'PENDING_APPROVAL',
    claims: [{ originalText: sharedClaimText }],
    evidence: [
      {
        sourceType: 'DOCUMENTATION',
        sourceUrl: 'https://nodejs.org/api/typescript.html',
        snippet: 'Node runs type-only TypeScript syntax directly.',
        relationship: 'SUPPORTS',
        targetClaimIndices: [0]
      }
    ]
  });

  // Second memory references identical canonical claim text with different casing/citations
  const mem2 = env.memoryService.createMemory(env.agentAlpha, {
    key: 'node.ts.composite',
    content: 'Composite summary referencing same Node 24 claim plus additional finding.',
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    status: 'PENDING_APPROVAL',
    claims: [
      { originalText: 'node 24 strips typescript types natively without transpilation [Source: nodejs.org]' },
      { originalText: 'Enums remain disallowed under strip-only mode.' }
    ],
    evidence: [
      {
        sourceType: 'CODE_VERIFICATION',
        snippet: 'Tested type stripping against Node 24 runtime directly.',
        relationship: 'SUPPORTS',
        targetClaimIndices: [0]
      }
    ]
  });

  const claims1 = env.memoryService.getClaimsByMemoryId(env.adminAlpha, mem1.id);
  const claims2 = env.memoryService.getClaimsByMemoryId(env.adminAlpha, mem2.id);

  assert.equal(claims1.length, 1);
  assert.equal(claims2.length, 2);
  assert.equal(
    claims2[0]!.id,
    claims1[0]!.id,
    'Canonical claim row must remain deduplicated in scope'
  );

  // Repository listClaims({ memoryId }) also resolves shared claim via memory_claim_links
  const listedForMem2 = env.memoryRepo.listClaims({
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    memoryId: mem2.id
  });
  assert.equal(listedForMem2.length, 2);
  assert.ok(listedForMem2.some((c) => c.id === claims1[0]!.id));

  // Each memory preserves its own explicit association pointing to the shared claim ID
  const assoc1 = env.memoryService.getClaimEvidenceAssociationsByMemoryId(env.adminAlpha, mem1.id);
  const assoc2 = env.memoryService.getClaimEvidenceAssociationsByMemoryId(env.adminAlpha, mem2.id);
  assert.equal(assoc1.length, 1);
  assert.equal(assoc2.length, 1);
  assert.equal(assoc1[0]!.claimId, claims1[0]!.id);
  assert.equal(assoc2[0]!.claimId, claims1[0]!.id);
  assert.notEqual(assoc1[0]!.evidenceId, assoc2[0]!.evidenceId);

  // Deleting mem1 preserves mem2's link to the shared claim and mem2's association
  env.memoryRepo.deleteMemory(mem1.id, env.scopeAlpha);
  const claims2AfterDelete = env.memoryService.getClaimsByMemoryId(env.adminAlpha, mem2.id);
  assert.equal(claims2AfterDelete.length, 2);
  assert.equal(claims2AfterDelete[0]!.id, claims1[0]!.id);
  assert.equal(env.memoryService.getClaimEvidenceAssociationsByMemoryId(env.adminAlpha, mem2.id).length, 1);
});

// ============================================================================
// 6. UPDATE proposals and composite summaries preserve links without auto-approval/supersession
// ============================================================================
test('6. UPDATE proposals and composite summaries retain shared claim links, verify explicitly, and never auto-approve or supersede', async () => {
  const env = setupAssociationTestEnv();

  // Existing ACTIVE memory sharing one claim
  const activeKey = 'research.finding.postgresql-wal-retention';
  const activeMem = env.memoryRepo.createMemory({
    key: activeKey,
    content: 'Research Topic: PostgreSQL WAL retention\n\nPrevious baseline findings.',
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    status: 'ACTIVE'
  });
  const sharedClaim = env.memoryRepo.addClaim({
    memoryId: activeMem.id,
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    originalText: 'PostgreSQL keeps WAL segments needed by replication slots.',
    taskId: env.taskAlpha.id
  });

  const verifier: IEvidenceVerifier = {
    verifierId: 'update-test-verifier',
    verifierVersion: '1.0',
    promptPolicyVersion: VERIFICATION_PROMPT_POLICY_VERSION,
    promptPolicyHash: VERIFICATION_PROMPT_POLICY_HASH,
    async evaluate({ claim, evidence }) {
      const stored = env.memoryRepo.getEvidenceById(evidence.id, env.scopeAlpha)!;
      return {
        claimId: claim.id,
        evidenceId: evidence.id,
        proposedRelationship: stored.relationship,
        outcome: 'PROPOSED',
        confidence: 0.99,
        explanation: 'High-confidence verification candidate.',
        verifierId: 'update-test-verifier',
        verifierVersion: '1.0'
      };
    }
  };

  const engine = new EvidenceVerificationEngine({
    verifier,
    memoryRepo: env.memoryRepo,
    authorizer: env.authorizer,
    auditRepo: env.auditRepo,
    taskRepo: env.taskRepo
  });

  const output: AgentOutput = {
    agentId: 'research-agent',
    status: 'COMPLETED',
    result: {
      report: {
        completionStatus: 'COMPLETED',
        researchQuestion: 'PostgreSQL WAL retention',
        keyFindings: [
          'PostgreSQL keeps WAL segments needed by replication slots.',
          'max_slot_wal_keep_size bounds retained WAL when standby disconnects.'
        ],
        evidenceAndSources: [
          {
            id: 'src-slots',
            title: 'PostgreSQL Replication Slots Docs',
            url: 'https://www.postgresql.org/docs/current/warm-standby.html',
            domain: 'www.postgresql.org',
            relationship: 'SUPPORTS',
            targetFindingIndex: 0,
            relevantEvidence: ['Replication slots prevent removal of WAL segments not yet received by standby.']
          },
          {
            id: 'src-max-slot-wal',
            title: 'PostgreSQL Runtime Config Replication',
            url: 'https://www.postgresql.org/docs/current/runtime-config-replication.html',
            domain: 'www.postgresql.org',
            relationship: 'LIMITATION',
            targetFindingIndex: 1,
            relevantEvidence: ['Exceeding max_slot_wal_keep_size invalidates the replication slot.']
          }
        ]
      }
    },
    summary: 'Completed WAL retention research',
    stepsExecuted: 2,
    durationMs: 30
  };

  const pipeline = new KnowledgeProposalPipeline();
  const submitted = await pipeline.processCompletedTask({
    task: env.taskAlpha,
    agentId: 'research-agent',
    output,
    caller: env.agentAlpha,
    memoryService: env.memoryService,
    verificationEngine: engine
  });

  // Expect 2 individual proposals + 1 composite proposal (which is UPDATE targeting activeMem)
  assert.equal(submitted.length, 3);
  const updateComposite = submitted.find((m) => {
    const meta = JSON.parse(m.metadataJson ?? '{}') as Record<string, unknown>;
    return meta.proposalType === 'UPDATE';
  });
  assert.ok(updateComposite, 'Composite proposal matching activeKey must be submitted as UPDATE proposal');
  const updateMeta = JSON.parse(updateComposite.metadataJson ?? '{}') as Record<string, unknown>;
  assert.equal(updateMeta.targetMemoryId, activeMem.id);
  assert.equal(updateComposite.status, 'PENDING_APPROVAL');

  // Finding 0 proposal, activeMem, and UPDATE composite ALL retain links to sharedClaim!
  const finding0Claims = env.memoryService.getClaimsByMemoryId(env.adminAlpha, submitted[0]!.id);
  const compositeClaims = env.memoryService.getClaimsByMemoryId(env.adminAlpha, updateComposite.id);
  const activeClaims = env.memoryService.getClaimsByMemoryId(env.adminAlpha, activeMem.id);
  assert.equal(finding0Claims[0]!.id, sharedClaim.id);
  assert.equal(compositeClaims.length, 2);
  assert.equal(compositeClaims[0]!.id, sharedClaim.id);
  assert.equal(activeClaims[0]!.id, sharedClaim.id);

  // Finding 1 LIMITATION verification preserved LIMITATION relationship
  const finding1Verifs = env.memoryService.getClaimVerificationsByClaimId(
    env.adminAlpha,
    compositeClaims[1]!.id
  );
  assert.equal(finding1Verifs.length, 1);
  assert.equal(finding1Verifs[0]!.proposedRelationship, 'LIMITATION');

  // Despite 0.99 confidence, activeMem remains ACTIVE & non-superseded, and all proposals stay PENDING_APPROVAL
  const activeAfter = env.memoryRepo.getMemoryById(activeMem.id, env.scopeAlpha);
  assert.equal(activeAfter?.status, 'ACTIVE');
  assert.equal(activeAfter?.supersededBy, null);
  for (const prop of submitted) {
    assert.equal(prop.status, 'PENDING_APPROVAL');
  }
});

// ============================================================================
// 7. Cross-workspace isolation across claims, associations, and verification
// ============================================================================
test('7. Cross-workspace isolation rejects cross-scope claim links, targetClaimIds, and association reads', async () => {
  const env = setupAssociationTestEnv();

  const betaMem = env.memoryService.createMemory(env.agentBeta, {
    key: 'beta.secret.claim',
    content: 'Beta workspace internal policy.',
    category: 'PROJECT_FACT',
    scopeType: env.scopeBeta.scopeType,
    scopeId: env.scopeBeta.scopeId,
    status: 'PENDING_APPROVAL',
    claims: [{ originalText: 'Beta uses private VPC endpoints only.' }],
    evidence: [
      {
        sourceType: 'DOCUMENTATION',
        snippet: 'Private VPC policy v1.',
        relationship: 'SUPPORTS',
        targetClaimIndices: [0]
      }
    ]
  });

  const betaClaims = env.memoryService.getClaimsByMemoryId(env.adminBeta, betaMem.id);
  const betaEvidence = env.memoryService.getEvidenceByMemoryId(env.adminBeta, betaMem.id);
  assert.equal(betaClaims.length, 1);
  assert.equal(betaEvidence.length, 1);

  // 7a. Alpha caller trying createMemory with targetClaimIds pointing to Beta claim fails closed
  assert.throws(
    () =>
      env.memoryService.createMemory(env.agentAlpha, {
        key: 'alpha.cross.scope.attack',
        content: 'Attempt to reference beta claim.',
        category: 'PROJECT_FACT',
        scopeType: env.scopeAlpha.scopeType,
        scopeId: env.scopeAlpha.scopeId,
        status: 'PENDING_APPROVAL',
        claims: [{ originalText: 'Alpha unrelated claim.' }],
        evidence: [
          {
            sourceType: 'WEB_RESEARCH',
            snippet: 'Cross-tenant probe.',
            relationship: 'SUPPORTS',
            targetClaimIds: [betaClaims[0]!.id]
          }
        ]
      }),
    (err) => err instanceof MemoryScopeViolationError
  );
  assert.equal(
    env.memoryRepo.getMemoryByKey('alpha.cross.scope.attack', env.scopeAlpha, 'PENDING_APPROVAL'),
    null
  );

  // 7b. Repository addClaim rejects linking a memory from Beta inside Alpha scope
  assert.throws(
    () =>
      env.memoryRepo.addClaim({
        memoryId: betaMem.id,
        scopeType: env.scopeAlpha.scopeType,
        scopeId: env.scopeAlpha.scopeId,
        originalText: 'Cross-scope link attempt.',
        taskId: env.taskAlpha.id
      }),
    (err) => err instanceof MemoryScopeViolationError
  );

  // 7c. Repository addClaimEvidenceAssociation rejects mismatched scope/claim/evidence
  const alphaMem = env.memoryService.createMemory(env.agentAlpha, {
    key: 'alpha.own.claim',
    content: 'Alpha memory.',
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    status: 'PENDING_APPROVAL',
    claims: [{ originalText: 'Alpha own claim.' }]
  });
  const alphaClaims = env.memoryService.getClaimsByMemoryId(env.adminAlpha, alphaMem.id);
  assert.throws(
    () =>
      env.memoryRepo.addClaimEvidenceAssociation({
        claimId: alphaClaims[0]!.id,
        evidenceId: betaEvidence[0]!.id,
        memoryId: alphaMem.id,
        scopeType: env.scopeAlpha.scopeType,
        scopeId: env.scopeAlpha.scopeId
      }),
    (err) => err instanceof MemoryScopeViolationError
  );

  // 7d. Cross-scope association reads and verification fail with MemoryScopeViolationError
  assert.throws(
    () => env.memoryService.getClaimEvidenceAssociationsByMemoryId(env.adminAlpha, betaMem.id),
    (err) => err instanceof MemoryScopeViolationError
  );
  await assert.rejects(
    () => env.engine.verifyProposalClaims(env.agentAlpha, betaMem.id),
    (err) => err instanceof MemoryScopeViolationError
  );

  // 7e. Conflicting association relationship override is rejected
  const alphaEv = env.memoryRepo.addEvidence({
    memoryId: alphaMem.id,
    sourceType: 'DOCUMENTATION',
    snippet: 'Supporting snippet.',
    relationship: 'SUPPORTS',
    taskId: env.taskAlpha.id,
    agentId: 'research-agent'
  });
  assert.throws(
    () =>
      env.memoryRepo.addClaimEvidenceAssociation({
        claimId: alphaClaims[0]!.id,
        evidenceId: alphaEv.id,
        memoryId: alphaMem.id,
        scopeType: env.scopeAlpha.scopeType,
        scopeId: env.scopeAlpha.scopeId,
        relationship: 'CONTRADICTS'
      }),
    (err) => err instanceof ValidationError
  );
});

// ============================================================================
// 8. Concurrent duplicate requests & default-off pipeline behavior
// ============================================================================
test('8. Concurrent duplicate verifyProposalClaims calls coalesce cleanly and pipeline keeps verification disabled by default', async () => {
  const env = setupAssociationTestEnv();

  let evaluations = 0;
  const slowVerifier: IEvidenceVerifier = {
    verifierId: 'concurrent-assoc-verifier',
    verifierVersion: '1.0',
    promptPolicyVersion: VERIFICATION_PROMPT_POLICY_VERSION,
    promptPolicyHash: VERIFICATION_PROMPT_POLICY_HASH,
    async evaluate({ claim, evidence }) {
      evaluations++;
      await new Promise((r) => setTimeout(r, 25));
      return {
        claimId: claim.id,
        evidenceId: evidence.id,
        proposedRelationship: 'SUPPORTS',
        outcome: 'PROPOSED',
        confidence: 0.91,
        explanation: 'Coalesced verification result.',
        verifierId: 'concurrent-assoc-verifier',
        verifierVersion: '1.0'
      };
    }
  };
  const concurrentEngine = new EvidenceVerificationEngine({
    verifier: slowVerifier,
    memoryRepo: env.memoryRepo,
    authorizer: env.authorizer,
    auditRepo: env.auditRepo,
    taskRepo: env.taskRepo,
    maxConcurrency: 2,
    maxBatchSize: 10
  });

  const proposal = env.memoryService.createMemory(env.agentAlpha, {
    key: 'concurrent.verify.test',
    content: 'WAL mode supports concurrent readers.',
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    status: 'PENDING_APPROVAL',
    claims: [
      { originalText: 'Claim 1.' },
      { originalText: 'Claim 2.' }
    ],
    evidence: [
      {
        sourceType: 'DOCUMENTATION',
        snippet: 'Evidence for Claim 1.',
        relationship: 'SUPPORTS',
        targetClaimIndices: [0]
      }
    ]
  });

  const [r1, r2] = await Promise.all([
    concurrentEngine.verifyProposalClaims(env.agentAlpha, proposal.id),
    concurrentEngine.verifyProposalClaims(env.agentAlpha, proposal.id)
  ]);

  assert.equal(r1.length, 1);
  assert.equal(r2.length, 1);
  assert.equal(r1[0]!.ok, true);
  assert.equal(r2[0]!.ok, true);
  assert.equal(evaluations, 1, 'Concurrent duplicate verifyProposalClaims calls must coalesce to 1 verifier invocation');
  assert.equal(
    env.memoryService
      .listClaimVerifications(env.adminAlpha)
      .filter((v) => v.verifierId === 'concurrent-assoc-verifier').length,
    1
  );

  // Default KnowledgeProposalPipeline without verificationEngine never runs verification automatically
  const defaultPipeline = new KnowledgeProposalPipeline();
  const defaultOutput: AgentOutput = {
    agentId: 'research-agent',
    status: 'COMPLETED',
    result: {
      report: {
        completionStatus: 'COMPLETED',
        researchQuestion: 'Default off verification check',
        keyFindings: ['Explicit verification opt-in remains false by default.'],
        evidenceAndSources: [
          {
            id: 'src-default-off',
            url: 'https://docs.example.org/default-off',
            domain: 'docs.example.org',
            relationship: 'SUPPORTS',
            targetFindingIndex: 0,
            relevantEvidence: ['Verification must remain disabled unless explicitly enabled.']
          }
        ]
      }
    },
    summary: 'Default-off check',
    stepsExecuted: 1,
    durationMs: 10
  };

  const defaultSubmitted = await defaultPipeline.processCompletedTask({
    task: env.taskAlpha,
    agentId: 'research-agent',
    output: defaultOutput,
    caller: env.agentAlpha,
    memoryService: env.memoryService
  });
  assert.equal(defaultSubmitted.length, 1);
  const defaultClaims = env.memoryService.getClaimsByMemoryId(env.adminAlpha, defaultSubmitted[0]!.id);
  const defaultAssocs = env.memoryService.getClaimEvidenceAssociationsByMemoryId(env.adminAlpha, defaultSubmitted[0]!.id);
  assert.equal(defaultClaims.length, 1);
  assert.equal(defaultAssocs.length, 1);
  assert.equal(
    env.memoryService.getClaimVerificationsByClaimId(env.adminAlpha, defaultClaims[0]!.id).length,
    0,
    'Verification must NOT run when verificationEngine is not provided (default-off)'
  );
});
