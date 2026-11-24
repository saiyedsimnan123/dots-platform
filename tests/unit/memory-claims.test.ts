/**
 * Next-Generation Dots AI Platform - Atomic Claim Extraction & Normalization Tests
 * Phase 4D.3D.4C.2: Scoped Atomic Claim Representation & Verification Foundation
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseManager } from '../../src/storage/db.ts';
import { MemoryRepository } from '../../src/storage/memory-repository.ts';
import { MemoryService } from '../../src/memory/memory-service.ts';
import { TaskRepository } from '../../src/storage/task-repository.ts';
import { AuditRepository } from '../../src/storage/audit-repository.ts';
import { MemoryAuthorizer } from '../../src/security/memory-authorizer.ts';
import { HostMemoryAuthority } from '../../src/security/host-authority.ts';
import {
  KnowledgeProposalPipeline,
  extractResearchProposals
} from '../../src/memory/knowledge-pipeline.ts';
import {
  stripCitationMarkers,
  canonicalizeClaimText,
  computeClaimHash,
  computeClaimId,
  createAtomicClaim
} from '../../src/memory/claim-normalizer.ts';
import type { AgentOutput } from '../../src/agents/types.ts';
import type {
  ScopeIdentifier,
  CallerContext,
  MemoryClaim
} from '../../src/domain/types.ts';
import {
  ValidationError,
  MemoryScopeViolationError,
  SecurityViolationError
} from '../../src/domain/errors.ts';

function setupClaimsTestEnv() {
  const db = new DatabaseManager(':memory:');
  const taskRepo = new TaskRepository(db);
  const auditRepo = new AuditRepository(db);
  const memoryRepo = new MemoryRepository(db);

  const scopeAlpha: ScopeIdentifier = { scopeType: 'WORKSPACE', scopeId: 'ws-alpha' };
  const scopeBeta: ScopeIdentifier = { scopeType: 'WORKSPACE', scopeId: 'ws-beta' };
  const scopeGlobal: ScopeIdentifier = { scopeType: 'GLOBAL', scopeId: 'default' };

  const identityProvider = {
    authenticate(credentials: unknown) {
      if (typeof credentials !== 'string') return null;
      if (credentials === 'token-admin-alpha') {
        return {
          principalId: 'admin-alpha',
          role: 'ADMIN' as const,
          permittedScopes: [scopeAlpha, scopeGlobal]
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

  // Authorize User Caller for Alpha
  const userCallerAlpha = authorizer.authorizeUser({
    credentials: 'token-admin-alpha',
    requestedScope: scopeAlpha
  });

  // Authorize User Caller for Beta
  const userCallerBeta = authorizer.authorizeUser({
    credentials: 'token-admin-beta',
    requestedScope: scopeBeta
  });

  // Create tasks
  const taskAlpha = hostAuthority.createTask(taskRepo, {
    goal: 'Research Redis distributed caching',
    scope: scopeAlpha,
    principalId: 'admin-alpha'
  });

  const taskBeta = hostAuthority.createTask(taskRepo, {
    goal: 'Research Redis distributed caching independently',
    scope: scopeBeta,
    principalId: 'admin-beta'
  });

  // Authorize Agent Callers
  const agentCallerAlpha = authorizer.authorizeAgent({
    taskId: taskAlpha.id,
    agentId: 'research-agent'
  });

  const agentCallerBeta = authorizer.authorizeAgent({
    taskId: taskBeta.id,
    agentId: 'research-agent'
  });

  return {
    db,
    taskRepo,
    auditRepo,
    memoryRepo,
    memoryService,
    hostAuthority,
    authorizer,
    scopeAlpha,
    scopeBeta,
    scopeGlobal,
    userCallerAlpha,
    userCallerBeta,
    agentCallerAlpha,
    agentCallerBeta,
    taskAlpha,
    taskBeta
  };
}

// ============================================================================
// 1. Citation marker removal from canonical text
// ============================================================================
test('1. Citation marker removal from canonical text', () => {
  // Test various citation marker formats
  const examples = [
    {
      raw: 'Basic Paxos guarantees safety in asynchronous networks [Source: lamport.example].',
      expected: 'basic paxos guarantees safety in asynchronous networks'
    },
    {
      raw: 'Raft enforces a strong leader invariant (Source: https://raft.github.io/raft.pdf).',
      expected: 'raft enforces a strong leader invariant'
    },
    {
      raw: 'QUIC eliminates head-of-line blocking [Ref: RFC 9000].',
      expected: 'quic eliminates head-of-line blocking'
    },
    {
      raw: 'Quantum cryptography provides information-theoretic security [1].',
      expected: 'quantum cryptography provides information-theoretic security'
    },
    {
      raw: 'Multi-version concurrency control reduces read lock contention [1, 2, 3].',
      expected: 'multi-version concurrency control reduces read lock contention'
    },
    {
      raw: 'Columnar storage accelerates analytical aggregates [Source](https://duckdb.org).',
      expected: 'columnar storage accelerates analytical aggregates'
    },
    {
      raw: 'Zero-downtime migrations require expand-contract [Citation: Fowler2015].',
      expected: 'zero-downtime migrations require expand-contract'
    }
  ];

  for (const { raw, expected } of examples) {
    const canonical = canonicalizeClaimText(raw);
    assert.equal(canonical, expected, `Failed to clean citation markers from: ${raw}`);
  }
});

// ============================================================================
// 2. Original claim text preservation
// ============================================================================
test('2. Original claim text preservation', () => {
  const { memoryRepo, scopeAlpha, taskAlpha } = setupClaimsTestEnv();

  const original = 'DuckDB delivers 10x faster execution for analytical queries [Source: duckdb.org].';
  const claim = memoryRepo.addClaim({
    originalText: original,
    scopeType: scopeAlpha.scopeType,
    scopeId: scopeAlpha.scopeId,
    taskId: taskAlpha.id
  });

  // Invariant: originalText must remain completely untouched, retaining exact casing, punctuation, and citation
  assert.equal(claim.originalText, original);
  assert.equal(claim.canonicalText, 'duckdb delivers 10x faster execution for analytical queries');
  assert.ok(claim.claimHash);
  assert.equal(claim.taskId, taskAlpha.id);
});

// ============================================================================
// 3. Stable hash for whitespace/casing variations
// ============================================================================
test('3. Stable hash for whitespace/casing variations', () => {
  const v1 = 'DuckDB is faster for OLAP queries.';
  const v2 = '  duckdb   is   FASTER   for   olap   queries.  ';
  const v3 = 'DuckDB is faster for OLAP queries [Source: duckdb.org].';
  const v4 = 'DUCKDB IS FASTER FOR OLAP QUERIES [1, 2]!';

  const c1 = canonicalizeClaimText(v1);
  const c2 = canonicalizeClaimText(v2);
  const c3 = canonicalizeClaimText(v3);
  const c4 = canonicalizeClaimText(v4);

  assert.equal(c1, 'duckdb is faster for olap queries');
  assert.equal(c2, c1);
  assert.equal(c3, c1);
  assert.equal(c4, c1);

  const h1 = computeClaimHash(c1);
  const h2 = computeClaimHash(c2);
  const h3 = computeClaimHash(c3);
  const h4 = computeClaimHash(c4);

  assert.equal(h1, h2);
  assert.equal(h1, h3);
  assert.equal(h1, h4);
});

// ============================================================================
// 4. Different claims producing different hashes
// ============================================================================
test('4. Different claims producing different hashes (no false equivalence or paraphrase collision)', () => {
  const c1 = canonicalizeClaimText('DuckDB is faster for columnar scans.');
  const c2 = canonicalizeClaimText('SQLite has lower startup latency for embedded reads.');
  const c3 = canonicalizeClaimText('DuckDB delivers high performance for columnar scans.'); // Paraphrase

  const h1 = computeClaimHash(c1);
  const h2 = computeClaimHash(c2);
  const h3 = computeClaimHash(c3);

  assert.notEqual(h1, h2, 'Distinct factual assertions must produce distinct hashes');
  assert.notEqual(h1, h3, 'Paraphrases must NOT have identical hashes without semantic verification');
});

// ============================================================================
// 5. Same claim in different workspaces remaining isolated
// ============================================================================
test('5. Same claim in different workspaces remaining isolated', () => {
  const { memoryRepo, memoryService, scopeAlpha, scopeBeta, userCallerAlpha, userCallerBeta, taskAlpha, taskBeta } =
    setupClaimsTestEnv();

  const identicalText = 'Redis Cluster hash slot migration is atomic per keyspace lock [Source: redis.io].';

  // Workspace Alpha stores the claim
  const claimAlpha = memoryService.createClaim(userCallerAlpha, {
    originalText: identicalText,
    scopeType: scopeAlpha.scopeType,
    scopeId: scopeAlpha.scopeId,
    taskId: taskAlpha.id
  });

  // Workspace Beta stores the identical proposition
  const claimBeta = memoryService.createClaim(userCallerBeta, {
    originalText: identicalText,
    scopeType: scopeBeta.scopeType,
    scopeId: scopeBeta.scopeId,
    taskId: taskBeta.id
  });

  // Invariant 1: Claim hashes are identical because canonical content is identical
  assert.equal(claimAlpha.claimHash, claimBeta.claimHash);

  // Invariant 2: Claim IDs are distinct because ID incorporates scope
  assert.notEqual(claimAlpha.id, claimBeta.id);
  assert.equal(claimAlpha.scopeId, 'ws-alpha');
  assert.equal(claimBeta.scopeId, 'ws-beta');

  // Invariant 3: Workspace Alpha querying by hash receives only Alpha's claim
  const fetchedAlpha = memoryService.getClaimByHash(userCallerAlpha, claimAlpha.claimHash);
  assert.ok(fetchedAlpha);
  assert.equal(fetchedAlpha.id, claimAlpha.id);
  assert.equal(fetchedAlpha.scopeId, 'ws-alpha');

  // Invariant 4: Workspace Beta querying by hash receives only Beta's claim
  const fetchedBeta = memoryService.getClaimByHash(userCallerBeta, claimBeta.claimHash);
  assert.ok(fetchedBeta);
  assert.equal(fetchedBeta.id, claimBeta.id);
  assert.equal(fetchedBeta.scopeId, 'ws-beta');
});

// ============================================================================
// 6. Duplicate claim handling
// ============================================================================
test('6. Duplicate claim handling within same scope is deterministic and idempotent', () => {
  const { memoryRepo, scopeAlpha, taskAlpha } = setupClaimsTestEnv();

  const mem = memoryRepo.createMemory({
    key: 'test.sqlite.wal',
    content: 'WAL mode concurrency documentation',
    category: 'PROJECT_FACT',
    scopeType: scopeAlpha.scopeType,
    scopeId: scopeAlpha.scopeId,
    status: 'ACTIVE'
  });

  const text = 'WAL mode permits concurrent readers without blocking writers.';

  // First insertion
  const first = memoryRepo.addClaim({
    originalText: text,
    scopeType: scopeAlpha.scopeType,
    scopeId: scopeAlpha.scopeId,
    taskId: taskAlpha.id
  });

  assert.equal(first.memoryId, null);

  // Second insertion of identical claim with a linked memoryId
  const second = memoryRepo.addClaim({
    originalText: text,
    scopeType: scopeAlpha.scopeType,
    scopeId: scopeAlpha.scopeId,
    taskId: taskAlpha.id,
    memoryId: mem.id
  });

  // Invariant: returned claim has identical ID and now links mem.id
  assert.equal(second.id, first.id);
  assert.equal(second.claimHash, first.claimHash);
  assert.equal(second.memoryId, mem.id);

  // Database count must remain 1
  const list = memoryRepo.listClaims({
    scopeType: scopeAlpha.scopeType,
    scopeId: scopeAlpha.scopeId
  });
  assert.equal(list.length, 1);
});

// ============================================================================
// 7. Unauthorized claim retrieval rejection
// ============================================================================
test('7. Unauthorized claim retrieval rejection across workspace boundaries', () => {
  const { memoryService, userCallerAlpha, userCallerBeta, scopeBeta, taskBeta } = setupClaimsTestEnv();

  // Create claim in Beta
  const claimBeta = memoryService.createClaim(userCallerBeta, {
    originalText: 'Confidential proprietary benchmark in Beta workspace.',
    scopeType: scopeBeta.scopeType,
    scopeId: scopeBeta.scopeId,
    taskId: taskBeta.id
  });

  // Caller in Alpha attempts to read Beta's claim by ID
  assert.throws(
    () => memoryService.getClaimById(userCallerAlpha, claimBeta.id),
    (err: unknown) => {
      assert.ok(err instanceof MemoryScopeViolationError);
      return true;
    }
  );
});

// ============================================================================
// 8. Malformed and empty claim rejection
// ============================================================================
test('8. Malformed and empty claim rejection', () => {
  const { memoryRepo, scopeAlpha, taskAlpha } = setupClaimsTestEnv();

  // 1. Empty string
  assert.throws(
    () =>
      memoryRepo.addClaim({
        originalText: '',
        scopeType: scopeAlpha.scopeType,
        scopeId: scopeAlpha.scopeId,
        taskId: taskAlpha.id
      }),
    (err: unknown) => {
      assert.ok(err instanceof ValidationError);
      assert.ok(err.message.includes('non-empty string'));
      return true;
    }
  );

  // 2. Whitespace-only string
  assert.throws(
    () =>
      memoryRepo.addClaim({
        originalText: '     \t  \n  ',
        scopeType: scopeAlpha.scopeType,
        scopeId: scopeAlpha.scopeId,
        taskId: taskAlpha.id
      }),
    (err: unknown) => {
      assert.ok(err instanceof ValidationError);
      return true;
    }
  );

  // 3. String consisting purely of citation markers (canonical text becomes empty)
  assert.throws(
    () =>
      memoryRepo.addClaim({
        originalText: '[Source: redis.io] [1, 2]',
        scopeType: scopeAlpha.scopeType,
        scopeId: scopeAlpha.scopeId,
        taskId: taskAlpha.id
      }),
    (err: unknown) => {
      assert.ok(err instanceof ValidationError);
      assert.ok(err.message.includes('citation markers'));
      return true;
    }
  );

  // 4. Missing taskId
  assert.throws(
    () =>
      memoryRepo.addClaim({
        originalText: 'Valid claim text.',
        scopeType: scopeAlpha.scopeType,
        scopeId: scopeAlpha.scopeId,
        taskId: ''
      }),
    (err: unknown) => {
      assert.ok(err instanceof ValidationError);
      assert.ok(err.message.includes('taskId'));
      return true;
    }
  );
});

// ============================================================================
// 9. Migration and persistence behavior (cascades & index uniqueness)
// ============================================================================
test('9. Migration and persistence behavior: schema, foreign keys, and atomic rollback', () => {
  const { db, memoryRepo, scopeAlpha, taskAlpha } = setupClaimsTestEnv();

  // Verify table exists and has proper columns
  const tableInfo = db.prepare("PRAGMA table_info('memory_claims')").all() as Array<{ name: string; type: string }>;
  const colNames = tableInfo.map((c) => c.name);

  assert.ok(colNames.includes('id'));
  assert.ok(colNames.includes('memory_id'));
  assert.ok(colNames.includes('scope_type'));
  assert.ok(colNames.includes('scope_id'));
  assert.ok(colNames.includes('original_text'));
  assert.ok(colNames.includes('canonical_text'));
  assert.ok(colNames.includes('claim_hash'));
  assert.ok(colNames.includes('subject'));
  assert.ok(colNames.includes('predicate'));
  assert.ok(colNames.includes('qualifier'));
  assert.ok(colNames.includes('task_id'));
  assert.ok(colNames.includes('created_at'));

  // Test ON DELETE SET NULL on memory deletion
  const memory = memoryRepo.createMemory({
    key: 'test.memory.claim.fk',
    content: 'Memory content backing claim test',
    category: 'PROJECT_FACT',
    scopeType: scopeAlpha.scopeType,
    scopeId: scopeAlpha.scopeId,
    status: 'ACTIVE'
  });

  const claim = memoryRepo.addClaim({
    memoryId: memory.id,
    originalText: 'Atomic claim referencing memory.',
    scopeType: scopeAlpha.scopeType,
    scopeId: scopeAlpha.scopeId,
    taskId: taskAlpha.id
  });

  assert.equal(claim.memoryId, memory.id);

  // Delete the memory record
  memoryRepo.deleteMemory(memory.id, scopeAlpha);

  // Claim must survive with memoryId set to NULL
  const survivingClaim = memoryRepo.getClaimById(claim.id);
  assert.ok(survivingClaim);
  assert.equal(survivingClaim.memoryId, null, 'Foreign key ON DELETE SET NULL must preserve claim provenance');

  // Test atomic rollback on failure
  assert.throws(() => {
    memoryRepo.transaction(() => {
      memoryRepo.addClaim({
        originalText: 'Claim inside failing transaction.',
        scopeType: scopeAlpha.scopeType,
        scopeId: scopeAlpha.scopeId,
        taskId: taskAlpha.id
      });
      throw new Error('Simulated atomic failure');
    });
  });

  const rolledBack = memoryRepo.listClaims({
    scopeType: scopeAlpha.scopeType,
    scopeId: scopeAlpha.scopeId
  });
  const found = rolledBack.some((c) => c.originalText.includes('failing transaction'));
  assert.equal(found, false, 'Transaction rollback must remove inserted claim');
});

// ============================================================================
// 10. Existing research evidence and memory approval behavior remaining unchanged
// ============================================================================
test('10. Existing research evidence and memory approval behavior remaining unchanged', async () => {
  const { memoryService, userCallerAlpha, agentCallerAlpha, taskAlpha, scopeAlpha } = setupClaimsTestEnv();

  // Create research output
  const output: AgentOutput = {
    agentId: 'research-agent',
    status: 'COMPLETED',
    result: {
      report: {
        completionStatus: 'SUCCESS',
        researchQuestion: 'PostgreSQL vs SQLite for microservices',
        keyFindings: [
          'SQLite achieves sub-millisecond read latency via direct shared memory [Source: sqlite.org].',
          'PostgreSQL requires TCP loopback communication adding latency [Source: postgresql.org].'
        ],
        evidenceAndSources: [
          {
            id: 'src-1',
            title: 'SQLite Architecture',
            url: 'https://sqlite.org/arch',
            domain: 'sqlite.org',
            relationship: 'SUPPORTS',
            targetFindingIndex: 0,
            relevantEvidence: ['Direct shared memory IPC eliminates network overhead.']
          },
          {
            id: 'src-2',
            title: 'PostgreSQL Architecture',
            url: 'https://postgresql.org/arch',
            domain: 'postgresql.org',
            relationship: 'SUPPORTS',
            targetFindingIndex: 1,
            relevantEvidence: ['TCP loopback protocol adds 1ms latency per query roundtrip.']
          }
        ]
      }
    },
    summary: 'Research completed',
    stepsExecuted: 2,
    durationMs: 120
  };

  const pipeline = new KnowledgeProposalPipeline();
  const proposals = await pipeline.processCompletedTask({
    task: taskAlpha,
    agentId: 'research-agent',
    output,
    caller: agentCallerAlpha,
    memoryService
  });

  // Verify proposals submitted in PENDING_APPROVAL
  assert.ok(proposals.length >= 2);
  for (const p of proposals) {
    assert.equal(p.status, 'PENDING_APPROVAL');
  }

  // Finding 0 proposal
  const finding0 = proposals[0]!;
  const evidence0 = memoryService.getEvidenceByMemoryId(agentCallerAlpha, finding0.id);
  assert.ok(evidence0.length > 0);
  assert.equal(evidence0[0]!.sourceDomain, 'sqlite.org');

  // Verify claims were attached and persisted atomically with the proposal
  const claims0 = memoryService.getClaimsByMemoryId(agentCallerAlpha, finding0.id);
  assert.ok(claims0.length > 0);
  assert.ok(claims0[0]!.originalText.includes('SQLite achieves sub-millisecond'));
  assert.equal(claims0[0]!.canonicalText, 'sqlite achieves sub-millisecond read latency via direct shared memory');

  // Verify human approval workflow operates correctly
  const approved = memoryService.decideProposal(userCallerAlpha, {
    memoryId: finding0.id,
    decision: 'APPROVE_NEW'
  });

  assert.equal(approved.status, 'ACTIVE');

  // Evidence and claims survive approval
  const evidenceAfter = memoryService.getEvidenceByMemoryId(userCallerAlpha, finding0.id);
  assert.equal(evidenceAfter.length, evidence0.length);

  const claimsAfter = memoryService.getClaimsByMemoryId(userCallerAlpha, finding0.id);
  assert.equal(claimsAfter.length, claims0.length);

  // Agent cannot approve
  assert.throws(
    () =>
      memoryService.decideProposal(agentCallerAlpha, {
        memoryId: proposals[1]!.id,
        decision: 'APPROVE_NEW'
      }),
    (err: unknown) => {
      assert.ok(err instanceof SecurityViolationError);
      return true;
    }
  );
});
