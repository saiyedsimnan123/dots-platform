/**
 * Next-Generation Dots AI Platform - Phase 4D.3D.4B: Structured Evidence Foundation Tests
 * 
 * Verifies:
 * 1. Structured research evidence extraction.
 * 2. Developer evidence extraction where applicable.
 * 3. Correct source URL and domain preservation.
 * 4. Missing source information does not produce fabricated evidence.
 * 5. Evidence is persisted with its pending proposal.
 * 6. Evidence insertion failure rolls back proposal creation.
 * 7. Evidence remains available after task cleanup.
 * 8. Duplicate evidence handling.
 * 9. Untrusted agent metadata cannot forge task or agent provenance.
 * 10. Workspace authorization prevents cross-scope evidence access.
 * 11. Existing evidence-free proposal behavior remains compatible.
 * 12. Existing approval, rejection, and supersession tests remain passing.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseManager } from '../../src/storage/db.ts';
import { TaskRepository } from '../../src/storage/task-repository.ts';
import { AuditRepository } from '../../src/storage/audit-repository.ts';
import {
  MemoryRepository,
  computeSnippetHash,
  computeEvidenceId
} from '../../src/storage/memory-repository.ts';
import { MemoryService } from '../../src/memory/memory-service.ts';
import { HostMemoryAuthority } from '../../src/security/host-authority.ts';
import {
  KnowledgeProposalPipeline,
  extractResearchProposals,
  extractDeveloperProposals,
  normalizeDomain,
  extractDomainFromUrl
} from '../../src/memory/knowledge-pipeline.ts';
import type { AgentOutput } from '../../src/agents/types.ts';
import type {
  ScopeIdentifier,
  CallerContext,
  Memory,
  CandidateEvidence,
  MemoryEvidence
} from '../../src/domain/types.ts';
import {
  ValidationError,
  MemoryScopeViolationError,
  MemoryNotFoundError,
  SecurityViolationError
} from '../../src/domain/errors.ts';

function setupEvidenceTestEnv() {
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

  const pipeline = new KnowledgeProposalPipeline();

  const adminAlpha = authorizer.authorizeUser({ credentials: 'token-admin-alpha', requestedScope: scopeAlpha });
  const adminBeta = authorizer.authorizeUser({ credentials: 'token-admin-beta', requestedScope: scopeBeta });

  const taskAlpha = hostAuthority.createTask(taskRepo, {
    id: 'task-evidence-alpha',
    goal: 'Research caching architectures and optimize Redis TTL settings',
    scope: scopeAlpha,
    principalId: 'admin-alpha'
  });

  const taskBeta = hostAuthority.createTask(taskRepo, {
    id: 'task-evidence-beta',
    goal: 'Investigate Postgres query optimizer settings',
    scope: scopeBeta,
    principalId: 'admin-beta'
  });

  const agentCallerAlpha = authorizer.authorizeAgent({ taskId: taskAlpha.id, agentId: 'research-agent' });
  const agentCallerBeta = authorizer.authorizeAgent({ taskId: taskBeta.id, agentId: 'developer-agent' });

  return {
    db,
    taskRepo,
    auditRepo,
    memoryRepo,
    hostAuthority,
    authorizer,
    memoryService,
    pipeline,
    scopeAlpha,
    scopeBeta,
    scopeGlobal,
    adminAlpha,
    adminBeta,
    taskAlpha,
    taskBeta,
    agentCallerAlpha,
    agentCallerBeta
  };
}

function makeAgentOutput(partial: Partial<AgentOutput> & { status: 'COMPLETED' | 'FAILED' | 'CANCELLED'; result: Record<string, unknown> }): AgentOutput {
  return {
    agentId: 'test-agent',
    summary: 'Execution completed',
    stepsExecuted: 1,
    durationMs: 100,
    ...partial
  };
}

// ============================================================================
// 1. Structured research evidence extraction
// ============================================================================
test('1. Structured research evidence extraction', () => {
  const output = makeAgentOutput({
    status: 'COMPLETED',
    result: {
      report: {
        completionStatus: 'SUCCESS',
        researchQuestion: 'How to scale distributed caching with Redis Cluster?',
        keyFindings: [
          'Redis cluster nodes require explicit slot allocation.',
          'Partition rebalancing can occur online without cluster downtime.'
        ],
        evidenceAndSources: [
          {
            id: 'src-1',
            title: 'Redis Cluster Specification',
            url: 'https://redis.io/docs/reference/cluster-spec/',
            domain: 'redis.io',
            relationship: 'SUPPORTS',
            targetFindingIndex: 0,
            relevantEvidence: [
              'Every Redis Cluster node has 16384 hash slots assigned.',
              'Slot migration uses the MIGRATE command with atomic keyspace lock.'
            ]
          },
          {
            id: 'src-2',
            title: 'AWS ElastiCache Redis Best Practices',
            url: 'https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/BestPractices.html',
            domain: 'docs.aws.amazon.com',
            relationship: 'SUPPORTS',
            targetFindingIndex: 1,
            relevantEvidence: [
              'Online cluster rebalancing prevents cache stampedes.'
            ]
          },
          {
            id: 'src-3',
            title: 'Background Redis Architecture Blog',
            url: 'https://example.com/redis-intro',
            domain: 'example.com',
            // No relationship specified - background source!
            relevantEvidence: [
              'Redis was created in 2009.'
            ]
          }
        ]
      }
    }
  });

  const proposals = extractResearchProposals(output, 'Redis clustering');
  // Two dedicated finding proposals + one composite summary proposal = 3 proposals
  assert.equal(proposals.length, 3);

  // Finding 1 proposal: has only src-1 evidence
  const finding1 = proposals[0];
  assert.ok(finding1.key.includes('redis-cluster-nodes-require'));
  assert.ok(finding1.evidence, 'Finding 1 evidence array must be present');
  assert.equal(finding1.evidence.length, 2, 'Should extract 2 candidate evidence items from src-1');
  assert.equal(finding1.evidence[0].sourceType, 'WEB_RESEARCH');
  assert.equal(finding1.evidence[0].sourceUrl, 'https://redis.io/docs/reference/cluster-spec/');
  assert.equal(finding1.evidence[0].sourceDomain, 'redis.io');
  assert.equal(finding1.evidence[0].sourceTitle, 'Redis Cluster Specification');
  assert.equal(finding1.evidence[0].snippet, 'Every Redis Cluster node has 16384 hash slots assigned.');
  assert.equal(finding1.evidence[0].relationship, 'SUPPORTS');
  assert.equal(finding1.evidence[0].snippetHash, computeSnippetHash('Every Redis Cluster node has 16384 hash slots assigned.'));
  assert.equal(finding1.evidence[1].snippet, 'Slot migration uses the MIGRATE command with atomic keyspace lock.');

  // Finding 2 proposal: has only src-2 evidence
  const finding2 = proposals[1];
  assert.ok(finding2.key.includes('partition-rebalancing-can-occur'));
  assert.ok(finding2.evidence, 'Finding 2 evidence array must be present');
  assert.equal(finding2.evidence.length, 1, 'Should extract 1 candidate evidence item from src-2');
  assert.equal(finding2.evidence[0].sourceDomain, 'docs.aws.amazon.com');
  assert.equal(finding2.evidence[0].relationship, 'SUPPORTS');

  // Background source src-3 must NOT appear in any proposal evidence
  const allAttachedEvidence = proposals.flatMap((p) => p.evidence ?? []);
  const src3Attached = allAttachedEvidence.some((e) => e.sourceUrl === 'https://example.com/redis-intro');
  assert.equal(src3Attached, false, 'Background source without explicit relationship must never produce evidence');
});

// ============================================================================
// 2. Developer evidence extraction where applicable
// ============================================================================
test('2. Developer evidence extraction where applicable (TEST, GENERATE, DEBUG)', () => {
  // Test operation
  const testOutput = makeAgentOutput({
    status: 'COMPLETED',
    result: {
      report: {
        operation: 'TEST',
        objective: 'Verify user authentication rate limiting',
        verificationResults: [
          {
            target: 'auth-rate-limit.test.ts',
            description: 'Rate limit blocks 11th request in 1 minute window',
            status: 'PASSED',
            evidence: 'HTTP 429 Too Many Requests received on request #11'
          },
          {
            target: 'auth-ip-whitelist.test.ts',
            description: 'Internal subnet bypasses rate limit',
            status: 'FAILED',
            evidence: 'HTTP 429 received instead of HTTP 200'
          }
        ],
        commands: [
          {
            command: 'npm run test:auth',
            status: 'EXECUTED',
            exitCode: 0,
            stdout: '10 passed, 0 failed'
          }
        ]
      }
    }
  });

  const testProposals = extractDeveloperProposals(testOutput, 'Run tests');
  assert.equal(testProposals.length, 1);
  const testEvidence = testProposals[0].evidence;
  assert.ok(testEvidence, 'Test procedure must have evidence');
  assert.equal(testEvidence.length, 3);

  // Check passed verification
  assert.equal(testEvidence[0].sourceType, 'CODE_VERIFICATION');
  assert.equal(testEvidence[0].sourceTitle, 'auth-rate-limit.test.ts');
  assert.equal(testEvidence[0].snippet, 'HTTP 429 Too Many Requests received on request #11');
  assert.equal(testEvidence[0].relationship, 'SUPPORTS');

  // Check failed verification
  assert.equal(testEvidence[1].sourceType, 'CODE_VERIFICATION');
  assert.equal(testEvidence[1].sourceTitle, 'auth-ip-whitelist.test.ts');
  assert.equal(testEvidence[1].relationship, 'CONTRADICTS');

  // Check executed command
  assert.equal(testEvidence[2].sourceType, 'TOOL_EXECUTION');
  assert.equal(testEvidence[2].sourceTitle, 'npm run test:auth');
  assert.equal(testEvidence[2].relationship, 'SUPPORTS');

  // Generate operation
  const generateOutput = makeAgentOutput({
    status: 'COMPLETED',
    result: {
      report: {
        operation: 'GENERATE',
        objective: 'Generate secure token hashing function',
        generatedCode: 'export function hashToken(token: string): string { ... }',
        verificationResults: [
          {
            target: 'token-hasher',
            description: 'Produces deterministic SHA-256 output',
            passed: true,
            evidence: 'Hash matched standard vector'
          }
        ]
      }
    }
  });

  const genProposals = extractDeveloperProposals(generateOutput, 'Generate code');
  assert.equal(genProposals.length, 1);
  assert.ok(genProposals[0].evidence);
  assert.equal(genProposals[0].evidence[0].sourceType, 'CODE_VERIFICATION');
  assert.equal(genProposals[0].evidence[0].relationship, 'SUPPORTS');
});

// ============================================================================
// 3. Correct source URL and domain preservation
// ============================================================================
test('3. Correct source URL and domain preservation', () => {
  assert.equal(extractDomainFromUrl('https://developer.mozilla.org/en-US/docs/Web/HTTP'), 'developer.mozilla.org');
  assert.equal(extractDomainFromUrl('http://docs.example.com:8080/path?query=1'), 'docs.example.com');
  assert.equal(extractDomainFromUrl('https://sub.domain.co.uk/path'), 'sub.domain.co.uk');
  assert.equal(normalizeDomain('  HTTPS://API.GITHUB.COM/v1  '), 'api.github.com');
  assert.equal(normalizeDomain('localhost'), 'localhost');
  assert.equal(normalizeDomain('   '), undefined);
  assert.equal(normalizeDomain(''), undefined);
  assert.equal(normalizeDomain(null), undefined);
});

// ============================================================================
// 4. Missing source information does not produce fabricated evidence
// ============================================================================
test('4. Missing source information does not produce fabricated evidence', () => {
  // Research output with no sources
  const noSourcesOutput = makeAgentOutput({
    status: 'COMPLETED',
    result: {
      report: {
        completionStatus: 'SUCCESS',
        researchQuestion: 'Is P equal to NP?',
        keyFindings: ['Problem remains open.'],
        evidenceAndSources: [] // Empty sources
      }
    }
  });
  const researchProposals = extractResearchProposals(noSourcesOutput, 'P vs NP');
  assert.equal(researchProposals.length, 0, 'No finding proposals without verified sources');

  // Developer output with no verificationResults or commands
  const noVerifDevOutput = makeAgentOutput({
    status: 'COMPLETED',
    result: {
      report: {
        operation: 'ANALYZE',
        objective: 'Analyze memory usage patterns',
        summary: 'Heap profile shows linear growth with payload size'
      }
    }
  });
  const devProposals = extractDeveloperProposals(noVerifDevOutput, 'Analyze memory');
  assert.equal(devProposals.length, 1);
  assert.equal(devProposals[0].evidence, undefined, 'Must not fabricate evidence when no verifications exist');
});

// ============================================================================
// 5. Evidence is persisted with its pending proposal
// ============================================================================
test('5. Evidence is persisted with its pending proposal', async () => {
  const env = setupEvidenceTestEnv();

  const output = makeAgentOutput({
    status: 'COMPLETED',
    result: {
      report: {
        completionStatus: 'SUCCESS',
        researchQuestion: 'What are safe database connection pool sizes?',
        keyFindings: ['Pool size of 20 to 50 connections prevents CPU saturation on 8-core DB.'],
        evidenceAndSources: [
          {
            title: 'PostgreSQL Connection Pooling Guide',
            url: 'https://wiki.postgresql.org/wiki/Number_Of_Database_Connections',
            domain: 'wiki.postgresql.org',
            relationship: 'SUPPORTS',
            relevantEvidence: ['Max connections = ((core_count * 2) + effective_spindle_count)']
          }
        ]
      }
    }
  });

  const proposals = await env.pipeline.processCompletedTask({
    task: env.taskAlpha,
    agentId: 'research-agent',
    output,
    caller: env.agentCallerAlpha,
    memoryService: env.memoryService
  });

  assert.equal(proposals.length, 1);
  const proposal = proposals[0];
  assert.equal(proposal.status, 'PENDING_APPROVAL');

  // Query evidence through memory service
  const evidenceList = env.memoryService.getEvidenceByMemoryId(env.adminAlpha, proposal.id);
  assert.equal(evidenceList.length, 1);
  const ev = evidenceList[0];

  assert.equal(ev.memoryId, proposal.id);
  assert.equal(ev.sourceType, 'WEB_RESEARCH');
  assert.equal(ev.sourceUrl, 'https://wiki.postgresql.org/wiki/Number_Of_Database_Connections');
  assert.equal(ev.sourceDomain, 'wiki.postgresql.org');
  assert.equal(ev.sourceTitle, 'PostgreSQL Connection Pooling Guide');
  assert.equal(ev.snippet, 'Max connections = ((core_count * 2) + effective_spindle_count)');
  assert.equal(ev.relationship, 'SUPPORTS');
  assert.equal(ev.taskId, env.taskAlpha.id);
  assert.equal(ev.agentId, 'research-agent', 'Evidence agentId must record the executing agent');
  assert.equal(env.agentCallerAlpha.principalId, 'admin-alpha', 'Authorizing principal must remain distinct');
  assert.ok(ev.createdAt);
  assert.ok(ev.id);
});

// ============================================================================
// 6. Evidence insertion failure rolls back proposal creation
// ============================================================================
test('6. Evidence insertion failure rolls back proposal creation', () => {
  const env = setupEvidenceTestEnv();

  // Attempt to create memory with invalid evidence relationship
  assert.throws(
    () => {
      env.memoryService.createMemory(env.agentCallerAlpha, {
        category: 'PROJECT_FACT',
        scopeType: 'WORKSPACE',
        scopeId: 'ws-alpha',
        key: 'invalid.evidence.key',
        content: 'This memory must not be committed to the database.',
        evidence: [
          {
            sourceType: 'WEB_RESEARCH',
            relationship: 'INVALID_RELATIONSHIP' as any,
            sourceUrl: 'https://example.com'
          }
        ]
      });
    },
    (err: unknown) => err instanceof ValidationError && String(err.message).includes('Invalid evidence relationship')
  );

  // Verify memory proposal was rolled back and does not exist in DB
  const memory = env.memoryRepo.getMemoryByKey('invalid.evidence.key', env.scopeAlpha);
  assert.equal(memory, null, 'Memory creation must be rolled back on evidence insertion failure');
});

// ============================================================================
// 7. Evidence remains available after task cleanup
// ============================================================================
test('7. Evidence remains available after task cleanup', async () => {
  const env = setupEvidenceTestEnv();

  const output = makeAgentOutput({
    status: 'COMPLETED',
    result: {
      report: {
        completionStatus: 'SUCCESS',
        researchQuestion: 'How does SQLite WAL mode handle concurrent readers?',
        keyFindings: ['WAL mode allows multiple readers without blocking writers.'],
        evidenceAndSources: [
          {
            title: 'SQLite WAL documentation',
            url: 'https://sqlite.org/wal.html',
            domain: 'sqlite.org',
            relationship: 'SUPPORTS',
            relevantEvidence: ['Readers do not block writers and writers do not block readers.']
          }
        ]
      }
    }
  });

  const proposals = await env.pipeline.processCompletedTask({
    task: env.taskAlpha,
    agentId: 'research-agent',
    output,
    caller: env.agentCallerAlpha,
    memoryService: env.memoryService
  });

  assert.equal(proposals.length, 1);
  const proposalId = proposals[0].id;

  // Confirm evidence is present
  const beforeEvidence = env.memoryService.getEvidenceByMemoryId(env.adminAlpha, proposalId);
  assert.equal(beforeEvidence.length, 1);

  // Now delete the task from the database (simulating retention cleanup / task purge)
  env.db.prepare('DELETE FROM tasks WHERE id = ?').run(env.taskAlpha.id);
  const taskCheck = env.taskRepo.getTaskById(env.taskAlpha.id);
  assert.equal(taskCheck, null, 'Task must be completely purged');

  // Verify evidence is STILL available and linked to the proposal
  const afterEvidence = env.memoryService.getEvidenceByMemoryId(env.adminAlpha, proposalId);
  assert.equal(afterEvidence.length, 1, 'Evidence must remain after task cleanup');
  assert.equal(afterEvidence[0].taskId, env.taskAlpha.id, 'Original task ID provenance must be preserved');
  assert.equal(afterEvidence[0].agentId, 'research-agent', 'Original agent ID provenance must be preserved');
});

// ============================================================================
// 8. Duplicate evidence handling
// ============================================================================
test('8. Duplicate evidence handling', () => {
  const env = setupEvidenceTestEnv();

  const memory = env.memoryRepo.createMemory({
    category: 'PROJECT_FACT',
    scopeType: 'WORKSPACE',
    scopeId: 'ws-alpha',
    key: 'dedup.test.key',
    content: 'Deduplication test memory',
    status: 'ACTIVE'
  });

  const snippet = 'Deterministic evidence excerpt';
  const snippetHash = computeSnippetHash(snippet);
  const expectedId = computeEvidenceId(memory.id, snippetHash, 'SUPPORTS');

  // First insertion
  const ev1 = env.memoryRepo.addEvidence({
    memoryId: memory.id,
    sourceType: 'WEB_RESEARCH',
    sourceUrl: 'https://example.com/spec',
    snippet,
    relationship: 'SUPPORTS',
    taskId: 'task-1',
    agentId: 'agent-1'
  });

  assert.equal(ev1.id, expectedId);

  // Second insertion of identical evidence
  const ev2 = env.memoryRepo.addEvidence({
    memoryId: memory.id,
    sourceType: 'WEB_RESEARCH',
    sourceUrl: 'https://example.com/spec',
    snippet,
    relationship: 'SUPPORTS',
    taskId: 'task-1',
    agentId: 'agent-1'
  });

  assert.equal(ev2.id, expectedId);

  // Verify only 1 evidence record exists for the memory
  const allEvidence = env.memoryRepo.getEvidenceByMemoryId(memory.id);
  assert.equal(allEvidence.length, 1, 'Duplicate evidence must be deduplicated cleanly');
});

// ============================================================================
// 9. Untrusted agent metadata cannot forge task or agent provenance
// ============================================================================
test('9. Untrusted agent metadata cannot forge task or agent provenance', () => {
  const env = setupEvidenceTestEnv();

  // Malicious agent attempts to pass forged taskId and agentId in metadata
  const memory = env.memoryService.createMemory(env.agentCallerAlpha, {
    category: 'PROJECT_FACT',
    scopeType: 'WORKSPACE',
    scopeId: 'ws-alpha',
    key: 'forgery.prevention.key',
    content: 'Untrusted metadata test content',
    metadata: {
      taskId: 'forged-task-id-666',
      agentId: 'forged-agent-id-999'
    },
    evidence: [
      {
        sourceType: 'WEB_RESEARCH',
        sourceUrl: 'https://trusted.org/research',
        snippet: 'Verified claim',
        relationship: 'SUPPORTS'
      }
    ]
  });

  const evidenceList = env.memoryService.getEvidenceByMemoryId(env.adminAlpha, memory.id);
  assert.equal(evidenceList.length, 1);
  const ev = evidenceList[0];

  // Must reflect trusted caller context, NOT the forged metadata
  assert.equal(ev.taskId, env.taskAlpha.id, 'Task ID must originate from trusted caller context');
  assert.notEqual(ev.taskId, 'forged-task-id-666');
  assert.equal(ev.agentId, 'research-agent', 'Agent ID must originate from trusted caller context');
  assert.notEqual(ev.agentId, 'forged-agent-id-999');
  assert.notEqual(ev.agentId, 'admin-alpha', 'Authorizing principal must not be used as agentId');
});

// ============================================================================
// 10. Workspace authorization prevents cross-scope evidence access
// ============================================================================
test('10. Workspace authorization prevents cross-scope evidence access', () => {
  const env = setupEvidenceTestEnv();

  // Create memory in workspace Alpha with evidence
  const memoryAlpha = env.memoryService.createMemory(env.adminAlpha, {
    category: 'PROJECT_FACT',
    scopeType: 'WORKSPACE',
    scopeId: 'ws-alpha',
    key: 'alpha.confidential.key',
    content: 'Confidential knowledge in workspace Alpha',
    evidence: [
      {
        sourceType: 'WEB_RESEARCH',
        sourceUrl: 'https://internal.alpha/docs',
        snippet: 'Alpha secret',
        relationship: 'SUPPORTS'
      }
    ]
  });

  // Admin Alpha can read evidence
  const alphaEvidence = env.memoryService.getEvidenceByMemoryId(env.adminAlpha, memoryAlpha.id);
  assert.equal(alphaEvidence.length, 1);

  // Admin Beta (scoped to workspace Beta) attempts to read Alpha's evidence -> must be denied
  assert.throws(
    () => {
      env.memoryService.getEvidenceByMemoryId(env.adminBeta, memoryAlpha.id);
    },
    (err: unknown) => err instanceof MemoryScopeViolationError
  );

  // MemoryRepository scoped query must also return empty array
  const repoEvidenceForBeta = env.memoryRepo.getEvidenceByMemoryId(memoryAlpha.id, env.scopeBeta);
  assert.equal(repoEvidenceForBeta.length, 0, 'Scoped repository lookup must return empty array for mismatched scope');
});

// ============================================================================
// 11. Existing evidence-free proposal behavior remains compatible
// ============================================================================
test('11. Existing evidence-free proposal behavior remains compatible', () => {
  const env = setupEvidenceTestEnv();

  // Create standard memory without evidence
  const memory = env.memoryService.createMemory(env.adminAlpha, {
    category: 'PROJECT_FACT',
    scopeType: 'WORKSPACE',
    scopeId: 'ws-alpha',
    key: 'evidence.free.key',
    content: 'Standard memory with zero evidence'
  });

  const evidence = env.memoryService.getEvidenceByMemoryId(env.adminAlpha, memory.id);
  assert.deepEqual(evidence, [], 'Evidence-free memory returns empty array');
});

// ============================================================================
// 12. Existing approval, rejection, and supersession tests remain passing
// ============================================================================
test('12. Existing approval, rejection, and supersession lifecycle preserves evidence', () => {
  const env = setupEvidenceTestEnv();

  // Create proposal with evidence
  const proposal = env.memoryService.createMemory(env.agentCallerAlpha, {
    category: 'PROJECT_FACT',
    scopeType: 'WORKSPACE',
    scopeId: 'ws-alpha',
    key: 'lifecycle.proposal.key',
    content: 'Initial proposal content with evidence',
    evidence: [
      {
        sourceType: 'WEB_RESEARCH',
        sourceUrl: 'https://rfc-editor.org/rfc/rfc9110',
        snippet: 'HTTP Semantics standard',
        relationship: 'SUPPORTS'
      }
    ]
  });

  assert.equal(proposal.status, 'PENDING_APPROVAL');

  // Verify evidence attached to pending proposal
  const pEvidence = env.memoryService.getEvidenceByMemoryId(env.adminAlpha, proposal.id);
  assert.equal(pEvidence.length, 1);

  // Approve proposal (APPROVE_NEW)
  const approved = env.memoryService.decideProposal(env.adminAlpha, {
    memoryId: proposal.id,
    decision: 'APPROVE_NEW'
  });

  assert.equal(approved.status, 'ACTIVE');

  // Evidence remains attached to active memory
  const aEvidence = env.memoryService.getEvidenceByMemoryId(env.adminAlpha, approved.id);
  assert.equal(aEvidence.length, 1);
  assert.equal(aEvidence[0].snippet, 'HTTP Semantics standard');

  // Create update proposal with new evidence
  const updateProposal = env.memoryService.createMemory(env.agentCallerAlpha, {
    category: 'PROJECT_FACT',
    scopeType: 'WORKSPACE',
    scopeId: 'ws-alpha',
    key: 'lifecycle.proposal.key',
    content: 'Updated proposal content with second evidence',
    metadata: {
      proposalType: 'UPDATE',
      targetMemoryId: approved.id,
      targetVersion: approved.version
    },
    evidence: [
      {
        sourceType: 'WEB_RESEARCH',
        sourceUrl: 'https://rfc-editor.org/rfc/rfc9111',
        snippet: 'HTTP Caching standard',
        relationship: 'SUPPORTS'
      }
    ]
  });

  // Approve update proposal with supersession (APPROVE_AND_SUPERSEDE)
  const supersededApproved = env.memoryService.decideProposal(env.adminAlpha, {
    memoryId: updateProposal.id,
    decision: 'APPROVE_AND_SUPERSEDE'
  });

  assert.equal(supersededApproved.status, 'ACTIVE');
  assert.equal(supersededApproved.version, 2);

  // Verify original superseded memory retains its original evidence
  const origEvidence = env.memoryService.getEvidenceByMemoryId(env.adminAlpha, approved.id);
  assert.equal(origEvidence.length, 1);
  assert.equal(origEvidence[0].snippet, 'HTTP Semantics standard');

  // Verify replacement memory has its new evidence
  const newEvidence = env.memoryService.getEvidenceByMemoryId(env.adminAlpha, supersededApproved.id);
  assert.equal(newEvidence.length, 1);
  assert.equal(newEvidence[0].snippet, 'HTTP Caching standard');
});

// ============================================================================
// 13. Trusted agent identity - DeveloperAgent and ResearchAgent evidence records identify actual executing agent
// ============================================================================
test('13. Trusted agent identity - DeveloperAgent and ResearchAgent evidence records identify actual executing agent', async () => {
  const env = setupEvidenceTestEnv();

  // 1. Process DeveloperAgent task
  const devOutput = makeAgentOutput({
    agentId: 'developer-agent',
    status: 'COMPLETED',
    result: {
      report: {
        operation: 'TEST',
        objective: 'Validate database migration rollbacks',
        verificationResults: [
          {
            target: 'migration-009',
            description: 'Rollback cleans up table schema',
            status: 'PASSED',
            evidence: 'Table dropped successfully'
          }
        ]
      }
    }
  });

  const devProposals = await env.pipeline.processCompletedTask({
    task: env.taskBeta,
    agentId: 'developer-agent',
    output: devOutput,
    caller: env.agentCallerBeta,
    memoryService: env.memoryService
  });

  assert.equal(devProposals.length, 1);
  const devEvidence = env.memoryService.getEvidenceByMemoryId(env.adminBeta, devProposals[0].id);
  assert.equal(devEvidence.length, 1);
  assert.equal(devEvidence[0].agentId, 'developer-agent', 'Evidence agentId must record developer-agent');

  // 2. Process ResearchAgent task
  const researchOutput = makeAgentOutput({
    agentId: 'research-agent',
    status: 'COMPLETED',
    result: {
      report: {
        completionStatus: 'SUCCESS',
        researchQuestion: 'Optimal TLS cipher suites for HTTP/2',
        keyFindings: ['ECDHE-ECDSA-AES128-GCM-SHA256 provides optimal throughput and security.'],
        evidenceAndSources: [
          {
            title: 'Mozilla SSL Configuration Generator',
            url: 'https://wiki.mozilla.org/Security/Server_Side_TLS',
            domain: 'wiki.mozilla.org',
            relationship: 'SUPPORTS',
            relevantEvidence: ['Intermediate compatibility configuration recommends ECDHE suites.']
          }
        ]
      }
    }
  });

  const resProposals = await env.pipeline.processCompletedTask({
    task: env.taskAlpha,
    agentId: 'research-agent',
    output: researchOutput,
    caller: env.agentCallerAlpha,
    memoryService: env.memoryService
  });

  assert.equal(resProposals.length, 1);
  const resEvidence = env.memoryService.getEvidenceByMemoryId(env.adminAlpha, resProposals[0].id);
  assert.equal(resEvidence.length, 1);
  assert.equal(resEvidence[0].agentId, 'research-agent', 'Evidence agentId must record research-agent');
});

// ============================================================================
// 14. Trusted agent identity - authorizing principal remains distinct from executing agent
// ============================================================================
test('14. Trusted agent identity - authorizing principal remains distinct from executing agent', () => {
  const env = setupEvidenceTestEnv();

  // Authorize agent caller with explicit task and executing agentId
  const caller = env.authorizer.authorizeAgent({
    taskId: env.taskAlpha.id,
    agentId: 'specialist-agent'
  });

  // Verify caller context properties
  assert.equal(caller.actor, 'AGENT');
  assert.equal(caller.agentId, 'specialist-agent');
  assert.equal(caller.principalId, 'admin-alpha', 'Authorizing principal must be the task creator');
  assert.notEqual(caller.agentId, caller.principalId, 'Agent ID and Principal ID must be distinct');

  // Create memory with evidence using this caller
  const memory = env.memoryService.createMemory(caller, {
    category: 'PROJECT_FACT',
    scopeType: 'WORKSPACE',
    scopeId: 'ws-alpha',
    key: 'principal.distinction.key',
    content: 'Knowledge verifying separation of principal and agent identity',
    evidence: [
      {
        sourceType: 'WEB_RESEARCH',
        sourceUrl: 'https://example.com/source',
        snippet: 'Relevant claim snippet',
        relationship: 'SUPPORTS'
      }
    ]
  });

  const evidenceList = env.memoryService.getEvidenceByMemoryId(env.adminAlpha, memory.id);
  assert.equal(evidenceList.length, 1);
  assert.equal(evidenceList[0].agentId, 'specialist-agent', 'Recorded agentId must be the executing agent');
  assert.notEqual(evidenceList[0].agentId, 'admin-alpha', 'Recorded agentId must NEVER be the user principal');
});

// ============================================================================
// 15. Trusted agent identity - forged or modified agent identity in caller context is rejected by HMAC
// ============================================================================
test('15. Trusted agent identity - forged or modified agent identity in caller context is rejected by HMAC', () => {
  const env = setupEvidenceTestEnv();

  // Legitimate agent caller
  const legitimate = env.authorizer.authorizeAgent({
    taskId: env.taskAlpha.id,
    agentId: 'research-agent'
  });

  // 1. Attacker attempts to forge agentId by tampering with property on context
  const tampered = {
    ...legitimate,
    agentId: 'root-admin-agent'
  };

  assert.throws(
    () => {
      env.authorizer.verify(tampered);
    },
    (err: unknown) => err instanceof SecurityViolationError && (err as any).violationType === 'FORGED_CALLER_CONTEXT'
  );

  // 2. Memory service rejects tampered context on createMemory
  assert.throws(
    () => {
      env.memoryService.createMemory(tampered as any, {
        category: 'PROJECT_FACT',
        scopeType: 'WORKSPACE',
        scopeId: 'ws-alpha',
        key: 'tampered.context.key',
        content: 'Tampered context must be rejected'
      });
    },
    (err: unknown) => err instanceof SecurityViolationError && (err as any).violationType === 'FORGED_CALLER_CONTEXT'
  );
});

// ============================================================================
// 16. Trusted agent identity - missing agent identity fails safely for agent execution with evidence
// ============================================================================
test('16. Trusted agent identity - missing agent identity fails safely for agent execution with evidence', () => {
  const env = setupEvidenceTestEnv();

  // Authorize agent without specifying agentId
  const callerWithoutAgentId = env.authorizer.authorizeAgent({
    taskId: env.taskAlpha.id
  });
  assert.equal(callerWithoutAgentId.agentId, undefined);

  // Creating memory WITH evidence must fail closed with MISSING_AGENT_IDENTITY
  assert.throws(
    () => {
      env.memoryService.createMemory(callerWithoutAgentId, {
        category: 'PROJECT_FACT',
        scopeType: 'WORKSPACE',
        scopeId: 'ws-alpha',
        key: 'missing.agent.id.evidence.key',
        content: 'Evidence creation without agent identity must fail',
        evidence: [
          {
            sourceType: 'WEB_RESEARCH',
            sourceUrl: 'https://example.com/spec',
            snippet: 'Snippet without agent identity',
            relationship: 'SUPPORTS'
          }
        ]
      });
    },
    (err: unknown) => err instanceof SecurityViolationError && (err as any).violationType === 'MISSING_AGENT_IDENTITY'
  );

  // However, evidence-free proposal creation without agent identity remains compatible
  const proposalWithoutEvidence = env.memoryService.createMemory(callerWithoutAgentId, {
    category: 'PROJECT_FACT',
    scopeType: 'WORKSPACE',
    scopeId: 'ws-alpha',
    key: 'evidence.free.compatible.key',
    content: 'Evidence-free memory creation remains compatible'
  });
  assert.equal(proposalWithoutEvidence.status, 'PENDING_APPROVAL');
});

// ============================================================================
// 17. Trusted agent identity - non-agent operations (USER, SYSTEM) remain compatible and do not label user as executing agent
// ============================================================================
test('17. Trusted agent identity - non-agent operations (USER, SYSTEM) remain compatible and do not label user as executing agent', () => {
  const env = setupEvidenceTestEnv();

  // 1. User caller creates memory with evidence
  const userMemory = env.memoryService.createMemory(env.adminAlpha, {
    category: 'PROJECT_FACT',
    scopeType: 'WORKSPACE',
    scopeId: 'ws-alpha',
    key: 'user.created.evidence.key',
    content: 'User manual assertion with citation',
    evidence: [
      {
        sourceType: 'USER_ASSERTION',
        sourceTitle: 'Manual inspection',
        snippet: 'Verified directly in console',
        relationship: 'SUPPORTS'
      }
    ]
  });

  const userEvidence = env.memoryService.getEvidenceByMemoryId(env.adminAlpha, userMemory.id);
  assert.equal(userEvidence.length, 1);
  assert.equal(userEvidence[0].agentId, 'user', 'User operation must record agentId as "user"');
  assert.notEqual(userEvidence[0].agentId, 'admin-alpha', 'User principal must NEVER be labeled as executing agent');

  // 2. System caller creates memory with evidence
  const systemCaller = env.hostAuthority.authorizeSystem({
    scope: env.scopeAlpha,
    taskId: env.taskAlpha.id
  });

  const sysMemory = env.memoryService.createMemory(systemCaller, {
    category: 'PROJECT_FACT',
    scopeType: 'WORKSPACE',
    scopeId: 'ws-alpha',
    key: 'system.created.evidence.key',
    content: 'System diagnostic result with evidence',
    evidence: [
      {
        sourceType: 'TOOL_EXECUTION',
        sourceTitle: 'System health check',
        snippet: 'All services healthy',
        relationship: 'SUPPORTS'
      }
    ]
  });

  const sysEvidence = env.memoryService.getEvidenceByMemoryId(env.adminAlpha, sysMemory.id);
  assert.equal(sysEvidence.length, 1);
  assert.equal(sysEvidence[0].agentId, 'system', 'System operation must record agentId as "system"');
});

// ============================================================================
// 18. Research evidence attribution - source for finding A is not automatically associated with finding B
// ============================================================================
test('18. Research evidence attribution - source for finding A is not automatically associated with finding B', () => {
  const output = makeAgentOutput({
    status: 'COMPLETED',
    result: {
      report: {
        completionStatus: 'SUCCESS',
        researchQuestion: 'Comparing Cassandra vs CockroachDB for multi-region replication',
        keyFindings: [
          'Cassandra uses peer-to-peer gossip and tunable eventual consistency.',
          'CockroachDB uses Multi-Raft consensus for strict serializability.'
        ],
        evidenceAndSources: [
          {
            id: 'src-cassandra',
            title: 'Apache Cassandra Architecture',
            url: 'https://cassandra.apache.org/doc/latest/architecture/',
            domain: 'cassandra.apache.org',
            relationship: 'SUPPORTS',
            targetFindingIndex: 0,
            relevantEvidence: ['Cassandra distributes data across cluster nodes using consistent hashing with token rings.']
          },
          {
            id: 'src-cockroach',
            title: 'CockroachDB Consensus Architecture',
            url: 'https://www.cockroachlabs.com/docs/stable/architecture/replication-layer.html',
            domain: 'cockroachlabs.com',
            relationship: 'SUPPORTS',
            targetFindingIndex: 1,
            relevantEvidence: ['Each range in CockroachDB forms a Raft consensus group replicating state across replicas.']
          }
        ]
      }
    }
  });

  const proposals = extractResearchProposals(output, 'Cassandra vs CockroachDB');
  // Two dedicated finding proposals + one composite summary proposal = 3
  assert.equal(proposals.length, 3);

  // Proposal for Finding 0 (Cassandra)
  const cassandraProposal = proposals[0];
  assert.ok(cassandraProposal.evidence, 'Cassandra proposal must have evidence');
  assert.equal(cassandraProposal.evidence.length, 1);
  assert.equal(cassandraProposal.evidence[0].sourceDomain, 'cassandra.apache.org');
  assert.equal(cassandraProposal.evidence[0].snippet, 'Cassandra distributes data across cluster nodes using consistent hashing with token rings.');

  // Proposal for Finding 1 (CockroachDB)
  const cockroachProposal = proposals[1];
  assert.ok(cockroachProposal.evidence, 'CockroachDB proposal must have evidence');
  assert.equal(cockroachProposal.evidence.length, 1);
  assert.equal(cockroachProposal.evidence[0].sourceDomain, 'cockroachlabs.com');
  assert.equal(cockroachProposal.evidence[0].snippet, 'Each range in CockroachDB forms a Raft consensus group replicating state across replicas.');

  // Critical Invariant: Source for Cassandra MUST NOT be attached to CockroachDB proposal
  const cockroachHasCassandraSource = cockroachProposal.evidence.some((e) => e.sourceDomain === 'cassandra.apache.org');
  assert.equal(cockroachHasCassandraSource, false, 'Source A must never be associated with Finding B');

  // Critical Invariant: Source for CockroachDB MUST NOT be attached to Cassandra proposal
  const cassandraHasCockroachSource = cassandraProposal.evidence.some((e) => e.sourceDomain === 'cockroachlabs.com');
  assert.equal(cassandraHasCockroachSource, false, 'Source B must never be associated with Finding A');
});

// ============================================================================
// 19. Research evidence attribution - source without explicit support information is not classified as SUPPORTS
// ============================================================================
test('19. Research evidence attribution - source without explicit support information is not classified as SUPPORTS', () => {
  const output = makeAgentOutput({
    status: 'COMPLETED',
    result: {
      report: {
        completionStatus: 'SUCCESS',
        researchQuestion: 'WebAssembly performance in serverless runtimes',
        keyFindings: ['Wasm module cold start latency is under 5ms.'],
        evidenceAndSources: [
          {
            id: 'src-background',
            title: 'Wasm Community Group History',
            url: 'https://webassembly.org/community/',
            domain: 'webassembly.org',
            // No relationship specified! Merely cited as general background
            relevantEvidence: ['WebAssembly was first announced in 2015.']
          }
        ]
      }
    }
  });

  const proposals = extractResearchProposals(output, 'Wasm serverless');
  assert.equal(proposals.length, 1);
  const proposal = proposals[0];

  // The source text should be retained in the Markdown proposal content for transparency
  assert.ok(proposal.content.includes('webassembly.org'));

  // But it must NEVER produce a CandidateEvidence with relationship SUPPORTS
  assert.equal(proposal.evidence, undefined, 'Source without explicit relationship must never be defaulted to SUPPORTS');
});

// ============================================================================
// 20. Research evidence attribution - explicitly established support, contradiction, and limitation are preserved
// ============================================================================
test('20. Research evidence attribution - explicitly established support, contradiction, and limitation are preserved', () => {
  const output = makeAgentOutput({
    status: 'COMPLETED',
    result: {
      report: {
        completionStatus: 'SUCCESS',
        researchQuestion: 'Zero-downtime database schema migration strategies',
        keyFindings: ['Expand-contract pattern enables zero downtime without exclusive table locks.'],
        evidenceAndSources: [
          {
            id: 'src-supports',
            title: 'Expand and Contract Pattern Guide',
            url: 'https://martinfowler.com/bliki/ParallelChange.html',
            domain: 'martinfowler.com',
            relationship: 'SUPPORTS',
            targetFindingIndex: 0,
            relevantEvidence: ['Parallel change allows gradual transition between schema versions.']
          },
          {
            id: 'src-contradicts',
            title: 'Pitfalls of Long-Running Migrations',
            url: 'https://example.com/migration-failures',
            domain: 'example.com',
            relationship: 'CONTRADICTS',
            targetFindingIndex: 0,
            relevantEvidence: ['Expand-contract doubles write amplification during transition window.']
          },
          {
            id: 'src-limitation',
            title: 'Storage Engine Locking Limitations',
            url: 'https://example.com/storage-limitations',
            domain: 'example.com',
            relationship: 'LIMITATION',
            targetFindingIndex: 0,
            relevantEvidence: ['Storage engines without online DDL support still require metadata locks.']
          }
        ]
      }
    }
  });

  const proposals = extractResearchProposals(output, 'Zero downtime migration');
  assert.equal(proposals.length, 1);
  const proposal = proposals[0];
  assert.ok(proposal.evidence);
  assert.equal(proposal.evidence.length, 3);

  const relationships = proposal.evidence.map((e) => e.relationship);
  assert.ok(relationships.includes('SUPPORTS'), 'Explicit SUPPORTS must be preserved');
  assert.ok(relationships.includes('CONTRADICTS'), 'Explicit CONTRADICTS must be preserved');
  assert.ok(relationships.includes('LIMITATION'), 'Explicit LIMITATION must be preserved');
});

// ============================================================================
// 21. Research evidence attribution - missing or malformed attribution data fails conservatively
// ============================================================================
test('21. Research evidence attribution - missing or malformed attribution data fails conservatively', () => {
  const output = makeAgentOutput({
    status: 'COMPLETED',
    result: {
      report: {
        completionStatus: 'SUCCESS',
        researchQuestion: 'QUIC protocol packet loss recovery',
        keyFindings: [
          'QUIC uses packet number spaces to eliminate retransmission ambiguity.'
        ],
        evidenceAndSources: [
          {
            id: 'src-malformed-index',
            title: 'RFC 9000 Specification',
            url: 'https://rfc-editor.org/rfc/rfc9000',
            domain: 'rfc-editor.org',
            relationship: 'SUPPORTS',
            targetFindingIndex: 999, // Out of bounds!
            relevantEvidence: ['QUIC packets carry new packet numbers on retransmission.']
          },
          {
            id: 'src-negative-index',
            title: 'Invalid Target',
            url: 'https://example.com/invalid',
            domain: 'example.com',
            relationship: 'SUPPORTS',
            targetFindingIndex: -1, // Negative index!
            relevantEvidence: ['Invalid snippet']
          }
        ]
      }
    }
  });

  const proposals = extractResearchProposals(output, 'QUIC packet loss');
  assert.equal(proposals.length, 1);
  const proposal = proposals[0];

  // Out-of-bounds indices must fail conservatively (no evidence attached)
  assert.equal(proposal.evidence, undefined, 'Malformed out-of-bounds finding targets must fail conservatively');
});

// ============================================================================
// 22. Research evidence attribution - research limitations proposal does not receive unrelated supporting evidence
// ============================================================================
test('22. Research evidence attribution - research limitations proposal does not receive unrelated supporting evidence', () => {
  const output = makeAgentOutput({
    status: 'COMPLETED',
    result: {
      report: {
        completionStatus: 'SUCCESS',
        researchQuestion: 'Quantum key distribution over fiber optics',
        keyFindings: ['BB84 protocol achieves information-theoretic security.'],
        limitationsAndUncertainty: ['Maximum transmission distance in commercial fiber is bounded by attenuation to ~100km.'],
        openQuestions: ['How can quantum repeaters scale without decoherence?'],
        evidenceAndSources: [
          {
            id: 'src-bb84',
            title: 'Quantum Cryptography: Public Key Distribution and Coin Tossing',
            url: 'https://example.com/bb84',
            domain: 'example.com',
            relationship: 'SUPPORTS',
            targetFindingIndex: 0,
            relevantEvidence: ['Eavesdropping induces detectable error rate on polarized photons.']
          }
        ]
      }
    }
  });

  const proposals = extractResearchProposals(output, 'Quantum key distribution');
  assert.equal(proposals.length, 2);

  // Finding proposal receives supporting evidence
  const findingProposal = proposals.find((p) => p.key.startsWith('research.finding.'));
  assert.ok(findingProposal);
  assert.ok(findingProposal.evidence);
  assert.equal(findingProposal.evidence[0].relationship, 'SUPPORTS');

  // Limitations proposal MUST NOT receive supporting evidence
  const limitationProposal = proposals.find((p) => p.key.startsWith('research.limitations.'));
  assert.ok(limitationProposal);
  assert.equal(limitationProposal.evidence, undefined, 'Limitations proposal must never receive SUPPORTS evidence');
});
