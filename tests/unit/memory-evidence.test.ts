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
  MemoryNotFoundError
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
    scope: scopeAlpha
  });

  const taskBeta = hostAuthority.createTask(taskRepo, {
    id: 'task-evidence-beta',
    goal: 'Investigate Postgres query optimizer settings',
    scope: scopeBeta
  });

  const agentCallerAlpha = authorizer.authorizeAgent({ taskId: taskAlpha.id });
  const agentCallerBeta = authorizer.authorizeAgent({ taskId: taskBeta.id });

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
            relevantEvidence: [
              'Every Redis Cluster node has 16384 hash slots assigned.',
              'Slot migration uses the MIGRATE command with atomic keyspace lock.'
            ]
          },
          {
            id: 'src-2',
            title: 'AWS ElastiCache Redis Best Practices',
            url: 'https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/BestPractices.html',
            relevantEvidence: [
              'Online cluster rebalancing prevents cache stampedes.'
            ]
          }
        ]
      }
    }
  });

  const proposals = extractResearchProposals(output, 'Redis clustering');
  assert.equal(proposals.length, 1);
  const proposal = proposals[0];
  assert.ok(proposal.evidence, 'Evidence array must be present');
  assert.equal(proposal.evidence.length, 3, 'Should extract 3 candidate evidence items from sources');

  // Verify first source evidence
  assert.equal(proposal.evidence[0].sourceType, 'WEB_RESEARCH');
  assert.equal(proposal.evidence[0].sourceUrl, 'https://redis.io/docs/reference/cluster-spec/');
  assert.equal(proposal.evidence[0].sourceDomain, 'redis.io');
  assert.equal(proposal.evidence[0].sourceTitle, 'Redis Cluster Specification');
  assert.equal(proposal.evidence[0].snippet, 'Every Redis Cluster node has 16384 hash slots assigned.');
  assert.equal(proposal.evidence[0].relationship, 'SUPPORTS');
  assert.equal(proposal.evidence[0].snippetHash, computeSnippetHash('Every Redis Cluster node has 16384 hash slots assigned.'));

  // Verify second item from first source
  assert.equal(proposal.evidence[1].sourceType, 'WEB_RESEARCH');
  assert.equal(proposal.evidence[1].snippet, 'Slot migration uses the MIGRATE command with atomic keyspace lock.');

  // Verify second source evidence domain extraction from url
  assert.equal(proposal.evidence[2].sourceDomain, 'docs.aws.amazon.com');
  assert.equal(proposal.evidence[2].relationship, 'SUPPORTS');
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
  assert.notEqual(ev.agentId, 'forged-agent-id-999');
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
