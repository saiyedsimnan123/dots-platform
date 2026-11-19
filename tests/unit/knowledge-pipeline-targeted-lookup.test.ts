/**
 * Next-Generation Dots AI Platform - Knowledge Pipeline Targeted Lookup & History Unpoisoning Tests
 * Phase 4D.3D.2: Targeted Memory Lookup & History Unpoisoning
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseManager } from '../../src/storage/db.ts';
import { TaskRepository } from '../../src/storage/task-repository.ts';
import { AuditRepository } from '../../src/storage/audit-repository.ts';
import { MemoryRepository } from '../../src/storage/memory-repository.ts';
import { HostMemoryAuthority } from '../../src/security/host-authority.ts';
import { MemoryService } from '../../src/memory/memory-service.ts';
import { ToolRegistry } from '../../src/tools/registry.ts';
import { PolicyEngine } from '../../src/security/policy-engine.ts';
import { ApprovalBroker } from '../../src/security/approval-broker.ts';
import { VerificationEngine } from '../../src/verification/verifier.ts';
import { TokenBudgetTracker } from '../../src/model/budget-tracker.ts';
import { MockModelProvider } from '../../src/model/mock-provider.ts';
import { TaskCoordinator } from '../../src/orchestrator/coordinator.ts';
import {
  KnowledgeProposalPipeline,
  slugify
} from '../../src/memory/knowledge-pipeline.ts';
import {
  AgentRegistry,
  type AgentOutput
} from '../../src/agents/index.ts';
import type { ScopeIdentifier } from '../../src/domain/types.ts';

function setupTargetedLookupEnv() {
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
          permittedScopes: [scopeBeta] // No global access
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

  const toolRegistry = new ToolRegistry();
  const policyEngine = new PolicyEngine({ workspaceRoot: '/fake/workspace', autoApproveTier2: true });
  const approvalBroker = new ApprovalBroker(taskRepo, auditRepo);
  const verifier = new VerificationEngine(taskRepo);
  const budgetTracker = new TokenBudgetTracker({ maxTokensPerTask: 100_000 });
  const agentRegistry = new AgentRegistry();
  const pipeline = new KnowledgeProposalPipeline();

  const coordinator = new TaskCoordinator({
    taskRepo,
    auditRepo,
    modelProvider: new MockModelProvider(),
    toolRegistry,
    policyEngine,
    approvalBroker,
    verifier,
    budgetTracker,
    workspaceRoot: '/fake/workspace',
    memoryService,
    hostAuthority,
    agentRegistry,
    knowledgePipeline: pipeline
  });

  const adminAlpha = authorizer.authorizeUser({ credentials: 'token-admin-alpha', requestedScope: scopeAlpha });
  const adminBeta = authorizer.authorizeUser({ credentials: 'token-admin-beta', requestedScope: scopeBeta });

  const taskAlpha = hostAuthority.createTask(taskRepo, {
    id: 'task-pipeline-alpha',
    goal: 'Analyze architecture for distributed cache',
    scope: scopeAlpha
  });

  const taskBeta = hostAuthority.createTask(taskRepo, {
    id: 'task-pipeline-beta',
    goal: 'Analyze indexing strategies in tenant beta',
    scope: scopeBeta,
    permittedScopes: [scopeBeta]
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

function makeResearchOutput(question: string, findingText: string, evidenceUrl = 'https://example.com/doc'): AgentOutput {
  return {
    agentId: 'research-agent',
    status: 'COMPLETED',
    result: {
      report: {
        researchQuestion: question,
        executiveSummary: 'Summary of performance findings.',
        keyFindings: [findingText],
        evidenceAndSources: [
          { domain: 'example.com', url: evidenceUrl, title: 'Performance Guide' }
        ],
        completionStatus: 'SUCCESS'
      }
    },
    summary: 'Research completed',
    stepsExecuted: 2,
    durationMs: 120
  };
}

// ============================================================================
// 1. Unpoisoning: Key with only an ARCHIVED record can be proposed again
// ============================================================================
test('Phase 4D.3D.2 - 1: A key with only an ARCHIVED record can be proposed again', async () => {
  const env = setupTargetedLookupEnv();

  const question = 'TTL tuning reduces memory pressure';
  const expectedKey = `research.finding.${slugify(question, 45)}`;

  // Seed an ARCHIVED memory
  const archived = env.memoryRepo.createMemory({
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    key: expectedKey,
    content: 'Old archived finding about TTL tuning',
    status: 'ARCHIVED'
  });
  assert.equal(archived.status, 'ARCHIVED');

  const output = makeResearchOutput(question, 'TTL tuning reduces memory pressure by half.');

  const proposals = await env.pipeline.processCompletedTask({
    task: env.taskAlpha,
    agentId: 'research-agent',
    output,
    caller: env.agentCallerAlpha,
    memoryService: env.memoryService
  });

  assert.equal(proposals.length, 1, 'Archived key must NOT poison or block new proposals');
  assert.equal(proposals[0].status, 'PENDING_APPROVAL');
  assert.equal(proposals[0].key, expectedKey);
  assert.equal(proposals[0].version, 1, 'New proposal is an ordinary initial proposal (version 1)');
  assert.equal(proposals[0].supersedesId, null, 'No automatic supersession linking');
  assert.equal(proposals[0].supersededBy, null);
  assert.notEqual(proposals[0].id, archived.id, 'New proposal must receive its own fresh ID');
});

// ============================================================================
// 2. Unpoisoning: Key with only a SUPERSEDED record can be proposed again
// ============================================================================
test('Phase 4D.3D.2 - 2: A key with only a SUPERSEDED record can be proposed again', async () => {
  const env = setupTargetedLookupEnv();

  const question = 'NVMe throughput peak limits';
  const expectedKey = `research.finding.${slugify(question, 45)}`;

  // Create an initial active memory v1, then supersede it with v2, then archive/supersede v2 so only historical records remain
  const memV1 = env.memoryRepo.createMemory({
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    key: expectedKey,
    content: 'Initial throughput test v1',
    status: 'ACTIVE'
  });

  const memV2 = env.memoryRepo.createMemory({
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    key: expectedKey,
    content: 'Revised throughput test v2',
    status: 'PENDING_APPROVAL'
  });

  // Supersede memV1 with memV2, leaving memV1 as SUPERSEDED and memV2 as ACTIVE
  env.memoryRepo.supersedeMemory({
    previousId: memV1.id,
    replacementId: memV2.id,
    scope: env.scopeAlpha,
    replacementStatus: 'ACTIVE'
  });

  // Archive memV2 so there is NO active memory for this key (only SUPERSEDED v1 and ARCHIVED v2)
  env.memoryRepo.updateMemory(memV2.id, env.scopeAlpha, { status: 'ARCHIVED' });

  // Verify no active memory exists
  const activeCheck = env.memoryRepo.getMemoryByKey(expectedKey, env.scopeAlpha, 'ACTIVE');
  assert.equal(activeCheck, null, 'Pre-condition: no ACTIVE memory for this key');

  const output = makeResearchOutput(question, 'NVMe throughput peaks at 3 GBps.');

  const proposals = await env.pipeline.processCompletedTask({
    task: env.taskAlpha,
    agentId: 'research-agent',
    output,
    caller: env.agentCallerAlpha,
    memoryService: env.memoryService
  });

  assert.equal(proposals.length, 1, 'Superseded historical records must NOT block new proposals');
  assert.equal(proposals[0].status, 'PENDING_APPROVAL');
  assert.equal(proposals[0].key, expectedKey);
  assert.equal(proposals[0].version, 1, 'Fresh ordinary proposal without version reuse');
  assert.equal(proposals[0].supersedesId, null);
});

// ============================================================================
// 3. Suppression: Key with an existing ACTIVE record having identical content remains suppressed
// ============================================================================
test('Phase 4D.3D.2 - 3: A key with an existing ACTIVE record having identical content remains suppressed', async () => {
  const env = setupTargetedLookupEnv();

  const question = 'Redis cache aside design';
  const expectedKey = `research.finding.${slugify(question, 45)}`;

  const output = makeResearchOutput(question, 'Redis cache-aside is standard.');
  const expectedContent = `Research Topic: ${question}\n\nKey Verified Findings:\n1. Redis cache-aside is standard.\n\nSources Cited:\n- Performance Guide: https://example.com/doc`;

  // Seed an ACTIVE memory with identical content
  env.memoryRepo.createMemory({
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    key: expectedKey,
    content: expectedContent,
    status: 'ACTIVE'
  });

  const proposals = await env.pipeline.processCompletedTask({
    task: env.taskAlpha,
    agentId: 'research-agent',
    output,
    caller: env.agentCallerAlpha,
    memoryService: env.memoryService
  });

  assert.equal(proposals.length, 0, 'Active key must remain suppressed until Phase 4D.3D.3 update proposals');
});

// ============================================================================
// 4. Suppression: Identical PENDING_APPROVAL proposal remains suppressed
// ============================================================================
test('Phase 4D.3D.2 - 4: An identical PENDING_APPROVAL proposal remains suppressed', async () => {
  const env = setupTargetedLookupEnv();

  const question = 'Write buffering avoid stalls';
  const output = makeResearchOutput(question, 'Write buffering avoids disk stalls.');

  // First execution: creates proposal in PENDING_APPROVAL
  const firstBatch = await env.pipeline.processCompletedTask({
    task: env.taskAlpha,
    agentId: 'research-agent',
    output,
    caller: env.agentCallerAlpha,
    memoryService: env.memoryService
  });
  assert.equal(firstBatch.length, 1);
  assert.equal(firstBatch[0].status, 'PENDING_APPROVAL');

  // Second execution with identical output: must be suppressed
  const secondBatch = await env.pipeline.processCompletedTask({
    task: env.taskAlpha,
    agentId: 'research-agent',
    output,
    caller: env.agentCallerAlpha,
    memoryService: env.memoryService
  });
  assert.equal(secondBatch.length, 0, 'Identical pending proposal must be suppressed');
});

// ============================================================================
// 5. Deduplication: Duplicate candidates in one extraction run remain deduplicated
// ============================================================================
test('Phase 4D.3D.2 - 5: Duplicate candidates in one extraction run remain deduplicated', async () => {
  const env = setupTargetedLookupEnv();

  // Multi-finding output with identical finding duplicated in the same report
  const output: AgentOutput = {
    agentId: 'research-agent',
    status: 'COMPLETED',
    result: {
      report: {
        researchQuestion: 'Concurrency patterns',
        executiveSummary: 'Executive summary',
        keyFindings: [
          'Optimistic locking avoids database row deadlocks in high concurrency.',
          'Optimistic locking avoids database row deadlocks in high concurrency.' // exact duplicate in same run
        ],
        evidenceAndSources: [
          { domain: 'example.com', url: 'https://example.com/db', title: 'DB Concurrency' }
        ],
        completionStatus: 'SUCCESS'
      }
    },
    summary: 'Research completed',
    stepsExecuted: 2,
    durationMs: 100
  };

  const proposals = await env.pipeline.processCompletedTask({
    task: env.taskAlpha,
    agentId: 'research-agent',
    output,
    caller: env.agentCallerAlpha,
    memoryService: env.memoryService
  });

  assert.equal(proposals.length, 1, 'In-run duplicate candidates must be deduplicated to exactly one proposal');
});

// ============================================================================
// 6. Scope Isolation: Workspace A historical records do not affect Workspace B
// ============================================================================
test('Phase 4D.3D.2 - 6: Workspace A historical records do not affect Workspace B', async () => {
  const env = setupTargetedLookupEnv();

  const question = 'Shared finding across workspaces';
  const expectedKey = `research.finding.${slugify(question, 45)}`;

  // Workspace A has ARCHIVED and SUPERSEDED records for this key
  env.memoryRepo.createMemory({
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    key: expectedKey,
    content: 'Workspace A archived finding',
    status: 'ARCHIVED'
  });

  const output = makeResearchOutput(question, 'Shared finding key content in Workspace B.');

  // Workspace B executes task
  const proposalsB = await env.pipeline.processCompletedTask({
    task: env.taskBeta,
    agentId: 'research-agent',
    output,
    caller: env.agentCallerBeta,
    memoryService: env.memoryService
  });

  assert.equal(proposalsB.length, 1, 'Workspace B must successfully create proposal regardless of Workspace A history');
  assert.equal(proposalsB[0].scopeType, 'WORKSPACE');
  assert.equal(proposalsB[0].scopeId, 'ws-beta');
});

// ============================================================================
// 7. Authorization: Global and workspace scope behavior matches authorization rules
// ============================================================================
test('Phase 4D.3D.2 - 7: Global and workspace scope behavior remains consistent with authorization rules', async () => {
  const env = setupTargetedLookupEnv();

  const question = 'Global standard protocol TLS';
  const expectedKey = `research.finding.${slugify(question, 45)}`;
  const findingText = 'Global standard protocol requires TLS 1.3 encryption.';
  const output = makeResearchOutput(question, findingText);
  const expectedContent = `Research Topic: ${question}\n\nKey Verified Findings:\n1. ${findingText}\n\nSources Cited:\n- Performance Guide: https://example.com/doc`;

  // 7a: Create an ACTIVE global memory with identical content
  const globalMem = env.memoryRepo.createMemory({
    category: 'PROJECT_FACT',
    scopeType: 'GLOBAL',
    scopeId: 'default',
    key: expectedKey,
    content: expectedContent,
    status: 'ACTIVE'
  });
  assert.equal(globalMem.status, 'ACTIVE');

  // Caller Alpha (has permittedScopes: [ws-alpha, global]) -> Suppressed against inherited active global memory!
  const proposalsAlpha = await env.pipeline.processCompletedTask({
    task: env.taskAlpha,
    agentId: 'research-agent',
    output,
    caller: env.agentCallerAlpha,
    memoryService: env.memoryService
  });
  assert.equal(proposalsAlpha.length, 0, 'Authorized workspace caller suppresses against inherited global active memory');

  // Caller Beta (permittedScopes: [ws-beta] ONLY, no global access) -> NOT suppressed because global is ineligible
  const proposalsBeta = await env.pipeline.processCompletedTask({
    task: env.taskBeta,
    agentId: 'research-agent',
    output,
    caller: env.agentCallerBeta,
    memoryService: env.memoryService
  });
  assert.equal(proposalsBeta.length, 1, 'Caller without global read access is not suppressed by unreadable global memory');
  assert.equal(proposalsBeta[0].scopeId, 'ws-beta');

  // 7c: If global memory is ARCHIVED, even authorized Caller Alpha is not suppressed
  env.memoryRepo.updateMemory(globalMem.id, env.scopeGlobal, { status: 'ARCHIVED' });

  const secondOutput = makeResearchOutput(question, 'Global standard protocol requires TLS 1.3 encryption.');
  const proposalsAlphaAfterArchive = await env.pipeline.processCompletedTask({
    task: env.taskAlpha,
    agentId: 'research-agent',
    output: secondOutput,
    caller: env.agentCallerAlpha,
    memoryService: env.memoryService
  });
  assert.equal(proposalsAlphaAfterArchive.length, 1, 'Archived global memory does not block workspace proposal');
  assert.equal(proposalsAlphaAfterArchive[0].scopeId, 'ws-alpha');
});

// ============================================================================
// 8. Bounded Execution: Pipeline processing no longer calls listMemories()
// ============================================================================
test('Phase 4D.3D.2 - 8: Pipeline processing no longer calls unbounded listMemories()', async () => {
  const env = setupTargetedLookupEnv();

  let listMemoriesCallCount = 0;
  const originalListMemories = env.memoryService.listMemories.bind(env.memoryService);
  env.memoryService.listMemories = (...args: Parameters<typeof originalListMemories>) => {
    listMemoriesCallCount++;
    return originalListMemories(...args);
  };

  const output = makeResearchOutput('Zero copy serialization', 'Zero copy serialization reduces CPU overhead.');

  const proposals = await env.pipeline.processCompletedTask({
    task: env.taskAlpha,
    agentId: 'research-agent',
    output,
    caller: env.agentCallerAlpha,
    memoryService: env.memoryService
  });

  assert.equal(proposals.length, 1);
  assert.equal(listMemoriesCallCount, 0, 'processCompletedTask must NEVER invoke listMemories()');
});

// ============================================================================
// 9. Scalability: Candidate evaluation uses targeted lookups on large historical dataset
// ============================================================================
test('Phase 4D.3D.2 - 9: Candidate evaluation uses targeted lookups on 500+ historical records without loading them', async () => {
  const env = setupTargetedLookupEnv();

  const question = 'Target unpoisoned key in large dataset';
  const targetKey = `research.finding.${slugify(question, 45)}`;

  // Populate 500 historical (ARCHIVED and SUPERSEDED) records across diverse keys
  env.db.transaction(() => {
    // 250 archived historical versions for the target key
    for (let i = 1; i <= 250; i++) {
      env.db.prepare(`
        INSERT INTO memories (
          id, category, scope_type, scope_id, key, content, status,
          priority, tags_json, metadata_json, version, supersedes_id, superseded_by,
          created_at, updated_at
        ) VALUES (?, 'PROJECT_FACT', 'WORKSPACE', 'ws-alpha', ?, ?, 'ARCHIVED', 50, '[]', '{}', ?, NULL, NULL, ?, ?)
      `).run(
        `archived-hist-${i}`,
        targetKey,
        `Historical archived observation version ${i}`,
        i,
        new Date(Date.now() - 1000000 + i).toISOString(),
        new Date(Date.now() - 1000000 + i).toISOString()
      );
    }

    // 250 superseded records for other keys in the same workspace
    for (let i = 1; i <= 250; i++) {
      env.db.prepare(`
        INSERT INTO memories (
          id, category, scope_type, scope_id, key, content, status,
          priority, tags_json, metadata_json, version, supersedes_id, superseded_by,
          created_at, updated_at
        ) VALUES (?, 'PROJECT_FACT', 'WORKSPACE', 'ws-alpha', ?, ?, 'SUPERSEDED', 50, '[]', '{}', 1, NULL, NULL, ?, ?)
      `).run(
        `superseded-other-${i}`,
        `other-historical-key-${i}`,
        `Superseded content ${i}`,
        new Date().toISOString(),
        new Date().toISOString()
      );
    }
  });

  const totalBefore = (env.db.prepare("SELECT COUNT(*) as c FROM memories WHERE scope_id = 'ws-alpha'").get() as { c: number }).c;
  assert.equal(totalBefore, 500, 'Pre-condition: exactly 500 historical rows seeded');

  // Spy on targeted lookups (getMemoryByKey and getPendingProposalsByKey) to observe bounded lookups
  let targetedLookupCalls = 0;
  const originalGetByKey = env.memoryService.getMemoryByKey.bind(env.memoryService);
  env.memoryService.getMemoryByKey = (...args: Parameters<typeof originalGetByKey>) => {
    targetedLookupCalls++;
    return originalGetByKey(...args);
  };
  const originalGetPending = env.memoryService.getPendingProposalsByKey.bind(env.memoryService);
  env.memoryService.getPendingProposalsByKey = (...args: Parameters<typeof originalGetPending>) => {
    targetedLookupCalls++;
    return originalGetPending(...args);
  };

  const output = makeResearchOutput(question, 'Target unpoisoned key in large dataset.');

  const proposals = await env.pipeline.processCompletedTask({
    task: env.taskAlpha,
    agentId: 'research-agent',
    output,
    caller: env.agentCallerAlpha,
    memoryService: env.memoryService
  });

  assert.equal(proposals.length, 1, 'Proposal must succeed despite 500 historical records');
  assert.equal(proposals[0].key, targetKey);
  assert.equal(proposals[0].status, 'PENDING_APPROVAL');
  assert.equal(proposals[0].version, 1, 'Initialized to fresh version 1');

  // Verify bounded lookups: exactly 2 targeted lookups (ACTIVE + PENDING_APPROVAL) were executed for the candidate
  assert.equal(targetedLookupCalls, 2, 'Candidate evaluation must make exactly targeted lookups (ACTIVE + PENDING_APPROVAL)');

  // Verify database count increased by exactly 1
  const totalAfter = (env.db.prepare("SELECT COUNT(*) as c FROM memories WHERE scope_id = 'ws-alpha'").get() as { c: number }).c;
  assert.equal(totalAfter, 501, 'Exactly one new proposal row added');
});
