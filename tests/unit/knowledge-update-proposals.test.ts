/**
 * Next-Generation Dots AI Platform - Knowledge Update Proposals Tests
 * Phase 4D.3D.3: Update Proposal Generation
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
  type AgentOutput
} from '../../src/agents/index.ts';
import type { ScopeIdentifier } from '../../src/domain/types.ts';
import { ValidationError, MemoryConflictError } from '../../src/domain/errors.ts';

function setupUpdateProposalEnv() {
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

  const toolRegistry = new ToolRegistry();
  const policyEngine = new PolicyEngine({ workspaceRoot: '/fake/workspace', autoApproveTier2: true });
  const approvalBroker = new ApprovalBroker(taskRepo, auditRepo);
  const verifier = new VerificationEngine(taskRepo);
  const budgetTracker = new TokenBudgetTracker({ maxTokensPerTask: 100_000 });
  const pipeline = new KnowledgeProposalPipeline();

  const adminAlpha = authorizer.authorizeUser({ credentials: 'token-admin-alpha', requestedScope: scopeAlpha });
  const adminBeta = authorizer.authorizeUser({ credentials: 'token-admin-beta', requestedScope: scopeBeta });

  const taskAlpha = hostAuthority.createTask(taskRepo, {
    id: 'task-update-alpha',
    goal: 'Analyze API latency and caching configurations',
    scope: scopeAlpha,
    permittedScopes: [scopeAlpha, scopeGlobal]
  });

  const taskBeta = hostAuthority.createTask(taskRepo, {
    id: 'task-update-beta',
    goal: 'Analyze worker threading in tenant beta',
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

function makeResearchOutput(question: string, findingText: string, metadataExtra?: Record<string, unknown>): AgentOutput {
  return {
    agentId: 'research-agent',
    status: 'COMPLETED',
    result: {
      report: {
        researchQuestion: question,
        executiveSummary: 'Summary of findings',
        keyFindings: [findingText],
        evidenceAndSources: [
          { domain: 'arch.internal', url: 'https://arch.internal/docs/cache', title: 'Architecture Standard' }
        ],
        completionStatus: 'SUCCESS',
        ...(metadataExtra ? { customMetadata: metadataExtra } : {})
      }
    },
    summary: 'Research completed',
    stepsExecuted: 2,
    durationMs: 80
  };
}

// ============================================================================
// 1. New key -> ordinary PENDING_APPROVAL proposal
// ============================================================================
test('Phase 4D.3D.3 - 1: New key generates ordinary PENDING_APPROVAL proposal without update metadata', async () => {
  const env = setupUpdateProposalEnv();

  const question = 'Kafka consumer group partition assignment';
  const expectedKey = `research.finding.${slugify(question, 45)}`;

  const output = makeResearchOutput(question, 'CooperativeStickyAssignor minimizes partition rebalances.');

  const proposals = await env.pipeline.processCompletedTask({
    task: env.taskAlpha,
    agentId: 'research-agent',
    output,
    caller: env.agentCallerAlpha,
    memoryService: env.memoryService
  });

  assert.equal(proposals.length, 1);
  const p = proposals[0];
  assert.equal(p.status, 'PENDING_APPROVAL');
  assert.equal(p.key, expectedKey);
  assert.equal(p.version, 1);
  assert.equal(p.supersedesId, null);
  assert.equal(p.supersededBy, null);

  const meta = JSON.parse(p.metadataJson);
  assert.equal(meta.source, 'automatic_knowledge_proposal');
  assert.equal(meta.proposalType, undefined, 'Ordinary proposal must NOT have proposalType: UPDATE');
  assert.equal(meta.targetMemoryId, undefined);
  assert.equal(meta.targetVersion, undefined);
});

// ============================================================================
// 2. Existing ACTIVE key with identical content -> no new proposal
// ============================================================================
test('Phase 4D.3D.3 - 2: Existing ACTIVE key with identical content suppresses duplicate proposal', async () => {
  const env = setupUpdateProposalEnv();

  const question = 'Postgres connection pooling limits';
  const expectedKey = `research.finding.${slugify(question, 45)}`;
  const findingText = 'PgBouncer with transaction pooling handles 10k connections with 200 pool size.';

  const output = makeResearchOutput(question, findingText);
  const formattedContent =
    `Research Topic: ${question}\n\n` +
    `Key Verified Findings:\n1. ${findingText}\n\n` +
    `Sources Cited:\n- Architecture Standard: https://arch.internal/docs/cache`;

  // Pre-seed ACTIVE memory with identical formatted content
  env.memoryRepo.createMemory({
    key: expectedKey,
    content: formattedContent,
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    status: 'ACTIVE'
  });

  const proposals = await env.pipeline.processCompletedTask({
    task: env.taskAlpha,
    agentId: 'research-agent',
    output,
    caller: env.agentCallerAlpha,
    memoryService: env.memoryService
  });

  assert.equal(proposals.length, 0, 'Identical content must be suppressed without generating proposal');
});

// ============================================================================
// 3 & 4. Existing ACTIVE key with changed content -> UPDATE proposal with target ID and version
// ============================================================================
test('Phase 4D.3D.3 - 3 & 4: Existing ACTIVE key with changed content creates UPDATE proposal with target ID and version', async () => {
  const env = setupUpdateProposalEnv();

  const question = 'Redis timeout configuration';
  const expectedKey = `research.finding.${slugify(question, 45)}`;

  // Seed baseline ACTIVE memory
  const activeMem = env.memoryRepo.createMemory({
    key: expectedKey,
    content: 'Initial baseline: Redis timeout set to 5000ms across all clusters.',
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    status: 'ACTIVE'
  });
  assert.equal(activeMem.status, 'ACTIVE');
  assert.equal(activeMem.version, 1);

  // Agent output with changed knowledge
  const output = makeResearchOutput(question, 'Revised baseline: Redis timeout should be reduced to 2500ms for read replicas.');

  const proposals = await env.pipeline.processCompletedTask({
    task: env.taskAlpha,
    agentId: 'research-agent',
    output,
    caller: env.agentCallerAlpha,
    memoryService: env.memoryService
  });

  assert.equal(proposals.length, 1, 'Changed content for active key must generate an UPDATE proposal');
  const proposal = proposals[0];
  assert.equal(proposal.status, 'PENDING_APPROVAL');
  assert.equal(proposal.key, expectedKey);
  assert.notEqual(proposal.id, activeMem.id);

  // Metadata verification
  const meta = JSON.parse(proposal.metadataJson);
  assert.equal(meta.proposalType, 'UPDATE', 'Must carry proposalType: UPDATE');
  assert.equal(meta.targetMemoryId, activeMem.id, 'Must reference the targeted ACTIVE memory ID');
  assert.equal(meta.targetVersion, 1, 'Must record target active memory version at proposal generation time');
});

// ============================================================================
// 5. Existing ACTIVE memory remains unchanged after proposal generation
// ============================================================================
test('Phase 4D.3D.3 - 5: Existing ACTIVE memory remains completely unchanged during proposal generation', async () => {
  const env = setupUpdateProposalEnv();

  const question = 'HTTP Keepalive duration';
  const expectedKey = `research.finding.${slugify(question, 45)}`;

  const activeMem = env.memoryRepo.createMemory({
    key: expectedKey,
    content: 'Keepalive duration is 60 seconds.',
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    status: 'ACTIVE',
    priority: 80
  });

  const output = makeResearchOutput(question, 'Keepalive duration updated to 120 seconds for internal services.');

  await env.pipeline.processCompletedTask({
    task: env.taskAlpha,
    agentId: 'research-agent',
    output,
    caller: env.agentCallerAlpha,
    memoryService: env.memoryService
  });

  // Verify the ACTIVE memory in database is completely untouched
  const refetched = env.memoryRepo.getMemoryById(activeMem.id, env.scopeAlpha);
  assert.ok(refetched);
  assert.equal(refetched.status, 'ACTIVE');
  assert.equal(refetched.content, 'Keepalive duration is 60 seconds.');
  assert.equal(refetched.version, 1);
  assert.equal(refetched.supersededBy, null);
  assert.equal(refetched.supersedesId, null);
  assert.equal(refetched.updatedAt, activeMem.updatedAt);
});

// ============================================================================
// 6. Identical pending update -> duplicate suppressed
// ============================================================================
test('Phase 4D.3D.3 - 6: Identical pending update proposal is suppressed as duplicate', async () => {
  const env = setupUpdateProposalEnv();

  const question = 'GRPC max receive message length';
  const expectedKey = `research.finding.${slugify(question, 45)}`;

  // Seed baseline ACTIVE memory
  env.memoryRepo.createMemory({
    key: expectedKey,
    content: 'Default GRPC max receive is 4MB.',
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    status: 'ACTIVE'
  });

  const output = makeResearchOutput(question, 'GRPC max receive should be 16MB for batch reporting.');

  // Run 1: creates update proposal
  const batch1 = await env.pipeline.processCompletedTask({
    task: env.taskAlpha,
    agentId: 'research-agent',
    output,
    caller: env.agentCallerAlpha,
    memoryService: env.memoryService
  });
  assert.equal(batch1.length, 1);
  assert.equal(batch1[0].status, 'PENDING_APPROVAL');

  // Run 2: identical output
  const batch2 = await env.pipeline.processCompletedTask({
    task: env.taskAlpha,
    agentId: 'research-agent',
    output,
    caller: env.agentCallerAlpha,
    memoryService: env.memoryService
  });
  assert.equal(batch2.length, 0, 'Duplicate pending update with identical content must be suppressed');
});

// ============================================================================
// 7. Different pending update for the same target -> deterministic behavior, documented and tested
// ============================================================================
test('Phase 4D.3D.3 - 7: Competing pending updates for same target accumulate cleanly without overwriting', async () => {
  const env = setupUpdateProposalEnv();

  const question = 'Database connection timeout';
  const expectedKey = `research.finding.${slugify(question, 45)}`;

  // Baseline ACTIVE memory (version 1)
  const activeMem = env.memoryRepo.createMemory({
    key: expectedKey,
    content: 'Original timeout: 10000ms',
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    status: 'ACTIVE'
  });

  // Agent 1 proposes timeout = 15000ms
  const output1 = makeResearchOutput(question, 'Recommendation A: timeout 15000ms for batch workers.');
  const batch1 = await env.pipeline.processCompletedTask({
    task: env.taskAlpha,
    agentId: 'research-agent',
    output: output1,
    caller: env.agentCallerAlpha,
    memoryService: env.memoryService
  });
  assert.equal(batch1.length, 1);
  const prop1 = batch1[0];

  // Agent 2 proposes competing timeout = 20000ms
  const output2 = makeResearchOutput(question, 'Recommendation B: timeout 20000ms for cold start resiliency.');
  const batch2 = await env.pipeline.processCompletedTask({
    task: env.taskAlpha,
    agentId: 'research-agent',
    output: output2,
    caller: env.agentCallerAlpha,
    memoryService: env.memoryService
  });
  assert.equal(batch2.length, 1);
  const prop2 = batch2[0];

  // Verify competing proposals do not overwrite one another
  assert.notEqual(prop1.id, prop2.id, 'Each competing update gets its own unique ID');
  assert.equal(prop1.status, 'PENDING_APPROVAL');
  assert.equal(prop2.status, 'PENDING_APPROVAL');
  assert.equal(prop1.key, expectedKey);
  assert.equal(prop2.key, expectedKey);

  const meta1 = JSON.parse(prop1.metadataJson);
  const meta2 = JSON.parse(prop2.metadataJson);
  assert.equal(meta1.targetMemoryId, activeMem.id);
  assert.equal(meta2.targetMemoryId, activeMem.id);
  assert.equal(meta1.targetVersion, 1);
  assert.equal(meta2.targetVersion, 1);

  // Duplicate suppression works for each competing proposal
  const reOutput1 = await env.pipeline.processCompletedTask({
    task: env.taskAlpha,
    agentId: 'research-agent',
    output: output1,
    caller: env.agentCallerAlpha,
    memoryService: env.memoryService
  });
  assert.equal(reOutput1.length, 0, 'Re-submitting Recommendation A is suppressed');

  const reOutput2 = await env.pipeline.processCompletedTask({
    task: env.taskAlpha,
    agentId: 'research-agent',
    output: output2,
    caller: env.agentCallerAlpha,
    memoryService: env.memoryService
  });
  assert.equal(reOutput2.length, 0, 'Re-submitting Recommendation B is suppressed');

  // Both proposals exist deterministically in database
  const pendingInDb = env.memoryService.getPendingProposalsByKey(env.agentCallerAlpha, expectedKey);
  assert.equal(pendingInDb.length, 2, 'Both competing updates coexist deterministically in PENDING_APPROVAL');
});

// ============================================================================
// 8. Archived-only and superseded-only keys -> existing Phase 4D.3D.2 behavior preserved
// ============================================================================
test('Phase 4D.3D.3 - 8: Archived-only and superseded-only keys generate ordinary proposals, not updates', async () => {
  const env = setupUpdateProposalEnv();

  // 8a: Archived-only key
  const questionArchived = 'Archived only subsystem fact';
  const keyArchived = `research.finding.${slugify(questionArchived, 45)}`;
  env.memoryRepo.createMemory({
    key: keyArchived,
    content: 'Archived legacy knowledge',
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    status: 'ARCHIVED'
  });

  const outputArchived = makeResearchOutput(questionArchived, 'Modern implementation details.');
  const proposalsArchived = await env.pipeline.processCompletedTask({
    task: env.taskAlpha,
    agentId: 'research-agent',
    output: outputArchived,
    caller: env.agentCallerAlpha,
    memoryService: env.memoryService
  });
  assert.equal(proposalsArchived.length, 1);
  assert.equal(proposalsArchived[0].status, 'PENDING_APPROVAL');
  const metaArchived = JSON.parse(proposalsArchived[0].metadataJson);
  assert.equal(metaArchived.proposalType, undefined, 'Archived key must NOT produce an UPDATE proposal');

  // 8b: Superseded-only key
  const questionSuperseded = 'Superseded only subsystem fact';
  const keySuperseded = `research.finding.${slugify(questionSuperseded, 45)}`;
  const m1 = env.memoryRepo.createMemory({
    key: keySuperseded,
    content: 'V1 content',
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    status: 'ACTIVE'
  });
  const m2 = env.memoryRepo.createMemory({
    key: keySuperseded,
    content: 'V2 content',
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    status: 'PENDING_APPROVAL'
  });
  env.memoryRepo.supersedeMemory({
    previousId: m1.id,
    replacementId: m2.id,
    scope: env.scopeAlpha,
    replacementStatus: 'ACTIVE'
  });
  // Archive m2 so only SUPERSEDED (m1) and ARCHIVED (m2) remain
  env.memoryRepo.updateMemory(m2.id, env.scopeAlpha, { status: 'ARCHIVED' });

  const outputSuperseded = makeResearchOutput(questionSuperseded, 'V3 revived knowledge.');
  const proposalsSuperseded = await env.pipeline.processCompletedTask({
    task: env.taskAlpha,
    agentId: 'research-agent',
    output: outputSuperseded,
    caller: env.agentCallerAlpha,
    memoryService: env.memoryService
  });
  assert.equal(proposalsSuperseded.length, 1);
  assert.equal(proposalsSuperseded[0].status, 'PENDING_APPROVAL');
  const metaSuperseded = JSON.parse(proposalsSuperseded[0].metadataJson);
  assert.equal(metaSuperseded.proposalType, undefined, 'Superseded key must NOT produce an UPDATE proposal');
});

// ============================================================================
// 9. Workspace isolation and authorized global inheritance
// ============================================================================
test('Phase 4D.3D.3 - 9: Workspace isolation and global inheritance remain intact', async () => {
  const env = setupUpdateProposalEnv();

  const question = 'Global protocol cipher suite';
  const expectedKey = `research.finding.${slugify(question, 45)}`;
  const globalFinding = 'TLS_AES_256_GCM_SHA384 is the global default cipher.';
  const globalFormatted =
    `Research Topic: ${question}\n\n` +
    `Key Verified Findings:\n1. ${globalFinding}\n\n` +
    `Sources Cited:\n- Architecture Standard: https://arch.internal/docs/cache`;

  // 1. Create ACTIVE global memory
  const globalMem = env.memoryRepo.createMemory({
    key: expectedKey,
    content: globalFormatted,
    category: 'PROJECT_FACT',
    scopeType: 'GLOBAL',
    scopeId: 'default',
    status: 'ACTIVE'
  });
  assert.equal(globalMem.status, 'ACTIVE');

  // 9a. Workspace Alpha with access to global -> suppressed against inherited global active memory
  const outputIdentical = makeResearchOutput(question, globalFinding);
  const proposalsAlphaIdentical = await env.pipeline.processCompletedTask({
    task: env.taskAlpha,
    agentId: 'research-agent',
    output: outputIdentical,
    caller: env.agentCallerAlpha,
    memoryService: env.memoryService
  });
  assert.equal(proposalsAlphaIdentical.length, 0, 'Workspace candidate matching inherited global active memory must be suppressed');

  // 9b. Global caller with changed content -> creates UPDATE proposal in GLOBAL scope
  const taskGlobal = env.hostAuthority.createTask(env.taskRepo, {
    id: 'task-update-global',
    goal: 'Analyze global security protocol updates',
    scope: env.scopeGlobal,
    permittedScopes: [env.scopeGlobal]
  });
  const agentCallerGlobal = env.authorizer.authorizeAgent({ taskId: taskGlobal.id });

  const outputGlobalUpdate = makeResearchOutput(question, 'Revised global cipher: TLS_AES_128_GCM_SHA256 for lightweight edge devices.');
  const proposalsGlobalUpdate = await env.pipeline.processCompletedTask({
    task: taskGlobal,
    agentId: 'research-agent',
    output: outputGlobalUpdate,
    caller: agentCallerGlobal,
    memoryService: env.memoryService
  });
  assert.equal(proposalsGlobalUpdate.length, 1);
  const pGlobal = proposalsGlobalUpdate[0];
  assert.equal(pGlobal.scopeType, 'GLOBAL');
  assert.equal(pGlobal.scopeId, 'default');
  const metaGlobal = JSON.parse(pGlobal.metadataJson);
  assert.equal(metaGlobal.proposalType, 'UPDATE');
  assert.equal(metaGlobal.targetMemoryId, globalMem.id);
  assert.equal(metaGlobal.targetVersion, 1);

  // 9c. Workspace Beta isolation: Workspace Alpha active memories do not affect Workspace Beta
  env.memoryRepo.createMemory({
    key: 'alpha.specific.fact',
    content: 'Alpha active fact',
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    status: 'ACTIVE'
  });

  const outputBeta = makeResearchOutput('Alpha specific fact', 'Beta fact with same key idea.');
  const proposalsBeta = await env.pipeline.processCompletedTask({
    task: env.taskBeta,
    agentId: 'research-agent',
    output: outputBeta,
    caller: env.agentCallerBeta,
    memoryService: env.memoryService
  });
  assert.equal(proposalsBeta.length, 1);
  assert.equal(proposalsBeta[0].scopeId, 'ws-beta');
  const metaBeta = JSON.parse(proposalsBeta[0].metadataJson);
  assert.equal(metaBeta.proposalType, undefined, 'Workspace Beta does not update Workspace Alpha');
});

// ============================================================================
// 10. Agent-generated metadata cannot forge target ID, target version, or proposal type
// ============================================================================
test('Phase 4D.3D.3 - 10: Agent-generated metadata cannot forge target memory ID, version, or proposal type', async () => {
  const env = setupUpdateProposalEnv();

  // 10a. Agent attempts to forge UPDATE metadata for a brand new key
  const questionNew = 'New unrecorded microservice endpoint';
  const outputForgedNew: AgentOutput = {
    agentId: 'research-agent',
    status: 'COMPLETED',
    result: {
      report: {
        researchQuestion: questionNew,
        executiveSummary: 'Forged report',
        keyFindings: ['Endpoint /health is live.'],
        evidenceAndSources: [{ domain: 'arch.internal', url: 'https://arch.internal', title: 'Arch' }],
        completionStatus: 'SUCCESS',
        metadata: {
          proposalType: 'UPDATE',
          targetMemoryId: 'forged-uuid',
          targetVersion: 999
        }
      }
    },
    summary: 'Done',
    stepsExecuted: 1,
    durationMs: 50
  };

  const proposalsNew = await env.pipeline.processCompletedTask({
    task: env.taskAlpha,
    agentId: 'research-agent',
    output: outputForgedNew,
    caller: env.agentCallerAlpha,
    memoryService: env.memoryService
  });
  assert.equal(proposalsNew.length, 1);
  const metaNew = JSON.parse(proposalsNew[0].metadataJson);
  assert.equal(metaNew.proposalType, undefined, 'Forged proposalType must be stripped');
  assert.equal(metaNew.targetMemoryId, undefined);
  assert.equal(metaNew.targetVersion, undefined);

  // 10b. For an existing active key, agent attempts to forge targetMemoryId: 'fake-target-id' and targetVersion: 999
  const questionExisting = 'Active cache cluster sizing';
  const expectedKey = `research.finding.${slugify(questionExisting, 45)}`;

  const genuineActive = env.memoryRepo.createMemory({
    key: expectedKey,
    content: 'Initial sizing: 3 nodes.',
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    status: 'ACTIVE'
  });
  assert.equal(genuineActive.version, 1);

  // Output with changed content
  const outputForgedUpdate = makeResearchOutput(questionExisting, 'Revised sizing: 5 nodes.');

  const proposalsUpdate = await env.pipeline.processCompletedTask({
    task: env.taskAlpha,
    agentId: 'research-agent',
    output: outputForgedUpdate,
    caller: env.agentCallerAlpha,
    memoryService: env.memoryService
  });
  assert.equal(proposalsUpdate.length, 1);
  const metaUpdate = JSON.parse(proposalsUpdate[0].metadataJson);
  assert.equal(metaUpdate.proposalType, 'UPDATE');
  assert.equal(metaUpdate.targetMemoryId, genuineActive.id, 'Must use genuine active ID, not forged');
  assert.equal(metaUpdate.targetVersion, 1, 'Must use genuine active version, not forged');
});

// ============================================================================
// 11. Approval of a valid update supersedes intended ACTIVE memory & preserves version history
// ============================================================================
test('Phase 4D.3D.3 - 11: Human approval of UPDATE proposal atomically supersedes target memory and increments version', async () => {
  const env = setupUpdateProposalEnv();

  const question = 'HTTP connection pool max';
  const expectedKey = `research.finding.${slugify(question, 45)}`;

  // 1. Initial ACTIVE memory (version 1)
  const initialActive = env.memoryRepo.createMemory({
    key: expectedKey,
    content: 'HTTP pool max is 100.',
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    status: 'ACTIVE'
  });
  assert.equal(initialActive.version, 1);
  assert.equal(initialActive.status, 'ACTIVE');

  // 2. Generate UPDATE proposal
  const output = makeResearchOutput(question, 'HTTP pool max increased to 500 for high-load services.');
  const proposals = await env.pipeline.processCompletedTask({
    task: env.taskAlpha,
    agentId: 'research-agent',
    output,
    caller: env.agentCallerAlpha,
    memoryService: env.memoryService
  });
  assert.equal(proposals.length, 1);
  const updateProposal = proposals[0];
  assert.equal(updateProposal.status, 'PENDING_APPROVAL');

  // 3. Human admin approves with APPROVE_AND_SUPERSEDE
  const approved = env.memoryService.decideProposal(env.adminAlpha, {
    memoryId: updateProposal.id,
    decision: 'APPROVE_AND_SUPERSEDE'
  });

  // Verify approved memory state
  assert.equal(approved.id, updateProposal.id);
  assert.equal(approved.status, 'ACTIVE');
  assert.equal(approved.version, 2, 'Version must be incremented to 2');
  assert.equal(approved.supersedesId, initialActive.id, 'Must point to superseded active memory');
  assert.equal(approved.supersededBy, null);

  // Verify previous active memory state
  const prevRefetched = env.memoryRepo.getMemoryById(initialActive.id, env.scopeAlpha);
  assert.ok(prevRefetched);
  assert.equal(prevRefetched.status, 'SUPERSEDED');
  assert.equal(prevRefetched.supersededBy, approved.id);

  // Verify version history query
  const history = env.memoryRepo.getMemoryHistory(expectedKey, env.scopeAlpha);
  assert.equal(history.length, 2);
  assert.equal(history[0].id, initialActive.id);
  assert.equal(history[0].version, 1);
  assert.equal(history[0].status, 'SUPERSEDED');
  assert.equal(history[1].id, approved.id);
  assert.equal(history[1].version, 2);
  assert.equal(history[1].status, 'ACTIVE');
});

// ============================================================================
// 12. Approval fails safely if target memory changed or was superseded
// ============================================================================
test('Phase 4D.3D.3 - 12: Approval fails safely if target memory changed, superseded, or archived', async () => {
  const env = setupUpdateProposalEnv();

  const question = 'Kafka batch size configuration';
  const expectedKey = `research.finding.${slugify(question, 45)}`;

  // 1. Initial ACTIVE memory (version 1)
  const initialActive = env.memoryRepo.createMemory({
    key: expectedKey,
    content: 'Kafka batch size is 16384 bytes.',
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    status: 'ACTIVE'
  });

  // 2. Generate competing proposals P1 and P2 targeting initialActive (version 1)
  const output1 = makeResearchOutput(question, 'Kafka batch size should be 32768 bytes.');
  const proposals1 = await env.pipeline.processCompletedTask({
    task: env.taskAlpha,
    agentId: 'research-agent',
    output: output1,
    caller: env.agentCallerAlpha,
    memoryService: env.memoryService
  });
  const p1 = proposals1[0];

  const output2 = makeResearchOutput(question, 'Kafka batch size should be 65536 bytes.');
  const proposals2 = await env.pipeline.processCompletedTask({
    task: env.taskAlpha,
    agentId: 'research-agent',
    output: output2,
    caller: env.agentCallerAlpha,
    memoryService: env.memoryService
  });
  const p2 = proposals2[0];

  // 3. Human admin approves P1 first -> initialActive is superseded, P1 becomes ACTIVE v2
  const approvedP1 = env.memoryService.decideProposal(env.adminAlpha, {
    memoryId: p1.id,
    decision: 'APPROVE_AND_SUPERSEDE'
  });
  assert.equal(approvedP1.status, 'ACTIVE');
  assert.equal(approvedP1.version, 2);

  // 4. Now attempt to approve P2 (which targeted initialActive v1, now stale!)
  // APPROVE_AND_SUPERSEDE must fail safely with ValidationError
  assert.throws(
    () => {
      env.memoryService.decideProposal(env.adminAlpha, {
        memoryId: p2.id,
        decision: 'APPROVE_AND_SUPERSEDE'
      });
    },
    (err: unknown) => {
      assert.ok(err instanceof ValidationError);
      assert.match(err.message, /target memory.*does not match|stale/i);
      return true;
    },
    'Must fail when approving stale proposal targeting already-superseded memory'
  );

  // 5. Attempting to approve P2 with APPROVE_NEW must also fail safely
  assert.throws(
    () => {
      env.memoryService.decideProposal(env.adminAlpha, {
        memoryId: p2.id,
        decision: 'APPROVE_NEW'
      });
    },
    (err: unknown) => {
      assert.ok(err instanceof MemoryConflictError || err instanceof ValidationError);
      return true;
    },
    'Must fail with conflict/validation error when attempting APPROVE_NEW'
  );

  // Invariant check: P1 remains ACTIVE v2, initialActive remains SUPERSEDED, P2 remains PENDING_APPROVAL
  const checkActive = env.memoryRepo.getMemoryByKey(expectedKey, env.scopeAlpha, 'ACTIVE');
  assert.equal(checkActive?.id, p1.id);
  assert.equal(checkActive?.version, 2);

  const checkP2 = env.memoryRepo.getMemoryById(p2.id, env.scopeAlpha);
  assert.equal(checkP2?.status, 'PENDING_APPROVAL');

  // 12b. If active memory is archived, approval of an update proposal fails safely
  env.memoryRepo.updateMemory(approvedP1.id, env.scopeAlpha, { status: 'ARCHIVED' });
  assert.throws(
    () => {
      env.memoryService.decideProposal(env.adminAlpha, {
        memoryId: p2.id,
        decision: 'APPROVE_AND_SUPERSEDE'
      });
    },
    ValidationError,
    'Cannot supersede when no active memory exists'
  );

  assert.throws(
    () => {
      env.memoryService.decideProposal(env.adminAlpha, {
        memoryId: p2.id,
        decision: 'APPROVE_NEW'
      });
    },
    ValidationError,
    'Cannot approve update proposal with APPROVE_NEW when target is no longer active'
  );
});

// ============================================================================
// 13. Rejection leaves original ACTIVE memory untouched
// ============================================================================
test('Phase 4D.3D.3 - 13: Rejection of an UPDATE proposal leaves original ACTIVE memory untouched', async () => {
  const env = setupUpdateProposalEnv();

  const question = 'TLS session ticket lifetime';
  const expectedKey = `research.finding.${slugify(question, 45)}`;

  // 1. Initial ACTIVE memory
  const initialActive = env.memoryRepo.createMemory({
    key: expectedKey,
    content: 'TLS ticket lifetime is 86400 seconds.',
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    status: 'ACTIVE'
  });

  // 2. Generate UPDATE proposal
  const output = makeResearchOutput(question, 'Proposed change: reduce TLS ticket lifetime to 3600 seconds.');
  const proposals = await env.pipeline.processCompletedTask({
    task: env.taskAlpha,
    agentId: 'research-agent',
    output,
    caller: env.agentCallerAlpha,
    memoryService: env.memoryService
  });
  assert.equal(proposals.length, 1);
  const proposal = proposals[0];

  // 3. Admin rejects proposal
  const rejected = env.memoryService.decideProposal(env.adminAlpha, {
    memoryId: proposal.id,
    decision: 'REJECT'
  });
  assert.equal(rejected.status, 'ARCHIVED');

  // 4. Verify initialActive remains ACTIVE and untouched
  const activeCheck = env.memoryRepo.getMemoryByKey(expectedKey, env.scopeAlpha, 'ACTIVE');
  assert.ok(activeCheck);
  assert.equal(activeCheck.id, initialActive.id);
  assert.equal(activeCheck.status, 'ACTIVE');
  assert.equal(activeCheck.version, 1);
  assert.equal(activeCheck.content, 'TLS ticket lifetime is 86400 seconds.');
  assert.equal(activeCheck.supersededBy, null);
  assert.equal(activeCheck.supersedesId, null);
});
