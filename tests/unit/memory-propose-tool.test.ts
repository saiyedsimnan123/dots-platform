/**
 * Next-Generation Dots AI Platform - Agent Memory Proposal Tool Tests
 * Phase 7.5: Substep 4 - Agent Memory-Proposal Tool Integration
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
import { createMemoryProposeTool, MEMORY_PROPOSE_TOOL_NAME } from '../../src/tools/memory-tools.ts';
import type { ScopeIdentifier, CallerContext } from '../../src/domain/types.ts';
import {
  ValidationError,
  SecurityViolationError,
  MemoryScopeViolationError,
  TaskNotFoundError
} from '../../src/domain/errors.ts';

function setupProposalTestEnv() {
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
      if (credentials === 'token-member-alpha') {
        return {
          principalId: 'member-alpha',
          role: 'MEMBER' as const,
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

  const tool = createMemoryProposeTool(memoryService, authorizer);
  const toolRegistry = new ToolRegistry();
  toolRegistry.register(tool);

  const policyEngine = new PolicyEngine({ workspaceRoot: 'C:\\fake\\workspace', autoApproveTier2: true });

  const adminAlpha = authorizer.authorizeUser({ credentials: 'token-admin-alpha', requestedScope: scopeAlpha });
  const adminBeta = authorizer.authorizeUser({ credentials: 'token-admin-beta', requestedScope: scopeBeta });

  // Create an attested task in Workspace Alpha
  const taskAlpha = hostAuthority.createTask(taskRepo, {
    id: 'task-alpha-prop',
    goal: 'Test task for agent memory proposal',
    scope: scopeAlpha
  });

  // Create an attested task in Workspace Beta
  const taskBeta = hostAuthority.createTask(taskRepo, {
    id: 'task-beta-prop',
    goal: 'Test task in Beta',
    scope: scopeBeta
  });

  return {
    db,
    taskRepo,
    auditRepo,
    memoryRepo,
    hostAuthority,
    authorizer,
    memoryService,
    tool,
    toolRegistry,
    policyEngine,
    scopeAlpha,
    scopeBeta,
    scopeGlobal,
    adminAlpha,
    adminBeta,
    taskAlpha,
    taskBeta
  };
}

// ============================================================================
// 1. Valid Agent Submission Path
// ============================================================================

test('memory_propose - a valid agent can submit a proposal through the intended tool path', async () => {
  const env = setupProposalTestEnv();

  const rawArgs = {
    key: 'project.build_tool',
    content: 'The project uses npm as the standard package manager.',
    category: 'PROJECT_FACT',
    priority: 80,
    tags: ['build', 'package_manager'],
    metadata: { env: 'production', version: 1 }
  };

  const context = {
    taskId: env.taskAlpha.id,
    stepId: 'step-1',
    workspaceRoot: 'C:\\fake\\workspace'
  };

  const result = await env.toolRegistry.execute(
    MEMORY_PROPOSE_TOOL_NAME,
    rawArgs,
    context,
    env.policyEngine
  );

  assert.equal(result.exitCode, 0);
  assert.equal(result.output.success, true);
  assert.equal(result.output.status, 'PENDING_APPROVAL');
  assert.equal(result.output.category, 'PROJECT_FACT');
  assert.equal(result.output.scopeType, 'WORKSPACE');
  assert.equal(result.output.scopeId, 'ws-alpha');
  assert.ok(typeof result.output.proposalId === 'string');

  // Verify minimal acknowledgement: output does not leak raw content
  assert.equal('content' in result.output, false);

  // Verify memory row in SQLite has status PENDING_APPROVAL
  const proposalId = result.output.proposalId as string;
  const row = env.memoryRepo.getMemoryById(proposalId, env.scopeAlpha);
  assert.ok(row);
  assert.equal(row.id, proposalId);
  assert.equal(row.status, 'PENDING_APPROVAL');
  assert.equal(row.key, 'project.build_tool');
  assert.equal(row.content, 'The project uses npm as the standard package manager.');
  assert.equal(row.priority, 80);
});

// ============================================================================
// 2. Pending Approval Invariant: Not Active Without Human Approval
// ============================================================================

test('memory_propose - proposal remains pending and does not become active without human approval', async () => {
  const env = setupProposalTestEnv();

  const context = {
    taskId: env.taskAlpha.id,
    stepId: 'step-1',
    workspaceRoot: 'C:\\fake\\workspace'
  };

  const execRes = await env.toolRegistry.execute(
    MEMORY_PROPOSE_TOOL_NAME,
    {
      key: 'pending.fact.check',
      content: 'Provisional fact pending review',
      category: 'PROJECT_FACT'
    },
    context,
    env.policyEngine
  );

  const proposalId = execRes.output.proposalId as string;

  // Invariant 1: getMemoryByKey (defaults to ACTIVE) returns null for pending proposals
  const activeCheck = env.memoryService.getMemoryByKey(env.adminAlpha, 'pending.fact.check');
  assert.equal(activeCheck, null, 'Proposal must not be returned by standard active key lookup');

  // Invariant 2: Context builder ignores pending proposals
  const builtContext = env.memoryService.buildTaskMemoryContext(env.adminAlpha, {
    query: 'fact check provisional',
    taskId: env.taskAlpha.id
  });
  assert.equal(builtContext.included.length, 0, 'Pending proposals must never be included in task memory context');

  // Invariant 3: Proposal transitions to ACTIVE only when human USER with APPROVE permission decides it
  const decided = env.memoryService.decideProposal(env.adminAlpha, {
    memoryId: proposalId,
    decision: 'APPROVED'
  });
  assert.equal(decided.status, 'ACTIVE');

  // Invariant 4: Now that it is active, getMemoryByKey finds it
  const nowActive = env.memoryService.getMemoryByKey(env.adminAlpha, 'pending.fact.check');
  assert.ok(nowActive);
  assert.equal(nowActive.status, 'ACTIVE');
});

// ============================================================================
// 3. Agent Self-Decision & Direct Activation Blocked
// ============================================================================

test('memory_propose - agent cannot approve, reject, or directly activate its own proposal', async () => {
  const env = setupProposalTestEnv();

  const context = {
    taskId: env.taskAlpha.id,
    stepId: 'step-1',
    workspaceRoot: 'C:\\fake\\workspace'
  };

  const execRes = await env.toolRegistry.execute(
    MEMORY_PROPOSE_TOOL_NAME,
    {
      key: 'self.approval.attempt',
      content: 'Agent trying to approve this',
      category: 'PROJECT_FACT'
    },
    context,
    env.policyEngine
  );

  const proposalId = execRes.output.proposalId as string;
  const agentCaller = env.authorizer.authorizeAgent({ taskId: env.taskAlpha.id });

  // 1. Agent cannot approve via decideProposal
  assert.throws(
    () => env.memoryService.decideProposal(agentCaller, {
      memoryId: proposalId,
      decision: 'APPROVED'
    }),
    (err: unknown) => err instanceof SecurityViolationError && err.violationType === 'UNAUTHORIZED_APPROVAL'
  );

  // 2. Agent cannot reject via decideProposal
  assert.throws(
    () => env.memoryService.decideProposal(agentCaller, {
      memoryId: proposalId,
      decision: 'REJECTED'
    }),
    (err: unknown) => err instanceof SecurityViolationError && err.violationType === 'UNAUTHORIZED_APPROVAL'
  );

  // 3. Agent cannot activate via updateMemory
  assert.throws(
    () => env.memoryService.updateMemory(agentCaller, proposalId, {
      status: 'ACTIVE'
    }),
    (err: unknown) => err instanceof SecurityViolationError && err.violationType === 'UNAUTHORIZED_APPROVAL'
  );

  // 4. Agent cannot delete proposal via deleteMemory
  assert.throws(
    () => env.memoryService.deleteMemory(agentCaller, proposalId),
    (err: unknown) => err instanceof SecurityViolationError && err.violationType === 'INSUFFICIENT_PERMISSIONS'
  );

  // Proposal must still be PENDING_APPROVAL
  const row = env.memoryRepo.getMemoryById(proposalId, env.scopeAlpha);
  assert.equal(row?.status, 'PENDING_APPROVAL');
});

// ============================================================================
// 4. Identity & Scope Containment: Forged / Impersonation Attempts Blocked
// ============================================================================

test('memory_propose - agent cannot choose foreign scope or impersonate another tenant', async () => {
  const env = setupProposalTestEnv();

  const context = {
    taskId: env.taskAlpha.id, // Task is bound to Workspace Alpha
    stepId: 'step-1',
    workspaceRoot: 'C:\\fake\\workspace'
  };

  // 1. Agent attempts to specify foreign workspace scope in tool arguments
  await assert.rejects(
    async () => {
      await env.toolRegistry.execute(
        MEMORY_PROPOSE_TOOL_NAME,
        {
          key: 'spoofed.scope.key',
          content: 'Trying to write to Beta',
          category: 'PROJECT_FACT',
          scopeType: 'WORKSPACE',
          scopeId: 'ws-beta' // Foreign scope!
        },
        context,
        env.policyEngine
      );
    },
    (err: unknown) => err instanceof MemoryScopeViolationError
  );

  // 2. Agent attempts to specify GLOBAL scope in tool arguments
  await assert.rejects(
    async () => {
      await env.toolRegistry.execute(
        MEMORY_PROPOSE_TOOL_NAME,
        {
          key: 'spoofed.global.key',
          content: 'Trying to write to Global',
          category: 'PROJECT_FACT',
          scopeType: 'GLOBAL',
          scopeId: 'default'
        },
        context,
        env.policyEngine
      );
    },
    (err: unknown) => err instanceof MemoryScopeViolationError
  );

  // 3. Unattested legacy task (no scope attestation) fails closed
  const legacyTask = env.taskRepo.createTask({ goal: 'Legacy unattested task' });
  await assert.rejects(
    async () => {
      await env.toolRegistry.execute(
        MEMORY_PROPOSE_TOOL_NAME,
        {
          key: 'legacy.prop.key',
          content: 'Unattested proposal',
          category: 'PROJECT_FACT'
        },
        { taskId: legacyTask.id, stepId: 'step-legacy', workspaceRoot: 'C:\\fake' },
        env.policyEngine
      );
    },
    (err: unknown) => (err instanceof ValidationError || err instanceof SecurityViolationError) &&
      (err.message.includes('lacks metadata') || (err as any).violationType === 'UNATTESTED_TASK_SCOPE')
  );

  // 4. Non-existent taskId fails closed
  await assert.rejects(
    async () => {
      await env.toolRegistry.execute(
        MEMORY_PROPOSE_TOOL_NAME,
        {
          key: 'nonexistent.task.key',
          content: 'Non-existent task',
          category: 'PROJECT_FACT'
        },
        { taskId: 'fake-task-id-999', stepId: 'step-fake', workspaceRoot: 'C:\\fake' },
        env.policyEngine
      );
    },
    (err: unknown) => err instanceof TaskNotFoundError
  );
});

// ============================================================================
// 5. Input Bounds & Oversized / Invalid Values Rejected
// ============================================================================

test('memory_propose - rejects oversized, invalid, or illegal arguments', async () => {
  const env = setupProposalTestEnv();
  const context = {
    taskId: env.taskAlpha.id,
    stepId: 'step-1',
    workspaceRoot: 'C:\\fake\\workspace'
  };

  // Missing or empty key
  await assert.rejects(
    () => env.toolRegistry.execute(MEMORY_PROPOSE_TOOL_NAME, { content: 'c', category: 'PROJECT_FACT' }, context, env.policyEngine),
    (err: unknown) => err instanceof ValidationError && err.message.includes('key must be a non-empty string')
  );
  await assert.rejects(
    () => env.toolRegistry.execute(MEMORY_PROPOSE_TOOL_NAME, { key: '   ', content: 'c', category: 'PROJECT_FACT' }, context, env.policyEngine),
    (err: unknown) => err instanceof ValidationError
  );

  // Key > 256 characters
  await assert.rejects(
    () => env.toolRegistry.execute(MEMORY_PROPOSE_TOOL_NAME, { key: 'a'.repeat(257), content: 'c', category: 'PROJECT_FACT' }, context, env.policyEngine),
    (err: unknown) => err instanceof ValidationError && err.message.includes('exceeds limit of 256 characters')
  );

  // Missing or empty content
  await assert.rejects(
    () => env.toolRegistry.execute(MEMORY_PROPOSE_TOOL_NAME, { key: 'valid.key', content: '', category: 'PROJECT_FACT' }, context, env.policyEngine),
    (err: unknown) => err instanceof ValidationError && err.message.includes('content must be a non-empty string')
  );

  // Content > 8192 characters
  await assert.rejects(
    () => env.toolRegistry.execute(MEMORY_PROPOSE_TOOL_NAME, { key: 'valid.key', content: 'x'.repeat(8193), category: 'PROJECT_FACT' }, context, env.policyEngine),
    (err: unknown) => err instanceof ValidationError && err.message.includes('exceeds limit of 8192 characters')
  );

  // Invalid category
  await assert.rejects(
    () => env.toolRegistry.execute(MEMORY_PROPOSE_TOOL_NAME, { key: 'valid.key', content: 'c', category: 'INVALID_CATEGORY' }, context, env.policyEngine),
    (err: unknown) => err instanceof ValidationError && err.message.includes('Invalid memory category')
  );

  // Invalid priority
  await assert.rejects(
    () => env.toolRegistry.execute(MEMORY_PROPOSE_TOOL_NAME, { key: 'valid.key', content: 'c', category: 'PROJECT_FACT', priority: 150 }, context, env.policyEngine),
    (err: unknown) => err instanceof ValidationError && err.message.includes('priority must be an integer between 0 and 100')
  );
  await assert.rejects(
    () => env.toolRegistry.execute(MEMORY_PROPOSE_TOOL_NAME, { key: 'valid.key', content: 'c', category: 'PROJECT_FACT', priority: 50.5 }, context, env.policyEngine),
    (err: unknown) => err instanceof ValidationError
  );

  // Tags > 50 items or items > 100 chars
  await assert.rejects(
    () => env.toolRegistry.execute(MEMORY_PROPOSE_TOOL_NAME, {
      key: 'valid.key',
      content: 'c',
      category: 'PROJECT_FACT',
      tags: Array.from({ length: 51 }, (_, i) => `tag_${i}`)
    }, context, env.policyEngine),
    (err: unknown) => err instanceof ValidationError && err.message.includes('exceeds maximum limit of 50 items')
  );
  await assert.rejects(
    () => env.toolRegistry.execute(MEMORY_PROPOSE_TOOL_NAME, {
      key: 'valid.key',
      content: 'c',
      category: 'PROJECT_FACT',
      tags: ['a'.repeat(101)]
    }, context, env.policyEngine),
    (err: unknown) => err instanceof ValidationError && err.message.includes('exceeds limit of 100 characters')
  );

  // Attempting to pass status = ACTIVE directly
  await assert.rejects(
    () => env.toolRegistry.execute(MEMORY_PROPOSE_TOOL_NAME, {
      key: 'valid.key',
      content: 'c',
      category: 'PROJECT_FACT',
      status: 'ACTIVE'
    }, context, env.policyEngine),
    (err: unknown) => err instanceof SecurityViolationError && err.violationType === 'AGENT_PROPOSAL_REQUIRED'
  );
});

// ============================================================================
// 6. Cross-Tenant Isolation
// ============================================================================

test('memory_propose - cross-tenant isolation prevents accessing or deciding proposals from other scopes', async () => {
  const env = setupProposalTestEnv();

  // Agent in Workspace Alpha proposes a memory
  const alphaContext = {
    taskId: env.taskAlpha.id,
    stepId: 'step-alpha',
    workspaceRoot: 'C:\\fake\\workspace'
  };

  const resAlpha = await env.toolRegistry.execute(
    MEMORY_PROPOSE_TOOL_NAME,
    {
      key: 'alpha.confidential.fact',
      content: 'Alpha confidential internal documentation',
      category: 'PROJECT_FACT'
    },
    alphaContext,
    env.policyEngine
  );
  const alphaProposalId = resAlpha.output.proposalId as string;

  // 1. Admin in Workspace Beta CANNOT retrieve or see Alpha's proposal
  assert.throws(
    () => env.memoryService.getMemoryById(env.adminBeta, alphaProposalId),
    (err: unknown) => err instanceof MemoryScopeViolationError
  );

  // 2. Admin in Workspace Beta CANNOT decide Alpha's proposal
  assert.throws(
    () => env.memoryService.decideProposal(env.adminBeta, {
      memoryId: alphaProposalId,
      decision: 'APPROVED'
    }),
    (err: unknown) => err instanceof MemoryScopeViolationError
  );

  // 3. Admin in Alpha CAN decide Alpha's proposal
  const decided = env.memoryService.decideProposal(env.adminAlpha, {
    memoryId: alphaProposalId,
    decision: 'APPROVED'
  });
  assert.equal(decided.status, 'ACTIVE');
});

// ============================================================================
// 7. Audit Privacy: Zero Content or Full Keys in Audit Details
// ============================================================================

test('memory_propose - audit privacy: audit logs do not leak raw proposal content or full proposed keys', async () => {
  const env = setupProposalTestEnv();

  const secretProposalKey = 'sensitive_key_finance_q3_secret';
  const secretProposalContent = 'REVENUE_EXCEEDING_PROJECTIONS_BY_90_PERCENT';

  const context = {
    taskId: env.taskAlpha.id,
    stepId: 'step-audit-privacy',
    workspaceRoot: 'C:\\fake\\workspace'
  };

  const execRes = await env.toolRegistry.execute(
    MEMORY_PROPOSE_TOOL_NAME,
    {
      key: secretProposalKey,
      content: secretProposalContent,
      category: 'PROJECT_FACT',
      metadata: { department: 'finance' }
    },
    context,
    env.policyEngine
  );
  assert.equal(execRes.exitCode, 0);

  // Check all audit events in AuditRepository
  const allAuditEvents = env.auditRepo.getEventsByTaskId(env.taskAlpha.id);
  const proposalSubmittedEvents = allAuditEvents.filter((e) => e.eventType === 'MEMORY_PROPOSAL_SUBMITTED');
  assert.ok(proposalSubmittedEvents.length >= 1, 'Expected at least one MEMORY_PROPOSAL_SUBMITTED audit event');

  for (const event of allAuditEvents) {
    // 1. Raw proposal content must NEVER appear in any audit event detailsJson
    assert.equal(
      event.detailsJson.includes(secretProposalContent),
      false,
      `Audit event '${event.eventType}' leaked secret proposal content!`
    );

    // 2. Full proposed key must NOT appear in proposal audit events
    if (event.eventType === 'MEMORY_PROPOSAL_SUBMITTED') {
      assert.equal(
        event.detailsJson.includes(secretProposalKey),
        false,
        `Audit event MEMORY_PROPOSAL_SUBMITTED leaked proposed key '${secretProposalKey}' in detailsJson!`
      );
      const details = JSON.parse(event.detailsJson);
      assert.equal('key' in details, false, 'MEMORY_PROPOSAL_SUBMITTED must not contain key property');
      assert.equal('content' in details, false, 'MEMORY_PROPOSAL_SUBMITTED must not contain content property');
      assert.equal(details.status, 'PENDING_APPROVAL');
      assert.equal(details.category, 'PROJECT_FACT');
      assert.equal(details.scopeType, 'WORKSPACE');
      assert.equal(details.scopeId, 'ws-alpha');
    }
  }
});

// ============================================================================
// 8. End-to-End Coordinator Integration with Auto-Registered memory_propose
// ============================================================================

test('memory_propose - coordinator end-to-end task execution with scripted agent memory proposal step', async () => {
  const env = setupProposalTestEnv();

  const modelProvider = new MockModelProvider();
  const coordinatorRegistry = new ToolRegistry();
  const approvalBroker = new ApprovalBroker(env.taskRepo, env.auditRepo);
  const verifier = new VerificationEngine(env.taskRepo);
  const budgetTracker = new TokenBudgetTracker({ db: env.db, maxCostPerTaskUsd: 1.0 });

  const coordinator = new TaskCoordinator({
    taskRepo: env.taskRepo,
    auditRepo: env.auditRepo,
    modelProvider,
    toolRegistry: coordinatorRegistry,
    policyEngine: env.policyEngine,
    approvalBroker,
    verifier,
    budgetTracker,
    workspaceRoot: 'C:\\fake\\workspace',
    memoryService: env.memoryService,
    hostAuthority: env.hostAuthority
  });

  // Verify memory_propose was automatically registered by coordinator
  const registeredTool = coordinatorRegistry.get(MEMORY_PROPOSE_TOOL_NAME);
  assert.ok(registeredTool, 'memory_propose should be automatically registered into coordinator tool registry');

  // Submit scoped task
  const task = await coordinator.submitScopedTask({
    goal: 'Analyze dependencies and propose learned procedure for builds',
    caller: env.adminAlpha,
    requestedScope: env.scopeAlpha
  });

  // Enqueue plan that includes memory_propose step
  modelProvider.enqueuePlan([
    {
      stepOrder: 1,
      description: 'Calculate build timeout',
      toolName: 'calculate',
      arguments: { expression: '300 + 60' },
      expectedOutcome: 'Timeout calculated'
    },
    {
      stepOrder: 2,
      description: 'Propose learned build procedure',
      toolName: MEMORY_PROPOSE_TOOL_NAME,
      arguments: {
        key: 'ci.build.procedure',
        content: 'Run npm ci, then npm run test, timeout is 360 seconds',
        category: 'LEARNED_PROCEDURE',
        priority: 75
      },
      expectedOutcome: 'Build procedure proposed'
    }
  ]);

  // Execute task through coordinator loop
  const completedTask = await coordinator.runToCompletion(task.id, 20);
  assert.equal(completedTask.status, 'COMPLETED');

  // Verify proposal was created in database with PENDING_APPROVAL
  const proposedMem = env.memoryRepo.getMemoryByKey('ci.build.procedure', env.scopeAlpha, 'PENDING_APPROVAL');
  assert.ok(proposedMem, 'Proposed memory must exist in database with PENDING_APPROVAL status');
  assert.equal(proposedMem.status, 'PENDING_APPROVAL');
  assert.equal(proposedMem.category, 'LEARNED_PROCEDURE');
  assert.equal(proposedMem.content, 'Run npm ci, then npm run test, timeout is 360 seconds');

  // Proposal is not active yet
  assert.equal(env.memoryService.getMemoryByKey(env.adminAlpha, 'ci.build.procedure'), null);

  // Human user approves it
  const approved = env.memoryService.decideProposal(env.adminAlpha, {
    memoryId: proposedMem.id,
    decision: 'APPROVED'
  });
  assert.equal(approved.status, 'ACTIVE');

  // Now active memory lookup succeeds
  const activeLookup = env.memoryService.getMemoryByKey(env.adminAlpha, 'ci.build.procedure');
  assert.ok(activeLookup);
  assert.equal(activeLookup.status, 'ACTIVE');
});
