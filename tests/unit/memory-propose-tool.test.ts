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
import {
  createMemoryProposeTool,
  MEMORY_PROPOSE_TOOL_NAME,
  validateProposalMetadata,
  validateSerializedMetadataSize,
  isPlainObject,
  MAX_METADATA_TOP_KEYS,
  MAX_METADATA_DEPTH,
  MAX_METADATA_TOTAL_VALUES,
  MAX_METADATA_ARRAY_ITEMS,
  MAX_METADATA_STRING_LENGTH,
  MAX_METADATA_SERIALIZED_BYTES
} from '../../src/tools/memory-tools.ts';
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

// ============================================================================
// 9. Bounded Memory Proposal Metadata Validation & Privacy
// ============================================================================

test('memory_propose - accepts valid nested metadata up to depth 5 and within all bounds', async () => {
  const env = setupProposalTestEnv();
  const context = {
    taskId: env.taskAlpha.id,
    stepId: 'step-meta-valid',
    workspaceRoot: 'C:\\fake\\workspace'
  };

  // Valid deeply nested structure (depth 5):
  // 1 (root) -> 2 (l2) -> 3 (l3) -> 4 (l4) -> 5 (l5)
  const validMetadata = {
    version: 1,
    flags: [true, false, null],
    notes: 'A'.repeat(4096), // string at boundary length
    l2: {
      num: 42.5,
      items: Array.from({ length: 100 }, (_, i) => i), // array at boundary 100 items
      l3: {
        active: true,
        l4: {
          tag: 'deep-tag',
          l5: {
            deepestValue: 'nested_success'
          }
        }
      }
    }
  };

  const result = await env.toolRegistry.execute(
    MEMORY_PROPOSE_TOOL_NAME,
    {
      key: 'valid.nested.meta.key',
      content: 'Memory content with valid metadata',
      category: 'PROJECT_FACT',
      metadata: validMetadata
    },
    context,
    env.policyEngine
  );

  assert.equal(result.exitCode, 0);
  assert.equal(result.output.success, true);
  const proposalId = result.output.proposalId as string;
  const persisted = env.memoryRepo.getMemoryById(proposalId, env.scopeAlpha);
  assert.ok(persisted);
  const parsedMeta = JSON.parse(persisted.metadataJson);
  assert.equal(parsedMeta.version, 1);
  assert.equal(parsedMeta.l2.l3.l4.l5.deepestValue, 'nested_success');
  assert.equal(parsedMeta.l2.items.length, 100);
});

test('memory_propose - rejects metadata exceeding maximum nesting depth of 5', async () => {
  const env = setupProposalTestEnv();
  const context = {
    taskId: env.taskAlpha.id,
    stepId: 'step-meta-depth',
    workspaceRoot: 'C:\\fake\\workspace'
  };

  // Nesting depth 6 with objects:
  // 1 (root) -> 2 (l2) -> 3 (l3) -> 4 (l4) -> 5 (l5) -> 6 (l6)
  const tooDeepObj = {
    l2: {
      l3: {
        l4: {
          l5: {
            l6: {
              tooDeep: true
            }
          }
        }
      }
    }
  };

  await assert.rejects(
    () => env.toolRegistry.execute(
      MEMORY_PROPOSE_TOOL_NAME,
      {
        key: 'too.deep.obj.key',
        content: 'Content',
        category: 'PROJECT_FACT',
        metadata: tooDeepObj
      },
      context,
      env.policyEngine
    ),
    (err: unknown) => err instanceof ValidationError && err.message.includes('exceeds maximum nesting depth of 5')
  );

  // Nesting depth 6 with arrays:
  // 1 (root) -> 2 (arr1) -> 3 (arr2) -> 4 (arr3) -> 5 (arr4) -> 6 (arr5)
  const tooDeepArr = {
    nested: [[[[[1]]]]]
  };

  await assert.rejects(
    () => env.toolRegistry.execute(
      MEMORY_PROPOSE_TOOL_NAME,
      {
        key: 'too.deep.arr.key',
        content: 'Content',
        category: 'PROJECT_FACT',
        metadata: tooDeepArr
      },
      context,
      env.policyEngine
    ),
    (err: unknown) => err instanceof ValidationError && err.message.includes('exceeds maximum nesting depth of 5')
  );
});

test('memory_propose - rejects metadata exceeding maximum 50 top-level keys', async () => {
  const env = setupProposalTestEnv();
  const context = {
    taskId: env.taskAlpha.id,
    stepId: 'step-meta-top-keys',
    workspaceRoot: 'C:\\fake\\workspace'
  };

  const tooManyTopKeys: Record<string, number> = {};
  for (let i = 0; i < 51; i++) {
    tooManyTopKeys[`k_${i}`] = i;
  }

  await assert.rejects(
    () => env.toolRegistry.execute(
      MEMORY_PROPOSE_TOOL_NAME,
      {
        key: 'too.many.keys.key',
        content: 'Content',
        category: 'PROJECT_FACT',
        metadata: tooManyTopKeys
      },
      context,
      env.policyEngine
    ),
    (err: unknown) => err instanceof ValidationError && err.message.includes('exceeds maximum limit of 50 keys (51 > 50)')
  );
});

test('memory_propose - rejects metadata exceeding maximum 500 total visited values', async () => {
  const env = setupProposalTestEnv();
  const context = {
    taskId: env.taskAlpha.id,
    stepId: 'step-meta-total-vals',
    workspaceRoot: 'C:\\fake\\workspace'
  };

  // 6 arrays of 100 items each = 600 items + 6 array nodes + 1 root node = 607 visited values (> 500)
  const tooManyValues: Record<string, number[]> = {};
  for (let a = 0; a < 6; a++) {
    tooManyValues[`arr_${a}`] = Array.from({ length: 100 }, (_, i) => i);
  }

  await assert.rejects(
    () => env.toolRegistry.execute(
      MEMORY_PROPOSE_TOOL_NAME,
      {
        key: 'too.many.values.key',
        content: 'Content',
        category: 'PROJECT_FACT',
        metadata: tooManyValues
      },
      context,
      env.policyEngine
    ),
    (err: unknown) => err instanceof ValidationError && err.message.includes('exceeds maximum limit of 500 total visited values')
  );
});

test('memory_propose - rejects metadata array exceeding maximum 100 items', async () => {
  const env = setupProposalTestEnv();
  const context = {
    taskId: env.taskAlpha.id,
    stepId: 'step-meta-arr-items',
    workspaceRoot: 'C:\\fake\\workspace'
  };

  const tooLongArray = {
    list: Array.from({ length: 101 }, (_, i) => i)
  };

  await assert.rejects(
    () => env.toolRegistry.execute(
      MEMORY_PROPOSE_TOOL_NAME,
      {
        key: 'too.long.arr.key',
        content: 'Content',
        category: 'PROJECT_FACT',
        metadata: tooLongArray
      },
      context,
      env.policyEngine
    ),
    (err: unknown) => err instanceof ValidationError && err.message.includes('exceeds maximum limit of 100 items (101 > 100)')
  );
});

test('memory_propose - rejects metadata string exceeding maximum 4,096 characters', async () => {
  const env = setupProposalTestEnv();
  const context = {
    taskId: env.taskAlpha.id,
    stepId: 'step-meta-str-len',
    workspaceRoot: 'C:\\fake\\workspace'
  };

  const tooLongString = {
    text: 'x'.repeat(4097)
  };

  await assert.rejects(
    () => env.toolRegistry.execute(
      MEMORY_PROPOSE_TOOL_NAME,
      {
        key: 'too.long.str.key',
        content: 'Content',
        category: 'PROJECT_FACT',
        metadata: tooLongString
      },
      context,
      env.policyEngine
    ),
    (err: unknown) => err instanceof ValidationError && err.message.includes('exceeds maximum limit of 4096 characters (4097 > 4096)')
  );
});

test('memory_propose - rejects serialized metadata exceeding maximum 16 KiB after sanitization', async () => {
  const env = setupProposalTestEnv();
  const context = {
    taskId: env.taskAlpha.id,
    stepId: 'step-meta-bytes',
    workspaceRoot: 'C:\\fake\\workspace'
  };

  // 5 strings of 3,500 characters each = ~17.5 KiB serialized (> 16 KiB / 16384 bytes)
  const oversizedSerialized = {
    f1: 'a'.repeat(3500),
    f2: 'b'.repeat(3500),
    f3: 'c'.repeat(3500),
    f4: 'd'.repeat(3500),
    f5: 'e'.repeat(3500)
  };

  await assert.rejects(
    () => env.toolRegistry.execute(
      MEMORY_PROPOSE_TOOL_NAME,
      {
        key: 'too.many.bytes.key',
        content: 'Content',
        category: 'PROJECT_FACT',
        metadata: oversizedSerialized
      },
      context,
      env.policyEngine
    ),
    (err: unknown) => err instanceof ValidationError && err.message.includes('exceeds maximum limit of 16 KiB (16384 bytes)')
  );
});

test('memory_propose - rejects cyclic structures safely with ValidationError and zero recursion overflow', async () => {
  const env = setupProposalTestEnv();
  const context = {
    taskId: env.taskAlpha.id,
    stepId: 'step-meta-cycle',
    workspaceRoot: 'C:\\fake\\workspace'
  };

  // Direct cyclic reference in object
  const cycleObj: Record<string, unknown> = { name: 'self_cycle' };
  cycleObj.self = cycleObj;

  await assert.rejects(
    () => env.toolRegistry.execute(
      MEMORY_PROPOSE_TOOL_NAME,
      {
        key: 'cycle.obj.key',
        content: 'Content',
        category: 'PROJECT_FACT',
        metadata: cycleObj
      },
      context,
      env.policyEngine
    ),
    (err: unknown) => err instanceof ValidationError && err.message.includes('cyclic references')
  );

  // Indirect cyclic reference (a -> b -> a)
  const cycleA: Record<string, unknown> = { name: 'cycle_a' };
  const cycleB: Record<string, unknown> = { name: 'cycle_b', refA: cycleA };
  cycleA.refB = cycleB;

  await assert.rejects(
    () => env.toolRegistry.execute(
      MEMORY_PROPOSE_TOOL_NAME,
      {
        key: 'cycle.indirect.key',
        content: 'Content',
        category: 'PROJECT_FACT',
        metadata: { a: cycleA }
      },
      context,
      env.policyEngine
    ),
    (err: unknown) => err instanceof ValidationError && err.message.includes('cyclic references')
  );

  // Cyclic reference in array
  const cycleArr: unknown[] = ['start'];
  cycleArr.push(cycleArr);

  await assert.rejects(
    () => env.toolRegistry.execute(
      MEMORY_PROPOSE_TOOL_NAME,
      {
        key: 'cycle.arr.key',
        content: 'Content',
        category: 'PROJECT_FACT',
        metadata: { list: cycleArr }
      },
      context,
      env.policyEngine
    ),
    (err: unknown) => err instanceof ValidationError && err.message.includes('cyclic references')
  );
});

test('memory_propose - rejects non-plain objects safely with ValidationError', async () => {
  const env = setupProposalTestEnv();
  const context = {
    taskId: env.taskAlpha.id,
    stepId: 'step-meta-nonplain',
    workspaceRoot: 'C:\\fake\\workspace'
  };

  // Top-level Date instance
  await assert.rejects(
    () => env.toolRegistry.execute(
      MEMORY_PROPOSE_TOOL_NAME,
      {
        key: 'nonplain.top.key',
        content: 'Content',
        category: 'PROJECT_FACT',
        metadata: new Date() as any
      },
      context,
      env.policyEngine
    ),
    (err: unknown) => err instanceof ValidationError && err.message.includes('plain object')
  );

  // Nested Date instance
  await assert.rejects(
    () => env.toolRegistry.execute(
      MEMORY_PROPOSE_TOOL_NAME,
      {
        key: 'nonplain.nested.date.key',
        content: 'Content',
        category: 'PROJECT_FACT',
        metadata: { timestamp: new Date() }
      },
      context,
      env.policyEngine
    ),
    (err: unknown) => err instanceof ValidationError && err.message.includes('non-plain object')
  );

  // Nested RegExp instance
  await assert.rejects(
    () => env.toolRegistry.execute(
      MEMORY_PROPOSE_TOOL_NAME,
      {
        key: 'nonplain.nested.regex.key',
        content: 'Content',
        category: 'PROJECT_FACT',
        metadata: { pattern: /regex/ }
      },
      context,
      env.policyEngine
    ),
    (err: unknown) => err instanceof ValidationError && err.message.includes('non-plain object')
  );

  // Nested Map instance
  await assert.rejects(
    () => env.toolRegistry.execute(
      MEMORY_PROPOSE_TOOL_NAME,
      {
        key: 'nonplain.nested.map.key',
        content: 'Content',
        category: 'PROJECT_FACT',
        metadata: { mapping: new Map() }
      },
      context,
      env.policyEngine
    ),
    (err: unknown) => err instanceof ValidationError && err.message.includes('non-plain object')
  );

  // Custom class instance
  class CustomMeta {
    prop = 123;
  }
  await assert.rejects(
    () => env.toolRegistry.execute(
      MEMORY_PROPOSE_TOOL_NAME,
      {
        key: 'nonplain.nested.class.key',
        content: 'Content',
        category: 'PROJECT_FACT',
        metadata: { instance: new CustomMeta() }
      },
      context,
      env.policyEngine
    ),
    (err: unknown) => err instanceof ValidationError && err.message.includes('non-plain object')
  );
});

test('memory_propose - rejects unsupported primitive types safely with ValidationError', async () => {
  const env = setupProposalTestEnv();
  const context = {
    taskId: env.taskAlpha.id,
    stepId: 'step-meta-unsupported-types',
    workspaceRoot: 'C:\\fake\\workspace'
  };

  // undefined value
  await assert.rejects(
    () => env.toolRegistry.execute(
      MEMORY_PROPOSE_TOOL_NAME,
      {
        key: 'unsupported.undefined.key',
        content: 'Content',
        category: 'PROJECT_FACT',
        metadata: { field: undefined }
      },
      context,
      env.policyEngine
    ),
    (err: unknown) => err instanceof ValidationError && err.message.includes('unsupported undefined value')
  );

  // symbol value
  await assert.rejects(
    () => env.toolRegistry.execute(
      MEMORY_PROPOSE_TOOL_NAME,
      {
        key: 'unsupported.symbol.key',
        content: 'Content',
        category: 'PROJECT_FACT',
        metadata: { field: Symbol('token') }
      },
      context,
      env.policyEngine
    ),
    (err: unknown) => err instanceof ValidationError && err.message.includes('unsupported symbol value')
  );

  // bigint value
  await assert.rejects(
    () => env.toolRegistry.execute(
      MEMORY_PROPOSE_TOOL_NAME,
      {
        key: 'unsupported.bigint.key',
        content: 'Content',
        category: 'PROJECT_FACT',
        metadata: { field: 9007199254740993n }
      },
      context,
      env.policyEngine
    ),
    (err: unknown) => err instanceof ValidationError && err.message.includes('unsupported bigint value')
  );

  // function value
  await assert.rejects(
    () => env.toolRegistry.execute(
      MEMORY_PROPOSE_TOOL_NAME,
      {
        key: 'unsupported.func.key',
        content: 'Content',
        category: 'PROJECT_FACT',
        metadata: { handler: () => {} }
      },
      context,
      env.policyEngine
    ),
    (err: unknown) => err instanceof ValidationError && err.message.includes('unsupported function value')
  );

  // NaN value
  await assert.rejects(
    () => env.toolRegistry.execute(
      MEMORY_PROPOSE_TOOL_NAME,
      {
        key: 'unsupported.nan.key',
        content: 'Content',
        category: 'PROJECT_FACT',
        metadata: { num: NaN }
      },
      context,
      env.policyEngine
    ),
    (err: unknown) => err instanceof ValidationError && err.message.includes('unsupported non-finite number')
  );

  // Infinity value
  await assert.rejects(
    () => env.toolRegistry.execute(
      MEMORY_PROPOSE_TOOL_NAME,
      {
        key: 'unsupported.infinity.key',
        content: 'Content',
        category: 'PROJECT_FACT',
        metadata: { num: Infinity }
      },
      context,
      env.policyEngine
    ),
    (err: unknown) => err instanceof ValidationError && err.message.includes('unsupported non-finite number')
  );
});

test('memory_propose - preserves secret scrubbing in nested metadata and respects error privacy', async () => {
  const env = setupProposalTestEnv();
  const context = {
    taskId: env.taskAlpha.id,
    stepId: 'step-meta-secret-scrubbing',
    workspaceRoot: 'C:\\fake\\workspace'
  };

  const passwordSecret = 'password_secret_123456';
  const apiTokenSecret = 'api_token_secret_789012';
  const githubSecret = 'ghp_111111111122222222223333333333444444';
  const bearerSecret = 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9token999';

  const rawMetadataWithSecret = {
    normalConfig: 'standard-value',
    nestedSection: {
      password: passwordSecret, // sensitive key -> must be stripped
      apiToken: apiTokenSecret, // sensitive key -> must be stripped
      safeNote: `User authorized with ${githubSecret} and ${bearerSecret}` // sensitive string values -> scrubbed
    }
  };

  const res = await env.toolRegistry.execute(
    MEMORY_PROPOSE_TOOL_NAME,
    {
      key: 'nested.scrubbed.meta.key',
      content: 'Proposing memory with nested credentials in metadata',
      category: 'PROJECT_FACT',
      metadata: rawMetadataWithSecret
    },
    context,
    env.policyEngine
  );

  assert.equal(res.exitCode, 0);
  const proposalId = res.output.proposalId as string;
  const memoryRow = env.memoryRepo.getMemoryById(proposalId, env.scopeAlpha);
  assert.ok(memoryRow);

  const persistedMetadata = JSON.parse(memoryRow.metadataJson);
  assert.equal(persistedMetadata.normalConfig, 'standard-value');
  assert.equal('password' in persistedMetadata.nestedSection, false, 'password key must be stripped');
  assert.equal('apiToken' in persistedMetadata.nestedSection, false, 'apiToken key must be stripped');

  // Verify secret keys and raw tokens never appear in persisted metadata JSON
  assert.equal(memoryRow.metadataJson.includes(passwordSecret), false, 'Password secret must not appear');
  assert.equal(memoryRow.metadataJson.includes(apiTokenSecret), false, 'API token secret must not appear');
  assert.equal(memoryRow.metadataJson.includes(githubSecret), false, 'GitHub token must be scrubbed');
  assert.equal(memoryRow.metadataJson.includes('token999'), false, 'Bearer token body must be scrubbed');

  // Verify scrubber redaction tags exist in scrubbed note
  assert.ok(persistedMetadata.nestedSection.safeNote.includes('[REDACTED_GITHUB_TOKEN]'));
  assert.ok(persistedMetadata.nestedSection.safeNote.includes('Bearer [REDACTED_TOKEN]'));
});

test('validateProposalMetadata & validateSerializedMetadataSize - direct boundary and edge cases', () => {
  // 1. isPlainObject edge cases
  assert.equal(isPlainObject({}), true);
  assert.equal(isPlainObject(Object.create(null)), true);
  assert.equal(isPlainObject(null), false);
  assert.equal(isPlainObject([]), false);
  assert.equal(isPlainObject('string'), false);
  assert.equal(isPlainObject(123), false);
  assert.equal(isPlainObject(true), false);
  assert.equal(isPlainObject(new Date()), false);
  assert.equal(isPlainObject(/regex/), false);
  assert.equal(isPlainObject(new Map()), false);
  assert.equal(isPlainObject(new Set()), false);

  // 2. validateProposalMetadata: non-plain object root throws
  assert.throws(
    () => validateProposalMetadata(null),
    (err: unknown) => err instanceof ValidationError && err.message === 'Memory metadata must be a plain object.'
  );
  assert.throws(
    () => validateProposalMetadata(['array']),
    (err: unknown) => err instanceof ValidationError && err.message === 'Memory metadata must be a plain object.'
  );
  assert.throws(
    () => validateProposalMetadata('primitive'),
    (err: unknown) => err instanceof ValidationError && err.message === 'Memory metadata must be a plain object.'
  );

  // 3. Exact boundary: 50 top-level keys passes, 51 throws
  const top50: Record<string, number> = {};
  for (let i = 0; i < 50; i++) top50[`k_${i}`] = i;
  assert.doesNotThrow(() => validateProposalMetadata(top50));
  top50['k_50'] = 50;
  assert.throws(
    () => validateProposalMetadata(top50),
    (err: unknown) => err instanceof ValidationError && err.message.includes('51 > 50')
  );

  // 4. Exact boundary: depth 5 passes, depth 6 throws
  const depth5 = { a: { b: { c: { d: { e: 'val' } } } } };
  assert.doesNotThrow(() => validateProposalMetadata(depth5));
  const depth6 = { a: { b: { c: { d: { e: { f: 'val' } } } } } };
  assert.throws(
    () => validateProposalMetadata(depth6),
    (err: unknown) => err instanceof ValidationError && err.message.includes('maximum nesting depth of 5')
  );

  // 5. Exact boundary: string length 4096 passes, 4097 throws
  assert.doesNotThrow(() => validateProposalMetadata({ s: 'x'.repeat(4096) }));
  assert.throws(
    () => validateProposalMetadata({ s: 'x'.repeat(4097) }),
    (err: unknown) => err instanceof ValidationError && err.message.includes('4097 > 4096')
  );

  // 6. Object key length > 4096 throws
  const longKeyObj: Record<string, string> = {};
  longKeyObj['k'.repeat(4097)] = 'val';
  assert.throws(
    () => validateProposalMetadata(longKeyObj),
    (err: unknown) => err instanceof ValidationError && err.message.includes('exceeds maximum limit of 4096 characters')
  );

  // 7. Exact boundary: array length 100 passes, 101 throws
  assert.doesNotThrow(() => validateProposalMetadata({ arr: Array.from({ length: 100 }, (_, i) => i) }));
  assert.throws(
    () => validateProposalMetadata({ arr: Array.from({ length: 101 }, (_, i) => i) }),
    (err: unknown) => err instanceof ValidationError && err.message.includes('101 > 100')
  );

  // 8. DAG (shared reference across separate branches) is allowed and does not falsely trigger cycle error
  const sharedLeaf = { leaf: 'valid' };
  const dag = { branchA: sharedLeaf, branchB: sharedLeaf };
  assert.doesNotThrow(() => validateProposalMetadata(dag));

  // 9. Object with throwing getter safely produces ValidationError without crashing
  const badObject = {};
  Object.defineProperty(badObject, 'explosiveProp', {
    get() {
      throw new Error('Getter failed intentionally');
    },
    enumerable: true
  });
  assert.throws(
    () => validateProposalMetadata(badObject),
    (err: unknown) => err instanceof ValidationError && err.message.includes('unreadable properties')
  );

  // 10. validateSerializedMetadataSize boundary: <= 16384 bytes passes, > 16384 bytes throws
  // Empty object is 2 bytes "{}"
  assert.doesNotThrow(() => validateSerializedMetadataSize({}));
  // String of length that serialized is exactly 16384 bytes:
  // {"k":""} -> 8 bytes boilerplate + 16376 chars = 16384 bytes
  const exact16KiB = { k: 'y'.repeat(16376) };
  assert.equal(Buffer.byteLength(JSON.stringify(exact16KiB), 'utf8'), 16384);
  assert.doesNotThrow(() => validateSerializedMetadataSize(exact16KiB));

  const over16KiB = { k: 'y'.repeat(16377) };
  assert.equal(Buffer.byteLength(JSON.stringify(over16KiB), 'utf8'), 16385);
  assert.throws(
    () => validateSerializedMetadataSize(over16KiB),
    (err: unknown) => err instanceof ValidationError && err.message.includes('16385 > 16384')
  );

  // 11. Error message privacy guarantee:
  // Thrown error messages never contain raw property values or sensitive tokens
  try {
    validateProposalMetadata({ mySecret: 'TOP_SECRET_PROPRIETARY_DATA_XYZ_999' });
  } catch (err: any) {
    assert.equal(err.message.includes('TOP_SECRET_PROPRIETARY_DATA_XYZ_999'), false);
  }
});
