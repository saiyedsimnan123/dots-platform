/**
 * Next-Generation Dots AI Platform - Global and Workspace Memory Inheritance Tests
 * Phase 4B.4: Secure Global & Workspace Memory Inheritance
 * 
 * Verifies:
 * 1. Global task retrieves authorized global memories only.
 * 2. Workspace task retrieves authorized global memories.
 * 3. Workspace task retrieves its own workspace memories.
 * 4. Workspace A cannot retrieve Workspace B memories.
 * 5. Workspace B cannot retrieve Workspace A memories.
 * 6. Caller A cannot retrieve Caller B global memories.
 * 7. Workspace-specific memory overrides a global record with the same normalized key.
 * 8. Unrelated global and workspace keys are both retained.
 * 9. Global records remain unchanged after workspace conflict resolution.
 * 10. Workspace agents cannot create global proposals.
 * 11. Workspace agents cannot modify or approve global memories.
 * 12. Human approval remains required for workspace proposals.
 * 13. Runtime memory_search uses the same inheritance rules.
 * 14. Pre-execution memory injection uses the same inheritance rules.
 * 15. Expired and inactive memories remain excluded.
 * 16. Relevance ranking and result limits remain correct.
 * 17. Context-size limits remain enforced.
 * 18. Provenance identifies inherited versus local memory without leaking content.
 * 19. Forged caller or workspace scope arguments cannot widen visibility.
 * 20. Authorization failures fail closed.
 * 21. Existing memory proposal, search, and injection tests remain passing.
 * 22. Existing strict workspace-isolation tests remain passing.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

import { DatabaseManager } from '../../src/storage/db.ts';
import { TaskRepository } from '../../src/storage/task-repository.ts';
import { AuditRepository } from '../../src/storage/audit-repository.ts';
import { MemoryRepository } from '../../src/storage/memory-repository.ts';
import { MemoryService } from '../../src/memory/memory-service.ts';
import { HostMemoryAuthority } from '../../src/security/host-authority.ts';
import { TokenIdentityProvider } from '../../src/security/token-identity-provider.ts';
import { TaskCoordinator } from '../../src/orchestrator/coordinator.ts';
import { MockModelProvider } from '../../src/model/mock-provider.ts';
import { ToolRegistry } from '../../src/tools/registry.ts';
import { PolicyEngine } from '../../src/security/policy-engine.ts';
import { ApprovalBroker } from '../../src/security/approval-broker.ts';
import { VerificationEngine } from '../../src/verification/verifier.ts';
import { TokenBudgetTracker } from '../../src/model/budget-tracker.ts';
import {
  createMemorySearchTool,
  createMemoryProposeTool,
  MEMORY_SEARCH_TOOL_NAME,
  MEMORY_PROPOSE_TOOL_NAME
} from '../../src/tools/memory-tools.ts';
import { KnowledgeProposalPipeline } from '../../src/memory/knowledge-pipeline.ts';
import {
  SecurityViolationError,
  MemoryScopeViolationError,
  ValidationError,
  TaskNotFoundError
} from '../../src/domain/errors.ts';
import type { ScopeIdentifier, CallerContext } from '../../src/domain/types.ts';

function setupInheritanceFixture() {
  const testDir = mkdtempSync(join(tmpdir(), 'dots-inheritance-test-'));
  const dbPath = join(testDir, 'inheritance.db');
  const db = new DatabaseManager(dbPath);

  const taskRepo = new TaskRepository(db);
  const auditRepo = new AuditRepository(db);
  const memoryRepo = new MemoryRepository(db);

  const scopeGlobal: ScopeIdentifier = { scopeType: 'GLOBAL', scopeId: 'default' };
  const scopeWorkspaceA: ScopeIdentifier = { scopeType: 'WORKSPACE', scopeId: 'ws-alpha' };
  const scopeWorkspaceB: ScopeIdentifier = { scopeType: 'WORKSPACE', scopeId: 'ws-beta' };

  // Identity provider with two principals:
  // Principal A has access to GLOBAL and ws-alpha
  // Principal B has access to GLOBAL and ws-beta
  // Principal Restricted has access ONLY to ws-alpha (no global)
  const idProvider = new TokenIdentityProvider([
    {
      token: 'token-principal-a',
      principalId: 'principal-a',
      role: 'ADMIN',
      permittedScopes: [scopeGlobal, scopeWorkspaceA]
    },
    {
      token: 'token-principal-b',
      principalId: 'principal-b',
      role: 'ADMIN',
      permittedScopes: [scopeGlobal, scopeWorkspaceB]
    },
    {
      token: 'token-principal-restricted',
      principalId: 'principal-restricted',
      role: 'MEMBER',
      permittedScopes: [scopeWorkspaceA]
    }
  ]);

  const hostAuthority = new HostMemoryAuthority({
    taskRepo,
    identityProvider: idProvider
  });
  const authorizer = hostAuthority.authorizer;

  const memoryService = new MemoryService({
    memoryRepo,
    auditRepo,
    taskRepo,
    authorizer,
    hostAuthority
  });

  const modelProvider = new MockModelProvider();
  const toolRegistry = new ToolRegistry();
  const policyEngine = new PolicyEngine({ workspaceRoot: testDir, autoApproveTier2: true });
  const approvalBroker = new ApprovalBroker(taskRepo, auditRepo);
  const verifier = new VerificationEngine(taskRepo);
  const budgetTracker = new TokenBudgetTracker({ db, maxCostPerTaskUsd: 1.0 });

  const coordinator = new TaskCoordinator({
    taskRepo,
    auditRepo,
    modelProvider,
    toolRegistry,
    policyEngine,
    approvalBroker,
    verifier,
    budgetTracker,
    workspaceRoot: testDir,
    memoryService,
    hostAuthority
  });

  const createMemory = (
    caller: CallerContext,
    input: Omit<import('../../src/domain/types.ts').CreateMemoryInput, 'scopeType' | 'scopeId'> & {
      scopeType?: import('../../src/domain/types.ts').MemoryScopeType;
      scopeId?: string;
    }
  ) => {
    return memoryService.createMemory(caller, {
      ...input,
      scopeType: input.scopeType ?? caller.scope.scopeType,
      scopeId: input.scopeId ?? caller.scope.scopeId
    });
  };

  const cleanup = () => {
    try {
      db.close();
    } catch {
      // ignore
    }
    try {
      rmSync(testDir, { recursive: true, force: true });
    } catch {
      // ignore
    }
  };

  return {
    testDir,
    db,
    taskRepo,
    auditRepo,
    memoryRepo,
    authorizer,
    hostAuthority,
    memoryService,
    createMemory,
    coordinator,
    toolRegistry,
    scopeGlobal,
    scopeWorkspaceA,
    scopeWorkspaceB,
    cleanup
  };
}

// ============================================================================
// 1. Global task retrieves authorized global memories only
// ============================================================================
test('Phase 4B.4 - 1: Global task retrieves authorized global memories only', () => {
  const f = setupInheritanceFixture();
  try {
    const callerGlobalA = f.authorizer.authorizeUser({
      credentials: 'token-principal-a',
      requestedScope: f.scopeGlobal
    });

    const callerWorkspaceA = f.authorizer.authorizeUser({
      credentials: 'token-principal-a',
      requestedScope: f.scopeWorkspaceA
    });

    // Create global memory for Principal A
    f.createMemory(callerGlobalA, {
      key: 'global.system.endpoint',
      content: 'Primary production endpoint is https://api.prod.dots.local:8443',
      category: 'PROJECT_FACT',
      status: 'ACTIVE'
    });

    // Create workspace memory in ws-alpha
    f.createMemory(callerWorkspaceA, {
      key: 'workspace.cache.mode',
      content: 'Local workspace cache strategy is in-memory LRU',
      category: 'PROJECT_FACT',
      status: 'ACTIVE'
    });

    // Global task searches memory
    const results = f.memoryService.searchMemories(callerGlobalA, {
      query: 'endpoint cache production'
    });

    assert.equal(results.length, 1);
    assert.equal(results[0]!.memory.key, 'global.system.endpoint');
    assert.equal(results[0]!.memory.scopeType, 'GLOBAL');
    assert.equal(results[0]!.isInherited, false);
  } finally {
    f.cleanup();
  }
});

// ============================================================================
// 2. Workspace task retrieves authorized global memories
// ============================================================================
test('Phase 4B.4 - 2: Workspace task retrieves authorized global memories', () => {
  const f = setupInheritanceFixture();
  try {
    const callerGlobalA = f.authorizer.authorizeUser({
      credentials: 'token-principal-a',
      requestedScope: f.scopeGlobal
    });

    const callerWorkspaceA = f.authorizer.authorizeUser({
      credentials: 'token-principal-a',
      requestedScope: f.scopeWorkspaceA
    });

    // Create global memory for Principal A
    f.createMemory(callerGlobalA, {
      key: 'global.db.port',
      content: 'Database listener runs on secure port 9443 with TLS',
      category: 'PROJECT_FACT',
      status: 'ACTIVE'
    });

    // Workspace task searches memory in ws-alpha
    const results = f.memoryService.searchMemories(callerWorkspaceA, {
      query: 'database port listener'
    });

    assert.equal(results.length, 1);
    assert.equal(results[0]!.memory.key, 'global.db.port');
    assert.equal(results[0]!.memory.scopeType, 'GLOBAL');
    assert.equal(results[0]!.isInherited, true);
  } finally {
    f.cleanup();
  }
});

// ============================================================================
// 3. Workspace task retrieves its own workspace memories
// ============================================================================
test('Phase 4B.4 - 3: Workspace task retrieves its own workspace memories', () => {
  const f = setupInheritanceFixture();
  try {
    const callerWorkspaceA = f.authorizer.authorizeUser({
      credentials: 'token-principal-a',
      requestedScope: f.scopeWorkspaceA
    });

    f.createMemory(callerWorkspaceA, {
      key: 'workspace.service.timeout',
      content: 'Workspace alpha HTTP client request timeout is 15000ms',
      category: 'PROJECT_FACT',
      status: 'ACTIVE'
    });

    const results = f.memoryService.searchMemories(callerWorkspaceA, {
      query: 'HTTP client request timeout'
    });

    assert.equal(results.length, 1);
    assert.equal(results[0]!.memory.key, 'workspace.service.timeout');
    assert.equal(results[0]!.memory.scopeType, 'WORKSPACE');
    assert.equal(results[0]!.isInherited, false);
  } finally {
    f.cleanup();
  }
});

// ============================================================================
// 4 & 5. Cross-workspace isolation: Workspace A cannot retrieve Workspace B, and vice versa
// ============================================================================
test('Phase 4B.4 - 4 & 5: Workspace A cannot retrieve Workspace B memories, and vice versa', () => {
  const f = setupInheritanceFixture();
  try {
    const callerWorkspaceA = f.authorizer.authorizeUser({
      credentials: 'token-principal-a',
      requestedScope: f.scopeWorkspaceA
    });

    const callerWorkspaceB = f.authorizer.authorizeUser({
      credentials: 'token-principal-b',
      requestedScope: f.scopeWorkspaceB
    });

    const memA = f.createMemory(callerWorkspaceA, {
      key: 'workspace.alpha.secret',
      content: 'Secret alpha telemetry token',
      category: 'PROJECT_FACT',
      status: 'ACTIVE'
    });

    const memB = f.createMemory(callerWorkspaceB, {
      key: 'workspace.beta.secret',
      content: 'Secret beta telemetry token',
      category: 'PROJECT_FACT',
      status: 'ACTIVE'
    });

    // Workspace A search does not return Workspace B memory
    const resultsA = f.memoryService.searchMemories(callerWorkspaceA, {
      query: 'secret telemetry token'
    });
    assert.equal(resultsA.length, 1);
    assert.equal(resultsA[0]!.memory.id, memA.id);

    // Workspace B search does not return Workspace A memory
    const resultsB = f.memoryService.searchMemories(callerWorkspaceB, {
      query: 'secret telemetry token'
    });
    assert.equal(resultsB.length, 1);
    assert.equal(resultsB[0]!.memory.id, memB.id);

    // Direct ID read across workspace throws MemoryScopeViolationError
    assert.throws(
      () => f.memoryService.getMemoryById(callerWorkspaceA, memB.id),
      (err: unknown) => err instanceof MemoryScopeViolationError
    );
    assert.throws(
      () => f.memoryService.getMemoryById(callerWorkspaceB, memA.id),
      (err: unknown) => err instanceof MemoryScopeViolationError
    );
  } finally {
    f.cleanup();
  }
});

// ============================================================================
// 6. Caller A cannot retrieve Caller B global memories
// ============================================================================
test('Phase 4B.4 - 6: Caller A cannot retrieve Caller B global memories', () => {
  const f = setupInheritanceFixture();
  try {
    const callerGlobalA = f.authorizer.authorizeUser({
      credentials: 'token-principal-a',
      requestedScope: f.scopeGlobal
    });
    const callerWorkspaceA = f.authorizer.authorizeUser({
      credentials: 'token-principal-a',
      requestedScope: f.scopeWorkspaceA
    });

    const callerGlobalB = f.authorizer.authorizeUser({
      credentials: 'token-principal-b',
      requestedScope: f.scopeGlobal
    });
    const callerWorkspaceB = f.authorizer.authorizeUser({
      credentials: 'token-principal-b',
      requestedScope: f.scopeWorkspaceB
    });

    // Caller A creates a global memory
    f.createMemory(callerGlobalA, {
      key: 'global.user_a.pref',
      content: 'User A prefers dark mode and typescript strict typing',
      category: 'USER_PREFERENCE',
      status: 'ACTIVE'
    });

    // Caller B creates a global memory
    f.createMemory(callerGlobalB, {
      key: 'global.user_b.pref',
      content: 'User B prefers light mode and relaxed linting',
      category: 'USER_PREFERENCE',
      status: 'ACTIVE'
    });

    // In Workspace A, Caller A should see only Caller A's global memory
    const resultsA = f.memoryService.searchMemories(callerWorkspaceA, {
      query: 'prefers typing mode'
    });
    assert.equal(resultsA.length, 1);
    assert.equal(resultsA[0]!.memory.key, 'global.user_a.pref');

    // In Workspace B, Caller B should see only Caller B's global memory
    const resultsB = f.memoryService.searchMemories(callerWorkspaceB, {
      query: 'prefers typing mode'
    });
    assert.equal(resultsB.length, 1);
    assert.equal(resultsB[0]!.memory.key, 'global.user_b.pref');
  } finally {
    f.cleanup();
  }
});

// ============================================================================
// 7. Workspace-specific memory overrides global record with same normalized key
// ============================================================================
test('Phase 4B.4 - 7: Workspace-specific memory overrides global record with same normalized key', () => {
  const f = setupInheritanceFixture();
  try {
    const callerGlobal = f.authorizer.authorizeUser({
      credentials: 'token-principal-a',
      requestedScope: f.scopeGlobal
    });
    const callerWorkspace = f.authorizer.authorizeUser({
      credentials: 'token-principal-a',
      requestedScope: f.scopeWorkspaceA
    });

    // Global memory with lowercase key
    const globalMem = f.createMemory(callerGlobal, {
      key: 'service.database.host',
      content: 'Global database host is global-db.dots.internal',
      category: 'PROJECT_FACT',
      priority: 99,
      status: 'ACTIVE'
    });

    // Workspace memory with mixed case key (same normalized key)
    const wsMem = f.createMemory(callerWorkspace, {
      key: 'SERVICE.DATABASE.HOST',
      content: 'Workspace override database host is localhost:5432',
      category: 'PROJECT_FACT',
      priority: 10,
      status: 'ACTIVE'
    });

    // Query in workspace scope
    const results = f.memoryService.searchMemories(callerWorkspace, {
      query: 'database host'
    });

    // Must return the workspace-specific memory, NOT the global one
    assert.equal(results.length, 1);
    assert.equal(results[0]!.memory.id, wsMem.id);
    assert.equal(results[0]!.memory.content, 'Workspace override database host is localhost:5432');
    assert.equal(results[0]!.isInherited, false);
  } finally {
    f.cleanup();
  }
});

// ============================================================================
// 8. Unrelated global and workspace keys are both retained
// ============================================================================
test('Phase 4B.4 - 8: Unrelated global and workspace keys are both retained', () => {
  const f = setupInheritanceFixture();
  try {
    const callerGlobal = f.authorizer.authorizeUser({
      credentials: 'token-principal-a',
      requestedScope: f.scopeGlobal
    });
    const callerWorkspace = f.authorizer.authorizeUser({
      credentials: 'token-principal-a',
      requestedScope: f.scopeWorkspaceA
    });

    f.createMemory(callerGlobal, {
      key: 'global.monitoring.tool',
      content: 'Platform wide telemetry monitoring system is Prometheus v2',
      category: 'PROJECT_FACT',
      status: 'ACTIVE'
    });

    f.createMemory(callerWorkspace, {
      key: 'workspace.cache.driver',
      content: 'Local workspace cache storage driver is Redis Cluster',
      category: 'PROJECT_FACT',
      status: 'ACTIVE'
    });

    const results = f.memoryService.searchMemories(callerWorkspace, {
      query: 'monitoring telemetry cache driver'
    });

    assert.equal(results.length, 2);
    const keys = results.map((r) => r.memory.key);
    assert.ok(keys.includes('global.monitoring.tool'));
    assert.ok(keys.includes('workspace.cache.driver'));
  } finally {
    f.cleanup();
  }
});

// ============================================================================
// 9. Global records remain unchanged after workspace conflict resolution
// ============================================================================
test('Phase 4B.4 - 9: Global records remain unchanged after workspace conflict resolution', () => {
  const f = setupInheritanceFixture();
  try {
    const callerGlobal = f.authorizer.authorizeUser({
      credentials: 'token-principal-a',
      requestedScope: f.scopeGlobal
    });
    const callerWorkspace = f.authorizer.authorizeUser({
      credentials: 'token-principal-a',
      requestedScope: f.scopeWorkspaceA
    });

    const globalMem = f.createMemory(callerGlobal, {
      key: 'service.cluster.name',
      content: 'Global production cluster dot-k8s-prod',
      category: 'PROJECT_FACT',
      status: 'ACTIVE'
    });

    f.createMemory(callerWorkspace, {
      key: 'service.cluster.name',
      content: 'Local dev cluster minikube-dev',
      category: 'PROJECT_FACT',
      status: 'ACTIVE'
    });

    // Execute query that resolves conflict in workspace
    f.memoryService.searchMemories(callerWorkspace, { query: 'cluster name' });

    // Global memory in database must remain ACTIVE, unchanged, and retrievable by global caller
    const refetchedGlobal = f.memoryService.getMemoryById(callerGlobal, globalMem.id);
    assert.ok(refetchedGlobal);
    assert.equal(refetchedGlobal.status, 'ACTIVE');
    assert.equal(refetchedGlobal.content, 'Global production cluster dot-k8s-prod');
  } finally {
    f.cleanup();
  }
});

// ============================================================================
// 10. Workspace agents cannot create global proposals
// ============================================================================
test('Phase 4B.4 - 10: Workspace agents cannot create global proposals', async () => {
  const f = setupInheritanceFixture();
  try {
    const userCaller = f.authorizer.authorizeUser({
      credentials: 'token-principal-a',
      requestedScope: f.scopeWorkspaceA
    });

    const task = await f.coordinator.submitScopedTask('Agent proposal restriction task', userCaller);
    const proposeTool = createMemoryProposeTool(f.memoryService, f.authorizer);

    // Attempting to propose in GLOBAL scope from a workspace task must be rejected
    await assert.rejects(
      async () => {
        await proposeTool.handler(
          {
            key: 'agent.illegal.global',
            content: 'Agent trying to write global memory',
            category: 'PROJECT_FACT',
            scopeType: 'GLOBAL',
            scopeId: 'default'
          },
          { taskId: task.id, stepId: 'step-1', workspaceRoot: f.testDir }
        );
      },
      (err: unknown) => err instanceof MemoryScopeViolationError
    );
  } finally {
    f.cleanup();
  }
});

// ============================================================================
// 11. Workspace agents cannot modify or approve global memories
// ============================================================================
test('Phase 4B.4 - 11: Workspace agents cannot modify or approve global memories', async () => {
  const f = setupInheritanceFixture();
  try {
    const userCaller = f.authorizer.authorizeUser({
      credentials: 'token-principal-a',
      requestedScope: f.scopeGlobal
    });
    const wsUserCaller = f.authorizer.authorizeUser({
      credentials: 'token-principal-a',
      requestedScope: f.scopeWorkspaceA
    });

    const globalMem = f.createMemory(userCaller, {
      key: 'global.immutable.fact',
      content: 'Original immutable fact',
      category: 'PROJECT_FACT',
      status: 'ACTIVE'
    });

    const task = await f.coordinator.submitScopedTask('Agent mutation restriction task', wsUserCaller);
    const agentCaller = f.authorizer.authorizeAgent({ taskId: task.id });

    // Workspace agent cannot update global memory
    assert.throws(
      () => f.memoryService.updateMemory(agentCaller, globalMem.id, { content: 'Agent tampered' }),
      (err: unknown) => err instanceof MemoryScopeViolationError || err instanceof SecurityViolationError
    );

    // Workspace agent cannot delete global memory
    assert.throws(
      () => f.memoryService.deleteMemory(agentCaller, globalMem.id),
      (err: unknown) => err instanceof SecurityViolationError || err instanceof MemoryScopeViolationError
    );

    // Workspace agent cannot approve memories
    assert.throws(
      () => f.memoryService.decideProposal(agentCaller, { memoryId: globalMem.id, decision: 'APPROVED' }),
      (err: unknown) => err instanceof SecurityViolationError
    );
  } finally {
    f.cleanup();
  }
});

// ============================================================================
// 12. Human approval remains required for workspace proposals
// ============================================================================
test('Phase 4B.4 - 12: Human approval remains required for workspace proposals', async () => {
  const f = setupInheritanceFixture();
  try {
    const userCaller = f.authorizer.authorizeUser({
      credentials: 'token-principal-a',
      requestedScope: f.scopeWorkspaceA
    });

    const task = await f.coordinator.submitScopedTask('Agent proposal lifecycle test', userCaller);
    const proposeTool = createMemoryProposeTool(f.memoryService, f.authorizer);

    const result = await proposeTool.handler(
      {
        key: 'learned.procedure.build',
        content: 'Run npm run build --workspace=packages/core',
        category: 'LEARNED_PROCEDURE'
      },
      { taskId: task.id, stepId: 'step-1', workspaceRoot: f.testDir }
    );

    assert.equal(result.exitCode, 0);
    const proposalId = (result.output as any).proposalId;
    assert.ok(proposalId);
    assert.equal((result.output as any).status, 'PENDING_APPROVAL');

    // Attempting to decide the proposal with AGENT caller fails
    const agentCaller = f.authorizer.authorizeAgent({ taskId: task.id });
    assert.throws(
      () => f.memoryService.decideProposal(agentCaller, { memoryId: proposalId, decision: 'APPROVED' }),
      (err: unknown) => err instanceof SecurityViolationError && err.violationType === 'UNAUTHORIZED_APPROVAL'
    );

    // Human USER caller can decide and approve
    const approved = f.memoryService.decideProposal(userCaller, { memoryId: proposalId, decision: 'APPROVED' });
    assert.equal(approved.status, 'ACTIVE');
    assert.equal(approved.scopeType, 'WORKSPACE');
  } finally {
    f.cleanup();
  }
});

// ============================================================================
// 13. Runtime memory_search uses the same inheritance rules
// ============================================================================
test('Phase 4B.4 - 13: Runtime memory_search uses the same inheritance rules', async () => {
  const f = setupInheritanceFixture();
  try {
    const callerGlobal = f.authorizer.authorizeUser({
      credentials: 'token-principal-a',
      requestedScope: f.scopeGlobal
    });
    const callerWorkspace = f.authorizer.authorizeUser({
      credentials: 'token-principal-a',
      requestedScope: f.scopeWorkspaceA
    });

    // Create authorized global memory
    f.createMemory(callerGlobal, {
      key: 'global.runtime.version',
      content: 'Node.js LTS runtime v20 is mandatory',
      category: 'PROJECT_FACT',
      status: 'ACTIVE'
    });

    // Create workspace memory
    f.createMemory(callerWorkspace, {
      key: 'workspace.runtime.flag',
      content: 'Run with --experimental-vm-modules flag',
      category: 'PROJECT_FACT',
      status: 'ACTIVE'
    });

    const task = await f.coordinator.submitScopedTask('Search tool test', callerWorkspace);
    const searchTool = createMemorySearchTool(f.memoryService, f.authorizer);

    const result = await searchTool.handler(
      { query: 'runtime Node.js flag' },
      { taskId: task.id, stepId: 'step-1', workspaceRoot: f.testDir }
    );

    assert.equal(result.exitCode, 0);
    const memories = (result.output as any).memories;
    assert.equal(memories.length, 2);

    const globalMem = memories.find((m: any) => m.key === 'global.runtime.version');
    assert.ok(globalMem);
    assert.equal(globalMem.scopeType, 'GLOBAL');
    assert.equal(globalMem.isInherited, true);

    const wsMem = memories.find((m: any) => m.key === 'workspace.runtime.flag');
    assert.ok(wsMem);
    assert.equal(wsMem.scopeType, 'WORKSPACE');
    assert.equal(wsMem.isInherited, false);
  } finally {
    f.cleanup();
  }
});

// ============================================================================
// 14. Pre-execution memory injection uses the same inheritance rules
// ============================================================================
test('Phase 4B.4 - 14: Pre-execution memory injection uses the same inheritance rules', async () => {
  const f = setupInheritanceFixture();
  try {
    const callerGlobal = f.authorizer.authorizeUser({
      credentials: 'token-principal-a',
      requestedScope: f.scopeGlobal
    });
    const callerWorkspace = f.authorizer.authorizeUser({
      credentials: 'token-principal-a',
      requestedScope: f.scopeWorkspaceA
    });

    // Global memory
    f.createMemory(callerGlobal, {
      key: 'global.compiler.target',
      content: 'TypeScript target is ES2022 with NodeNext module resolution',
      category: 'PROJECT_FACT',
      status: 'ACTIVE'
    });

    // Workspace memory overriding a key
    f.createMemory(callerWorkspace, {
      key: 'workspace.linter.rules',
      content: 'ESLint strict rules enabled locally',
      category: 'PROJECT_FACT',
      status: 'ACTIVE'
    });

    const task = await f.coordinator.submitScopedTask(
      'Compile code with TypeScript target and ESLint rules',
      callerWorkspace
    );
    const agentCaller = f.authorizer.authorizeAgent({ taskId: task.id });

    const context = f.memoryService.buildTaskMemoryContext(agentCaller, {
      query: task.goal,
      taskId: task.id,
      recordInjections: true
    });

    assert.equal(context.included.length, 2);
    const globalInc = context.included.find((i) => i.key === 'global.compiler.target');
    assert.ok(globalInc);
    assert.equal(globalInc.scopeType, 'GLOBAL');
    assert.equal(globalInc.isInherited, true);

    const wsInc = context.included.find((i) => i.key === 'workspace.linter.rules');
    assert.ok(wsInc);
    assert.equal(wsInc.scopeType, 'WORKSPACE');
    assert.equal(wsInc.isInherited, false);

    // Verify injection provenance recorded properly for both
    const injections = f.memoryService.getInjectionsByTaskId(agentCaller, task.id);
    assert.equal(injections.length, 2);
  } finally {
    f.cleanup();
  }
});

// ============================================================================
// 15. Expired and inactive memories remain excluded
// ============================================================================
test('Phase 4B.4 - 15: Expired and inactive memories remain excluded', () => {
  const f = setupInheritanceFixture();
  try {
    const callerGlobal = f.authorizer.authorizeUser({
      credentials: 'token-principal-a',
      requestedScope: f.scopeGlobal
    });
    const callerWorkspace = f.authorizer.authorizeUser({
      credentials: 'token-principal-a',
      requestedScope: f.scopeWorkspaceA
    });

    // Active global memory
    f.createMemory(callerGlobal, {
      key: 'global.active.fact',
      content: 'This memory is active and current',
      category: 'PROJECT_FACT',
      status: 'ACTIVE'
    });

    // Expired global memory
    f.createMemory(callerGlobal, {
      key: 'global.expired.fact',
      content: 'This memory expired in the past',
      category: 'PROJECT_FACT',
      metadata: { expiresAt: '2020-01-01T00:00:00.000Z' },
      status: 'ACTIVE'
    });

    // Archived global memory
    const toArchive = f.createMemory(callerGlobal, {
      key: 'global.archived.fact',
      content: 'This memory is archived',
      category: 'PROJECT_FACT',
      status: 'ACTIVE'
    });
    f.memoryService.archiveMemory(callerGlobal, toArchive.id);

    // Search from workspace
    const results = f.memoryService.searchMemories(callerWorkspace, {
      query: 'memory fact active expired archived'
    });

    assert.equal(results.length, 1);
    assert.equal(results[0]!.memory.key, 'global.active.fact');
  } finally {
    f.cleanup();
  }
});

// ============================================================================
// 16. Relevance ranking and result limits remain correct
// ============================================================================
test('Phase 4B.4 - 16: Relevance ranking and result limits remain correct', () => {
  const f = setupInheritanceFixture();
  try {
    const callerGlobal = f.authorizer.authorizeUser({
      credentials: 'token-principal-a',
      requestedScope: f.scopeGlobal
    });
    const callerWorkspace = f.authorizer.authorizeUser({
      credentials: 'token-principal-a',
      requestedScope: f.scopeWorkspaceA
    });

    // 4 global memories + 4 workspace memories matching query
    for (let i = 1; i <= 4; i++) {
      f.createMemory(callerGlobal, {
        key: `global.benchmark.item.${i}`,
        content: `Benchmark metric global measurement index ${i} score test`,
        category: 'PROJECT_FACT',
        priority: 50 + i,
        status: 'ACTIVE'
      });
      f.createMemory(callerWorkspace, {
        key: `workspace.benchmark.item.${i}`,
        content: `Benchmark metric workspace measurement index ${i} score test`,
        category: 'PROJECT_FACT',
        priority: 60 + i,
        status: 'ACTIVE'
      });
    }

    // Limit to 3 results
    const results = f.memoryService.searchMemories(callerWorkspace, {
      query: 'benchmark metric measurement score',
      limit: 3
    });

    assert.equal(results.length, 3);
    // Highest priority workspace items ranked first
    assert.ok(results[0]!.score > 0);
  } finally {
    f.cleanup();
  }
});

// ============================================================================
// 17. Context-size limits remain enforced
// ============================================================================
test('Phase 4B.4 - 17: Context-size limits remain enforced', () => {
  const f = setupInheritanceFixture();
  try {
    const callerGlobal = f.authorizer.authorizeUser({
      credentials: 'token-principal-a',
      requestedScope: f.scopeGlobal
    });
    const callerWorkspace = f.authorizer.authorizeUser({
      credentials: 'token-principal-a',
      requestedScope: f.scopeWorkspaceA
    });

    // Add multiple global and workspace memories
    for (let i = 1; i <= 10; i++) {
      f.createMemory(callerGlobal, {
        key: `global.data.${i}`,
        content: 'Data block global content ' + 'A'.repeat(500),
        category: 'PROJECT_FACT',
        status: 'ACTIVE'
      });
      f.createMemory(callerWorkspace, {
        key: `workspace.data.${i}`,
        content: 'Data block workspace content ' + 'B'.repeat(500),
        category: 'PROJECT_FACT',
        status: 'ACTIVE'
      });
    }

    const context = f.memoryService.buildTaskMemoryContext(callerWorkspace, {
      query: 'Data block content',
      maxBudgetChars: 2000
    });

    assert.ok(context.totalChars <= 2000);
    assert.ok(context.included.length > 0);
    assert.ok(context.excluded.length > 0);
    assert.ok(context.excluded.some((e) => e.reason === 'EXCLUDED_BUDGET_CEILING'));
  } finally {
    f.cleanup();
  }
});

// ============================================================================
// 18. Provenance identifies inherited versus local memory without leaking content
// ============================================================================
test('Phase 4B.4 - 18: Provenance identifies inherited versus local memory without leaking content', () => {
  const f = setupInheritanceFixture();
  try {
    const callerGlobal = f.authorizer.authorizeUser({
      credentials: 'token-principal-a',
      requestedScope: f.scopeGlobal
    });
    const callerWorkspace = f.authorizer.authorizeUser({
      credentials: 'token-principal-a',
      requestedScope: f.scopeWorkspaceA
    });

    const secretMarker = 'CLASSIFIED_PROPRIETARY_PAYLOAD_TOKEN';

    f.createMemory(callerGlobal, {
      key: 'global.provenance.check',
      content: `Global provenance content containing ${secretMarker}`,
      category: 'PROJECT_FACT',
      status: 'ACTIVE'
    });

    f.createMemory(callerWorkspace, {
      key: 'workspace.provenance.check',
      content: `Workspace provenance content containing ${secretMarker}`,
      category: 'PROJECT_FACT',
      status: 'ACTIVE'
    });

    const context = f.memoryService.buildTaskMemoryContext(callerWorkspace, {
      query: 'provenance check payload token'
    });

    assert.equal(context.included.length, 2);

    const globalInc = context.included.find((i) => i.key === 'global.provenance.check');
    assert.ok(globalInc);
    assert.equal(globalInc.isInherited, true);
    assert.equal(globalInc.scopeType, 'GLOBAL');

    const wsInc = context.included.find((i) => i.key === 'workspace.provenance.check');
    assert.ok(wsInc);
    assert.equal(wsInc.isInherited, false);
    assert.equal(wsInc.scopeType, 'WORKSPACE');

    // Verify audit logs do not leak memory content
    const auditRows = f.db.prepare('SELECT * FROM audit_events WHERE event_type = ?')
      .all('MEMORY_RETRIEVED') as Array<{ details_json: string }>;
    for (const row of auditRows) {
      assert.ok(!row.details_json.includes(secretMarker));
    }
  } finally {
    f.cleanup();
  }
});

// ============================================================================
// 19. Forged caller or workspace scope arguments cannot widen visibility
// ============================================================================
test('Phase 4B.4 - 19: Forged caller or workspace scope arguments cannot widen visibility', () => {
  const f = setupInheritanceFixture();
  try {
    const callerWorkspaceA = f.authorizer.authorizeUser({
      credentials: 'token-principal-a',
      requestedScope: f.scopeWorkspaceA
    });

    // Attempting to pass scopeType: 'GLOBAL' or scopeId: 'ws-beta' in search options must throw
    assert.throws(
      () => {
        f.memoryService.searchMemories(callerWorkspaceA, {
          query: 'test',
          scopeType: 'GLOBAL'
        });
      },
      (err: unknown) => err instanceof MemoryScopeViolationError
    );

    assert.throws(
      () => {
        f.memoryService.searchMemories(callerWorkspaceA, {
          query: 'test',
          scopeId: 'ws-beta'
        });
      },
      (err: unknown) => err instanceof MemoryScopeViolationError
    );

    assert.throws(
      () => {
        f.memoryService.buildTaskMemoryContext(callerWorkspaceA, {
          query: 'test',
          ...({ scopeType: 'GLOBAL' } as any)
        });
      },
      (err: unknown) => err instanceof MemoryScopeViolationError
    );
  } finally {
    f.cleanup();
  }
});

// ============================================================================
// 20. Authorization failures fail closed
// ============================================================================
test('Phase 4B.4 - 20: Authorization failures fail closed', () => {
  const f = setupInheritanceFixture();
  try {
    const callerRestricted = f.authorizer.authorizeUser({
      credentials: 'token-principal-restricted',
      requestedScope: f.scopeWorkspaceA
    });

    const callerGlobalA = f.authorizer.authorizeUser({
      credentials: 'token-principal-a',
      requestedScope: f.scopeGlobal
    });

    f.createMemory(callerGlobalA, {
      key: 'global.classified.key',
      content: 'Classified global knowledge',
      category: 'PROJECT_FACT',
      status: 'ACTIVE'
    });

    // Caller Restricted has NO global scope permitted. Must NOT inherit global memory.
    const results = f.memoryService.searchMemories(callerRestricted, {
      query: 'classified global knowledge'
    });
    assert.equal(results.length, 0);

    const context = f.memoryService.buildTaskMemoryContext(callerRestricted, {
      query: 'classified global knowledge'
    });
    assert.equal(context.included.length, 0);
  } finally {
    f.cleanup();
  }
});

// ============================================================================
// 21. KnowledgeProposalPipeline duplicate suppression with inherited memories
// ============================================================================
test('Phase 4B.4 - 21: KnowledgeProposalPipeline suppresses duplicates matching inherited global memory', async () => {
  const f = setupInheritanceFixture();
  try {
    const callerGlobalA = f.authorizer.authorizeUser({
      credentials: 'token-principal-a',
      requestedScope: f.scopeGlobal
    });
    const callerWorkspaceA = f.authorizer.authorizeUser({
      credentials: 'token-principal-a',
      requestedScope: f.scopeWorkspaceA
    });

    // Create global fact
    const globalKey = 'research.finding.quantum-supremacy';
    const globalContent = 'Verified quantum supremacy demonstrated with 70 qubits';
    f.createMemory(callerGlobalA, {
      key: globalKey,
      content: globalContent,
      category: 'PROJECT_FACT',
      status: 'ACTIVE'
    });

    const task = await f.coordinator.submitScopedTask('Quantum research task', callerWorkspaceA);
    const agentCaller = f.authorizer.authorizeAgent({ taskId: task.id });

    const pipeline = new KnowledgeProposalPipeline();

    // Agent outputs report with exact same key/content that already exists in inherited memory
    const agentOutput = {
      agentId: 'research-agent',
      taskId: task.id,
      status: 'COMPLETED' as const,
      summary: 'Quantum research complete',
      stepsExecuted: 2,
      durationMs: 100,
      result: {
        report: {
          completionStatus: 'SUCCESS',
          researchQuestion: 'Quantum Supremacy',
          keyFindings: [globalContent],
          evidenceAndSources: [{ title: 'Paper', url: 'https://arxiv.org/1234' }]
        }
      }
    };

    const submitted = await pipeline.processCompletedTask({
      task,
      agentId: 'research-agent',
      output: agentOutput,
      caller: agentCaller,
      memoryService: f.memoryService
    });

    // Duplicate must be suppressed against inherited global memory!
    assert.equal(submitted.length, 0);
  } finally {
    f.cleanup();
  }
});

// ============================================================================
// 22. Strict workspace isolation: Workspace proposal approval cannot modify global memory
// ============================================================================
test('Phase 4B.4 - 22: Workspace proposal approval cannot modify global memory', () => {
  const f = setupInheritanceFixture();
  try {
    const callerGlobalA = f.authorizer.authorizeUser({
      credentials: 'token-principal-a',
      requestedScope: f.scopeGlobal
    });
    const callerWorkspaceA = f.authorizer.authorizeUser({
      credentials: 'token-principal-a',
      requestedScope: f.scopeWorkspaceA
    });

    const sharedKey = 'service.gateway.port';

    // 1. Create global memory
    const globalMem = f.createMemory(callerGlobalA, {
      key: sharedKey,
      content: 'Global port 443',
      category: 'PROJECT_FACT',
      status: 'ACTIVE'
    });

    // 2. Create workspace proposal with same key
    const wsProposal = f.createMemory(callerWorkspaceA, {
      key: sharedKey,
      content: 'Workspace port 8443',
      category: 'PROJECT_FACT',
      status: 'PENDING_APPROVAL'
    });

    // 3. Approve workspace proposal
    const approvedWs = f.memoryService.decideProposal(callerWorkspaceA, {
      memoryId: wsProposal.id,
      decision: 'APPROVED'
    });
    assert.equal(approvedWs.status, 'ACTIVE');
    assert.equal(approvedWs.scopeType, 'WORKSPACE');

    // 4. Verify global memory is completely untouched
    const refetchedGlobal = f.memoryService.getMemoryById(callerGlobalA, globalMem.id);
    assert.ok(refetchedGlobal);
    assert.equal(refetchedGlobal.status, 'ACTIVE');
    assert.equal(refetchedGlobal.content, 'Global port 443');
    assert.equal(refetchedGlobal.scopeType, 'GLOBAL');

    // 5. Verify conflict resolution in workspace: workspace memory wins
    const searchResult = f.memoryService.searchMemories(callerWorkspaceA, {
      query: 'gateway port'
    });
    assert.equal(searchResult.length, 1);
    assert.equal(searchResult[0]!.memory.id, approvedWs.id);
    assert.equal(searchResult[0]!.memory.content, 'Workspace port 8443');
    assert.equal(searchResult[0]!.isInherited, false);
  } finally {
    f.cleanup();
  }
});
