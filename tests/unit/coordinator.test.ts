/**
 * Next-Generation Dots AI Platform - Task Coordinator Unit Tests
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { resolve } from 'node:path';
import { existsSync, rmSync, mkdirSync } from 'node:fs';
import { DatabaseManager } from '../../src/storage/db.ts';
import { TaskRepository } from '../../src/storage/task-repository.ts';
import { AuditRepository } from '../../src/storage/audit-repository.ts';
import { MemoryRepository } from '../../src/storage/memory-repository.ts';
import { MemoryService } from '../../src/memory/memory-service.ts';
import { HostMemoryAuthority } from '../../src/security/host-authority.ts';
import {
  MemoryAuthorizer,
  type TrustedIdentityProvider,
  type AuthenticatedPrincipal
} from '../../src/security/memory-authorizer.ts';
import { MockModelProvider } from '../../src/model/mock-provider.ts';
import { ToolRegistry } from '../../src/tools/registry.ts';
import { PolicyEngine } from '../../src/security/policy-engine.ts';
import { ApprovalBroker } from '../../src/security/approval-broker.ts';
import { VerificationEngine } from '../../src/verification/verifier.ts';
import { TokenBudgetTracker } from '../../src/model/budget-tracker.ts';
import { TaskCoordinator } from '../../src/orchestrator/coordinator.ts';
import { ValidationError, SecurityViolationError } from '../../src/domain/errors.ts';
import type { CallerContext } from '../../src/domain/types.ts';

const testWorkspace = resolve('test_coord_workspace');

function createTestHarness(autoApproveTier2 = true) {
  if (existsSync(testWorkspace)) rmSync(testWorkspace, { recursive: true, force: true });
  mkdirSync(testWorkspace, { recursive: true });

  const db = new DatabaseManager(':memory:');
  const taskRepo = new TaskRepository(db);
  const auditRepo = new AuditRepository(db);
  const modelProvider = new MockModelProvider();
  const toolRegistry = new ToolRegistry();
  const policyEngine = new PolicyEngine({ workspaceRoot: testWorkspace, autoApproveTier2 });
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
    workspaceRoot: testWorkspace
  });

  return {
    db, taskRepo, auditRepo, modelProvider, toolRegistry,
    policyEngine, approvalBroker, verifier, budgetTracker, coordinator
  };
}

test('TaskCoordinator - runs end-to-end task from submission to completion', async () => {
  const harness = createTestHarness();

  try {
    // 1. Submit task
    const task = await harness.coordinator.submitTask('Compute math total');
    assert.equal(task.status, 'SUBMITTED');

    // 2. Enqueue model plan: 1 step calling calculate tool
    harness.modelProvider.enqueuePlan([
      {
        stepOrder: 1,
        description: 'Calculate sum',
        toolName: 'calculate',
        arguments: { expression: '100 + 250' },
        expectedOutcome: 'Math expression evaluated'
      }
    ]);

    // 3. Run to completion
    const completed = await harness.coordinator.runToCompletion(task.id);
    assert.equal(completed.status, 'COMPLETED');
    assert.ok(completed.completedAt !== null);

    // Verify step was verified
    const steps = harness.taskRepo.getStepsByTaskId(task.id);
    assert.equal(steps.length, 1);
    assert.equal(steps[0]!.status, 'VERIFIED');

    // Verify tool execution was logged
    const execs = harness.taskRepo.getToolExecutionsByStepId(steps[0]!.id);
    assert.equal(execs.length, 1);
    assert.equal(execs[0]!.exitCode, 0);
    const output = JSON.parse(execs[0]!.outputJson) as { result: number };
    assert.equal(output.result, 350);

    // Verify audit events
    const events = harness.auditRepo.getEventsByTaskId(task.id);
    const eventTypes = events.map((e) => e.eventType);
    assert.ok(eventTypes.includes('TASK_CREATED'));
    assert.ok(eventTypes.includes('PLAN_GENERATED'));
    assert.ok(eventTypes.includes('TOOL_EXECUTION_COMPLETED'));
    assert.ok(eventTypes.includes('EVIDENCE_VERIFIED'));
  } finally {
    harness.db.close();
    if (existsSync(testWorkspace)) rmSync(testWorkspace, { recursive: true, force: true });
  }
});

test('TaskCoordinator - pauses at AWAITING_APPROVAL for Tier 3 tool until user approval', async () => {
  const harness = createTestHarness();

  // Register Tier 3 tool
  harness.toolRegistry.register({
    definition: {
      name: 'network_deploy',
      description: 'Deploys service',
      parameters: { env: { type: 'string', description: 'target env' } }
    },
    riskTier: 'TIER_3',
    handler: async () => ({ output: { status: 'deployed' }, exitCode: 0, durationMs: 10 })
  });

  try {
    const task = await harness.coordinator.submitTask('Deploy service to prod');

    // Enqueue plan calling Tier 3 tool
    harness.modelProvider.enqueuePlan([
      {
        stepOrder: 1,
        description: 'Deploy to production',
        toolName: 'network_deploy',
        arguments: { env: 'production' },
        expectedOutcome: 'Service deployed'
      }
    ]);

    // Step 1: SUBMITTED -> PLANNING
    const s1 = await harness.coordinator.step(task.id);
    assert.equal(s1.status, 'PLANNING');

    // Step 2: PLANNING -> AWAITING_APPROVAL (policy detects Tier 3)
    const s2 = await harness.coordinator.step(task.id);
    assert.equal(s2.status, 'AWAITING_APPROVAL');

    // Verify runToCompletion halts while AWAITING_APPROVAL
    const paused = await harness.coordinator.runToCompletion(task.id, 5);
    assert.equal(paused.status, 'AWAITING_APPROVAL');

    // User submits approval
    const approvals = harness.taskRepo.getApprovalRequestsByTaskId(task.id);
    assert.equal(approvals.length, 1);
    harness.approvalBroker.submitDecision(approvals[0]!.approvalToken, 'APPROVED', 'lead-architect');

    // Resume execution
    const completed = await harness.coordinator.runToCompletion(task.id);
    assert.equal(completed.status, 'COMPLETED');
  } finally {
    harness.db.close();
    if (existsSync(testWorkspace)) rmSync(testWorkspace, { recursive: true, force: true });
  }
});

test('TaskCoordinator - handles bounded retries and fails cleanly when retry budget is exhausted', async () => {
  const harness = createTestHarness();

  // Register failing tool
  harness.toolRegistry.register({
    definition: {
      name: 'failing_tool',
      description: 'Always fails',
      parameters: {}
    },
    riskTier: 'TIER_1',
    handler: async () => {
      throw new Error('Unrecoverable hardware error');
    }
  });

  try {
    const task = await harness.coordinator.submitTask('Task with failing step');
    harness.modelProvider.enqueuePlan([
      {
        stepOrder: 1,
        description: 'Call doomed tool',
        toolName: 'failing_tool',
        arguments: {},
        expectedOutcome: 'Success'
      }
    ]);

    const finalTask = await harness.coordinator.runToCompletion(task.id, 20);
    assert.equal(finalTask.status, 'FAILED');
    assert.ok(finalTask.errorSummary?.includes('exhausted retry budget'));
  } finally {
    harness.db.close();
    if (existsSync(testWorkspace)) rmSync(testWorkspace, { recursive: true, force: true });
  }
});

// --- Phase 7.4 Substep 3: Coordinator Dependencies, Trusted Scope & Database Identity Tests ---

class MockIdentityProvider implements TrustedIdentityProvider {
  private readonly principals = new Map<string, AuthenticatedPrincipal>();

  public register(token: string, principal: AuthenticatedPrincipal): void {
    this.principals.set(token, principal);
  }

  public authenticate(credentials: unknown): AuthenticatedPrincipal | null {
    if (typeof credentials === 'string') {
      return this.principals.get(credentials) ?? null;
    }
    return null;
  }
}

function createMemoryCoordHarness(options: {
  db?: DatabaseManager;
  taskDb?: DatabaseManager;
  auditDb?: DatabaseManager;
  memoryDb?: DatabaseManager;
  idProvider?: TrustedIdentityProvider;
} = {}) {
  const sharedDb = options.db ?? new DatabaseManager(':memory:');
  const taskDb = options.taskDb ?? sharedDb;
  const auditDb = options.auditDb ?? sharedDb;
  const memoryDb = options.memoryDb ?? sharedDb;

  const taskRepo = new TaskRepository(taskDb);
  const auditRepo = new AuditRepository(auditDb);
  const memoryRepo = new MemoryRepository(memoryDb);
  const hostAuthority = new HostMemoryAuthority({
    taskRepo,
    identityProvider: options.idProvider
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
  const policyEngine = new PolicyEngine({ workspaceRoot: testWorkspace, autoApproveTier2: true });
  const approvalBroker = new ApprovalBroker(taskRepo, auditRepo);
  const verifier = new VerificationEngine(taskRepo);
  const budgetTracker = new TokenBudgetTracker({ db: sharedDb, maxCostPerTaskUsd: 1.0 });

  return {
    sharedDb,
    taskDb,
    auditDb,
    memoryDb,
    taskRepo,
    auditRepo,
    memoryRepo,
    hostAuthority,
    authorizer,
    memoryService,
    modelProvider,
    toolRegistry,
    policyEngine,
    approvalBroker,
    verifier,
    budgetTracker,
    createCoordinator: (overrideOptions = {}) => new TaskCoordinator({
      taskRepo,
      auditRepo,
      modelProvider,
      toolRegistry,
      policyEngine,
      approvalBroker,
      verifier,
      budgetTracker,
      workspaceRoot: testWorkspace,
      memoryService,
      hostAuthority,
      ...overrideOptions
    })
  };
}

test('TaskCoordinator - existing constructors and submitTask callers remain compatible', async () => {
  const harness = createTestHarness();

  try {
    // Legacy construction without memoryService or hostAuthority
    assert.equal(harness.coordinator.memoryService, undefined);
    assert.equal(harness.coordinator.authorizer, undefined);

    const task = await harness.coordinator.submitTask('Legacy task', { customSetting: 'active' });
    assert.equal(task.status, 'SUBMITTED');
    assert.equal(task.goal, 'Legacy task');

    // Scope verification on coordinator returns null for legacy task
    assert.equal(harness.coordinator.verifyTaskScope(task), null);

    const events = harness.auditRepo.getEventsByTaskId(task.id);
    assert.equal(events.length, 1);
    assert.equal(events[0]!.eventType, 'TASK_CREATED');
  } finally {
    harness.db.close();
    if (existsSync(testWorkspace)) rmSync(testWorkspace, { recursive: true, force: true });
  }
});

test('TaskCoordinator - shared database instance is accepted across taskRepo, auditRepo, and memoryService', () => {
  const harness = createMemoryCoordHarness();

  try {
    const coordinator = harness.createCoordinator();
    assert.equal(coordinator.memoryService, harness.memoryService);
    assert.equal(coordinator.authorizer, harness.authorizer);
    assert.ok(coordinator.promptCompiler);
  } finally {
    harness.sharedDb.close();
    if (existsSync(testWorkspace)) rmSync(testWorkspace, { recursive: true, force: true });
  }
});

test('TaskCoordinator - rejects mismatched task/audit database instances when memory integration is enabled', () => {
  const taskDb = new DatabaseManager(':memory:');
  const auditDb = new DatabaseManager(':memory:');
  const memoryDb = new DatabaseManager(':memory:');

  try {
    const taskRepo = new TaskRepository(taskDb);
    const auditRepo = new AuditRepository(auditDb);
    const memoryRepo = new MemoryRepository(memoryDb);
    const memoryService = new MemoryService({ memoryRepo });

    const modelProvider = new MockModelProvider();
    const toolRegistry = new ToolRegistry();
    const policyEngine = new PolicyEngine({ workspaceRoot: testWorkspace });
    const approvalBroker = new ApprovalBroker(taskRepo, auditRepo);
    const verifier = new VerificationEngine(taskRepo);
    const budgetTracker = new TokenBudgetTracker({ db: taskDb, maxCostPerTaskUsd: 1.0 });

    assert.throws(
      () => new TaskCoordinator({
        taskRepo,
        auditRepo,
        modelProvider,
        toolRegistry,
        policyEngine,
        approvalBroker,
        verifier,
        budgetTracker,
        workspaceRoot: testWorkspace,
        memoryService
      }),
      (err: unknown) => {
        assert.ok(err instanceof ValidationError);
        assert.match(err.message, /TaskRepository and AuditRepository must share the exact same DatabaseManager instance/);
        return true;
      }
    );
  } finally {
    taskDb.close();
    auditDb.close();
    memoryDb.close();
  }
});

test('TaskCoordinator - rejects mismatched memory-service database instance', () => {
  const sharedDb = new DatabaseManager(':memory:');
  const separateMemoryDb = new DatabaseManager(':memory:');

  try {
    const taskRepo = new TaskRepository(sharedDb);
    const auditRepo = new AuditRepository(sharedDb);
    const memoryRepo = new MemoryRepository(separateMemoryDb);
    const memoryService = new MemoryService({ memoryRepo });

    const modelProvider = new MockModelProvider();
    const toolRegistry = new ToolRegistry();
    const policyEngine = new PolicyEngine({ workspaceRoot: testWorkspace });
    const approvalBroker = new ApprovalBroker(taskRepo, auditRepo);
    const verifier = new VerificationEngine(taskRepo);
    const budgetTracker = new TokenBudgetTracker({ db: sharedDb, maxCostPerTaskUsd: 1.0 });

    assert.throws(
      () => new TaskCoordinator({
        taskRepo,
        auditRepo,
        modelProvider,
        toolRegistry,
        policyEngine,
        approvalBroker,
        verifier,
        budgetTracker,
        workspaceRoot: testWorkspace,
        memoryService
      }),
      (err: unknown) => {
        assert.ok(err instanceof ValidationError);
        assert.match(err.message, /MemoryService, TaskRepository, and AuditRepository must share the exact same DatabaseManager instance/);
        return true;
      }
    );
  } finally {
    sharedDb.close();
    separateMemoryDb.close();
  }
});

test('TaskCoordinator - raw caller-supplied scope metadata cannot authorize memory access', async () => {
  const harness = createMemoryCoordHarness();

  try {
    const coordinator = harness.createCoordinator();

    // Caller attempts to supply unverified scope in metadata
    const task = await coordinator.submitTask('Attacked task', {
      scope: { scopeType: 'WORKSPACE', scopeId: 'finance' },
      workspaceId: 'finance'
    });

    // Coordinator verifyTaskScope must reject/ignore raw metadata and return null
    const verifiedScope = coordinator.verifyTaskScope(task);
    assert.equal(verifiedScope, null);

    // Agent authorization for this task fails because there is no trusted host attestation
    assert.throws(
      () => harness.authorizer.authorizeAgent({ taskId: task.id }),
      (err: unknown) => {
        assert.ok(err instanceof ValidationError);
        assert.match(err.message, /lacks a trusted host scope attestation/);
        return true;
      }
    );
  } finally {
    harness.sharedDb.close();
    if (existsSync(testWorkspace)) rmSync(testWorkspace, { recursive: true, force: true });
  }
});

test('TaskCoordinator - unattested legacy tasks cannot use memory integration', async () => {
  const harness = createMemoryCoordHarness();

  try {
    const coordinator = harness.createCoordinator();
    const task = await coordinator.submitTask('Legacy task with no scope claims');

    assert.equal(coordinator.verifyTaskScope(task), null);

    // Memory authorization for the legacy task fails closed
    assert.throws(
      () => harness.authorizer.authorizeAgent({ taskId: task.id }),
      (err: unknown) => {
        assert.ok(err instanceof ValidationError);
        assert.match(err.message, /lacks (metadata required to establish authoritative scope|a trusted host scope attestation)/);
        return true;
      }
    );
  } finally {
    harness.sharedDb.close();
    if (existsSync(testWorkspace)) rmSync(testWorkspace, { recursive: true, force: true });
  }
});

test('TaskCoordinator - unauthorized or forged scope/caller context fails closed', async () => {
  const idProvider = new MockIdentityProvider();
  idProvider.register('token-eng-member', {
    principalId: 'eng-dev',
    role: 'MEMBER',
    permittedScopes: [{ scopeType: 'WORKSPACE', scopeId: 'engineering' }]
  });
  idProvider.register('token-viewer', {
    principalId: 'audit-viewer',
    role: 'VIEWER',
    permittedScopes: [{ scopeType: 'WORKSPACE', scopeId: 'engineering' }]
  });

  const harness = createMemoryCoordHarness({ idProvider });

  try {
    const coordinator = harness.createCoordinator();

    // 1. Forged caller context (handcrafted literal not issued by host authority)
    const forgedCaller: CallerContext = {
      actor: 'USER',
      scope: { scopeType: 'WORKSPACE', scopeId: 'engineering' },
      permissions: new Set(['READ', 'WRITE'])
    };

    await assert.rejects(
      async () => coordinator.submitScopedTask('Attempt with forged context', forgedCaller),
      (err: unknown) => {
        assert.ok(err instanceof SecurityViolationError);
        assert.equal((err as SecurityViolationError).violationType, 'FORGED_CALLER_CONTEXT');
        return true;
      }
    );

    // 2. Caller context with unauthorized requestedScope
    const engUser = harness.authorizer.authorizeUser({
      credentials: 'token-eng-member',
      requestedScope: { scopeType: 'WORKSPACE', scopeId: 'engineering' }
    });

    await assert.rejects(
      async () => coordinator.submitScopedTask({
        goal: 'Finance manipulation',
        caller: engUser,
        requestedScope: { scopeType: 'WORKSPACE', scopeId: 'finance' } // Mismatch!
      }),
      (err: unknown) => {
        assert.ok(err instanceof SecurityViolationError);
        assert.equal((err as SecurityViolationError).violationType, 'TASK_CALLER_SCOPE_MISMATCH');
        return true;
      }
    );

    // 3. Caller lacking WRITE permissions (e.g., VIEWER)
    const viewer = harness.authorizer.authorizeUser({
      credentials: 'token-viewer',
      requestedScope: { scopeType: 'WORKSPACE', scopeId: 'engineering' }
    });

    await assert.rejects(
      async () => coordinator.submitScopedTask('Viewer attempt to create task', viewer),
      (err: unknown) => {
        assert.ok(err instanceof SecurityViolationError);
        assert.equal((err as SecurityViolationError).violationType, 'PERMISSION_DENIED');
        return true;
      }
    );

    // 4. Forged scope attestation in task metadata
    const forgedTask = harness.taskRepo.createTask({
      goal: 'Task with fake attestation',
      metadata: {
        _scopeAttestation: {
          scopeType: 'WORKSPACE',
          scopeId: 'engineering',
          signature: 'deadbeef0123456789abcdef0123456789abcdef0123456789abcdef01234567',
          timestamp: new Date().toISOString()
        }
      }
    });

    assert.throws(
      () => coordinator.verifyTaskScope(forgedTask),
      (err: unknown) => {
        assert.ok(err instanceof SecurityViolationError);
        assert.equal((err as SecurityViolationError).violationType, 'FORGED_TASK_SCOPE');
        return true;
      }
    );

    // 5. Valid caller context creates genuinely attested task
    const validTask = await coordinator.submitScopedTask('Legitimate engineering task', engUser);
    assert.equal(validTask.status, 'SUBMITTED');
    const verifiedScope = coordinator.verifyTaskScope(validTask);
    assert.deepEqual(verifiedScope, { scopeType: 'WORKSPACE', scopeId: 'engineering' });
  } finally {
    harness.sharedDb.close();
    if (existsSync(testWorkspace)) rmSync(testWorkspace, { recursive: true, force: true });
  }
});

test('TaskCoordinator - credentials and authentication secrets are never persisted in task metadata or audit details', async () => {
  const idProvider = new MockIdentityProvider();
  idProvider.register('token-admin', {
    principalId: 'sys-admin',
    role: 'ADMIN',
    permittedScopes: [{ scopeType: 'WORKSPACE', scopeId: 'sec-ops' }]
  });

  const harness = createMemoryCoordHarness({ idProvider });

  try {
    const coordinator = harness.createCoordinator();

    // 1. Submit legacy task with credentials in metadata
    const legacyTask = await coordinator.submitTask('Legacy task with sensitive inputs', {
      credentials: { token: 'super-secret-token' },
      apiKey: 'AIzaSyD9876543210zyxwvutsrqponmlkjihgfed',
      password: 'mypassword123',
      secret: 'mysecret',
      auth: 'Bearer token123',
      note: 'Normal note with embedded key AIzaSyD9876543210zyxwvutsrqponmlkjihgfed',
      regularConfig: 'safe_value'
    });

    const legacyMetaJson = legacyTask.metadataJson!;
    assert.ok(!legacyMetaJson.includes('super-secret-token'));
    assert.ok(!legacyMetaJson.includes('mypassword123'));
    assert.ok(!legacyMetaJson.includes('mysecret'));
    assert.ok(!legacyMetaJson.includes('AIzaSyD9876543210zyxwvutsrqponmlkjihgfed'));
    assert.ok(legacyMetaJson.includes('[REDACTED_GOOGLE_API_KEY]'));
    assert.ok(legacyMetaJson.includes('safe_value'));

    const legacyEvents = harness.auditRepo.getEventsByTaskId(legacyTask.id);
    const legacyEventJson = legacyEvents[0]!.detailsJson;
    assert.ok(!legacyEventJson.includes('super-secret-token'));
    assert.ok(!legacyEventJson.includes('mypassword123'));
    assert.ok(!legacyEventJson.includes('AIzaSyD9876543210zyxwvutsrqponmlkjihgfed'));
    assert.ok(legacyEventJson.includes('[REDACTED_GOOGLE_API_KEY]'));
    assert.ok(legacyEventJson.includes('safe_value'));

    // 2. Submit scoped task with credentials in metadata
    const adminUser = harness.authorizer.authorizeUser({
      credentials: 'token-admin',
      requestedScope: { scopeType: 'WORKSPACE', scopeId: 'sec-ops' }
    });

    const scopedTask = await coordinator.submitScopedTask({
      goal: 'Scoped task with sensitive metadata',
      caller: adminUser,
      metadata: {
        token: 'bearer-xyz-12345',
        apiKey: 'AIzaSyAABBCCDDEEFF001122334455667788990',
        allowedSetting: 'active_mode'
      }
    });

    const scopedMetaJson = scopedTask.metadataJson!;
    assert.ok(!scopedMetaJson.includes('bearer-xyz-12345'));
    assert.ok(!scopedMetaJson.includes('AIzaSyAABBCCDDEEFF001122334455667788990'));
    assert.ok(scopedMetaJson.includes('active_mode'));

    const scopedEvents = harness.auditRepo.getEventsByTaskId(scopedTask.id);
    const scopedEventJson = scopedEvents[0]!.detailsJson;
    assert.ok(!scopedEventJson.includes('bearer-xyz-12345'));
    assert.ok(!scopedEventJson.includes('AIzaSyAABBCCDDEEFF001122334455667788990'));
    assert.ok(scopedEventJson.includes('active_mode'));
  } finally {
    harness.sharedDb.close();
    if (existsSync(testWorkspace)) rmSync(testWorkspace, { recursive: true, force: true });
  }
});

test('TaskCoordinator - rejects mismatched coordinator authorizer and host authority', () => {
  const harness = createMemoryCoordHarness();
  const differentHostAuthority = new HostMemoryAuthority({ taskRepo: harness.taskRepo });

  try {
    assert.throws(
      () => harness.createCoordinator({
        hostAuthority: harness.hostAuthority,
        authorizer: differentHostAuthority.authorizer
      }),
      (err: unknown) => {
        assert.ok(err instanceof ValidationError);
        assert.match(err.message, /Coordinator authorizer must be the exact authorizer owned by its configured HostMemoryAuthority/);
        return true;
      }
    );
  } finally {
    harness.sharedDb.close();
    if (existsSync(testWorkspace)) rmSync(testWorkspace, { recursive: true, force: true });
  }
});

test('TaskCoordinator - rejects mismatched MemoryService authorization configuration', () => {
  const sharedDb = new DatabaseManager(':memory:');

  try {
    const taskRepo = new TaskRepository(sharedDb);
    const auditRepo = new AuditRepository(sharedDb);
    const memoryRepo = new MemoryRepository(sharedDb);

    const hostAuthority1 = new HostMemoryAuthority({ taskRepo });
    const hostAuthority2 = new HostMemoryAuthority({ taskRepo });

    // 1. MemoryService itself rejects mismatched authorizer and hostAuthority
    assert.throws(
      () => new MemoryService({
        memoryRepo,
        auditRepo,
        taskRepo,
        hostAuthority: hostAuthority1,
        authorizer: hostAuthority2.authorizer
      }),
      (err: unknown) => {
        assert.ok(err instanceof ValidationError);
        assert.match(err.message, /MemoryService authorizer must be the exact authorizer owned by its configured HostMemoryAuthority/);
        return true;
      }
    );

    // 2. Coordinator rejects MemoryService configured with a different authority than Coordinator's hostAuthority
    const memoryService1 = new MemoryService({
      memoryRepo,
      auditRepo,
      taskRepo,
      hostAuthority: hostAuthority1
    });

    const modelProvider = new MockModelProvider();
    const toolRegistry = new ToolRegistry();
    const policyEngine = new PolicyEngine({ workspaceRoot: testWorkspace });
    const approvalBroker = new ApprovalBroker(taskRepo, auditRepo);
    const verifier = new VerificationEngine(taskRepo);
    const budgetTracker = new TokenBudgetTracker({ db: sharedDb, maxCostPerTaskUsd: 1.0 });

    assert.throws(
      () => new TaskCoordinator({
        taskRepo,
        auditRepo,
        modelProvider,
        toolRegistry,
        policyEngine,
        approvalBroker,
        verifier,
        budgetTracker,
        workspaceRoot: testWorkspace,
        memoryService: memoryService1,
        hostAuthority: hostAuthority2
      }),
      (err: unknown) => {
        assert.ok(err instanceof ValidationError);
        assert.match(err.message, /MemoryService and Coordinator must share the exact same MemoryAuthorizer instance owned by HostMemoryAuthority/);
        return true;
      }
    );
  } finally {
    sharedDb.close();
  }
});

test('TaskCoordinator - prevents creating a task with an attestation for a caller accepted by a different authority', async () => {
  const idProvider1 = new MockIdentityProvider();
  idProvider1.register('token-user-auth1', {
    principalId: 'user-1',
    role: 'MEMBER',
    permittedScopes: [{ scopeType: 'WORKSPACE', scopeId: 'analytics' }]
  });

  const harness = createMemoryCoordHarness({ idProvider: idProvider1 });
  const otherHostAuthority = new HostMemoryAuthority({ taskRepo: harness.taskRepo });

  try {
    // Caller context issued by authority 1
    const callerAuth1 = harness.authorizer.authorizeUser({
      credentials: 'token-user-auth1',
      requestedScope: { scopeType: 'WORKSPACE', scopeId: 'analytics' }
    });

    // Coordinator configured strictly with authority 2 (with matching memoryService2)
    const memoryService2 = new MemoryService({
      memoryRepo: harness.memoryRepo,
      auditRepo: harness.auditRepo,
      taskRepo: harness.taskRepo,
      hostAuthority: otherHostAuthority
    });

    const coordinatorOther = harness.createCoordinator({
      hostAuthority: otherHostAuthority,
      memoryService: memoryService2
    });

    // Submitting with caller from authority 1 to coordinator bound to authority 2 must fail closed
    await assert.rejects(
      async () => coordinatorOther.submitScopedTask('Illegitimate cross-authority task', callerAuth1),
      (err: unknown) => {
        assert.ok(err instanceof SecurityViolationError);
        assert.equal((err as SecurityViolationError).violationType, 'FORGED_CALLER_CONTEXT');
        return true;
      }
    );
  } finally {
    harness.sharedDb.close();
    if (existsSync(testWorkspace)) rmSync(testWorkspace, { recursive: true, force: true });
  }
});

test('TaskCoordinator - recursively sanitizes arrays and nested object/array combinations in metadata', async () => {
  const idProvider = new MockIdentityProvider();
  idProvider.register('token-admin', {
    principalId: 'admin-1',
    role: 'ADMIN',
    permittedScopes: [{ scopeType: 'WORKSPACE', scopeId: 'research' }]
  });

  const harness = createMemoryCoordHarness({ idProvider });

  try {
    const coordinator = harness.createCoordinator();

    const complexMetadata = {
      stringArray: [
        'Normal string item',
        'Sensitive key AIzaSyD9876543210zyxwvutsrqponmlkjihgfed embedded in string',
        'sk-abcdef1234567890abcdef1234567890'
      ],
      objectArray: [
        {
          password: 'secret_password_in_array',
          token: 'token_in_array',
          apiKey: 'key_in_array',
          auth: 'Bearer auth_in_array',
          regularName: 'safe_name_in_array',
          secretText: 'Bearer supersecrettoken123'
        },
        {
          itemNumber: 999,
          isActive: true
        }
      ],
      deeplyNested: {
        matrix: [
          [
            {
              credentials: { secret: 'nested_deep_secret' },
              note: 'Matrix note with AIzaSyD9876543210zyxwvutsrqponmlkjihgfed',
              preservedCount: 42
            }
          ]
        ]
      }
    };

    // 1. Submit legacy task with complex nested arrays
    const legacyTask = await coordinator.submitTask('Legacy task with nested array metadata', complexMetadata);
    const legacyMetaJson = legacyTask.metadataJson!;

    // Sensitive keys stripped
    assert.ok(!legacyMetaJson.includes('secret_password_in_array'));
    assert.ok(!legacyMetaJson.includes('token_in_array'));
    assert.ok(!legacyMetaJson.includes('key_in_array'));
    assert.ok(!legacyMetaJson.includes('auth_in_array'));
    assert.ok(!legacyMetaJson.includes('nested_deep_secret'));

    // Detectable secrets in strings scrubbed
    assert.ok(!legacyMetaJson.includes('AIzaSyD9876543210zyxwvutsrqponmlkjihgfed'));
    assert.ok(!legacyMetaJson.includes('sk-abcdef1234567890abcdef1234567890'));
    assert.ok(!legacyMetaJson.includes('supersecrettoken123'));
    assert.ok(legacyMetaJson.includes('[REDACTED_GOOGLE_API_KEY]'));
    assert.ok(legacyMetaJson.includes('[REDACTED_OPENAI_API_KEY]'));
    assert.ok(legacyMetaJson.includes('[REDACTED_TOKEN]'));

    // Legitimate metadata preserved
    assert.ok(legacyMetaJson.includes('Normal string item'));
    assert.ok(legacyMetaJson.includes('safe_name_in_array'));
    assert.ok(legacyMetaJson.includes('999'));
    assert.ok(legacyMetaJson.includes('preservedCount'));
    assert.ok(legacyMetaJson.includes('42'));

    // Audit event matches
    const legacyEvents = harness.auditRepo.getEventsByTaskId(legacyTask.id);
    const legacyEventJson = legacyEvents[0]!.detailsJson;
    assert.ok(!legacyEventJson.includes('secret_password_in_array'));
    assert.ok(!legacyEventJson.includes('AIzaSyD9876543210zyxwvutsrqponmlkjihgfed'));
    assert.ok(!legacyEventJson.includes('sk-abcdef1234567890abcdef1234567890'));
    assert.ok(legacyEventJson.includes('safe_name_in_array'));

    // 2. Submit scoped task with complex nested arrays
    const adminUser = harness.authorizer.authorizeUser({
      credentials: 'token-admin',
      requestedScope: { scopeType: 'WORKSPACE', scopeId: 'research' }
    });

    const scopedTask = await coordinator.submitScopedTask({
      goal: 'Scoped task with nested array metadata',
      caller: adminUser,
      metadata: complexMetadata
    });

    const scopedMetaJson = scopedTask.metadataJson!;
    assert.ok(!scopedMetaJson.includes('secret_password_in_array'));
    assert.ok(!scopedMetaJson.includes('token_in_array'));
    assert.ok(!scopedMetaJson.includes('nested_deep_secret'));
    assert.ok(!scopedMetaJson.includes('AIzaSyD9876543210zyxwvutsrqponmlkjihgfed'));
    assert.ok(!scopedMetaJson.includes('sk-abcdef1234567890abcdef1234567890'));
    assert.ok(scopedMetaJson.includes('[REDACTED_GOOGLE_API_KEY]'));
    assert.ok(scopedMetaJson.includes('safe_name_in_array'));
    assert.ok(scopedMetaJson.includes('42'));

    const scopedEvents = harness.auditRepo.getEventsByTaskId(scopedTask.id);
    const scopedEventJson = scopedEvents[0]!.detailsJson;
    assert.ok(!scopedEventJson.includes('secret_password_in_array'));
    assert.ok(!scopedEventJson.includes('AIzaSyD9876543210zyxwvutsrqponmlkjihgfed'));
    assert.ok(scopedEventJson.includes('safe_name_in_array'));
  } finally {
    harness.sharedDb.close();
    if (existsSync(testWorkspace)) rmSync(testWorkspace, { recursive: true, force: true });
  }
});
