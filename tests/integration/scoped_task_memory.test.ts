/**
 * Next-Generation Dots AI Platform - Scoped Task Memory Integration Test
 * 
 * Phase 7.4 Substep 5:
 * Validates the complete end-to-end lifecycle of a host-authorized scoped task using long-term memory:
 * 1. Trusted identity and workspace scope establishment via host memory authorizer.
 * 2. Active workspace memory persistence with a unique, harmless marker.
 * 3. Scoped task submission with cryptographic host attestation.
 * 4. Autonomous memory retrieval, prompt compilation, and atomic plan + provenance persistence.
 * 5. Full task execution through verification to COMPLETED state.
 * 6. Verification of memory injection provenance semantics (charCount, estimatedTokens).
 * 7. Verification of audit event chronology and strict audit privacy (no memory content or credentials leaked).
 * 8. Cold reboot persistence verification after closing and reopening the SQLite database.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { existsSync, rmSync, mkdirSync, mkdtempSync } from 'node:fs';
import { DatabaseManager } from '../../src/storage/db.ts';
import { TaskRepository } from '../../src/storage/task-repository.ts';
import { AuditRepository } from '../../src/storage/audit-repository.ts';
import { MemoryRepository } from '../../src/storage/memory-repository.ts';
import { HostMemoryAuthority } from '../../src/security/host-authority.ts';
import type { TrustedIdentityProvider, AuthenticatedPrincipal } from '../../src/security/memory-authorizer.ts';
import { MemoryService } from '../../src/memory/memory-service.ts';
import { TaskCoordinator } from '../../src/orchestrator/coordinator.ts';
import { MockModelProvider } from '../../src/model/mock-provider.ts';
import type { CompiledPlanPrompt } from '../../src/model/types.ts';
import { ToolRegistry } from '../../src/tools/registry.ts';
import { PolicyEngine } from '../../src/security/policy-engine.ts';
import { ApprovalBroker } from '../../src/security/approval-broker.ts';
import { VerificationEngine } from '../../src/verification/verifier.ts';
import { TokenBudgetTracker } from '../../src/model/budget-tracker.ts';

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

test('Scoped Task Memory Integration - full lifecycle from submission through verified completion, provenance, and cold reboot persistence', async () => {
  let testDir: string | null = null;
  let db1: DatabaseManager | null = null;
  let db2: DatabaseManager | null = null;

  const testAuthToken = 'secret-token-analyst-42';
  const testScopeId = 'analytics-prod';
  const memoryMarker = 'UNIQUE_SAFE_MARKER_PORT_9443';
  const memoryContent = `Primary backend database listener on ${memoryMarker}.`;

  try {
    testDir = mkdtempSync(join(tmpdir(), 'dots-scoped-mem-'));
    const testDiskDb = join(testDir, 'scoped_memory.db');
    const testWorkspace = join(testDir, 'workspace');
    mkdirSync(testWorkspace, { recursive: true });

    // =========================================================================
    // 1. Setup Shared Database, Authority, MemoryService, and Coordinator
    // =========================================================================
    db1 = new DatabaseManager(testDiskDb);
    const taskRepo1 = new TaskRepository(db1);
    const auditRepo1 = new AuditRepository(db1);
    const memoryRepo1 = new MemoryRepository(db1);

    const idProvider = new MockIdentityProvider();
    idProvider.register(testAuthToken, {
      principalId: 'analyst-1',
      role: 'MEMBER',
      permittedScopes: [{ scopeType: 'WORKSPACE', scopeId: testScopeId }]
    });

    const hostAuthority1 = new HostMemoryAuthority({
      taskRepo: taskRepo1,
      identityProvider: idProvider
    });
    const authorizer1 = hostAuthority1.authorizer;

    const memoryService1 = new MemoryService({
      memoryRepo: memoryRepo1,
      auditRepo: auditRepo1,
      taskRepo: taskRepo1,
      authorizer: authorizer1,
      hostAuthority: hostAuthority1
    });

    const modelProvider1 = new MockModelProvider();
    const toolRegistry1 = new ToolRegistry();
    const policyEngine1 = new PolicyEngine({ workspaceRoot: testWorkspace, autoApproveTier2: true });
    const approvalBroker1 = new ApprovalBroker(taskRepo1, auditRepo1);
    const verifier1 = new VerificationEngine(taskRepo1);
    const budgetTracker1 = new TokenBudgetTracker({ db: db1, maxCostPerTaskUsd: 1.0 });

    const coordinator1 = new TaskCoordinator({
      taskRepo: taskRepo1,
      auditRepo: auditRepo1,
      modelProvider: modelProvider1,
      toolRegistry: toolRegistry1,
      policyEngine: policyEngine1,
      approvalBroker: approvalBroker1,
      verifier: verifier1,
      budgetTracker: budgetTracker1,
      workspaceRoot: testWorkspace,
      memoryService: memoryService1,
      hostAuthority: hostAuthority1
    });

    // =========================================================================
    // 2. Establish Valid Host-Authorized Identity and Workspace Scope
    // =========================================================================
    const userCaller = authorizer1.authorizeUser({
      credentials: testAuthToken,
      requestedScope: { scopeType: 'WORKSPACE', scopeId: testScopeId }
    });
    assert.equal(userCaller.actor, 'USER');
    assert.equal(userCaller.scope.scopeType, 'WORKSPACE');
    assert.equal(userCaller.scope.scopeId, testScopeId);

    // =========================================================================
    // 3. Create Active Workspace-Scoped Memory with Unique Marker
    // =========================================================================
    const createdMemory = memoryService1.createMemory(userCaller, {
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: testScopeId,
      key: 'service.listener.port',
      content: memoryContent,
      tags: ['database', 'listener', 'port'],
      priority: 90,
      status: 'ACTIVE'
    });
    assert.ok(createdMemory.id);
    assert.equal(createdMemory.status, 'ACTIVE');

    // =========================================================================
    // 4. Submit Scoped Task and Run to Completion using Deterministic Plan
    // =========================================================================
    const goal = 'Connect to service listener port and format confirmation banner';
    const submittedTask = await coordinator1.submitScopedTask({
      goal,
      caller: userCaller,
      requestedScope: { scopeType: 'WORKSPACE', scopeId: testScopeId }
    });
    assert.equal(submittedTask.status, 'SUBMITTED');

    // Enqueue a deterministic 2-step plan with variable chaining
    modelProvider1.enqueuePlan([
      {
        stepOrder: 1,
        description: 'Calculate listener port offset',
        toolName: 'calculate',
        arguments: { expression: '9000 + 443' },
        expectedOutcome: 'Port offset computed'
      },
      {
        stepOrder: 2,
        description: 'Format confirmation banner',
        toolName: 'text_transform',
        arguments: {
          operation: 'uppercase',
          text: 'Listener port: {{steps[1].result}} verified'
        },
        expectedOutcome: 'Confirmation banner formatted'
      }
    ]);

    // Run coordinator lifecycle loop to completion
    const completedTask = await coordinator1.runToCompletion(submittedTask.id, 50);

    // =========================================================================
    // 5. Verify Task reaches COMPLETED and Steps are VERIFIED
    // =========================================================================
    assert.equal(completedTask.status, 'COMPLETED');
    assert.ok(completedTask.completedAt !== null, 'completedAt must be populated');

    const steps1 = taskRepo1.getStepsByTaskId(submittedTask.id);
    assert.equal(steps1.length, 2);
    assert.equal(steps1[0]!.status, 'VERIFIED');
    assert.equal(steps1[1]!.status, 'VERIFIED');

    // =========================================================================
    // 6. Verify Memory Injection Provenance Semantics
    // =========================================================================
    const injections1 = memoryRepo1.getInjectionsByTaskId(submittedTask.id);
    assert.equal(injections1.length, 1, 'Exactly one memory injection provenance record must exist');

    const inj = injections1[0]!;
    assert.equal(inj.taskId, submittedTask.id);
    assert.equal(inj.memoryId, createdMemory.id);
    assert.equal(inj.charCount, memoryContent.length, 'charCount must equal memory.content.length');
    assert.equal(
      inj.estimatedTokens,
      Math.ceil(memoryContent.length / 3.8),
      'estimatedTokens must equal Math.ceil(charCount / 3.8)'
    );
    assert.ok(inj.injectedAt, 'injectedAt must be populated');

    // Confirm that the model actually received the compiled prompt with the marker
    const calls = modelProvider1.getRecordedCalls();
    assert.equal(calls.length, 1);
    assert.equal(calls[0]!.args.goal, goal);
    assert.equal(calls[0]!.args.context, undefined, 'Raw memory context must not be separately passed in legacy context arg');

    const compiledPrompt = calls[0]!.args.compiledPrompt as CompiledPlanPrompt;
    assert.ok(compiledPrompt, 'CompiledPlanPrompt must be provided to model provider');
    assert.equal(compiledPrompt.contextIncluded, true);
    assert.equal(compiledPrompt.contextOmitted, false);
    assert.ok(
      compiledPrompt.userPrompt.includes(memoryMarker),
      'Compiled user prompt must contain memory marker'
    );
    assert.equal(calls[0]!.args.userPrompt, compiledPrompt.userPrompt);

    // =========================================================================
    // 7. Verify Audit Event Chronology (Actual Event Model)
    // =========================================================================
    const events1 = auditRepo1.getEventsByTaskId(submittedTask.id);
    assert.ok(events1.length >= 6, 'Audit trail must contain all lifecycle milestones');

    const eventTypes = events1.map((e) => e.eventType);
    const taskCreatedIdx = eventTypes.indexOf('TASK_CREATED');
    const memoryRetrievedIdx = eventTypes.indexOf('MEMORY_RETRIEVED');
    const planGeneratedIdx = eventTypes.indexOf('PLAN_GENERATED');
    const firstToolCompletedIdx = eventTypes.indexOf('TOOL_EXECUTION_COMPLETED');
    const firstEvidenceVerifiedIdx = eventTypes.indexOf('EVIDENCE_VERIFIED');

    assert.ok(taskCreatedIdx !== -1, 'TASK_CREATED must be recorded');
    assert.ok(memoryRetrievedIdx !== -1, 'MEMORY_RETRIEVED must be recorded');
    assert.ok(planGeneratedIdx !== -1, 'PLAN_GENERATED must be recorded');
    assert.ok(firstToolCompletedIdx !== -1, 'TOOL_EXECUTION_COMPLETED must be recorded');
    assert.ok(firstEvidenceVerifiedIdx !== -1, 'EVIDENCE_VERIFIED must be recorded');

    // Strict chronological sequence
    assert.ok(taskCreatedIdx < memoryRetrievedIdx, 'TASK_CREATED must precede MEMORY_RETRIEVED');
    assert.ok(memoryRetrievedIdx < planGeneratedIdx, 'MEMORY_RETRIEVED must precede PLAN_GENERATED');
    assert.ok(planGeneratedIdx < firstToolCompletedIdx, 'PLAN_GENERATED must precede TOOL_EXECUTION_COMPLETED');
    assert.ok(firstToolCompletedIdx < firstEvidenceVerifiedIdx, 'TOOL_EXECUTION_COMPLETED must precede EVIDENCE_VERIFIED');

    // Verify PLAN_GENERATED audit details
    const planEvent = events1.find((e) => e.eventType === 'PLAN_GENERATED')!;
    const planDetails = JSON.parse(planEvent.detailsJson) as {
      stepCount: number;
      injectedMemoriesCount: number;
      injectedMemoryIds: string[];
    };
    assert.equal(planDetails.stepCount, 2);
    assert.equal(planDetails.injectedMemoriesCount, 1);
    assert.deepEqual(planDetails.injectedMemoryIds, [createdMemory.id]);

    // =========================================================================
    // 8. Verify Audit Details Privacy (No Raw Memory Marker or Secrets)
    // =========================================================================
    for (const evt of events1) {
      assert.ok(
        !evt.detailsJson.includes(memoryMarker),
        `Audit event '${evt.eventType}' leaked raw memory marker: ${evt.detailsJson}`
      );
      assert.ok(
        !evt.detailsJson.includes(testAuthToken),
        `Audit event '${evt.eventType}' leaked credential secret: ${evt.detailsJson}`
      );
    }

    // =========================================================================
    // 9. Close and Reopen Database (Cold-Start Persistence Verification)
    // =========================================================================
    db1.close();
    db1 = null;

    db2 = new DatabaseManager(testDiskDb);
    const taskRepo2 = new TaskRepository(db2);
    const auditRepo2 = new AuditRepository(db2);
    const memoryRepo2 = new MemoryRepository(db2);

    // Verify task state persisted intact
    const persistedTask = taskRepo2.getTaskById(submittedTask.id);
    assert.ok(persistedTask, 'Task must exist after cold restart');
    assert.equal(persistedTask.status, 'COMPLETED');
    assert.ok(persistedTask.completedAt !== null);

    // Verify plan steps persisted intact
    const persistedSteps = taskRepo2.getStepsByTaskId(submittedTask.id);
    assert.equal(persistedSteps.length, 2);
    assert.equal(persistedSteps[0]!.status, 'VERIFIED');
    assert.equal(persistedSteps[1]!.status, 'VERIFIED');

    // Verify memory injection provenance persisted intact
    const persistedInjections = memoryRepo2.getInjectionsByTaskId(submittedTask.id);
    assert.equal(persistedInjections.length, 1);
    assert.equal(persistedInjections[0]!.taskId, submittedTask.id);
    assert.equal(persistedInjections[0]!.memoryId, createdMemory.id);
    assert.equal(persistedInjections[0]!.charCount, memoryContent.length);
    assert.equal(persistedInjections[0]!.estimatedTokens, Math.ceil(memoryContent.length / 3.8));

    // Verify audit logs persisted intact without leaks
    const persistedEvents = auditRepo2.getEventsByTaskId(submittedTask.id);
    assert.equal(persistedEvents.length, events1.length);
    for (const pe of persistedEvents) {
      assert.ok(!pe.detailsJson.includes(memoryMarker), 'Rehydrated audit must not leak memory marker');
      assert.ok(!pe.detailsJson.includes(testAuthToken), 'Rehydrated audit must not leak credential');
    }
  } finally {
    // =========================================================================
    // 10. Clean up Database Handles and Unique Temporary Directory
    // =========================================================================
    try {
      if (db1?.isOpen) db1.close();
    } finally {
      try {
        if (db2?.isOpen) db2.close();
      } finally {
        if (testDir && existsSync(testDir)) {
          rmSync(testDir, { recursive: true, force: true });
        }
      }
    }
  }
});
