/**
 * Next-Generation Dots AI Platform - Phase 7.5 Memory Lifecycle Integration Test
 * 
 * Verifies the complete end-to-end memory lifecycle, cross-tenant isolation,
 * human approval gating, export verification, archival, purge, tamper-evident audit
 * privacy, and cold-start database persistence across the Phase 7.5 architecture.
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
import { MEMORY_PROPOSE_TOOL_NAME } from '../../src/tools/memory-tools.ts';
import { verifyBundleChecksum } from '../../src/memory/canonical-json.ts';
import { isMemoryAuditEvent } from '../../src/storage/audit-policy.ts';
import {
  ValidationError,
  SecurityViolationError,
  MemoryScopeViolationError
} from '../../src/domain/errors.ts';

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

// ============================================================================
// Test 1 — Full memory lifecycle and persistence
// ============================================================================

test('Phase 7.5 Integration - Full memory lifecycle: proposal, isolation, human approval, retrieval, export, archive, purge, audit privacy, and cold reboot durability', async () => {
  let testDir: string | null = null;
  let db1: DatabaseManager | null = null;
  let db2: DatabaseManager | null = null;

  const sentinelToken = 'secret-token-analyst-lifecycle-7788';
  const testScopeId = 'lifecycle-ws-alpha';
  const sentinelKey = 'infra.db.cluster_endpoint';
  const sentinelMarker = 'UNIQUE_TEST_SENTINEL_PAYLOAD_CLUSTER_9941';
  const sentinelContent = `Primary backend cluster endpoint is https://db-cluster-9941.internal.net:5432 with ${sentinelMarker}`;
  const sentinelTag = 'SENTINEL_TAG_CLUSTER_DISCOVERY_9941';
  const sentinelMetaKey = 'sentinelSecretDiagnostic';
  const sentinelMetaVal = 'SENTINEL_METADATA_SECRET_TOKEN_9941';

  try {
    testDir = mkdtempSync(join(tmpdir(), 'dots-p75-lifecycle-'));
    const testDiskDb = join(testDir, 'lifecycle.db');
    const testWorkspace = join(testDir, 'workspace');
    mkdirSync(testWorkspace, { recursive: true });

    // 1. Setup shared database, repos, and host authority
    db1 = new DatabaseManager(testDiskDb);
    const taskRepo1 = new TaskRepository(db1);
    const auditRepo1 = new AuditRepository(db1);
    const memoryRepo1 = new MemoryRepository(db1);

    const idProvider = new MockIdentityProvider();
    idProvider.register(sentinelToken, {
      principalId: 'analyst-alpha',
      role: 'ADMIN',
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

    // Verify memory_propose tool was automatically registered by coordinator
    assert.ok(
      toolRegistry1.get(MEMORY_PROPOSE_TOOL_NAME),
      'memory_propose tool must be automatically registered in coordinator registry'
    );

    // Authenticate verified human caller
    const userCaller = authorizer1.authorizeUser({
      credentials: sentinelToken,
      requestedScope: { scopeType: 'WORKSPACE', scopeId: testScopeId }
    });
    assert.equal(userCaller.actor, 'USER');
    assert.equal(userCaller.scope.scopeType, 'WORKSPACE');
    assert.equal(userCaller.scope.scopeId, testScopeId);

    // -------------------------------------------------------------------------
    // Sequence 1: Autonomous task submits memory proposal via memory_propose
    // -------------------------------------------------------------------------
    const task1 = await coordinator1.submitScopedTask({
      goal: 'Inspect environment and propose cluster connection settings',
      caller: userCaller,
      requestedScope: { scopeType: 'WORKSPACE', scopeId: testScopeId }
    });
    assert.equal(task1.status, 'SUBMITTED');

    modelProvider1.enqueuePlan([
      {
        stepOrder: 1,
        description: 'Propose cluster endpoint for workspace',
        toolName: MEMORY_PROPOSE_TOOL_NAME,
        arguments: {
          key: sentinelKey,
          content: sentinelContent,
          category: 'PROJECT_FACT',
          tags: ['database', 'cluster', sentinelTag],
          metadata: {
            clusterRegion: 'us-east-1',
            [sentinelMetaKey]: sentinelMetaVal
          },
          priority: 85
        },
        expectedOutcome: 'Proposal registered with pending approval'
      }
    ]);

    const completedTask1 = await coordinator1.runToCompletion(task1.id, 20);
    assert.equal(completedTask1.status, 'COMPLETED');

    const steps1 = taskRepo1.getStepsByTaskId(task1.id);
    assert.equal(steps1.length, 1);
    assert.equal(steps1[0]!.status, 'VERIFIED');

    // -------------------------------------------------------------------------
    // Sequence 2: Verify proposal remains PENDING_APPROVAL and is not active
    // -------------------------------------------------------------------------
    const pendingMem = memoryRepo1.getMemoryByKey(sentinelKey, userCaller.scope, 'PENDING_APPROVAL');
    assert.ok(pendingMem, 'Proposal must exist in database with PENDING_APPROVAL status');
    assert.equal(pendingMem.status, 'PENDING_APPROVAL');
    assert.equal(pendingMem.content, sentinelContent);
    const proposalId = pendingMem.id;

    // Active lookup via memory service must return null while pending
    const initialActiveLookup = memoryService1.getMemoryByKey(userCaller, sentinelKey);
    assert.equal(initialActiveLookup, null, 'Pending proposal must not be returned on active memory lookup');

    // -------------------------------------------------------------------------
    // Sequence 3: Downstream task before approval verifies content is NOT injected
    // -------------------------------------------------------------------------
    modelProvider1.clearHistory();
    const task2A = await coordinator1.submitScopedTask({
      goal: 'Connect to database cluster endpoint and check status',
      caller: userCaller,
      requestedScope: { scopeType: 'WORKSPACE', scopeId: testScopeId }
    });

    modelProvider1.enqueuePlan([
      {
        stepOrder: 1,
        description: 'Verify connection baseline',
        toolName: 'calculate',
        arguments: { expression: '1 + 1' },
        expectedOutcome: 'Baseline checked'
      }
    ]);

    const completedTask2A = await coordinator1.runToCompletion(task2A.id, 20);
    assert.equal(completedTask2A.status, 'COMPLETED');

    const calls2A = modelProvider1.getRecordedCalls();
    assert.equal(calls2A.length, 1);
    const compiled2A = calls2A[0]!.args.compiledPrompt as CompiledPlanPrompt;
    assert.ok(compiled2A, 'CompiledPlanPrompt must be provided to model provider');
    assert.equal(
      compiled2A.userPrompt.includes(sentinelMarker),
      false,
      'User prompt must not contain pending proposal sentinel content'
    );
    assert.equal(
      compiled2A.userPrompt.includes(sentinelKey),
      false,
      'User prompt must not contain pending proposal key'
    );
    assert.equal(
      compiled2A.userPrompt.includes(proposalId),
      false,
      'User prompt must not contain pending proposal ID'
    );

    // Verify zero memory injections recorded for Task 2A
    const injections2A = memoryRepo1.getInjectionsByTaskId(task2A.id);
    assert.equal(injections2A.length, 0, 'No injection provenance should exist for Task 2A');

    // -------------------------------------------------------------------------
    // Sequence 4: Authenticate human user and approve proposal
    // -------------------------------------------------------------------------
    const approvedMem = memoryService1.decideProposal(userCaller, {
      memoryId: proposalId,
      decision: 'APPROVED'
    });
    assert.equal(approvedMem.id, proposalId);
    assert.equal(approvedMem.status, 'ACTIVE');

    // Active lookup now succeeds
    const activeLookupAfterApproval = memoryService1.getMemoryByKey(userCaller, sentinelKey);
    assert.ok(activeLookupAfterApproval, 'Active lookup must succeed after human approval');
    assert.equal(activeLookupAfterApproval.status, 'ACTIVE');

    // -------------------------------------------------------------------------
    // Sequence 5: Subsequent scoped task retrieves approved memory with provenance
    // -------------------------------------------------------------------------
    modelProvider1.clearHistory();
    const task2B = await coordinator1.submitScopedTask({
      goal: 'Query cluster endpoint configuration for migration',
      caller: userCaller,
      requestedScope: { scopeType: 'WORKSPACE', scopeId: testScopeId }
    });

    modelProvider1.enqueuePlan([
      {
        stepOrder: 1,
        description: 'Format migration banner',
        toolName: 'text_transform',
        arguments: { operation: 'uppercase', text: 'Migration target confirmed' },
        expectedOutcome: 'Banner formatted'
      }
    ]);

    const completedTask2B = await coordinator1.runToCompletion(task2B.id, 20);
    assert.equal(completedTask2B.status, 'COMPLETED');

    const calls2B = modelProvider1.getRecordedCalls();
    assert.equal(calls2B.length, 1);
    const compiled2B = calls2B[0]!.args.compiledPrompt as CompiledPlanPrompt;
    assert.ok(compiled2B, 'CompiledPlanPrompt must be provided to model provider');
    assert.equal(compiled2B.contextIncluded, true, 'Approved active memory must be included in prompt context');
    assert.ok(
      compiled2B.userPrompt.includes(sentinelMarker),
      'User prompt must include approved memory sentinel content'
    );

    // Verify injection provenance recorded
    const injections2B = memoryRepo1.getInjectionsByTaskId(task2B.id);
    assert.equal(injections2B.length, 1, 'Exactly one injection provenance record must exist for Task 2B');
    assert.equal(injections2B[0]!.memoryId, proposalId);
    assert.equal(injections2B[0]!.charCount, sentinelContent.length);

    // Verify memory usage history reflects task injection
    const usageHistory = memoryService1.getMemoryUsageHistory(userCaller, proposalId);
    assert.equal(usageHistory.totalInjections, 1);
    assert.equal(usageHistory.memoryId, proposalId);

    // -------------------------------------------------------------------------
    // Sequence 6: Export memory and verify bundle using export-verification API
    // -------------------------------------------------------------------------
    const exportBundle = memoryService1.exportMemories(userCaller, {
      scopeType: 'WORKSPACE',
      scopeId: testScopeId
    });
    assert.equal(exportBundle.count, 1);
    assert.equal(exportBundle.memories.length, 1);
    assert.equal(exportBundle.memories[0]!.key, sentinelKey);
    assert.equal(exportBundle.memories[0]!.content, sentinelContent);
    assert.ok(exportBundle.checksum, 'Export bundle must contain SHA-256 checksum');

    const isBundleValid = verifyBundleChecksum(exportBundle);
    assert.equal(isBundleValid, true, 'Canonical export checksum verification must pass');

    // -------------------------------------------------------------------------
    // Sequence 7: Archive memory and verify exclusion from eligible context
    // -------------------------------------------------------------------------
    const archivedMem = memoryService1.archiveMemory(userCaller, proposalId);
    assert.equal(archivedMem.id, proposalId);
    assert.equal(archivedMem.status, 'ARCHIVED');

    // Run Task 3: verify archived memory is not included in prompt context
    modelProvider1.clearHistory();
    const task3 = await coordinator1.submitScopedTask({
      goal: 'Query cluster endpoint configuration after archival',
      caller: userCaller,
      requestedScope: { scopeType: 'WORKSPACE', scopeId: testScopeId }
    });

    modelProvider1.enqueuePlan([
      {
        stepOrder: 1,
        description: 'Verify offline fallback',
        toolName: 'calculate',
        arguments: { expression: '2 * 2' },
        expectedOutcome: 'Fallback verified'
      }
    ]);

    const completedTask3 = await coordinator1.runToCompletion(task3.id, 20);
    assert.equal(completedTask3.status, 'COMPLETED');

    const calls3 = modelProvider1.getRecordedCalls();
    assert.equal(calls3.length, 1);
    const compiled3 = calls3[0]!.args.compiledPrompt as CompiledPlanPrompt;
    assert.equal(
      compiled3.userPrompt.includes(sentinelMarker),
      false,
      'Prompt must not contain archived memory sentinel content'
    );
    assert.equal(
      compiled3.userPrompt.includes(sentinelKey),
      false,
      'Prompt must not contain archived memory key'
    );
    assert.equal(
      compiled3.userPrompt.includes(proposalId),
      false,
      'Prompt must not contain archived memory ID'
    );

    // Verify zero memory injections recorded for Task 3
    const injections3 = memoryRepo1.getInjectionsByTaskId(task3.id);
    assert.equal(injections3.length, 0, 'No injection provenance should exist for Task 3');

    // -------------------------------------------------------------------------
    // Sequence 8: Purge archived memory using valid strict UTC cutoff
    // -------------------------------------------------------------------------
    const purgeCutoff = new Date(Date.now() + 5000).toISOString();
    const purgeResult = memoryService1.purgeArchivedMemories(userCaller, {
      olderThan: purgeCutoff
    });
    assert.equal(purgeResult.purgedCount, 1, 'Exactly 1 archived memory should be purged');

    // Permanent removal check: memory row must be gone from database
    const memoryAfterPurge = memoryRepo1.getMemoryById(proposalId, userCaller.scope);
    assert.equal(memoryAfterPurge, null, 'Purged memory record must be permanently removed from memories table');

    // Provenance preservation check: injection foreign key is set to NULL but task injection row remains
    const injectionsAfterPurge = memoryRepo1.getInjectionsByTaskId(task2B.id);
    assert.equal(injectionsAfterPurge.length, 1, 'Task injection row must remain for accounting');
    assert.equal(injectionsAfterPurge[0]!.memoryId, null, 'memoryId must be NULL after purge due to foreign key cascade');

    // -------------------------------------------------------------------------
    // Sequence 9: Inspect persisted SQLite audit events for lifecycle and privacy
    // -------------------------------------------------------------------------
    interface SqlAuditRow {
      readonly id: number;
      readonly task_id: string;
      readonly event_type: string;
      readonly details_json: string;
    }

    const allAuditRows = db1.prepare('SELECT id, task_id, event_type, details_json FROM audit_events ORDER BY id ASC').all() as unknown as SqlAuditRow[];
    assert.ok(allAuditRows.length >= 8, 'Expected at least 8 audit events across the lifecycle');

    const eventTypesPersisted = new Set(allAuditRows.map((r) => r.event_type));
    assert.ok(eventTypesPersisted.has('TASK_CREATED'), 'Audit log must record TASK_CREATED');
    assert.ok(eventTypesPersisted.has('MEMORY_PROPOSAL_SUBMITTED'), 'Audit log must record MEMORY_PROPOSAL_SUBMITTED');
    assert.ok(eventTypesPersisted.has('MEMORY_PROPOSAL_DECIDED'), 'Audit log must record MEMORY_PROPOSAL_DECIDED');
    assert.ok(eventTypesPersisted.has('MEMORY_RETRIEVED'), 'Audit log must record MEMORY_RETRIEVED');
    assert.ok(eventTypesPersisted.has('MEMORY_EXPORTED'), 'Audit log must record MEMORY_EXPORTED');
    assert.ok(eventTypesPersisted.has('MEMORY_ARCHIVED'), 'Audit log must record MEMORY_ARCHIVED');
    assert.ok(eventTypesPersisted.has('MEMORIES_PURGED'), 'Audit log must record MEMORIES_PURGED');

    // Privacy Guarantee: zero credentials leaked across any audit row, and zero raw content/keys/tags/metadata in memory lifecycle audit rows
    for (const row of allAuditRows) {
      assert.equal(
        row.details_json.includes(sentinelToken),
        false,
        `Audit row ${row.id} (${row.event_type}) leaked auth token credential: ${row.details_json}`
      );
      if (isMemoryAuditEvent(row.event_type)) {
        assert.equal(
          row.details_json.includes(sentinelMarker),
          false,
          `Memory audit row ${row.id} (${row.event_type}) leaked raw sentinel content: ${row.details_json}`
        );
        assert.equal(
          row.details_json.includes(sentinelKey),
          false,
          `Memory audit row ${row.id} (${row.event_type}) leaked raw memory key: ${row.details_json}`
        );
        assert.equal(
          row.details_json.includes(sentinelTag),
          false,
          `Memory audit row ${row.id} (${row.event_type}) leaked sentinel tag: ${row.details_json}`
        );
        assert.equal(
          row.details_json.includes(sentinelMetaVal),
          false,
          `Memory audit row ${row.id} (${row.event_type}) leaked sentinel metadata value: ${row.details_json}`
        );
        assert.equal(
          row.details_json.includes(sentinelMetaKey),
          false,
          `Memory audit row ${row.id} (${row.event_type}) leaked sentinel metadata property key: ${row.details_json}`
        );
      }
    }

    // Explicitly verify the MEMORIES_PURGED audit event structure and privacy
    const purgeEvent = allAuditRows.find((r) => r.event_type === 'MEMORIES_PURGED');
    assert.ok(purgeEvent, 'MEMORIES_PURGED audit event must exist in database');
    assert.equal(purgeEvent.details_json.includes(sentinelMarker), false);
    assert.equal(purgeEvent.details_json.includes(sentinelKey), false);
    assert.equal(purgeEvent.details_json.includes(sentinelTag), false);
    assert.equal(purgeEvent.details_json.includes(sentinelMetaVal), false);
    assert.equal(purgeEvent.details_json.includes(sentinelMetaKey), false);
    assert.equal(purgeEvent.details_json.includes(sentinelToken), false);
    const parsedPurge = JSON.parse(purgeEvent.details_json);
    assert.equal(parsedPurge.purgedCount, 1);
    assert.equal(parsedPurge.scopeType, 'WORKSPACE');
    assert.equal(parsedPurge.scopeId, testScopeId);
    assert.ok(parsedPurge.cutoffTimestamp);

    // -------------------------------------------------------------------------
    // Sequence 10: Close and reopen database (Cold-Start Persistence Verification)
    // -------------------------------------------------------------------------
    db1.close();
    db1 = null;

    db2 = new DatabaseManager(testDiskDb);
    const taskRepo2 = new TaskRepository(db2);
    const auditRepo2 = new AuditRepository(db2);
    const memoryRepo2 = new MemoryRepository(db2);

    // Verify all four task states and plan steps persisted intact
    const persistedTask1 = taskRepo2.getTaskById(task1.id);
    assert.ok(persistedTask1, 'Task 1 must exist after restart');
    assert.equal(persistedTask1.status, 'COMPLETED');
    const stepsTask1 = taskRepo2.getStepsByTaskId(task1.id);
    assert.equal(stepsTask1.length, 1);
    assert.equal(stepsTask1[0]!.status, 'VERIFIED');

    const persistedTask2A = taskRepo2.getTaskById(task2A.id);
    assert.ok(persistedTask2A, 'Task 2A must exist after restart');
    assert.equal(persistedTask2A.status, 'COMPLETED');
    const stepsTask2A = taskRepo2.getStepsByTaskId(task2A.id);
    assert.equal(stepsTask2A.length, 1);
    assert.equal(stepsTask2A[0]!.status, 'VERIFIED');

    const persistedTask2B = taskRepo2.getTaskById(task2B.id);
    assert.ok(persistedTask2B, 'Task 2B must exist after restart');
    assert.equal(persistedTask2B.status, 'COMPLETED');
    const stepsTask2B = taskRepo2.getStepsByTaskId(task2B.id);
    assert.equal(stepsTask2B.length, 1);
    assert.equal(stepsTask2B[0]!.status, 'VERIFIED');

    const persistedTask3 = taskRepo2.getTaskById(task3.id);
    assert.ok(persistedTask3, 'Task 3 must exist after restart');
    assert.equal(persistedTask3.status, 'COMPLETED');
    const stepsTask3 = taskRepo2.getStepsByTaskId(task3.id);
    assert.equal(stepsTask3.length, 1);
    assert.equal(stepsTask3[0]!.status, 'VERIFIED');

    // Verify purged memory row remains absent after cold reboot
    const persistedMemoryAfterPurge = memoryRepo2.getMemoryById(proposalId, userCaller.scope);
    assert.equal(persistedMemoryAfterPurge, null, 'Memory must remain absent after restart');

    // Verify injection provenance persisted intact
    const persistedInjections2B = memoryRepo2.getInjectionsByTaskId(task2B.id);
    assert.equal(persistedInjections2B.length, 1);
    assert.equal(persistedInjections2B[0]!.charCount, sentinelContent.length);

    // Verify audit logs persisted intact without leaks
    const persistedAuditRows = db2.prepare('SELECT id, event_type, details_json FROM audit_events ORDER BY id ASC').all() as unknown as SqlAuditRow[];
    assert.equal(persistedAuditRows.length, allAuditRows.length, 'Audit event count must match after restart');
    for (const row of persistedAuditRows) {
      assert.equal(row.details_json.includes(sentinelToken), false);
      if (isMemoryAuditEvent(row.event_type)) {
        assert.equal(row.details_json.includes(sentinelMarker), false);
        assert.equal(row.details_json.includes(sentinelKey), false);
        assert.equal(row.details_json.includes(sentinelTag), false);
        assert.equal(row.details_json.includes(sentinelMetaVal), false);
        assert.equal(row.details_json.includes(sentinelMetaKey), false);
      }
    }
  } finally {
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

// ============================================================================
// Test 2 — Authorization and lifecycle invariants
// ============================================================================

test('Phase 7.5 Integration - Authorization and lifecycle invariants: multi-tenant isolation, agent approval restriction, proposal status gate, invalid purge rejection, and failure atomicity', async () => {
  let testDir: string | null = null;
  let db: DatabaseManager | null = null;

  const scopeA = { scopeType: 'WORKSPACE' as const, scopeId: 'tenant-alpha' };
  const scopeB = { scopeType: 'WORKSPACE' as const, scopeId: 'tenant-beta' };

  const tokenAdminA = 'secret-token-admin-alpha-1122';
  const tokenUserA = 'secret-token-user-alpha-3344';
  const tokenAdminB = 'secret-token-admin-beta-5566';

  try {
    testDir = mkdtempSync(join(tmpdir(), 'dots-p75-invariants-'));
    const testDiskDb = join(testDir, 'invariants.db');
    const testWorkspace = join(testDir, 'workspace');
    mkdirSync(testWorkspace, { recursive: true });

    db = new DatabaseManager(testDiskDb);
    const taskRepo = new TaskRepository(db);
    const auditRepo = new AuditRepository(db);
    const memoryRepo = new MemoryRepository(db);

    const idProvider = new MockIdentityProvider();
    idProvider.register(tokenAdminA, {
      principalId: 'admin-alpha',
      role: 'ADMIN',
      permittedScopes: [scopeA]
    });
    idProvider.register(tokenUserA, {
      principalId: 'user-alpha',
      role: 'MEMBER',
      permittedScopes: [scopeA]
    });
    idProvider.register(tokenAdminB, {
      principalId: 'admin-beta',
      role: 'ADMIN',
      permittedScopes: [scopeB]
    });

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
    const policyEngine = new PolicyEngine({ workspaceRoot: testWorkspace, autoApproveTier2: true });
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
      workspaceRoot: testWorkspace,
      memoryService,
      hostAuthority
    });

    // Authorize caller contexts
    const adminCallerA = authorizer.authorizeUser({ credentials: tokenAdminA, requestedScope: scopeA });
    const userCallerA = authorizer.authorizeUser({ credentials: tokenUserA, requestedScope: scopeA });
    const adminCallerB = authorizer.authorizeUser({ credentials: tokenAdminB, requestedScope: scopeB });

    // -------------------------------------------------------------------------
    // 1. Cross-Tenant Isolation: User B cannot read, decide, export, archive, or delete Tenant A memory
    // -------------------------------------------------------------------------
    const memoryA = memoryService.createMemory(adminCallerA, {
      key: 'tenant.alpha.confidential_config',
      content: 'Confidential configuration data for Tenant Alpha',
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: 'tenant-alpha',
      status: 'ACTIVE'
    });

    // Tenant A agent proposal
    const taskA = await coordinator.submitScopedTask({
      goal: 'Propose procedure for Tenant Alpha',
      caller: adminCallerA,
      requestedScope: scopeA
    });

    modelProvider.enqueuePlan([
      {
        stepOrder: 1,
        description: 'Propose procedure',
        toolName: MEMORY_PROPOSE_TOOL_NAME,
        arguments: {
          key: 'tenant.alpha.procedure',
          content: 'Alpha procedure guidelines',
          category: 'LEARNED_PROCEDURE'
        },
        expectedOutcome: 'Proposal registered'
      }
    ]);

    await coordinator.runToCompletion(taskA.id, 20);
    const proposalA = memoryRepo.getMemoryByKey('tenant.alpha.procedure', scopeA, 'PENDING_APPROVAL');
    assert.ok(proposalA, 'Proposal A must be in PENDING_APPROVAL');

    // Tenant B cross-scope read attempts must fail
    assert.throws(
      () => memoryService.getMemoryById(adminCallerB, memoryA.id),
      MemoryScopeViolationError,
      'User B must not be permitted to read Tenant A active memory'
    );
    assert.throws(
      () => memoryService.getMemoryById(adminCallerB, proposalA.id),
      MemoryScopeViolationError,
      'User B must not be permitted to read Tenant A proposal'
    );

    // Tenant B cross-scope decision attempt must fail
    assert.throws(
      () => memoryService.decideProposal(adminCallerB, { memoryId: proposalA.id, decision: 'APPROVED' }),
      MemoryScopeViolationError,
      'User B must not be permitted to decide Tenant A proposal'
    );

    // Tenant B cross-scope export attempt must fail
    assert.throws(
      () => memoryService.exportMemories(adminCallerB, { scopeType: 'WORKSPACE', scopeId: 'tenant-alpha' }),
      MemoryScopeViolationError,
      'User B must not be permitted to export Tenant A scope'
    );

    // Tenant B cross-scope archive and delete attempts must fail
    assert.throws(
      () => memoryService.archiveMemory(adminCallerB, memoryA.id),
      MemoryScopeViolationError,
      'User B must not be permitted to archive Tenant A memory'
    );
    assert.throws(
      () => memoryService.deleteMemory(adminCallerB, memoryA.id),
      MemoryScopeViolationError,
      'User B must not be permitted to delete Tenant A memory'
    );

    // Verify Tenant A records remain unchanged
    const memoryACheck = memoryRepo.getMemoryById(memoryA.id, scopeA);
    assert.ok(memoryACheck);
    assert.equal(memoryACheck.status, 'ACTIVE');

    const proposalACheck = memoryRepo.getMemoryById(proposalA.id, scopeA);
    assert.ok(proposalACheck);
    assert.equal(proposalACheck.status, 'PENDING_APPROVAL');

    // -------------------------------------------------------------------------
    // 2. Autonomous Agent Cannot Approve Own Proposal
    // -------------------------------------------------------------------------
    const agentCallerA = authorizer.authorizeAgent({ taskId: taskA.id });
    assert.throws(
      () => memoryService.decideProposal(agentCallerA, { memoryId: proposalA.id, decision: 'APPROVED' }),
      SecurityViolationError,
      'Agents must be strictly forbidden from approving memory proposals'
    );
    assert.equal(
      memoryRepo.getMemoryById(proposalA.id, scopeA)!.status,
      'PENDING_APPROVAL',
      'Proposal must remain PENDING_APPROVAL after rejected agent attempt'
    );

    // -------------------------------------------------------------------------
    // 3. Agent-Supplied Status Cannot Bypass PENDING_APPROVAL Gate
    // -------------------------------------------------------------------------
    // Direct createMemory by agent caller with ACTIVE status is rejected
    assert.throws(
      () => memoryService.createMemory(agentCallerA, {
        key: 'agent.direct.bypass',
        content: 'Bypass attempt',
        category: 'PROJECT_FACT',
        scopeType: 'WORKSPACE',
        scopeId: 'tenant-alpha',
        status: 'ACTIVE'
      }),
      SecurityViolationError,
      'Agent cannot directly create ACTIVE memories'
    );

    // -------------------------------------------------------------------------
    // 4. Archiving or Deleting Cannot Bypass Proposal Required Approval State
    // -------------------------------------------------------------------------
    assert.throws(
      () => memoryService.archiveMemory(adminCallerA, proposalA.id),
      SecurityViolationError,
      'Cannot archive a pending proposal directly'
    );
    assert.throws(
      () => memoryService.deleteMemory(adminCallerA, proposalA.id),
      SecurityViolationError,
      'Cannot delete a pending proposal directly'
    );
    assert.throws(
      () => memoryService.updateMemory(adminCallerA, proposalA.id, { status: 'ACTIVE' }),
      SecurityViolationError,
      'Cannot transition status of a pending proposal via updateMemory'
    );
    assert.equal(
      memoryRepo.getMemoryById(proposalA.id, scopeA)!.status,
      'PENDING_APPROVAL',
      'Proposal must remain PENDING_APPROVAL after invalid transition attempts'
    );

    // -------------------------------------------------------------------------
    // 5. Invalid Purge Cutoffs Rejected Without Deleting Eligible Records
    // -------------------------------------------------------------------------
    // Archive memoryA so that an archived record exists
    memoryService.archiveMemory(adminCallerA, memoryA.id);
    const archivedCheck = memoryRepo.getMemoryById(memoryA.id, scopeA);
    assert.ok(archivedCheck);
    assert.equal(archivedCheck.status, 'ARCHIVED');

    // Invalid non-ISO timestamp
    assert.throws(
      () => memoryService.purgeArchivedMemories(adminCallerA, { olderThan: 'INVALID-TIMESTAMP' }),
      ValidationError
    );

    // Non-UTC timezone offset (+02:00)
    assert.throws(
      () => memoryService.purgeArchivedMemories(adminCallerA, { olderThan: '2026-10-19T12:00:00+02:00' }),
      ValidationError
    );

    // Missing Z suffix
    assert.throws(
      () => memoryService.purgeArchivedMemories(adminCallerA, { olderThan: '2026-10-19 12:00:00' }),
      ValidationError
    );

    // Calendar rollover (Feb 30)
    assert.throws(
      () => memoryService.purgeArchivedMemories(adminCallerA, { olderThan: '2026-02-30T00:00:00.000Z' }),
      ValidationError
    );

    // Verify archived record is NOT deleted after invalid purge attempts
    const archivedStillExists = memoryRepo.getMemoryById(memoryA.id, scopeA);
    assert.ok(archivedStillExists, 'Archived memory must survive invalid purge attempts without deletion');
    assert.equal(archivedStillExists.status, 'ARCHIVED');

    // -------------------------------------------------------------------------
    // 6. Inspect Actual Persisted Denial Audit Events
    // -------------------------------------------------------------------------
    interface SqlDenialRow {
      readonly id: number;
      readonly event_type: string;
      readonly details_json: string;
    }

    const denialRows = db.prepare(
      "SELECT id, event_type, details_json FROM audit_events WHERE event_type = 'MEMORY_ACCESS_DENIED' ORDER BY id ASC"
    ).all() as unknown as SqlDenialRow[];

    assert.ok(denialRows.length >= 4, 'Expected multiple MEMORY_ACCESS_DENIED audit events for rejected attempts');
    for (const d of denialRows) {
      // Must not leak unverified foreign tenant keys or raw content
      assert.equal(d.details_json.includes('Confidential configuration data'), false);
      assert.equal(d.details_json.includes(tokenAdminA), false);
      assert.equal(d.details_json.includes(tokenAdminB), false);
    }
  } finally {
    try {
      if (db?.isOpen) db.close();
    } finally {
      if (testDir && existsSync(testDir)) {
        rmSync(testDir, { recursive: true, force: true });
      }
    }
  }
});
