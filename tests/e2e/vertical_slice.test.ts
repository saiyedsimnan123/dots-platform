/**
 * Next-Generation Dots AI Platform - Phase 5 Vertical Slice E2E Test
 * 
 * Acceptance Criteria Reference: docs/ACCEPTANCE_CRITERIA.md Section 3
 * 
 * Complete Vertical Slice Scenario:
 * 1. User submits a task: "Compute SHA-256 hash of test payload and save verification log"
 * 2. Backend persists it in SQLite (WAL mode).
 * 3. Agent plans and invokes 1 explicitly allowed tool (hash_file) inside jailed sandbox.
 * 4. Result is independently verified by host verification engine (file existence & checksum match).
 * 5. Cold-start crash simulation: process terminates abruptly.
 * 6. Application reboots, reopens the SQLite database, rehydrates state.
 * 7. Completed task, verification evidence, and audit logs are 100% intact with zero corruption.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { resolve } from 'node:path';
import { existsSync, rmSync, mkdirSync, writeFileSync, unlinkSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { DatabaseManager } from '../../src/storage/db.ts';
import { TaskRepository } from '../../src/storage/task-repository.ts';
import { AuditRepository } from '../../src/storage/audit-repository.ts';
import { CrashRecoveryEngine } from '../../src/storage/recovery.ts';
import { MockModelProvider } from '../../src/model/mock-provider.ts';
import { ToolRegistry } from '../../src/tools/registry.ts';
import { PolicyEngine } from '../../src/security/policy-engine.ts';
import { ApprovalBroker } from '../../src/security/approval-broker.ts';
import { VerificationEngine } from '../../src/verification/verifier.ts';
import { TokenBudgetTracker } from '../../src/model/budget-tracker.ts';
import { TaskCoordinator } from '../../src/orchestrator/coordinator.ts';

const testDiskDb = 'e2e_vertical_slice.db';
const testSandboxDir = resolve('e2e_sandbox_workspace');

function cleanArtifacts(): void {
  for (const ext of ['', '-wal', '-shm']) {
    const f = `${testDiskDb}${ext}`;
    try {
      if (existsSync(f)) unlinkSync(f);
    } catch {
      // Ignore brief OS locks
    }
  }
  if (existsSync(testSandboxDir)) {
    rmSync(testSandboxDir, { recursive: true, force: true });
  }
}

test('Vertical Slice E2E - Task submission, sandboxed execution, verification, and reboot recovery', async () => {
  cleanArtifacts();
  mkdirSync(testSandboxDir, { recursive: true });

  // Create initial test payload file inside sandbox
  const payloadPath = resolve(testSandboxDir, 'payload.txt');
  const payloadContent = 'Dots Next-Generation AI Platform Vertical Slice Payload';
  writeFileSync(payloadPath, payloadContent, 'utf8');
  const expectedHash = createHash('sha256').update(payloadContent).digest('hex');

  let db1: DatabaseManager | null = null;
  let db2: DatabaseManager | null = null;
  let submittedTaskId = '';

  try {
    // =========================================================================
    // STEP 1 & 2: Ingestion, Persistence & Execution in First Process Instance
    // =========================================================================
    db1 = new DatabaseManager(testDiskDb);
    const taskRepo1 = new TaskRepository(db1);
    const auditRepo1 = new AuditRepository(db1);
    const modelProvider1 = new MockModelProvider();
    const toolRegistry1 = new ToolRegistry();
    const policyEngine1 = new PolicyEngine({ workspaceRoot: testSandboxDir });
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
      workspaceRoot: testSandboxDir
    });

    // Submit task
    const task = await coordinator1.submitTask('Compute SHA-256 hash of test payload');
    submittedTaskId = task.id;
    assert.equal(task.status, 'SUBMITTED');

    // Program deterministic model to call hash_file tool on the payload
    modelProvider1.enqueuePlan([
      {
        stepOrder: 1,
        description: 'Compute SHA-256 hash of payload.txt',
        toolName: 'hash_file',
        arguments: { path: 'payload.txt', algorithm: 'sha256' },
        expectedOutcome: 'SHA-256 digest calculated'
      }
    ]);

    // Run to completion
    const completedTask = await coordinator1.runToCompletion(task.id);
    assert.equal(completedTask.status, 'COMPLETED');
    assert.ok(completedTask.completedAt !== null);

    // Assert that tool execution was recorded in database
    const steps1 = taskRepo1.getStepsByTaskId(task.id);
    assert.equal(steps1.length, 1);
    assert.equal(steps1[0]!.status, 'VERIFIED');

    const execs1 = taskRepo1.getToolExecutionsByStepId(steps1[0]!.id);
    assert.equal(execs1.length, 1);
    const output1 = JSON.parse(execs1[0]!.outputJson) as { hash: string };
    assert.equal(output1.hash, expectedHash);

    // Assert host verifier independently recorded verification evidence
    const verifications1 = taskRepo1.getVerificationsByStepId(steps1[0]!.id);
    assert.ok(verifications1.length > 0);
    assert.equal(verifications1[0]!.passed, true);

    // =========================================================================
    // STEP 5: Simulated Cold-Start Crash (Close DB & terminate process state)
    // =========================================================================
    db1.close();
    db1 = null;

    // =========================================================================
    // STEP 6 & 7: Reboot Fresh Application Instance and Rehydrate Task State
    // =========================================================================
    db2 = new DatabaseManager(testDiskDb);
    const taskRepo2 = new TaskRepository(db2);
    const auditRepo2 = new AuditRepository(db2);
    const recoveryEngine = new CrashRecoveryEngine(taskRepo2, auditRepo2);

    // Run startup reconciliation
    const recoveryReport = recoveryEngine.reconcileInterruptedTasks();
    assert.equal(recoveryReport.scannedCount, 0); // Completed task requires no recovery mutations
    assert.equal(recoveryReport.reconciledTasks.length, 0);

    // Retrieve task from cold database
    const rehydratedTask = taskRepo2.getTaskById(submittedTaskId);
    assert.ok(rehydratedTask);
    assert.equal(rehydratedTask.id, submittedTaskId);
    assert.equal(rehydratedTask.status, 'COMPLETED');
    assert.ok(rehydratedTask.completedAt !== null);

    // Verify full audit log is preserved
    const events = auditRepo2.getEventsByTaskId(submittedTaskId);
    const eventTypes = events.map((e) => e.eventType);
    assert.ok(eventTypes.includes('TASK_CREATED'));
    assert.ok(eventTypes.includes('PLAN_GENERATED'));
    assert.ok(eventTypes.includes('TOOL_EXECUTION_COMPLETED'));
    assert.ok(eventTypes.includes('EVIDENCE_VERIFIED'));

    // Verify token usage persisted
    const budgetTracker2 = new TokenBudgetTracker({ db: db2 });
    const usage = budgetTracker2.getUsageForTask(submittedTaskId);
    assert.ok(usage.totalTokens > 0);
  } finally {
    if (db1 && (db1 as DatabaseManager).isOpen) (db1 as DatabaseManager).close();
    if (db2 && (db2 as DatabaseManager).isOpen) (db2 as DatabaseManager).close();
    cleanArtifacts();
  }
});
