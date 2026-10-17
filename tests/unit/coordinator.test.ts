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
import { MockModelProvider } from '../../src/model/mock-provider.ts';
import { ToolRegistry } from '../../src/tools/registry.ts';
import { PolicyEngine } from '../../src/security/policy-engine.ts';
import { ApprovalBroker } from '../../src/security/approval-broker.ts';
import { VerificationEngine } from '../../src/verification/verifier.ts';
import { TokenBudgetTracker } from '../../src/model/budget-tracker.ts';
import { TaskCoordinator } from '../../src/orchestrator/coordinator.ts';

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
