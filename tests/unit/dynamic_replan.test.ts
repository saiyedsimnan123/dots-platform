/**
 * Next-Generation Dots AI Platform - Dynamic Replanning & Circuit Breakers Unit Tests
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { resolve } from 'node:path';
import { existsSync, rmSync, mkdirSync, readFileSync } from 'node:fs';
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

const testWorkspace = resolve('test_replan_workspace');

function setupHarness(enableDynamicReplan = true, maxPlanSteps = 8, maxTotalRetries = 5, enableCompensation = false) {
  if (existsSync(testWorkspace)) rmSync(testWorkspace, { recursive: true, force: true });
  mkdirSync(testWorkspace, { recursive: true });

  const db = new DatabaseManager(':memory:');
  const taskRepo = new TaskRepository(db);
  const auditRepo = new AuditRepository(db);
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
    enableDynamicReplan,
    maxPlanSteps,
    maxTotalRetries,
    enableCompensation
  });

  return {
    db, taskRepo, auditRepo, modelProvider, toolRegistry,
    policyEngine, approvalBroker, verifier, budgetTracker, coordinator
  };
}

test('Dynamic Replanning - recovers from exhausted step failure by generating and executing recovery plan', async () => {
  const harness = setupHarness(true);

  // Register a faulty tool that always fails
  harness.toolRegistry.register({
    definition: {
      name: 'broken_network_fetch',
      description: 'Simulates network service downtime',
      parameters: {}
    },
    riskTier: 'TIER_1',
    handler: async () => {
      throw new Error('Connection refused: remote gateway timed out');
    }
  });

  try {
    const task = await harness.coordinator.submitTask('Fetch data or compute fallback');

    // 1. Initial plan: step 1 calls broken_network_fetch
    harness.modelProvider.enqueuePlan([
      {
        stepOrder: 1,
        description: 'Attempt network fetch',
        toolName: 'broken_network_fetch',
        arguments: {},
        expectedOutcome: 'Data fetched'
      }
    ]);

    // 2. Recovery plan: enqueued for the dynamic replanning call
    harness.modelProvider.enqueuePlan([
      {
        stepOrder: 1,
        description: 'Execute local fallback computation',
        toolName: 'calculate',
        arguments: { expression: '500 + 42' },
        expectedOutcome: 'Fallback value computed'
      }
    ]);

    const completed = await harness.coordinator.runToCompletion(task.id, 30);
    assert.equal(completed.status, 'COMPLETED');

    const steps = harness.taskRepo.getStepsByTaskId(task.id);
    assert.equal(steps.length, 2);

    // Step 1 was marked SKIPPED after retries exhausted
    assert.equal(steps[0]!.toolName, 'broken_network_fetch');
    assert.equal(steps[0]!.status, 'SKIPPED');

    // Step 2 was appended dynamically and VERIFIED
    assert.equal(steps[1]!.toolName, 'calculate');
    assert.equal(steps[1]!.status, 'VERIFIED');

    // Verify audit event for replanning
    const events = harness.auditRepo.getEventsByTaskId(task.id);
    const replanEvents = events.filter((e) => e.eventType === 'DYNAMIC_REPLAN_ATTEMPTED');
    assert.equal(replanEvents.length, 1);
  } finally {
    harness.db.close();
    if (existsSync(testWorkspace)) rmSync(testWorkspace, { recursive: true, force: true });
  }
});

test('Circuit Breaker - fails task when maxPlanSteps limit is breached during planning', async () => {
  const harness = setupHarness(false, 3); // maxPlanSteps = 3

  try {
    const task = await harness.coordinator.submitTask('Massive workflow exceeding limit');

    // Plan with 4 steps breaches limit of 3
    harness.modelProvider.enqueuePlan([
      { stepOrder: 1, description: 's1', toolName: 'calculate', arguments: { expression: '1' }, expectedOutcome: 'ok' },
      { stepOrder: 2, description: 's2', toolName: 'calculate', arguments: { expression: '2' }, expectedOutcome: 'ok' },
      { stepOrder: 3, description: 's3', toolName: 'calculate', arguments: { expression: '3' }, expectedOutcome: 'ok' },
      { stepOrder: 4, description: 's4', toolName: 'calculate', arguments: { expression: '4' }, expectedOutcome: 'ok' }
    ]);

    const finalTask = await harness.coordinator.runToCompletion(task.id, 10);
    assert.equal(finalTask.status, 'FAILED');
    assert.ok(finalTask.errorSummary?.includes('Plan exceeded maximum allowed step limit'));
  } finally {
    harness.db.close();
    if (existsSync(testWorkspace)) rmSync(testWorkspace, { recursive: true, force: true });
  }
});

test('Rollback Compensation - cleans up scratch files on task failure when enabled', async () => {
  const harness = setupHarness(false, 8, 5, true); // enableCompensation = true
  const scratchFile = resolve(testWorkspace, 'partial_result.txt');

  // Register tool that writes a file, followed by a tool that fails
  harness.toolRegistry.register({
    definition: {
      name: 'flaky_finisher',
      description: 'Fails execution',
      parameters: {}
    },
    riskTier: 'TIER_1',
    handler: async () => {
      throw new Error('Fatal mid-task crash');
    }
  });

  try {
    const task = await harness.coordinator.submitTask('Mutate and crash', { compensateOnFailure: true });

    harness.modelProvider.enqueuePlan([
      {
        stepOrder: 1,
        description: 'Write partial file',
        toolName: 'file_write',
        arguments: { path: scratchFile, content: 'will be rolled back' },
        expectedOutcome: 'Written'
      },
      {
        stepOrder: 2,
        description: 'Fatal crash',
        toolName: 'flaky_finisher',
        arguments: {},
        expectedOutcome: 'Failed'
      }
    ]);

    const finalTask = await harness.coordinator.runToCompletion(task.id, 25);
    assert.equal(finalTask.status, 'FAILED');

    // The scratch file written in step 1 should have been deleted by compensation rollback!
    assert.equal(existsSync(scratchFile), false);

    // Verify audit event
    const events = harness.auditRepo.getEventsByTaskId(task.id);
    const compEvents = events.filter((e) => e.eventType === 'COMPENSATION_EXECUTED');
    assert.equal(compEvents.length, 1);
  } finally {
    harness.db.close();
    if (existsSync(testWorkspace)) rmSync(testWorkspace, { recursive: true, force: true });
  }
});
