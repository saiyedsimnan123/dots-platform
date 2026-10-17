/**
 * Next-Generation Dots AI Platform - Multi-Step Workflow Integration Test
 * 
 * Verifies end-to-end multi-step DAG execution, output variable chaining across steps,
 * host verification of every step, and final state completion.
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

const testWorkspace = resolve('test_multistep_workspace');

test('Multi-Step Workflow - executes 4-step pipeline chaining outputs and verifying evidence', async () => {
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
    workspaceRoot: testWorkspace
  });

  try {
    const task = await coordinator.submitTask('Compute total, format summary, write file, and hash evidence');
    const destinationPath = resolve(testWorkspace, 'final_summary.txt');

    // Enqueue 4-step plan with variable chaining
    modelProvider.enqueuePlan([
      {
        stepOrder: 1,
        description: 'Calculate subtotal',
        toolName: 'calculate',
        arguments: { expression: '25 * 4' },
        expectedOutcome: 'Subtotal computed'
      },
      {
        stepOrder: 2,
        description: 'Format report text',
        toolName: 'text_transform',
        arguments: {
          operation: 'uppercase',
          text: 'Verified Total: {{steps[1].result}} credits'
        },
        expectedOutcome: 'Text formatted'
      },
      {
        stepOrder: 3,
        description: 'Write summary report to disk',
        toolName: 'file_write',
        arguments: {
          path: destinationPath,
          content: '{{steps[2].result}}'
        },
        expectedOutcome: 'File written'
      },
      {
        stepOrder: 4,
        description: 'Compute SHA-256 digest of summary file',
        toolName: 'hash_file',
        arguments: {
          path: '{{steps[3].path}}',
          algorithm: 'sha256'
        },
        expectedOutcome: 'Hash calculated'
      }
    ]);

    // Run coordinator loop
    const completedTask = await coordinator.runToCompletion(task.id, 50);

    // 1. Verify Task Status
    assert.equal(completedTask.status, 'COMPLETED');
    assert.ok(completedTask.completedAt !== null);

    // 2. Verify all 4 steps reached VERIFIED status
    const steps = taskRepo.getStepsByTaskId(task.id);
    assert.equal(steps.length, 4);
    for (const step of steps) {
      assert.equal(step.status, 'VERIFIED', `Step ${step.stepOrder} was not verified`);
    }

    // 3. Verify disk side effects
    assert.ok(existsSync(destinationPath));
    const fileContent = readFileSync(destinationPath, 'utf8');
    assert.equal(fileContent, 'VERIFIED TOTAL: 100 CREDITS');

    // 4. Verify tool executions and chaining
    const step4Execs = taskRepo.getToolExecutionsByStepId(steps[3]!.id);
    assert.equal(step4Execs.length, 1);
    const step4Output = JSON.parse(step4Execs[0]!.outputJson) as { hash: string; algorithm: string };
    assert.equal(step4Output.algorithm, 'sha256');
    assert.ok(step4Output.hash.length === 64);

    // 5. Verify audit trail covers all steps
    const auditEvents = auditRepo.getEventsByTaskId(task.id);
    const completedToolEvents = auditEvents.filter((e) => e.eventType === 'TOOL_EXECUTION_COMPLETED');
    assert.equal(completedToolEvents.length, 4);

    const verifiedEvents = auditEvents.filter((e) => e.eventType === 'EVIDENCE_VERIFIED');
    assert.equal(verifiedEvents.length, 4);
  } finally {
    db.close();
    if (existsSync(testWorkspace)) rmSync(testWorkspace, { recursive: true, force: true });
  }
});
