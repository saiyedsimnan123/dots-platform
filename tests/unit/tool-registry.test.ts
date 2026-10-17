/**
 * Next-Generation Dots AI Platform - Tool Registry Unit Tests
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { resolve } from 'node:path';
import { ToolRegistry } from '../../src/tools/registry.ts';
import { PolicyEngine } from '../../src/security/policy-engine.ts';
import { ApprovalBroker } from '../../src/security/approval-broker.ts';
import { DatabaseManager } from '../../src/storage/db.ts';
import { TaskRepository } from '../../src/storage/task-repository.ts';
import { ValidationError, SecurityViolationError } from '../../src/domain/errors.ts';

const testWorkspace = resolve('test_tool_registry_workspace');

test('ToolRegistry - lists all standard tool definitions', () => {
  const registry = new ToolRegistry();
  const defs = registry.listDefinitions();

  const names = defs.map((d) => d.name);
  assert.ok(names.includes('calculate'));
  assert.ok(names.includes('file_read'));
  assert.ok(names.includes('file_write'));
  assert.ok(names.includes('hash_file'));
  assert.ok(names.includes('file_list'));
});

test('ToolRegistry - throws ValidationError for unregistered tool', async () => {
  const registry = new ToolRegistry();
  const policyEngine = new PolicyEngine({ workspaceRoot: testWorkspace });

  await assert.rejects(
    async () => {
      await registry.execute('format_c_drive', {}, {
        taskId: 't1',
        stepId: 's1',
        workspaceRoot: testWorkspace
      }, policyEngine);
    },
    (err: unknown) => {
      assert(err instanceof ValidationError);
      assert.ok((err as ValidationError).message.includes('not registered'));
      return true;
    }
  );
});

test('ToolRegistry - blocks Tier 3 operation without approved token', async () => {
  const registry = new ToolRegistry();
  const policyEngine = new PolicyEngine({ workspaceRoot: testWorkspace });

  // Register simulated Tier 3 tool
  registry.register({
    definition: {
      name: 'send_webhook',
      description: 'Sends external webhook payload',
      parameters: { url: { type: 'string', description: 'URL' } }
    },
    riskTier: 'TIER_3',
    handler: async () => ({ output: { status: 'sent' }, exitCode: 0, durationMs: 5 })
  });

  // Attempt execution without approval token
  await assert.rejects(
    async () => {
      await registry.execute('send_webhook', { url: 'https://example.com' }, {
        taskId: 't1',
        stepId: 's1',
        workspaceRoot: testWorkspace
      }, policyEngine);
    },
    (err: unknown) => {
      assert(err instanceof SecurityViolationError);
      assert.equal((err as SecurityViolationError).violationType, 'APPROVAL_REQUIRED');
      return true;
    }
  );
});

test('ToolRegistry - permits Tier 3 operation when valid approval token is provided', async () => {
  const db = new DatabaseManager(':memory:');
  const taskRepo = new TaskRepository(db);
  const approvalBroker = new ApprovalBroker(taskRepo);
  const registry = new ToolRegistry();
  const policyEngine = new PolicyEngine({ workspaceRoot: testWorkspace });

  // Setup task and step in DB
  const task = taskRepo.createTask({ goal: 'Execute approved action' });
  const step = taskRepo.createStep({
    taskId: task.id,
    stepOrder: 1,
    description: 'Call webhook',
    toolName: 'send_webhook',
    toolArguments: { url: 'https://api.test' }
  });

  // Register Tier 3 tool
  registry.register({
    definition: {
      name: 'send_webhook',
      description: 'Sends webhook',
      parameters: { url: { type: 'string', description: 'URL' } }
    },
    riskTier: 'TIER_3',
    handler: async () => ({ output: { status: 'sent' }, exitCode: 0, durationMs: 10 })
  });

  // Request approval
  const approval = approvalBroker.requestApproval({
    taskId: task.id,
    stepId: step.id,
    riskTier: 'TIER_3',
    actionSummary: 'Send webhook to api.test',
    targetResource: 'https://api.test',
    parameterDiff: { url: 'https://api.test' }
  });

  // Submit approval
  approvalBroker.submitDecision(approval.approvalToken, 'APPROVED', 'operator-dan');

  // Execute with approved token
  const result = await registry.execute(
    'send_webhook',
    { url: 'https://api.test' },
    { taskId: task.id, stepId: step.id, workspaceRoot: testWorkspace },
    policyEngine,
    approvalBroker,
    approval.approvalToken
  );

  assert.equal(result.exitCode, 0);
  assert.equal(result.output.status, 'sent');

  db.close();
});
