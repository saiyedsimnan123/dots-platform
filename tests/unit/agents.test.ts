/**
 * Next-Generation Dots AI Platform - Shared Agent Interface Unit Tests
 * Phase 1 / Phase 3 Agent Architecture Foundation
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { resolve } from 'node:path';
import { existsSync, rmSync, mkdirSync, writeFileSync } from 'node:fs';
import { DatabaseManager } from '../../src/storage/db.ts';
import { TaskRepository } from '../../src/storage/task-repository.ts';
import { AuditRepository } from '../../src/storage/audit-repository.ts';
import { MockModelProvider } from '../../src/model/mock-provider.ts';
import { ToolRegistry } from '../../src/tools/registry.ts';
import { standardTools } from '../../src/tools/sandbox-tools.ts';
import { PolicyEngine } from '../../src/security/policy-engine.ts';
import { ApprovalBroker } from '../../src/security/approval-broker.ts';
import { VerificationEngine } from '../../src/verification/verifier.ts';
import { TokenBudgetTracker } from '../../src/model/budget-tracker.ts';
import { TaskCoordinator } from '../../src/orchestrator/coordinator.ts';
import {
  BaseAgent,
  MockAgent,
  AgentRegistry,
  createAgentExecutionContext,
  type AgentInput,
  type AgentOutput,
  type AgentExecutionContext,
  type IAgent
} from '../../src/agents/index.ts';
import {
  ValidationError,
  SecurityViolationError,
  AgentNotFoundError,
  DuplicateAgentRegistrationError,
  AgentCapabilityError,
  AgentCancelledError
} from '../../src/domain/errors.ts';

const testWorkspace = resolve('test_agents_workspace');

function createTestHarness(autoApproveTier2 = true) {
  if (existsSync(testWorkspace)) {
    rmSync(testWorkspace, { recursive: true, force: true });
  }
  mkdirSync(testWorkspace, { recursive: true });

  const db = new DatabaseManager(':memory:');
  const taskRepo = new TaskRepository(db);
  const auditRepo = new AuditRepository(db);
  const modelProvider = new MockModelProvider();
  const toolRegistry = new ToolRegistry(standardTools);
  const policyEngine = new PolicyEngine({ workspaceRoot: testWorkspace, autoApproveTier2 });
  const approvalBroker = new ApprovalBroker(taskRepo, auditRepo);
  const verifier = new VerificationEngine(taskRepo);
  const budgetTracker = new TokenBudgetTracker({ db, maxCostPerTaskUsd: 1.0 });
  const agentRegistry = new AgentRegistry();

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
    agentRegistry
  });

  return {
    db,
    taskRepo,
    auditRepo,
    modelProvider,
    toolRegistry,
    policyEngine,
    approvalBroker,
    verifier,
    budgetTracker,
    agentRegistry,
    coordinator,
    workspaceRoot: testWorkspace
  };
}

test('BaseAgent - validates parameters and manages lifecycle and capabilities', () => {
  // Rejects invalid options
  assert.throws(
    () => new MockAgent({ id: '' }),
    (err: unknown) => err instanceof ValidationError && err.message.includes('Agent ID')
  );
  assert.throws(
    () => new MockAgent({ name: '   ' }),
    (err: unknown) => err instanceof ValidationError && err.message.includes('Agent name')
  );

  const agent = new MockAgent({
    id: 'agent-alpha',
    name: 'Agent Alpha',
    description: 'A test agent',
    version: '1.2.0',
    capabilities: ['research', 'Developer', 'custom_tool']
  });

  assert.equal(agent.id, 'agent-alpha');
  assert.equal(agent.name, 'Agent Alpha');
  assert.equal(agent.description, 'A test agent');
  assert.equal(agent.version, '1.2.0');
  assert.equal(agent.status, 'IDLE');

  // Case-insensitive capability check
  assert.equal(agent.supportsCapability('research'), true);
  assert.equal(agent.supportsCapability('RESEARCH'), true);
  assert.equal(agent.supportsCapability('developer'), true);
  assert.equal(agent.supportsCapability('DEVELOPER'), true);
  assert.equal(agent.supportsCapability('custom_tool'), true);
  assert.equal(agent.supportsCapability('analytics'), false);
  assert.equal(agent.supportsCapability(''), false);

  // Immutability of capabilities
  assert.throws(() => {
    (agent.capabilities as string[]).push('new_cap');
  });
});

test('AgentRegistry - registration, retrieval, and listing', () => {
  const registry = new AgentRegistry();

  const agent1 = new MockAgent({ id: 'agent-1', name: 'Agent One', capabilities: ['general'] });
  const agent2 = new MockAgent({ id: 'agent-2', name: 'Agent Two', capabilities: ['research', 'analytics'] });

  registry.register(agent1);
  registry.register(agent2);

  assert.equal(registry.has('agent-1'), true);
  assert.equal(registry.has('agent-2'), true);
  assert.equal(registry.has('agent-3'), false);

  assert.equal(registry.get('agent-1'), agent1);
  assert.equal(registry.get('agent-2'), agent2);
  assert.equal(registry.get('non-existent'), undefined);

  assert.equal(registry.getOrThrow('agent-1'), agent1);
  assert.throws(
    () => registry.getOrThrow('non-existent'),
    (err: unknown) => err instanceof AgentNotFoundError && err.code === 'AGENT_NOT_FOUND'
  );

  const list = registry.list();
  assert.equal(list.length, 2);
  assert.deepEqual(list.map((a) => a.id), ['agent-1', 'agent-2']);

  const definitions = registry.listDefinitions();
  assert.equal(definitions.length, 2);
  assert.equal(definitions[0].id, 'agent-1');
  assert.equal(definitions[0].name, 'Agent One');

  // Unregister
  assert.equal(registry.unregister('agent-1'), true);
  assert.equal(registry.has('agent-1'), false);
  assert.equal(registry.unregister('agent-1'), false);
});

test('AgentRegistry - duplicate registration rejection', () => {
  const registry = new AgentRegistry();
  const agent1 = new MockAgent({ id: 'agent-dup', name: 'Original' });
  const agent2 = new MockAgent({ id: 'agent-dup', name: 'Duplicate' });

  registry.register(agent1);
  assert.throws(
    () => registry.register(agent2),
    (err: unknown) =>
      err instanceof DuplicateAgentRegistrationError &&
      err.code === 'DUPLICATE_AGENT_REGISTRATION' &&
      err.message.includes('agent-dup')
  );
});

test('AgentRegistry - capability filtering and validation', () => {
  const registry = new AgentRegistry();
  const general = new MockAgent({ id: 'gen', name: 'General', capabilities: ['general'] });
  const researcher = new MockAgent({ id: 'res', name: 'Researcher', capabilities: ['research', 'analytics'] });
  const developer = new MockAgent({ id: 'dev', name: 'Developer', capabilities: ['developer', 'research'] });

  registry.register(general);
  registry.register(researcher);
  registry.register(developer);

  const researchers = registry.findByCapability('research');
  assert.equal(researchers.length, 2);
  assert.deepEqual(researchers.map((a) => a.id).sort(), ['dev', 'res']);

  const devs = registry.findByCapability('DEVELOPER');
  assert.equal(devs.length, 1);
  assert.equal(devs[0].id, 'dev');

  const none = registry.findByCapability('non_existent_cap');
  assert.equal(none.length, 0);

  // Validation
  assert.equal(registry.validateCapability('res', 'research'), true);
  assert.equal(registry.validateCapability('res', 'analytics'), true);

  assert.throws(
    () => registry.validateCapability('res', 'developer'),
    (err: unknown) =>
      err instanceof AgentCapabilityError &&
      err.code === 'UNSUPPORTED_CAPABILITY' &&
      err.capability === 'developer'
  );

  assert.throws(
    () => registry.validateCapability('unknown-agent', 'research'),
    (err: unknown) => err instanceof AgentNotFoundError
  );
});

test('AgentRegistry - successful execution and standardized result format', async () => {
  const harness = createTestHarness();
  const registry = harness.agentRegistry;

  const agent = new MockAgent({
    id: 'executor-1',
    name: 'Executor Agent',
    executeMock: async (input, context) => {
      return {
        agentId: 'executor-1',
        taskId: input.taskId ?? context.taskId,
        status: 'COMPLETED',
        result: { computed: 42, query: input.goal },
        summary: `Processed goal: ${input.goal}`,
        stepsExecuted: 2,
        durationMs: 15
      };
    }
  });

  registry.register(agent);

  const context = createAgentExecutionContext({
    taskId: 'task-100',
    workspaceRoot: harness.workspaceRoot,
    toolRegistry: harness.toolRegistry,
    policyEngine: harness.policyEngine
  });

  const output = await registry.execute('executor-1', { goal: 'Calculate metrics' }, context);

  assert.equal(output.agentId, 'executor-1');
  assert.equal(output.taskId, 'task-100');
  assert.equal(output.status, 'COMPLETED');
  assert.equal(output.result.computed, 42);
  assert.equal(output.result.query, 'Calculate metrics');
  assert.equal(output.summary, 'Processed goal: Calculate metrics');
  assert.equal(output.stepsExecuted, 2);
  assert.equal(output.durationMs >= 0, true);

  // Input validation
  await assert.rejects(
    async () => registry.execute('executor-1', { goal: '   ' }, context),
    (err: unknown) => err instanceof ValidationError && err.message.includes('goal must be a non-empty')
  );
});

test('AgentRegistry - error containment without crashing runtime', async () => {
  const harness = createTestHarness();
  const registry = harness.agentRegistry;

  const failingAgent = new MockAgent({
    id: 'fail-agent',
    name: 'Failing Agent',
    executeMock: async () => {
      throw new Error('Internal database unreachable in agent worker');
    }
  });

  registry.register(failingAgent);

  const context = createAgentExecutionContext({
    taskId: 'task-fail',
    workspaceRoot: harness.workspaceRoot,
    toolRegistry: harness.toolRegistry,
    policyEngine: harness.policyEngine
  });

  // Must not throw an unhandled exception or crash
  const output = await registry.execute('fail-agent', { goal: 'Do dangerous action' }, context);

  assert.equal(output.agentId, 'fail-agent');
  assert.equal(output.taskId, 'task-fail');
  assert.equal(output.status, 'FAILED');
  assert.match(output.summary, /Internal database unreachable/);
  assert.match(output.error ?? '', /Internal database unreachable/);
  assert.equal(output.stepsExecuted, 0);
  assert.equal(output.durationMs >= 0, true);
});

test('AgentRegistry & BaseAgent - cancellation handling', async () => {
  const harness = createTestHarness();
  const registry = harness.agentRegistry;

  const agent = new MockAgent({
    id: 'cancel-agent',
    name: 'Cancellable Agent',
    executeMock: async (input, context) => {
      // Simulate checking cancellation midway
      if (input.signal?.aborted) {
        throw new AgentCancelledError('Aborted midway');
      }
      return {
        agentId: 'cancel-agent',
        status: 'COMPLETED',
        result: {},
        summary: 'Done',
        stepsExecuted: 1,
        durationMs: 5
      };
    }
  });

  registry.register(agent);

  const context = createAgentExecutionContext({
    taskId: 'task-cancel',
    workspaceRoot: harness.workspaceRoot,
    toolRegistry: harness.toolRegistry,
    policyEngine: harness.policyEngine
  });

  // 1. Pre-flight cancellation
  const preAborted = new AbortController();
  preAborted.abort('User hit cancel');

  const preOutput = await registry.execute(
    'cancel-agent',
    { goal: 'Long running query', signal: preAborted.signal },
    context
  );

  assert.equal(preOutput.status, 'CANCELLED');
  assert.match(preOutput.summary, /cancelled before start/);
  assert.match(preOutput.error ?? '', /User hit cancel/);

  // 2. Mid-flight cancellation
  const midAborted = new AbortController();
  const cancellableAgent = new MockAgent({
    id: 'mid-cancel-agent',
    executeMock: async (input, ctx) => {
      midAborted.abort('Cancelled during step 2');
      if (input.signal?.aborted || ctx.signal?.aborted) {
        throw new AgentCancelledError('Aborted by signal');
      }
      return {
        agentId: 'mid-cancel-agent',
        status: 'COMPLETED',
        result: {},
        summary: 'Done',
        stepsExecuted: 1,
        durationMs: 5
      };
    }
  });

  registry.register(cancellableAgent);

  const midOutput = await registry.execute(
    'mid-cancel-agent',
    { goal: 'Stepwise task', signal: midAborted.signal },
    context
  );

  assert.equal(midOutput.status, 'CANCELLED');
  assert.equal(cancellableAgent.status, 'CANCELLED');
});

test('AgentExecutionContext - safe tool execution, risk tier policy, and approval gates', async () => {
  const harness = createTestHarness(false); // autoApproveTier2 = false
  const testFile = resolve(harness.workspaceRoot, 'safe_file.txt');
  writeFileSync(testFile, 'initial test data', 'utf-8');

  // Create real task & step for foreign key constraints on approval requests
  const secTask = harness.taskRepo.createTask({ goal: 'Security test task' });
  const secStep = harness.taskRepo.createStep({
    taskId: secTask.id,
    stepOrder: 1,
    description: 'Fetch remote documentation',
    toolName: 'web_fetch',
    toolArguments: { url: 'https://example.com' }
  });

  const context = createAgentExecutionContext({
    taskId: secTask.id,
    workspaceRoot: harness.workspaceRoot,
    toolRegistry: harness.toolRegistry,
    policyEngine: harness.policyEngine,
    approvalBroker: harness.approvalBroker
  });

  // 1. Safe Tier 1 read tool inside workspace succeeds
  const readResult = await context.executeTool('file_read', { path: 'safe_file.txt' });
  assert.equal(readResult.exitCode, 0);
  assert.equal(readResult.output.content, 'initial test data');

  // 2. Path traversal attack strictly blocked
  await assert.rejects(
    async () => context.executeTool('file_read', { path: '../../etc/passwd' }),
    (err: unknown) => err instanceof SecurityViolationError && err.code === 'SECURITY_VIOLATION'
  );

  // 3. Tier 3 tool (web_fetch) without approval token strictly blocked
  await assert.rejects(
    async () => context.executeTool('web_fetch', { url: 'https://example.com' }),
    (err: unknown) =>
      err instanceof SecurityViolationError &&
      (err.violationType === 'APPROVAL_REQUIRED' || err.code === 'SECURITY_VIOLATION')
  );

  // 4. Tier 3 tool with valid approved token succeeds
  const req = harness.approvalBroker.requestApproval({
    taskId: secTask.id,
    stepId: secStep.id,
    riskTier: 'TIER_3',
    actionSummary: 'Fetch remote documentation',
    targetResource: 'https://example.com',
    parameterDiff: { url: 'https://example.com' }
  });

  harness.approvalBroker.submitDecision(req.approvalToken, 'APPROVED', 'test-operator');

  // executeTool with approved token
  const approvedResult = await context.executeTool(
    'web_fetch',
    { url: 'https://example.com' },
    req.approvalToken
  );
  assert.equal(approvedResult.exitCode, 0);
  assert.equal(approvedResult.output.url, 'https://example.com');
});

test('TaskCoordinator - executeAgent end-to-end integration', async () => {
  const harness = createTestHarness();
  const coordinator = harness.coordinator;

  const agent = new MockAgent({
    id: 'researcher-agent',
    name: 'Research Agent',
    capabilities: ['research'],
    executeMock: async (input, context) => {
      // Agent reads a file using safe context
      const filePath = resolve(harness.workspaceRoot, 'input.txt');
      writeFileSync(filePath, 'Research notes for goal', 'utf-8');

      const toolRes = await context.executeTool('file_read', { path: 'input.txt' });
      return {
        agentId: 'researcher-agent',
        taskId: input.taskId ?? context.taskId,
        status: 'COMPLETED',
        result: {
          findings: `Analyzed: ${toolRes.output.content}`,
          goal: input.goal
        },
        summary: 'Research completed successfully.',
        stepsExecuted: 1,
        durationMs: 25
      };
    }
  });

  coordinator.agentRegistry.register(agent);

  const output = await coordinator.executeAgent('researcher-agent', {
    goal: 'Analyze market trends'
  });

  assert.equal(output.agentId, 'researcher-agent');
  assert.equal(output.status, 'COMPLETED');
  assert.match(String(output.result.findings), /Analyzed: Research notes/);

  // Verify task was created and transitioned to COMPLETED in database
  assert.ok(output.taskId);
  const task = harness.taskRepo.getTaskById(output.taskId!);
  assert.ok(task);
  assert.equal(task.status, 'COMPLETED');
  assert.equal(task.goal, 'Analyze market trends');

  // Verify audit events
  const events = harness.auditRepo.getEventsByTaskId(task.id);
  const eventTypes = events.map((e) => e.eventType);

  assert.ok(eventTypes.includes('TASK_CREATED'));
  assert.ok(eventTypes.includes('AGENT_EXECUTION_STARTED'));
  assert.ok(eventTypes.includes('AGENT_EXECUTION_COMPLETED'));
});

test('TaskCoordinator - step() and runToCompletion() support agent delegation via metadata', async () => {
  const harness = createTestHarness();
  const coordinator = harness.coordinator;

  const agent = new MockAgent({
    id: 'delegated-agent',
    name: 'Delegated Agent',
    capabilities: ['general'],
    executeMock: async (input, context) => {
      return {
        agentId: 'delegated-agent',
        taskId: input.taskId ?? context.taskId,
        status: 'COMPLETED',
        result: { completedBy: 'delegated-agent' },
        summary: 'Agent delegation worked perfectly.',
        stepsExecuted: 1,
        durationMs: 10
      };
    }
  });

  coordinator.agentRegistry.register(agent);

  // Submit task with agentId metadata
  const task = await coordinator.submitTask('Perform delegated task', {
    agentId: 'delegated-agent'
  });

  assert.equal(task.status, 'SUBMITTED');

  // runToCompletion delegates to agent and runs through state machine
  const finalTask = await coordinator.runToCompletion(task.id);

  assert.equal(finalTask.status, 'COMPLETED');

  const events = harness.auditRepo.getEventsByTaskId(task.id);
  const eventTypes = events.map((e) => e.eventType);

  assert.ok(eventTypes.includes('TASK_CREATED'));
  assert.ok(eventTypes.includes('AGENT_EXECUTION_STARTED'));
  assert.ok(eventTypes.includes('AGENT_EXECUTION_COMPLETED'));
});

test('TaskCoordinator - executeAgent records failure and cancelled states accurately', async () => {
  const harness = createTestHarness();
  const coordinator = harness.coordinator;

  // Failing agent
  const failingAgent = new MockAgent({
    id: 'error-agent',
    executeMock: async () => {
      throw new Error('API Rate limit exceeded in agent');
    }
  });
  coordinator.agentRegistry.register(failingAgent);

  const failOutput = await coordinator.executeAgent('error-agent', {
    goal: 'Run query'
  });

  assert.equal(failOutput.status, 'FAILED');
  const failTask = harness.taskRepo.getTaskById(failOutput.taskId!);
  assert.ok(failTask);
  assert.equal(failTask.status, 'FAILED');

  const failEvents = harness.auditRepo.getEventsByTaskId(failTask.id);
  assert.ok(failEvents.some((e) => e.eventType === 'AGENT_EXECUTION_FAILED'));

  // Cancelled agent
  const cancelledController = new AbortController();
  cancelledController.abort('Manual abort');

  const cancelOutput = await coordinator.executeAgent(
    'error-agent',
    {
      goal: 'Cancelled query',
      signal: cancelledController.signal
    }
  );

  assert.equal(cancelOutput.status, 'CANCELLED');
  const cancelTask = harness.taskRepo.getTaskById(cancelOutput.taskId!);
  assert.ok(cancelTask);
  assert.equal(cancelTask.status, 'CANCELLED');

  const cancelEvents = harness.auditRepo.getEventsByTaskId(cancelTask.id);
  assert.ok(cancelEvents.some((e) => e.eventType === 'TASK_CANCELLED'));
});
