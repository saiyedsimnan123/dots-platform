/**
 * Next-Generation Dots AI Platform - Business Task Workflow Unit Tests
 * Milestone 2B: Business Task Workflows
 */

import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  DatabaseManager,
  TaskRepository,
  AuditRepository,
  MemoryRepository,
  ToolRegistry,
  standardTools,
  PolicyEngine,
  ApprovalBroker,
  VerificationEngine,
  TokenBudgetTracker,
  MemoryService,
  MockModelProvider,
  TaskCoordinator,
  AgentRegistry,
  BaseAgent,
  TaskWorkflowService,
  TokenIdentityProvider,
  DotsRuntime,
  type AgentInput,
  type AgentOutput,
  type AgentExecutionContext,
  type CallerContext,
  type AgentCapability
} from '../../src/index.ts';
import { HostMemoryAuthority } from '../../src/security/host-authority.ts';
import {
  AgentCapabilityError,
  AgentNotFoundError,
  InvalidStateTransitionError,
  SecurityViolationError,
  TaskNotFoundError,
  ValidationError
} from '../../src/domain/errors.ts';

const ADMIN_TOKEN = 'admin-secret-token-123456';
const MEMBER_TOKEN = 'member-secret-token-123456';
const VIEWER_TOKEN = 'viewer-secret-token-123456';
const WS2_MEMBER_TOKEN = 'ws2-member-secret-token-123456';

function createTempDir(): string {
  return mkdtempSync(join(tmpdir(), 'dots-biztask-unit-'));
}

class TestBusinessAgent extends BaseAgent {
  public override async execute(input: AgentInput, context: AgentExecutionContext): Promise<AgentOutput> {
    const params = input.parameters ?? {};
    return {
      agentId: this.id,
      status: 'COMPLETED',
      summary: `Processed business task: ${input.goal}`,
      result: {
        analysis: 'success',
        receivedParams: params,
        secretInput: input.parameters?.secretApiKey ? 'REDACTED' : 'clean'
      },
      stepsExecuted: 2,
      durationMs: 42
    };
  }
}

class FailingAgent extends BaseAgent {
  public override async execute(): Promise<AgentOutput> {
    return {
      agentId: this.id,
      status: 'FAILED',
      summary: 'Task processing failed due to upstream timeout',
      error: 'Upstream payment gateway timeout',
      result: {},
      stepsExecuted: 1,
      durationMs: 15
    };
  }
}

class ApprovalRequiringAgent extends BaseAgent {
  public override async execute(input: AgentInput, context: AgentExecutionContext): Promise<AgentOutput> {
    // Attempt Tier 3 operation: web_search without approval token
    await context.executeTool('web_search', { query: 'financial market data' });
    return {
      agentId: this.id,
      status: 'COMPLETED',
      summary: 'Completed financial query',
      result: { queried: true },
      stepsExecuted: 1,
      durationMs: 25
    };
  }
}

class EmptyCapabilityAgent extends BaseAgent {
  constructor() {
    super({
      id: 'empty-cap-agent',
      name: 'Empty Cap Agent',
      description: 'Agent with no capabilities',
      capabilities: []
    });
  }

  public override async execute(): Promise<AgentOutput> {
    return { agentId: this.id, status: 'COMPLETED', summary: 'None', result: {}, stepsExecuted: 0, durationMs: 0 };
  }
}

describe('Milestone 2B: Business Task Workflows - Unit Tests', () => {
  const tempDirs: string[] = [];

  afterEach(() => {
    while (tempDirs.length > 0) {
      const dir = tempDirs.pop()!;
      rmSync(dir, { recursive: true, force: true });
    }
  });

  function setupEnvironment(options: { dbPath?: string } = {}) {
    const dir = createTempDir();
    tempDirs.push(dir);
    const dbPath = options.dbPath ?? join(dir, 'dots.db');

    const db = new DatabaseManager(dbPath);
    const taskRepo = new TaskRepository(db);
    const auditRepo = new AuditRepository(db);
    const memoryRepo = new MemoryRepository(db);

    const identityProvider = new TokenIdentityProvider([
      {
        token: ADMIN_TOKEN,
        principalId: 'alice-admin',
        role: 'ADMIN',
        permittedScopes: [
          { scopeType: 'WORKSPACE', scopeId: 'ws-alpha' },
          { scopeType: 'GLOBAL', scopeId: 'default' }
        ]
      },
      {
        token: MEMBER_TOKEN,
        principalId: 'bob-member',
        role: 'MEMBER',
        permittedScopes: [{ scopeType: 'WORKSPACE', scopeId: 'ws-alpha' }]
      },
      {
        token: VIEWER_TOKEN,
        principalId: 'carol-viewer',
        role: 'VIEWER',
        permittedScopes: [{ scopeType: 'WORKSPACE', scopeId: 'ws-alpha' }]
      },
      {
        token: WS2_MEMBER_TOKEN,
        principalId: 'dave-ws2',
        role: 'MEMBER',
        permittedScopes: [{ scopeType: 'WORKSPACE', scopeId: 'ws-beta' }]
      }
    ]);

    const hostAuthority = new HostMemoryAuthority({
      hostSecret: 'test-host-secret-12345678901234567890',
      taskRepo,
      identityProvider
    });
    const authorizer = hostAuthority.authorizer;

    const memoryService = new MemoryService({
      memoryRepo,
      auditRepo,
      taskRepo,
      authorizer,
      hostAuthority
    });

    const toolRegistry = new ToolRegistry();
    for (const tool of standardTools) {
      toolRegistry.register(tool);
    }

    const policyEngine = new PolicyEngine({ workspaceRoot: dir, autoApproveTier2: true });
    const approvalBroker = new ApprovalBroker(taskRepo, auditRepo);
    const verifier = new VerificationEngine();
    const budgetTracker = new TokenBudgetTracker({ db, maxCostPerTaskUsd: 5.0 });
    const modelProvider = new MockModelProvider();

    const agentRegistry = new AgentRegistry();
    agentRegistry.register(
      new TestBusinessAgent({
        id: 'biz-agent',
        name: 'Business Agent',
        description: 'Processes business operations',
        capabilities: ['general', 'data_analysis']
      })
    );
    agentRegistry.register(
      new FailingAgent({
        id: 'failing-agent',
        name: 'Failing Agent',
        description: 'Always fails',
        capabilities: ['general']
      })
    );
    agentRegistry.register(
      new ApprovalRequiringAgent({
        id: 'approval-agent',
        name: 'Approval Agent',
        description: 'Requires tier 3 approval',
        capabilities: ['web_access']
      })
    );
    agentRegistry.register(new EmptyCapabilityAgent());

    const coordinator = new TaskCoordinator({
      taskRepo,
      auditRepo,
      modelProvider,
      toolRegistry,
      policyEngine,
      approvalBroker,
      verifier,
      budgetTracker,
      workspaceRoot: dir,
      memoryService,
      hostAuthority,
      authorizer,
      agentRegistry
    });

    const workflowService = new TaskWorkflowService({
      taskRepo,
      auditRepo,
      coordinator,
      agentRegistry,
      authorizer,
      hostAuthority,
      budgetTracker
    });

    const memberCaller = authorizer.authorizeUser({
      credentials: MEMBER_TOKEN,
      requestedScope: { scopeType: 'WORKSPACE', scopeId: 'ws-alpha' }
    });

    const viewerCaller = authorizer.authorizeUser({
      credentials: VIEWER_TOKEN,
      requestedScope: { scopeType: 'WORKSPACE', scopeId: 'ws-alpha' }
    });

    const ws2Caller = authorizer.authorizeUser({
      credentials: WS2_MEMBER_TOKEN,
      requestedScope: { scopeType: 'WORKSPACE', scopeId: 'ws-beta' }
    });

    return {
      dir,
      db,
      taskRepo,
      auditRepo,
      coordinator,
      agentRegistry,
      modelProvider,
      workflowService,
      memberCaller,
      viewerCaller,
      ws2Caller
    };
  }

  it('submits a business task with objective, description, parameters, and agentId', async () => {
    const { workflowService, memberCaller } = setupEnvironment();

    const task = await workflowService.submitTask(memberCaller, {
      objective: 'Q3 Financial Revenue Audit',
      description: 'Audit regional numbers against ERP ledger',
      agentId: 'biz-agent',
      parameters: { quarter: 'Q3', year: 2026 },
      run: false
    });

    assert.ok(task.id);
    assert.equal(task.goal, 'Q3 Financial Revenue Audit');
    assert.equal(task.status, 'SUBMITTED');
    assert.equal(task.scope.scopeType, 'WORKSPACE');
    assert.equal(task.scope.scopeId, 'ws-alpha');
    assert.equal(task.metadata.description, 'Audit regional numbers against ERP ledger');
    assert.equal(task.metadata.agentId, 'biz-agent');
    assert.deepEqual(task.metadata.parameters, { quarter: 'Q3', year: 2026 });
  });

  it('validates input and rejects invalid objective or excessive length', async () => {
    const { workflowService, memberCaller } = setupEnvironment();

    // 1. Empty objective
    await assert.rejects(
      async () => {
        await workflowService.submitTask(memberCaller, { objective: '   ' });
      },
      (err: unknown) => err instanceof ValidationError && /objective/i.test((err as Error).message)
    );

    // 2. Overlong objective (>2048 chars)
    await assert.rejects(
      async () => {
        await workflowService.submitTask(memberCaller, { objective: 'A'.repeat(2049) });
      },
      (err: unknown) => err instanceof ValidationError && /maximum allowed/i.test((err as Error).message)
    );

    // 3. Invalid parameters (not an object)
    await assert.rejects(
      async () => {
        await workflowService.submitTask(memberCaller, {
          objective: 'Valid objective',
          parameters: 'not-an-object' as any
        });
      },
      (err: unknown) => err instanceof ValidationError && /parameters/i.test((err as Error).message)
    );
  });

  it('validates agent existence and rejects unknown agent IDs', async () => {
    const { workflowService, memberCaller } = setupEnvironment();

    await assert.rejects(
      async () => {
        await workflowService.submitTask(memberCaller, {
          objective: 'Analyze customer churn',
          agentId: 'non-existent-agent-id'
        });
      },
      (err: unknown) => err instanceof AgentNotFoundError && (err as AgentNotFoundError).agentId === 'non-existent-agent-id'
    );
  });

  it('rejects agents without supported capabilities cleanly', async () => {
    const { workflowService, memberCaller } = setupEnvironment();

    await assert.rejects(
      async () => {
        await workflowService.submitTask(memberCaller, {
          objective: 'Analyze customer churn',
          agentId: 'empty-cap-agent'
        });
      },
      (err: unknown) => err instanceof AgentCapabilityError && (err as AgentCapabilityError).agentId === 'empty-cap-agent'
    );
  });

  it('executes task through TaskCoordinator and records structured output and metadata', async () => {
    const { workflowService, memberCaller } = setupEnvironment();

    const created = await workflowService.submitTask(memberCaller, {
      objective: 'Run regional payroll reconciliation',
      agentId: 'biz-agent',
      parameters: { region: 'EMEA', currency: 'EUR' },
      run: false
    });

    const completed = await workflowService.runTask(memberCaller, created.id);
    assert.equal(completed.status, 'COMPLETED');
    assert.ok(completed.completedAt);

    // Retrieve structured business task result view
    const resultView = workflowService.getTaskResult(memberCaller, created.id);
    assert.equal(resultView.taskId, created.id);
    assert.equal(resultView.status, 'COMPLETED');
    assert.equal(resultView.agentId, 'biz-agent');
    assert.equal(resultView.summary, 'Processed business task: Run regional payroll reconciliation');
    assert.deepEqual((resultView.output as any).receivedParams, { region: 'EMEA', currency: 'EUR' });
    assert.equal(resultView.stepsExecuted, 2);
    assert.equal(resultView.durationMs, 42);
    assert.ok(resultView.completedAt);
  });

  it('handles execution failure without corrupting task state or fabricating success', async () => {
    const { workflowService, memberCaller } = setupEnvironment();

    const created = await workflowService.submitTask(memberCaller, {
      objective: 'Charge credit card batch',
      agentId: 'failing-agent',
      run: true
    });

    assert.equal(created.status, 'FAILED');
    assert.equal(created.errorSummary, 'Upstream payment gateway timeout');

    const resultView = workflowService.getTaskResult(memberCaller, created.id);
    assert.equal(resultView.status, 'FAILED');
    assert.equal(resultView.error, 'Upstream payment gateway timeout');
    assert.equal(resultView.output, null);
  });

  it('enforces tool approvals and suspends task in AWAITING_APPROVAL without bypass', async () => {
    const { workflowService, memberCaller, taskRepo, modelProvider } = setupEnvironment();

    // 1. Agent calling Tier 3 tool without approval is blocked with APPROVAL_REQUIRED
    const agentTask = await workflowService.submitTask(memberCaller, {
      objective: 'Query public market data via unapproved agent',
      agentId: 'approval-agent',
      run: true
    });
    assert.equal(agentTask.status, 'FAILED');
    assert.ok(agentTask.errorSummary?.includes('explicit human approval'));

    // 2. Step workflow with Tier 3 tool pauses at AWAITING_APPROVAL and creates approval request
    modelProvider.enqueuePlan([
      {
        stepOrder: 1,
        description: 'Search market data',
        toolName: 'web_search',
        arguments: { query: 'financial report' },
        expectedOutcome: 'Market report found'
      }
    ]);

    const stepTask = await workflowService.submitTask(memberCaller, {
      objective: 'Search web for financial data',
      run: false
    });

    const awaiting = await workflowService.runTask(memberCaller, stepTask.id);
    assert.equal(awaiting.status, 'AWAITING_APPROVAL');

    const pendingApprovals = taskRepo.getApprovalRequestsByTaskId(stepTask.id);
    assert.equal(pendingApprovals.length, 1);
    assert.equal(pendingApprovals[0]!.decision, 'PENDING');
    assert.equal(pendingApprovals[0]!.riskTier, 'TIER_3');
  });

  it('cancels pending and running tasks safely and rejects invalid state transitions', async () => {
    const { workflowService, memberCaller } = setupEnvironment();

    // 1. Safe cancellation of submitted task
    const task1 = await workflowService.submitTask(memberCaller, {
      objective: 'To be cancelled before run',
      agentId: 'biz-agent',
      run: false
    });
    assert.equal(task1.status, 'SUBMITTED');

    const cancelled1 = workflowService.cancelTask(memberCaller, task1.id, 'User changed priority');
    assert.equal(cancelled1.status, 'CANCELLED');

    // Cancelling an already cancelled task is idempotent
    const cancelledAgain = workflowService.cancelTask(memberCaller, task1.id);
    assert.equal(cancelledAgain.status, 'CANCELLED');

    // 2. Reject cancellation of COMPLETED task
    const task2 = await workflowService.submitTask(memberCaller, {
      objective: 'Run to completion first',
      agentId: 'biz-agent',
      run: true
    });
    assert.equal(task2.status, 'COMPLETED');

    assert.throws(
      () => {
        workflowService.cancelTask(memberCaller, task2.id);
      },
      (err: unknown) => err instanceof InvalidStateTransitionError && (err as InvalidStateTransitionError).fromStatus === 'COMPLETED'
    );
  });

  it('supports pagination and status and agent filtering in listTasks', async () => {
    const { workflowService, memberCaller } = setupEnvironment();

    // Submit 5 tasks with varied status and agents
    await workflowService.submitTask(memberCaller, { objective: 'Task 1', agentId: 'biz-agent', run: true });
    await workflowService.submitTask(memberCaller, { objective: 'Task 2', agentId: 'biz-agent', run: false });
    await workflowService.submitTask(memberCaller, { objective: 'Task 3', agentId: 'failing-agent', run: true });
    await workflowService.submitTask(memberCaller, { objective: 'Task 4', agentId: 'biz-agent', run: false });
    await workflowService.submitTask(memberCaller, { objective: 'Task 5', agentId: 'failing-agent', run: true });

    // Filter by status COMPLETED
    const completedList = workflowService.listTasks(memberCaller, { status: 'COMPLETED' });
    assert.equal(completedList.total, 1);
    assert.equal(completedList.tasks.length, 1);
    assert.equal(completedList.tasks[0]!.goal, 'Task 1');

    // Filter by status FAILED
    const failedList = workflowService.listTasks(memberCaller, { status: 'FAILED' });
    assert.equal(failedList.total, 2);

    // Filter by agentId biz-agent
    const bizList = workflowService.listTasks(memberCaller, { agentId: 'biz-agent' });
    assert.equal(bizList.total, 3);

    // Pagination: limit 2, offset 1 on bizList
    const paged = workflowService.listTasks(memberCaller, { agentId: 'biz-agent', limit: 2, offset: 1 });
    assert.equal(paged.total, 3);
    assert.equal(paged.tasks.length, 2);
  });

  it('enforces caller ownership and workspace scope isolation strictly', async () => {
    const { workflowService, memberCaller, viewerCaller, ws2Caller } = setupEnvironment();

    // 1. Viewer cannot submit tasks (lacks WRITE permission)
    await assert.rejects(
      async () => {
        await workflowService.submitTask(viewerCaller, { objective: 'Unauthorized task' });
      },
      (err: unknown) => err instanceof SecurityViolationError && (err as SecurityViolationError).violationType === 'PERMISSION_DENIED'
    );

    // 2. Member creates task in ws-alpha
    const task = await workflowService.submitTask(memberCaller, {
      objective: 'Confidential ws-alpha task',
      agentId: 'biz-agent',
      run: false
    });

    // 3. Caller in ws-beta cannot read, run, or cancel it
    assert.throws(
      () => {
        workflowService.getTask(ws2Caller, task.id);
      },
      (err: unknown) => err instanceof SecurityViolationError && (err as SecurityViolationError).violationType === 'TASK_CALLER_SCOPE_MISMATCH'
    );

    assert.throws(
      () => {
        workflowService.getTaskResult(ws2Caller, task.id);
      },
      (err: unknown) => err instanceof SecurityViolationError && (err as SecurityViolationError).violationType === 'TASK_CALLER_SCOPE_MISMATCH'
    );

    await assert.rejects(
      async () => {
        await workflowService.runTask(ws2Caller, task.id);
      },
      (err: unknown) => err instanceof SecurityViolationError && (err as SecurityViolationError).violationType === 'TASK_CALLER_SCOPE_MISMATCH'
    );

    assert.throws(
      () => {
        workflowService.cancelTask(ws2Caller, task.id);
      },
      (err: unknown) => err instanceof SecurityViolationError && (err as SecurityViolationError).violationType === 'TASK_CALLER_SCOPE_MISMATCH'
    );

    // 4. Listing in ws-beta yields 0 tasks
    const ws2List = workflowService.listTasks(ws2Caller);
    assert.equal(ws2List.total, 0);
    assert.equal(ws2List.tasks.length, 0);
  });

  it('scrubs sensitive credentials from task descriptions, errors, and results', async () => {
    const { workflowService, memberCaller } = setupEnvironment();

    const secretKey = 'sk-ant-api03-12345678901234567890123456789012-12345678901234567890123456789012-AA';
    const task = await workflowService.submitTask(memberCaller, {
      objective: `Process invoice using token ${secretKey}`,
      description: `Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.secret`,
      agentId: 'biz-agent',
      parameters: { secretApiKey: secretKey },
      run: true
    });

    assert.ok(!task.goal.includes(secretKey));
    assert.ok(task.goal.includes('[REDACTED_ANTHROPIC_API_KEY]'));

    const resultView = workflowService.getTaskResult(memberCaller, task.id);
    assert.ok(!JSON.stringify(resultView).includes(secretKey));
  });
});
