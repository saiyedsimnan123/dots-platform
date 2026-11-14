/**
 * Next-Generation Dots AI Platform - Business Task Workflow Integration Tests
 * Milestone 2B: Business Task Workflows
 */

import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  DotsRuntime,
  DotsHttpServer,
  MockModelProvider,
  AgentRegistry,
  BaseAgent,
  runCli,
  type CliIo,
  type AgentInput,
  type AgentOutput,
  type AgentExecutionContext
} from '../../src/index.ts';

const ADMIN_TOKEN = 'admin-secret-token-123456';
const MEMBER_TOKEN = 'member-secret-token-123456';
const VIEWER_TOKEN = 'viewer-secret-token-123456';
const WS2_TOKEN = 'ws2-admin-secret-token-123456';

function createTempDir(): string {
  return mkdtempSync(join(tmpdir(), 'dots-biztask-api-'));
}

class TestFinanceAgent extends BaseAgent {
  public override async execute(input: AgentInput, context: AgentExecutionContext): Promise<AgentOutput> {
    const params = input.parameters ?? {};
    return {
      agentId: this.id,
      status: 'COMPLETED',
      summary: `Processed financial statement for ${input.goal}`,
      result: {
        reconciled: true,
        statementId: params.statementId ?? 'STMT-999',
        balance: 154200.5
      },
      stepsExecuted: 2,
      durationMs: 38
    };
  }
}

class TestFailingAgent extends BaseAgent {
  public override async execute(): Promise<AgentOutput> {
    return {
      agentId: this.id,
      status: 'FAILED',
      summary: 'Database connection failed',
      error: 'Postgres pool connection timeout',
      result: {},
      stepsExecuted: 1,
      durationMs: 12
    };
  }
}

describe('Milestone 2B: Business Task Workflow HTTP API & CLI Integration', () => {
  const tempDirs: string[] = [];

  afterEach(() => {
    while (tempDirs.length > 0) {
      const dir = tempDirs.pop()!;
      rmSync(dir, { recursive: true, force: true });
    }
  });

  function setupServer() {
    const dir = createTempDir();
    tempDirs.push(dir);
    const dbPath = join(dir, 'dots.db');
    const mockProvider = new MockModelProvider();

    const agentRegistry = new AgentRegistry();
    agentRegistry.register(
      new TestFinanceAgent({
        id: 'finance-agent',
        name: 'Finance Agent',
        description: 'Reconciles financial records',
        capabilities: ['finance', 'accounting']
      })
    );
    agentRegistry.register(
      new TestFailingAgent({
        id: 'failing-agent',
        name: 'Failing Agent',
        description: 'Fails operations',
        capabilities: ['general']
      })
    );

    const runtime = new DotsRuntime({
      dbPath,
      workspaceRoot: dir,
      host: '127.0.0.1',
      port: 0,
      silentLogs: true,
      enableScheduler: false,
      modelProvider: mockProvider,
      agentRegistry,
      tokens: [
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
          token: WS2_TOKEN,
          principalId: 'dave-ws2',
          role: 'ADMIN',
          permittedScopes: [{ scopeType: 'WORKSPACE', scopeId: 'ws-beta' }]
        }
      ]
    });

    const server = new DotsHttpServer(runtime);
    return { dir, dbPath, mockProvider, agentRegistry, runtime, server };
  }

  it('enforces authentication, role authorization, and scope isolation over HTTP', async () => {
    const { server } = setupServer();
    const started = await server.start();

    try {
      // 1. Unauthenticated request -> 401
      const unauthRes = await fetch(`${started.url}/api/tasks`);
      assert.equal(unauthRes.status, 401);

      // 2. Viewer role attempting to submit task -> 403 Forbidden
      const viewerSubmitRes = await fetch(`${started.url}/api/tasks`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${VIEWER_TOKEN}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ objective: 'Disallowed viewer task' })
      });
      assert.equal(viewerSubmitRes.status, 403);

      // 3. Member in ws-alpha creates a task
      const memberSubmitRes = await fetch(`${started.url}/api/tasks`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${MEMBER_TOKEN}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          objective: 'Alpha Confidential Task',
          agentId: 'finance-agent',
          run: false
        })
      });
      assert.equal(memberSubmitRes.status, 201);
      const memberJson = await memberSubmitRes.json() as any;
      const taskId = memberJson.task.id;
      assert.ok(taskId);

      // 4. User in ws-beta cannot access ws-alpha task -> 403
      const crossScopeGet = await fetch(`${started.url}/api/tasks/${taskId}`, {
        headers: { Authorization: `Bearer ${WS2_TOKEN}` }
      });
      assert.equal(crossScopeGet.status, 403);

      const crossScopeStatus = await fetch(`${started.url}/api/tasks/${taskId}/status`, {
        headers: { Authorization: `Bearer ${WS2_TOKEN}` }
      });
      assert.equal(crossScopeStatus.status, 403);

      const crossScopeResult = await fetch(`${started.url}/api/tasks/${taskId}/result`, {
        headers: { Authorization: `Bearer ${WS2_TOKEN}` }
      });
      assert.equal(crossScopeResult.status, 403);

      const crossScopeRun = await fetch(`${started.url}/api/tasks/${taskId}/run`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${WS2_TOKEN}` }
      });
      assert.equal(crossScopeRun.status, 403);

      const crossScopeCancel = await fetch(`${started.url}/api/tasks/${taskId}/cancel`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${WS2_TOKEN}` }
      });
      assert.equal(crossScopeCancel.status, 403);
    } finally {
      await server.stop();
    }
  });

  it('supports full task lifecycle, status checking, and result retrieval over HTTP', async () => {
    const { server } = setupServer();
    const started = await server.start();

    try {
      // 1. Submit task without running
      const submitRes = await fetch(`${started.url}/api/tasks`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${MEMBER_TOKEN}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          objective: 'Reconcile Q4 Statements',
          description: 'Compare bank statements with GL',
          agentId: 'finance-agent',
          parameters: { statementId: 'STMT-2026-Q4' },
          run: false
        })
      });
      assert.equal(submitRes.status, 201);
      const submitJson = await submitRes.json() as any;
      const taskId = submitJson.task.id;
      assert.equal(submitJson.task.goal, 'Reconcile Q4 Statements');
      assert.equal(submitJson.task.status, 'SUBMITTED');
      assert.equal(submitJson.task.metadata.agentId, 'finance-agent');

      // 2. Check task status via GET /api/tasks/:id/status
      const statusRes = await fetch(`${started.url}/api/tasks/${taskId}/status`, {
        headers: { Authorization: `Bearer ${MEMBER_TOKEN}` }
      });
      assert.equal(statusRes.status, 200);
      const statusJson = await statusRes.json() as any;
      assert.equal(statusJson.taskId, taskId);
      assert.equal(statusJson.status, 'SUBMITTED');
      assert.equal(statusJson.goal, 'Reconcile Q4 Statements');

      // 3. Run the task via POST /api/tasks/:id/run
      const runRes = await fetch(`${started.url}/api/tasks/${taskId}/run`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${MEMBER_TOKEN}` }
      });
      assert.equal(runRes.status, 200);
      const runJson = await runRes.json() as any;
      assert.equal(runJson.task.status, 'COMPLETED');

      // 4. Retrieve structured task result via GET /api/tasks/:id/result
      const resultRes = await fetch(`${started.url}/api/tasks/${taskId}/result`, {
        headers: { Authorization: `Bearer ${MEMBER_TOKEN}` }
      });
      assert.equal(resultRes.status, 200);
      const resultJson = await resultRes.json() as any;
      assert.ok(resultJson.result);
      assert.equal(resultJson.result.taskId, taskId);
      assert.equal(resultJson.result.status, 'COMPLETED');
      assert.equal(resultJson.result.agentId, 'finance-agent');
      assert.equal(resultJson.result.summary, 'Processed financial statement for Reconcile Q4 Statements');
      assert.equal(resultJson.result.output.reconciled, true);
      assert.equal(resultJson.result.output.statementId, 'STMT-2026-Q4');
      assert.equal(resultJson.result.output.balance, 154200.5);

      // 5. Query task list with filtering via GET /api/tasks?status=COMPLETED&agentId=finance-agent
      const listRes = await fetch(
        `${started.url}/api/tasks?status=COMPLETED&agentId=finance-agent&limit=10&offset=0`,
        { headers: { Authorization: `Bearer ${MEMBER_TOKEN}` } }
      );
      assert.equal(listRes.status, 200);
      const listJson = await listRes.json() as any;
      assert.equal(listJson.total, 1);
      assert.equal(listJson.tasks.length, 1);
      assert.equal(listJson.tasks[0].id, taskId);

      // 6. Attempt to cancel completed task -> 400 (InvalidStateTransitionError)
      const cancelRes = await fetch(`${started.url}/api/tasks/${taskId}/cancel`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${MEMBER_TOKEN}` }
      });
      assert.equal(cancelRes.status, 400);

      // 7. Unknown agent validation error -> 404
      const unknownAgentRes = await fetch(`${started.url}/api/tasks`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${MEMBER_TOKEN}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          objective: 'Unknown agent task',
          agentId: 'non-existent-agent'
        })
      });
      assert.equal(unknownAgentRes.status, 404);
    } finally {
      await server.stop();
    }
  });

  it('executes CLI task operations in local mode', async () => {
    const { dbPath, dir, agentRegistry } = setupServer();

    const cliOverrides = {
      dbPath,
      workspaceRoot: dir,
      agentRegistry,
      tokens: [
        {
          token: ADMIN_TOKEN,
          principalId: 'alice-admin',
          role: 'ADMIN' as const,
          permittedScopes: [
            { scopeType: 'WORKSPACE' as const, scopeId: 'ws-alpha' },
            { scopeType: 'GLOBAL' as const, scopeId: 'default' }
          ]
        },
        {
          token: MEMBER_TOKEN,
          principalId: 'bob-member',
          role: 'MEMBER' as const,
          permittedScopes: [{ scopeType: 'WORKSPACE' as const, scopeId: 'ws-alpha' }]
        }
      ]
    };

    let capturedOut = '';
    let capturedErr = '';
    const io: CliIo = {
      stdout: (t) => { capturedOut += `${t}\n`; },
      stderr: (t) => { capturedErr += `${t}\n`; }
    };

    // 1. Submit task
    capturedOut = '';
    let code = await runCli(
      [
        'task', 'submit', 'Audit Ledger Balance',
        '--description', 'Local CLI test description',
        '--agent', 'finance-agent',
        '--params', '{"statementId":"STMT-LOCAL-1"}',
        '--no-wait',
        '--token', MEMBER_TOKEN,
        '--db', dbPath,
        '--workspace', dir,
        '--json'
      ],
      io,
      cliOverrides
    );
    assert.equal(code, 0, `CLI failed: ${capturedErr}`);
    const submitOutput = JSON.parse(capturedOut.trim());
    const taskId = submitOutput.task.id;
    assert.ok(taskId);
    assert.equal(submitOutput.task.goal, 'Audit Ledger Balance');
    assert.equal(submitOutput.task.status, 'SUBMITTED');

    // 2. List tasks
    capturedOut = '';
    code = await runCli(
      [
        'task', 'list',
        '--agent', 'finance-agent',
        '--token', MEMBER_TOKEN,
        '--db', dbPath,
        '--workspace', dir,
        '--json'
      ],
      io,
      cliOverrides
    );
    assert.equal(code, 0);
    const listOutput = JSON.parse(capturedOut.trim());
    assert.equal(listOutput.total, 1);
    assert.equal(listOutput.tasks[0].id, taskId);

    // 3. Status of task
    capturedOut = '';
    code = await runCli(
      [
        'task', 'status', taskId,
        '--token', MEMBER_TOKEN,
        '--db', dbPath,
        '--workspace', dir,
        '--json'
      ],
      io,
      cliOverrides
    );
    assert.equal(code, 0);
    const statusOutput = JSON.parse(capturedOut.trim());
    assert.equal(statusOutput.taskId, taskId);
    assert.equal(statusOutput.status, 'SUBMITTED');

    // 4. Run task
    capturedOut = '';
    code = await runCli(
      [
        'task', 'run', taskId,
        '--token', MEMBER_TOKEN,
        '--db', dbPath,
        '--workspace', dir,
        '--json'
      ],
      io,
      cliOverrides
    );
    assert.equal(code, 0);
    const runOutput = JSON.parse(capturedOut.trim());
    assert.equal(runOutput.task.status, 'COMPLETED');

    // 5. Result of task
    capturedOut = '';
    code = await runCli(
      [
        'task', 'result', taskId,
        '--token', MEMBER_TOKEN,
        '--db', dbPath,
        '--workspace', dir,
        '--json'
      ],
      io,
      cliOverrides
    );
    assert.equal(code, 0);
    const resultOutput = JSON.parse(capturedOut.trim());
    assert.equal(resultOutput.result.taskId, taskId);
    assert.equal(resultOutput.result.status, 'COMPLETED');
    assert.equal(resultOutput.result.output.reconciled, true);
    assert.equal(resultOutput.result.output.statementId, 'STMT-LOCAL-1');

    // 6. Submit second task and cancel it
    capturedOut = '';
    code = await runCli(
      [
        'task', 'submit', 'Task to Cancel',
        '--agent', 'finance-agent',
        '--no-wait',
        '--token', MEMBER_TOKEN,
        '--db', dbPath,
        '--workspace', dir,
        '--json'
      ],
      io,
      cliOverrides
    );
    assert.equal(code, 0);
    const cancelTargetId = JSON.parse(capturedOut.trim()).task.id;

    capturedOut = '';
    code = await runCli(
      [
        'task', 'cancel', cancelTargetId,
        '--reason', 'Cancelled via local CLI',
        '--token', MEMBER_TOKEN,
        '--db', dbPath,
        '--workspace', dir,
        '--json'
      ],
      io,
      cliOverrides
    );
    assert.equal(code, 0);
    const cancelOutput = JSON.parse(capturedOut.trim());
    assert.equal(cancelOutput.task.status, 'CANCELLED');
  });

  it('executes CLI task operations in remote HTTP mode', async () => {
    const { server } = setupServer();
    const started = await server.start();

    let capturedOut = '';
    let capturedErr = '';
    const io: CliIo = {
      stdout: (t) => { capturedOut += `${t}\n`; },
      stderr: (t) => { capturedErr += `${t}\n`; }
    };

    try {
      // 1. Submit task remotely
      capturedOut = '';
      let code = await runCli(
        [
          'task', 'submit', 'Remote Audit Workflow',
          '--description', 'Submitted over remote HTTP',
          '--agent', 'finance-agent',
          '--params', '{"statementId":"STMT-REMOTE-42"}',
          '--token', MEMBER_TOKEN,
          '--server', started.url,
          '--json'
        ],
        io
      );
      assert.equal(code, 0, `CLI remote failed: ${capturedErr}`);
      const submitOutput = JSON.parse(capturedOut.trim());
      const taskId = submitOutput.task.id;
      assert.ok(taskId);
      assert.equal(submitOutput.task.status, 'COMPLETED');

      // 2. Result remotely
      capturedOut = '';
      code = await runCli(
        [
          'task', 'result', taskId,
          '--token', MEMBER_TOKEN,
          '--server', started.url,
          '--json'
        ],
        io
      );
      assert.equal(code, 0);
      const resultOutput = JSON.parse(capturedOut.trim());
      assert.equal(resultOutput.result.taskId, taskId);
      assert.equal(resultOutput.result.status, 'COMPLETED');
      assert.equal(resultOutput.result.output.statementId, 'STMT-REMOTE-42');

      // 3. Status remotely
      capturedOut = '';
      code = await runCli(
        [
          'task', 'status', taskId,
          '--token', MEMBER_TOKEN,
          '--server', started.url,
          '--json'
        ],
        io
      );
      assert.equal(code, 0);
      const statusOutput = JSON.parse(capturedOut.trim());
      assert.equal(statusOutput.taskId, taskId);
      assert.equal(statusOutput.status, 'COMPLETED');

      // 4. List remotely
      capturedOut = '';
      code = await runCli(
        [
          'task', 'list',
          '--status', 'COMPLETED',
          '--token', MEMBER_TOKEN,
          '--server', started.url,
          '--json'
        ],
        io
      );
      assert.equal(code, 0);
      const listOutput = JSON.parse(capturedOut.trim());
      assert.equal(listOutput.total, 1);
      assert.equal(listOutput.tasks[0].id, taskId);
    } finally {
      await server.stop();
    }
  });
});
