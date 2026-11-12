import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  DotsRuntime,
  DotsHttpServer,
  MockModelProvider,
  runCli
} from '../../src/index.ts';

const ADMIN_TOKEN = 'admin-secret-token-123456';
const MEMBER_TOKEN = 'member-secret-token-123456';
const VIEWER_TOKEN = 'viewer-secret-token-123456';
const OTHER_WS_ADMIN_TOKEN = 'ws2-admin-secret-token-123456';

function createTempDir(): string {
  return mkdtempSync(join(tmpdir(), 'dots-p8a-'));
}

describe('Phase 8A: CLI, HTTP REST API, SSE, Auth & Scope Isolation', () => {
  const tempDirs: string[] = [];

  afterEach(() => {
    while (tempDirs.length > 0) {
      const dir = tempDirs.pop()!;
      rmSync(dir, { recursive: true, force: true });
    }
  });

  function setupServer(maxBodyBytes = 1024 * 64) {
    const dir = createTempDir();
    tempDirs.push(dir);
    const dbPath = join(dir, 'dots.db');
    const mockProvider = new MockModelProvider();
    const runtime = new DotsRuntime({
      dbPath,
      workspaceRoot: dir,
      host: '127.0.0.1',
      port: 0,
      silentLogs: true,
      enableScheduler: false,
      autoApproveTier2: false,
      maxBodyBytes,
      modelProvider: mockProvider,
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
          token: OTHER_WS_ADMIN_TOKEN,
          principalId: 'dave-ws2',
          role: 'ADMIN',
          permittedScopes: [{ scopeType: 'WORKSPACE', scopeId: 'ws-beta' }]
        }
      ]
    });

    const server = new DotsHttpServer(runtime);
    return { dir, dbPath, mockProvider, runtime, server };
  }

  it('enforces authentication, role-based approval restrictions, scope isolation, secret scrubbing, and request size limits over HTTP', async () => {
    const { mockProvider, server } = setupServer(512);
    const started = await server.start();

    try {
      // 1. Health endpoint
      const healthRes = await fetch(`${started.url}/health`);
      assert.equal(healthRes.status, 200);
      const healthJson = (await healthRes.json()) as { status: string };
      assert.equal(healthJson.status, 'ok');

      // 2. Unauthenticated rejection
      const unauthRes = await fetch(`${started.url}/api/tasks`);
      assert.equal(unauthRes.status, 401);

      // 3. Request size limit (413)
      const hugeRes = await fetch(`${started.url}/api/tasks`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${MEMBER_TOKEN}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ goal: 'x'.repeat(1024) })
      });
      assert.equal(hugeRes.status, 413);

      // 4. VIEWER cannot submit task (403)
      const viewerWriteRes = await fetch(`${started.url}/api/tasks`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${VIEWER_TOKEN}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ goal: 'Compute 1+1' })
      });
      assert.equal(viewerWriteRes.status, 403);

      // 5. MEMBER submits task requiring Tier 3 approval (file_write), with secret in metadata that must be scrubbed
      mockProvider.enqueuePlan([
        {
          stepOrder: 1,
          description: 'Write approved file',
          toolName: 'file_write',
          arguments: { path: 'hello.txt', content: 'hi from phase 8a' },
          expectedOutcome: 'File written'
        }
      ]);

      const submitRes = await fetch(`${started.url}/api/tasks`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${MEMBER_TOKEN}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          goal: 'Write greeting with leaked key sk-abcdefghijklmnopqrstuvwxyz123456',
          metadata: { note: 'Bearer supersecrettokenvalue123', apiKey: 'AIzaSyDummyKeyValue1234567890123456789' },
          run: true
        })
      });
      assert.equal(submitRes.status, 201);
      const submitJson = (await submitRes.json()) as { task: { id: string; status: string; goal: string; metadata: Record<string, unknown> } };
      assert.equal(submitJson.task.status, 'AWAITING_APPROVAL');
      assert.ok(!submitJson.task.goal.includes('sk-abcdefghijklmnopqrstuvwxyz123456'));
      assert.equal(submitJson.task.metadata.apiKey, undefined);
      assert.equal(submitJson.task.metadata.note, 'Bearer [REDACTED_TOKEN]');
      assert.ok(!JSON.stringify(submitJson).includes('_scopeAttestation'));

      // 6. List approvals in ws-alpha (token must NOT leak approvalToken)
      const approvalsRes = await fetch(`${started.url}/api/approvals?decision=PENDING`, {
        headers: {
          Authorization: `Bearer ${ADMIN_TOKEN}`,
          'X-Dots-Scope': 'WORKSPACE:ws-alpha'
        }
      });
      assert.equal(approvalsRes.status, 200);
      const approvalsJson = (await approvalsRes.json()) as { approvals: Array<{ id: string; taskId: string; approvalToken?: string }> };
      assert.equal(approvalsJson.approvals.length, 1);
      assert.equal(approvalsJson.approvals[0]!.approvalToken, undefined);
      const approvalId = approvalsJson.approvals[0]!.id;

      // 7. Role-based approval restriction: MEMBER cannot approve (403)
      const memberApproveRes = await fetch(`${started.url}/api/approvals/${approvalId}/decide`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${MEMBER_TOKEN}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ decision: 'APPROVED' })
      });
      assert.equal(memberApproveRes.status, 403);

      // 8. Scope isolation: ws-beta ADMIN cannot view task or approve ws-alpha approval
      const crossScopeTaskRes = await fetch(`${started.url}/api/tasks/${submitJson.task.id}`, {
        headers: { Authorization: `Bearer ${OTHER_WS_ADMIN_TOKEN}` }
      });
      assert.equal(crossScopeTaskRes.status, 403);

      const crossScopeApproveRes = await fetch(`${started.url}/api/approvals/${approvalId}/decide`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${OTHER_WS_ADMIN_TOKEN}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ decision: 'APPROVED' })
      });
      assert.equal(crossScopeApproveRes.status, 403);

      // 9. Authorized ADMIN in ws-alpha approves and resumes task to COMPLETED
      const adminApproveRes = await fetch(`${started.url}/api/approvals/${approvalId}/decide`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${ADMIN_TOKEN}`,
          'X-Dots-Scope': 'WORKSPACE:ws-alpha',
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ decision: 'APPROVED', resume: true })
      });
      assert.equal(adminApproveRes.status, 200);
      const approvedJson = (await adminApproveRes.json()) as {
        approval: { decision: string; decidedBy: string };
        task: { status: string };
      };
      assert.equal(approvedJson.approval.decision, 'APPROVED');
      assert.equal(approvedJson.approval.decidedBy, 'alice-admin');
      assert.equal(approvedJson.task.status, 'COMPLETED');
    } finally {
      await server.stop();
    }
  });

  it('streams scope-isolated, secret-scrubbed Server-Sent Events via GET /api/events', async () => {
    const { mockProvider, server } = setupServer();
    const started = await server.start();
    const abortController = new AbortController();

    try {
      const sseRes = await fetch(`${started.url}/api/events`, {
        headers: {
          Authorization: `Bearer ${ADMIN_TOKEN}`,
          'X-Dots-Scope': 'WORKSPACE:ws-alpha'
        },
        signal: abortController.signal
      });
      assert.equal(sseRes.status, 200);
      assert.ok(sseRes.headers.get('content-type')?.includes('text/event-stream'));

      // Submit a task in ws-beta (must NOT appear in ws-alpha SSE stream)
      mockProvider.enqueuePlan([
        {
          stepOrder: 1,
          description: 'Calc beta',
          toolName: 'calculate',
          arguments: { expression: '2 + 2' },
          expectedOutcome: '4'
        }
      ]);
      await fetch(`${started.url}/api/tasks`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${OTHER_WS_ADMIN_TOKEN}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ goal: 'Beta secret task', run: true })
      });

      // Submit a task in ws-alpha (MUST appear in ws-alpha SSE stream)
      mockProvider.enqueuePlan([
        {
          stepOrder: 1,
          description: 'Calc alpha',
          toolName: 'calculate',
          arguments: { expression: '6 * 7' },
          expectedOutcome: '42'
        }
      ]);
      await fetch(`${started.url}/api/tasks`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${MEMBER_TOKEN}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ goal: 'Alpha task with ghp_123456789012345678901234567890123456', run: true })
      });

      const reader = sseRes.body!.getReader();
      const decoder = new TextDecoder();
      let collected = '';
      const deadline = Date.now() + 2000;
      while (Date.now() < deadline && !collected.includes('task.updated')) {
        const chunk = await reader.read();
        if (chunk.done) break;
        collected += decoder.decode(chunk.value, { stream: true });
      }

      assert.ok(collected.includes('event: task.created'));
      assert.ok(collected.includes('event: task.updated'));
      assert.ok(!collected.includes('Beta secret task'));
      assert.ok(!collected.includes('ghp_123456789012345678901234567890123456'));
      assert.ok(collected.includes('[REDACTED_GITHUB_TOKEN]'));
    } finally {
      abortController.abort();
      await server.stop();
    }
  });

  it('executes CLI task, approval, and memory commands cleanly', async () => {
    const dir = createTempDir();
    tempDirs.push(dir);
    const dbPath = join(dir, 'cli.db');
    const mockProvider = new MockModelProvider();
    mockProvider.enqueuePlan([
      {
        stepOrder: 1,
        description: 'Calculate 3 * 9',
        toolName: 'calculate',
        arguments: { expression: '3 * 9' },
        expectedOutcome: '27'
      }
    ]);

    const tokens = [
      {
        token: ADMIN_TOKEN,
        principalId: 'cli-admin',
        role: 'ADMIN' as const,
        permittedScopes: [{ scopeType: 'WORKSPACE' as const, scopeId: 'cli-ws' }]
      }
    ];

    const out: string[] = [];
    const err: string[] = [];
    const io = {
      stdout: (t: string) => out.push(t),
      stderr: (t: string) => err.push(t)
    };

    const runCode = await runCli(
      ['--token', ADMIN_TOKEN, '--db', dbPath, '--workspace', dir, '--json', 'run', 'Compute 3 * 9'],
      io,
      { modelProvider: mockProvider, tokens }
    );
    assert.equal(runCode, 0, err.join('\n'));
    const runParsed = JSON.parse(out.pop()!) as { task: { id: string; status: string } };
    assert.equal(runParsed.task.status, 'COMPLETED');

    const statusCode = await runCli(
      ['--token', ADMIN_TOKEN, '--db', dbPath, '--workspace', dir, '--json', 'status', runParsed.task.id],
      io,
      { tokens }
    );
    assert.equal(statusCode, 0);
    const statusParsed = JSON.parse(out.pop()!) as { task: { id: string }; steps: unknown[] };
    assert.equal(statusParsed.task.id, runParsed.task.id);
    assert.equal(statusParsed.steps.length, 1);

    const memCreateCode = await runCli(
      [
        '--token',
        ADMIN_TOKEN,
        '--db',
        dbPath,
        '--workspace',
        dir,
        '--json',
        'memory',
        'create',
        '--category',
        'PROJECT_FACT',
        '--key',
        'runtime-lang',
        '--content',
        'Node.js 24 TypeScript'
      ],
      io,
      { tokens }
    );
    assert.equal(memCreateCode, 0, err.join('\n'));
    const memCreated = JSON.parse(out.pop()!) as { memory: { id: string; key: string } };
    assert.equal(memCreated.memory.key, 'runtime-lang');

    const memListCode = await runCli(
      ['--token', ADMIN_TOKEN, '--db', dbPath, '--workspace', dir, '--json', 'memory', 'list'],
      io,
      { tokens }
    );
    assert.equal(memListCode, 0);
    const memList = JSON.parse(out.pop()!) as { memories: Array<{ id: string }> };
    assert.equal(memList.memories.length, 1);
  });
});
