/**
 * Next-Generation Dots AI Platform - Conversation API & CLI Integration Tests
 * Milestone 2A: Persistent Conversation System
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
  runCli,
  type CliIo
} from '../../src/index.ts';

const ADMIN_TOKEN = 'admin-secret-token-123456';
const MEMBER_TOKEN = 'member-secret-token-123456';
const VIEWER_TOKEN = 'viewer-secret-token-123456';
const WS2_TOKEN = 'ws2-admin-secret-token-123456';

function createTempDir(): string {
  return mkdtempSync(join(tmpdir(), 'dots-conv-api-'));
}

describe('Milestone 2A: Conversation HTTP API & CLI Integration', () => {
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

    const runtime = new DotsRuntime({
      dbPath,
      workspaceRoot: dir,
      host: '127.0.0.1',
      port: 0,
      silentLogs: true,
      enableScheduler: false,
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
          token: WS2_TOKEN,
          principalId: 'dave-ws2',
          role: 'ADMIN',
          permittedScopes: [{ scopeType: 'WORKSPACE', scopeId: 'ws-beta' }]
        }
      ]
    });

    const server = new DotsHttpServer(runtime);
    return { dir, dbPath, mockProvider, runtime, server };
  }

  it('enforces authentication, role authorization, and scope isolation over HTTP', async () => {
    const { server } = setupServer();
    const started = await server.start();

    try {
      // 1. Unauthenticated request -> 401
      const unauthRes = await fetch(`${started.url}/api/conversations`);
      assert.equal(unauthRes.status, 401);

      // 2. Viewer role attempting to create conversation -> 403 Forbidden
      const viewerCreateRes = await fetch(`${started.url}/api/conversations`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${VIEWER_TOKEN}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ title: 'Viewer Attempt' })
      });
      assert.equal(viewerCreateRes.status, 403);

      // 3. Member in ws-alpha creates conversation -> 201 Created
      const createRes = await fetch(`${started.url}/api/conversations`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${MEMBER_TOKEN}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ title: 'Alpha Team Chat' })
      });
      assert.equal(createRes.status, 201);
      const createJson = (await createRes.json()) as { conversation: { id: string; title: string; scope: { scopeId: string } } };
      assert.equal(createJson.conversation.title, 'Alpha Team Chat');
      assert.equal(createJson.conversation.scope.scopeId, 'ws-alpha');
      const convId = createJson.conversation.id;

      // 4. Viewer in ws-alpha can read conversation -> 200 OK
      const viewerReadRes = await fetch(`${started.url}/api/conversations/${convId}`, {
        headers: { Authorization: `Bearer ${VIEWER_TOKEN}` }
      });
      assert.equal(viewerReadRes.status, 200);

      // 5. Viewer in ws-alpha cannot send message -> 403 Forbidden
      const viewerSendRes = await fetch(`${started.url}/api/conversations/${convId}/messages`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${VIEWER_TOKEN}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ content: 'Unauthorized write' })
      });
      assert.equal(viewerSendRes.status, 403);

      // 6. Caller in ws-beta attempts to read conversation -> 403 Scope Violation
      const ws2ReadRes = await fetch(`${started.url}/api/conversations/${convId}`, {
        headers: { Authorization: `Bearer ${WS2_TOKEN}` }
      });
      assert.equal(ws2ReadRes.status, 403);

      // 7. Caller in ws-beta attempts to send message -> 403 Scope Violation
      const ws2SendRes = await fetch(`${started.url}/api/conversations/${convId}/messages`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${WS2_TOKEN}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ content: 'Cross-scope post' })
      });
      assert.equal(ws2SendRes.status, 403);
    } finally {
      await server.stop();
    }
  });

  it('supports full conversation lifecycle and message exchange over HTTP', async () => {
    const { server, mockProvider } = setupServer();
    const started = await server.start();

    try {
      mockProvider.enqueueCompletion('HTTP assistant response 1');

      // 1. Create conversation
      const createRes = await fetch(`${started.url}/api/conversations`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${MEMBER_TOKEN}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ title: 'Project Planning', metadata: { topic: 'milestone-2a' } })
      });
      assert.equal(createRes.status, 201);
      const createJson = (await createRes.json()) as { conversation: { id: string; status: string } };
      const convId = createJson.conversation.id;

      // 2. List conversations
      const listRes = await fetch(`${started.url}/api/conversations`, {
        headers: { Authorization: `Bearer ${MEMBER_TOKEN}` }
      });
      assert.equal(listRes.status, 200);
      const listJson = (await listRes.json()) as { conversations: Array<{ id: string }>; total: number };
      assert.equal(listJson.total, 1);
      assert.equal(listJson.conversations[0].id, convId);

      // 3. Send message
      const sendRes = await fetch(`${started.url}/api/conversations/${convId}/messages`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${MEMBER_TOKEN}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ content: 'What is the schedule for Milestone 2A?' })
      });
      assert.equal(sendRes.status, 200);
      const sendJson = (await sendRes.json()) as {
        userMessage: { content: string };
        assistantMessage: { content: string };
      };
      assert.equal(sendJson.userMessage.content, 'What is the schedule for Milestone 2A?');
      assert.equal(sendJson.assistantMessage.content, 'HTTP assistant response 1');

      // 4. Get conversation details and messages
      const getRes = await fetch(`${started.url}/api/conversations/${convId}`, {
        headers: { Authorization: `Bearer ${MEMBER_TOKEN}` }
      });
      assert.equal(getRes.status, 200);
      const getJson = (await getRes.json()) as {
        conversation: { id: string; title: string };
        messages: Array<{ role: string; content: string }>;
        totalMessages: number;
      };
      assert.equal(getJson.totalMessages, 2);
      assert.equal(getJson.messages[0].role, 'user');
      assert.equal(getJson.messages[1].role, 'assistant');

      // 5. Update conversation metadata
      const patchRes = await fetch(`${started.url}/api/conversations/${convId}`, {
        method: 'PATCH',
        headers: {
          Authorization: `Bearer ${MEMBER_TOKEN}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ title: 'Milestone 2A Execution' })
      });
      assert.equal(patchRes.status, 200);
      const patchJson = (await patchRes.json()) as { conversation: { title: string } };
      assert.equal(patchJson.conversation.title, 'Milestone 2A Execution');

      // 6. Archive conversation
      const archiveRes = await fetch(`${started.url}/api/conversations/${convId}/archive`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${MEMBER_TOKEN}` }
      });
      assert.equal(archiveRes.status, 200);
      const archiveJson = (await archiveRes.json()) as { conversation: { status: string } };
      assert.equal(archiveJson.conversation.status, 'ARCHIVED');

      // 7. Hard delete conversation
      const deleteRes = await fetch(`${started.url}/api/conversations/${convId}?hard=true`, {
        method: 'DELETE',
        headers: {
          Authorization: `Bearer ${ADMIN_TOKEN}`,
          'X-Dots-Scope': 'WORKSPACE:ws-alpha'
        }
      });
      assert.equal(deleteRes.status, 200);
      const deleteJson = (await deleteRes.json()) as { deleted: boolean };
      assert.equal(deleteJson.deleted, true);

      // 8. Confirm deleted -> 404
      const notFoundRes = await fetch(`${started.url}/api/conversations/${convId}`, {
        headers: { Authorization: `Bearer ${MEMBER_TOKEN}` }
      });
      assert.equal(notFoundRes.status, 404);
    } finally {
      await server.stop();
    }
  });

  it('executes CLI conversation operations in local mode', async () => {
    const dir = createTempDir();
    tempDirs.push(dir);
    const dbPath = join(dir, 'cli.db');

    const mockProvider = new MockModelProvider();
    mockProvider.enqueueCompletion('CLI assistant response');

    const cliOverrides = {
      dbPath,
      workspaceRoot: dir,
      modelProvider: mockProvider,
      tokens: [
        {
          token: ADMIN_TOKEN,
          principalId: 'alice-admin',
          role: 'ADMIN' as const,
          permittedScopes: [{ scopeType: 'WORKSPACE' as const, scopeId: 'ws-alpha' }]
        },
        {
          token: MEMBER_TOKEN,
          principalId: 'bob-member',
          role: 'MEMBER' as const,
          permittedScopes: [{ scopeType: 'WORKSPACE' as const, scopeId: 'ws-alpha' }]
        }
      ]
    };

    let capturedOutput = '';
    const io: CliIo = {
      stdout: (text: string) => {
        capturedOutput += `${text}\n`;
      },
      stderr: (text: string) => {
        capturedOutput += `[ERR] ${text}\n`;
      }
    };

    // 1. Create conversation via CLI
    let code = await runCli(
      ['conversation', 'create', '--title', 'CLI Test Session', '--token', MEMBER_TOKEN, '--json'],
      io,
      cliOverrides
    );
    assert.equal(code, 0);
    const created = JSON.parse(capturedOutput.trim()) as { conversation: { id: string; title: string } };
    assert.ok(created.conversation.id);
    assert.equal(created.conversation.title, 'CLI Test Session');
    const convId = created.conversation.id;

    // 2. List conversations via CLI
    capturedOutput = '';
    code = await runCli(
      ['conversation', 'list', '--token', MEMBER_TOKEN, '--json'],
      io,
      cliOverrides
    );
    assert.equal(code, 0);
    const listRes = JSON.parse(capturedOutput.trim()) as { conversations: Array<{ id: string }>; total: number };
    assert.equal(listRes.total, 1);
    assert.equal(listRes.conversations[0].id, convId);

    // 3. Send message via CLI
    capturedOutput = '';
    code = await runCli(
      ['conversation', 'send', convId, 'Hello from CLI', '--token', MEMBER_TOKEN, '--json'],
      io,
      cliOverrides
    );
    assert.equal(code, 0);
    const sendRes = JSON.parse(capturedOutput.trim()) as {
      userMessage: { content: string };
      assistantMessage: { content: string };
    };
    assert.equal(sendRes.userMessage.content, 'Hello from CLI');
    assert.equal(sendRes.assistantMessage.content, 'CLI assistant response');

    // 4. Get conversation details via CLI
    capturedOutput = '';
    code = await runCli(
      ['conversation', 'get', convId, '--token', MEMBER_TOKEN, '--json'],
      io,
      cliOverrides
    );
    assert.equal(code, 0);
    const getRes = JSON.parse(capturedOutput.trim()) as {
      conversation: { id: string };
      messages: Array<{ content: string }>;
      totalMessages: number;
    };
    assert.equal(getRes.totalMessages, 2);

    // 5. Update conversation via CLI
    capturedOutput = '';
    code = await runCli(
      ['conversation', 'update', convId, '--title', 'Renamed CLI Session', '--token', MEMBER_TOKEN, '--json'],
      io,
      cliOverrides
    );
    assert.equal(code, 0);
    const updateRes = JSON.parse(capturedOutput.trim()) as { conversation: { title: string } };
    assert.equal(updateRes.conversation.title, 'Renamed CLI Session');

    // 6. Archive conversation via CLI
    capturedOutput = '';
    code = await runCli(
      ['conversation', 'archive', convId, '--token', MEMBER_TOKEN, '--json'],
      io,
      cliOverrides
    );
    assert.equal(code, 0);
    const archiveRes = JSON.parse(capturedOutput.trim()) as { conversation: { status: string } };
    assert.equal(archiveRes.conversation.status, 'ARCHIVED');

    // 7. Delete conversation via CLI (hard delete)
    capturedOutput = '';
    code = await runCli(
      ['conversation', 'delete', convId, '--hard', '--token', ADMIN_TOKEN, '--json'],
      io,
      cliOverrides
    );
    assert.equal(code, 0);
    const deleteRes = JSON.parse(capturedOutput.trim()) as { deleted: boolean };
    assert.equal(deleteRes.deleted, true);
  });

  it('executes CLI conversation operations in remote HTTP mode', async () => {
    const { server, mockProvider } = setupServer();
    const started = await server.start();

    mockProvider.enqueueCompletion('Remote CLI assistant response');

    let capturedOutput = '';
    const io: CliIo = {
      stdout: (text: string) => {
        capturedOutput += `${text}\n`;
      },
      stderr: (text: string) => {
        capturedOutput += `[ERR] ${text}\n`;
      }
    };

    try {
      // 1. Create conversation remotely via CLI
      let code = await runCli(
        [
          'conversation',
          'create',
          '--title',
          'Remote CLI Chat',
          '--server',
          started.url,
          '--token',
          MEMBER_TOKEN,
          '--json'
        ],
        io
      );
      assert.equal(code, 0);
      const created = JSON.parse(capturedOutput.trim()) as { conversation: { id: string } };
      const convId = created.conversation.id;

      // 2. Send message remotely via CLI
      capturedOutput = '';
      code = await runCli(
        [
          'conversation',
          'send',
          convId,
          'Remote CLI query',
          '--server',
          started.url,
          '--token',
          MEMBER_TOKEN,
          '--json'
        ],
        io
      );
      assert.equal(code, 0);
      const sendRes = JSON.parse(capturedOutput.trim()) as {
        userMessage: { content: string };
        assistantMessage: { content: string };
      };
      assert.equal(sendRes.userMessage.content, 'Remote CLI query');
      assert.equal(sendRes.assistantMessage.content, 'Remote CLI assistant response');

      // 3. List messages remotely via CLI
      capturedOutput = '';
      code = await runCli(
        [
          'conversation',
          'messages',
          convId,
          '--server',
          started.url,
          '--token',
          MEMBER_TOKEN,
          '--json'
        ],
        io
      );
      assert.equal(code, 0);
      const msgsRes = JSON.parse(capturedOutput.trim()) as { messages: Array<{ content: string }>; total: number };
      assert.equal(msgsRes.total, 2);

      // 4. Archive conversation remotely via CLI
      capturedOutput = '';
      code = await runCli(
        [
          'conversation',
          'archive',
          convId,
          '--server',
          started.url,
          '--token',
          MEMBER_TOKEN,
          '--json'
        ],
        io
      );
      assert.equal(code, 0);
      const archiveRes = JSON.parse(capturedOutput.trim()) as { conversation: { status: string } };
      assert.equal(archiveRes.conversation.status, 'ARCHIVED');
    } finally {
      await server.stop();
    }
  });
});
