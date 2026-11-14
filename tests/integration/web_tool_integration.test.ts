/**
 * Next-Generation Dots AI Platform - Milestone 2C Integration Tests
 * Verification of Tools HTTP API Endpoint, CLI tools list (Local & Remote), and Agent Web Tool Execution
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DotsRuntime } from '../../src/runtime/app.ts';
import { DotsHttpServer } from '../../src/api/http-server.ts';
import { runCli, type CliIo } from '../../src/cli/main.ts';
import { MockWebSearchProvider, setWebSearchProvider } from '../../src/tools/web-tools.ts';
import { BaseAgent } from '../../src/agents/base-agent.ts';
import type { AgentExecutionContext, AgentInput, AgentOutput } from '../../src/agents/types.ts';
import type { CallerContext } from '../../src/domain/types.ts';

function createMockIo(): { io: CliIo; getStdout: () => string; getStderr: () => string } {
  let stdout = '';
  let stderr = '';
  return {
    io: {
      stdout: (chunk: string) => {
        stdout += chunk;
      },
      stderr: (chunk: string) => {
        stderr += chunk;
      }
    },
    getStdout: () => stdout,
    getStderr: () => stderr
  };
}

test('HTTP API - GET /api/tools requires authentication and returns tool catalog', async () => {
  const tmpDir = mkdtempSync(join(tmpdir(), 'dots-tools-api-'));
  const dbPath = join(tmpDir, 'test.db');

  const runtime = new DotsRuntime({
    dbPath,
    workspaceRoot: tmpDir,
    provider: 'mock',
    silentLogs: true,
    tokens: [
      {
        token: 'admin-token',
        principalId: 'admin-user',
        role: 'ADMIN',
        permittedScopes: [{ scopeType: 'GLOBAL', scopeId: 'default' }]
      }
    ]
  });

  const server = new DotsHttpServer(runtime, { port: 0, host: '127.0.0.1' });
  const started = await server.start();
  const baseUrl = started.url;

  try {
    // 1. Unauthenticated request should be rejected with 401
    const unauthRes = await fetch(`${baseUrl}/api/tools`);
    assert.equal(unauthRes.status, 401);

    // 2. Authenticated request should return tool list
    const authRes = await fetch(`${baseUrl}/api/tools`, {
      headers: {
        Authorization: 'Bearer admin-token'
      }
    });
    assert.equal(authRes.status, 200);

    const body = (await authRes.json()) as { tools: Array<{ name: string; riskTier: string; description: string }>; count: number };
    assert.ok(Array.isArray(body.tools));
    assert.ok(body.count >= 8);

    const toolNames = new Set(body.tools.map((t) => t.name));
    assert.ok(toolNames.has('calculate'));
    assert.ok(toolNames.has('file_read'));
    assert.ok(toolNames.has('web_search'));
    assert.ok(toolNames.has('web_fetch'));

    const searchTool = body.tools.find((t) => t.name === 'web_search');
    assert.ok(searchTool);
    assert.equal(searchTool.riskTier, 'TIER_3');
  } finally {
    await server.stop();
    await runtime.stop();
    rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('CLI - dots tools list operates in local and remote modes', async () => {
  const tmpDir = mkdtempSync(join(tmpdir(), 'dots-tools-cli-'));
  const dbPath = join(tmpDir, 'test.db');

  const tokens = [
    {
      token: 'admin-cli-token',
      principalId: 'admin-user',
      role: 'ADMIN' as const,
      permittedScopes: [{ scopeType: 'GLOBAL' as const, scopeId: 'default' }]
    }
  ];

  const runtime = new DotsRuntime({
    dbPath,
    workspaceRoot: tmpDir,
    provider: 'mock',
    silentLogs: true,
    tokens
  });

  const server = new DotsHttpServer(runtime, { port: 0, host: '127.0.0.1' });
  const started = await server.start();
  const baseUrl = started.url;

  try {
    // 1. Local mode CLI: dots tools list --token <token> --db <dbPath> --json
    const localIo = createMockIo();
    const localExit = await runCli(
      ['--token', 'admin-cli-token', '--db', dbPath, '--workspace', tmpDir, '--json', 'tools', 'list'],
      localIo.io,
      { tokens }
    );
    assert.equal(localExit, 0, localIo.getStderr());

    const localData = JSON.parse(localIo.getStdout()) as { tools: Array<{ name: string }>; count: number };
    assert.ok(Array.isArray(localData.tools));
    assert.ok(localData.count >= 8);
    const localNames = new Set(localData.tools.map((t) => t.name));
    assert.ok(localNames.has('web_fetch'));
    assert.ok(localNames.has('web_search'));

    // 2. Remote mode CLI: dots tools list --server <baseUrl> --token <token>
    const remoteIo = createMockIo();
    const remoteExit = await runCli(
      ['--server', baseUrl, '--token', 'admin-cli-token', '--json', 'tools', 'list'],
      remoteIo.io
    );
    assert.equal(remoteExit, 0, remoteIo.getStderr());

    const remoteData = JSON.parse(remoteIo.getStdout()) as { tools: Array<{ name: string }>; count: number };
    assert.ok(Array.isArray(remoteData.tools));
    assert.equal(remoteData.count, localData.count);
  } finally {
    await server.stop();
    await runtime.stop();
    rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('Agent Tool Execution - agent discovers and executes tools via context', async () => {
  const tmpDir = mkdtempSync(join(tmpdir(), 'dots-agent-tools-'));
  const dbPath = join(tmpDir, 'test.db');

  const mockSearch = new MockWebSearchProvider();
  mockSearch.setDefaultResults([
    {
      title: 'Dots Verification Architecture',
      url: 'https://dots.dev/verifier',
      snippet: 'Cryptographic hash and evidence-based verification.',
      domain: 'dots.dev'
    }
  ]);
  setWebSearchProvider(mockSearch);

  // Define an agent that uses context.listTools() and executes calculate tool
  class ToolUsingAgent extends BaseAgent {
    constructor() {
      super({
        id: 'agent.tool-consumer',
        name: 'Tool Consumer Agent',
        description: 'Agent that discovers and invokes tools via context',
        capabilities: ['CALCULATE', 'TOOL_DISCOVERY']
      });
    }

    public async execute(input: AgentInput, context: AgentExecutionContext): Promise<AgentOutput> {
      // 1. Discover tools
      const tools = context.listTools();
      const hasSearch = tools.some((t) => t.name === 'web_search');
      assert.ok(hasSearch, 'Context must list web_search tool');

      // 2. Execute calculate tool (Tier 0, safe)
      const calcResult = await context.executeTool('calculate', { expression: '40 + 2' });

      return {
        agentId: this.id,
        taskId: input.taskId,
        status: 'COMPLETED',
        result: {
          calculation: calcResult.output,
          toolsDiscoveredCount: tools.length
        },
        summary: `Discovered ${tools.length} tools and calculated 42.`,
        stepsExecuted: 1,
        durationMs: 10
      };
    }
  }

  const runtime = new DotsRuntime({
    dbPath,
    workspaceRoot: tmpDir,
    provider: 'mock',
    silentLogs: true,
    tokens: [
      {
        token: 'admin-agent-token',
        principalId: 'admin-agent',
        role: 'ADMIN',
        permittedScopes: [{ scopeType: 'GLOBAL', scopeId: 'default' }]
      }
    ]
  });

  runtime.agentRegistry.register(new ToolUsingAgent());

  try {
    const { caller } = runtime.authenticateUser('admin-agent-token');

    const taskResult = await runtime.submitTask(caller, {
      objective: 'Run tool-using agent test',
      agentId: 'agent.tool-consumer',
      run: true
    });

    assert.equal(taskResult.status, 'COMPLETED');
    const resultView = runtime.getTaskResult(caller, taskResult.id);
    assert.equal(resultView.status, 'COMPLETED');
    const resultObj = resultView.output as {
      calculation: { result: number };
      toolsDiscoveredCount: number;
    };
    assert.equal(resultObj.calculation.result, 42);
    assert.ok(resultObj.toolsDiscoveredCount >= 8);
  } finally {
    setWebSearchProvider(null);
    await runtime.stop();
    rmSync(tmpDir, { recursive: true, force: true });
  }
});
