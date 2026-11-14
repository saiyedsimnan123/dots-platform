/**
 * Next-Generation Dots AI Platform - Research Agent Integration Tests
 * Phase 3A: TaskCoordinator, TaskWorkflow, ConversationService, HTTP API & CLI Integration
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
import type { ResearchReport } from '../../src/agents/research-agent.ts';

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

test('Research Agent - executes end-to-end through TaskCoordinator and persists audit and result metadata', async () => {
  const tmpDir = mkdtempSync(join(tmpdir(), 'dots-research-coord-'));
  const dbPath = join(tmpDir, 'test.db');

  const mockSearch = new MockWebSearchProvider();
  mockSearch.setDefaultResults([
    {
      title: 'Quantum Key Distribution Standards',
      url: 'https://qkd-standards.example/overview',
      snippet: 'QKD uses quantum mechanics to guarantee secure cryptographic communication. Practical deployment has achieved 100km fiber range.',
      domain: 'qkd-standards.example'
    },
    {
      title: 'Post-Quantum Cryptography Migration Guide',
      url: 'https://pqc-guide.example/migration',
      snippet: 'NIST selected lattice-based algorithms for general encryption and digital signatures to counter Shor algorithm threats.',
      domain: 'pqc-guide.example'
    }
  ]);
  setWebSearchProvider(mockSearch);

  const runtime = new DotsRuntime({
    dbPath,
    workspaceRoot: tmpDir,
    provider: 'mock',
    webSearchProvider: mockSearch,
    autoApproveTier2: true,
    autoApproveTier3: true,
    silentLogs: true,
    tokens: [
      {
        token: 'researcher-token',
        principalId: 'researcher-user',
        role: 'ADMIN',
        permittedScopes: [{ scopeType: 'GLOBAL', scopeId: 'default' }]
      }
    ]
  });

  try {
    const { caller } = runtime.authenticateUser('researcher-token');

    // 1. Submit and run task via TaskCoordinator executeAgent
    const output = await runtime.coordinator.executeAgent('research-agent', {
      goal: 'Evaluate Quantum Key Distribution vs Post-Quantum Cryptography',
      caller,
      parameters: { depth: 'standard' }
    });

    assert.equal(output.status, 'COMPLETED');
    assert.equal(output.agentId, 'research-agent');
    assert.ok(output.taskId);

    const report = output.result.report as ResearchReport;
    assert.equal(report.completionStatus, 'COMPLETED');
    assert.equal(report.evidenceAndSources.length, 2);
    assert.ok(report.keyFindings.length >= 2);

    // 2. Verify Task State Machine transition in TaskRepository
    const task = runtime.taskRepo.getTaskById(output.taskId!);
    assert.ok(task);
    assert.equal(task.status, 'COMPLETED');

    // 3. Verify Audit Events recorded in AuditRepository
    const events = runtime.auditRepo.getEventsByTaskId(output.taskId!);
    const eventTypes = events.map((e) => e.eventType);
    assert.ok(eventTypes.includes('AGENT_EXECUTION_STARTED'));
    assert.ok(eventTypes.includes('AGENT_EXECUTION_COMPLETED'));
  } finally {
    setWebSearchProvider(null);
    await runtime.stop();
    rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('Research Agent - business task submission via TaskWorkflowService returns structured research results', async () => {
  const tmpDir = mkdtempSync(join(tmpdir(), 'dots-research-workflow-'));
  const dbPath = join(tmpDir, 'test.db');

  const mockSearch = new MockWebSearchProvider();
  mockSearch.setDefaultResults([
    {
      title: 'Decentralized Autonomous Organizations Overview',
      url: 'https://governance.example/dao-overview',
      snippet: 'DAOs represent native on-chain governance coordination with transparent voting and programmable treasury allocations.',
      domain: 'governance.example'
    },
    {
      title: 'Legal and Regulatory Challenges for DAOs',
      url: 'https://legal.example/dao-regulations',
      snippet: 'Key regulatory challenges include legal entity recognition, fiduciary responsibility, and jurisdiction ambiguities.',
      domain: 'legal.example'
    }
  ]);
  setWebSearchProvider(mockSearch);

  const runtime = new DotsRuntime({
    dbPath,
    workspaceRoot: tmpDir,
    provider: 'mock',
    webSearchProvider: mockSearch,
    autoApproveTier2: true,
    autoApproveTier3: true,
    silentLogs: true,
    tokens: [
      {
        token: 'analyst-token',
        principalId: 'analyst-user',
        role: 'MEMBER',
        permittedScopes: [{ scopeType: 'GLOBAL', scopeId: 'default' }]
      }
    ]
  });

  try {
    const { caller } = runtime.authenticateUser('analyst-token');

    // Submit task selecting the research agent
    const submitted = await runtime.submitTask(caller, {
      objective: 'Analyze legal and governance structures of DAOs',
      agentId: 'research-agent',
      parameters: { depth: 'standard' },
      run: true
    });

    assert.equal(submitted.status, 'COMPLETED');

    // Retrieve structured business task result view
    const resultView = runtime.getTaskResult(caller, submitted.id);
    assert.equal(resultView.status, 'COMPLETED');
    assert.equal(resultView.agentId, 'research-agent');

    const resultObj = resultView.output as { report: ResearchReport; reportMarkdown: string };
    assert.ok(resultObj.report);
    assert.equal(resultObj.report.completionStatus, 'COMPLETED');
    assert.equal(resultObj.report.evidenceAndSources.length, 2);
    assert.ok(resultObj.reportMarkdown.includes('# Research Report:'));
  } finally {
    setWebSearchProvider(null);
    await runtime.stop();
    rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('Research Agent - persistent conversation integration formats rich markdown response and preserves history', async () => {
  const tmpDir = mkdtempSync(join(tmpdir(), 'dots-research-conv-'));
  const dbPath = join(tmpDir, 'test.db');

  const mockSearch = new MockWebSearchProvider();
  mockSearch.setDefaultResults([
    {
      title: 'Fusion Energy Progress Report',
      url: 'https://energy.example/fusion-2026',
      snippet: 'Net energy gain Q > 1 has been verified in experimental magnetic confinement tokamaks, but economical commercial generation requires sustained pulse stability.',
      domain: 'energy.example'
    },
    {
      title: 'Fission vs Fusion Capital Costs',
      url: 'https://nuclear-finance.example/costs',
      snippet: 'Initial capital costs for fusion prototypes remain substantially higher than existing generation-III+ fission reactors.',
      domain: 'nuclear-finance.example'
    }
  ]);
  setWebSearchProvider(mockSearch);

  const runtime = new DotsRuntime({
    dbPath,
    workspaceRoot: tmpDir,
    provider: 'mock',
    webSearchProvider: mockSearch,
    autoApproveTier2: true,
    autoApproveTier3: true,
    silentLogs: true,
    tokens: [
      {
        token: 'user-conv-token',
        principalId: 'user-alice',
        role: 'MEMBER',
        permittedScopes: [{ scopeType: 'GLOBAL', scopeId: 'default' }]
      }
    ]
  });

  try {
    const { caller } = runtime.authenticateUser('user-conv-token');

    // 1. Create a persistent conversation bound to the research agent
    const conversation = runtime.createConversation(caller, {
      title: 'Nuclear Energy Research',
      agentId: 'research-agent'
    });
    assert.equal(conversation.agentId, 'research-agent');

    // 2. Send research inquiry
    const sendResult = await runtime.sendConversationMessage(caller, conversation.id, {
      content: 'What is the current economic viability of nuclear fusion compared to fission?'
    });

    assert.ok(sendResult.assistantMessage);
    assert.equal(sendResult.assistantMessage.role, 'assistant');
    assert.equal(sendResult.assistantMessage.name, 'research-agent');

    // Assistant message must contain rich markdown report
    const messageContent = sendResult.assistantMessage.content;
    assert.ok(messageContent.includes('# Research Report:'));
    assert.ok(messageContent.includes('## Executive Summary'));
    assert.ok(messageContent.includes('## Key Findings'));
    assert.ok(messageContent.includes('energy.example'));

    // 3. Conversation history must contain both user message and research assistant report
    const history = runtime.getConversationMessages(caller, conversation.id);
    assert.equal(history.total, 2);
    assert.equal(history.messages[0]!.role, 'user');
    assert.equal(history.messages[1]!.role, 'assistant');
  } finally {
    setWebSearchProvider(null);
    await runtime.stop();
    rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('HTTP API & CLI - agents catalog endpoint and CLI agents list (local & remote)', async () => {
  const tmpDir = mkdtempSync(join(tmpdir(), 'dots-agents-api-'));
  const dbPath = join(tmpDir, 'test.db');

  const tokens = [
    {
      token: 'admin-agent-token',
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
    // 1. HTTP GET /api/agents (401 unauthenticated check)
    const unauthRes = await fetch(`${baseUrl}/api/agents`);
    assert.equal(unauthRes.status, 401);

    // 2. HTTP GET /api/agents (200 authenticated check)
    const authRes = await fetch(`${baseUrl}/api/agents`, {
      headers: {
        Authorization: 'Bearer admin-agent-token'
      }
    });
    assert.equal(authRes.status, 200);

    const body = (await authRes.json()) as {
      agents: Array<{ id: string; name: string; capabilities: string[] }>;
      count: number;
    };
    assert.ok(Array.isArray(body.agents));
    assert.ok(body.count >= 1);

    const researchDef = body.agents.find((a) => a.id === 'research-agent');
    assert.ok(researchDef, 'research-agent must be discoverable in /api/agents catalog');
    assert.ok(researchDef.capabilities.includes('research'));
    assert.ok(researchDef.capabilities.includes('conversation'));

    // 3. Local CLI: dots agents list --token ... --db ... --json
    const localIo = createMockIo();
    const localExit = await runCli(
      ['--token', 'admin-agent-token', '--db', dbPath, '--workspace', tmpDir, '--json', 'agents', 'list'],
      localIo.io,
      { tokens }
    );
    assert.equal(localExit, 0, localIo.getStderr());

    const localData = JSON.parse(localIo.getStdout()) as { agents: Array<{ id: string }>; count: number };
    assert.ok(Array.isArray(localData.agents));
    assert.ok(localData.agents.some((a) => a.id === 'research-agent'));

    // 4. Remote CLI: dots agents list --server ... --token ... --json
    const remoteIo = createMockIo();
    const remoteExit = await runCli(
      ['--server', baseUrl, '--token', 'admin-agent-token', '--json', 'agents', 'list'],
      remoteIo.io
    );
    assert.equal(remoteExit, 0, remoteIo.getStderr());

    const remoteData = JSON.parse(remoteIo.getStdout()) as { agents: Array<{ id: string }>; count: number };
    assert.ok(Array.isArray(remoteData.agents));
    assert.equal(remoteData.count, localData.count);
  } finally {
    await server.stop();
    await runtime.stop();
    rmSync(tmpDir, { recursive: true, force: true });
  }
});
