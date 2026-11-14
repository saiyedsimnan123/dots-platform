/**
 * Next-Generation Dots AI Platform - Developer Agent Integration Tests
 * Phase 3C: TaskCoordinator, TaskWorkflow, ConversationService, HTTP API & CLI Integration
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DotsRuntime } from '../../src/runtime/app.ts';
import { DotsHttpServer } from '../../src/api/http-server.ts';
import { runCli, type CliIo } from '../../src/cli/main.ts';
import type { DeveloperReport } from '../../src/agents/developer-agent.ts';

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

test('Developer Agent - executes end-to-end through TaskCoordinator and persists audit and result metadata', async () => {
  const tmpDir = mkdtempSync(join(tmpdir(), 'dots-dev-coord-'));
  const dbPath = join(tmpDir, 'test.db');

  const sourceFile = join(tmpDir, 'service.ts');
  writeFileSync(
    sourceFile,
    'export class MetricCollector {\n' +
    '  private count = 0;\n' +
    '  public record() { this.count++; }\n' +
    '  public get() { return this.count; }\n' +
    '}\n',
    'utf8'
  );

  const runtime = new DotsRuntime({
    dbPath,
    workspaceRoot: tmpDir,
    provider: 'mock',
    autoApproveTier2: true,
    autoApproveTier3: true,
    silentLogs: true,
    tokens: [
      {
        token: 'dev-token',
        principalId: 'dev-user',
        role: 'ADMIN',
        permittedScopes: [{ scopeType: 'GLOBAL', scopeId: 'default' }]
      }
    ]
  });

  try {
    const { caller } = runtime.authenticateUser('dev-token');

    // 1. Submit and execute task via TaskCoordinator executeAgent
    const output = await runtime.coordinator.executeAgent('developer-agent', {
      goal: 'Analyze service.ts and propose test plan',
      caller,
      parameters: {
        operation: 'TEST_PLAN',
        files: ['service.ts']
      }
    });

    assert.equal(output.status, 'COMPLETED');
    assert.equal(output.agentId, 'developer-agent');
    assert.ok(output.taskId);

    const report = output.result.report as DeveloperReport;
    assert.equal(report.operation, 'TEST_PLAN');
    assert.equal(report.completionStatus, 'COMPLETED');
    assert.equal(report.filesInspected.length, 1);
    assert.equal(report.filesInspected[0]!.path, 'service.ts');
    assert.ok(report.generatedCode?.includes('Happy Path Scenarios'));

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
    await runtime.stop();
    rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('Developer Agent - business task submission via TaskWorkflowService returns structured report', async () => {
  const tmpDir = mkdtempSync(join(tmpdir(), 'dots-dev-workflow-'));
  const dbPath = join(tmpDir, 'test.db');

  const runtime = new DotsRuntime({
    dbPath,
    workspaceRoot: tmpDir,
    provider: 'mock',
    autoApproveTier2: true,
    autoApproveTier3: true,
    silentLogs: true,
    tokens: [
      {
        token: 'dev-token',
        principalId: 'dev-user',
        role: 'MEMBER',
        permittedScopes: [{ scopeType: 'GLOBAL', scopeId: 'default' }]
      }
    ]
  });

  try {
    const { caller } = runtime.authenticateUser('dev-token');

    const buggyCode =
      'export function divide(a: number, b: number): number {\n' +
      '  if (b === 0) throw new Error("Division by zero");\n' +
      '  return a / b;\n' +
      '}\n';

    // Submit task selecting developer alias via runtime.submitTask
    const submitted = await runtime.submitTask(caller, {
      objective: 'Review divide implementation for edge cases',
      agentId: 'developer',
      parameters: {
        operation: 'REVIEW',
        code: buggyCode
      },
      run: true
    });

    assert.equal(submitted.status, 'COMPLETED');

    // Retrieve structured business task result view
    const resultView = runtime.getTaskResult(caller, submitted.id);
    assert.equal(resultView.status, 'COMPLETED');
    assert.equal(resultView.agentId, 'developer');

    const resultObj = resultView.output as { report: DeveloperReport; reportMarkdown: string };
    assert.ok(resultObj.report);
    assert.equal(resultObj.report.operation, 'REVIEW');
    assert.equal(resultObj.report.completionStatus, 'COMPLETED');
    assert.ok(resultObj.reportMarkdown.includes('# Developer Report:'));
  } finally {
    await runtime.stop();
    rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('Developer Agent - persistent conversation integration formats rich markdown response and preserves history', async () => {
  const tmpDir = mkdtempSync(join(tmpdir(), 'dots-dev-conv-'));
  const dbPath = join(tmpDir, 'test.db');

  const runtime = new DotsRuntime({
    dbPath,
    workspaceRoot: tmpDir,
    provider: 'mock',
    autoApproveTier2: true,
    autoApproveTier3: true,
    silentLogs: true,
    tokens: [
      {
        token: 'conv-user-token',
        principalId: 'conv-user',
        role: 'MEMBER',
        permittedScopes: [{ scopeType: 'GLOBAL', scopeId: 'default' }]
      }
    ]
  });

  try {
    const { caller } = runtime.authenticateUser('conv-user-token');

    // 1. Create persistent conversation bound to developer-agent
    const conversation = runtime.createConversation(caller, {
      title: 'Debugging Token Authentication',
      agentId: 'developer-agent'
    });
    assert.equal(conversation.agentId, 'developer-agent');

    // 2. Send message requesting bug analysis
    const sendResult = await runtime.sendConversationMessage(caller, conversation.id, {
      content: 'Debug this code:\n```typescript\nfunction get(obj) { return obj.name; }\n```\nError: Cannot read properties of undefined'
    });

    assert.ok(sendResult.assistantMessage);
    assert.equal(sendResult.assistantMessage.role, 'assistant');
    assert.equal(sendResult.assistantMessage.name, 'developer-agent');

    // Markdown report check
    const content = sendResult.assistantMessage.content;
    assert.ok(content.includes('# Developer Report:'));
    assert.ok(content.includes('## Executive Summary'));
    assert.ok(content.includes('## Verification & Test Execution'));

    // 3. Verify messages are persisted and retrieved chronologically
    const history = runtime.getConversationMessages(caller, conversation.id);
    assert.equal(history.total, 2);
    assert.equal(history.messages[0]!.role, 'user');
    assert.equal(history.messages[1]!.role, 'assistant');
  } finally {
    await runtime.stop();
    rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('Developer Agent - discoverable via HTTP API and CLI agents catalog', async () => {
  const tmpDir = mkdtempSync(join(tmpdir(), 'dots-dev-api-'));
  const dbPath = join(tmpDir, 'test.db');

  const tokens = [
    {
      token: 'admin-token',
      principalId: 'admin-user',
      role: 'ADMIN' as const,
      permittedScopes: [{ scopeType: 'GLOBAL' as const, scopeId: 'default' }]
    }
  ];

  const runtime = new DotsRuntime({
    dbPath,
    workspaceRoot: tmpDir,
    provider: 'mock',
    autoApproveTier2: true,
    autoApproveTier3: true,
    silentLogs: true,
    tokens
  });

  const server = new DotsHttpServer(runtime, { port: 0, host: '127.0.0.1' });
  const started = await server.start();
  const serverUrl = started.url;

  try {
    // 1. HTTP GET /api/agents
    const res = await fetch(`${serverUrl}/api/agents`, {
      headers: { Authorization: 'Bearer admin-token' }
    });
    assert.equal(res.status, 200);
    const body = (await res.json()) as { agents: Array<{ id: string; capabilities: string[] }> };
    assert.ok(Array.isArray(body.agents));

    const devAgentDef = body.agents.find((a) => a.id === 'developer-agent');
    assert.ok(devAgentDef);
    assert.ok(devAgentDef.capabilities.includes('development'));
    assert.ok(devAgentDef.capabilities.includes('code-analysis'));
    assert.ok(devAgentDef.capabilities.includes('debugging'));

    const devAliasDef = body.agents.find((a) => a.id === 'developer');
    assert.ok(devAliasDef);

    // 2. CLI in remote HTTP mode
    const mockIoRemote = createMockIo();
    const codeRemote = await runCli(
      ['--server', serverUrl, '--token', 'admin-token', '--json', 'agents', 'list'],
      mockIoRemote.io
    );
    assert.equal(codeRemote, 0, mockIoRemote.getStderr());
    assert.ok(mockIoRemote.getStdout().includes('developer-agent'));

    // 3. CLI in local mode
    const mockIoLocal = createMockIo();
    const codeLocal = await runCli(
      [
        '--token',
        'admin-token',
        '--db',
        dbPath,
        '--workspace',
        tmpDir,
        '--json',
        'agents',
        'list'
      ],
      mockIoLocal.io,
      { tokens }
    );
    assert.equal(codeLocal, 0, mockIoLocal.getStderr());
    assert.ok(mockIoLocal.getStdout().includes('developer-agent'));
  } finally {
    await server.stop();
    await runtime.stop();
    rmSync(tmpDir, { recursive: true, force: true });
  }
});
