/**
 * Next-Generation Dots AI Platform - Analytics Agent Integration Tests
 * Phase 3B: TaskCoordinator, TaskWorkflow, ConversationService, HTTP API & CLI Integration
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DotsRuntime } from '../../src/runtime/app.ts';
import { DotsHttpServer } from '../../src/api/http-server.ts';
import { runCli, type CliIo } from '../../src/cli/main.ts';
import type { AnalyticsReport } from '../../src/agents/analytics-agent.ts';

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

test('Analytics Agent - executes end-to-end through TaskCoordinator and persists audit and result metadata', async () => {
  const tmpDir = mkdtempSync(join(tmpdir(), 'dots-analytics-coord-'));
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
        token: 'analyst-token',
        principalId: 'analyst-user',
        role: 'ADMIN',
        permittedScopes: [{ scopeType: 'GLOBAL', scopeId: 'default' }]
      }
    ]
  });

  try {
    const { caller } = runtime.authenticateUser('analyst-token');

    const csvData =
      'region,revenue,units_sold\n' +
      'East,12000,150\n' +
      'West,18500,210\n' +
      'East,14200,165\n' +
      'North,9800,110\n' +
      'West,21000,240\n';

    // 1. Submit and execute task via TaskCoordinator executeAgent
    const output = await runtime.coordinator.executeAgent('analytics-agent', {
      goal: 'Analyze quarterly regional revenue and sales performance',
      caller,
      parameters: { csv: csvData }
    });

    assert.equal(output.status, 'COMPLETED');
    assert.equal(output.agentId, 'analytics-agent');
    assert.ok(output.taskId);

    const report = output.result.report as AnalyticsReport;
    assert.equal(report.datasetProfile.rowCount, 5);
    assert.equal(report.datasetProfile.columnCount, 3);
    assert.ok(report.numericStatistics['revenue']);
    assert.ok(report.numericStatistics['units_sold']);
    assert.equal(report.dataQuality.overallQualityScore, 'EXCELLENT');

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

test('Analytics Agent - business task submission via TaskWorkflowService returns structured analytics', async () => {
  const tmpDir = mkdtempSync(join(tmpdir(), 'dots-analytics-workflow-'));
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
        token: 'analyst-token',
        principalId: 'analyst-user',
        role: 'MEMBER',
        permittedScopes: [{ scopeType: 'GLOBAL', scopeId: 'default' }]
      }
    ]
  });

  try {
    const { caller } = runtime.authenticateUser('analyst-token');

    const jsonRecords = [
      { employee_id: 'E01', department: 'Engineering', tenure_years: 4, salary: 120000 },
      { employee_id: 'E02', department: 'Engineering', tenure_years: 2, salary: 95000 },
      { employee_id: 'E03', department: 'Marketing', tenure_years: 5, salary: 85000 },
      { employee_id: 'E04', department: 'Sales', tenure_years: 3, salary: 90000 }
    ];

    // Submit task selecting analytics alias via runtime.submitTask
    const submitted = await runtime.submitTask(caller, {
      objective: 'Evaluate departmental compensation distribution',
      agentId: 'analytics',
      parameters: { records: jsonRecords },
      run: true
    });

    assert.equal(submitted.status, 'COMPLETED');

    // Retrieve structured business task result view
    const resultView = runtime.getTaskResult(caller, submitted.id);
    assert.equal(resultView.status, 'COMPLETED');
    assert.equal(resultView.agentId, 'analytics');

    const resultObj = resultView.output as { report: AnalyticsReport; reportMarkdown: string };
    assert.ok(resultObj.report);
    assert.equal(resultObj.report.datasetProfile.rowCount, 4);
    assert.equal(resultObj.report.numericStatistics['salary']!.mean, 97500);
    assert.ok(resultView.summary && resultView.summary.includes('Analytics completed'));
  } finally {
    await runtime.stop();
    rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('Analytics Agent - persistent conversation integration formats rich markdown response and preserves history', async () => {
  const tmpDir = mkdtempSync(join(tmpdir(), 'dots-analytics-conv-'));
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

    // 1. Create persistent conversation bound to analytics-agent
    const conversation = runtime.createConversation(caller, {
      title: 'Store Performance Analysis',
      agentId: 'analytics-agent'
    });
    assert.equal(conversation.agentId, 'analytics-agent');

    // 2. Send message with inline CSV data
    const csvContent =
      'store_id,foot_traffic,conversion_rate,daily_revenue\n' +
      'S01,500,0.12,3200\n' +
      'S02,750,0.15,5100\n' +
      'S03,300,0.08,1800\n' +
      'S04,900,0.18,6500\n';

    const sendResult = await runtime.sendConversationMessage(caller, conversation.id, {
      content: csvContent
    });

    assert.ok(sendResult.assistantMessage);
    assert.equal(sendResult.assistantMessage.role, 'assistant');
    assert.equal(sendResult.assistantMessage.name, 'analytics-agent');

    // Markdown table check
    assert.ok(sendResult.assistantMessage.content.includes('# Analytics Report'));
    assert.ok(sendResult.assistantMessage.content.includes('## Dataset Profile'));
    assert.ok(sendResult.assistantMessage.content.includes('## Descriptive Statistics'));

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

test('Analytics Agent - discoverable via HTTP API and CLI agents catalog', async () => {
  const tmpDir = mkdtempSync(join(tmpdir(), 'dots-analytics-api-'));
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

    const analyticsAgentDef = body.agents.find((a) => a.id === 'analytics-agent');
    assert.ok(analyticsAgentDef);
    assert.ok(analyticsAgentDef.capabilities.includes('analytics'));
    assert.ok(analyticsAgentDef.capabilities.includes('data-analysis'));

    const analyticsAliasDef = body.agents.find((a) => a.id === 'analytics');
    assert.ok(analyticsAliasDef);

    // 2. CLI in remote HTTP mode
    const mockIoRemote = createMockIo();
    const codeRemote = await runCli(
      ['--server', serverUrl, '--token', 'admin-token', '--json', 'agents', 'list'],
      mockIoRemote.io
    );
    assert.equal(codeRemote, 0, mockIoRemote.getStderr());
    assert.ok(mockIoRemote.getStdout().includes('analytics-agent'));

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
    assert.ok(mockIoLocal.getStdout().includes('analytics-agent'));
  } finally {
    await server.stop();
    await runtime.stop();
    rmSync(tmpDir, { recursive: true, force: true });
  }
});
