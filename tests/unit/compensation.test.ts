/**
 * Next-Generation Dots AI Platform - Compensation Manager Unit Tests
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { resolve } from 'node:path';
import { existsSync, rmSync, mkdirSync, writeFileSync } from 'node:fs';
import { DatabaseManager } from '../../src/storage/db.ts';
import { TaskRepository } from '../../src/storage/task-repository.ts';
import { AuditRepository } from '../../src/storage/audit-repository.ts';
import { CompensationManager } from '../../src/orchestrator/compensation.ts';

const testWorkspace = resolve('test_comp_workspace');

function setupTest() {
  if (existsSync(testWorkspace)) rmSync(testWorkspace, { recursive: true, force: true });
  mkdirSync(testWorkspace, { recursive: true });

  const db = new DatabaseManager(':memory:');
  const taskRepo = new TaskRepository(db);
  const auditRepo = new AuditRepository(db);
  const compensationManager = new CompensationManager(taskRepo, auditRepo, testWorkspace);

  return { db, taskRepo, auditRepo, compensationManager };
}

test('CompensationManager - safely reverts created files inside workspace and records audit event', async () => {
  const { db, taskRepo, auditRepo, compensationManager } = setupTest();

  try {
    const task = taskRepo.createTask({ goal: 'Task that created scratch files' });
    const step = taskRepo.createStep({
      taskId: task.id,
      stepOrder: 1,
      description: 'Write scratch file',
      toolName: 'file_write',
      toolArguments: { path: resolve(testWorkspace, 'scratch_file.txt'), content: 'temporary' }
    });

    const scratchPath = resolve(testWorkspace, 'scratch_file.txt');
    writeFileSync(scratchPath, 'temporary', 'utf8');
    assert.ok(existsSync(scratchPath));

    taskRepo.recordToolExecution({
      stepId: step.id,
      toolName: 'file_write',
      input: { path: scratchPath, content: 'temporary' },
      output: { path: scratchPath, bytesWritten: 9 },
      exitCode: 0,
      durationMs: 5
    });

    const result = await compensationManager.compensate(task.id);
    assert.equal(result.totalReverted, 1);
    assert.equal(result.actions.length, 1);
    assert.equal(result.actions[0]!.status, 'REVERTED');
    assert.equal(existsSync(scratchPath), false);

    // Verify audit record
    const events = auditRepo.getEventsByTaskId(task.id);
    const compEvents = events.filter((e) => e.eventType === 'COMPENSATION_EXECUTED');
    assert.equal(compEvents.length, 1);
  } finally {
    db.close();
    if (existsSync(testWorkspace)) rmSync(testWorkspace, { recursive: true, force: true });
  }
});

test('CompensationManager - skips files outside workspace root for perimeter safety', async () => {
  const { db, taskRepo, compensationManager } = setupTest();

  try {
    const task = taskRepo.createTask({ goal: 'Task with external file attempt' });
    const step = taskRepo.createStep({
      taskId: task.id,
      stepOrder: 1,
      description: 'Write outside workspace',
      toolName: 'file_write',
      toolArguments: { path: 'C:\\Windows\\System32\\fake.txt', content: 'dangerous' }
    });

    taskRepo.recordToolExecution({
      stepId: step.id,
      toolName: 'file_write',
      input: { path: 'C:\\Windows\\System32\\fake.txt', content: 'dangerous' },
      output: {},
      exitCode: 0,
      durationMs: 5
    });

    const result = await compensationManager.compensate(task.id);
    assert.equal(result.totalReverted, 0);
    assert.equal(result.actions.length, 1);
    assert.equal(result.actions[0]!.status, 'SKIPPED');
  } finally {
    db.close();
    if (existsSync(testWorkspace)) rmSync(testWorkspace, { recursive: true, force: true });
  }
});
