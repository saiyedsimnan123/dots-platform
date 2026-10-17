/**
 * Next-Generation Dots AI Platform - Compensation Manager Comprehensive Tests
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { resolve, join } from 'node:path';
import { existsSync, rmSync, mkdirSync, writeFileSync, readFileSync, symlinkSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { DatabaseManager } from '../../src/storage/db.ts';
import { TaskRepository } from '../../src/storage/task-repository.ts';
import { AuditRepository } from '../../src/storage/audit-repository.ts';
import { CompensationManager } from '../../src/orchestrator/compensation.ts';

const testWorkspace = resolve('test_comp_workspace');
const siblingWorkspace = resolve('test_comp_workspace_sibling');
const externalDir = resolve('test_comp_external');

function setupTest() {
  cleanupTest();
  mkdirSync(testWorkspace, { recursive: true });
  mkdirSync(siblingWorkspace, { recursive: true });
  mkdirSync(externalDir, { recursive: true });

  const db = new DatabaseManager(':memory:');
  const taskRepo = new TaskRepository(db);
  const auditRepo = new AuditRepository(db);
  const compensationManager = new CompensationManager(taskRepo, auditRepo, testWorkspace);

  return { db, taskRepo, auditRepo, compensationManager };
}

function cleanupTest() {
  if (existsSync(testWorkspace)) rmSync(testWorkspace, { recursive: true, force: true });
  if (existsSync(siblingWorkspace)) rmSync(siblingWorkspace, { recursive: true, force: true });
  if (existsSync(externalDir)) rmSync(externalDir, { recursive: true, force: true });
}

test('CompensationManager - safely deletes newly created files (existedBefore: false)', async () => {
  const { db, taskRepo, auditRepo, compensationManager } = setupTest();

  try {
    const task = taskRepo.createTask({ goal: 'Create scratch file' });
    const step = taskRepo.createStep({
      taskId: task.id,
      stepOrder: 1,
      description: 'Write new scratch file',
      toolName: 'file_write',
      toolArguments: { path: 'scratch.txt', content: 'temporary' }
    });

    const scratchPath = resolve(testWorkspace, 'scratch.txt');
    writeFileSync(scratchPath, 'temporary', 'utf8');
    assert.ok(existsSync(scratchPath));

    taskRepo.recordToolExecution({
      stepId: step.id,
      toolName: 'file_write',
      input: { path: scratchPath, content: 'temporary' },
      output: { path: scratchPath, bytesWritten: 9, existedBefore: false },
      exitCode: 0,
      durationMs: 5
    });

    const result = await compensationManager.compensate(task.id);
    assert.equal(result.totalReverted, 1);
    assert.equal(result.totalSkipped, 0);
    assert.equal(result.totalFailed, 0);
    assert.equal(result.isComplete, true);
    assert.equal(result.actions[0]!.action, 'file_delete');
    assert.equal(result.actions[0]!.status, 'REVERTED');
    assert.equal(existsSync(scratchPath), false);

    // Verify audit record
    const events = auditRepo.getEventsByTaskId(task.id);
    const compEvents = events.filter((e) => e.eventType === 'COMPENSATION_EXECUTED');
    assert.equal(compEvents.length, 1);
  } finally {
    db.close();
    cleanupTest();
  }
});

test('CompensationManager - restores pre-existing files from verified backup and NEVER deletes them', async () => {
  const { db, taskRepo, compensationManager } = setupTest();

  try {
    const filePath = resolve(testWorkspace, 'important_config.json');
    const originalContent = '{"version": "1.0.0", "safe": true}';
    const originalHash = createHash('sha256').update(originalContent).digest('hex');

    // Create file before task
    writeFileSync(filePath, originalContent, 'utf8');

    const task = taskRepo.createTask({ goal: 'Task that mutated config' });
    const step = taskRepo.createStep({
      taskId: task.id,
      stepOrder: 1,
      description: 'Overwrite config',
      toolName: 'file_write',
      toolArguments: { path: filePath, content: 'corrupted payload' }
    });

    // Mutate file
    writeFileSync(filePath, 'corrupted payload', 'utf8');

    taskRepo.recordToolExecution({
      stepId: step.id,
      toolName: 'file_write',
      input: { path: filePath, content: 'corrupted payload' },
      output: {
        path: filePath,
        bytesWritten: 17,
        existedBefore: true,
        previousContent: originalContent,
        previousHash: originalHash
      },
      exitCode: 0,
      durationMs: 5
    });

    const result = await compensationManager.compensate(task.id);
    assert.equal(result.totalReverted, 1);
    assert.equal(result.actions[0]!.action, 'file_restore');
    assert.equal(result.actions[0]!.status, 'REVERTED');

    // File MUST exist and MUST match original content
    assert.ok(existsSync(filePath));
    const restoredContent = readFileSync(filePath, 'utf8');
    assert.equal(restoredContent, originalContent);
  } finally {
    db.close();
    cleanupTest();
  }
});

test('CompensationManager - leaves overwritten file untouched if backup is missing', async () => {
  const { db, taskRepo, compensationManager } = setupTest();

  try {
    const filePath = resolve(testWorkspace, 'existing_file.txt');
    writeFileSync(filePath, 'mutated content', 'utf8');

    const task = taskRepo.createTask({ goal: 'Overwritten without backup' });
    const step = taskRepo.createStep({
      taskId: task.id,
      stepOrder: 1,
      description: 'Write file',
      toolName: 'file_write',
      toolArguments: { path: filePath, content: 'mutated content' }
    });

    // existedBefore: true, but missing previousContent/previousHash
    taskRepo.recordToolExecution({
      stepId: step.id,
      toolName: 'file_write',
      input: { path: filePath, content: 'mutated content' },
      output: { path: filePath, bytesWritten: 15, existedBefore: true },
      exitCode: 0,
      durationMs: 5
    });

    const result = await compensationManager.compensate(task.id);
    assert.equal(result.totalReverted, 0);
    assert.equal(result.totalSkipped, 1);
    assert.equal(result.actions[0]!.status, 'SKIPPED');
    assert.ok(result.actions[0]!.details?.includes('missing backup'));

    // File MUST NOT have been deleted
    assert.ok(existsSync(filePath));
    assert.equal(readFileSync(filePath, 'utf8'), 'mutated content');
  } finally {
    db.close();
    cleanupTest();
  }
});

test('CompensationManager - leaves overwritten file untouched if backup hash is corrupted/mismatched', async () => {
  const { db, taskRepo, compensationManager } = setupTest();

  try {
    const filePath = resolve(testWorkspace, 'tampered_backup.txt');
    writeFileSync(filePath, 'current content', 'utf8');

    const task = taskRepo.createTask({ goal: 'Tampered backup test' });
    const step = taskRepo.createStep({
      taskId: task.id,
      stepOrder: 1,
      description: 'Write file',
      toolName: 'file_write',
      toolArguments: { path: filePath, content: 'current content' }
    });

    taskRepo.recordToolExecution({
      stepId: step.id,
      toolName: 'file_write',
      input: { path: filePath, content: 'current content' },
      output: {
        path: filePath,
        bytesWritten: 15,
        existedBefore: true,
        previousContent: 'backup text',
        previousHash: 'wrong_sha256_hash_value_that_does_not_match'
      },
      exitCode: 0,
      durationMs: 5
    });

    const result = await compensationManager.compensate(task.id);
    assert.equal(result.totalReverted, 0);
    assert.equal(result.totalSkipped, 1);
    assert.equal(result.actions[0]!.status, 'SKIPPED');
    assert.ok(result.actions[0]!.details?.includes('hash mismatch'));

    // File MUST NOT have been deleted
    assert.ok(existsSync(filePath));
  } finally {
    db.close();
    cleanupTest();
  }
});

test('CompensationManager - rejects path traversal outside workspace', async () => {
  const { db, taskRepo, compensationManager } = setupTest();

  try {
    const task = taskRepo.createTask({ goal: 'Path traversal attempt' });
    const step = taskRepo.createStep({
      taskId: task.id,
      stepOrder: 1,
      description: 'Write external',
      toolName: 'file_write',
      toolArguments: { path: '../../outside.txt', content: 'evil' }
    });

    taskRepo.recordToolExecution({
      stepId: step.id,
      toolName: 'file_write',
      input: { path: '../../outside.txt', content: 'evil' },
      output: { path: '../../outside.txt', bytesWritten: 4, existedBefore: false },
      exitCode: 0,
      durationMs: 5
    });

    const result = await compensationManager.compensate(task.id);
    assert.equal(result.totalReverted, 0);
    assert.equal(result.totalSkipped, 1);
    assert.equal(result.actions[0]!.status, 'SKIPPED');
    assert.ok(result.actions[0]!.details?.includes('traversal') || result.actions[0]!.details?.includes('escapes'));
  } finally {
    db.close();
    cleanupTest();
  }
});

test('CompensationManager - rejects sibling-prefix directory attacks', async () => {
  const { db, taskRepo, compensationManager } = setupTest();

  try {
    const siblingFile = join(siblingWorkspace, 'victim.txt');
    writeFileSync(siblingFile, 'do not delete', 'utf8');

    const task = taskRepo.createTask({ goal: 'Sibling prefix attack' });
    const step = taskRepo.createStep({
      taskId: task.id,
      stepOrder: 1,
      description: 'Write sibling',
      toolName: 'file_write',
      toolArguments: { path: siblingFile, content: 'evil' }
    });

    taskRepo.recordToolExecution({
      stepId: step.id,
      toolName: 'file_write',
      input: { path: siblingFile, content: 'evil' },
      output: { path: siblingFile, bytesWritten: 4, existedBefore: false },
      exitCode: 0,
      durationMs: 5
    });

    const result = await compensationManager.compensate(task.id);
    assert.equal(result.totalReverted, 0);
    assert.equal(result.totalSkipped, 1);
    assert.equal(result.actions[0]!.status, 'SKIPPED');

    // Sibling file MUST NOT be deleted
    assert.ok(existsSync(siblingFile));
  } finally {
    db.close();
    cleanupTest();
  }
});

test('CompensationManager - rejects absolute external system paths', async () => {
  const { db, taskRepo, compensationManager } = setupTest();

  try {
    const task = taskRepo.createTask({ goal: 'Absolute external path' });
    const step = taskRepo.createStep({
      taskId: task.id,
      stepOrder: 1,
      description: 'Write system file',
      toolName: 'file_write',
      toolArguments: { path: 'C:\\Windows\\System32\\fake.txt', content: 'dangerous' }
    });

    taskRepo.recordToolExecution({
      stepId: step.id,
      toolName: 'file_write',
      input: { path: 'C:\\Windows\\System32\\fake.txt', content: 'dangerous' },
      output: { path: 'C:\\Windows\\System32\\fake.txt', bytesWritten: 9, existedBefore: false },
      exitCode: 0,
      durationMs: 5
    });

    const result = await compensationManager.compensate(task.id);
    assert.equal(result.totalReverted, 0);
    assert.equal(result.totalSkipped, 1);
    assert.equal(result.actions[0]!.status, 'SKIPPED');
  } finally {
    db.close();
    cleanupTest();
  }
});

test('CompensationManager - rejects symlink escape targets', async () => {
  const { db, taskRepo, compensationManager } = setupTest();

  try {
    const symlinkPath = join(testWorkspace, 'symlink_outside');
    let symlinkCreated = false;
    try {
      symlinkSync(externalDir, symlinkPath, 'junction');
      symlinkCreated = true;
    } catch {
      // Junction/symlink not supported in environment
    }

    if (symlinkCreated) {
      const externalTargetFile = join(symlinkPath, 'escaped.txt');
      const task = taskRepo.createTask({ goal: 'Symlink escape' });
      const step = taskRepo.createStep({
        taskId: task.id,
        stepOrder: 1,
        description: 'Write through symlink',
        toolName: 'file_write',
        toolArguments: { path: externalTargetFile, content: 'escaped' }
      });

      taskRepo.recordToolExecution({
        stepId: step.id,
        toolName: 'file_write',
        input: { path: externalTargetFile, content: 'escaped' },
        output: { path: externalTargetFile, bytesWritten: 7, existedBefore: false },
        exitCode: 0,
        durationMs: 5
      });

      const result = await compensationManager.compensate(task.id);
      assert.equal(result.totalReverted, 0);
      assert.equal(result.totalSkipped, 1);
      assert.equal(result.actions[0]!.status, 'SKIPPED');
    }
  } finally {
    db.close();
    cleanupTest();
  }
});

test('CompensationManager - is idempotent across repeated compensation runs', async () => {
  const { db, taskRepo, compensationManager } = setupTest();

  try {
    const filePath = resolve(testWorkspace, 'idempotent.txt');
    writeFileSync(filePath, 'to be deleted', 'utf8');

    const task = taskRepo.createTask({ goal: 'Idempotency test' });
    const step = taskRepo.createStep({
      taskId: task.id,
      stepOrder: 1,
      description: 'Write file',
      toolName: 'file_write',
      toolArguments: { path: filePath, content: 'to be deleted' }
    });

    taskRepo.recordToolExecution({
      stepId: step.id,
      toolName: 'file_write',
      input: { path: filePath, content: 'to be deleted' },
      output: { path: filePath, bytesWritten: 13, existedBefore: false },
      exitCode: 0,
      durationMs: 5
    });

    // Run 1: file deleted
    const result1 = await compensationManager.compensate(task.id);
    assert.equal(result1.totalReverted, 1);
    assert.equal(result1.totalSkipped, 0);
    assert.equal(existsSync(filePath), false);

    // Run 2: idempotent skip, no crash
    const result2 = await compensationManager.compensate(task.id);
    assert.equal(result2.totalReverted, 0);
    assert.equal(result2.totalSkipped, 1);
    assert.equal(result2.actions[0]!.status, 'SKIPPED');
    assert.ok(result2.actions[0]!.details?.includes('does not exist'));
  } finally {
    db.close();
    cleanupTest();
  }
});
