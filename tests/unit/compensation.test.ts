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

function sha256(text: string): string {
  return createHash('sha256').update(text).digest('hex');
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
      output: { path: scratchPath, bytesWritten: 9, writtenHash: sha256('temporary'), existedBefore: false },
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

test('CompensationManager - multiple writes to one pre-existing file restores original content in reverse order', async () => {
  const { db, taskRepo, compensationManager } = setupTest();

  try {
    const filePath = resolve(testWorkspace, 'chained_config.json');
    const v0 = '{"version": "0.0.0"}';
    const v1 = '{"version": "1.0.0"}';
    const v2 = '{"version": "2.0.0"}';

    // File existed before workflow
    writeFileSync(filePath, v0, 'utf8');

    const task = taskRepo.createTask({ goal: 'Chained writes to pre-existing file' });

    // Step 1: writes v1 over v0
    const step1 = taskRepo.createStep({
      taskId: task.id,
      stepOrder: 1,
      description: 'Write v1',
      toolName: 'file_write',
      toolArguments: { path: filePath, content: v1 }
    });
    taskRepo.recordToolExecution({
      stepId: step1.id,
      toolName: 'file_write',
      input: { path: filePath, content: v1 },
      output: {
        path: filePath,
        bytesWritten: v1.length,
        writtenHash: sha256(v1),
        existedBefore: true,
        previousContent: v0,
        previousHash: sha256(v0)
      },
      exitCode: 0,
      durationMs: 5
    });

    // Step 2: writes v2 over v1
    const step2 = taskRepo.createStep({
      taskId: task.id,
      stepOrder: 2,
      description: 'Write v2',
      toolName: 'file_write',
      toolArguments: { path: filePath, content: v2 }
    });
    taskRepo.recordToolExecution({
      stepId: step2.id,
      toolName: 'file_write',
      input: { path: filePath, content: v2 },
      output: {
        path: filePath,
        bytesWritten: v2.length,
        writtenHash: sha256(v2),
        existedBefore: true,
        previousContent: v1,
        previousHash: sha256(v1)
      },
      exitCode: 0,
      durationMs: 5
    });

    // Current state on disk is v2
    writeFileSync(filePath, v2, 'utf8');

    const result = await compensationManager.compensate(task.id);
    assert.equal(result.totalReverted, 2);
    assert.equal(result.totalFailed, 0);

    // Final state on disk MUST be the original v0
    assert.ok(existsSync(filePath));
    const contentOnDisk = readFileSync(filePath, 'utf8');
    assert.equal(contentOnDisk, v0);
  } finally {
    db.close();
    cleanupTest();
  }
});

test('CompensationManager - newly created file written multiple times is cleanly removed in reverse order', async () => {
  const { db, taskRepo, compensationManager } = setupTest();

  try {
    const filePath = resolve(testWorkspace, 'multi_scratch.txt');
    const d1 = 'first draft';
    const d2 = 'final draft';

    const task = taskRepo.createTask({ goal: 'Multiple writes to new file' });

    // Step 1: creates file with d1
    const step1 = taskRepo.createStep({
      taskId: task.id,
      stepOrder: 1,
      description: 'Create file with d1',
      toolName: 'file_write',
      toolArguments: { path: filePath, content: d1 }
    });
    taskRepo.recordToolExecution({
      stepId: step1.id,
      toolName: 'file_write',
      input: { path: filePath, content: d1 },
      output: {
        path: filePath,
        bytesWritten: d1.length,
        writtenHash: sha256(d1),
        existedBefore: false
      },
      exitCode: 0,
      durationMs: 5
    });

    // Step 2: updates file with d2
    const step2 = taskRepo.createStep({
      taskId: task.id,
      stepOrder: 2,
      description: 'Update file with d2',
      toolName: 'file_write',
      toolArguments: { path: filePath, content: d2 }
    });
    taskRepo.recordToolExecution({
      stepId: step2.id,
      toolName: 'file_write',
      input: { path: filePath, content: d2 },
      output: {
        path: filePath,
        bytesWritten: d2.length,
        writtenHash: sha256(d2),
        existedBefore: true,
        previousContent: d1,
        previousHash: sha256(d1)
      },
      exitCode: 0,
      durationMs: 5
    });

    // Current state on disk is d2
    writeFileSync(filePath, d2, 'utf8');

    const result = await compensationManager.compensate(task.id);
    assert.equal(result.totalReverted, 2);
    assert.equal(result.totalFailed, 0);

    // Final state on disk: file MUST NOT exist!
    assert.equal(existsSync(filePath), false);
  } finally {
    db.close();
    cleanupTest();
  }
});

test('CompensationManager - safely restores an originally empty file ("")', async () => {
  const { db, taskRepo, compensationManager } = setupTest();

  try {
    const filePath = resolve(testWorkspace, 'empty_sentinel.lock');
    const originalContent = ''; // Empty string
    writeFileSync(filePath, originalContent, 'utf8');

    const task = taskRepo.createTask({ goal: 'Mutate empty file' });
    const step = taskRepo.createStep({
      taskId: task.id,
      stepOrder: 1,
      description: 'Write over empty file',
      toolName: 'file_write',
      toolArguments: { path: filePath, content: 'locked' }
    });

    writeFileSync(filePath, 'locked', 'utf8');

    taskRepo.recordToolExecution({
      stepId: step.id,
      toolName: 'file_write',
      input: { path: filePath, content: 'locked' },
      output: {
        path: filePath,
        bytesWritten: 6,
        writtenHash: sha256('locked'),
        existedBefore: true,
        previousContent: originalContent,
        previousHash: sha256(originalContent)
      },
      exitCode: 0,
      durationMs: 5
    });

    const result = await compensationManager.compensate(task.id);
    assert.equal(result.totalReverted, 1);
    assert.equal(result.actions[0]!.action, 'file_restore');
    assert.equal(result.actions[0]!.status, 'REVERTED');

    // File MUST exist and be empty
    assert.ok(existsSync(filePath));
    const content = readFileSync(filePath, 'utf8');
    assert.equal(content, '');
  } finally {
    db.close();
    cleanupTest();
  }
});

test('CompensationManager - preserves newly created file if modified after workflow wrote it', async () => {
  const { db, taskRepo, compensationManager } = setupTest();

  try {
    const filePath = resolve(testWorkspace, 'user_edited_scratch.txt');
    const workflowContent = 'created by agent';
    const userModifiedContent = 'created by agent\nUser added manual critical notes!';

    const task = taskRepo.createTask({ goal: 'Task that created scratch file' });
    const step = taskRepo.createStep({
      taskId: task.id,
      stepOrder: 1,
      description: 'Write file',
      toolName: 'file_write',
      toolArguments: { path: filePath, content: workflowContent }
    });

    // Write file with user modifications
    writeFileSync(filePath, userModifiedContent, 'utf8');

    taskRepo.recordToolExecution({
      stepId: step.id,
      toolName: 'file_write',
      input: { path: filePath, content: workflowContent },
      output: {
        path: filePath,
        bytesWritten: workflowContent.length,
        writtenHash: sha256(workflowContent),
        existedBefore: false
      },
      exitCode: 0,
      durationMs: 5
    });

    const result = await compensationManager.compensate(task.id);
    assert.equal(result.totalReverted, 0);
    assert.equal(result.totalSkipped, 1);
    assert.equal(result.actions[0]!.status, 'SKIPPED');
    assert.ok(result.actions[0]!.details?.includes('modified after workflow'));

    // File MUST NOT be deleted
    assert.ok(existsSync(filePath));
    assert.equal(readFileSync(filePath, 'utf8'), userModifiedContent);
  } finally {
    db.close();
    cleanupTest();
  }
});

test('CompensationManager - preserves overwritten pre-existing file if modified after workflow wrote it', async () => {
  const { db, taskRepo, compensationManager } = setupTest();

  try {
    const filePath = resolve(testWorkspace, 'user_edited_config.json');
    const originalV0 = '{"v": 0}';
    const workflowV1 = '{"v": 1}';
    const userV2 = '{"v": 1, "external_patch": true}';

    const task = taskRepo.createTask({ goal: 'Task that mutated config' });
    const step = taskRepo.createStep({
      taskId: task.id,
      stepOrder: 1,
      description: 'Write v1',
      toolName: 'file_write',
      toolArguments: { path: filePath, content: workflowV1 }
    });

    // File now contains userV2 on disk
    writeFileSync(filePath, userV2, 'utf8');

    taskRepo.recordToolExecution({
      stepId: step.id,
      toolName: 'file_write',
      input: { path: filePath, content: workflowV1 },
      output: {
        path: filePath,
        bytesWritten: workflowV1.length,
        writtenHash: sha256(workflowV1),
        existedBefore: true,
        previousContent: originalV0,
        previousHash: sha256(originalV0)
      },
      exitCode: 0,
      durationMs: 5
    });

    const result = await compensationManager.compensate(task.id);
    assert.equal(result.totalReverted, 0);
    assert.equal(result.totalSkipped, 1);
    assert.equal(result.actions[0]!.status, 'SKIPPED');
    assert.ok(result.actions[0]!.details?.includes('modified after workflow'));

    // User's modifications MUST NOT be overwritten
    assert.equal(readFileSync(filePath, 'utf8'), userV2);
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

    taskRepo.recordToolExecution({
      stepId: step.id,
      toolName: 'file_write',
      input: { path: filePath, content: 'mutated content' },
      output: { path: filePath, bytesWritten: 15, writtenHash: sha256('mutated content'), existedBefore: true },
      exitCode: 0,
      durationMs: 5
    });

    const result = await compensationManager.compensate(task.id);
    assert.equal(result.totalReverted, 0);
    assert.equal(result.totalSkipped, 1);
    assert.equal(result.actions[0]!.status, 'SKIPPED');
    assert.ok(result.actions[0]!.details?.includes('missing backup'));

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
        writtenHash: sha256('current content'),
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
      output: { path: filePath, bytesWritten: 13, writtenHash: sha256('to be deleted'), existedBefore: false },
      exitCode: 0,
      durationMs: 5
    });

    // Run 1: file deleted
    const result1 = await compensationManager.compensate(task.id);
    assert.equal(result1.totalReverted, 1);
    assert.equal(result1.totalSkipped, 0);
    assert.equal(result1.isComplete, true);
    assert.equal(existsSync(filePath), false);

    // Run 2: idempotent skip, no crash
    const result2 = await compensationManager.compensate(task.id);
    assert.equal(result2.totalReverted, 0);
    assert.equal(result2.totalSkipped, 1);
    assert.equal(result2.isComplete, false);
    assert.equal(result2.actions[0]!.status, 'SKIPPED');
    assert.ok(result2.actions[0]!.details?.includes('does not exist'));
  } finally {
    db.close();
    cleanupTest();
  }
});

test('CompensationManager - does not recreate missing overwritten pre-existing file, reports SKIPPED, and marks isComplete: false with audit event', async () => {
  const { db, taskRepo, auditRepo, compensationManager } = setupTest();

  try {
    const filePath = resolve(testWorkspace, 'missing_overwritten_config.json');
    const originalV0 = '{"initial": "v0"}';
    const workflowV1 = '{"workflow": "v1"}';

    // File existed before workflow
    writeFileSync(filePath, originalV0, 'utf8');

    const task = taskRepo.createTask({ goal: 'Task that overwrote config and then file was removed' });
    const step = taskRepo.createStep({
      taskId: task.id,
      stepOrder: 1,
      description: 'Overwrite config',
      toolName: 'file_write',
      toolArguments: { path: filePath, content: workflowV1 }
    });

    taskRepo.recordToolExecution({
      stepId: step.id,
      toolName: 'file_write',
      input: { path: filePath, content: workflowV1 },
      output: {
        path: filePath,
        bytesWritten: workflowV1.length,
        writtenHash: sha256(workflowV1),
        existedBefore: true,
        previousContent: originalV0,
        previousHash: sha256(originalV0)
      },
      exitCode: 0,
      durationMs: 5
    });

    // File was deleted/missing before compensation runs
    if (existsSync(filePath)) rmSync(filePath, { force: true });
    assert.equal(existsSync(filePath), false);

    const result = await compensationManager.compensate(task.id);

    // Rollback MUST NOT be marked complete because an action was skipped
    assert.equal(result.isComplete, false);
    assert.equal(result.totalReverted, 0);
    assert.equal(result.totalSkipped, 1);
    assert.equal(result.totalFailed, 0);
    assert.equal(result.actions.length, 1);
    assert.equal(result.actions[0]!.action, 'file_restore');
    assert.equal(result.actions[0]!.status, 'SKIPPED');
    assert.ok(result.actions[0]!.details?.includes('missing on disk'));
    assert.ok(result.actions[0]!.details?.includes('differs from expected post-write state'));

    // File MUST NOT have been recreated!
    assert.equal(existsSync(filePath), false);

    // Audit-event accuracy
    const events = auditRepo.getEventsByTaskId(task.id);
    const compEvents = events.filter((e) => e.eventType === 'COMPENSATION_EXECUTED');
    assert.equal(compEvents.length, 1);
    const eventDetails = JSON.parse(compEvents[0]!.detailsJson) as {
      totalReverted: number;
      totalSkipped: number;
      totalFailed: number;
      isComplete: boolean;
      actions: Array<{ status: string; action: string; details?: string }>;
    };
    assert.equal(eventDetails.isComplete, false);
    assert.equal(eventDetails.totalReverted, 0);
    assert.equal(eventDetails.totalSkipped, 1);
    assert.equal(eventDetails.totalFailed, 0);
    assert.equal(eventDetails.actions[0]!.status, 'SKIPPED');
    assert.ok(eventDetails.actions[0]!.details?.includes('differs from expected post-write state'));
  } finally {
    db.close();
    cleanupTest();
  }
});

test('CompensationManager - correctly reports isComplete: false when actions are SKIPPED or FAILED, and isComplete: true only when fully reverted', async () => {
  const { db, taskRepo, auditRepo, compensationManager } = setupTest();

  try {
    // 1. Fully reverted case
    const taskSuccess = taskRepo.createTask({ goal: 'Successful rollback task' });
    const stepSuccess = taskRepo.createStep({
      taskId: taskSuccess.id,
      stepOrder: 1,
      description: 'Write file',
      toolName: 'file_write',
      toolArguments: { path: 'clean.txt', content: 'temp' }
    });
    const cleanPath = resolve(testWorkspace, 'clean.txt');
    writeFileSync(cleanPath, 'temp', 'utf8');
    taskRepo.recordToolExecution({
      stepId: stepSuccess.id,
      toolName: 'file_write',
      input: { path: cleanPath, content: 'temp' },
      output: { path: cleanPath, bytesWritten: 4, writtenHash: sha256('temp'), existedBefore: false },
      exitCode: 0,
      durationMs: 5
    });

    const resSuccess = await compensationManager.compensate(taskSuccess.id);
    assert.equal(resSuccess.totalReverted, 1);
    assert.equal(resSuccess.totalSkipped, 0);
    assert.equal(resSuccess.totalFailed, 0);
    assert.equal(resSuccess.isComplete, true);

    const auditSuccess = auditRepo.getEventsByTaskId(taskSuccess.id).find((e) => e.eventType === 'COMPENSATION_EXECUTED');
    assert.ok(auditSuccess);
    const successDetails = JSON.parse(auditSuccess.detailsJson) as { isComplete: boolean };
    assert.equal(successDetails.isComplete, true);

    // 2. Skipped action case (e.g. modified post-write)
    const taskSkipped = taskRepo.createTask({ goal: 'Skipped rollback task' });
    const stepSkipped = taskRepo.createStep({
      taskId: taskSkipped.id,
      stepOrder: 1,
      description: 'Write scratch',
      toolName: 'file_write',
      toolArguments: { path: 'post_mod.txt', content: 'agent' }
    });
    const modPath = resolve(testWorkspace, 'post_mod.txt');
    writeFileSync(modPath, 'agent modified externally', 'utf8');
    taskRepo.recordToolExecution({
      stepId: stepSkipped.id,
      toolName: 'file_write',
      input: { path: modPath, content: 'agent' },
      output: { path: modPath, bytesWritten: 5, writtenHash: sha256('agent'), existedBefore: false },
      exitCode: 0,
      durationMs: 5
    });

    const resSkipped = await compensationManager.compensate(taskSkipped.id);
    assert.equal(resSkipped.totalReverted, 0);
    assert.equal(resSkipped.totalSkipped, 1);
    assert.equal(resSkipped.totalFailed, 0);
    assert.equal(resSkipped.isComplete, false); // Must NOT be true!

    const auditSkipped = auditRepo.getEventsByTaskId(taskSkipped.id).find((e) => e.eventType === 'COMPENSATION_EXECUTED');
    assert.ok(auditSkipped);
    const skippedDetails = JSON.parse(auditSkipped.detailsJson) as { isComplete: boolean; totalSkipped: number };
    assert.equal(skippedDetails.isComplete, false);
    assert.equal(skippedDetails.totalSkipped, 1);

    // 3. Failed action case (e.g. corrupted payload)
    const taskFailed = taskRepo.createTask({ goal: 'Failed rollback task' });
    const stepFailed = taskRepo.createStep({
      taskId: taskFailed.id,
      stepOrder: 1,
      description: 'Bad JSON execution',
      toolName: 'file_write',
      toolArguments: {}
    });
    db.prepare(`
      INSERT INTO tool_executions (id, step_id, tool_name, input_json, output_json, exit_code, duration_ms, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run('exec-corrupt', stepFailed.id, 'file_write', '{ malformed json', '{ malformed json', 0, 5, new Date().toISOString());

    const resFailed = await compensationManager.compensate(taskFailed.id);
    assert.equal(resFailed.totalReverted, 0);
    assert.equal(resFailed.totalSkipped, 0);
    assert.equal(resFailed.totalFailed, 1);
    assert.equal(resFailed.isComplete, false); // Must NOT be true!

    const auditFailed = auditRepo.getEventsByTaskId(taskFailed.id).find((e) => e.eventType === 'COMPENSATION_EXECUTED');
    assert.ok(auditFailed);
    const failedDetails = JSON.parse(auditFailed.detailsJson) as { isComplete: boolean; totalFailed: number };
    assert.equal(failedDetails.isComplete, false);
    assert.equal(failedDetails.totalFailed, 1);
  } finally {
    db.close();
    cleanupTest();
  }
});

