/**
 * Next-Generation Dots AI Platform - Verifier Unit Tests
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { resolve } from 'node:path';
import { writeFileSync, existsSync, rmSync, mkdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { VerificationEngine } from '../../src/verification/verifier.ts';
import { DatabaseManager } from '../../src/storage/db.ts';
import { TaskRepository } from '../../src/storage/task-repository.ts';
import type { TaskStep, ToolExecution } from '../../src/domain/types.ts';

const testEnvDir = resolve('test_verifier_dir');

test('VerificationEngine - verifies FILE_EXISTS and FILE_NON_EMPTY', () => {
  if (existsSync(testEnvDir)) rmSync(testEnvDir, { recursive: true, force: true });
  mkdirSync(testEnvDir, { recursive: true });

  const testFile = resolve(testEnvDir, 'proof.txt');
  writeFileSync(testFile, 'evidence data', 'utf8');

  const verifier = new VerificationEngine();
  const mockStep: TaskStep = {
    id: 's1', taskId: 't1', stepOrder: 1, description: 'd', toolName: 'file_write',
    toolArgumentsJson: '{}', status: 'EXECUTING', retryCount: 0, maxRetries: 2,
    createdAt: '2026-10-17T00:00:00Z', completedAt: null
  };
  const mockExec: ToolExecution = {
    id: 'e1', stepId: 's1', toolName: 'file_write', inputJson: '{}', outputJson: '{}',
    exitCode: 0, durationMs: 5, createdAt: '2026-10-17T00:00:00Z'
  };

  try {
    // Check existence
    const existsCheck = verifier.verify(mockStep, mockExec, {
      checkType: 'FILE_EXISTS',
      target: testFile,
      expectedValue: 'true'
    });
    assert.equal(existsCheck.passed, true);

    // Check non-empty
    const nonEmptyCheck = verifier.verify(mockStep, mockExec, {
      checkType: 'FILE_NON_EMPTY',
      target: testFile,
      expectedValue: 'true'
    });
    assert.equal(nonEmptyCheck.passed, true);

    // Check non-existent file returns passed: false
    const missingCheck = verifier.verify(mockStep, mockExec, {
      checkType: 'FILE_EXISTS',
      target: resolve(testEnvDir, 'ghost.txt'),
      expectedValue: 'true'
    });
    assert.equal(missingCheck.passed, false);
  } finally {
    if (existsSync(testEnvDir)) rmSync(testEnvDir, { recursive: true, force: true });
  }
});

test('VerificationEngine - verifies cryptographic HASH_MATCH', () => {
  if (existsSync(testEnvDir)) rmSync(testEnvDir, { recursive: true, force: true });
  mkdirSync(testEnvDir, { recursive: true });

  const testFile = resolve(testEnvDir, 'hash_evidence.bin');
  const payload = 'deterministic verification content';
  writeFileSync(testFile, payload, 'utf8');
  const expectedHash = createHash('sha256').update(payload).digest('hex');

  const verifier = new VerificationEngine();
  const mockStep: TaskStep = {
    id: 's2', taskId: 't1', stepOrder: 1, description: 'd', toolName: 'hash_file',
    toolArgumentsJson: '{}', status: 'EXECUTING', retryCount: 0, maxRetries: 2,
    createdAt: '2026-10-17T00:00:00Z', completedAt: null
  };
  const mockExec: ToolExecution = {
    id: 'e2', stepId: 's2', toolName: 'hash_file', inputJson: '{}', outputJson: '{}',
    exitCode: 0, durationMs: 5, createdAt: '2026-10-17T00:00:00Z'
  };

  try {
    // Matching hash
    const passResult = verifier.verify(mockStep, mockExec, {
      checkType: 'HASH_MATCH',
      target: testFile,
      expectedValue: expectedHash
    });
    assert.equal(passResult.passed, true);
    assert.equal(passResult.actualValue, expectedHash);

    // Mismatched hash
    const failResult = verifier.verify(mockStep, mockExec, {
      checkType: 'HASH_MATCH',
      target: testFile,
      expectedValue: '0000000000000000000000000000000000000000000000000000000000000000'
    });
    assert.equal(failResult.passed, false);
  } finally {
    if (existsSync(testEnvDir)) rmSync(testEnvDir, { recursive: true, force: true });
  }
});

test('VerificationEngine - persists verification records in SQLite repository', () => {
  const db = new DatabaseManager(':memory:');
  const taskRepo = new TaskRepository(db);

  const task = taskRepo.createTask({ goal: 'Verification storage test' });
  const step = taskRepo.createStep({
    taskId: task.id,
    stepOrder: 1,
    description: 'Execute tool',
    toolName: 'calculate',
    toolArguments: { expression: '1 + 1' }
  });
  const exec = taskRepo.recordToolExecution({
    stepId: step.id,
    toolName: 'calculate',
    input: { expression: '1 + 1' },
    output: { result: 2 },
    exitCode: 0,
    durationMs: 2
  });

  const verifier = new VerificationEngine(taskRepo);
  const outcome = verifier.verify(step, exec, {
    checkType: 'OUTPUT_KEY_EXISTS',
    target: 'result',
    expectedValue: 'true'
  });

  assert.equal(outcome.passed, true);
  assert.ok(outcome.record);
  assert.equal(outcome.record.stepId, step.id);

  const stored = taskRepo.getVerificationsByStepId(step.id);
  assert.equal(stored.length, 1);
  assert.equal(stored[0]!.checkType, 'OUTPUT_KEY_EXISTS');
  assert.equal(stored[0]!.passed, true);

  db.close();
});
