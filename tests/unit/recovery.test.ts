/**
 * Next-Generation Dots AI Platform - Crash Recovery & Persistence Tests
 * 
 * Architectural Mandate:
 * Verifies that the platform can recover cleanly after an unexpected process crash.
 * Demonstrates state rehydration, step retry bounds, and audit logging after reopening
 * the database connection.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, unlinkSync } from 'node:fs';
import { DatabaseManager } from '../../src/storage/db.ts';
import { TaskRepository } from '../../src/storage/task-repository.ts';
import { AuditRepository } from '../../src/storage/audit-repository.ts';
import { CrashRecoveryEngine } from '../../src/storage/recovery.ts';

function cleanDbFiles(basePath: string): void {
  for (const ext of ['', '-wal', '-shm']) {
    const file = `${basePath}${ext}`;
    try {
      if (existsSync(file)) {
        unlinkSync(file);
      }
    } catch {
      // Ignore cleanup locks if held by OS briefly
    }
  }
}

test('CrashRecoveryEngine - detects interrupted tasks on boot and schedules bounded recovery', () => {
  const testDbPath = 'test_crash_recovery_1.db';
  cleanDbFiles(testDbPath);

  let db1: DatabaseManager | null = null;
  let db2: DatabaseManager | null = null;

  try {
    // Phase A: Active execution before crash
    db1 = new DatabaseManager(testDbPath);
    const taskRepo1 = new TaskRepository(db1);

    const task = taskRepo1.createTask({ goal: 'Long running task that crashes mid-flight' });
    taskRepo1.updateTaskStatus(task.id, 'SUBMITTED', 'PLANNING');
    taskRepo1.updateTaskStatus(task.id, 'PLANNING', 'EXECUTING');

    const step = taskRepo1.createStep({
      taskId: task.id,
      stepOrder: 1,
      description: 'Compute massive dataset hash',
      toolName: 'hash_file',
      toolArguments: { path: 'sandbox/data.bin' },
      maxRetries: 2
    });
    taskRepo1.updateStepStatus(step.id, 'EXECUTING');

    // Simulate abrupt crash: close DB connection immediately without clean shutdown
    db1.close();

    // Phase B: Application restarts fresh (simulating server boot)
    db2 = new DatabaseManager(testDbPath);
    const taskRepo2 = new TaskRepository(db2);
    const auditRepo2 = new AuditRepository(db2);
    const recoveryEngine = new CrashRecoveryEngine(taskRepo2, auditRepo2);

    // Run startup reconciliation
    const report = recoveryEngine.reconcileInterruptedTasks();
    assert.equal(report.scannedCount, 1);
    assert.equal(report.reconciledTasks.length, 1);
    assert.equal(report.reconciledTasks[0]?.taskId, task.id);
    assert.equal(report.reconciledTasks[0]?.previousStatus, 'EXECUTING');
    assert.equal(report.reconciledTasks[0]?.newStatus, 'RECOVERING');

    // Verify task state in database after reboot
    const recoveredTask = taskRepo2.getTaskById(task.id);
    assert.ok(recoveredTask);
    assert.equal(recoveredTask.status, 'RECOVERING');
    assert.ok(recoveredTask.errorSummary?.includes('retry 1/2'));

    // Verify step retryCount was incremented
    const recoveredStep = taskRepo2.getStepById(step.id);
    assert.ok(recoveredStep);
    assert.equal(recoveredStep.status, 'FAILED');
    assert.equal(recoveredStep.retryCount, 1);

    // Verify audit log has the crash event recorded
    const auditEvents = auditRepo2.getEventsByTaskId(task.id);
    const crashEvent = auditEvents.find(e => e.eventType === 'CRASH_INTERRUPTION_DETECTED');
    assert.ok(crashEvent);
    assert.equal(crashEvent.actor, 'SYSTEM');
  } finally {
    if (db1 && db1.isOpen) db1.close();
    if (db2 && db2.isOpen) db2.close();
    cleanDbFiles(testDbPath);
  }
});

test('CrashRecoveryEngine - marks task FAILED when retries are exhausted after repeated crashes', () => {
  const testDbPath = 'test_crash_recovery_exhausted.db';
  cleanDbFiles(testDbPath);

  let db1: DatabaseManager | null = null;
  let db2: DatabaseManager | null = null;

  try {
    db1 = new DatabaseManager(testDbPath);
    const taskRepo1 = new TaskRepository(db1);

    const task = taskRepo1.createTask({ goal: 'Failing task that exhausts retries' });
    taskRepo1.updateTaskStatus(task.id, 'SUBMITTED', 'PLANNING');
    taskRepo1.updateTaskStatus(task.id, 'PLANNING', 'EXECUTING');

    const step = taskRepo1.createStep({
      taskId: task.id,
      stepOrder: 1,
      description: 'Step that repeatedly crashes',
      toolName: 'failing_tool',
      toolArguments: {},
      maxRetries: 2
    });
    // Set retryCount already at maxRetries (2)
    taskRepo1.updateStepStatus(step.id, 'EXECUTING', 2);

    // Simulate crash
    db1.close();

    // Reopen after crash
    db2 = new DatabaseManager(testDbPath);
    const taskRepo2 = new TaskRepository(db2);
    const auditRepo2 = new AuditRepository(db2);
    const recoveryEngine = new CrashRecoveryEngine(taskRepo2, auditRepo2);

    const report = recoveryEngine.reconcileInterruptedTasks();
    assert.equal(report.scannedCount, 1);
    assert.equal(report.reconciledTasks[0]?.newStatus, 'FAILED');

    const failedTask = taskRepo2.getTaskById(task.id);
    assert.ok(failedTask);
    assert.equal(failedTask.status, 'FAILED');
    assert.ok(failedTask.errorSummary?.includes('Max retries exhausted'));
  } finally {
    if (db1 && db1.isOpen) db1.close();
    if (db2 && db2.isOpen) db2.close();
    cleanDbFiles(testDbPath);
  }
});

test('CrashRecoveryEngine - leaves COMPLETED and FAILED tasks untouched upon reopening', () => {
  const testDbPath = 'test_crash_recovery_clean.db';
  cleanDbFiles(testDbPath);

  let db1: DatabaseManager | null = null;
  let db2: DatabaseManager | null = null;

  try {
    db1 = new DatabaseManager(testDbPath);
    const taskRepo1 = new TaskRepository(db1);

    const task1 = taskRepo1.createTask({ goal: 'Already completed task' });
    taskRepo1.updateTaskStatus(task1.id, 'SUBMITTED', 'PLANNING');
    taskRepo1.updateTaskStatus(task1.id, 'PLANNING', 'EXECUTING');
    taskRepo1.updateTaskStatus(task1.id, 'EXECUTING', 'VERIFYING');
    taskRepo1.updateTaskStatus(task1.id, 'VERIFYING', 'COMPLETED');

    const task2 = taskRepo1.createTask({ goal: 'Already cancelled task' });
    taskRepo1.updateTaskStatus(task2.id, 'SUBMITTED', 'CANCELLED');

    db1.close();

    // Reopen database
    db2 = new DatabaseManager(testDbPath);
    const taskRepo2 = new TaskRepository(db2);
    const auditRepo2 = new AuditRepository(db2);
    const recoveryEngine = new CrashRecoveryEngine(taskRepo2, auditRepo2);

    const report = recoveryEngine.reconcileInterruptedTasks();
    assert.equal(report.scannedCount, 0);
    assert.equal(report.reconciledTasks.length, 0);

    const t1 = taskRepo2.getTaskById(task1.id);
    assert.equal(t1?.status, 'COMPLETED');

    const t2 = taskRepo2.getTaskById(task2.id);
    assert.equal(t2?.status, 'CANCELLED');
  } finally {
    if (db1 && db1.isOpen) db1.close();
    if (db2 && db2.isOpen) db2.close();
    cleanDbFiles(testDbPath);
  }
});
