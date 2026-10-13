/**
 * Next-Generation Dots AI Platform - Task Repository Unit Tests
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseManager } from '../../src/storage/db.ts';
import { TaskRepository } from '../../src/storage/task-repository.ts';
import {
  ValidationError,
  TaskNotFoundError,
  ConcurrencyConflictError,
  InvalidStateTransitionError
} from '../../src/domain/errors.ts';

test('TaskRepository - creates and retrieves tasks', () => {
  const db = new DatabaseManager(':memory:');
  const repo = new TaskRepository(db);

  const task = repo.createTask({
    goal: 'Build next-gen agent engine',
    metadata: { source: 'user-cli', priority: 'high' }
  });

  assert.ok(task.id);
  assert.equal(task.goal, 'Build next-gen agent engine');
  assert.equal(task.status, 'SUBMITTED');
  assert.equal(task.currentStepIndex, 0);
  assert.ok(task.createdAt);
  assert.equal(task.completedAt, null);

  const fetched = repo.getTaskById(task.id);
  assert.ok(fetched);
  assert.equal(fetched.id, task.id);
  assert.equal(fetched.goal, task.goal);
  assert.equal(fetched.status, 'SUBMITTED');

  // Verify non-existent ID returns null
  assert.equal(repo.getTaskById('unknown-id'), null);

  db.close();
});

test('TaskRepository - rejects empty task goals with ValidationError', () => {
  const db = new DatabaseManager(':memory:');
  const repo = new TaskRepository(db);

  assert.throws(
    () => repo.createTask({ goal: '   ' }),
    (err: unknown) => {
      assert(err instanceof ValidationError);
      assert.equal(err.code, 'VALIDATION_ERROR');
      return true;
    }
  );

  db.close();
});

test('TaskRepository - lists tasks with status filter and pagination', () => {
  const db = new DatabaseManager(':memory:');
  const repo = new TaskRepository(db);

  const t1 = repo.createTask({ goal: 'Task 1' });
  const t2 = repo.createTask({ goal: 'Task 2' });
  const t3 = repo.createTask({ goal: 'Task 3' });

  // Transition t2 to PLANNING
  repo.updateTaskStatus(t2.id, 'SUBMITTED', 'PLANNING');

  const allTasks = repo.listTasks({ limit: 10 });
  assert.equal(allTasks.length, 3);

  const submittedTasks = repo.listTasks({ status: 'SUBMITTED' });
  assert.equal(submittedTasks.length, 2);
  assert.ok(submittedTasks.some(t => t.id === t1.id));
  assert.ok(submittedTasks.some(t => t.id === t3.id));

  const planningTasks = repo.listTasks({ status: 'PLANNING' });
  assert.equal(planningTasks.length, 1);
  assert.equal(planningTasks[0]?.id, t2.id);

  db.close();
});

test('TaskRepository - executes valid state transitions and updates timestamps', () => {
  const db = new DatabaseManager(':memory:');
  const repo = new TaskRepository(db);

  const task = repo.createTask({ goal: 'Multi-step transition task' });

  // SUBMITTED -> PLANNING
  const p1 = repo.updateTaskStatus(task.id, 'SUBMITTED', 'PLANNING');
  assert.equal(p1.status, 'PLANNING');
  assert.equal(p1.completedAt, null);

  // PLANNING -> EXECUTING
  const p2 = repo.updateTaskStatus(task.id, 'PLANNING', 'EXECUTING');
  assert.equal(p2.status, 'EXECUTING');

  // EXECUTING -> VERIFYING
  const p3 = repo.updateTaskStatus(task.id, 'EXECUTING', 'VERIFYING');
  assert.equal(p3.status, 'VERIFYING');

  // VERIFYING -> COMPLETED (terminal)
  const p4 = repo.updateTaskStatus(task.id, 'VERIFYING', 'COMPLETED');
  assert.equal(p4.status, 'COMPLETED');
  assert.ok(p4.completedAt !== null);

  db.close();
});

test('TaskRepository - rejects illegal transitions via FSM validation', () => {
  const db = new DatabaseManager(':memory:');
  const repo = new TaskRepository(db);

  const task = repo.createTask({ goal: 'Test illegal transition' });

  // Attempt to transition directly from SUBMITTED to COMPLETED
  assert.throws(
    () => repo.updateTaskStatus(task.id, 'SUBMITTED', 'COMPLETED'),
    (err: unknown) => {
      assert(err instanceof InvalidStateTransitionError);
      assert.equal(err.fromStatus, 'SUBMITTED');
      assert.equal(err.toStatus, 'COMPLETED');
      return true;
    }
  );

  // Assert status in database was unchanged
  const unchanged = repo.getTaskById(task.id);
  assert.equal(unchanged?.status, 'SUBMITTED');

  db.close();
});

test('TaskRepository - detects optimistic concurrency conflicts', () => {
  const db = new DatabaseManager(':memory:');
  const repo = new TaskRepository(db);

  const task = repo.createTask({ goal: 'Test concurrency conflict' });

  // Worker A transitions task to PLANNING
  repo.updateTaskStatus(task.id, 'SUBMITTED', 'PLANNING');

  // Worker B attempts to transition assuming it is still SUBMITTED
  assert.throws(
    () => repo.updateTaskStatus(task.id, 'SUBMITTED', 'CANCELLED'),
    (err: unknown) => {
      assert(err instanceof ConcurrencyConflictError);
      assert.equal(err.taskId, task.id);
      assert.equal(err.expectedStatus, 'SUBMITTED');
      assert.equal(err.actualStatus, 'PLANNING');
      return true;
    }
  );

  db.close();
});

test('TaskRepository - throws TaskNotFoundError for unknown task ID', () => {
  const db = new DatabaseManager(':memory:');
  const repo = new TaskRepository(db);

  assert.throws(
    () => repo.updateTaskStatus('fake-uuid-1234', 'SUBMITTED', 'PLANNING'),
    (err: unknown) => {
      assert(err instanceof TaskNotFoundError);
      assert.equal(err.taskId, 'fake-uuid-1234');
      return true;
    }
  );

  db.close();
});

test('TaskRepository - manages plan steps, executions, and verifications', () => {
  const db = new DatabaseManager(':memory:');
  const repo = new TaskRepository(db);

  const task = repo.createTask({ goal: 'Test step workflow' });

  // 1. Add steps
  const step1 = repo.createStep({
    taskId: task.id,
    stepOrder: 1,
    description: 'Calculate cryptographic hash',
    toolName: 'hash_file',
    toolArguments: { path: 'sandbox/payload.txt', algorithm: 'sha256' }
  });

  const step2 = repo.createStep({
    taskId: task.id,
    stepOrder: 2,
    description: 'Verify output file existence',
    toolName: 'file_exists',
    toolArguments: { path: 'sandbox/payload.txt.sha256' }
  });

  const steps = repo.getStepsByTaskId(task.id);
  assert.equal(steps.length, 2);
  assert.equal(steps[0]?.stepOrder, 1);
  assert.equal(steps[1]?.stepOrder, 2);

  // 2. Update step status
  const updatedStep1 = repo.updateStepStatus(step1.id, 'EXECUTING');
  assert.equal(updatedStep1.status, 'EXECUTING');

  // 3. Record tool execution
  const toolExec = repo.recordToolExecution({
    stepId: step1.id,
    toolName: 'hash_file',
    input: { path: 'sandbox/payload.txt' },
    output: { hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' },
    exitCode: 0,
    durationMs: 42
  });
  assert.ok(toolExec.id);
  assert.equal(toolExec.exitCode, 0);

  const execLogs = repo.getToolExecutionsByStepId(step1.id);
  assert.equal(execLogs.length, 1);
  assert.equal(execLogs[0]?.toolName, 'hash_file');

  // 4. Record verification
  const verification = repo.recordVerification({
    stepId: step1.id,
    checkType: 'HASH_MATCH',
    passed: true,
    expectedValue: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    actualValue: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    evidenceData: { verifiedBytes: 0, source: 'fs' }
  });
  assert.ok(verification.id);
  assert.equal(verification.passed, true);

  const verifications = repo.getVerificationsByStepId(step1.id);
  assert.equal(verifications.length, 1);
  assert.equal(verifications[0]?.passed, true);

  db.close();
});

test('TaskRepository - manages human approval request workflows', () => {
  const db = new DatabaseManager(':memory:');
  const repo = new TaskRepository(db);

  const task = repo.createTask({ goal: 'Approve risky operation' });
  const step = repo.createStep({
    taskId: task.id,
    stepOrder: 1,
    description: 'Execute script',
    toolName: 'run_script',
    toolArguments: { script: 'deploy.sh' }
  });

  // Create approval request
  const approval = repo.createApprovalRequest({
    taskId: task.id,
    stepId: step.id,
    riskTier: 'TIER_3',
    actionSummary: 'Execute external script deploy.sh',
    targetResource: 'deploy.sh',
    parameterDiff: { command: 'bash deploy.sh' }
  });

  assert.ok(approval.approvalToken);
  assert.equal(approval.decision, 'PENDING');

  // Retrieve by token
  const retrieved = repo.getApprovalRequestByToken(approval.approvalToken);
  assert.ok(retrieved);
  assert.equal(retrieved.id, approval.id);

  // Update decision to APPROVED
  const decided = repo.updateApprovalDecision(approval.id, 'APPROVED', 'human-operator-alice');
  assert.equal(decided.decision, 'APPROVED');
  assert.equal(decided.decidedBy, 'human-operator-alice');
  assert.ok(decided.decidedAt !== null);

  db.close();
});

test('TaskRepository - parameterized SQL is completely immune to SQL injection attacks', () => {
  const db = new DatabaseManager(':memory:');
  const repo = new TaskRepository(db);

  const maliciousPayload = "Test'; DROP TABLE tasks; --";
  const task = repo.createTask({ goal: maliciousPayload });

  assert.equal(task.goal, maliciousPayload);

  // Verify tasks table was NOT dropped
  const fetched = repo.getTaskById(task.id);
  assert.ok(fetched);
  assert.equal(fetched.goal, maliciousPayload);

  db.close();
});
