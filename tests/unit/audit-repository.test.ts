/**
 * Next-Generation Dots AI Platform - Audit Repository Unit Tests
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { DatabaseManager } from '../../src/storage/db.ts';
import { TaskRepository } from '../../src/storage/task-repository.ts';
import { AuditRepository } from '../../src/storage/audit-repository.ts';
import { ValidationError } from '../../src/domain/errors.ts';

test('AuditRepository - appends and retrieves tamper-evident audit events', () => {
  const db = new DatabaseManager(':memory:');
  const taskRepo = new TaskRepository(db);
  const auditRepo = new AuditRepository(db);

  const task = taskRepo.createTask({ goal: 'Audit logging test' });

  const eventDetails = {
    proposedTool: 'file_write',
    path: 'sandbox/test.txt',
    byteCount: 128
  };

  const event = auditRepo.appendEvent({
    taskId: task.id,
    eventType: 'POLICY_EVALUATED',
    actor: 'POLICY_ENGINE',
    details: eventDetails
  });

  assert.ok(event.id);
  assert.equal(event.taskId, task.id);
  assert.equal(event.eventType, 'POLICY_EVALUATED');
  assert.equal(event.actor, 'POLICY_ENGINE');
  assert.equal(event.detailsJson, JSON.stringify(eventDetails));

  // Verify SHA-256 hash
  const expectedHash = createHash('sha256')
    .update(JSON.stringify(eventDetails), 'utf8')
    .digest('hex');
  assert.equal(event.payloadHash, expectedHash);
  assert.equal(event.payloadHash.length, 64);

  // Retrieve all events for task
  const allEvents = auditRepo.getEventsByTaskId(task.id);
  assert.equal(allEvents.length, 1);
  assert.equal(allEvents[0]?.id, event.id);

  // Retrieve single event by ID
  const single = auditRepo.getEventById(event.id);
  assert.ok(single);
  assert.equal(single.payloadHash, expectedHash);

  db.close();
});

test('AuditRepository - rejects audit events missing taskId', () => {
  const db = new DatabaseManager(':memory:');
  const auditRepo = new AuditRepository(db);

  assert.throws(
    () => {
      auditRepo.appendEvent({
        taskId: '',
        eventType: 'TASK_CREATED',
        actor: 'SYSTEM',
        details: {}
      });
    },
    (err: unknown) => {
      assert(err instanceof ValidationError);
      return true;
    }
  );

  db.close();
});
