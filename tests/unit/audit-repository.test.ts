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

test('AuditRepository - enforces memory audit privacy policy across all memory audit event types at shared boundary', () => {
  const db = new DatabaseManager(':memory:');
  const taskRepo = new TaskRepository(db);
  const auditRepo = new AuditRepository(db);

  const task = taskRepo.createTask({ goal: 'Shared boundary privacy enforcement test' });

  const sentinelKey = 'FORBIDDEN_RAW_KEY_SENTINEL_XYZ_999';
  const sentinelContent = 'FORBIDDEN_RAW_CONTENT_SENTINEL_ABC_888';
  const sentinelTag = 'FORBIDDEN_TAG_SENTINEL_777';
  const sentinelMeta = 'FORBIDDEN_METADATA_SENTINEL_666';
  const arbitraryInjectedField = 'MALICIOUS_INJECTED_FIELD_555';

  // Sample payloads containing both safe operational fields and forbidden sensitive/arbitrary fields
  const testCases: Array<{
    eventType: (typeof import('../../src/storage/audit-policy.ts').MEMORY_AUDIT_EVENT_TYPES)[number];
    rawDetails: Record<string, unknown>;
    expectedPreserved: Record<string, unknown>;
  }> = [
    {
      eventType: 'MEMORY_CREATED',
      rawDetails: {
        memoryId: 'mem-create-1',
        category: 'PROJECT_FACT',
        scopeType: 'WORKSPACE',
        scopeId: 'ws-1',
        status: 'ACTIVE',
        key: sentinelKey,
        content: sentinelContent,
        tags: [sentinelTag],
        metadata: { secret: sentinelMeta },
        arbitrary: arbitraryInjectedField
      },
      expectedPreserved: {
        memoryId: 'mem-create-1',
        category: 'PROJECT_FACT',
        scopeType: 'WORKSPACE',
        scopeId: 'ws-1',
        status: 'ACTIVE'
      }
    },
    {
      eventType: 'MEMORY_PROPOSAL_SUBMITTED',
      rawDetails: {
        memoryId: 'mem-prop-1',
        category: 'USER_PREFERENCE',
        scopeType: 'WORKSPACE',
        scopeId: 'ws-1',
        status: 'PENDING_APPROVAL',
        proposedBy: 'AGENT',
        key: sentinelKey,
        content: sentinelContent,
        tags: [sentinelTag]
      },
      expectedPreserved: {
        memoryId: 'mem-prop-1',
        category: 'USER_PREFERENCE',
        scopeType: 'WORKSPACE',
        scopeId: 'ws-1',
        status: 'PENDING_APPROVAL',
        proposedBy: 'AGENT'
      }
    },
    {
      eventType: 'MEMORY_RETRIEVED',
      rawDetails: {
        memoryId: 'mem-ret-1',
        memoryIds: ['mem-ret-1', 'mem-ret-2'],
        count: 2,
        category: 'PROJECT_FACT',
        scopeType: 'WORKSPACE',
        scopeId: 'ws-1',
        taskId: task.id,
        operation: 'buildTaskMemoryContext',
        totalInjections: 5,
        key: sentinelKey,
        content: sentinelContent
      },
      expectedPreserved: {
        memoryId: 'mem-ret-1',
        memoryIds: ['mem-ret-1', 'mem-ret-2'],
        count: 2,
        category: 'PROJECT_FACT',
        scopeType: 'WORKSPACE',
        scopeId: 'ws-1',
        taskId: task.id,
        operation: 'buildTaskMemoryContext',
        totalInjections: 5
      }
    },
    {
      eventType: 'MEMORY_UPDATED',
      rawDetails: {
        memoryId: 'mem-upd-1',
        category: 'PROJECT_FACT',
        scopeType: 'WORKSPACE',
        scopeId: 'ws-1',
        updatedFields: ['content', 'tags'],
        key: sentinelKey,
        content: sentinelContent,
        metadata: { secret: sentinelMeta }
      },
      expectedPreserved: {
        memoryId: 'mem-upd-1',
        category: 'PROJECT_FACT',
        scopeType: 'WORKSPACE',
        scopeId: 'ws-1',
        updatedFields: ['content', 'tags']
      }
    },
    {
      eventType: 'MEMORY_ARCHIVED',
      rawDetails: {
        memoryId: 'mem-arc-1',
        category: 'PROJECT_FACT',
        scopeType: 'WORKSPACE',
        scopeId: 'ws-1',
        key: sentinelKey,
        content: sentinelContent
      },
      expectedPreserved: {
        memoryId: 'mem-arc-1',
        category: 'PROJECT_FACT',
        scopeType: 'WORKSPACE',
        scopeId: 'ws-1'
      }
    },
    {
      eventType: 'MEMORY_DELETED',
      rawDetails: {
        memoryId: 'mem-del-1',
        category: 'PROJECT_FACT',
        scopeType: 'WORKSPACE',
        scopeId: 'ws-1',
        key: sentinelKey,
        content: sentinelContent
      },
      expectedPreserved: {
        memoryId: 'mem-del-1',
        category: 'PROJECT_FACT',
        scopeType: 'WORKSPACE',
        scopeId: 'ws-1'
      }
    },
    {
      eventType: 'MEMORY_PROPOSAL_DECIDED',
      rawDetails: {
        memoryId: 'mem-dec-1',
        category: 'PROJECT_FACT',
        decision: 'APPROVED',
        decidedBy: 'USER',
        scopeType: 'WORKSPACE',
        scopeId: 'ws-1',
        previousStatus: 'PENDING_APPROVAL',
        newStatus: 'ACTIVE',
        key: sentinelKey,
        content: sentinelContent
      },
      expectedPreserved: {
        memoryId: 'mem-dec-1',
        category: 'PROJECT_FACT',
        decision: 'APPROVED',
        decidedBy: 'USER',
        scopeType: 'WORKSPACE',
        scopeId: 'ws-1',
        previousStatus: 'PENDING_APPROVAL',
        newStatus: 'ACTIVE'
      }
    },
    {
      eventType: 'MEMORY_EXPORTED',
      rawDetails: {
        scopeType: 'WORKSPACE',
        scopeId: 'ws-1',
        exportedCount: 10,
        checksum: 'sha256-dummy-checksum',
        key: sentinelKey,
        content: sentinelContent
      },
      expectedPreserved: {
        scopeType: 'WORKSPACE',
        scopeId: 'ws-1',
        exportedCount: 10,
        checksum: 'sha256-dummy-checksum'
      }
    },
    {
      eventType: 'MEMORIES_IMPORTED',
      rawDetails: {
        targetScopeType: 'WORKSPACE',
        targetScopeId: 'ws-1',
        totalInBundle: 5,
        importedCount: 3,
        skippedCount: 1,
        overwrittenCount: 1,
        conflictStrategy: 'OVERWRITE',
        checksum: 'sha256-dummy-checksum',
        key: sentinelKey,
        content: sentinelContent
      },
      expectedPreserved: {
        targetScopeType: 'WORKSPACE',
        targetScopeId: 'ws-1',
        totalInBundle: 5,
        importedCount: 3,
        skippedCount: 1,
        overwrittenCount: 1,
        conflictStrategy: 'OVERWRITE',
        checksum: 'sha256-dummy-checksum'
      }
    },
    {
      eventType: 'MEMORIES_PURGED',
      rawDetails: {
        scopeType: 'WORKSPACE',
        scopeId: 'ws-1',
        purgeMode: 'CUTOFF',
        purgedCount: 7,
        batchSizeLimit: 100,
        cutoffTimestamp: '2026-01-01T00:00:00.000Z',
        key: sentinelKey,
        content: sentinelContent
      },
      expectedPreserved: {
        scopeType: 'WORKSPACE',
        scopeId: 'ws-1',
        purgeMode: 'CUTOFF',
        purgedCount: 7,
        batchSizeLimit: 100,
        cutoffTimestamp: '2026-01-01T00:00:00.000Z'
      }
    },
    {
      eventType: 'MEMORY_ACCESS_DENIED',
      rawDetails: {
        reason: 'CROSS_SCOPE_READ_ATTEMPT',
        operation: 'getMemoryById',
        memoryId: 'mem-den-1',
        category: 'PROJECT_FACT',
        expectedScope: 'WORKSPACE:ws-1',
        callerScope: 'WORKSPACE:ws-2',
        taskScope: 'WORKSPACE:ws-1',
        memoryScope: 'WORKSPACE:ws-2',
        attemptedScope: 'WORKSPACE:ws-fake',
        attemptedStatus: 'ACTIVE',
        currentStatus: 'PENDING_APPROVAL',
        status: 'PENDING_APPROVAL',
        requiredPermission: 'READ',
        actor: 'AGENT',
        scopeType: 'WORKSPACE',
        scopeId: 'ws-1',
        taskId: task.id,
        key: sentinelKey,
        content: sentinelContent,
        tags: [sentinelTag],
        metadata: { secret: sentinelMeta }
      },
      expectedPreserved: {
        reason: 'CROSS_SCOPE_READ_ATTEMPT',
        operation: 'getMemoryById',
        memoryId: 'mem-den-1',
        category: 'PROJECT_FACT',
        expectedScope: 'WORKSPACE:ws-1',
        callerScope: 'WORKSPACE:ws-2',
        taskScope: 'WORKSPACE:ws-1',
        memoryScope: 'WORKSPACE:ws-2',
        attemptedScope: 'WORKSPACE:ws-fake',
        attemptedStatus: 'ACTIVE',
        currentStatus: 'PENDING_APPROVAL',
        status: 'PENDING_APPROVAL',
        requiredPermission: 'READ',
        actor: 'AGENT',
        scopeType: 'WORKSPACE',
        scopeId: 'ws-1',
        taskId: task.id
      }
    }
  ];

  for (const tc of testCases) {
    const event = auditRepo.appendEvent({
      taskId: task.id,
      eventType: tc.eventType,
      actor: 'USER',
      details: tc.rawDetails
    });

    const parsedDetails = JSON.parse(event.detailsJson);

    // 1. Verify safe operational fields match expected preserved fields exactly
    assert.deepEqual(
      parsedDetails,
      tc.expectedPreserved,
      `Event ${tc.eventType} details should match expected allowlisted fields`
    );

    // 2. Verify forbidden properties do not exist
    assert.equal('key' in parsedDetails, false, `Event ${tc.eventType} leaked 'key' property`);
    assert.equal('content' in parsedDetails, false, `Event ${tc.eventType} leaked 'content' property`);
    assert.equal('tags' in parsedDetails, false, `Event ${tc.eventType} leaked 'tags' property`);
    assert.equal('metadata' in parsedDetails, false, `Event ${tc.eventType} leaked 'metadata' property`);
    assert.equal('arbitrary' in parsedDetails, false, `Event ${tc.eventType} leaked arbitrary property`);

    // 3. Verify sensitive substrings do not appear in serialized JSON string
    assert.equal(event.detailsJson.includes(sentinelKey), false);
    assert.equal(event.detailsJson.includes(sentinelContent), false);
    assert.equal(event.detailsJson.includes(sentinelTag), false);
    assert.equal(event.detailsJson.includes(sentinelMeta), false);
    assert.equal(event.detailsJson.includes(arbitraryInjectedField), false);

    // 4. Verify persisted database row matches
    const persisted = auditRepo.getEventById(event.id);
    assert.ok(persisted);
    assert.equal(persisted.detailsJson, event.detailsJson);
    assert.equal(persisted.payloadHash, event.payloadHash);
  }

  db.close();
});

test('AuditRepository - preserves unrelated audit event types and allows arbitrary fields on non-memory events', () => {
  const db = new DatabaseManager(':memory:');
  const taskRepo = new TaskRepository(db);
  const auditRepo = new AuditRepository(db);

  const task = taskRepo.createTask({ goal: 'Unrelated audit event preservation test' });

  const nonMemoryDetails = {
    key: 'allowed-config-key',
    content: 'arbitrary non-memory string',
    customField: 'preserved-value',
    nested: {
      tags: ['tag1', 'tag2'],
      metadata: { deep: true }
    }
  };

  const event = auditRepo.appendEvent({
    taskId: task.id,
    eventType: 'TOOL_EXECUTION_COMPLETED',
    actor: 'AGENT',
    details: nonMemoryDetails
  });

  const parsed = JSON.parse(event.detailsJson);
  assert.deepEqual(
    parsed,
    nonMemoryDetails,
    'Non-memory audit event details must be preserved completely unmodified'
  );
  assert.equal(parsed.key, 'allowed-config-key');
  assert.equal(parsed.content, 'arbitrary non-memory string');

  db.close();
});

test('AuditRepository - filters non-schema property names from updatedFields in MEMORY_UPDATED', () => {
  const db = new DatabaseManager(':memory:');
  const taskRepo = new TaskRepository(db);
  const auditRepo = new AuditRepository(db);

  const task = taskRepo.createTask({ goal: 'updatedFields filtering test' });

  const event = auditRepo.appendEvent({
    taskId: task.id,
    eventType: 'MEMORY_UPDATED',
    actor: 'USER',
    details: {
      memoryId: 'mem-field-test',
      updatedFields: [
        'content',
        'tags',
        'SECRET_INJECTED_FIELD_NAME',
        'arbitraryString',
        'priority'
      ]
    }
  });

  const parsed = JSON.parse(event.detailsJson);
  assert.deepEqual(
    parsed.updatedFields,
    ['content', 'tags', 'priority'],
    'Only safe schema field names should be retained in updatedFields'
  );

  db.close();
});
