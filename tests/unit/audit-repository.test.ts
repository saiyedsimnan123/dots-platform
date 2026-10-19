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


test('AuditRepository - value hardening: drops nested objects and non-primitive values from memory audit fields', () => {
  const db = new DatabaseManager(':memory:');
  const taskRepo = new TaskRepository(db);
  const auditRepo = new AuditRepository(db);
  const task = taskRepo.createTask({ goal: 'Value hardening test - nested objects' });

  const event = auditRepo.appendEvent({
    taskId: task.id,
    eventType: 'MEMORY_CREATED',
    actor: 'USER',
    details: {
      memoryId: { leaked: 'nested-object-payload' },
      category: { subKey: 'PROJECT_FACT' },
      scopeType: ['WORKSPACE'],
      scopeId: { nested: 'ws-1' },
      status: { status: 'ACTIVE' }
    }
  });

  const parsed = JSON.parse(event.detailsJson);
  assert.deepEqual(parsed, {}, 'All nested objects or non-primitive values must be dropped');
  assert.equal('memoryId' in parsed, false);
  assert.equal('category' in parsed, false);
  assert.equal('scopeType' in parsed, false);
  assert.equal('scopeId' in parsed, false);
  assert.equal('status' in parsed, false);

  db.close();
});

test('AuditRepository - value hardening: drops non-enum strings for finite allowlisted properties', () => {
  const db = new DatabaseManager(':memory:');
  const taskRepo = new TaskRepository(db);
  const auditRepo = new AuditRepository(db);
  const task = taskRepo.createTask({ goal: 'Value hardening test - finite enums' });

  // Test MEMORY_PROPOSAL_DECIDED with invalid enums
  const event1 = auditRepo.appendEvent({
    taskId: task.id,
    eventType: 'MEMORY_PROPOSAL_DECIDED',
    actor: 'USER',
    details: {
      memoryId: 'mem-dec-valid',
      category: 'INVALID_CATEGORY_XYZ',
      decision: 'MAYBE_APPROVE',
      decidedBy: 'UNKNOWN_ACTOR',
      scopeType: 'INVALID_SCOPE',
      scopeId: 'ws-1',
      previousStatus: 'NOT_A_STATUS',
      newStatus: 'SUPER_ACTIVE'
    }
  });

  const parsed1 = JSON.parse(event1.detailsJson);
  assert.deepEqual(parsed1, {
    memoryId: 'mem-dec-valid',
    scopeId: 'ws-1'
  }, 'Invalid enums must be dropped while valid fields are retained');

  // Test MEMORIES_IMPORTED with invalid conflict strategy
  const event2 = auditRepo.appendEvent({
    taskId: task.id,
    eventType: 'MEMORIES_IMPORTED',
    actor: 'USER',
    details: {
      targetScopeType: 'WORKSPACE',
      targetScopeId: 'ws-1',
      conflictStrategy: 'INVALID_MERGE_STRATEGY',
      totalInBundle: 1,
      importedCount: 1
    }
  });

  const parsed2 = JSON.parse(event2.detailsJson);
  assert.equal('conflictStrategy' in parsed2, false);
  assert.equal(parsed2.targetScopeType, 'WORKSPACE');
  assert.equal(parsed2.totalInBundle, 1);

  // Test MEMORIES_PURGED with invalid purgeMode
  const event3 = auditRepo.appendEvent({
    taskId: task.id,
    eventType: 'MEMORIES_PURGED',
    actor: 'USER',
    details: {
      scopeType: 'WORKSPACE',
      scopeId: 'ws-1',
      purgeMode: 'NUKE_ALL',
      purgedCount: 0
    }
  });

  const parsed3 = JSON.parse(event3.detailsJson);
  assert.equal('purgeMode' in parsed3, false);
  assert.equal(parsed3.purgedCount, 0);

  db.close();
});

test('AuditRepository - value hardening: enforces strict ID and scope formats', () => {
  const db = new DatabaseManager(':memory:');
  const taskRepo = new TaskRepository(db);
  const auditRepo = new AuditRepository(db);
  const task = taskRepo.createTask({ goal: 'Value hardening test - ID formats' });

  const event = auditRepo.appendEvent({
    taskId: task.id,
    eventType: 'MEMORY_ACCESS_DENIED',
    actor: 'AGENT',
    details: {
      memoryId: 'mem-1; DROP TABLE users;--',
      taskId: 'task/with/slashes',
      scopeId: 'ws space invalid',
      expectedScope: 'INVALID_SCOPE_NO_COLON',
      callerScope: 'WORKSPACE:valid-scope-1',
      reason: 'CROSS_SCOPE_READ_ATTEMPT',
      operation: 'getMemoryById',
      checksum: 'bad checksum with spaces @#$'
    }
  });

  const parsed = JSON.parse(event.detailsJson);
  assert.equal('memoryId' in parsed, false, 'Malformed memoryId with SQL injection must be dropped');
  assert.equal('taskId' in parsed, false, 'Malformed taskId with slashes must be dropped');
  assert.equal('scopeId' in parsed, false, 'Malformed scopeId with spaces must be dropped');
  assert.equal('expectedScope' in parsed, false, 'Malformed scope string without colon must be dropped');
  assert.equal('checksum' in parsed, false, 'Malformed checksum with special characters must be dropped');
  assert.equal(parsed.callerScope, 'WORKSPACE:valid-scope-1');
  assert.equal(parsed.reason, 'CROSS_SCOPE_READ_ATTEMPT');
  assert.equal(parsed.operation, 'getMemoryById');

  db.close();
});

test('AuditRepository - value hardening: enforces strict numeric bounds for counts and batch limits', () => {
  const db = new DatabaseManager(':memory:');
  const taskRepo = new TaskRepository(db);
  const auditRepo = new AuditRepository(db);
  const task = taskRepo.createTask({ goal: 'Value hardening test - numerics' });

  const event = auditRepo.appendEvent({
    taskId: task.id,
    eventType: 'MEMORIES_PURGED',
    actor: 'USER',
    details: {
      scopeType: 'WORKSPACE',
      scopeId: 'ws-1',
      purgeMode: 'CUTOFF',
      purgedCount: -1,
      batchSizeLimit: 0
    }
  });

  const parsed = JSON.parse(event.detailsJson);
  assert.equal('purgedCount' in parsed, false, 'Negative purgedCount must be dropped');
  assert.equal('batchSizeLimit' in parsed, false, 'Zero batchSizeLimit must be dropped');
  assert.equal(parsed.scopeType, 'WORKSPACE');
  assert.equal(parsed.purgeMode, 'CUTOFF');

  // Verify non-negative 0 is accepted for counts, and positive integers are accepted for batchSizeLimit
  const validEvent = auditRepo.appendEvent({
    taskId: task.id,
    eventType: 'MEMORIES_PURGED',
    actor: 'USER',
    details: {
      scopeType: 'WORKSPACE',
      scopeId: 'ws-1',
      purgeMode: 'CUTOFF',
      purgedCount: 0,
      batchSizeLimit: 100
    }
  });

  const validParsed = JSON.parse(validEvent.detailsJson);
  assert.equal(validParsed.purgedCount, 0, 'Zero count must be preserved');
  assert.equal(validParsed.batchSizeLimit, 100, 'Valid positive batch limit must be preserved');

  // Verify non-integers and string numbers are dropped
  const nonIntEvent = auditRepo.appendEvent({
    taskId: task.id,
    eventType: 'MEMORY_RETRIEVED',
    actor: 'USER',
    details: {
      memoryId: 'mem-1',
      count: 3.14,
      totalInjections: '5'
    }
  });

  const nonIntParsed = JSON.parse(nonIntEvent.detailsJson);
  assert.equal('count' in nonIntParsed, false, 'Float count must be dropped');
  assert.equal('totalInjections' in nonIntParsed, false, 'String totalInjections must be dropped');
  assert.equal(nonIntParsed.memoryId, 'mem-1');

  db.close();
});

test('AuditRepository - value hardening: enforces strict ISO 8601 UTC timestamp format and prevents calendar rollover', () => {
  const db = new DatabaseManager(':memory:');
  const taskRepo = new TaskRepository(db);
  const auditRepo = new AuditRepository(db);
  const task = taskRepo.createTask({ goal: 'Value hardening test - timestamps' });

  const invalidTimestamps = [
    '2026-01-01',
    '2026-01-01T12:00:00',
    '2026-01-01T12:00:00+02:00',
    '2026-01-01T12:00:00.1234Z',
    '2026-02-30T00:00:00Z',
    '2026-13-01T00:00:00Z',
    'not-a-timestamp',
    '2026-01-01T25:00:00Z'
  ];

  for (const invalidTs of invalidTimestamps) {
    const event = auditRepo.appendEvent({
      taskId: task.id,
      eventType: 'MEMORIES_PURGED',
      actor: 'USER',
      details: {
        scopeType: 'WORKSPACE',
        scopeId: 'ws-1',
        purgeMode: 'CUTOFF',
        cutoffTimestamp: invalidTs
      }
    });

    const parsed = JSON.parse(event.detailsJson);
    assert.equal(
      'cutoffTimestamp' in parsed,
      false,
      `Invalid timestamp '${invalidTs}' must be dropped`
    );
  }

  // Valid timestamps must be preserved
  const validTimestamps = [
    '2026-01-01T00:00:00Z',
    '2026-01-01T00:00:00.1Z',
    '2026-01-01T00:00:00.12Z',
    '2026-01-01T00:00:00.123Z'
  ];

  for (const validTs of validTimestamps) {
    const event = auditRepo.appendEvent({
      taskId: task.id,
      eventType: 'MEMORIES_PURGED',
      actor: 'USER',
      details: {
        scopeType: 'WORKSPACE',
        scopeId: 'ws-1',
        purgeMode: 'CUTOFF',
        cutoffTimestamp: validTs
      }
    });

    const parsed = JSON.parse(event.detailsJson);
    assert.equal(
      parsed.cutoffTimestamp,
      validTs,
      `Valid timestamp '${validTs}' must be preserved`
    );
  }

  db.close();
});

test('AuditRepository - value hardening: validates every array element in memoryIds', () => {
  const db = new DatabaseManager(':memory:');
  const taskRepo = new TaskRepository(db);
  const auditRepo = new AuditRepository(db);
  const task = taskRepo.createTask({ goal: 'Value hardening test - memoryIds array' });

  // Mixed array: valid IDs retained, invalid elements (objects, malformed strings) dropped
  const event = auditRepo.appendEvent({
    taskId: task.id,
    eventType: 'MEMORY_RETRIEVED',
    actor: 'USER',
    details: {
      memoryIds: [
        'valid-mem-1',
        { malicious: 'object-payload' },
        'invalid id with spaces',
        'valid-mem-2',
        12345
      ]
    }
  });

  const parsed = JSON.parse(event.detailsJson);
  assert.deepEqual(
    parsed.memoryIds,
    ['valid-mem-1', 'valid-mem-2'],
    'Only valid ID strings should be retained in memoryIds'
  );

  // Array of only objects: entire property should be dropped
  const allInvalidEvent = auditRepo.appendEvent({
    taskId: task.id,
    eventType: 'MEMORY_RETRIEVED',
    actor: 'USER',
    details: {
      memoryIds: [{ malicious: 'payload1' }, { malicious: 'payload2' }]
    }
  });

  const allInvalidParsed = JSON.parse(allInvalidEvent.detailsJson);
  assert.equal('memoryIds' in allInvalidParsed, false, 'Array of only invalid elements must be dropped');

  db.close();
});

test('AuditRepository - value hardening: ignores prototype pollution payloads', () => {
  const db = new DatabaseManager(':memory:');
  const taskRepo = new TaskRepository(db);
  const auditRepo = new AuditRepository(db);
  const task = taskRepo.createTask({ goal: 'Value hardening test - prototype pollution' });

  const pollutedInput = JSON.parse(
    '{"__proto__": {"polluted": "yes"}, "constructor": {"evil": true}, "prototype": {"evil": true}, "memoryId": "mem-pollute-1", "category": "PROJECT_FACT"}'
  );

  const event = auditRepo.appendEvent({
    taskId: task.id,
    eventType: 'MEMORY_CREATED',
    actor: 'USER',
    details: pollutedInput
  });

  const parsed = JSON.parse(event.detailsJson);
  assert.deepEqual(parsed, {
    memoryId: 'mem-pollute-1',
    category: 'PROJECT_FACT'
  });

  // Verify Object prototype was not contaminated
  assert.equal((Object.prototype as Record<string, unknown>).polluted, undefined);
  assert.equal(Object.hasOwn(parsed, '__proto__'), false);
  assert.equal(Object.hasOwn(parsed, 'constructor'), false);
  assert.equal(Object.hasOwn(parsed, 'prototype'), false);
  assert.equal(event.detailsJson.includes('polluted'), false);
  assert.equal(event.detailsJson.includes('evil'), false);

  db.close();
});
