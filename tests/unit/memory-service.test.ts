/**
 * Next-Generation Dots AI Platform - Memory Service Unit & Adversarial Tests
 * Phase 7.3: Memory Subsystem
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseManager } from '../../src/storage/db.ts';
import { TaskRepository } from '../../src/storage/task-repository.ts';
import { AuditRepository } from '../../src/storage/audit-repository.ts';
import { MemoryRepository } from '../../src/storage/memory-repository.ts';
import { RelevanceMatcher } from '../../src/memory/relevance-matcher.ts';
import { MemoryContextBuilder } from '../../src/memory/context-builder.ts';
import { MemoryService } from '../../src/memory/memory-service.ts';
import type { CallerContext, ScopeIdentifier } from '../../src/domain/types.ts';
import {
  ValidationError,
  SecurityViolationError,
  MemoryScopeViolationError,
  MemoryNotFoundError,
  TaskNotFoundError
} from '../../src/domain/errors.ts';

function setupServiceTest() {
  const db = new DatabaseManager(':memory:');
  const taskRepo = new TaskRepository(db);
  const auditRepo = new AuditRepository(db);
  const memoryRepo = new MemoryRepository(db);
  const relevanceMatcher = new RelevanceMatcher();
  const contextBuilder = new MemoryContextBuilder({ matcher: relevanceMatcher });
  const memoryService = new MemoryService({
    memoryRepo,
    auditRepo,
    taskRepo,
    relevanceMatcher,
    contextBuilder
  });

  const workspaceA: ScopeIdentifier = { scopeType: 'WORKSPACE', scopeId: 'ws-alpha' };
  const workspaceB: ScopeIdentifier = { scopeType: 'WORKSPACE', scopeId: 'ws-beta' };
  const globalScope: ScopeIdentifier = { scopeType: 'GLOBAL', scopeId: 'default' };

  return {
    db,
    taskRepo,
    auditRepo,
    memoryRepo,
    memoryService,
    workspaceA,
    workspaceB,
    globalScope
  };
}

test('MemoryService - CallerContext validation and permission checks', () => {
  const { db, memoryService, taskRepo, workspaceA } = setupServiceTest();

  try {
    const task = taskRepo.createTask({ goal: 'Permission validation task' });

    // 1. Missing or non-object caller
    assert.throws(
      () => memoryService.getMemoryById(null as any, 'mem-1'),
      (err: unknown) => err instanceof ValidationError && err.message.includes('CallerContext')
    );

    // 2. Invalid actor
    assert.throws(
      () => memoryService.getMemoryById({
        actor: 'INVALID_ACTOR' as any,
        scope: workspaceA,
        permissions: ['READ']
      }, 'mem-1'),
      (err: unknown) => err instanceof ValidationError && err.message.includes('actor')
    );

    // 3. Missing scope
    assert.throws(
      () => memoryService.getMemoryById({
        actor: 'USER',
        scope: null as any,
        permissions: ['READ']
      }, 'mem-1'),
      (err: unknown) => err instanceof ValidationError && err.message.includes('scope')
    );

    // 4. Invalid scopeType or scopeId
    assert.throws(
      () => memoryService.getMemoryById({
        actor: 'USER',
        scope: { scopeType: 'INVALID' as any, scopeId: 'ws-1' },
        permissions: ['READ']
      }, 'mem-1'),
      (err: unknown) => err instanceof ValidationError && err.message.includes('scopeType')
    );

    assert.throws(
      () => memoryService.getMemoryById({
        actor: 'USER',
        scope: { scopeType: 'GLOBAL', scopeId: 'not-default' },
        permissions: ['READ']
      }, 'mem-1'),
      (err: unknown) => err instanceof ValidationError && err.message.includes('default')
    );

    // 5. Missing or invalid permissions
    assert.throws(
      () => memoryService.getMemoryById({
        actor: 'USER',
        scope: workspaceA,
        permissions: null as any
      }, 'mem-1'),
      (err: unknown) => err instanceof ValidationError && err.message.includes('permissions')
    );

    assert.throws(
      () => memoryService.getMemoryById({
        actor: 'USER',
        scope: workspaceA,
        permissions: ['INVALID_PERMISSION' as any]
      }, 'mem-1'),
      (err: unknown) => err instanceof ValidationError && err.message.includes('Invalid permission')
    );

    // 6. Insufficient permissions on READ
    const noPermCaller: CallerContext = {
      actor: 'USER',
      scope: workspaceA,
      permissions: [],
      taskId: task.id
    };

    assert.throws(
      () => memoryService.getMemoryById(noPermCaller, 'mem-1'),
      (err: unknown) => {
        assert.ok(err instanceof SecurityViolationError);
        assert.equal(err.code, 'SECURITY_VIOLATION');
        assert.equal(err.violationType, 'INSUFFICIENT_PERMISSIONS');
        return true;
      }
    );

    // 7. Insufficient permissions on WRITE
    const readOnlyCaller: CallerContext = {
      actor: 'USER',
      scope: workspaceA,
      permissions: ['READ'],
      taskId: task.id
    };

    assert.throws(
      () => memoryService.createMemory(readOnlyCaller, {
        category: 'PROJECT_FACT',
        scopeType: 'WORKSPACE',
        scopeId: workspaceA.scopeId,
        key: 'test.key',
        content: 'test content'
      }),
      (err: unknown) => err instanceof SecurityViolationError && err.violationType === 'INSUFFICIENT_PERMISSIONS'
    );

    // 8. Insufficient permissions on DELETE
    const writeOnlyCaller: CallerContext = {
      actor: 'USER',
      scope: workspaceA,
      permissions: ['READ', 'WRITE'],
      taskId: task.id
    };

    assert.throws(
      () => memoryService.deleteMemory(writeOnlyCaller, 'mem-1'),
      (err: unknown) => err instanceof SecurityViolationError && err.violationType === 'INSUFFICIENT_PERMISSIONS'
    );

    assert.throws(
      () => memoryService.archiveMemory(writeOnlyCaller, 'mem-1'),
      (err: unknown) => err instanceof SecurityViolationError && err.violationType === 'INSUFFICIENT_PERMISSIONS'
    );

    // 9. Insufficient permissions on APPROVE
    assert.throws(
      () => memoryService.decideProposal(writeOnlyCaller, {
        memoryId: 'mem-1',
        decision: 'APPROVED'
      }),
      (err: unknown) => err instanceof SecurityViolationError && err.violationType === 'INSUFFICIENT_PERMISSIONS'
    );
  } finally {
    db.close();
  }
});

test('MemoryService - strictly enforces scope derivation and blocks cross-workspace operations', () => {
  const { db, memoryService, taskRepo, workspaceA, workspaceB, globalScope } = setupServiceTest();

  try {
    const taskA = taskRepo.createTask({
      goal: 'Workspace A task',
      metadata: { workspaceId: workspaceA.scopeId }
    });
    const taskB = taskRepo.createTask({
      goal: 'Workspace B task',
      metadata: { workspaceId: workspaceB.scopeId }
    });

    const userCallerA: CallerContext = {
      actor: 'USER',
      scope: workspaceA,
      permissions: ['READ', 'WRITE', 'DELETE', 'APPROVE'],
      taskId: taskA.id
    };

    const userCallerB: CallerContext = {
      actor: 'USER',
      scope: workspaceB,
      permissions: ['READ', 'WRITE', 'DELETE', 'APPROVE'],
      taskId: taskB.id
    };

    // 1. Create memory in Workspace A
    const memA = memoryService.createMemory(userCallerA, {
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: workspaceA.scopeId,
      key: 'service.port',
      content: 'Port 8080'
    });

    assert.ok(memA.id);
    assert.equal(memA.scopeType, 'WORKSPACE');
    assert.equal(memA.scopeId, workspaceA.scopeId);

    // 2. Caller A retrieves it successfully
    const readByA = memoryService.getMemoryById(userCallerA, memA.id);
    assert.ok(readByA);
    assert.equal(readByA.content, 'Port 8080');

    // 3. Caller B in Workspace B attempts cross-workspace read by ID -> MemoryScopeViolationError
    assert.throws(
      () => memoryService.getMemoryById(userCallerB, memA.id),
      (err: unknown) => {
        assert.ok(err instanceof MemoryScopeViolationError);
        assert.equal(err.code, 'MEMORY_SCOPE_VIOLATION');
        return true;
      }
    );

    // 4. Caller B listMemories returns 0 records from Workspace A
    const listB = memoryService.listMemories(userCallerB);
    assert.equal(listB.length, 0);

    // 5. Caller B attempts cross-workspace update -> MemoryScopeViolationError
    assert.throws(
      () => memoryService.updateMemory(userCallerB, memA.id, { content: 'Tampered' }),
      (err: unknown) => err instanceof MemoryScopeViolationError
    );

    // 6. Caller B attempts cross-workspace archive -> MemoryScopeViolationError
    assert.throws(
      () => memoryService.archiveMemory(userCallerB, memA.id),
      (err: unknown) => err instanceof MemoryScopeViolationError
    );

    // 7. Caller B attempts cross-workspace delete -> MemoryScopeViolationError
    assert.throws(
      () => memoryService.deleteMemory(userCallerB, memA.id),
      (err: unknown) => err instanceof MemoryScopeViolationError
    );

    // 8. Global scope isolation: Global caller cannot access workspace memory
    const globalCaller: CallerContext = {
      actor: 'USER',
      scope: globalScope,
      permissions: ['READ', 'WRITE', 'DELETE', 'APPROVE']
    };

    assert.throws(
      () => memoryService.getMemoryById(globalCaller, memA.id),
      (err: unknown) => err instanceof MemoryScopeViolationError
    );
  } finally {
    db.close();
  }
});

test('MemoryService - rejects attempts to forge scope through untrusted caller input', () => {
  const { db, memoryService, taskRepo, workspaceA, workspaceB, globalScope } = setupServiceTest();

  try {
    const taskA = taskRepo.createTask({
      goal: 'Workspace A task',
      metadata: { workspaceId: workspaceA.scopeId }
    });

    const agentCaller: CallerContext = {
      actor: 'AGENT',
      scope: workspaceA,
      permissions: ['READ', 'WRITE'],
      taskId: taskA.id
    };

    // 1. Agent attempts to specify scopeId of Workspace B inside createMemory
    assert.throws(
      () => memoryService.createMemory(agentCaller, {
        category: 'PROJECT_FACT',
        scopeType: 'WORKSPACE',
        scopeId: workspaceB.scopeId, // Attempted spoof
        key: 'spoofed.key',
        content: 'Spoofed content'
      }),
      (err: unknown) => {
        assert.ok(err instanceof MemoryScopeViolationError);
        assert.ok(err.message.includes('Memory scope violation'));
        return true;
      }
    );

    // 2. Agent attempts to specify scopeType of GLOBAL inside createMemory
    assert.throws(
      () => memoryService.createMemory(agentCaller, {
        category: 'USER_PREFERENCE',
        scopeType: 'GLOBAL', // Attempted spoof
        scopeId: globalScope.scopeId,
        key: 'spoofed.global',
        content: 'Spoofed global'
      }),
      (err: unknown) => err instanceof MemoryScopeViolationError
    );

    // 3. Agent attempts to specify different scopeId inside listMemories filter
    assert.throws(
      () => memoryService.listMemories(agentCaller, {
        scopeId: workspaceB.scopeId
      } as any),
      (err: unknown) => err instanceof MemoryScopeViolationError
    );
  } finally {
    db.close();
  }
});

test('MemoryService - agent memory proposals remain inactive until human approval', () => {
  const { db, memoryService, taskRepo, workspaceA } = setupServiceTest();

  try {
    const task = taskRepo.createTask({
      goal: 'Agent research task',
      metadata: { workspaceId: workspaceA.scopeId }
    });

    const agentCaller: CallerContext = {
      actor: 'AGENT',
      scope: workspaceA,
      permissions: ['READ', 'WRITE'],
      taskId: task.id
    };

    const userCaller: CallerContext = {
      actor: 'USER',
      scope: workspaceA,
      permissions: ['READ', 'WRITE', 'DELETE', 'APPROVE'],
      taskId: task.id
    };

    // 1. Agent attempts to directly create an ACTIVE memory -> SecurityViolationError
    assert.throws(
      () => memoryService.createMemory(agentCaller, {
        category: 'PROJECT_FACT',
        scopeType: 'WORKSPACE',
        scopeId: workspaceA.scopeId,
        key: 'database.engine',
        content: 'PostgreSQL 16',
        status: 'ACTIVE'
      }),
      (err: unknown) => {
        assert.ok(err instanceof SecurityViolationError);
        assert.equal(err.violationType, 'AGENT_PROPOSAL_REQUIRED');
        return true;
      }
    );

    // 2. Agent creates memory without status or with PENDING_APPROVAL -> persists as PENDING_APPROVAL proposal
    const proposal = memoryService.createMemory(agentCaller, {
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: workspaceA.scopeId,
      key: 'database.engine',
      content: 'PostgreSQL 16'
    });

    assert.ok(proposal.id);
    assert.equal(proposal.status, 'PENDING_APPROVAL');

    // 3. Verify proposal is NOT included in ACTIVE listMemories
    const activeList = memoryService.listMemories(userCaller, { status: 'ACTIVE' });
    assert.equal(activeList.length, 0);

    // 4. Verify proposal is NOT included in buildTaskMemoryContext
    const context = memoryService.buildTaskMemoryContext(userCaller, {
      query: 'What database engine are we using?'
    });
    assert.equal(context.included.length, 0);

    // 5. Agent attempts self-approval -> SecurityViolationError
    assert.throws(
      () => memoryService.decideProposal(agentCaller, {
        memoryId: proposal.id,
        decision: 'APPROVED'
      }),
      (err: unknown) => {
        assert.ok(err instanceof SecurityViolationError);
        assert.equal(err.violationType, 'UNAUTHORIZED_APPROVAL');
        return true;
      }
    );

    // 6. Agent attempts to activate via updateMemory -> SecurityViolationError
    assert.throws(
      () => memoryService.updateMemory(agentCaller, proposal.id, {
        status: 'ACTIVE'
      }),
      (err: unknown) => {
        assert.ok(err instanceof SecurityViolationError);
        assert.equal(err.violationType, 'UNAUTHORIZED_APPROVAL');
        return true;
      }
    );

    // 7. Non-user (SYSTEM) attempts approval -> SecurityViolationError
    const systemCaller: CallerContext = {
      actor: 'SYSTEM',
      scope: workspaceA,
      permissions: ['APPROVE'],
      taskId: task.id
    };
    assert.throws(
      () => memoryService.decideProposal(systemCaller, {
        memoryId: proposal.id,
        decision: 'APPROVED'
      }),
      (err: unknown) => err instanceof SecurityViolationError && err.violationType === 'UNAUTHORIZED_APPROVAL'
    );

    // 8. Human user approves the proposal -> status becomes ACTIVE
    const approved = memoryService.decideProposal(userCaller, {
      memoryId: proposal.id,
      decision: 'APPROVED'
    });

    assert.equal(approved.id, proposal.id);
    assert.equal(approved.status, 'ACTIVE');

    // 9. Now it is visible in ACTIVE list and included in context
    const updatedActiveList = memoryService.listMemories(userCaller, { status: 'ACTIVE' });
    assert.equal(updatedActiveList.length, 1);
    assert.equal(updatedActiveList[0]?.id, proposal.id);

    const updatedContext = memoryService.buildTaskMemoryContext(userCaller, {
      query: 'database engine postgresql'
    });
    assert.equal(updatedContext.included.length, 1);
    assert.equal(updatedContext.included[0]?.id, proposal.id);

    // 10. Agent attempts to directly modify the now ACTIVE memory -> SecurityViolationError
    assert.throws(
      () => memoryService.updateMemory(agentCaller, proposal.id, {
        content: 'Tampered database engine'
      }),
      (err: unknown) => {
        assert.ok(err instanceof SecurityViolationError);
        assert.equal(err.violationType, 'AGENT_MUTATION_RESTRICTED');
        return true;
      }
    );
  } finally {
    db.close();
  }
});

test('MemoryService - human rejection archives proposals', () => {
  const { db, memoryService, taskRepo, workspaceA } = setupServiceTest();

  try {
    const task = taskRepo.createTask({ goal: 'Rejection test task' });

    const agentCaller: CallerContext = {
      actor: 'AGENT',
      scope: workspaceA,
      permissions: ['READ', 'WRITE'],
      taskId: task.id
    };

    const userCaller: CallerContext = {
      actor: 'USER',
      scope: workspaceA,
      permissions: ['READ', 'WRITE', 'DELETE', 'APPROVE'],
      taskId: task.id
    };

    const proposal = memoryService.createMemory(agentCaller, {
      category: 'LEARNED_PROCEDURE',
      scopeType: 'WORKSPACE',
      scopeId: workspaceA.scopeId,
      key: 'deploy.step',
      content: 'Run dangerous untested script'
    });

    assert.equal(proposal.status, 'PENDING_APPROVAL');

    // User rejects the proposal
    const rejected = memoryService.decideProposal(userCaller, {
      memoryId: proposal.id,
      decision: 'REJECTED'
    });

    assert.equal(rejected.status, 'ARCHIVED');

    // Remains excluded from active memories
    const activeList = memoryService.listMemories(userCaller, { status: 'ACTIVE' });
    assert.equal(activeList.length, 0);

    // Cannot decide an already decided proposal
    assert.throws(
      () => memoryService.decideProposal(userCaller, {
        memoryId: proposal.id,
        decision: 'APPROVED'
      }),
      (err: unknown) => err instanceof ValidationError && err.message.includes('not pending approval')
    );
  } finally {
    db.close();
  }
});

test('MemoryService - prevents task and memory scope mismatches in injection provenance', () => {
  const { db, memoryService, taskRepo, workspaceA, workspaceB } = setupServiceTest();

  try {
    const taskA = taskRepo.createTask({
      goal: 'Task in Workspace A',
      metadata: { workspaceId: workspaceA.scopeId }
    });
    const taskB = taskRepo.createTask({
      goal: 'Task in Workspace B',
      metadata: { workspaceId: workspaceB.scopeId }
    });

    const userCallerA: CallerContext = {
      actor: 'USER',
      scope: workspaceA,
      permissions: ['READ', 'WRITE', 'DELETE', 'APPROVE'],
      taskId: taskA.id
    };

    const userCallerB: CallerContext = {
      actor: 'USER',
      scope: workspaceB,
      permissions: ['READ', 'WRITE', 'DELETE', 'APPROVE'],
      taskId: taskB.id
    };

    const memA = memoryService.createMemory(userCallerA, {
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: workspaceA.scopeId,
      key: 'arch.pattern',
      content: 'Event-driven architecture'
    });

    const memB = memoryService.createMemory(userCallerB, {
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: workspaceB.scopeId,
      key: 'arch.pattern',
      content: 'Monolithic architecture'
    });

    // 1. Valid injection: Task A + Memory A (both in Workspace A) succeeds
    const injectionA = memoryService.recordTaskInjection(userCallerA, {
      taskId: taskA.id,
      memoryId: memA.id,
      charCount: memA.content.length,
      estimatedTokens: 6
    });

    assert.ok(injectionA.id);
    assert.equal(injectionA.taskId, taskA.id);
    assert.equal(injectionA.memoryId, memA.id);

    // 2. Mismatch: Caller in Workspace A tries to inject Memory A into Task B (Workspace B)
    assert.throws(
      () => memoryService.recordTaskInjection(userCallerA, {
        taskId: taskB.id,
        memoryId: memA.id,
        charCount: memA.content.length,
        estimatedTokens: 6
      }),
      (err: unknown) => {
        assert.ok(err instanceof MemoryScopeViolationError);
        return true;
      }
    );

    // 3. Mismatch: Caller in Workspace B tries to inject Memory A (Workspace A) into Task B (Workspace B)
    assert.throws(
      () => memoryService.recordTaskInjection(userCallerB, {
        taskId: taskB.id,
        memoryId: memA.id, // Belonging to Workspace A
        charCount: memA.content.length,
        estimatedTokens: 6
      }),
      (err: unknown) => err instanceof MemoryScopeViolationError
    );

    // 4. Non-existent task ID throws TaskNotFoundError
    assert.throws(
      () => memoryService.recordTaskInjection(userCallerA, {
        taskId: 'non-existent-task-id',
        memoryId: memA.id,
        charCount: 10,
        estimatedTokens: 3
      }),
      (err: unknown) => err instanceof TaskNotFoundError
    );

    // 5. Cross-scope context building with task ID mismatch
    assert.throws(
      () => memoryService.buildTaskMemoryContext(userCallerA, {
        query: 'architecture',
        taskId: taskB.id // Task B is in Workspace B
      }),
      (err: unknown) => err instanceof MemoryScopeViolationError
    );

    // 6. Cross-scope retrieval of injection records
    assert.throws(
      () => memoryService.getInjectionsByTaskId(userCallerA, taskB.id),
      (err: unknown) => err instanceof MemoryScopeViolationError
    );
  } finally {
    db.close();
  }
});

test('MemoryService - hard deletion physically erases content and nulls injection foreign keys', () => {
  const { db, memoryService, taskRepo, workspaceA } = setupServiceTest();

  try {
    const task = taskRepo.createTask({
      goal: 'Secret processing task',
      metadata: { workspaceId: workspaceA.scopeId }
    });

    const userCaller: CallerContext = {
      actor: 'USER',
      scope: workspaceA,
      permissions: ['READ', 'WRITE', 'DELETE', 'APPROVE'],
      taskId: task.id
    };

    const secretContent = 'CRITICAL_SECRET_CREDENTIAL_KEY_VALUE_XYZ';
    const mem = memoryService.createMemory(userCaller, {
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: workspaceA.scopeId,
      key: 'internal.secret',
      content: secretContent
    });

    // Record injection
    const injection = memoryService.recordTaskInjection(userCaller, {
      taskId: task.id,
      memoryId: mem.id,
      charCount: secretContent.length,
      estimatedTokens: 12
    });
    assert.equal(injection.memoryId, mem.id);

    // Hard-delete the memory
    const deleted = memoryService.deleteMemory(userCaller, mem.id);
    assert.equal(deleted, true);

    // Memory is no longer readable
    assert.equal(memoryService.getMemoryById(userCaller, mem.id), null);

    // Raw database verification: physical row is gone
    const rawMem = db.prepare('SELECT * FROM memories WHERE id = ?').get(mem.id);
    assert.equal(rawMem, undefined);

    // Injection record is preserved with memory_id = null
    const taskInjections = memoryService.getInjectionsByTaskId(userCaller, task.id);
    assert.equal(taskInjections.length, 1);
    assert.equal(taskInjections[0]?.id, injection.id);
    assert.equal(taskInjections[0]?.memoryId, null);
  } finally {
    db.close();
  }
});

test('MemoryService - audit privacy guarantee: raw memory content is never logged in audit events', () => {
  const { db, memoryService, taskRepo, auditRepo, workspaceA } = setupServiceTest();

  try {
    const task = taskRepo.createTask({
      goal: 'Comprehensive privacy audit task',
      metadata: { workspaceId: workspaceA.scopeId }
    });

    const sensitiveUserSecret = 'TOP_SECRET_USER_PASSWORD_ALPHA_BRAVO';
    const sensitiveAgentSecret = 'PROPRIETARY_MODEL_WEIGHT_SECRET_CHARLIE';

    const userCaller: CallerContext = {
      actor: 'USER',
      scope: workspaceA,
      permissions: ['READ', 'WRITE', 'DELETE', 'APPROVE'],
      taskId: task.id
    };

    const agentCaller: CallerContext = {
      actor: 'AGENT',
      scope: workspaceA,
      permissions: ['READ', 'WRITE'],
      taskId: task.id
    };

    // 1. User creates active memory -> MEMORY_CREATED
    const memUser = memoryService.createMemory(userCaller, {
      category: 'USER_PREFERENCE',
      scopeType: 'WORKSPACE',
      scopeId: workspaceA.scopeId,
      key: 'user.password.pattern',
      content: sensitiveUserSecret
    });

    // 2. Read memory -> MEMORY_RETRIEVED
    memoryService.getMemoryById(userCaller, memUser.id);
    memoryService.getMemoryByKey(userCaller, 'user.password.pattern');

    // 3. Update memory -> MEMORY_UPDATED
    memoryService.updateMemory(userCaller, memUser.id, {
      content: 'UPDATED_SECRET_REPLACEMENT'
    });

    // 4. Agent submits proposal -> MEMORY_PROPOSAL_SUBMITTED
    const proposal = memoryService.createMemory(agentCaller, {
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: workspaceA.scopeId,
      key: 'model.weight.config',
      content: sensitiveAgentSecret
    });

    // 5. User approves proposal -> MEMORY_PROPOSAL_DECIDED
    memoryService.decideProposal(userCaller, {
      memoryId: proposal.id,
      decision: 'APPROVED'
    });

    // 6. Security denial -> MEMORY_ACCESS_DENIED
    try {
      memoryService.decideProposal(agentCaller, {
        memoryId: proposal.id,
        decision: 'APPROVED'
      });
    } catch {
      // Expected security rejection
    }

    // 7. Context building -> MEMORY_RETRIEVED
    memoryService.buildTaskMemoryContext(userCaller, {
      query: 'password pattern config',
      taskId: task.id
    });

    // 8. Archive and hard-delete -> MEMORY_ARCHIVED, MEMORY_DELETED
    memoryService.archiveMemory(userCaller, memUser.id);
    memoryService.deleteMemory(userCaller, memUser.id);

    // Retrieve ALL audit events for the task
    const allEvents = auditRepo.getEventsByTaskId(task.id);
    assert.ok(allEvents.length >= 8, `Expected at least 8 audit events, received ${allEvents.length}`);

    // Verify each event type is present
    const eventTypes = new Set(allEvents.map((e) => e.eventType));
    assert.ok(eventTypes.has('MEMORY_CREATED'));
    assert.ok(eventTypes.has('MEMORY_RETRIEVED'));
    assert.ok(eventTypes.has('MEMORY_UPDATED'));
    assert.ok(eventTypes.has('MEMORY_PROPOSAL_SUBMITTED'));
    assert.ok(eventTypes.has('MEMORY_PROPOSAL_DECIDED'));
    assert.ok(eventTypes.has('MEMORY_ACCESS_DENIED'));
    assert.ok(eventTypes.has('MEMORY_ARCHIVED'));
    assert.ok(eventTypes.has('MEMORY_DELETED'));

    // STRICT PRIVACY ASSERTION: Neither secret ever appears anywhere in any audit detailsJson
    for (const event of allEvents) {
      assert.equal(
        event.detailsJson.includes(sensitiveUserSecret),
        false,
        `Audit event ${event.eventType} leaked sensitive user content in detailsJson!`
      );
      assert.equal(
        event.detailsJson.includes('UPDATED_SECRET_REPLACEMENT'),
        false,
        `Audit event ${event.eventType} leaked updated content in detailsJson!`
      );
      assert.equal(
        event.detailsJson.includes(sensitiveAgentSecret),
        false,
        `Audit event ${event.eventType} leaked sensitive agent content in detailsJson!`
      );
    }
  } finally {
    db.close();
  }
});

test('RelevanceMatcher & MemoryContextBuilder - hardened runtime validation', () => {
  // 1. Explicit null weight rejected with ValidationError instead of silently defaulting
  assert.throws(
    () => new RelevanceMatcher({ keyWeight: null as any }),
    (err: unknown) => err instanceof ValidationError && err.message.includes('keyWeight')
  );

  assert.throws(
    () => new RelevanceMatcher({ tagWeight: null as any }),
    (err: unknown) => err instanceof ValidationError && err.message.includes('tagWeight')
  );

  assert.throws(
    () => new RelevanceMatcher({ wordWeight: null as any }),
    (err: unknown) => err instanceof ValidationError && err.message.includes('wordWeight')
  );

  // 2. Invalid string weights rejected
  assert.throws(
    () => new RelevanceMatcher({ keyWeight: 'invalid' as any }),
    (err: unknown) => err instanceof ValidationError && err.message.includes('keyWeight')
  );

  // 3. Invalid stopWords rejected
  assert.throws(
    () => new RelevanceMatcher({ stopWords: 'not-a-set' as any }),
    (err: unknown) => err instanceof ValidationError && err.message.includes('Stop words')
  );

  // 4. MemoryContextBuilder rejects invalid matcher instance
  assert.throws(
    () => new MemoryContextBuilder({ matcher: {} as any }),
    (err: unknown) => err instanceof ValidationError && err.message.includes('Matcher must be an instance')
  );
});
