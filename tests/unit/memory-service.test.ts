/**
 * Next-Generation Dots AI Platform - Memory Service Security Hardening Tests
 * Phase 7.3: Security Hardening
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
import { MemoryAuthorizer } from '../../src/security/memory-authorizer.ts';
import type { ScopeIdentifier } from '../../src/domain/types.ts';
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

test('MemoryService - Host authorization boundary prevents forged caller contexts', () => {
  const { db, memoryService, taskRepo, workspaceA, workspaceB } = setupServiceTest();

  try {
    const taskA = taskRepo.createTask({
      goal: 'Authorized task A',
      metadata: { workspaceId: workspaceA.scopeId }
    });

    // 1. Raw handcrafted object literal is REJECTED even if structurally valid
    const unsealedLiteral = {
      actor: 'USER' as const,
      scope: workspaceA,
      permissions: ['READ' as const, 'WRITE' as const, 'DELETE' as const, 'APPROVE' as const],
      taskId: taskA.id
    };

    assert.throws(
      () => memoryService.getMemoryById(unsealedLiteral as any, 'mem-1'),
      (err: unknown) => {
        assert.ok(err instanceof SecurityViolationError);
        assert.equal(err.violationType, 'FORGED_CALLER_CONTEXT');
        return true;
      }
    );

    // 2. Legitimate host-issued context is ACCEPTED
    const validUser = memoryService.issueContext({
      actor: 'USER',
      scope: workspaceA,
      permissions: ['READ', 'WRITE', 'DELETE', 'APPROVE'],
      taskId: taskA.id
    });
    assert.equal(memoryService.getMemoryById(validUser, 'mem-nonexistent'), null);

    // 3. Adversarial tampering: Actor tampering (AGENT -> USER)
    const validAgent = memoryService.issueContext({
      actor: 'AGENT',
      scope: workspaceA,
      permissions: ['READ', 'WRITE'],
      taskId: taskA.id
    });

    const tamperedActor = { ...validAgent, actor: 'USER' as const };
    assert.throws(
      () => memoryService.getMemoryById(tamperedActor as any, 'mem-1'),
      (err: unknown) => err instanceof SecurityViolationError && err.violationType === 'FORGED_CALLER_CONTEXT'
    );

    // 4. Adversarial tampering: Permissions tampering (Escalate permissions to APPROVE)
    const tamperedPermissions = {
      ...validAgent,
      permissions: new Set(['READ', 'WRITE', 'APPROVE'] as const)
    };
    assert.throws(
      () => memoryService.getMemoryById(tamperedPermissions as any, 'mem-1'),
      (err: unknown) => err instanceof SecurityViolationError && err.violationType === 'FORGED_CALLER_CONTEXT'
    );

    // 5. Adversarial tampering: Scope tampering (ws-alpha -> ws-beta)
    const tamperedScope = {
      ...validAgent,
      scope: workspaceB
    };
    assert.throws(
      () => memoryService.getMemoryById(tamperedScope as any, 'mem-1'),
      (err: unknown) => err instanceof SecurityViolationError && err.violationType === 'FORGED_CALLER_CONTEXT'
    );

    // 6. Adversarial attack: Context issued by an independent authorizer (different host secret)
    const externalAuthorizer = new MemoryAuthorizer();
    const foreignContext = externalAuthorizer.issueContext({
      actor: 'USER',
      scope: workspaceA,
      permissions: ['READ', 'WRITE', 'DELETE', 'APPROVE'],
      taskId: taskA.id
    });

    assert.throws(
      () => memoryService.getMemoryById(foreignContext, 'mem-1'),
      (err: unknown) => err instanceof SecurityViolationError && err.violationType === 'FORGED_CALLER_CONTEXT'
    );

    // 7. Handcrafted object with spoofed _proof property
    const spoofedProof = {
      actor: 'USER' as const,
      scope: workspaceA,
      permissions: ['READ' as const, 'WRITE' as const],
      taskId: taskA.id,
      _proof: { signature: 'abcdef1234567890', nonce: 'fake-nonce' }
    };
    assert.throws(
      () => memoryService.getMemoryById(spoofedProof as any, 'mem-1'),
      (err: unknown) => err instanceof SecurityViolationError && err.violationType === 'FORGED_CALLER_CONTEXT'
    );
  } finally {
    db.close();
  }
});

test('MemoryService - Permission separation and insufficient permission enforcement', () => {
  const { db, memoryService, taskRepo, workspaceA } = setupServiceTest();

  try {
    const task = taskRepo.createTask({
      goal: 'Permission verification task',
      metadata: { workspaceId: workspaceA.scopeId }
    });

    // Caller with READ only
    const readCaller = memoryService.issueContext({
      actor: 'USER',
      scope: workspaceA,
      permissions: ['READ'],
      taskId: task.id
    });

    assert.throws(
      () => memoryService.createMemory(readCaller, {
        category: 'PROJECT_FACT',
        scopeType: 'WORKSPACE',
        scopeId: workspaceA.scopeId,
        key: 'test.key',
        content: 'content'
      }),
      (err: unknown) => err instanceof SecurityViolationError && err.violationType === 'INSUFFICIENT_PERMISSIONS'
    );

    assert.throws(
      () => memoryService.updateMemory(readCaller, 'mem-1', { content: 'updated' }),
      (err: unknown) => err instanceof SecurityViolationError && err.violationType === 'INSUFFICIENT_PERMISSIONS'
    );

    assert.throws(
      () => memoryService.archiveMemory(readCaller, 'mem-1'),
      (err: unknown) => err instanceof SecurityViolationError && err.violationType === 'INSUFFICIENT_PERMISSIONS'
    );

    assert.throws(
      () => memoryService.deleteMemory(readCaller, 'mem-1'),
      (err: unknown) => err instanceof SecurityViolationError && err.violationType === 'INSUFFICIENT_PERMISSIONS'
    );

    // Caller with WRITE only (lacks APPROVE and DELETE)
    const writeCaller = memoryService.issueContext({
      actor: 'USER',
      scope: workspaceA,
      permissions: ['WRITE'],
      taskId: task.id
    });

    assert.throws(
      () => memoryService.archiveMemory(writeCaller, 'mem-1'),
      (err: unknown) => err instanceof SecurityViolationError && err.violationType === 'INSUFFICIENT_PERMISSIONS'
    );

    assert.throws(
      () => memoryService.deleteMemory(writeCaller, 'mem-1'),
      (err: unknown) => err instanceof SecurityViolationError && err.violationType === 'INSUFFICIENT_PERMISSIONS'
    );

    assert.throws(
      () => memoryService.decideProposal(writeCaller, {
        memoryId: 'mem-1',
        decision: 'APPROVED'
      }),
      (err: unknown) => err instanceof SecurityViolationError && err.violationType === 'INSUFFICIENT_PERMISSIONS'
    );
  } finally {
    db.close();
  }
});

test('MemoryService - Approval bypass prevention across all update and proposal paths', () => {
  const { db, memoryService, taskRepo, workspaceA } = setupServiceTest();

  try {
    const task = taskRepo.createTask({
      goal: 'Proposal bypass testing task',
      metadata: { workspaceId: workspaceA.scopeId }
    });

    const agentCaller = memoryService.issueContext({
      actor: 'AGENT',
      scope: workspaceA,
      permissions: ['READ', 'WRITE'],
      taskId: task.id
    });

    const userWriteOnly = memoryService.issueContext({
      actor: 'USER',
      scope: workspaceA,
      permissions: ['READ', 'WRITE'],
      taskId: task.id
    });

    const userFull = memoryService.issueContext({
      actor: 'USER',
      scope: workspaceA,
      permissions: ['READ', 'WRITE', 'DELETE', 'APPROVE'],
      taskId: task.id
    });

    // 1. Agent submits proposal
    const proposal = memoryService.createMemory(agentCaller, {
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: workspaceA.scopeId,
      key: 'cache.ttl',
      content: '3600 seconds'
    });
    assert.equal(proposal.status, 'PENDING_APPROVAL');

    // 2. BYPASS ATTEMPT 1: User with WRITE alone attempts to activate proposal via updateMemory
    assert.throws(
      () => memoryService.updateMemory(userWriteOnly, proposal.id, {
        status: 'ACTIVE'
      }),
      (err: unknown) => {
        assert.ok(err instanceof SecurityViolationError);
        assert.equal(err.violationType, 'UNAUTHORIZED_APPROVAL');
        return true;
      }
    );

    // 3. BYPASS ATTEMPT 2: User with FULL permissions (including APPROVE) attempts to activate via updateMemory
    // MUST FAIL: Only the trusted decideProposal path may approve proposals!
    assert.throws(
      () => memoryService.updateMemory(userFull, proposal.id, {
        status: 'ACTIVE'
      }),
      (err: unknown) => {
        assert.ok(err instanceof SecurityViolationError);
        assert.equal(err.violationType, 'UNAUTHORIZED_APPROVAL');
        return true;
      }
    );

    // 4. BYPASS ATTEMPT 3: Agent attempts to activate proposal via updateMemory
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

    // 5. BYPASS ATTEMPT 4: User attempts direct status transition to ARCHIVED via updateMemory
    assert.throws(
      () => memoryService.updateMemory(userWriteOnly, proposal.id, {
        status: 'ARCHIVED'
      }),
      (err: unknown) => {
        assert.ok(err instanceof SecurityViolationError);
        assert.equal(err.violationType, 'UNAUTHORIZED_APPROVAL');
        return true;
      }
    );

    // 6. BYPASS ATTEMPT 5: Agent attempts to decideProposal on its own proposal
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

    // 7. BYPASS ATTEMPT 6: System actor attempts to decideProposal
    const systemCaller = memoryService.issueContext({
      actor: 'SYSTEM',
      scope: workspaceA,
      permissions: ['APPROVE'],
      taskId: task.id
    });
    assert.throws(
      () => memoryService.decideProposal(systemCaller, {
        memoryId: proposal.id,
        decision: 'APPROVED'
      }),
      (err: unknown) => {
        assert.ok(err instanceof SecurityViolationError);
        assert.equal(err.violationType, 'UNAUTHORIZED_APPROVAL');
        return true;
      }
    );

    // 8. TRUSTED APPROVAL PATH: Human USER with APPROVE permission calls decideProposal
    const approved = memoryService.decideProposal(userFull, {
      memoryId: proposal.id,
      decision: 'APPROVED'
    });
    assert.equal(approved.id, proposal.id);
    assert.equal(approved.status, 'ACTIVE');

    // 9. BYPASS ATTEMPT 7: Calling decideProposal on an already ACTIVE memory fails
    assert.throws(
      () => memoryService.decideProposal(userFull, {
        memoryId: proposal.id,
        decision: 'APPROVED'
      }),
      (err: unknown) => err instanceof ValidationError && err.message.includes('not pending approval')
    );

    // 10. Agent cannot modify already ACTIVE memory
    assert.throws(
      () => memoryService.updateMemory(agentCaller, proposal.id, {
        content: 'Tampered cache TTL'
      }),
      (err: unknown) => err instanceof SecurityViolationError && err.violationType === 'AGENT_MUTATION_RESTRICTED'
    );
  } finally {
    db.close();
  }
});

test('MemoryService - Injection provenance fails closed on unverified task scope and inactive memories', () => {
  const { db, memoryService, taskRepo, workspaceA, workspaceB } = setupServiceTest();

  try {
    const userA = memoryService.issueContext({
      actor: 'USER',
      scope: workspaceA,
      permissions: ['READ', 'WRITE', 'DELETE', 'APPROVE']
    });

    const agentA = memoryService.issueContext({
      actor: 'AGENT',
      scope: workspaceA,
      permissions: ['READ', 'WRITE']
    });

    // Create an ACTIVE memory in Workspace A
    const activeMemA = memoryService.createMemory(userA, {
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: workspaceA.scopeId,
      key: 'db.host',
      content: 'db.internal.alpha'
    });
    assert.equal(activeMemA.status, 'ACTIVE');

    // Create a PENDING_APPROVAL proposal in Workspace A
    const pendingMemA = memoryService.createMemory(agentA, {
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: workspaceA.scopeId,
      key: 'db.port',
      content: '5432'
    });
    assert.equal(pendingMemA.status, 'PENDING_APPROVAL');

    // 1. Task without TaskRepository fails closed
    const standaloneService = new MemoryService({
      memoryRepo: new MemoryRepository(db)
    });
    const standaloneUser = standaloneService.issueContext({
      actor: 'USER',
      scope: workspaceA,
      permissions: ['READ', 'WRITE']
    });

    assert.throws(
      () => standaloneService.recordTaskInjection(standaloneUser, {
        taskId: 'some-task',
        memoryId: activeMemA.id,
        charCount: 10,
        estimatedTokens: 3
      }),
      (err: unknown) => err instanceof ValidationError && err.message.includes('TaskRepository is required')
    );

    // 2. Unknown task ID fails closed with TaskNotFoundError
    assert.throws(
      () => memoryService.recordTaskInjection(userA, {
        taskId: 'unknown-task-id',
        memoryId: activeMemA.id,
        charCount: 10,
        estimatedTokens: 3
      }),
      (err: unknown) => err instanceof TaskNotFoundError
    );

    // 3. Task with missing metadata fails closed (no fallback to caller scope!)
    const taskMissingMeta = taskRepo.createTask({
      goal: 'Task lacking metadata'
    });
    assert.throws(
      () => memoryService.recordTaskInjection(userA, {
        taskId: taskMissingMeta.id,
        memoryId: activeMemA.id,
        charCount: 10,
        estimatedTokens: 3
      }),
      (err: unknown) => err instanceof ValidationError && err.message.includes('lacks metadata required to establish authoritative scope')
    );

    // 4. Task with malformed/untrusted JSON metadata fails closed
    const taskInvalidMeta = taskRepo.createTask({
      goal: 'Task with invalid metadata',
      metadata: { randomAttributeWithoutWorkspace: true }
    });
    assert.throws(
      () => memoryService.recordTaskInjection(userA, {
        taskId: taskInvalidMeta.id,
        memoryId: activeMemA.id,
        charCount: 10,
        estimatedTokens: 3
      }),
      (err: unknown) => err instanceof ValidationError && err.message.includes('does not contain valid scope information')
    );

    // 5. Cross-workspace task fails closed
    const taskWorkspaceB = taskRepo.createTask({
      goal: 'Task in Workspace B',
      metadata: { workspaceId: workspaceB.scopeId }
    });
    assert.throws(
      () => memoryService.recordTaskInjection(userA, {
        taskId: taskWorkspaceB.id,
        memoryId: activeMemA.id,
        charCount: 10,
        estimatedTokens: 3
      }),
      (err: unknown) => err instanceof MemoryScopeViolationError
    );

    // 6. Inactive memory (PENDING_APPROVAL) rejected from injection provenance
    const validTaskA = taskRepo.createTask({
      goal: 'Valid task in Workspace A',
      metadata: { workspaceId: workspaceA.scopeId }
    });

    assert.throws(
      () => memoryService.recordTaskInjection(userA, {
        taskId: validTaskA.id,
        memoryId: pendingMemA.id,
        charCount: 10,
        estimatedTokens: 3
      }),
      (err: unknown) => {
        assert.ok(err instanceof ValidationError);
        assert.ok(err.message.includes('Cannot record injection provenance for inactive memory'));
        return true;
      }
    );

    // 7. Legitimate injection with valid task and ACTIVE memory succeeds
    const injection = memoryService.recordTaskInjection(userA, {
      taskId: validTaskA.id,
      memoryId: activeMemA.id,
      charCount: activeMemA.content.length,
      estimatedTokens: 5
    });
    assert.ok(injection.id);
    assert.equal(injection.taskId, validTaskA.id);
    assert.equal(injection.memoryId, activeMemA.id);
  } finally {
    db.close();
  }
});

test('MemoryService - Batch injection guarantees zero partial writes on validation failure', () => {
  const { db, memoryService, taskRepo, memoryRepo, workspaceA } = setupServiceTest();

  try {
    const userA = memoryService.issueContext({
      actor: 'USER',
      scope: workspaceA,
      permissions: ['READ', 'WRITE', 'DELETE', 'APPROVE']
    });

    const agentA = memoryService.issueContext({
      actor: 'AGENT',
      scope: workspaceA,
      permissions: ['READ', 'WRITE']
    });

    const taskA = taskRepo.createTask({
      goal: 'Atomic batch injection task',
      metadata: { workspaceId: workspaceA.scopeId }
    });

    const mem1 = memoryService.createMemory(userA, {
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: workspaceA.scopeId,
      key: 'batch.key.1',
      content: 'Valid active record 1'
    });

    const mem2 = memoryService.createMemory(userA, {
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: workspaceA.scopeId,
      key: 'batch.key.2',
      content: 'Valid active record 2'
    });

    // Inactive proposal (will trigger validation failure on third item)
    const mem3Pending = memoryService.createMemory(agentA, {
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: workspaceA.scopeId,
      key: 'batch.key.3',
      content: 'Pending proposal 3'
    });

    // Attempt batch injection where 3rd item is invalid
    assert.throws(
      () => memoryService.recordTaskInjectionsBatch(userA, [
        { taskId: taskA.id, memoryId: mem1.id, charCount: 10, estimatedTokens: 3 },
        { taskId: taskA.id, memoryId: mem2.id, charCount: 10, estimatedTokens: 3 },
        { taskId: taskA.id, memoryId: mem3Pending.id, charCount: 10, estimatedTokens: 3 }
      ]),
      (err: unknown) => err instanceof ValidationError && err.message.includes('inactive memory')
    );

    // TRANSACTIONAL INTEGRITY ASSERTION: Exactly 0 records must exist in database!
    const persistedInjections = memoryRepo.getInjectionsByTaskId(taskA.id);
    assert.equal(
      persistedInjections.length,
      0,
      'Batch injection failed partially: earlier records were not rolled back!'
    );

    // Now execute a valid batch of 2 active memories
    const successfulBatch = memoryService.recordTaskInjectionsBatch(userA, [
      { taskId: taskA.id, memoryId: mem1.id, charCount: 10, estimatedTokens: 3 },
      { taskId: taskA.id, memoryId: mem2.id, charCount: 10, estimatedTokens: 3 }
    ]);
    assert.equal(successfulBatch.length, 2);

    const savedInjections = memoryRepo.getInjectionsByTaskId(taskA.id);
    assert.equal(savedInjections.length, 2);
  } finally {
    db.close();
  }
});

test('MemoryService - Mandatory audit logging fails closed on state mutations', () => {
  const { db, taskRepo, memoryRepo, workspaceA } = setupServiceTest();

  try {
    const task = taskRepo.createTask({
      goal: 'Audit failure test task',
      metadata: { workspaceId: workspaceA.scopeId }
    });

    // Construct a failing AuditRepository
    const failingAuditRepo = {
      appendEvent: () => {
        throw new Error('DISK_FULL: simulated immutable audit failure');
      },
      getEventsByTaskId: () => [],
      getEventById: () => null
    } as unknown as AuditRepository;

    const failingService = new MemoryService({
      memoryRepo,
      auditRepo: failingAuditRepo,
      taskRepo
    });

    const userCaller = failingService.issueContext({
      actor: 'USER',
      scope: workspaceA,
      permissions: ['READ', 'WRITE', 'DELETE', 'APPROVE'],
      taskId: task.id
    });

    // 1. Mandatory audit failure on createMemory MUST FAIL CLOSED
    assert.throws(
      () => failingService.createMemory(userCaller, {
        category: 'PROJECT_FACT',
        scopeType: 'WORKSPACE',
        scopeId: workspaceA.scopeId,
        key: 'fail.audit.key',
        content: 'content'
      }),
      (err: unknown) => err instanceof Error && err.message.includes('DISK_FULL')
    );

    // 2. Read operation with failing audit telemetry DOES NOT block reading (best-effort)
    // First create a memory directly via repository for read testing
    const existing = memoryRepo.createMemory({
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: workspaceA.scopeId,
      key: 'read.audit.key',
      content: 'readable content'
    });

    const read = failingService.getMemoryById(userCaller, existing.id);
    assert.ok(read);
    assert.equal(read.key, 'read.audit.key');
  } finally {
    db.close();
  }
});

test('MemoryService - Hard deletion physically erases content and nulls injection foreign keys', () => {
  const { db, memoryService, taskRepo, workspaceA } = setupServiceTest();

  try {
    const task = taskRepo.createTask({
      goal: 'Secret processing task',
      metadata: { workspaceId: workspaceA.scopeId }
    });

    const userCaller = memoryService.issueContext({
      actor: 'USER',
      scope: workspaceA,
      permissions: ['READ', 'WRITE', 'DELETE', 'APPROVE'],
      taskId: task.id
    });

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

test('MemoryService - Audit privacy guarantee: raw memory content is never logged in audit events', () => {
  const { db, memoryService, taskRepo, auditRepo, workspaceA } = setupServiceTest();

  try {
    const task = taskRepo.createTask({
      goal: 'Comprehensive privacy audit task',
      metadata: { workspaceId: workspaceA.scopeId }
    });

    const sensitiveUserSecret = 'TOP_SECRET_USER_PASSWORD_ALPHA_BRAVO';
    const sensitiveAgentSecret = 'PROPRIETARY_MODEL_WEIGHT_SECRET_CHARLIE';

    const userCaller = memoryService.issueContext({
      actor: 'USER',
      scope: workspaceA,
      permissions: ['READ', 'WRITE', 'DELETE', 'APPROVE'],
      taskId: task.id
    });

    const agentCaller = memoryService.issueContext({
      actor: 'AGENT',
      scope: workspaceA,
      permissions: ['READ', 'WRITE'],
      taskId: task.id
    });

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

    // 3. Update memory content -> MEMORY_UPDATED
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

test('RelevanceMatcher & MemoryContextBuilder - hardened runtime validation for explicit null and invalid instances', () => {
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
