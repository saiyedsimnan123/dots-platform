/**
 * Next-Generation Dots AI Platform - Memory Service Security Hardening Tests
 * Phase 7.3: Trusted Identity Boundary & Shared Audit Transaction Invariant
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
import {
  MemoryAuthorizer,
  type TrustedIdentityProvider,
  type AuthenticatedPrincipal
} from '../../src/security/memory-authorizer.ts';
import { HostMemoryAuthority } from '../../src/security/host-authority.ts';
import type { ScopeIdentifier, AppendAuditEventInput, AuditEvent } from '../../src/domain/types.ts';
import {
  ValidationError,
  SecurityViolationError,
  MemoryScopeViolationError,
  MemoryNotFoundError,
  TaskNotFoundError
} from '../../src/domain/errors.ts';

function setupServiceTest(options: {
  identityProvider?: TrustedIdentityProvider;
  _testPostAuditHook?: () => void;
} = {}) {
  const db = new DatabaseManager(':memory:');
  const taskRepo = new TaskRepository(db);
  const auditRepo = new AuditRepository(db);
  const memoryRepo = new MemoryRepository(db);

  const workspaceA: ScopeIdentifier = { scopeType: 'WORKSPACE', scopeId: 'ws-alpha' };
  const workspaceB: ScopeIdentifier = { scopeType: 'WORKSPACE', scopeId: 'ws-beta' };
  const globalScope: ScopeIdentifier = { scopeType: 'GLOBAL', scopeId: 'default' };

  // Default trusted identity provider mapping verified tokens to authentic principals
  const identityProvider: TrustedIdentityProvider = options.identityProvider ?? {
    authenticate(credentials: unknown): AuthenticatedPrincipal | null {
      if (typeof credentials !== 'string') {
        return null;
      }
      if (credentials === 'token-admin-alpha') {
        return {
          principalId: 'user-admin',
          role: 'ADMIN',
          permittedScopes: [workspaceA, globalScope]
        };
      }
      if (credentials === 'token-member-alpha') {
        return {
          principalId: 'user-member',
          role: 'MEMBER',
          permittedScopes: [workspaceA]
        };
      }
      if (credentials === 'token-viewer-alpha') {
        return {
          principalId: 'user-viewer',
          role: 'VIEWER',
          permittedScopes: [workspaceA]
        };
      }
      if (credentials === 'token-admin-beta') {
        return {
          principalId: 'user-beta',
          role: 'ADMIN',
          permittedScopes: [workspaceB]
        };
      }
      return null;
    }
  };

  const hostAuthority = new HostMemoryAuthority({
    taskRepo,
    identityProvider
  });
  const authorizer = hostAuthority.authorizer;

  const relevanceMatcher = new RelevanceMatcher();
  const contextBuilder = new MemoryContextBuilder({ matcher: relevanceMatcher });
  const memoryService = new MemoryService({
    memoryRepo,
    auditRepo,
    taskRepo,
    authorizer,
    hostAuthority,
    relevanceMatcher,
    contextBuilder,
    _testPostAuditHook: options._testPostAuditHook
  });

  return {
    db,
    taskRepo,
    auditRepo,
    memoryRepo,
    hostAuthority,
    authorizer,
    identityProvider,
    memoryService,
    workspaceA,
    workspaceB,
    globalScope
  };
}

test('MemoryService - Host authorization boundary prevents forged caller contexts and boundary misuse', () => {
  const { db, hostAuthority, authorizer, memoryService, taskRepo, workspaceA, workspaceB } = setupServiceTest();

  try {
    const taskA = hostAuthority.createTask(taskRepo, {
      goal: 'Authorized task A',
      scope: workspaceA
    });

    // 1. Boundary Fix Verification: MemoryService does NOT expose issueContext or authorizer publicly
    assert.equal((memoryService as any).issueContext, undefined, 'MemoryService.issueContext must not exist');
    assert.equal((memoryService as any).authorizer, undefined, 'MemoryService.authorizer must be private');

    // 2. Raw handcrafted object literal is REJECTED even if structurally valid
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

    // 3. Legitimate host-issued context is ACCEPTED
    const validUser = authorizer.authorizeUser({
      credentials: 'token-admin-alpha',
      requestedScope: workspaceA,
      taskId: taskA.id
    });
    assert.equal(memoryService.getMemoryById(validUser, 'mem-nonexistent'), null);

    // 4. Adversarial tampering: Actor tampering (AGENT -> USER)
    const validAgent = authorizer.authorizeAgent({
      taskId: taskA.id
    });

    const tamperedActor = { ...validAgent, actor: 'USER' as const };
    assert.throws(
      () => memoryService.getMemoryById(tamperedActor as any, 'mem-1'),
      (err: unknown) => err instanceof SecurityViolationError && err.violationType === 'FORGED_CALLER_CONTEXT'
    );

    // 5. Adversarial tampering: Permissions tampering (Escalate permissions to APPROVE)
    const tamperedPermissions = {
      ...validAgent,
      permissions: new Set(['READ', 'WRITE', 'APPROVE'] as const)
    };
    assert.throws(
      () => memoryService.getMemoryById(tamperedPermissions as any, 'mem-1'),
      (err: unknown) => err instanceof SecurityViolationError && err.violationType === 'FORGED_CALLER_CONTEXT'
    );

    // 6. Adversarial tampering: Scope tampering (ws-alpha -> ws-beta)
    const tamperedScope = {
      ...validAgent,
      scope: workspaceB
    };
    assert.throws(
      () => memoryService.getMemoryById(tamperedScope as any, 'mem-1'),
      (err: unknown) => err instanceof SecurityViolationError && err.violationType === 'FORGED_CALLER_CONTEXT'
    );

    // 7. Adversarial attack: Context issued by an independent authorizer (different host secret)
    const externalIdentityProvider: TrustedIdentityProvider = {
      authenticate: () => ({
        principalId: 'user-ext',
        role: 'ADMIN',
        permittedScopes: [workspaceA]
      })
    };
    const externalHost = new HostMemoryAuthority({ taskRepo, identityProvider: externalIdentityProvider });
    const externalTask = externalHost.createTask(taskRepo, {
      goal: 'External task',
      scope: workspaceA
    });
    const foreignContext = externalHost.authorizer.authorizeUser({
      credentials: 'any-token',
      requestedScope: workspaceA,
      taskId: externalTask.id
    });

    assert.throws(
      () => memoryService.getMemoryById(foreignContext, 'mem-1'),
      (err: unknown) => err instanceof SecurityViolationError && err.violationType === 'FORGED_CALLER_CONTEXT'
    );

    // 8. Handcrafted object with spoofed _proof property
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

test('MemoryService - Permission separation and role-based policy enforcement', () => {
  const { db, hostAuthority, authorizer, memoryService, taskRepo, workspaceA } = setupServiceTest();

  try {
    const task = hostAuthority.createTask(taskRepo, {
      goal: 'Permission verification task',
      scope: workspaceA
    });

    // Caller with VIEWER role (READ only)
    const readCaller = authorizer.authorizeUser({
      credentials: 'token-viewer-alpha',
      requestedScope: workspaceA,
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

    // Caller with MEMBER role (WRITE and READ, but lacks APPROVE and DELETE)
    const writeCaller = authorizer.authorizeUser({
      credentials: 'token-member-alpha',
      requestedScope: workspaceA,
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
  const { db, hostAuthority, authorizer, memoryService, taskRepo, workspaceA } = setupServiceTest();

  try {
    const task = hostAuthority.createTask(taskRepo, {
      goal: 'Proposal bypass testing task',
      scope: workspaceA
    });

    const agentCaller = authorizer.authorizeAgent({
      taskId: task.id
    });

    const userWriteOnly = authorizer.authorizeUser({
      credentials: 'token-member-alpha',
      requestedScope: workspaceA,
      taskId: task.id
    });

    const userFull = authorizer.authorizeUser({
      credentials: 'token-admin-alpha',
      requestedScope: workspaceA,
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
    const systemCaller = hostAuthority.authorizeSystem({
      scope: workspaceA,
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
  const { db, hostAuthority, authorizer, memoryService, taskRepo, workspaceA, workspaceB } = setupServiceTest();

  try {
    const taskA = hostAuthority.createTask(taskRepo, {
      goal: 'Task A for injection',
      scope: workspaceA
    });

    const userA = authorizer.authorizeUser({
      credentials: 'token-admin-alpha',
      requestedScope: workspaceA,
      taskId: taskA.id
    });

    const agentA = authorizer.authorizeAgent({
      taskId: taskA.id
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
    const standaloneAuthorizer = new HostMemoryAuthority({
      identityProvider: {
        authenticate: () => ({
          principalId: 'user-alone',
          role: 'MEMBER',
          permittedScopes: [workspaceA]
        })
      }
    }).authorizer;
    const standaloneService = new MemoryService({
      memoryRepo: new MemoryRepository(db),
      authorizer: standaloneAuthorizer
    });
    const standaloneUser = standaloneAuthorizer.authorizeUser({
      credentials: 'valid-token',
      requestedScope: workspaceA
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

    // 4. Task with un-attested metadata fails closed
    const taskInvalidMeta = taskRepo.createTask({
      goal: 'Task with un-attested metadata',
      metadata: { workspaceId: workspaceA.scopeId }
    });
    assert.throws(
      () => memoryService.recordTaskInjection(userA, {
        taskId: taskInvalidMeta.id,
        memoryId: activeMemA.id,
        charCount: 10,
        estimatedTokens: 3
      }),
      (err: unknown) => err instanceof ValidationError && err.message.includes('lacks a trusted host scope attestation')
    );

    // 4b. Task with forged host attestation signature fails closed
    const taskForgedMeta = taskRepo.createTask({
      goal: 'Task with forged attestation',
      metadata: {
        _scopeAttestation: {
          scopeType: 'WORKSPACE',
          scopeId: workspaceA.scopeId,
          signature: 'deadbeef00112233445566778899aabbccddeeff',
          timestamp: new Date().toISOString()
        }
      }
    });
    assert.throws(
      () => memoryService.recordTaskInjection(userA, {
        taskId: taskForgedMeta.id,
        memoryId: activeMemA.id,
        charCount: 10,
        estimatedTokens: 3
      }),
      (err: unknown) => err instanceof SecurityViolationError && err.violationType === 'FORGED_TASK_SCOPE'
    );

    // 5. Cross-workspace task fails closed
    const taskWorkspaceB = hostAuthority.createTask(taskRepo, {
      goal: 'Task in Workspace B',
      scope: workspaceB
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
    const validTaskA = hostAuthority.createTask(taskRepo, {
      goal: 'Valid task in Workspace A',
      scope: workspaceA
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
  const { db, hostAuthority, authorizer, memoryService, taskRepo, memoryRepo, workspaceA } = setupServiceTest();

  try {
    const taskA = hostAuthority.createTask(taskRepo, {
      goal: 'Atomic batch injection task',
      scope: workspaceA
    });

    const userA = authorizer.authorizeUser({
      credentials: 'token-admin-alpha',
      requestedScope: workspaceA,
      taskId: taskA.id
    });

    const agentA = authorizer.authorizeAgent({
      taskId: taskA.id
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

test('MemoryService - Mandatory audit logging fails closed on state mutations and rolls back database changes', () => {
  const { db, hostAuthority, authorizer, taskRepo, memoryRepo, workspaceA } = setupServiceTest();

  try {
    const task = hostAuthority.createTask(taskRepo, {
      goal: 'Audit failure test task',
      scope: workspaceA
    });

    // Construct a failing AuditRepository that shares the exact same DatabaseManager
    const failingAuditRepo = new class extends AuditRepository {
      override appendEvent(input: AppendAuditEventInput): AuditEvent {
        throw new Error('DISK_FULL: simulated immutable audit failure');
      }
    }(db);

    const failingService = new MemoryService({
      memoryRepo,
      auditRepo: failingAuditRepo,
      taskRepo,
      authorizer
    });

    const userCaller = authorizer.authorizeUser({
      credentials: 'token-admin-alpha',
      requestedScope: workspaceA,
      taskId: task.id
    });

    // 1. createMemory: Mandatory audit failure MUST throw AND roll back row creation in SQLite
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

    const createdRow = db.prepare('SELECT * FROM memories WHERE key = ?').get('fail.audit.key');
    assert.equal(createdRow, undefined, 'createMemory must roll back SQLite row insertion on audit failure');

    // 2. Read operation with failing audit telemetry DOES NOT block reading (best-effort)
    const existing = memoryRepo.createMemory({
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: workspaceA.scopeId,
      key: 'read.audit.key',
      content: 'original readable content'
    });

    const read = failingService.getMemoryById(userCaller, existing.id);
    assert.ok(read);
    assert.equal(read.key, 'read.audit.key');

    // 3. updateMemory: Mandatory audit failure MUST throw AND roll back content changes
    assert.throws(
      () => failingService.updateMemory(userCaller, existing.id, {
        content: 'TAMPERED_CONTENT_DURING_AUDIT_FAILURE'
      }),
      (err: unknown) => err instanceof Error && err.message.includes('DISK_FULL')
    );

    const rolledBackUpdate = db.prepare('SELECT content FROM memories WHERE id = ?').get(existing.id) as { content: string };
    assert.equal(
      rolledBackUpdate.content,
      'original readable content',
      'updateMemory must roll back content mutation on audit failure'
    );

    // 4. archiveMemory: Mandatory audit failure MUST throw AND roll back status transition
    assert.throws(
      () => failingService.archiveMemory(userCaller, existing.id),
      (err: unknown) => err instanceof Error && err.message.includes('DISK_FULL')
    );

    const rolledBackArchive = db.prepare('SELECT status FROM memories WHERE id = ?').get(existing.id) as { status: string };
    assert.equal(
      rolledBackArchive.status,
      'ACTIVE',
      'archiveMemory must roll back status change on audit failure'
    );

    // 5. deleteMemory: Mandatory audit failure MUST throw AND roll back row deletion
    assert.throws(
      () => failingService.deleteMemory(userCaller, existing.id),
      (err: unknown) => err instanceof Error && err.message.includes('DISK_FULL')
    );

    const retainedRow = db.prepare('SELECT id FROM memories WHERE id = ?').get(existing.id);
    assert.ok(retainedRow, 'deleteMemory must roll back row deletion on audit failure');

    // 6. decideProposal: Mandatory audit failure MUST throw AND roll back decision
    const pendingProposal = memoryRepo.createMemory({
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: workspaceA.scopeId,
      key: 'pending.audit.proposal',
      content: 'proposal text',
      status: 'PENDING_APPROVAL'
    });

    assert.throws(
      () => failingService.decideProposal(userCaller, {
        memoryId: pendingProposal.id,
        decision: 'APPROVED'
      }),
      (err: unknown) => err instanceof Error && err.message.includes('DISK_FULL')
    );

    const rolledBackProposal = db.prepare('SELECT status FROM memories WHERE id = ?').get(pendingProposal.id) as { status: string };
    assert.equal(
      rolledBackProposal.status,
      'PENDING_APPROVAL',
      'decideProposal must roll back approval status change on audit failure'
    );
  } finally {
    db.close();
  }
});

test('MemoryService - Enforces shared DatabaseManager constructor invariant across repositories', () => {
  const db1 = new DatabaseManager(':memory:');
  const db2 = new DatabaseManager(':memory:');

  try {
    const memoryRepo = new MemoryRepository(db1);
    const auditRepoDiffDb = new AuditRepository(db2);
    const taskRepoDiffDb = new TaskRepository(db2);

    // 1. AuditRepository using different DatabaseManager is rejected
    assert.throws(
      () => new MemoryService({
        memoryRepo,
        auditRepo: auditRepoDiffDb
      }),
      (err: unknown) => {
        assert.ok(err instanceof ValidationError);
        assert.ok(err.message.includes('exact same DatabaseManager instance to guarantee transactional atomicity'));
        return true;
      }
    );

    // 2. TaskRepository using different DatabaseManager is rejected
    assert.throws(
      () => new MemoryService({
        memoryRepo,
        taskRepo: taskRepoDiffDb
      }),
      (err: unknown) => {
        assert.ok(err instanceof ValidationError);
        assert.ok(err.message.includes('MemoryRepository and TaskRepository must share the exact same DatabaseManager instance'));
        return true;
      }
    );
  } finally {
    db1.close();
    db2.close();
  }
});

test('MemoryService - Guarantees two-way atomicity: no orphaned audit event when memory transaction fails after audit append', () => {
  const db = new DatabaseManager(':memory:');
  const taskRepo = new TaskRepository(db);
  const auditRepo = new AuditRepository(db);
  const memoryRepo = new MemoryRepository(db);
  const workspaceA: ScopeIdentifier = { scopeType: 'WORKSPACE', scopeId: 'ws-alpha' };

  const hostAuthority = new HostMemoryAuthority({
    taskRepo,
    identityProvider: {
      authenticate: () => ({
        principalId: 'admin-user',
        role: 'ADMIN',
        permittedScopes: [workspaceA]
      })
    }
  });

  const task = hostAuthority.createTask(taskRepo, {
    goal: 'Two-way atomicity verification task',
    scope: workspaceA
  });

  const adminCaller = hostAuthority.authorizer.authorizeUser({
    credentials: 'admin-token',
    requestedScope: workspaceA,
    taskId: task.id
  });

  // Construct MemoryService with hook that simulates a failure immediately after audit append
  const failingPostAuditService = new MemoryService({
    memoryRepo,
    auditRepo,
    taskRepo,
    authorizer: hostAuthority.authorizer,
    _testPostAuditHook: () => {
      throw new Error('CRASH_AFTER_AUDIT_APPEND: database transaction must roll back both memory and audit events');
    }
  });

  try {
    assert.throws(
      () => failingPostAuditService.createMemory(adminCaller, {
        category: 'PROJECT_FACT',
        scopeType: 'WORKSPACE',
        scopeId: workspaceA.scopeId,
        key: 'two.way.atomic.key',
        content: 'atomic payload'
      }),
      (err: unknown) => err instanceof Error && err.message.includes('CRASH_AFTER_AUDIT_APPEND')
    );

    // 1. Verify memory row is rolled back
    const memRow = db.prepare('SELECT * FROM memories WHERE key = ?').get('two.way.atomic.key');
    assert.equal(memRow, undefined, 'Memory row must not exist in database');

    // 2. ATOMICITY VERIFICATION: Verify NO orphaned audit event was left committed
    const auditRows = db.prepare('SELECT * FROM audit_events WHERE task_id = ?').all(task.id);
    assert.equal(
      auditRows.length,
      0,
      'Orphaned audit event detected! Audit event was not rolled back when memory transaction failed.'
    );
  } finally {
    db.close();
  }
});

test('MemoryService - Hard deletion physically erases content and nulls injection foreign keys', () => {
  const { db, hostAuthority, authorizer, memoryService, taskRepo, workspaceA } = setupServiceTest();

  try {
    const task = hostAuthority.createTask(taskRepo, {
      goal: 'Secret processing task',
      scope: workspaceA
    });

    const userCaller = authorizer.authorizeUser({
      credentials: 'token-admin-alpha',
      requestedScope: workspaceA,
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
  const { db, hostAuthority, authorizer, memoryService, taskRepo, auditRepo, workspaceA } = setupServiceTest();

  try {
    const task = hostAuthority.createTask(taskRepo, {
      goal: 'Comprehensive privacy audit task',
      scope: workspaceA
    });

    const sensitiveUserSecret = 'TOP_SECRET_USER_PASSWORD_ALPHA_BRAVO';
    const sensitiveAgentSecret = 'PROPRIETARY_MODEL_WEIGHT_SECRET_CHARLIE';

    const userCaller = authorizer.authorizeUser({
      credentials: 'token-admin-alpha',
      requestedScope: workspaceA,
      taskId: task.id
    });

    const agentCaller = authorizer.authorizeAgent({
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

test('MemoryAuthorizer - Untrusted caller cannot obtain ADMIN permissions, impersonate a user, mint system authority, or access unauthorized workspaces', () => {
  const db = new DatabaseManager(':memory:');
  const taskRepo = new TaskRepository(db);
  const workspaceA: ScopeIdentifier = { scopeType: 'WORKSPACE', scopeId: 'ws-alpha' };
  const workspaceB: ScopeIdentifier = { scopeType: 'WORKSPACE', scopeId: 'ws-beta' };

  // 1. Fail closed when identity provider is missing
  const authorizerWithoutIdP = new MemoryAuthorizer({ taskRepo });
  assert.throws(
    () => authorizerWithoutIdP.authorizeUser({ credentials: 'any-token' }),
    (err: unknown) => {
      assert.ok(err instanceof SecurityViolationError);
      assert.equal(err.violationType, 'MISSING_IDENTITY_INTEGRATION');
      return true;
    }
  );

  const testIdP: TrustedIdentityProvider = {
    authenticate(credentials: unknown): AuthenticatedPrincipal | null {
      if (credentials === 'viewer-token') {
        return {
          principalId: 'viewer-alice',
          role: 'VIEWER',
          permittedScopes: [workspaceA]
        };
      }
      if (credentials === 'member-token') {
        return {
          principalId: 'member-bob',
          role: 'MEMBER',
          permittedScopes: [workspaceA]
        };
      }
      return null;
    }
  };

  const hostAuthority = new HostMemoryAuthority({ taskRepo, identityProvider: testIdP });
  const authorizer = hostAuthority.authorizer;

  const taskA = hostAuthority.createTask(taskRepo, {
    goal: 'Test task',
    scope: workspaceA
  });

  try {
    // 2. Untrusted caller CANNOT obtain ADMIN permissions by passing { role: 'ADMIN' }
    const viewerContext = authorizer.authorizeUser({
      credentials: 'viewer-token',
      requestedScope: workspaceA,
      ...({ role: 'ADMIN' } as any)
    });
    assert.equal(viewerContext.actor, 'USER');
    const viewerPerms = new Set(viewerContext.permissions);
    assert.ok(viewerPerms.has('READ'));
    assert.equal(viewerPerms.has('WRITE'), false, 'VIEWER must not receive WRITE permission');
    assert.equal(viewerPerms.has('DELETE'), false, 'VIEWER must not receive DELETE permission');
    assert.equal(viewerPerms.has('APPROVE'), false, 'VIEWER must not receive APPROVE permission');

    // 3. Untrusted caller CANNOT impersonate another user by passing { userId: 'admin-alice' }
    const memberContext = authorizer.authorizeUser({
      credentials: 'member-token',
      requestedScope: workspaceA,
      ...({ userId: 'admin-alice' } as any)
    });
    assert.equal(memberContext.actor, 'USER');
    // Verify context proves member-bob identity, not spoofed admin-alice
    const memberPerms = new Set(memberContext.permissions);
    assert.ok(memberPerms.has('READ'));
    assert.ok(memberPerms.has('WRITE'));
    assert.equal(memberPerms.has('APPROVE'), false, 'MEMBER must not receive APPROVE permission');
    assert.equal(memberPerms.has('DELETE'), false, 'MEMBER must not receive DELETE permission');

    // 4. Untrusted caller CANNOT mint system authority without a valid HostToken
    assert.throws(
      () => authorizer.authorizeSystem({ scope: workspaceA }),
      (err: unknown) => {
        assert.ok(err instanceof SecurityViolationError);
        assert.equal(err.violationType, 'HOST_TOKEN_REQUIRED');
        return true;
      }
    );

    // Passing a fake/handcrafted host token is rejected
    assert.throws(
      () => authorizer.authorizeSystem({ scope: workspaceA }, {} as any),
      (err: unknown) => {
        assert.ok(err instanceof SecurityViolationError);
        assert.equal(err.violationType, 'HOST_TOKEN_REQUIRED');
        return true;
      }
    );

    // Internal _authorizeSystem with fake token is also rejected
    assert.throws(
      () => (authorizer as any)._authorizeSystem({ scope: workspaceA }, {} as any),
      (err: unknown) => {
        assert.ok(err instanceof SecurityViolationError);
        assert.equal(err.violationType, 'HOST_TOKEN_REQUIRED');
        return true;
      }
    );

    // 5. Untrusted caller CANNOT create a task without a valid HostToken
    assert.throws(
      () => authorizer.createTask(taskRepo, { goal: 'unauthorized task', scope: workspaceA }),
      (err: unknown) => {
        assert.ok(err instanceof SecurityViolationError);
        assert.equal(err.violationType, 'HOST_TOKEN_REQUIRED');
        return true;
      }
    );

    // Untrusted caller CANNOT attest a task scope without a valid HostToken
    assert.throws(
      () => authorizer.attestTaskScope('some-task-id', workspaceA),
      (err: unknown) => {
        assert.ok(err instanceof SecurityViolationError);
        assert.equal(err.violationType, 'HOST_TOKEN_REQUIRED');
        return true;
      }
    );

    // 6. Authenticated user CANNOT access an unauthorized workspace
    assert.throws(
      () => authorizer.authorizeUser({
        credentials: 'member-token',
        requestedScope: workspaceB // Bob is only permitted for workspaceA
      }),
      (err: unknown) => {
        assert.ok(err instanceof SecurityViolationError);
        assert.equal(err.violationType, 'UNAUTHORIZED_WORKSPACE');
        return true;
      }
    );

    // 7. Invalid/unrecognized credentials fail closed
    assert.throws(
      () => authorizer.authorizeUser({ credentials: 'invalid-or-expired-token' }),
      (err: unknown) => {
        assert.ok(err instanceof SecurityViolationError);
        assert.equal(err.violationType, 'UNAUTHENTICATED');
        return true;
      }
    );

    // 8. Missing credentials fail closed
    assert.throws(
      () => authorizer.authorizeUser({}),
      (err: unknown) => {
        assert.ok(err instanceof SecurityViolationError);
        assert.equal(err.violationType, 'UNAUTHENTICATED');
        return true;
      }
    );

    // 9. Automated agent permissions are permanently locked to READ and WRITE (never APPROVE or DELETE)
    const agentContext = authorizer.authorizeAgent({ taskId: taskA.id });
    assert.equal(agentContext.actor, 'AGENT');
    assert.equal(agentContext.scope.scopeType, 'WORKSPACE');
    assert.equal(agentContext.scope.scopeId, 'ws-alpha');
    const agentPerms = new Set(agentContext.permissions);
    assert.ok(agentPerms.has('READ'));
    assert.ok(agentPerms.has('WRITE'));
    assert.equal(agentPerms.has('APPROVE'), false);
    assert.equal(agentPerms.has('DELETE'), false);
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
