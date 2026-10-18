/**
 * Next-Generation Dots AI Platform - Memory Purge Tests
 * Phase 7.5: Substep 3 - Safe Archived Memory Purge
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseManager } from '../../src/storage/db.ts';
import { TaskRepository } from '../../src/storage/task-repository.ts';
import { AuditRepository } from '../../src/storage/audit-repository.ts';
import { MemoryRepository } from '../../src/storage/memory-repository.ts';
import { MemoryService } from '../../src/memory/memory-service.ts';
import { RelevanceMatcher } from '../../src/memory/relevance-matcher.ts';
import { MemoryContextBuilder } from '../../src/memory/context-builder.ts';
import { HostMemoryAuthority } from '../../src/security/host-authority.ts';
import type {
  ScopeIdentifier,
  CallerContext,
  Memory
} from '../../src/domain/types.ts';
import {
  ValidationError,
  SecurityViolationError,
  MemoryScopeViolationError,
  MemoryNotFoundError
} from '../../src/domain/errors.ts';

function setupTestEnvironment(options: {
  _testPostAuditHook?: () => void;
  _testMidPurgeHook?: (deletedCount: number) => void;
  _testPostPurgeAuditHook?: () => void;
} = {}) {
  const db = new DatabaseManager(':memory:');
  const taskRepo = new TaskRepository(db);
  const auditRepo = new AuditRepository(db);
  const memoryRepo = new MemoryRepository(db);

  const scopeAlpha: ScopeIdentifier = { scopeType: 'WORKSPACE', scopeId: 'ws-alpha' };
  const scopeBeta: ScopeIdentifier = { scopeType: 'WORKSPACE', scopeId: 'ws-beta' };
  const scopeGlobal: ScopeIdentifier = { scopeType: 'GLOBAL', scopeId: 'default' };

  const identityProvider = {
    authenticate(credentials: unknown) {
      if (typeof credentials !== 'string') return null;
      if (credentials === 'token-admin-alpha') {
        return {
          principalId: 'admin-alpha',
          role: 'ADMIN' as const, // READ, WRITE, DELETE, APPROVE
          permittedScopes: [scopeAlpha, scopeGlobal]
        };
      }
      if (credentials === 'token-member-alpha') {
        return {
          principalId: 'member-alpha',
          role: 'MEMBER' as const, // READ, WRITE
          permittedScopes: [scopeAlpha]
        };
      }
      if (credentials === 'token-readonly-alpha') {
        return {
          principalId: 'ro-alpha',
          role: 'VIEWER' as const, // READ
          permittedScopes: [scopeAlpha]
        };
      }
      if (credentials === 'token-admin-beta') {
        return {
          principalId: 'admin-beta',
          role: 'ADMIN' as const,
          permittedScopes: [scopeBeta]
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

  const memoryService = new MemoryService({
    memoryRepo,
    auditRepo,
    taskRepo,
    authorizer,
    hostAuthority,
    relevanceMatcher: new RelevanceMatcher(),
    contextBuilder: new MemoryContextBuilder(),
    _testPostAuditHook: options._testPostAuditHook,
    _testMidPurgeHook: options._testMidPurgeHook,
    _testPostPurgeAuditHook: options._testPostPurgeAuditHook
  });

  const adminAlpha = authorizer.authorizeUser({ credentials: 'token-admin-alpha', requestedScope: scopeAlpha });
  const memberAlpha = authorizer.authorizeUser({ credentials: 'token-member-alpha', requestedScope: scopeAlpha });
  const readOnlyAlpha = authorizer.authorizeUser({ credentials: 'token-readonly-alpha', requestedScope: scopeAlpha });
  const adminBeta = authorizer.authorizeUser({ credentials: 'token-admin-beta', requestedScope: scopeBeta });

  return {
    db,
    taskRepo,
    auditRepo,
    memoryRepo,
    hostAuthority,
    authorizer,
    memoryService,
    scopeAlpha,
    scopeBeta,
    scopeGlobal,
    adminAlpha,
    memberAlpha,
    readOnlyAlpha,
    adminBeta
  };
}

/**
 * Helper to seed an archived memory in a specific scope.
 */
function createArchivedMemory(
  env: ReturnType<typeof setupTestEnvironment>,
  caller: CallerContext,
  key: string,
  content: string = 'archived content',
  category: 'PROJECT_FACT' | 'USER_PREFERENCE' | 'LEARNED_PROCEDURE' = 'PROJECT_FACT'
): Memory {
  const mem = env.memoryService.createMemory(caller, {
    key,
    content,
    category,
    scopeType: caller.scope.scopeType,
    scopeId: caller.scope.scopeId
  });
  return env.memoryService.archiveMemory(caller, mem.id);
}

// ============================================================================
// 1. Authorization & Security Boundary Gates
// ============================================================================

test('purgeArchivedMemories - rejects unverified or forged caller context', () => {
  const env = setupTestEnvironment();

  // Completely forged context object
  const forgedCaller: CallerContext = {
    actor: 'USER',
    scope: env.scopeAlpha,
    permissions: ['READ', 'WRITE', 'DELETE', 'APPROVE']
  };

  assert.throws(
    () => env.memoryService.purgeArchivedMemories(forgedCaller, { olderThan: new Date().toISOString() }),
    (err: unknown) => err instanceof SecurityViolationError && err.violationType === 'FORGED_CALLER_CONTEXT'
  );
});

test('purgeArchivedMemories - enforces DELETE permission on caller (MEMBER and VIEWER rejected)', () => {
  const env = setupTestEnvironment();
  const cutoff = new Date().toISOString();

  // MEMBER role has READ + WRITE, lacks DELETE
  assert.throws(
    () => env.memoryService.purgeArchivedMemories(env.memberAlpha, { olderThan: cutoff }),
    (err: unknown) => err instanceof SecurityViolationError && err.violationType === 'INSUFFICIENT_PERMISSIONS'
  );

  // VIEWER role has READ only, lacks DELETE
  assert.throws(
    () => env.memoryService.purgeArchivedMemories(env.readOnlyAlpha, { olderThan: cutoff }),
    (err: unknown) => err instanceof SecurityViolationError && err.violationType === 'INSUFFICIENT_PERMISSIONS'
  );
});

test('purgeArchivedMemories - rejects agent callers from directly purging memories', () => {
  const env = setupTestEnvironment();
  const agentTask = env.hostAuthority.createTask(env.taskRepo, {
    id: 'task-agent-purge',
    goal: 'Agent attempting purge',
    scope: env.scopeAlpha
  });
  const agentCaller = env.authorizer.authorizeAgent({ taskId: agentTask.id });

  assert.throws(
    () => env.memoryService.purgeArchivedMemories(agentCaller, { olderThan: new Date().toISOString() }),
    (err: unknown) => err instanceof SecurityViolationError && err.violationType === 'AGENT_PURGE_RESTRICTED'
  );

  const auditEvents = env.auditRepo.getEventsByTaskId(agentTask.id);
  const deniedEvent = auditEvents.find((e) => e.eventType === 'MEMORY_ACCESS_DENIED');
  assert.ok(deniedEvent, 'Expected MEMORY_ACCESS_DENIED audit event');
  assert.ok(deniedEvent.detailsJson.includes('AGENT_PURGE_DENIED'));
});

// ============================================================================
// 2. Options Validation & Scope Containment
// ============================================================================

test('purgeArchivedMemories - rejects ambiguous options (both or neither memoryIds / olderThan)', () => {
  const env = setupTestEnvironment();

  // Neither provided
  assert.throws(
    () => env.memoryService.purgeArchivedMemories(env.adminAlpha, {} as any),
    (err: unknown) => err instanceof ValidationError && err.message.includes('Deliberate purge required')
  );

  // Both provided
  assert.throws(
    () => env.memoryService.purgeArchivedMemories(env.adminAlpha, {
      memoryIds: ['some-id'],
      olderThan: new Date().toISOString()
    }),
    (err: unknown) => err instanceof ValidationError && err.message.includes('Ambiguous purge options')
  );

  // Non-object options
  assert.throws(
    () => env.memoryService.purgeArchivedMemories(env.adminAlpha, null as any),
    (err: unknown) => err instanceof ValidationError
  );
});

test('purgeArchivedMemories - rejects scope spoofing in options', () => {
  const env = setupTestEnvironment();

  assert.throws(
    () => env.memoryService.purgeArchivedMemories(env.adminAlpha, {
      olderThan: new Date().toISOString(),
      scopeType: 'WORKSPACE',
      scopeId: 'ws-beta' // does not match adminAlpha's ws-alpha
    }),
    (err: unknown) => err instanceof MemoryScopeViolationError
  );
});

// ============================================================================
// 3. Deliberate ID-List Purging & Scope Isolation
// ============================================================================

test('purgeArchivedMemories - cross-scope IDs are rejected with zero partial deletion', () => {
  const env = setupTestEnvironment();

  const alpha1 = createArchivedMemory(env, env.adminAlpha, 'alpha_archived_1');
  const alpha2 = createArchivedMemory(env, env.adminAlpha, 'alpha_archived_2');
  const beta1 = createArchivedMemory(env, env.adminBeta, 'beta_archived_1');

  // Attempt to purge alpha1, beta1 (foreign), and alpha2
  assert.throws(
    () => env.memoryService.purgeArchivedMemories(env.adminAlpha, {
      memoryIds: [alpha1.id, beta1.id, alpha2.id]
    }),
    (err: unknown) => err instanceof MemoryScopeViolationError
  );

  // Invariant: Zero partial deletion. All records must still exist!
  assert.ok(env.memoryRepo.getMemoryById(alpha1.id, env.scopeAlpha), 'alpha1 must not be deleted');
  assert.ok(env.memoryRepo.getMemoryById(alpha2.id, env.scopeAlpha), 'alpha2 must not be deleted');
  assert.ok(env.memoryRepo.getMemoryById(beta1.id, env.scopeBeta), 'beta1 must not be deleted');

  // Audit event for denied access recorded
  const auditEvents = env.auditRepo.getEventsByTaskId('__system_memory__');
  const deniedEvent = auditEvents.find((e) => e.eventType === 'MEMORY_ACCESS_DENIED');
  assert.ok(deniedEvent, 'Expected MEMORY_ACCESS_DENIED audit event');
  assert.ok(deniedEvent.detailsJson.includes('CROSS_SCOPE_PURGE_ATTEMPT'));
});

test('purgeArchivedMemories - ID list: missing ID or non-archived (ACTIVE / PENDING_APPROVAL) status rejected without deletion', () => {
  const env = setupTestEnvironment();

  // 1. Missing ID
  assert.throws(
    () => env.memoryService.purgeArchivedMemories(env.adminAlpha, {
      memoryIds: ['non-existent-memory-id']
    }),
    (err: unknown) => err instanceof MemoryNotFoundError
  );

  // 2. Active memory
  const activeMem = env.memoryService.createMemory(env.adminAlpha, {
    key: 'active_fact',
    content: 'active fact content',
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId
  });

  assert.throws(
    () => env.memoryService.purgeArchivedMemories(env.adminAlpha, {
      memoryIds: [activeMem.id]
    }),
    (err: unknown) => err instanceof ValidationError && err.message.includes('Only records with status \'ARCHIVED\' can be purged')
  );
  assert.ok(env.memoryRepo.getMemoryById(activeMem.id, env.scopeAlpha), 'Active memory must remain intact');

  // 3. Proposal (PENDING_APPROVAL)
  const agentTask = env.hostAuthority.createTask(env.taskRepo, {
    id: 'task-agent-prop',
    goal: 'Agent proposing memory',
    scope: env.scopeAlpha
  });
  const agentCaller = env.authorizer.authorizeAgent({ taskId: agentTask.id });
  const proposalMem = env.memoryService.createMemory(agentCaller, {
    key: 'proposed_fact',
    content: 'proposed content',
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId
  });
  assert.equal(proposalMem.status, 'PENDING_APPROVAL');

  assert.throws(
    () => env.memoryService.purgeArchivedMemories(env.adminAlpha, {
      memoryIds: [proposalMem.id]
    }),
    (err: unknown) => err instanceof ValidationError && err.message.includes('Only records with status \'ARCHIVED\' can be purged')
  );
  assert.ok(env.memoryRepo.getMemoryById(proposalMem.id, env.scopeAlpha), 'Proposal memory must remain intact');
});

// ============================================================================
// 4. Cutoff-Based Purging & Boundary Semantics
// ============================================================================

test('purgeArchivedMemories - cutoff: purges only ARCHIVED records, never ACTIVE or PENDING_APPROVAL', () => {
  const env = setupTestEnvironment();

  // 1. Create an active memory
  const activeMem = env.memoryService.createMemory(env.adminAlpha, {
    key: 'keep_active_key',
    content: 'active memory content',
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId
  });

  // 2. Create an archived memory
  const archivedMem = createArchivedMemory(env, env.adminAlpha, 'purge_archived_key');

  // 3. Create a proposal
  const agentTask = env.hostAuthority.createTask(env.taskRepo, {
    id: 'task-agent-prop-cutoff',
    goal: 'Agent proposal',
    scope: env.scopeAlpha
  });
  const agentCaller = env.authorizer.authorizeAgent({ taskId: agentTask.id });
  const propMem = env.memoryService.createMemory(agentCaller, {
    key: 'keep_prop_key',
    content: 'proposal memory content',
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId
  });

  // Set cutoff into the future to encompass all updated_at timestamps
  const futureCutoff = new Date(Date.now() + 60000).toISOString();

  const result = env.memoryService.purgeArchivedMemories(env.adminAlpha, { olderThan: futureCutoff });

  // Only the 1 archived record should be purged
  assert.equal(result.eligibleCount, 1);
  assert.equal(result.purgedCount, 1);
  assert.equal(result.purgeMode, 'CUTOFF');

  // Verify archived record is permanently gone
  assert.equal(env.memoryRepo.getMemoryById(archivedMem.id, env.scopeAlpha), null);

  // Invariant: ACTIVE and PENDING_APPROVAL records must NOT be purged
  const activeCheck = env.memoryRepo.getMemoryById(activeMem.id, env.scopeAlpha);
  assert.ok(activeCheck);
  assert.equal(activeCheck.status, 'ACTIVE');

  const propCheck = env.memoryRepo.getMemoryById(propMem.id, env.scopeAlpha);
  assert.ok(propCheck);
  assert.equal(propCheck.status, 'PENDING_APPROVAL');
});

test('purgeArchivedMemories - cutoff boundaries and invalid timestamp validation', () => {
  const env = setupTestEnvironment();

  // Invalid timestamps
  assert.throws(
    () => env.memoryService.purgeArchivedMemories(env.adminAlpha, { olderThan: '' }),
    (err: unknown) => err instanceof ValidationError
  );
  assert.throws(
    () => env.memoryService.purgeArchivedMemories(env.adminAlpha, { olderThan: 'not-a-timestamp' }),
    (err: unknown) => err instanceof ValidationError
  );
  assert.throws(
    () => env.memoryService.purgeArchivedMemories(env.adminAlpha, { olderThan: 12345 as any }),
    (err: unknown) => err instanceof ValidationError
  );

  // Timestamp boundary testing:
  // Create 3 archived records directly with distinct updated_at timestamps
  const cutoffTime = '2026-10-15T12:00:00.000Z';
  const beforeTime = '2026-10-15T11:59:59.999Z';
  const exactTime = '2026-10-15T12:00:00.000Z';
  const afterTime = '2026-10-15T12:00:00.001Z';

  const m1 = env.memoryRepo.createMemory({
    key: 'm1_before',
    content: 'c1',
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    status: 'ARCHIVED'
  });
  env.db.prepare('UPDATE memories SET updated_at = ? WHERE id = ?').run(beforeTime, m1.id);

  const m2 = env.memoryRepo.createMemory({
    key: 'm2_exact',
    content: 'c2',
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    status: 'ARCHIVED'
  });
  env.db.prepare('UPDATE memories SET updated_at = ? WHERE id = ?').run(exactTime, m2.id);

  const m3 = env.memoryRepo.createMemory({
    key: 'm3_after',
    content: 'c3',
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    status: 'ARCHIVED'
  });
  env.db.prepare('UPDATE memories SET updated_at = ? WHERE id = ?').run(afterTime, m3.id);

  const result = env.memoryService.purgeArchivedMemories(env.adminAlpha, { olderThan: cutoffTime });

  // Boundary check: m1 (before) and m2 (exact <=) must be purged. m3 (after) must NOT be purged.
  assert.equal(result.eligibleCount, 2);
  assert.equal(result.purgedCount, 2);

  assert.equal(env.memoryRepo.getMemoryById(m1.id, env.scopeAlpha), null, 'm1 (before) must be purged');
  assert.equal(env.memoryRepo.getMemoryById(m2.id, env.scopeAlpha), null, 'm2 (exact boundary) must be purged');
  assert.ok(env.memoryRepo.getMemoryById(m3.id, env.scopeAlpha), 'm3 (after cutoff) must NOT be purged');
});

// ============================================================================
// 5. Dry-Run Semantics
// ============================================================================

test('purgeArchivedMemories - dry run reports eligibility but causes no deletion or mutation audit event', () => {
  const env = setupTestEnvironment();

  const m1 = createArchivedMemory(env, env.adminAlpha, 'dry_run_mem_1');
  const m2 = createArchivedMemory(env, env.adminAlpha, 'dry_run_mem_2');

  // 1. Dry run via ID list
  const dryRunIdsResult = env.memoryService.purgeArchivedMemories(env.adminAlpha, {
    memoryIds: [m1.id, m2.id],
    dryRun: true
  });

  assert.equal(dryRunIdsResult.isDryRun, true);
  assert.equal(dryRunIdsResult.eligibleCount, 2);
  assert.equal(dryRunIdsResult.purgedCount, 0);
  assert.deepEqual(dryRunIdsResult.targetScope, env.scopeAlpha);

  // Verify records are untouched
  assert.ok(env.memoryRepo.getMemoryById(m1.id, env.scopeAlpha));
  assert.ok(env.memoryRepo.getMemoryById(m2.id, env.scopeAlpha));

  // Verify zero MEMORIES_PURGED audit events
  const auditEvents = env.auditRepo.getEventsByTaskId('__system_memory__');
  const purgedEvent = auditEvents.find((e) => e.eventType === 'MEMORIES_PURGED');
  assert.equal(purgedEvent, undefined, 'Dry run must not create MEMORIES_PURGED audit event');

  // 2. Dry run via Cutoff
  const dryRunCutoffResult = env.memoryService.purgeArchivedMemories(env.adminAlpha, {
    olderThan: new Date(Date.now() + 60000).toISOString(),
    dryRun: true
  });

  assert.equal(dryRunCutoffResult.isDryRun, true);
  assert.equal(dryRunCutoffResult.eligibleCount, 2);
  assert.equal(dryRunCutoffResult.purgedCount, 0);

  // Still untouched
  assert.ok(env.memoryRepo.getMemoryById(m1.id, env.scopeAlpha));
  assert.ok(env.memoryRepo.getMemoryById(m2.id, env.scopeAlpha));
});

// ============================================================================
// 6. Permanent Deletion & Provenance Preservation
// ============================================================================

test('purgeArchivedMemories - successful purge deletes eligible archived records permanently', () => {
  const env = setupTestEnvironment();

  const m1 = createArchivedMemory(env, env.adminAlpha, 'permanent_del_1');
  const m2 = createArchivedMemory(env, env.adminAlpha, 'permanent_del_2');

  const result = env.memoryService.purgeArchivedMemories(env.adminAlpha, {
    memoryIds: [m1.id, m2.id]
  });

  assert.equal(result.isDryRun, false);
  assert.equal(result.eligibleCount, 2);
  assert.equal(result.purgedCount, 2);

  // Physically gone from database
  assert.equal(env.memoryRepo.getMemoryById(m1.id, env.scopeAlpha), null);
  assert.equal(env.memoryRepo.getMemoryById(m2.id, env.scopeAlpha), null);
  const rowCheck = env.db.prepare('SELECT COUNT(*) as count FROM memories WHERE id IN (?, ?)').get(m1.id, m2.id) as { count: number };
  assert.equal(rowCheck.count, 0);

  // Audit event recorded
  const auditEvents = env.auditRepo.getEventsByTaskId('__system_memory__');
  const purgedEvent = auditEvents.find((e) => e.eventType === 'MEMORIES_PURGED');
  assert.ok(purgedEvent);
  const details = JSON.parse(purgedEvent.detailsJson);
  assert.equal(details.purgedCount, 2);
  assert.equal(details.scopeType, 'WORKSPACE');
  assert.equal(details.scopeId, 'ws-alpha');
});

test('purgeArchivedMemories - injection provenance rows survive with memory_id set to NULL', () => {
  const env = setupTestEnvironment();

  // Create task with attested scope
  const task = env.hostAuthority.createTask(env.taskRepo, {
    id: 'task-provenance-test',
    goal: 'Provenance preservation test',
    scope: env.scopeAlpha
  });

  // Create active memory and record injection
  const mem = env.memoryService.createMemory(env.adminAlpha, {
    key: 'provenance_mem',
    content: 'provenance content for task',
    category: 'PROJECT_FACT',
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId
  });

  const injection = env.memoryService.recordTaskInjection(env.adminAlpha, {
    taskId: task.id,
    memoryId: mem.id,
    charCount: 100,
    estimatedTokens: 27
  });

  assert.equal(injection.memoryId, mem.id);

  // Archive memory
  env.memoryService.archiveMemory(env.adminAlpha, mem.id);

  // Purge memory
  const purgeResult = env.memoryService.purgeArchivedMemories(env.adminAlpha, {
    memoryIds: [mem.id]
  });
  assert.equal(purgeResult.purgedCount, 1);

  // Verify memory row is physically deleted
  assert.equal(env.memoryRepo.getMemoryById(mem.id, env.scopeAlpha), null);

  // Verify injection row survived with memory_id = NULL
  const injections = env.memoryRepo.getInjectionsByTaskId(task.id);
  assert.equal(injections.length, 1);
  const preservedInjection = injections[0];
  assert.equal(preservedInjection.id, injection.id);
  assert.equal(preservedInjection.taskId, task.id);
  assert.equal(preservedInjection.memoryId, null, 'memory_id must be set to null by SQLite foreign key ON DELETE SET NULL');
  assert.equal(preservedInjection.charCount, 100);
  assert.equal(preservedInjection.estimatedTokens, 27);
  assert.equal(preservedInjection.injectedAt, injection.injectedAt);
});

// ============================================================================
// 7. Atomic Rollback Guarantees
// ============================================================================

test('purgeArchivedMemories - atomicity: failure during a later deletion rolls back earlier deletions', () => {
  // Use _testMidPurgeHook to simulate an unexpected crash or database failure after the first deletion
  const env = setupTestEnvironment({
    _testMidPurgeHook(deletedCount) {
      if (deletedCount === 1) {
        throw new Error('SIMULATED_FAILURE_MID_PURGE: database crash after deleting first item');
      }
    }
  });

  const m1 = createArchivedMemory(env, env.adminAlpha, 'rollback_m1');
  const m2 = createArchivedMemory(env, env.adminAlpha, 'rollback_m2');

  assert.throws(
    () => env.memoryService.purgeArchivedMemories(env.adminAlpha, {
      memoryIds: [m1.id, m2.id]
    }),
    (err: unknown) => err instanceof Error && err.message.includes('SIMULATED_FAILURE_MID_PURGE')
  );

  // Invariant: Because of atomic transaction rollback, m1 must NOT remain deleted! Both m1 and m2 must exist!
  assert.ok(env.memoryRepo.getMemoryById(m1.id, env.scopeAlpha), 'm1 must be restored by rollback');
  assert.ok(env.memoryRepo.getMemoryById(m2.id, env.scopeAlpha), 'm2 must remain intact');

  // Verify no MEMORIES_PURGED audit event was committed
  const auditEvents = env.auditRepo.getEventsByTaskId('__system_memory__');
  assert.equal(auditEvents.find((e) => e.eventType === 'MEMORIES_PURGED'), undefined);
});

test('purgeArchivedMemories - atomicity: failure during the audit write rolls back all deletions', () => {
  // Use _testPostPurgeAuditHook to simulate an audit failure/crash immediately after purge audit write
  const env = setupTestEnvironment({
    _testPostPurgeAuditHook() {
      throw new Error('SIMULATED_FAILURE_AFTER_AUDIT: audit write or post-audit hook failure');
    }
  });

  const m1 = createArchivedMemory(env, env.adminAlpha, 'audit_fail_m1');
  const m2 = createArchivedMemory(env, env.adminAlpha, 'audit_fail_m2');

  assert.throws(
    () => env.memoryService.purgeArchivedMemories(env.adminAlpha, {
      memoryIds: [m1.id, m2.id]
    }),
    (err: unknown) => err instanceof Error && err.message.includes('SIMULATED_FAILURE_AFTER_AUDIT')
  );

  // Invariant: Both memories must still exist!
  assert.ok(env.memoryRepo.getMemoryById(m1.id, env.scopeAlpha), 'm1 must be restored by rollback');
  assert.ok(env.memoryRepo.getMemoryById(m2.id, env.scopeAlpha), 'm2 must be restored by rollback');

  // Verify no MEMORIES_PURGED audit event committed
  const auditEvents = env.auditRepo.getEventsByTaskId('__system_memory__');
  assert.equal(auditEvents.find((e) => e.eventType === 'MEMORIES_PURGED'), undefined);
});

// ============================================================================
// 8. Privacy Guarantees
// ============================================================================

test('purgeArchivedMemories - audit and result privacy: zero keys or memory content in result and audit details', () => {
  const env = setupTestEnvironment();

  const secretKey = 'top_secret_purge_key_999';
  const secretContent = 'super_sensitive_financial_record_content_888';

  const mem = createArchivedMemory(env, env.adminAlpha, secretKey, secretContent);

  const result = env.memoryService.purgeArchivedMemories(env.adminAlpha, {
    memoryIds: [mem.id]
  });

  // 1. Result DTO privacy check
  const resultJson = JSON.stringify(result);
  assert.equal(resultJson.includes(secretKey), false, 'Result DTO must not expose memory key');
  assert.equal(resultJson.includes(secretContent), false, 'Result DTO must not expose memory content');
  assert.equal('keys' in (result as any), false);
  assert.equal('content' in (result as any), false);
  assert.equal(result.purgedCount, 1);

  // 2. Audit Event privacy check
  const auditEvents = env.auditRepo.getEventsByTaskId('__system_memory__');
  const purgeEvent = auditEvents.find((e) => e.eventType === 'MEMORIES_PURGED');
  assert.ok(purgeEvent);

  assert.equal(purgeEvent.detailsJson.includes(secretKey), false, 'Audit event must not expose memory key');
  assert.equal(purgeEvent.detailsJson.includes(secretContent), false, 'Audit event must not expose memory content');

  const details = JSON.parse(purgeEvent.detailsJson);
  assert.equal('key' in details, false);
  assert.equal('content' in details, false);
  assert.equal(details.purgedCount, 1);
  assert.equal(details.scopeType, 'WORKSPACE');
  assert.equal(details.scopeId, 'ws-alpha');
});

// ============================================================================
// 9. Batch Limits & Empty Selections
// ============================================================================

test('purgeArchivedMemories - batch limits and empty selections behave safely', () => {
  const env = setupTestEnvironment();

  // 1. Empty ID list
  const emptyIdsResult = env.memoryService.purgeArchivedMemories(env.adminAlpha, {
    memoryIds: []
  });
  assert.equal(emptyIdsResult.eligibleCount, 0);
  assert.equal(emptyIdsResult.purgedCount, 0);

  // 2. Cutoff with no matching records
  const ancientCutoffResult = env.memoryService.purgeArchivedMemories(env.adminAlpha, {
    olderThan: '1970-01-01T00:00:00.000Z'
  });
  assert.equal(ancientCutoffResult.eligibleCount, 0);
  assert.equal(ancientCutoffResult.purgedCount, 0);

  // 3. Batch limits with Cutoff
  for (let i = 1; i <= 5; i++) {
    createArchivedMemory(env, env.adminAlpha, `batch_mem_${i}`);
  }

  const futureCutoff = new Date(Date.now() + 60000).toISOString();

  // Total eligible is 5, but maxBatchSize is 2
  const batchResult = env.memoryService.purgeArchivedMemories(env.adminAlpha, {
    olderThan: futureCutoff,
    maxBatchSize: 2
  });

  assert.equal(batchResult.eligibleCount, 5, 'Total eligible should be 5');
  assert.equal(batchResult.purgedCount, 2, 'Only 2 items purged due to maxBatchSize');
  assert.equal(batchResult.batchSizeLimit, 2);

  // Remaining 3 records must still be in database
  const remaining = env.memoryRepo.listMemories({
    scopeType: env.scopeAlpha.scopeType,
    scopeId: env.scopeAlpha.scopeId,
    status: 'ARCHIVED'
  });
  assert.equal(remaining.length, 3, '3 archived records must remain');

  // 4. Batch limits with ID list (rejects exceeding batch size to prevent accidental partial deletion)
  const remainingIds = remaining.map((r) => r.id);
  assert.throws(
    () => env.memoryService.purgeArchivedMemories(env.adminAlpha, {
      memoryIds: remainingIds,
      maxBatchSize: 2 // 3 IDs provided but max is 2
    }),
    (err: unknown) => err instanceof ValidationError && err.message.includes('exceeds maximum batch size limit')
  );

  // 5. Invalid maxBatchSize values
  assert.throws(
    () => env.memoryService.purgeArchivedMemories(env.adminAlpha, { olderThan: futureCutoff, maxBatchSize: 0 }),
    (err: unknown) => err instanceof ValidationError
  );
  assert.throws(
    () => env.memoryService.purgeArchivedMemories(env.adminAlpha, { olderThan: futureCutoff, maxBatchSize: -5 }),
    (err: unknown) => err instanceof ValidationError
  );
  assert.throws(
    () => env.memoryService.purgeArchivedMemories(env.adminAlpha, { olderThan: futureCutoff, maxBatchSize: 2.5 }),
    (err: unknown) => err instanceof ValidationError
  );
});
