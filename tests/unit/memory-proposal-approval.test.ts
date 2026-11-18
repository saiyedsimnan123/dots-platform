/**
 * Next-Generation Dots AI Platform - Atomic Proposal Conflict Resolution Unit Tests
 * Phase 4D.3C: Atomic Knowledge Proposal Approval & Conflict Resolution
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseManager } from '../../src/storage/db.ts';
import { TaskRepository } from '../../src/storage/task-repository.ts';
import { AuditRepository } from '../../src/storage/audit-repository.ts';
import { MemoryRepository } from '../../src/storage/memory-repository.ts';
import { EmbeddingJobRepository } from '../../src/storage/embedding-job-repository.ts';
import { MemoryEmbeddingRepository } from '../../src/storage/memory-embedding-repository.ts';
import { HostMemoryAuthority } from '../../src/security/host-authority.ts';
import { MemoryService } from '../../src/memory/memory-service.ts';
import {
  ValidationError,
  MemoryNotFoundError,
  MemoryConflictError,
  MemoryScopeViolationError,
  SecurityViolationError
} from '../../src/domain/errors.ts';
import type { ScopeIdentifier, CallerContext, ProposalDecision } from '../../src/domain/types.ts';

function setupProposalTestEnv(options: { _testPostAuditHook?: () => void } = {}) {
  const db = new DatabaseManager(':memory:');
  const taskRepo = new TaskRepository(db);
  const auditRepo = new AuditRepository(db);
  const memoryRepo = new MemoryRepository(db);
  const embeddingJobRepo = new EmbeddingJobRepository(db);
  const embeddingRepo = new MemoryEmbeddingRepository(db);

  const scopeAlpha: ScopeIdentifier = { scopeType: 'WORKSPACE', scopeId: 'ws-alpha' };
  const scopeBeta: ScopeIdentifier = { scopeType: 'WORKSPACE', scopeId: 'ws-beta' };
  const scopeGlobal: ScopeIdentifier = { scopeType: 'GLOBAL', scopeId: 'default' };

  const identityProvider = {
    authenticate(credentials: unknown) {
      if (typeof credentials !== 'string') return null;
      if (credentials === 'token-admin-alpha') {
        return {
          principalId: 'admin-alpha',
          role: 'ADMIN' as const,
          permittedScopes: [scopeAlpha, scopeGlobal]
        };
      }
      if (credentials === 'token-user-read-alpha') {
        return {
          principalId: 'user-read-alpha',
          role: 'MEMBER' as const,
          permissions: ['READ'] as const,
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
    embeddingJobRepo,
    embeddingRepo,
    _testPostAuditHook: options._testPostAuditHook
  });

  const adminAlpha = authorizer.authorizeUser({ credentials: 'token-admin-alpha', requestedScope: scopeAlpha });
  const adminBeta = authorizer.authorizeUser({ credentials: 'token-admin-beta', requestedScope: scopeBeta });
  const readOnlyAlpha = authorizer.authorizeUser({ credentials: 'token-user-read-alpha', requestedScope: scopeAlpha });

  const taskAlpha = hostAuthority.createTask(taskRepo, {
    id: 'task-alpha-1',
    goal: 'Alpha test task',
    scope: scopeAlpha
  });
  const agentAlpha = authorizer.authorizeAgent({ taskId: taskAlpha.id });

  return {
    db,
    taskRepo,
    auditRepo,
    memoryRepo,
    embeddingJobRepo,
    embeddingRepo,
    hostAuthority,
    authorizer,
    memoryService,
    scopeAlpha,
    scopeBeta,
    scopeGlobal,
    adminAlpha,
    adminBeta,
    readOnlyAlpha,
    taskAlpha,
    agentAlpha
  };
}

// ============================================================================
// 1. Approving a proposal with no conflict
// ============================================================================
test('1. Approving a proposal with no conflict (APPROVE_NEW and APPROVED)', () => {
  const env = setupProposalTestEnv();
  try {
    // 1A. Test APPROVE_NEW
    const prop1 = env.memoryService.createMemory(env.agentAlpha, {
      key: 'service.timeout',
      content: 'Default HTTP timeout is 5000ms',
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: env.scopeAlpha.scopeId
    });
    assert.equal(prop1.status, 'PENDING_APPROVAL');

    const approved1 = env.memoryService.decideProposal(env.adminAlpha, {
      memoryId: prop1.id,
      decision: 'APPROVE_NEW'
    });
    assert.equal(approved1.status, 'ACTIVE');
    assert.equal(approved1.version, 1);
    assert.equal(approved1.supersedesId, null);
    assert.equal(approved1.supersededBy, null);

    // Verify embedding job was enqueued
    const jobs1 = env.embeddingJobRepo.listJobs({ memoryId: prop1.id });
    assert.equal(jobs1.length, 1);
    assert.equal(jobs1[0].status, 'PENDING');

    // Verify audit event
    const auditRows = env.db.prepare(
      'SELECT * FROM audit_events WHERE event_type = ? AND details_json LIKE ?'
    ).all('MEMORY_PROPOSAL_DECIDED', `%"${prop1.id}"%`) as Array<{ details_json: string }>;
    assert.equal(auditRows.length, 1);
    const details1 = JSON.parse(auditRows[0].details_json);
    assert.equal(details1.decision, 'APPROVE_NEW');
    assert.equal(details1.newStatus, 'ACTIVE');
    assert.equal(details1.previousStatus, 'PENDING_APPROVAL');

    // 1B. Test legacy APPROVED (backward compatibility)
    const prop2 = env.memoryService.createMemory(env.agentAlpha, {
      key: 'service.retry_count',
      content: 'Default retry count is 3',
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: env.scopeAlpha.scopeId
    });
    const approved2 = env.memoryService.decideProposal(env.adminAlpha, {
      memoryId: prop2.id,
      decision: 'APPROVED'
    });
    assert.equal(approved2.status, 'ACTIVE');
    assert.equal(approved2.version, 1);

    // 1C. Test REJECT and REJECTED
    const prop3 = env.memoryService.createMemory(env.agentAlpha, {
      key: 'service.deprecated_flag',
      content: 'Deprecated flag setting',
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: env.scopeAlpha.scopeId
    });
    const rejected3 = env.memoryService.decideProposal(env.adminAlpha, {
      memoryId: prop3.id,
      decision: 'REJECT'
    });
    assert.equal(rejected3.status, 'ARCHIVED');

    const prop4 = env.memoryService.createMemory(env.agentAlpha, {
      key: 'service.deprecated_flag_2',
      content: 'Another deprecated flag',
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: env.scopeAlpha.scopeId
    });
    const rejected4 = env.memoryService.decideProposal(env.adminAlpha, {
      memoryId: prop4.id,
      decision: 'REJECTED'
    });
    assert.equal(rejected4.status, 'ARCHIVED');
  } finally {
    env.db.close();
  }
});

// ============================================================================
// 2. Rejecting a conflicting proposal using APPROVE_NEW
// ============================================================================
test('2. Rejecting a conflicting proposal using APPROVE_NEW and APPROVED with MemoryConflictError', () => {
  const env = setupProposalTestEnv();
  try {
    // 1. Create an active memory
    const active = env.memoryService.createMemory(env.adminAlpha, {
      key: 'cache.ttl',
      content: 'Cache TTL is 60 seconds',
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: env.scopeAlpha.scopeId
    });
    assert.equal(active.status, 'ACTIVE');

    // 2. Agent proposes an update for the same key
    const proposal = env.memoryService.createMemory(env.agentAlpha, {
      key: 'cache.ttl',
      content: 'Cache TTL should be increased to 300 seconds',
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: env.scopeAlpha.scopeId
    });
    assert.equal(proposal.status, 'PENDING_APPROVAL');

    // 3. Attempting APPROVE_NEW must throw MemoryConflictError
    assert.throws(
      () => env.memoryService.decideProposal(env.adminAlpha, {
        memoryId: proposal.id,
        decision: 'APPROVE_NEW'
      }),
      (err: unknown) => {
        assert.ok(err instanceof MemoryConflictError);
        assert.equal(err.key, 'cache.ttl');
        assert.equal(err.scopeType, 'WORKSPACE');
        assert.equal(err.scopeId, env.scopeAlpha.scopeId);
        return true;
      }
    );

    // 4. Attempting legacy APPROVED must also throw MemoryConflictError
    assert.throws(
      () => env.memoryService.decideProposal(env.adminAlpha, {
        memoryId: proposal.id,
        decision: 'APPROVED'
      }),
      (err: unknown) => {
        assert.ok(err instanceof MemoryConflictError);
        return true;
      }
    );

    // 5. Invariant: Neither record is mutated
    const activeAfter = env.memoryService.getMemoryById(env.adminAlpha, active.id);
    assert.equal(activeAfter?.status, 'ACTIVE');
    assert.equal(activeAfter?.version, 1);
    assert.equal(activeAfter?.supersededBy, null);

    const proposalAfter = env.memoryService.getMemoryById(env.adminAlpha, proposal.id);
    assert.equal(proposalAfter?.status, 'PENDING_APPROVAL');
    assert.equal(proposalAfter?.version, 1);
    assert.equal(proposalAfter?.supersedesId, null);

    // Invariant: No embedding job enqueued for the proposal
    const jobs = env.embeddingJobRepo.listJobs({ memoryId: proposal.id });
    assert.equal(jobs.length, 0);

    // Invariant: No MEMORY_PROPOSAL_DECIDED audit event exists
    const audits = env.db.prepare(
      'SELECT * FROM audit_events WHERE event_type = ? AND details_json LIKE ?'
    ).all('MEMORY_PROPOSAL_DECIDED', `%"${proposal.id}"%`);
    assert.equal(audits.length, 0);
  } finally {
    env.db.close();
  }
});

// ============================================================================
// 3. Explicit APPROVE_AND_SUPERSEDE
// ============================================================================
test('3. Explicit APPROVE_AND_SUPERSEDE transitions active memory to SUPERSEDED and proposal to ACTIVE', () => {
  const env = setupProposalTestEnv();
  try {
    // 1. Initial active memory (v1)
    const activeV1 = env.memoryService.createMemory(env.adminAlpha, {
      key: 'database.pool_size',
      content: 'Maximum connection pool size is 20',
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: env.scopeAlpha.scopeId
    });
    assert.equal(activeV1.status, 'ACTIVE');
    assert.equal(activeV1.version, 1);

    // 2. Proposal from agent with same key
    const proposal = env.memoryService.createMemory(env.agentAlpha, {
      key: 'database.pool_size',
      content: 'Maximum connection pool size is 50 for high concurrency',
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: env.scopeAlpha.scopeId
    });
    assert.equal(proposal.status, 'PENDING_APPROVAL');

    // 3. User explicitly approves and supersedes
    const approved = env.memoryService.decideProposal(env.adminAlpha, {
      memoryId: proposal.id,
      decision: 'APPROVE_AND_SUPERSEDE'
    });

    // 4. Verify replacement memory (now ACTIVE, version 2, linked to v1)
    assert.equal(approved.id, proposal.id);
    assert.equal(approved.status, 'ACTIVE');
    assert.equal(approved.version, 2);
    assert.equal(approved.supersedesId, activeV1.id);
    assert.equal(approved.supersededBy, null);

    // 5. Verify previous memory (now SUPERSEDED, linked to proposal)
    const previousAfter = env.memoryService.getMemoryById(env.adminAlpha, activeV1.id);
    assert.ok(previousAfter);
    assert.equal(previousAfter.status, 'SUPERSEDED');
    assert.equal(previousAfter.version, 1);
    assert.equal(previousAfter.supersededBy, approved.id);
    assert.equal(previousAfter.supersedesId, null);

    // 6. Verify lineage chain via getMemoryHistory
    const history = env.memoryRepo.getMemoryHistory('database.pool_size', env.scopeAlpha);
    assert.equal(history.length, 2);
    assert.equal(history[0].id, activeV1.id);
    assert.equal(history[0].status, 'SUPERSEDED');
    assert.equal(history[0].version, 1);
    assert.equal(history[1].id, approved.id);
    assert.equal(history[1].status, 'ACTIVE');
    assert.equal(history[1].version, 2);

    // 7. Verify embedding job enqueued for approved replacement
    const replacementJobs = env.embeddingJobRepo.listJobs({ memoryId: approved.id });
    assert.equal(replacementJobs.length, 1);
    assert.equal(replacementJobs[0].status, 'PENDING');

    // 8. Verify audit event
    const auditRows = env.db.prepare(
      'SELECT * FROM audit_events WHERE event_type = ? AND details_json LIKE ?'
    ).all('MEMORY_PROPOSAL_DECIDED', `%"${approved.id}"%`) as Array<{ details_json: string }>;
    assert.equal(auditRows.length, 1);
    const details = JSON.parse(auditRows[0].details_json);
    assert.equal(details.decision, 'APPROVE_AND_SUPERSEDE');
    assert.equal(details.supersededMemoryId, activeV1.id);
    assert.equal(details.newStatus, 'ACTIVE');
    assert.equal(details.previousStatus, 'PENDING_APPROVAL');
  } finally {
    env.db.close();
  }
});

// ============================================================================
// 4. Correct v1 -> v2 -> v3 proposal evolution
// ============================================================================
test('4. Correct multi-step evolution: v1 -> v2 -> v3 via consecutive proposals', () => {
  const env = setupProposalTestEnv();
  try {
    const key = 'architecture.message_broker';

    // 1. Initial creation (v1)
    const v1 = env.memoryService.createMemory(env.adminAlpha, {
      key,
      content: 'Message broker is RabbitMQ',
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: env.scopeAlpha.scopeId
    });
    assert.equal(v1.version, 1);
    assert.equal(v1.status, 'ACTIVE');

    // 2. Proposal 1 (v1 -> v2)
    const p1 = env.memoryService.createMemory(env.agentAlpha, {
      key,
      content: 'Migrated message broker from RabbitMQ to Kafka for event streaming',
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: env.scopeAlpha.scopeId
    });
    const v2 = env.memoryService.decideProposal(env.adminAlpha, {
      memoryId: p1.id,
      decision: 'APPROVE_AND_SUPERSEDE'
    });
    assert.equal(v2.version, 2);
    assert.equal(v2.status, 'ACTIVE');
    assert.equal(v2.supersedesId, v1.id);

    // 3. Proposal 2 (v2 -> v3)
    const p2 = env.memoryService.createMemory(env.agentAlpha, {
      key,
      content: 'Upgraded message broker to Apache Pulsar for tiered storage and geo-replication',
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: env.scopeAlpha.scopeId
    });
    const v3 = env.memoryService.decideProposal(env.adminAlpha, {
      memoryId: p2.id,
      decision: 'APPROVE_AND_SUPERSEDE'
    });
    assert.equal(v3.version, 3);
    assert.equal(v3.status, 'ACTIVE');
    assert.equal(v3.supersedesId, v2.id);

    // 4. Verify complete history
    const history = env.memoryRepo.getMemoryHistory(key, env.scopeAlpha);
    assert.equal(history.length, 3);

    // v1
    assert.equal(history[0].id, v1.id);
    assert.equal(history[0].version, 1);
    assert.equal(history[0].status, 'SUPERSEDED');
    assert.equal(history[0].supersedesId, null);
    assert.equal(history[0].supersededBy, v2.id);

    // v2
    assert.equal(history[1].id, v2.id);
    assert.equal(history[1].version, 2);
    assert.equal(history[1].status, 'SUPERSEDED');
    assert.equal(history[1].supersedesId, v1.id);
    assert.equal(history[1].supersededBy, v3.id);

    // v3
    assert.equal(history[2].id, v3.id);
    assert.equal(history[2].version, 3);
    assert.equal(history[2].status, 'ACTIVE');
    assert.equal(history[2].supersedesId, v2.id);
    assert.equal(history[2].supersededBy, null);

    // 5. Query active memory returns v3 only
    const active = env.memoryRepo.getMemoryByKey(key, env.scopeAlpha, 'ACTIVE');
    assert.ok(active);
    assert.equal(active.id, v3.id);
    assert.equal(active.version, 3);
  } finally {
    env.db.close();
  }
});

// ============================================================================
// 5. APPROVE_AND_SUPERSEDE when NO active memory exists throws ValidationError
// ============================================================================
test('5. APPROVE_AND_SUPERSEDE when NO active memory exists throws ValidationError', () => {
  const env = setupProposalTestEnv();
  try {
    const proposal = env.memoryService.createMemory(env.agentAlpha, {
      key: 'brand.new.key',
      content: 'Brand new configuration without prior history',
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: env.scopeAlpha.scopeId
    });

    assert.throws(
      () => env.memoryService.decideProposal(env.adminAlpha, {
        memoryId: proposal.id,
        decision: 'APPROVE_AND_SUPERSEDE'
      }),
      (err: unknown) => {
        assert.ok(err instanceof ValidationError);
        assert.ok(err.message.includes('no active memory exists'));
        assert.ok(err.message.includes('APPROVE_NEW'));
        return true;
      }
    );

    // Proposal remains PENDING_APPROVAL
    const inDb = env.memoryService.getMemoryById(env.adminAlpha, proposal.id);
    assert.equal(inDb?.status, 'PENDING_APPROVAL');
  } finally {
    env.db.close();
  }
});

// ============================================================================
// 6. Transaction rollback on injected failure and audit record rollback
// ============================================================================
test('6. Transaction rollback: injected failure rolls back memory mutations, lineage, and audit events', () => {
  let shouldFail = false;
  const env = setupProposalTestEnv({
    _testPostAuditHook: () => {
      if (shouldFail) {
        throw new Error('SIMULATED_PROPOSAL_APPROVAL_CRASH');
      }
    }
  });

  try {
    const key = 'rollback.test.key';

    // 1. Create active v1
    const v1 = env.memoryService.createMemory(env.adminAlpha, {
      key,
      content: 'Original content v1',
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: env.scopeAlpha.scopeId
    });
    assert.equal(v1.status, 'ACTIVE');

    // 2. Submit proposal
    const p1 = env.memoryService.createMemory(env.agentAlpha, {
      key,
      content: 'Replacement content proposed',
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: env.scopeAlpha.scopeId
    });
    assert.equal(p1.status, 'PENDING_APPROVAL');

    // 3. Trigger simulated failure during APPROVE_AND_SUPERSEDE
    shouldFail = true;

    assert.throws(
      () => env.memoryService.decideProposal(env.adminAlpha, {
        memoryId: p1.id,
        decision: 'APPROVE_AND_SUPERSEDE'
      }),
      (err: unknown) => err instanceof Error && err.message.includes('SIMULATED_PROPOSAL_APPROVAL_CRASH')
    );

    // 4. Verify v1 remains ACTIVE, superseded_by remains null
    const v1After = env.memoryService.getMemoryById(env.adminAlpha, v1.id);
    assert.ok(v1After);
    assert.equal(v1After.status, 'ACTIVE', 'v1 must remain ACTIVE after rollback');
    assert.equal(v1After.supersededBy, null, 'v1.supersededBy must remain null after rollback');

    // 5. Verify proposal remains PENDING_APPROVAL, supersedes_id remains null, version remains 1
    const p1After = env.memoryService.getMemoryById(env.adminAlpha, p1.id);
    assert.ok(p1After);
    assert.equal(p1After.status, 'PENDING_APPROVAL', 'Proposal must remain PENDING_APPROVAL after rollback');
    assert.equal(p1After.supersedesId, null, 'Proposal.supersedesId must remain null after rollback');
    assert.equal(p1After.version, 1, 'Proposal.version must remain 1 after rollback');

    // 6. Verify audit event for MEMORY_PROPOSAL_DECIDED was rolled back
    const decidedAudits = env.db.prepare(
      'SELECT * FROM audit_events WHERE event_type = ? AND details_json LIKE ?'
    ).all('MEMORY_PROPOSAL_DECIDED', `%"${p1.id}"%`);
    assert.equal(decidedAudits.length, 0, 'Audit event must be rolled back');

    // 7. Verify no embedding job was enqueued for p1
    const jobs = env.embeddingJobRepo.listJobs({ memoryId: p1.id });
    assert.equal(jobs.length, 0, 'Embedding jobs must be rolled back');
  } finally {
    env.db.close();
  }
});

// ============================================================================
// 7. Embedding job consistency on supersession and rejection
// ============================================================================
test('7. Embedding job consistency: cancels pending jobs for superseded memory, deletes embeddings on reject', () => {
  const env = setupProposalTestEnv();
  try {
    const key = 'embedding.test.key';

    // 1. Create active v1
    const v1 = env.memoryService.createMemory(env.adminAlpha, {
      key,
      content: 'Embedding content v1',
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: env.scopeAlpha.scopeId
    });

    // Check that job was created for v1
    const v1Jobs = env.embeddingJobRepo.listJobs({ memoryId: v1.id });
    assert.equal(v1Jobs.length, 1);
    assert.equal(v1Jobs[0].status, 'PENDING');

    // Insert mock embedding for v1
    env.embeddingRepo.insertEmbedding({
      memoryId: v1.id,
      modelId: 'default',
      modelRevision: 'main',
      embedding: new Float32Array([1, 0, 0]),
      dimensions: 3
    });
    assert.ok(env.embeddingRepo.getEmbedding(v1.id, 'default', 'main'));

    // 2. Submit proposal
    const p1 = env.memoryService.createMemory(env.agentAlpha, {
      key,
      content: 'Embedding content v2 replacement',
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: env.scopeAlpha.scopeId
    });

    // 3. Approve and supersede
    env.memoryService.decideProposal(env.adminAlpha, {
      memoryId: p1.id,
      decision: 'APPROVE_AND_SUPERSEDE'
    });

    // Invariant: v1 pending jobs are cancelled
    const v1JobsAfter = env.embeddingJobRepo.listJobs({ memoryId: v1.id });
    assert.equal(v1JobsAfter[0].status, 'CANCELLED');

    // Invariant: v1 embeddings are deleted
    assert.equal(env.embeddingRepo.getEmbedding(v1.id, 'default', 'main'), null);

    // Invariant: p1 has a pending embedding job
    const p1Jobs = env.embeddingJobRepo.listJobs({ memoryId: p1.id });
    assert.equal(p1Jobs.length, 1);
    assert.equal(p1Jobs[0].status, 'PENDING');

    // 4. Submit proposal p2, then reject it
    const p2 = env.memoryService.createMemory(env.agentAlpha, {
      key,
      content: 'Embedding content v3 draft rejected',
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: env.scopeAlpha.scopeId
    });
    env.memoryService.decideProposal(env.adminAlpha, {
      memoryId: p2.id,
      decision: 'REJECT'
    });

    const p2Jobs = env.embeddingJobRepo.listJobs({ memoryId: p2.id });
    assert.equal(p2Jobs.length, 0);
  } finally {
    env.db.close();
  }
});

// ============================================================================
// 8. Authorization and workspace isolation
// ============================================================================
test('8. Authorization and workspace isolation: agents, unauthorized users, and cross-scope callers are blocked', () => {
  const env = setupProposalTestEnv();
  try {
    const proposal = env.memoryService.createMemory(env.agentAlpha, {
      key: 'auth.test.key',
      content: 'Restricted proposal content',
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: env.scopeAlpha.scopeId
    });

    // 8A. Agent self-approval attempt throws SecurityViolationError
    assert.throws(
      () => env.memoryService.decideProposal(env.agentAlpha, {
        memoryId: proposal.id,
        decision: 'APPROVE_NEW'
      }),
      (err: unknown) => {
        assert.ok(err instanceof SecurityViolationError);
        assert.equal(err.violationType, 'UNAUTHORIZED_APPROVAL');
        return true;
      }
    );

    // 8B. User without APPROVE permission throws SecurityViolationError
    assert.throws(
      () => env.memoryService.decideProposal(env.readOnlyAlpha, {
        memoryId: proposal.id,
        decision: 'APPROVE_NEW'
      }),
      (err: unknown) => {
        assert.ok(err instanceof SecurityViolationError);
        return true;
      }
    );

    // 8C. User from another workspace (adminBeta) attempting to decide proposal in workspace A throws MemoryScopeViolationError
    assert.throws(
      () => env.memoryService.decideProposal(env.adminBeta, {
        memoryId: proposal.id,
        decision: 'APPROVE_NEW'
      }),
      (err: unknown) => {
        assert.ok(err instanceof MemoryScopeViolationError);
        return true;
      }
    );

    // 8D. Proposal in workspace A cannot supersede an active memory in workspace B
    // Create an active memory in workspace B with the same key
    env.memoryService.createMemory(env.adminBeta, {
      key: 'auth.test.key',
      content: 'Workspace Beta active content',
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: env.scopeBeta.scopeId
    });

    // In workspace A, no active memory exists with this key!
    // Attempting APPROVE_AND_SUPERSEDE on proposal in workspace A must fail with ValidationError
    assert.throws(
      () => env.memoryService.decideProposal(env.adminAlpha, {
        memoryId: proposal.id,
        decision: 'APPROVE_AND_SUPERSEDE'
      }),
      (err: unknown) => {
        assert.ok(err instanceof ValidationError);
        assert.ok(err.message.includes('no active memory exists'));
        return true;
      }
    );

    // But APPROVE_NEW in workspace A succeeds cleanly without interfering with workspace B
    const approvedA = env.memoryService.decideProposal(env.adminAlpha, {
      memoryId: proposal.id,
      decision: 'APPROVE_NEW'
    });
    assert.equal(approvedA.status, 'ACTIVE');

    // Both workspace A and workspace B now have active memories with key 'auth.test.key' (scope isolation!)
    const memA = env.memoryRepo.getMemoryByKey('auth.test.key', env.scopeAlpha, 'ACTIVE');
    const memB = env.memoryRepo.getMemoryByKey('auth.test.key', env.scopeBeta, 'ACTIVE');
    assert.ok(memA);
    assert.ok(memB);
    assert.notEqual(memA.id, memB.id);
  } finally {
    env.db.close();
  }
});

// ============================================================================
// 9. Repeated approval and invalid proposal states
// ============================================================================
test('9. Repeated approval and invalid proposal states are strictly rejected', () => {
  const env = setupProposalTestEnv();
  try {
    const proposal = env.memoryService.createMemory(env.agentAlpha, {
      key: 'state.test.key',
      content: 'State test content',
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: env.scopeAlpha.scopeId
    });

    // First approval succeeds
    const approved = env.memoryService.decideProposal(env.adminAlpha, {
      memoryId: proposal.id,
      decision: 'APPROVE_NEW'
    });
    assert.equal(approved.status, 'ACTIVE');

    // Second approval attempt must fail with ValidationError (status is now ACTIVE, not PENDING_APPROVAL)
    assert.throws(
      () => env.memoryService.decideProposal(env.adminAlpha, {
        memoryId: proposal.id,
        decision: 'APPROVE_NEW'
      }),
      (err: unknown) => {
        assert.ok(err instanceof ValidationError);
        assert.ok(err.message.includes('not pending approval'));
        return true;
      }
    );

    // Archiving a proposal then attempting to decide it must fail
    const prop2 = env.memoryService.createMemory(env.agentAlpha, {
      key: 'state.test.key.2',
      content: 'State test content 2',
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: env.scopeAlpha.scopeId
    });
    env.memoryService.decideProposal(env.adminAlpha, {
      memoryId: prop2.id,
      decision: 'REJECT'
    });

    assert.throws(
      () => env.memoryService.decideProposal(env.adminAlpha, {
        memoryId: prop2.id,
        decision: 'APPROVE_NEW'
      }),
      (err: unknown) => {
        assert.ok(err instanceof ValidationError);
        assert.ok(err.message.includes('not pending approval'));
        return true;
      }
    );
  } finally {
    env.db.close();
  }
});

// ============================================================================
// 10. Decision strategy validation and input hardening
// ============================================================================
test('10. Decision strategy input validation rejects invalid, empty, or defaulted decisions', () => {
  const env = setupProposalTestEnv();
  try {
    const proposal = env.memoryService.createMemory(env.agentAlpha, {
      key: 'validate.strategy.key',
      content: 'Validation content',
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: env.scopeAlpha.scopeId
    });

    // Invalid decision string
    assert.throws(
      () => env.memoryService.decideProposal(env.adminAlpha, {
        memoryId: proposal.id,
        decision: 'AUTO_MERGE' as unknown as ProposalDecision
      }),
      (err: unknown) => {
        assert.ok(err instanceof ValidationError);
        assert.ok(err.message.includes('Invalid proposal decision'));
        return true;
      }
    );

    // Missing decision
    assert.throws(
      () => env.memoryService.decideProposal(env.adminAlpha, {
        memoryId: proposal.id
      } as unknown as { memoryId: string; decision: ProposalDecision }),
      (err: unknown) => err instanceof ValidationError
    );

    // Missing memoryId
    assert.throws(
      () => env.memoryService.decideProposal(env.adminAlpha, {
        memoryId: '',
        decision: 'APPROVE_NEW'
      }),
      (err: unknown) => err instanceof ValidationError
    );

    // Null input
    assert.throws(
      () => env.memoryService.decideProposal(env.adminAlpha, null as unknown as { memoryId: string; decision: ProposalDecision }),
      (err: unknown) => err instanceof ValidationError
    );
  } finally {
    env.db.close();
  }
});

// ============================================================================
// 11. Concurrent approval attempts: two pending proposals with same key
// ============================================================================
test('11. Concurrent approval attempts: two proposals with same key cannot both be approved as new', () => {
  const env = setupProposalTestEnv();
  try {
    const key = 'concurrent.key';

    // Agent submits two proposals with the same key
    const p1 = env.memoryService.createMemory(env.agentAlpha, {
      key,
      content: 'Proposal candidate 1',
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: env.scopeAlpha.scopeId
    });

    const p2 = env.memoryService.createMemory(env.agentAlpha, {
      key,
      content: 'Proposal candidate 2',
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: env.scopeAlpha.scopeId
    });

    assert.equal(p1.status, 'PENDING_APPROVAL');
    assert.equal(p2.status, 'PENDING_APPROVAL');

    // 1. Approve p1 as APPROVE_NEW
    const approved1 = env.memoryService.decideProposal(env.adminAlpha, {
      memoryId: p1.id,
      decision: 'APPROVE_NEW'
    });
    assert.equal(approved1.status, 'ACTIVE');

    // 2. Approving p2 as APPROVE_NEW must now fail with MemoryConflictError because p1 is ACTIVE
    assert.throws(
      () => env.memoryService.decideProposal(env.adminAlpha, {
        memoryId: p2.id,
        decision: 'APPROVE_NEW'
      }),
      (err: unknown) => {
        assert.ok(err instanceof MemoryConflictError);
        assert.equal(err.key, key);
        return true;
      }
    );

    // 3. Instead, p2 can be approved with APPROVE_AND_SUPERSEDE
    const approved2 = env.memoryService.decideProposal(env.adminAlpha, {
      memoryId: p2.id,
      decision: 'APPROVE_AND_SUPERSEDE'
    });
    assert.equal(approved2.status, 'ACTIVE');
    assert.equal(approved2.version, 2);
    assert.equal(approved2.supersedesId, approved1.id);

    // p1 is now SUPERSEDED
    const p1After = env.memoryService.getMemoryById(env.adminAlpha, p1.id);
    assert.equal(p1After?.status, 'SUPERSEDED');
    assert.equal(p1After?.supersededBy, approved2.id);
  } finally {
    env.db.close();
  }
});
