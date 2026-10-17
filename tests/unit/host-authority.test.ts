/**
 * Next-Generation Dots AI Platform - Host Authorization Boundary Regression Tests
 * Phase 7.3: Trusted Host Boundary Hardening
 * 
 * Verifies:
 * 1. Public API boundary: src/index.ts does NOT export HostMemoryAuthority, HostToken,
 *    createHostAuthorizerPair, or privileged factories.
 * 2. Internal Authorizer module boundary: src/security/memory-authorizer.ts does NOT export
 *    any host factory or privileged operations (createHostAuthorizerPair is absent).
 * 3. Unprivileged MemoryAuthorizer: Callers constructing ordinary MemoryAuthorizer (even with
 *    forged hostToken options) do not acquire privileged methods; all privileged operations
 *    (authorizeSystem, createTask, attestTaskScope, and internal variants) are completely undefined
 *    on the authorizer object.
 * 4. Host Bootstrap Module: src/security/host-authority.ts encapsulates host authority creation,
 *    allowing trusted host bootstrap to create attested tasks and issue system contexts.
 * 5. Verification Boundary: Unprivileged authorizer instances can verify host-issued contexts
 *    and task attestations, while rejecting forged contexts and unverified tasks.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { DatabaseManager } from '../../src/storage/db.ts';
import { TaskRepository } from '../../src/storage/task-repository.ts';
import * as PublicApi from '../../src/index.ts';
import * as MemoryAuthorizerModule from '../../src/security/memory-authorizer.ts';
import { HostMemoryAuthority } from '../../src/security/host-authority.ts';
import {
  SecurityViolationError,
  ValidationError,
  TaskNotFoundError
} from '../../src/domain/errors.ts';
import type { ScopeIdentifier } from '../../src/domain/types.ts';

test('Security Regression - Public API (src/index.ts) does NOT export privileged host capabilities', () => {
  // 1. HostMemoryAuthority must NOT be exported from public package index
  assert.equal(
    (PublicApi as Record<string, unknown>).HostMemoryAuthority,
    undefined,
    'Public package entry point src/index.ts must NOT export HostMemoryAuthority.'
  );

  // 2. HostToken capability token must NOT be exported from public package index
  assert.equal(
    (PublicApi as Record<string, unknown>).HostToken,
    undefined,
    'Public package entry point src/index.ts must NOT export HostToken.'
  );

  // 3. createHostAuthorizerPair factory must NOT be exported from public package index
  assert.equal(
    (PublicApi as Record<string, unknown>).createHostAuthorizerPair,
    undefined,
    'Public package entry point src/index.ts must NOT export createHostAuthorizerPair.'
  );

  // 4. No privileged functions or factories exported
  assert.equal(
    (PublicApi as Record<string, unknown>).createTask,
    undefined,
    'Public package entry point src/index.ts must NOT export createTask.'
  );
  assert.equal(
    (PublicApi as Record<string, unknown>).authorizeSystem,
    undefined,
    'Public package entry point src/index.ts must NOT export authorizeSystem.'
  );
  assert.equal(
    (PublicApi as Record<string, unknown>)._authorizeSystem,
    undefined,
    'Public package entry point src/index.ts must NOT export _authorizeSystem.'
  );
  assert.equal(
    (PublicApi as Record<string, unknown>)._createTask,
    undefined,
    'Public package entry point src/index.ts must NOT export _createTask.'
  );
  assert.equal(
    (PublicApi as Record<string, unknown>).attestTaskScope,
    undefined,
    'Public package entry point src/index.ts must NOT export attestTaskScope.'
  );
  assert.equal(
    (PublicApi as Record<string, unknown>)._attestTaskScope,
    undefined,
    'Public package entry point src/index.ts must NOT export _attestTaskScope.'
  );

  // 5. MemoryAuthorizer IS exported as the unprivileged authorizer
  assert.equal(
    typeof PublicApi.MemoryAuthorizer,
    'function',
    'Public package entry point must export unprivileged MemoryAuthorizer constructor.'
  );
});

test('Security Regression - src/security/memory-authorizer.ts does NOT export any host factory', () => {
  // Direct import of memory-authorizer module must not reveal any host factory
  assert.equal(
    (MemoryAuthorizerModule as Record<string, unknown>).createHostAuthorizerPair,
    undefined,
    'memory-authorizer.ts must NOT export createHostAuthorizerPair.'
  );
  assert.equal(
    (MemoryAuthorizerModule as Record<string, unknown>).HostMemoryAuthority,
    undefined,
    'memory-authorizer.ts must NOT export HostMemoryAuthority.'
  );
  assert.equal(
    (MemoryAuthorizerModule as Record<string, unknown>).HostToken,
    undefined,
    'memory-authorizer.ts must NOT export HostToken.'
  );
  assert.equal(
    (MemoryAuthorizerModule as Record<string, unknown>).HostPrivilegedOperations,
    undefined,
    'memory-authorizer.ts must NOT export HostPrivilegedOperations.'
  );
});

test('Security Regression - Public MemoryAuthorizer with forged hostToken cannot acquire privileged capabilities', () => {
  const db = new DatabaseManager(':memory:');
  const taskRepo = new TaskRepository(db);
  const workspaceA: ScopeIdentifier = { scopeType: 'WORKSPACE', scopeId: 'ws-alpha' };

  try {
    // Ordinary caller constructs unprivileged authorizer from public API, attempting to pass a forged hostToken
    const publicAuthorizer = new PublicApi.MemoryAuthorizer({
      taskRepo,
      hostToken: 'forged-host-token-attempt'
    } as any);

    // 1. Privileged methods DO NOT EXIST on the authorizer object (undefined at runtime)
    assert.equal(typeof (publicAuthorizer as any).authorizeSystem, 'undefined');
    assert.equal(typeof (publicAuthorizer as any)._authorizeSystem, 'undefined');
    assert.equal(typeof (publicAuthorizer as any).createTask, 'undefined');
    assert.equal(typeof (publicAuthorizer as any)._createTask, 'undefined');
    assert.equal(typeof (publicAuthorizer as any).attestTaskScope, 'undefined');
    assert.equal(typeof (publicAuthorizer as any)._attestTaskScope, 'undefined');

    // 2. Attempting to invoke any privileged method throws TypeError (not a function)
    assert.throws(
      () => (publicAuthorizer as any).authorizeSystem({ scope: workspaceA }),
      (err: unknown) => err instanceof TypeError
    );
    assert.throws(
      () => (publicAuthorizer as any)._authorizeSystem({ scope: workspaceA }),
      (err: unknown) => err instanceof TypeError
    );
    assert.throws(
      () => (publicAuthorizer as any).createTask(taskRepo, { goal: 'rogue task', scope: workspaceA }),
      (err: unknown) => err instanceof TypeError
    );
    assert.throws(
      () => (publicAuthorizer as any)._createTask(taskRepo, { goal: 'rogue task', scope: workspaceA }),
      (err: unknown) => err instanceof TypeError
    );
    assert.throws(
      () => (publicAuthorizer as any).attestTaskScope('rogue-id', workspaceA),
      (err: unknown) => err instanceof TypeError
    );
    assert.throws(
      () => (publicAuthorizer as any)._attestTaskScope('rogue-id', workspaceA),
      (err: unknown) => err instanceof TypeError
    );

    // 3. User authorization without identity provider fails closed with MISSING_IDENTITY_INTEGRATION
    assert.throws(
      () => publicAuthorizer.authorizeUser({ credentials: 'some-token' }),
      (err: unknown) => {
        assert.ok(err instanceof SecurityViolationError);
        assert.equal(err.violationType, 'MISSING_IDENTITY_INTEGRATION');
        return true;
      }
    );

    // 4. Agent authorization without a real task fails closed with TaskNotFoundError
    assert.throws(
      () => publicAuthorizer.authorizeAgent({ taskId: 'non-existent-task' }),
      (err: unknown) => err instanceof TaskNotFoundError
    );

    // 5. Attempting to pass a forged context to verify() fails closed
    assert.throws(
      () => publicAuthorizer.verify({
        actor: 'SYSTEM',
        scope: workspaceA,
        permissions: new Set(['READ', 'WRITE', 'DELETE']),
        _proof: { signature: 'forged-signature', nonce: 'forged-nonce' }
      }),
      (err: unknown) => {
        assert.ok(err instanceof SecurityViolationError);
        assert.equal(err.violationType, 'FORGED_CALLER_CONTEXT');
        return true;
      }
    );

    // 6. Attempting to verify a task created without host attestation fails closed
    const forgedTask = taskRepo.createTask({
      id: 'forged-task-1',
      goal: 'Forged task lacking host attestation',
      metadata: { scope: workspaceA }
    });
    assert.throws(
      () => publicAuthorizer.verifyTaskScope(forgedTask),
      (err: unknown) => err instanceof ValidationError
    );
  } finally {
    db.close();
  }
});

test('Security - Internal HostMemoryAuthority successfully boots and establishes trusted boundary', () => {
  const db = new DatabaseManager(':memory:');
  const taskRepo = new TaskRepository(db);
  const workspaceAlpha: ScopeIdentifier = { scopeType: 'WORKSPACE', scopeId: 'ws-alpha' };
  const workspaceBeta: ScopeIdentifier = { scopeType: 'WORKSPACE', scopeId: 'ws-beta' };

  try {
    const host = new HostMemoryAuthority({
      taskRepo,
      identityProvider: {
        authenticate: (creds: unknown) => {
          if (creds === 'alice-secret') {
            return {
              principalId: 'alice',
              role: 'MEMBER',
              permittedScopes: [workspaceAlpha]
            };
          }
          if (creds === 'admin-secret') {
            return {
              principalId: 'super-admin',
              role: 'ADMIN',
              permittedScopes: [workspaceAlpha, workspaceBeta]
            };
          }
          return null;
        }
      }
    });

    // 1. Host bootstrap creates attested task
    const task = host.createTask(taskRepo, {
      goal: 'Authorized host task',
      scope: workspaceAlpha
    });
    assert.ok(task.id);

    // 2. Unprivileged authorizer verifies task scope
    const authorizer = host.authorizer;
    const verifiedScope = authorizer.verifyTaskScope(task);
    assert.equal(verifiedScope.scopeType, 'WORKSPACE');
    assert.equal(verifiedScope.scopeId, 'ws-alpha');

    // 3. Agent authorized for task gets locked permissions (READ, WRITE) and verified scope
    const agentContext = authorizer.authorizeAgent({ taskId: task.id });
    assert.equal(agentContext.actor, 'AGENT');
    assert.equal(agentContext.scope.scopeType, 'WORKSPACE');
    assert.equal(agentContext.scope.scopeId, 'ws-alpha');
    assert.deepEqual(Array.from(agentContext.permissions).sort(), ['READ', 'WRITE']);

    // Context verifies successfully
    const verifiedAgentContext = authorizer.verify(agentContext);
    assert.equal(verifiedAgentContext, agentContext);

    // 4. Host issues system context with full system permissions
    const systemContext = host.authorizeSystem({
      scope: { scopeType: 'GLOBAL', scopeId: 'default' }
    });
    assert.equal(systemContext.actor, 'SYSTEM');
    assert.deepEqual(Array.from(systemContext.permissions).sort(), ['DELETE', 'READ', 'WRITE']);

    // Context verifies successfully via unprivileged authorizer
    const verifiedSystemContext = authorizer.verify(systemContext);
    assert.equal(verifiedSystemContext, systemContext);

    // 5. Privileged operations DO NOT EXIST on the authorizer property
    assert.equal(typeof (authorizer as any).authorizeSystem, 'undefined');
    assert.equal(typeof (authorizer as any)._authorizeSystem, 'undefined');
    assert.equal(typeof (authorizer as any).createTask, 'undefined');
    assert.equal(typeof (authorizer as any)._createTask, 'undefined');
    assert.equal(typeof (authorizer as any).attestTaskScope, 'undefined');
    assert.equal(typeof (authorizer as any)._attestTaskScope, 'undefined');

    assert.throws(
      () => (authorizer as any).authorizeSystem({ scope: workspaceAlpha }),
      (err: unknown) => err instanceof TypeError
    );
    assert.throws(
      () => (authorizer as any).createTask(taskRepo, { goal: 'unauthorized', scope: workspaceAlpha }),
      (err: unknown) => err instanceof TypeError
    );

    // 6. Sensitive properties and capability methods are not exposed on authorizer
    assert.equal(typeof (authorizer as any).registerSystemContext, 'undefined');
    assert.equal(typeof (authorizer as any).getHostSecret, 'undefined');
    assert.equal((authorizer as any).hostSecret, undefined);
    assert.equal((authorizer as any).issuedContexts, undefined);

    // 7. User authorization via IdentityProvider works with resolved principal and permitted scopes
    const aliceContext = authorizer.authorizeUser({
      credentials: 'alice-secret',
      requestedScope: workspaceAlpha,
      taskId: task.id
    });
    assert.equal(aliceContext.actor, 'USER');
    assert.deepEqual(Array.from(aliceContext.permissions).sort(), ['READ', 'WRITE']);

    // Alice cannot access unassigned workspaceBeta
    assert.throws(
      () => authorizer.authorizeUser({
        credentials: 'alice-secret',
        requestedScope: workspaceBeta
      }),
      (err: unknown) => {
        assert.ok(err instanceof SecurityViolationError);
        assert.equal(err.violationType, 'UNAUTHORIZED_WORKSPACE');
        return true;
      }
    );
  } finally {
    db.close();
  }
});

test('Security - ECMAScript #private fields prevent runtime property inspection and tampering', () => {
  const db = new DatabaseManager(':memory:');
  const taskRepo = new TaskRepository(db);
  const workspaceAlpha: ScopeIdentifier = { scopeType: 'WORKSPACE', scopeId: 'ws-alpha' };

  try {
    const host = new HostMemoryAuthority({ taskRepo });
    const authorizer = host.authorizer;

    // 1. ECMAScript #private fields are completely absent from reflection & property inspection
    assert.equal((authorizer as any).hostSecret, undefined);
    assert.equal((authorizer as any).issuedContexts, undefined);
    assert.equal((authorizer as any).taskRepo, undefined);
    assert.equal((authorizer as any).identityProvider, undefined);

    // No own property names or symbols on authorizer instance
    assert.deepEqual(Object.getOwnPropertyNames(authorizer), []);
    assert.deepEqual(Object.getOwnPropertySymbols(authorizer), []);
    assert.equal(Reflect.has(authorizer, 'hostSecret'), false);
    assert.equal(Reflect.has(authorizer, 'issuedContexts'), false);

    // No own property names on host instance
    assert.deepEqual(Object.getOwnPropertyNames(host), []);
    assert.equal((host as any).hostSecret, undefined);

    // 2. Tampering resistance: Assigning an expando property does not affect private state
    (authorizer as any).hostSecret = Buffer.from('attacker-injected-secret-for-forgery');

    // Host operations and verifications continue to use the true #private host secret
    const task = host.createTask(taskRepo, {
      goal: 'Task verified under tampering attempt',
      scope: workspaceAlpha
    });
    const verifiedScope = authorizer.verifyTaskScope(task);
    assert.equal(verifiedScope.scopeId, 'ws-alpha');

    const systemCtx = host.authorizeSystem({ scope: workspaceAlpha });
    assert.equal(authorizer.verify(systemCtx), systemCtx);

    // A task forged using the injected expando secret is rejected
    const attackerSecret = Buffer.from('attacker-injected-secret-for-forgery');
    const fakeTimestamp = new Date().toISOString();
    const forgedPayload = `TASK_SCOPE|forged-task|WORKSPACE|ws-alpha|${fakeTimestamp}`;
    const forgedSig = createHmac('sha256', attackerSecret).update(forgedPayload, 'utf8').digest('hex');

    const forgedTask = taskRepo.createTask({
      id: 'forged-task',
      goal: 'Attacker-crafted task',
      metadata: {
        _scopeAttestation: {
          scopeType: 'WORKSPACE',
          scopeId: 'ws-alpha',
          signature: forgedSig,
          timestamp: fakeTimestamp
        }
      }
    });

    assert.throws(
      () => authorizer.verifyTaskScope(forgedTask),
      (err: unknown) => {
        assert.ok(err instanceof SecurityViolationError);
        assert.equal(err.violationType, 'FORGED_TASK_SCOPE');
        return true;
      }
    );
  } finally {
    db.close();
  }
});

test('Security - Cryptographic verification rejects forged task scopes and forged or tampered caller contexts', () => {
  const db = new DatabaseManager(':memory:');
  const taskRepo = new TaskRepository(db);
  const workspaceAlpha: ScopeIdentifier = { scopeType: 'WORKSPACE', scopeId: 'ws-alpha' };
  const workspaceBeta: ScopeIdentifier = { scopeType: 'WORKSPACE', scopeId: 'ws-beta' };

  try {
    const host = new HostMemoryAuthority({ taskRepo });
    const authorizer = host.authorizer;

    const task = host.createTask(taskRepo, {
      goal: 'Authorized task',
      scope: workspaceAlpha
    });

    // 1. Task scope with tampered scopeId is rejected
    const tamperedMeta = JSON.parse(task.metadataJson!);
    tamperedMeta._scopeAttestation.scopeId = 'ws-beta'; // Attacker attempts workspace escalation
    const tamperedTask = {
      ...task,
      metadataJson: JSON.stringify(tamperedMeta)
    };

    assert.throws(
      () => authorizer.verifyTaskScope(tamperedTask),
      (err: unknown) => {
        assert.ok(err instanceof SecurityViolationError);
        assert.equal(err.violationType, 'FORGED_TASK_SCOPE');
        return true;
      }
    );

    // 2. Caller context without cryptographic proof is rejected
    const unsealedContext = {
      actor: 'SYSTEM',
      scope: workspaceAlpha,
      permissions: new Set(['READ', 'WRITE', 'DELETE'])
    };
    assert.throws(
      () => authorizer.verify(unsealedContext),
      (err: unknown) => {
        assert.ok(err instanceof SecurityViolationError);
        assert.equal(err.violationType, 'FORGED_CALLER_CONTEXT');
        return true;
      }
    );

    // 3. Caller context with fabricated signature is rejected
    const forgedContext = {
      actor: 'SYSTEM',
      scope: workspaceAlpha,
      permissions: new Set(['READ', 'WRITE', 'DELETE']),
      _proof: {
        signature: 'deadbeef1234567890abcdefdeadbeef1234567890abcdefdeadbeef12345678',
        nonce: 'aabbccddeeff0011'
      }
    };
    assert.throws(
      () => authorizer.verify(forgedContext),
      (err: unknown) => {
        assert.ok(err instanceof SecurityViolationError);
        assert.equal(err.violationType, 'FORGED_CALLER_CONTEXT');
        return true;
      }
    );

    // 4. Authenticated agent context tampered to escalate permissions is rejected
    const validAgentCtx = authorizer.authorizeAgent({ taskId: task.id });
    const tamperedAgentCtx = {
      ...validAgentCtx,
      permissions: new Set(['READ', 'WRITE', 'DELETE', 'APPROVE']) // Escalation attempt
    };
    assert.throws(
      () => authorizer.verify(tamperedAgentCtx),
      (err: unknown) => {
        assert.ok(err instanceof SecurityViolationError);
        assert.equal(err.violationType, 'FORGED_CALLER_CONTEXT');
        return true;
      }
    );

    // 5. Context issued by a different host authority is rejected
    const foreignHost = new HostMemoryAuthority({ taskRepo });
    const foreignContext = foreignHost.authorizeSystem({ scope: workspaceAlpha });
    assert.throws(
      () => authorizer.verify(foreignContext),
      (err: unknown) => {
        assert.ok(err instanceof SecurityViolationError);
        assert.equal(err.violationType, 'FORGED_CALLER_CONTEXT');
        return true;
      }
    );
  } finally {
    db.close();
  }
});

test('Security - MemoryAuthorizer constructor rejects invalid host bootstrap handles', () => {
  let registrarCalled = false;
  const fakeHandle = {
    capability: Symbol('fake.capability'),
    setRegistrar: () => {
      registrarCalled = true;
    }
  };

  // Instantiating with an invalid capability handle must not invoke setRegistrar
  const authorizer = new PublicApi.MemoryAuthorizer({}, fakeHandle as any);
  assert.equal(registrarCalled, false, 'Invalid capability handle must not register context registrar.');

  // Instantiating without any handle succeeds as an unprivileged authorizer
  const plainAuthorizer = new PublicApi.MemoryAuthorizer({});
  assert.ok(plainAuthorizer);
  assert.equal((plainAuthorizer as any).hostSecret, undefined);
});
