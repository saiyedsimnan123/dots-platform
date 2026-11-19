import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  DotsRuntime,
  DotsHttpServer,
  MockModelProvider,
  ValidationError,
  type Memory
} from '../../src/index.ts';

const ADMIN_TOKEN = 'admin-secret-token-strict-val-123456';

function createTempDir(): string {
  return mkdtempSync(join(tmpdir(), 'dots-update-strict-'));
}

describe('Phase 4D.3D.3B: Strict Update Metadata Validation & HTTP Sanitization', () => {
  const tempDirs: string[] = [];

  afterEach(() => {
    while (tempDirs.length > 0) {
      const dir = tempDirs.pop()!;
      rmSync(dir, { recursive: true, force: true });
    }
  });

  function setupTestEnv() {
    const dir = createTempDir();
    tempDirs.push(dir);
    const dbPath = join(dir, 'dots.db');
    const mockProvider = new MockModelProvider();
    const runtime = new DotsRuntime({
      dbPath,
      workspaceRoot: dir,
      host: '127.0.0.1',
      port: 0,
      silentLogs: true,
      enableScheduler: false,
      autoApproveTier2: false,
      modelProvider: mockProvider,
      tokens: [
        {
          token: ADMIN_TOKEN,
          principalId: 'admin-alice',
          role: 'ADMIN',
          permittedScopes: [
            { scopeType: 'WORKSPACE', scopeId: 'ws-alpha' },
            { scopeType: 'GLOBAL', scopeId: 'default' }
          ]
        }
      ]
    });

    const server = new DotsHttpServer(runtime);

    const caller = runtime.authorizer.authorizeUser({
      credentials: ADMIN_TOKEN,
      requestedScope: { scopeType: 'WORKSPACE', scopeId: 'ws-alpha' }
    });

    return { dir, dbPath, runtime, server, caller };
  }

  // ==========================================================================
  // 1. HTTP memory creation strips all three reserved metadata fields
  // ==========================================================================
  it('1. HTTP memory creation strips all three reserved metadata fields', async () => {
    const { server, runtime, caller } = setupTestEnv();
    const started = await server.start();

    try {
      const res = await fetch(`${started.url}/api/memories`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${ADMIN_TOKEN}`,
          'Content-Type': 'application/json',
          'X-Dots-Scope': 'WORKSPACE:ws-alpha'
        },
        body: JSON.stringify({
          category: 'PROJECT_FACT',
          key: 'http.reserved.strip.test',
          content: 'Testing stripping of reserved metadata fields over HTTP',
          status: 'PENDING_APPROVAL',
          metadata: {
            proposalType: 'UPDATE',
            targetMemoryId: 'forged-target-memory-id',
            targetVersion: 42,
            legitimateField: 'keep-me'
          }
        })
      });

      assert.equal(res.status, 201);
      const json = (await res.json()) as { memory: Memory };
      assert.ok(json.memory.id);

      // Verify returned memory metadataJson
      assert.ok(json.memory.metadataJson, 'metadataJson must be present');
      const meta = JSON.parse(json.memory.metadataJson) as Record<string, unknown>;
      assert.equal(meta.proposalType, undefined, 'proposalType must be stripped');
      assert.equal(meta.targetMemoryId, undefined, 'targetMemoryId must be stripped');
      assert.equal(meta.targetVersion, undefined, 'targetVersion must be stripped');
      assert.equal(meta.legitimateField, 'keep-me', 'legitimateField must be preserved');

      // Verify database row directly
      const raw = runtime.memoryRepo.getMemoryById(json.memory.id, caller.scope);
      assert.ok(raw);
      assert.ok(raw.metadataJson);
      const dbMeta = JSON.parse(raw.metadataJson);
      assert.equal(dbMeta.proposalType, undefined);
      assert.equal(dbMeta.targetMemoryId, undefined);
      assert.equal(dbMeta.targetVersion, undefined);
      assert.equal(dbMeta.legitimateField, 'keep-me');
    } finally {
      await server.stop();
    }
  });

  // ==========================================================================
  // 2. HTTP memory creation preserves legitimate metadata
  // ==========================================================================
  it('2. HTTP memory creation preserves legitimate metadata', async () => {
    const { server } = setupTestEnv();
    const started = await server.start();

    try {
      const res = await fetch(`${started.url}/api/memories`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${ADMIN_TOKEN}`,
          'Content-Type': 'application/json',
          'X-Dots-Scope': 'WORKSPACE:ws-alpha'
        },
        body: JSON.stringify({
          category: 'PROJECT_FACT',
          key: 'http.legit.meta.test',
          content: 'Legitimate metadata preserved',
          status: 'PENDING_APPROVAL',
          metadata: {
            author: 'alice',
            environment: 'staging',
            clusterCount: 3,
            features: ['auto_scaling', 'monitoring'],
            nestedConfig: { timeoutMs: 5000, debug: true }
          }
        })
      });

      assert.equal(res.status, 201);
      const json = (await res.json()) as { memory: Memory };
      const meta = JSON.parse(json.memory.metadataJson) as Record<string, unknown>;
      assert.equal(meta.author, 'alice');
      assert.equal(meta.environment, 'staging');
      assert.equal(meta.clusterCount, 3);
      assert.deepEqual(meta.features, ['auto_scaling', 'monitoring']);
      assert.deepEqual(meta.nestedConfig, { timeoutMs: 5000, debug: true });
    } finally {
      await server.stop();
    }
  });

  // ==========================================================================
  // 3. HTTP memory creation preserves existing credential sanitization
  // ==========================================================================
  it('3. HTTP memory creation preserves existing credential sanitization', async () => {
    const { server } = setupTestEnv();
    const started = await server.start();

    try {
      const res = await fetch(`${started.url}/api/memories`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${ADMIN_TOKEN}`,
          'Content-Type': 'application/json',
          'X-Dots-Scope': 'WORKSPACE:ws-alpha'
        },
        body: JSON.stringify({
          category: 'PROJECT_FACT',
          key: 'http.credential.sanitization.test',
          content: 'Checking credential sanitization',
          metadata: {
            apiKey: 'AIzaSyDummyKeyValue1234567890123456789',
            password: 'SuperSecretPassword!',
            authToken: 'secret_token_value',
            safeNote: 'Bearer token value leaked: Bearer abcdef1234567890abcdef1234567890',
            normalField: 'verified safe'
          }
        })
      });

      assert.equal(res.status, 201);
      const json = (await res.json()) as { memory: Memory };
      const meta = JSON.parse(json.memory.metadataJson) as Record<string, unknown>;

      // Sensitive keys must be omitted
      assert.equal(meta.apiKey, undefined, 'apiKey key must be omitted');
      assert.equal(meta.password, undefined, 'password key must be omitted');
      assert.equal(meta.authToken, undefined, 'authToken key must be omitted');

      // String secrets must be scrubbed
      assert.ok(
        typeof meta.safeNote === 'string' && meta.safeNote.includes('[REDACTED_TOKEN]'),
        'String secret in value must be scrubbed'
      );
      assert.equal(meta.normalField, 'verified safe');
    } finally {
      await server.stop();
    }
  });

  // ==========================================================================
  // 4. A valid UPDATE proposal still approves through APPROVE_AND_SUPERSEDE
  // ==========================================================================
  it('4. A valid UPDATE proposal still approves through APPROVE_AND_SUPERSEDE', async () => {
    const { runtime, caller } = setupTestEnv();

    const activeMem = runtime.memoryRepo.createMemory({
      category: 'PROJECT_FACT',
      scopeType: caller.scope.scopeType,
      scopeId: caller.scope.scopeId,
      key: 'service.endpoint.url',
      content: 'https://v1.api.example.com',
      status: 'ACTIVE'
    });
    assert.equal(activeMem.version, 1);
    assert.equal(activeMem.status, 'ACTIVE');

    const updateProposal = runtime.memoryRepo.createMemory({
      category: 'PROJECT_FACT',
      scopeType: caller.scope.scopeType,
      scopeId: caller.scope.scopeId,
      key: 'service.endpoint.url',
      content: 'https://v2.api.example.com',
      status: 'PENDING_APPROVAL',
      metadata: {
        proposalType: 'UPDATE',
        targetMemoryId: activeMem.id,
        targetVersion: 1
      }
    });

    const decided = runtime.memoryService.decideProposal(caller, {
      memoryId: updateProposal.id,
      decision: 'APPROVE_AND_SUPERSEDE'
    });

    assert.equal(decided.id, updateProposal.id);
    assert.equal(decided.status, 'ACTIVE');
    assert.equal(decided.version, 2);
    assert.equal(decided.supersedesId, activeMem.id);

    const oldActive = runtime.memoryRepo.getMemoryById(activeMem.id, caller.scope);
    assert.ok(oldActive);
    assert.equal(oldActive.status, 'SUPERSEDED');
    assert.equal(oldActive.supersededBy, updateProposal.id);
  });

  // ==========================================================================
  // 5. Missing targetMemoryId fails safely
  // ==========================================================================
  it('5. Missing targetMemoryId fails safely', async () => {
    const { runtime, caller } = setupTestEnv();

    const activeMem = runtime.memoryRepo.createMemory({
      category: 'PROJECT_FACT',
      scopeType: caller.scope.scopeType,
      scopeId: caller.scope.scopeId,
      key: 'target.id.missing.test',
      content: 'Active content',
      status: 'ACTIVE'
    });

    const proposal = runtime.memoryRepo.createMemory({
      category: 'PROJECT_FACT',
      scopeType: caller.scope.scopeType,
      scopeId: caller.scope.scopeId,
      key: 'target.id.missing.test',
      content: 'Proposed update without targetMemoryId',
      status: 'PENDING_APPROVAL',
      metadata: {
        proposalType: 'UPDATE',
        targetVersion: 1
      }
    });

    assert.throws(
      () =>
        runtime.memoryService.decideProposal(caller, {
          memoryId: proposal.id,
          decision: 'APPROVE_AND_SUPERSEDE'
        }),
      (err: unknown) => {
        assert.ok(err instanceof ValidationError);
        assert.match(err.message, /targetMemoryId must be a non-empty string/);
        return true;
      }
    );

    // Active memory remains untouched
    const activeCheck = runtime.memoryRepo.getMemoryById(activeMem.id, caller.scope);
    assert.equal(activeCheck?.status, 'ACTIVE');
    assert.equal(activeCheck?.version, 1);
    assert.equal(activeCheck?.supersededBy, null);

    // Proposal remains untouched
    const propCheck = runtime.memoryRepo.getMemoryById(proposal.id, caller.scope);
    assert.equal(propCheck?.status, 'PENDING_APPROVAL');
  });

  // ==========================================================================
  // 6. Empty or non-string targetMemoryId fails safely
  // ==========================================================================
  it('6. Empty or non-string targetMemoryId fails safely', async () => {
    const { runtime, caller } = setupTestEnv();

    const activeMem = runtime.memoryRepo.createMemory({
      category: 'PROJECT_FACT',
      scopeType: caller.scope.scopeType,
      scopeId: caller.scope.scopeId,
      key: 'target.id.empty.test',
      content: 'Active content',
      status: 'ACTIVE'
    });

    const invalidTargetIds = ['', '   ', null, 12345, true, {}, []];

    for (const badId of invalidTargetIds) {
      const proposal = runtime.memoryRepo.createMemory({
        category: 'PROJECT_FACT',
        scopeType: caller.scope.scopeType,
        scopeId: caller.scope.scopeId,
        key: 'target.id.empty.test',
        content: `Proposed update with bad target ID: ${String(badId)}`,
        status: 'PENDING_APPROVAL',
        metadata: {
          proposalType: 'UPDATE',
          targetMemoryId: badId,
          targetVersion: 1
        }
      });

      assert.throws(
        () =>
          runtime.memoryService.decideProposal(caller, {
            memoryId: proposal.id,
            decision: 'APPROVE_AND_SUPERSEDE'
          }),
        (err: unknown) => {
          assert.ok(err instanceof ValidationError);
          assert.match(err.message, /targetMemoryId must be a non-empty string/);
          return true;
        },
        `Expected targetMemoryId '${String(badId)}' to throw ValidationError`
      );

      // Verify states remain untouched
      const activeCheck = runtime.memoryRepo.getMemoryById(activeMem.id, caller.scope);
      assert.equal(activeCheck?.status, 'ACTIVE');
      assert.equal(activeCheck?.version, 1);
      assert.equal(activeCheck?.supersededBy, null);

      const propCheck = runtime.memoryRepo.getMemoryById(proposal.id, caller.scope);
      assert.equal(propCheck?.status, 'PENDING_APPROVAL');
    }
  });

  // ==========================================================================
  // 7. Missing targetVersion fails safely
  // ==========================================================================
  it('7. Missing targetVersion fails safely', async () => {
    const { runtime, caller } = setupTestEnv();

    const activeMem = runtime.memoryRepo.createMemory({
      category: 'PROJECT_FACT',
      scopeType: caller.scope.scopeType,
      scopeId: caller.scope.scopeId,
      key: 'target.version.missing.test',
      content: 'Active content',
      status: 'ACTIVE'
    });

    const proposal = runtime.memoryRepo.createMemory({
      category: 'PROJECT_FACT',
      scopeType: caller.scope.scopeType,
      scopeId: caller.scope.scopeId,
      key: 'target.version.missing.test',
      content: 'Proposed update without targetVersion',
      status: 'PENDING_APPROVAL',
      metadata: {
        proposalType: 'UPDATE',
        targetMemoryId: activeMem.id
      }
    });

    assert.throws(
      () =>
        runtime.memoryService.decideProposal(caller, {
          memoryId: proposal.id,
          decision: 'APPROVE_AND_SUPERSEDE'
        }),
      (err: unknown) => {
        assert.ok(err instanceof ValidationError);
        assert.match(err.message, /targetVersion must be a positive integer/);
        return true;
      }
    );

    const activeCheck = runtime.memoryRepo.getMemoryById(activeMem.id, caller.scope);
    assert.equal(activeCheck?.status, 'ACTIVE');
    assert.equal(activeCheck?.version, 1);

    const propCheck = runtime.memoryRepo.getMemoryById(proposal.id, caller.scope);
    assert.equal(propCheck?.status, 'PENDING_APPROVAL');
  });

  // ==========================================================================
  // 8. Null, string, zero, negative, and fractional targetVersion values fail safely
  // ==========================================================================
  it('8. Null, string, zero, negative, and fractional targetVersion values fail safely', async () => {
    const { runtime, caller } = setupTestEnv();

    const activeMem = runtime.memoryRepo.createMemory({
      category: 'PROJECT_FACT',
      scopeType: caller.scope.scopeType,
      scopeId: caller.scope.scopeId,
      key: 'target.version.bad.test',
      content: 'Active content',
      status: 'ACTIVE'
    });

    const invalidVersions = [null, '1', 'v1', 0, -1, -99, 1.5, 2.7, NaN, Infinity, -Infinity, {}, []];

    for (const badVer of invalidVersions) {
      const proposal = runtime.memoryRepo.createMemory({
        category: 'PROJECT_FACT',
        scopeType: caller.scope.scopeType,
        scopeId: caller.scope.scopeId,
        key: 'target.version.bad.test',
        content: `Proposed update with bad version: ${String(badVer)}`,
        status: 'PENDING_APPROVAL',
        metadata: {
          proposalType: 'UPDATE',
          targetMemoryId: activeMem.id,
          targetVersion: badVer
        }
      });

      assert.throws(
        () =>
          runtime.memoryService.decideProposal(caller, {
            memoryId: proposal.id,
            decision: 'APPROVE_AND_SUPERSEDE'
          }),
        (err: unknown) => {
          assert.ok(err instanceof ValidationError);
          assert.match(err.message, /targetVersion must be a positive integer/);
          return true;
        },
        `Expected targetVersion '${String(badVer)}' to throw ValidationError`
      );

      const activeCheck = runtime.memoryRepo.getMemoryById(activeMem.id, caller.scope);
      assert.equal(activeCheck?.status, 'ACTIVE');
      assert.equal(activeCheck?.version, 1);

      const propCheck = runtime.memoryRepo.getMemoryById(proposal.id, caller.scope);
      assert.equal(propCheck?.status, 'PENDING_APPROVAL');
    }
  });

  // ==========================================================================
  // 9. Malformed metadataJson fails safely
  // ==========================================================================
  it('9. Malformed metadataJson fails safely', async () => {
    const { runtime, caller } = setupTestEnv();

    const activeMem = runtime.memoryRepo.createMemory({
      category: 'PROJECT_FACT',
      scopeType: caller.scope.scopeType,
      scopeId: caller.scope.scopeId,
      key: 'malformed.json.test',
      content: 'Active content',
      status: 'ACTIVE'
    });

    const proposal = runtime.memoryRepo.createMemory({
      category: 'PROJECT_FACT',
      scopeType: caller.scope.scopeType,
      scopeId: caller.scope.scopeId,
      key: 'malformed.json.test',
      content: 'Proposal with corrupt metadataJson',
      status: 'PENDING_APPROVAL'
    });

    // Directly corrupt metadata_json in SQLite
    runtime.db.prepare('UPDATE memories SET metadata_json = ? WHERE id = ?').run(
      '{"proposalType": "UPDATE", "targetMemoryId": "bad-json',
      proposal.id
    );

    // APPROVE_AND_SUPERSEDE must fail closed
    assert.throws(
      () =>
        runtime.memoryService.decideProposal(caller, {
          memoryId: proposal.id,
          decision: 'APPROVE_AND_SUPERSEDE'
        }),
      (err: unknown) => {
        assert.ok(err instanceof ValidationError);
        assert.match(err.message, /proposal metadata contains invalid JSON/);
        return true;
      }
    );

    // APPROVE_NEW must also fail closed
    assert.throws(
      () =>
        runtime.memoryService.decideProposal(caller, {
          memoryId: proposal.id,
          decision: 'APPROVE_NEW'
        }),
      (err: unknown) => {
        assert.ok(err instanceof ValidationError);
        assert.match(err.message, /proposal metadata contains invalid JSON/);
        return true;
      }
    );

    // Verify active record was untouched
    const activeCheck = runtime.memoryRepo.getMemoryById(activeMem.id, caller.scope);
    assert.equal(activeCheck?.status, 'ACTIVE');
    assert.equal(activeCheck?.version, 1);
  });

  // ==========================================================================
  // 10. Failed approval leaves original ACTIVE memory and proposal unchanged
  // ==========================================================================
  it('10. Failed approval leaves original ACTIVE memory and proposal unchanged', async () => {
    const { runtime, caller } = setupTestEnv();

    const activeMem = runtime.memoryRepo.createMemory({
      category: 'PROJECT_FACT',
      scopeType: caller.scope.scopeType,
      scopeId: caller.scope.scopeId,
      key: 'rollback.integrity.test',
      content: 'Original active content',
      status: 'ACTIVE'
    });

    const proposal = runtime.memoryRepo.createMemory({
      category: 'PROJECT_FACT',
      scopeType: caller.scope.scopeType,
      scopeId: caller.scope.scopeId,
      key: 'rollback.integrity.test',
      content: 'Proposal content that will fail validation',
      status: 'PENDING_APPROVAL',
      metadata: {
        proposalType: 'UPDATE',
        targetMemoryId: activeMem.id,
        targetVersion: 0 // invalid version
      }
    });

    // Record snapshot of rows
    const activeSnapshot = runtime.memoryRepo.getMemoryById(activeMem.id, caller.scope);
    const proposalSnapshot = runtime.memoryRepo.getMemoryById(proposal.id, caller.scope);

    assert.throws(() =>
      runtime.memoryService.decideProposal(caller, {
        memoryId: proposal.id,
        decision: 'APPROVE_AND_SUPERSEDE'
      })
    );

    // Check after failure
    const activeAfter = runtime.memoryRepo.getMemoryById(activeMem.id, caller.scope);
    const proposalAfter = runtime.memoryRepo.getMemoryById(proposal.id, caller.scope);

    assert.deepEqual(activeAfter, activeSnapshot);
    assert.deepEqual(proposalAfter, proposalSnapshot);
  });

  // ==========================================================================
  // 11. Existing ordinary proposals can still use APPROVE_NEW
  // ==========================================================================
  it('11. Existing ordinary proposals can still use APPROVE_NEW', async () => {
    const { runtime, caller } = setupTestEnv();

    const proposal = runtime.memoryRepo.createMemory({
      category: 'PROJECT_FACT',
      scopeType: caller.scope.scopeType,
      scopeId: caller.scope.scopeId,
      key: 'brand.new.ordinary.proposal',
      content: 'Brand new knowledge without conflicts',
      status: 'PENDING_APPROVAL',
      metadata: {
        source: 'automatic_knowledge_proposal',
        agentId: 'research-agent'
      }
    });

    const decided = runtime.memoryService.decideProposal(caller, {
      memoryId: proposal.id,
      decision: 'APPROVE_NEW'
    });

    assert.equal(decided.id, proposal.id);
    assert.equal(decided.status, 'ACTIVE');
    assert.equal(decided.version, 1);
    assert.equal(decided.supersedesId, null);
    assert.equal(decided.supersededBy, null);
  });

  // ==========================================================================
  // 12. Existing stale-target protection remains intact
  // ==========================================================================
  it('12. Existing stale-target protection remains intact', async () => {
    const { runtime, caller } = setupTestEnv();

    const activeMem = runtime.memoryRepo.createMemory({
      category: 'PROJECT_FACT',
      scopeType: caller.scope.scopeType,
      scopeId: caller.scope.scopeId,
      key: 'stale.protection.test',
      content: 'Active content v1',
      status: 'ACTIVE'
    });

    // 12a: Proposal targets wrong memory ID
    const wrongIdProposal = runtime.memoryRepo.createMemory({
      category: 'PROJECT_FACT',
      scopeType: caller.scope.scopeType,
      scopeId: caller.scope.scopeId,
      key: 'stale.protection.test',
      content: 'Update targeting nonexistent ID',
      status: 'PENDING_APPROVAL',
      metadata: {
        proposalType: 'UPDATE',
        targetMemoryId: 'wrong-active-id-999',
        targetVersion: 1
      }
    });

    assert.throws(
      () =>
        runtime.memoryService.decideProposal(caller, {
          memoryId: wrongIdProposal.id,
          decision: 'APPROVE_AND_SUPERSEDE'
        }),
      (err: unknown) => {
        assert.ok(err instanceof ValidationError);
        assert.match(err.message, /target memory 'wrong-active-id-999' does not match current active memory/);
        return true;
      }
    );

    // 12b: Proposal targets stale version
    const staleVerProposal = runtime.memoryRepo.createMemory({
      category: 'PROJECT_FACT',
      scopeType: caller.scope.scopeType,
      scopeId: caller.scope.scopeId,
      key: 'stale.protection.test',
      content: 'Update targeting stale version',
      status: 'PENDING_APPROVAL',
      metadata: {
        proposalType: 'UPDATE',
        targetMemoryId: activeMem.id,
        targetVersion: 2 // current version is 1, so version 2 is a mismatch/stale
      }
    });

    assert.throws(
      () =>
        runtime.memoryService.decideProposal(caller, {
          memoryId: staleVerProposal.id,
          decision: 'APPROVE_AND_SUPERSEDE'
        }),
      (err: unknown) => {
        assert.ok(err instanceof ValidationError);
        assert.match(err.message, /target memory version 2 is stale \(current active memory version is 1\)/);
        return true;
      }
    );

    // 12c: Update proposal approved with APPROVE_NEW when active memory was deleted/archived
    runtime.memoryRepo.archiveMemory(activeMem.id, caller.scope);
    const updateAfterArchive = runtime.memoryRepo.createMemory({
      category: 'PROJECT_FACT',
      scopeType: caller.scope.scopeType,
      scopeId: caller.scope.scopeId,
      key: 'stale.protection.test',
      content: 'Update after target archived',
      status: 'PENDING_APPROVAL',
      metadata: {
        proposalType: 'UPDATE',
        targetMemoryId: activeMem.id,
        targetVersion: 1
      }
    });

    assert.throws(
      () =>
        runtime.memoryService.decideProposal(caller, {
          memoryId: updateAfterArchive.id,
          decision: 'APPROVE_NEW'
        }),
      (err: unknown) => {
        assert.ok(err instanceof ValidationError);
        assert.match(err.message, /target memory '.*' is no longer active/);
        return true;
      }
    );
  });
});
