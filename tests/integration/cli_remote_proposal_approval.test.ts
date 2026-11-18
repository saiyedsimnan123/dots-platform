/**
 * Next-Generation Dots AI Platform - Remote CLI Proposal Approval Integration Tests
 * Phase 4D.3C.2: Fix Remote CLI Supersession Forwarding
 */

import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  DotsRuntime,
  DotsHttpServer,
  MockModelProvider,
  runCli,
  type CliIo
} from '../../src/index.ts';

const ADMIN_TOKEN = 'admin-secret-token-123456';
const OTHER_WS_ADMIN_TOKEN = 'ws2-admin-secret-token-123456';

function createTempDir(): string {
  return mkdtempSync(join(tmpdir(), 'dots-cli-remote-'));
}

describe('Phase 4D.3C.2: Remote CLI Proposal Approval & Supersession Forwarding', () => {
  const tempDirs: string[] = [];

  afterEach(() => {
    while (tempDirs.length > 0) {
      const dir = tempDirs.pop()!;
      rmSync(dir, { recursive: true, force: true });
    }
  });

  function setupServer() {
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
          principalId: 'alice-admin',
          role: 'ADMIN',
          permittedScopes: [
            { scopeType: 'WORKSPACE', scopeId: 'ws-alpha' },
            { scopeType: 'GLOBAL', scopeId: 'default' }
          ]
        },
        {
          token: OTHER_WS_ADMIN_TOKEN,
          principalId: 'dave-ws2',
          role: 'ADMIN',
          permittedScopes: [{ scopeType: 'WORKSPACE', scopeId: 'ws-beta' }]
        }
      ]
    });

    const server = new DotsHttpServer(runtime);
    return { dir, dbPath, mockProvider, runtime, server };
  }

  function createCapturingIo(): { io: CliIo; getOut: () => string; getErr: () => string; reset: () => void } {
    let out = '';
    let err = '';
    return {
      io: {
        stdout: (t) => { out += `${t}\n`; },
        stderr: (t) => { err += `${t}\n`; }
      },
      getOut: () => out,
      getErr: () => err,
      reset: () => {
        out = '';
        err = '';
      }
    };
  }

  it('remote CLI approves new proposal without --supersede (APPROVE_NEW)', async () => {
    const { server, runtime } = setupServer();
    const started = await server.start();
    const capturing = createCapturingIo();

    try {
      // 1. Create a proposal directly in PENDING_APPROVAL
      const proposal = runtime.memoryRepo.createMemory({
        key: 'remote.cli.new_key',
        content: 'New setting value',
        category: 'PROJECT_FACT',
        scopeType: 'WORKSPACE',
        scopeId: 'ws-alpha',
        status: 'PENDING_APPROVAL'
      });
      assert.equal(proposal.status, 'PENDING_APPROVAL');

      // 2. Call remote CLI: dots memory approve <id> --server <url> --token <token> --scope WORKSPACE:ws-alpha
      const code = await runCli(
        [
          'memory',
          'approve',
          proposal.id,
          '--token',
          ADMIN_TOKEN,
          '--scope',
          'WORKSPACE:ws-alpha',
          '--server',
          started.url,
          '--json'
        ],
        capturing.io
      );

      assert.equal(code, 0, `Remote CLI failed: ${capturing.getErr()}`);
      const parsed = JSON.parse(capturing.getOut().trim()) as { memory: { id: string; status: string; version: number } };
      assert.equal(parsed.memory.id, proposal.id);
      assert.equal(parsed.memory.status, 'ACTIVE');
      assert.equal(parsed.memory.version, 1);
    } finally {
      await server.stop();
    }
  });

  it('remote CLI fails with 409 Conflict when approving conflicting proposal without --supersede', async () => {
    const { server, runtime } = setupServer();
    const started = await server.start();
    const capturing = createCapturingIo();

    try {
      const scopeAlpha = { scopeType: 'WORKSPACE' as const, scopeId: 'ws-alpha' };

      // 1. Create active memory (v1)
      const active = runtime.memoryRepo.createMemory({
        key: 'remote.cli.conflict_key',
        content: 'Active v1 content',
        category: 'PROJECT_FACT',
        scopeType: 'WORKSPACE',
        scopeId: 'ws-alpha',
        status: 'ACTIVE'
      });
      assert.equal(active.status, 'ACTIVE');

      // 2. Create pending proposal for same key
      const proposal = runtime.memoryRepo.createMemory({
        key: 'remote.cli.conflict_key',
        content: 'Proposed replacement content',
        category: 'PROJECT_FACT',
        scopeType: 'WORKSPACE',
        scopeId: 'ws-alpha',
        status: 'PENDING_APPROVAL'
      });

      // 3. Remote CLI approve without --supersede must fail with conflict (exit code 1)
      const code = await runCli(
        [
          'memory',
          'approve',
          proposal.id,
          '--token',
          ADMIN_TOKEN,
          '--scope',
          'WORKSPACE:ws-alpha',
          '--server',
          started.url,
          '--json'
        ],
        capturing.io
      );

      assert.notEqual(code, 0, 'Must fail when active key conflict exists without --supersede');
      const errOut = capturing.getErr() || capturing.getOut();
      assert.ok(errOut.includes('Active memory with key') || errOut.includes('MEMORY_CONFLICT') || errOut.includes('409'));

      // Invariant: active memory remains ACTIVE, proposal remains PENDING_APPROVAL
      const activeAfter = runtime.memoryRepo.getMemoryById(active.id, scopeAlpha);
      assert.equal(activeAfter?.status, 'ACTIVE');
      const proposalAfter = runtime.memoryRepo.getMemoryById(proposal.id, scopeAlpha);
      assert.equal(proposalAfter?.status, 'PENDING_APPROVAL');
    } finally {
      await server.stop();
    }
  });

  it('remote CLI approves and supersedes conflicting proposal with --supersede (APPROVE_AND_SUPERSEDE)', async () => {
    const { server, runtime } = setupServer();
    const started = await server.start();
    const capturing = createCapturingIo();

    try {
      const scopeAlpha = { scopeType: 'WORKSPACE' as const, scopeId: 'ws-alpha' };

      // 1. Create active memory (v1)
      const active = runtime.memoryRepo.createMemory({
        key: 'remote.cli.supersede_key',
        content: 'Original v1 content',
        category: 'PROJECT_FACT',
        scopeType: 'WORKSPACE',
        scopeId: 'ws-alpha',
        status: 'ACTIVE'
      });
      assert.equal(active.status, 'ACTIVE');

      // 2. Create pending proposal for same key
      const proposal = runtime.memoryRepo.createMemory({
        key: 'remote.cli.supersede_key',
        content: 'Replacement v2 content via remote CLI',
        category: 'PROJECT_FACT',
        scopeType: 'WORKSPACE',
        scopeId: 'ws-alpha',
        status: 'PENDING_APPROVAL'
      });

      // 3. Remote CLI approve with --supersede
      const code = await runCli(
        [
          'memory',
          'approve',
          proposal.id,
          '--supersede',
          '--reason',
          'Approved with supersession over remote CLI',
          '--token',
          ADMIN_TOKEN,
          '--scope',
          'WORKSPACE:ws-alpha',
          '--server',
          started.url,
          '--json'
        ],
        capturing.io
      );

      assert.equal(code, 0, `Remote CLI supersede failed: ${capturing.getErr()}`);
      const parsed = JSON.parse(capturing.getOut().trim()) as {
        memory: { id: string; status: string; version: number; supersedesId: string }
      };

      // 4. Verify replacement memory is ACTIVE, version 2, supersedesId linked
      assert.equal(parsed.memory.id, proposal.id);
      assert.equal(parsed.memory.status, 'ACTIVE');
      assert.equal(parsed.memory.version, 2);
      assert.equal(parsed.memory.supersedesId, active.id);

      // 5. Verify previous memory in DB is SUPERSEDED, supersededBy linked
      const activeAfter = runtime.memoryRepo.getMemoryById(active.id, scopeAlpha);
      assert.equal(activeAfter?.status, 'SUPERSEDED');
      assert.equal(activeAfter?.supersededBy, proposal.id);
    } finally {
      await server.stop();
    }
  });

  it('remote CLI rejects proposal (REJECT), and --supersede is not applied to rejection', async () => {
    const { server, runtime } = setupServer();
    const started = await server.start();
    const capturing = createCapturingIo();

    try {
      const scopeAlpha = { scopeType: 'WORKSPACE' as const, scopeId: 'ws-alpha' };

      // 1. Create active memory (v1)
      const active = runtime.memoryRepo.createMemory({
        key: 'remote.cli.reject_key',
        content: 'Active v1 content to remain active',
        category: 'PROJECT_FACT',
        scopeType: 'WORKSPACE',
        scopeId: 'ws-alpha',
        status: 'ACTIVE'
      });

      // 2. Submit proposal 1 for ordinary rejection
      const prop1 = runtime.memoryRepo.createMemory({
        key: 'remote.cli.reject_key',
        content: 'Bad proposal 1',
        category: 'PROJECT_FACT',
        scopeType: 'WORKSPACE',
        scopeId: 'ws-alpha',
        status: 'PENDING_APPROVAL'
      });

      // Reject via remote CLI without --supersede
      capturing.reset();
      const code1 = await runCli(
        [
          'memory',
          'reject',
          prop1.id,
          '--reason',
          'Rejected bad proposal',
          '--token',
          ADMIN_TOKEN,
          '--scope',
          'WORKSPACE:ws-alpha',
          '--server',
          started.url,
          '--json'
        ],
        capturing.io
      );
      assert.equal(code1, 0, `Remote CLI reject failed: ${capturing.getErr()}`);
      const parsed1 = JSON.parse(capturing.getOut().trim()) as { memory: { id: string; status: string } };
      assert.equal(parsed1.memory.id, prop1.id);
      assert.equal(parsed1.memory.status, 'ARCHIVED');

      // 3. Submit proposal 2 and reject with --supersede flag present
      const prop2 = runtime.memoryRepo.createMemory({
        key: 'remote.cli.reject_key',
        content: 'Bad proposal 2',
        category: 'PROJECT_FACT',
        scopeType: 'WORKSPACE',
        scopeId: 'ws-alpha',
        status: 'PENDING_APPROVAL'
      });

      capturing.reset();
      const code2 = await runCli(
        [
          'memory',
          'reject',
          prop2.id,
          '--supersede',
          '--reason',
          'Rejecting despite supersede flag',
          '--token',
          ADMIN_TOKEN,
          '--scope',
          'WORKSPACE:ws-alpha',
          '--server',
          started.url,
          '--json'
        ],
        capturing.io
      );
      assert.equal(code2, 0, `Remote CLI reject with supersede failed: ${capturing.getErr()}`);
      const parsed2 = JSON.parse(capturing.getOut().trim()) as { memory: { id: string; status: string } };
      assert.equal(parsed2.memory.id, prop2.id);
      assert.equal(parsed2.memory.status, 'ARCHIVED');

      // Verify active memory is STILL ACTIVE (rejection did NOT supersede it)
      const activeAfter = runtime.memoryRepo.getMemoryById(active.id, scopeAlpha);
      assert.equal(activeAfter?.status, 'ACTIVE');
      assert.equal(activeAfter?.supersededBy, null);
    } finally {
      await server.stop();
    }
  });

  it('remote CLI respects scope and token authentication boundaries', async () => {
    const { server, runtime } = setupServer();
    const started = await server.start();
    const capturing = createCapturingIo();

    try {
      const prop = runtime.memoryRepo.createMemory({
        key: 'remote.cli.scope_guarded',
        content: 'Scope guarded item',
        category: 'PROJECT_FACT',
        scopeType: 'WORKSPACE',
        scopeId: 'ws-alpha',
        status: 'PENDING_APPROVAL'
      });

      // 1. Invalid token should fail with 401
      capturing.reset();
      const badTokenCode = await runCli(
        [
          'memory',
          'approve',
          prop.id,
          '--token',
          'invalid-token-xyz',
          '--scope',
          'WORKSPACE:ws-alpha',
          '--server',
          started.url,
          '--json'
        ],
        capturing.io
      );
      assert.notEqual(badTokenCode, 0);

      // 2. Caller from ws-beta cannot approve proposal in ws-alpha (scope violation)
      capturing.reset();
      const crossWsCode = await runCli(
        [
          'memory',
          'approve',
          prop.id,
          '--token',
          OTHER_WS_ADMIN_TOKEN,
          '--scope',
          'WORKSPACE:ws-beta',
          '--server',
          started.url,
          '--json'
        ],
        capturing.io
      );
      assert.notEqual(crossWsCode, 0);
    } finally {
      await server.stop();
    }
  });
});
