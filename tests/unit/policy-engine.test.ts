/**
 * Next-Generation Dots AI Platform - Policy Engine Unit Tests
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { resolve } from 'node:path';
import { PolicyEngine } from '../../src/security/policy-engine.ts';
import { SecurityViolationError } from '../../src/domain/errors.ts';

const testWorkspace = resolve('sandbox_test_workspace');

test('PolicyEngine - auto-approves Tier 0 and Tier 1 safe tools', () => {
  const engine = new PolicyEngine({ workspaceRoot: testWorkspace });

  const t0 = engine.evaluate('calculate', { expression: '2 + 2' }, 'TIER_0');
  assert.equal(t0.decision, 'ALLOWED');
  assert.equal(t0.approvalRequired, false);

  const t1 = engine.evaluate('file_read', { path: 'notes.txt' }, 'TIER_1');
  assert.equal(t1.decision, 'ALLOWED');
  assert.equal(t1.approvalRequired, false);
  assert.equal(t1.sanitizedArguments.path, resolve(testWorkspace, 'notes.txt'));
});

test('PolicyEngine - strictly prevents directory traversal attacks', () => {
  const engine = new PolicyEngine({ workspaceRoot: testWorkspace });

  const traversalPayloads = [
    '../../Windows/System32/calc.exe',
    '../secret.env',
    '..\\..\\passwords.txt',
    'subdir/../../../etc/passwd'
  ];

  for (const maliciousPath of traversalPayloads) {
    assert.throws(
      () => {
        engine.evaluate('file_write', { path: maliciousPath, content: 'evil' }, 'TIER_2');
      },
      (err: unknown) => {
        assert(err instanceof SecurityViolationError);
        assert.equal(err.code, 'SECURITY_VIOLATION');
        assert.equal(err.violationType, 'PATH_TRAVERSAL_DETECTED');
        return true;
      },
      `Expected traversal rejection for: ${maliciousPath}`
    );
  }
});

test('PolicyEngine - flags Tier 3 and Tier 4 operations for human approval', () => {
  const engine = new PolicyEngine({ workspaceRoot: testWorkspace });

  const t3 = engine.evaluate('run_script', { script: 'deploy.sh' }, 'TIER_3');
  assert.equal(t3.decision, 'REQUIRES_APPROVAL');
  assert.equal(t3.approvalRequired, true);

  const t4 = engine.evaluate('delete_directory', { path: 'data' }, 'TIER_4');
  assert.equal(t4.decision, 'REQUIRES_APPROVAL');
  assert.equal(t4.approvalRequired, true);
});

test('PolicyEngine - denies unknown or unregistered risk tiers', () => {
  const engine = new PolicyEngine({ workspaceRoot: testWorkspace });
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const result = engine.evaluate('mystery_tool', {}, 'INVALID_TIER' as any);
  assert.equal(result.decision, 'DENIED');
});
