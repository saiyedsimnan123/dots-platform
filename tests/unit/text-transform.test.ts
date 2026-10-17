/**
 * Next-Generation Dots AI Platform - text_transform Tool Unit Tests
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { textTransformTool } from '../../src/tools/sandbox-tools.ts';
import { ToolExecutionError } from '../../src/domain/errors.ts';

const mockContext = { taskId: 't1', stepId: 's1', workspaceRoot: '.' };

test('textTransformTool - performs uppercase, lowercase, and trim operations', async () => {
  const upper = await textTransformTool.handler({ operation: 'uppercase', text: 'hello dots' }, mockContext);
  assert.equal(upper.exitCode, 0);
  assert.equal((upper.output as { result: string }).result, 'HELLO DOTS');

  const lower = await textTransformTool.handler({ operation: 'lowercase', text: 'HELLO WORLD' }, mockContext);
  assert.equal(lower.exitCode, 0);
  assert.equal((lower.output as { result: string }).result, 'hello world');

  const trimmed = await textTransformTool.handler({ operation: 'trim', text: '   spaced text   ' }, mockContext);
  assert.equal(trimmed.exitCode, 0);
  assert.equal((trimmed.output as { result: string }).result, 'spaced text');
});

test('textTransformTool - performs string replacement and json operations', async () => {
  const replaced = await textTransformTool.handler({
    operation: 'replace',
    text: 'apple banana apple cherry',
    pattern: 'apple',
    replacement: 'orange'
  }, mockContext);
  assert.equal((replaced.output as { result: string }).result, 'orange banana orange cherry');

  const parsed = await textTransformTool.handler({
    operation: 'json_parse',
    text: '{"status": "ok", "count": 42}'
  }, mockContext);
  assert.deepEqual((parsed.output as { result: { status: string; count: number } }).result, { status: 'ok', count: 42 });

  const stringified = await textTransformTool.handler({
    operation: 'json_stringify',
    text: '{"a":1}'
  }, mockContext);
  assert.ok(typeof (stringified.output as { result: string }).result === 'string');
});

test('textTransformTool - rejects unsupported operation', async () => {
  await assert.rejects(
    async () => {
      await textTransformTool.handler({ operation: 'unsupported_op', text: 'test' }, mockContext);
    },
    (err: unknown) => {
      assert.ok(err instanceof ToolExecutionError);
      assert.ok(err.message.includes('Unsupported text_transform operation'));
      return true;
    }
  );
});
