/**
 * Next-Generation Dots AI Platform - Sandboxed Tools Unit Tests
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { resolve } from 'node:path';
import { existsSync, rmSync, mkdirSync } from 'node:fs';
import {
  calculateTool,
  fileWriteTool,
  fileReadTool,
  fileListTool,
  hashFileTool
} from '../../src/tools/sandbox-tools.ts';
import { ToolExecutionError } from '../../src/domain/errors.ts';

const testSandboxDir = resolve('test_sandbox_env');

test('calculateTool - evaluates valid arithmetic expressions', async () => {
  const result = await calculateTool.handler({ expression: '10 * 5 + (20 / 4)' }, {
    taskId: 't1',
    stepId: 's1',
    workspaceRoot: testSandboxDir
  });

  assert.equal(result.exitCode, 0);
  assert.equal(result.output.result, 55);
});

test('calculateTool - strictly rejects non-mathematical or malicious expressions', async () => {
  const forbidden = [
    'process.exit(1)',
    'require("fs")',
    'fetch("http://evil.com")',
    'console.log("hacked")'
  ];

  for (const expr of forbidden) {
    await assert.rejects(
      async () => {
        await calculateTool.handler({ expression: expr }, {
          taskId: 't1',
          stepId: 's1',
          workspaceRoot: testSandboxDir
        });
      },
      (err: unknown) => {
        assert(err instanceof ToolExecutionError);
        assert.ok((err as ToolExecutionError).message.includes('forbidden characters'));
        return true;
      }
    );
  }
});

test('fileWriteTool and fileReadTool - writes and reads files inside sandbox', async () => {
  if (existsSync(testSandboxDir)) rmSync(testSandboxDir, { recursive: true, force: true });
  mkdirSync(testSandboxDir, { recursive: true });

  const filePath = resolve(testSandboxDir, 'hello.txt');

  try {
    // 1. Write file
    const writeResult = await fileWriteTool.handler({
      path: filePath,
      content: 'Hello, Dots Platform!'
    }, {
      taskId: 't1',
      stepId: 's1',
      workspaceRoot: testSandboxDir
    });

    assert.equal(writeResult.exitCode, 0);
    assert.equal(writeResult.output.bytesWritten, 21);

    // 2. Read file
    const readResult = await fileReadTool.handler({
      path: filePath
    }, {
      taskId: 't1',
      stepId: 's2',
      workspaceRoot: testSandboxDir
    });

    assert.equal(readResult.exitCode, 0);
    assert.equal(readResult.output.content, 'Hello, Dots Platform!');
    assert.equal(readResult.output.byteSize, 21);
  } finally {
    if (existsSync(testSandboxDir)) rmSync(testSandboxDir, { recursive: true, force: true });
  }
});

test('hashFileTool - calculates cryptographic SHA-256 digest', async () => {
  if (existsSync(testSandboxDir)) rmSync(testSandboxDir, { recursive: true, force: true });
  mkdirSync(testSandboxDir, { recursive: true });

  const filePath = resolve(testSandboxDir, 'hash_test.txt');

  try {
    await fileWriteTool.handler({
      path: filePath,
      content: 'cryptographic verification payload'
    }, {
      taskId: 't1',
      stepId: 's1',
      workspaceRoot: testSandboxDir
    });

    const hashResult = await hashFileTool.handler({
      path: filePath,
      algorithm: 'sha256'
    }, {
      taskId: 't1',
      stepId: 's2',
      workspaceRoot: testSandboxDir
    });

    assert.equal(hashResult.exitCode, 0);
    assert.equal(hashResult.output.algorithm, 'sha256');
    // SHA256 length is 64 hex characters
    assert.equal(String(hashResult.output.hash).length, 64);
  } finally {
    if (existsSync(testSandboxDir)) rmSync(testSandboxDir, { recursive: true, force: true });
  }
});

test('fileListTool - lists files in directory', async () => {
  if (existsSync(testSandboxDir)) rmSync(testSandboxDir, { recursive: true, force: true });
  mkdirSync(testSandboxDir, { recursive: true });

  try {
    await fileWriteTool.handler({ path: resolve(testSandboxDir, 'file1.txt'), content: '1' }, { taskId: 't', stepId: 's', workspaceRoot: testSandboxDir });
    await fileWriteTool.handler({ path: resolve(testSandboxDir, 'file2.txt'), content: '2' }, { taskId: 't', stepId: 's', workspaceRoot: testSandboxDir });

    const listResult = await fileListTool.handler({ path: testSandboxDir }, {
      taskId: 't1',
      stepId: 's1',
      workspaceRoot: testSandboxDir
    });

    assert.equal(listResult.exitCode, 0);
    assert.equal(listResult.output.count, 2);
    const entries = listResult.output.entries as string[];
    assert.ok(entries.includes('file1.txt'));
    assert.ok(entries.includes('file2.txt'));
  } finally {
    if (existsSync(testSandboxDir)) rmSync(testSandboxDir, { recursive: true, force: true });
  }
});
