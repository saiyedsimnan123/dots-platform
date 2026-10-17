/**
 * Next-Generation Dots AI Platform - Variable Resolver Unit Tests
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { VariableResolver } from '../../src/orchestrator/variable-resolver.ts';
import type { StepOutputContext } from '../../src/orchestrator/variable-resolver.ts';
import { WorkflowExecutionError } from '../../src/domain/errors.ts';

test('VariableResolver - resolves exact typed values from previous step outputs', () => {
  const completedSteps: StepOutputContext[] = [
    {
      stepOrder: 1,
      toolName: 'calculate',
      output: { expression: '20 + 22', result: 42, active: true, complex: { count: 99 } }
    }
  ];

  // Number typed preservation
  const resolvedNumber = VariableResolver.resolve(
    { total: '{{steps[1].result}}' },
    completedSteps,
    2
  );
  assert.strictEqual(resolvedNumber.total, 42);

  // Boolean typed preservation
  const resolvedBool = VariableResolver.resolve(
    { isOk: '{{step1.output.active}}' },
    completedSteps,
    2
  );
  assert.strictEqual(resolvedBool.isOk, true);

  // Nested property access
  const resolvedNested = VariableResolver.resolve(
    { count: '{{steps[1].complex.count}}' },
    completedSteps,
    2
  );
  assert.strictEqual(resolvedNested.count, 99);
});

test('VariableResolver - interpolates embedded variables into string templates', () => {
  const completedSteps: StepOutputContext[] = [
    {
      stepOrder: 1,
      toolName: 'calculate',
      output: { result: 100 }
    },
    {
      stepOrder: 2,
      toolName: 'file_read',
      output: { path: 'data.txt', count: 5 }
    }
  ];

  const resolved = VariableResolver.resolve(
    {
      message: 'Processed {{step2.count}} records for total: ${{step1.result}} USD',
      path: 'output_{{steps[2].count}}.json'
    },
    completedSteps,
    3
  );

  assert.equal(resolved.message, 'Processed 5 records for total: $100 USD');
  assert.equal(resolved.path, 'output_5.json');
});

test('VariableResolver - resolves recursively inside arrays and nested dictionaries', () => {
  const completedSteps: StepOutputContext[] = [
    {
      stepOrder: 1,
      toolName: 'hash_file',
      output: { hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' }
    }
  ];

  const inputArgs = {
    metadata: {
      expectedHash: '{{steps[1].hash}}',
      tags: ['audit', 'sha256:{{steps[1].hash}}']
    }
  };

  const resolved = VariableResolver.resolve(inputArgs, completedSteps, 2) as {
    metadata: { expectedHash: string; tags: string[] };
  };

  assert.equal(resolved.metadata.expectedHash, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  assert.equal(resolved.metadata.tags[1], 'sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
});

test('VariableResolver - throws WorkflowExecutionError when step output does not exist', () => {
  assert.throws(
    () => {
      VariableResolver.resolve({ val: '{{steps[2].result}}' }, [], 1);
    },
    (err: unknown) => {
      assert.ok(err instanceof WorkflowExecutionError);
      assert.ok(err.message.includes('step 2 has not completed'));
      return true;
    }
  );
});

test('VariableResolver - throws WorkflowExecutionError when property does not exist in output', () => {
  const completedSteps: StepOutputContext[] = [
    {
      stepOrder: 1,
      toolName: 'calculate',
      output: { result: 50 }
    }
  ];

  assert.throws(
    () => {
      VariableResolver.resolve({ val: '{{steps[1].nonExistent}}' }, completedSteps, 2);
    },
    (err: unknown) => {
      assert.ok(err instanceof WorkflowExecutionError);
      assert.ok(err.message.includes("Property 'nonExistent' not found in output of step 1"));
      return true;
    }
  );
});

test('VariableResolver - throws WorkflowExecutionError on malformed variable syntax', () => {
  assert.throws(
    () => {
      VariableResolver.resolve({ val: '{{invalid_syntax}}' }, [], 1);
    },
    (err: unknown) => {
      assert.ok(err instanceof WorkflowExecutionError);
      assert.ok(err.message.includes('Invalid variable syntax'));
      return true;
    }
  );
});
