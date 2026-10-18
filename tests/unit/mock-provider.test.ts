/**
 * Next-Generation Dots AI Platform - Mock Model Provider Unit Tests
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { MockModelProvider } from '../../src/model/mock-provider.ts';
import type { ToolDefinition, PlanStepProposal } from '../../src/model/types.ts';

const tools: ToolDefinition[] = [
  {
    name: 'hash_file',
    description: 'Computes file hash',
    parameters: { path: { type: 'string', description: 'path' } }
  }
];

test('MockModelProvider - generates deterministic fallback plan', async () => {
  const provider = new MockModelProvider('test-mock');
  assert.equal(provider.name, 'mock-provider');
  assert.equal(provider.modelId, 'test-mock');

  const result = await provider.generatePlan('Calculate hash', tools);
  assert.ok(result.steps.length > 0);
  assert.equal(result.steps[0]!.toolName, 'hash_file');
  assert.ok(result.usage.totalTokens > 0);
  assert.ok(result.usage.estimatedCostUsd >= 0);

  const calls = provider.getRecordedCalls();
  assert.equal(calls.length, 1);
  assert.equal(calls[0]!.method, 'generatePlan');
});

test('MockModelProvider - returns enqueued scripted plan', async () => {
  const provider = new MockModelProvider();
  const scriptedPlan: PlanStepProposal[] = [
    {
      stepOrder: 1,
      description: 'Step 1: Check environment',
      toolName: 'check_env',
      arguments: { key: 'NODE_ENV' },
      expectedOutcome: 'Environment verified'
    },
    {
      stepOrder: 2,
      description: 'Step 2: Run verification',
      toolName: 'verify_system',
      arguments: {},
      expectedOutcome: 'System operational'
    }
  ];

  provider.enqueuePlan(scriptedPlan);
  const result = await provider.generatePlan('Run checks', tools);

  assert.equal(result.steps.length, 2);
  assert.equal(result.steps[0]!.toolName, 'check_env');
  assert.equal(result.steps[1]!.toolName, 'verify_system');
});

test('MockModelProvider - returns enqueued completion with tool calls', async () => {
  const provider = new MockModelProvider();
  provider.enqueueCompletion('Proposed action', [
    {
      id: 'call_1',
      toolName: 'hash_file',
      arguments: { path: 'sandbox/data.txt' }
    }
  ]);

  const completion = await provider.generateCompletion([
    { role: 'user', content: 'What tool should I run?' }
  ]);

  assert.equal(completion.content, 'Proposed action');
  assert.ok(completion.toolCalls);
  assert.equal(completion.toolCalls.length, 1);
  assert.equal(completion.toolCalls[0]!.toolName, 'hash_file');
});

test('MockModelProvider - simulates injected API failure', async () => {
  const provider = new MockModelProvider();
  provider.simulateFailureNext(new Error('Simulated upstream rate limit (HTTP 429)'));

  await assert.rejects(
    async () => {
      await provider.generatePlan('Goal', tools);
    },
    /Simulated upstream rate limit/
  );
});

test('MockModelProvider - clears call history', async () => {
  const provider = new MockModelProvider();
  await provider.generateCompletion([{ role: 'user', content: 'hello' }]);
  assert.equal(provider.getRecordedCalls().length, 1);

  provider.clearHistory();
  assert.equal(provider.getRecordedCalls().length, 0);
});

test('MockModelProvider - generatePlan records pre-compiled prompt and updates token accounting', async () => {
  const provider = new MockModelProvider();
  const compiledPrompt = {
    systemInstruction: 'Compiled system instructions for planning',
    userPrompt: 'TASK GOAL:\nBuild artifact\n\nADDITIONAL CONTEXT / ARTIFACTS:\n{"records":[{"id":"mem-1"}]}',
    contextOmitted: false
  };

  const result = await provider.generatePlan('Build artifact', tools, undefined, compiledPrompt);
  assert.ok(result.steps.length > 0);

  const calls = provider.getRecordedCalls();
  assert.equal(calls.length, 1);
  assert.equal(calls[0]!.method, 'generatePlan');
  assert.equal(calls[0]!.args.goal, 'Build artifact');
  assert.equal(calls[0]!.args.compiledPrompt, compiledPrompt);
  assert.equal(calls[0]!.args.systemInstruction, compiledPrompt.systemInstruction);
  assert.equal(calls[0]!.args.userPrompt, compiledPrompt.userPrompt);

  // Token accounting uses compiled prompt characters
  const expectedChars = compiledPrompt.userPrompt.length + compiledPrompt.systemInstruction.length;
  assert.equal(result.usage.promptTokens, Math.ceil(expectedChars / 4) + 50);
});

test('MockModelProvider - generatePlan supports 3-arg compiledPrompt path and legacy context path', async () => {
  const provider = new MockModelProvider();

  // 1. 3-arg call with compiledPrompt
  const compiled = {
    systemInstruction: 'System instructions',
    userPrompt: 'TASK GOAL:\nGoal 1',
    contextOmitted: false
  };
  await provider.generatePlan('Goal 1', tools, compiled as any);

  // 2. Legacy 3-arg call with context string
  await provider.generatePlan('Goal 2', tools, 'Legacy context body');

  const calls = provider.getRecordedCalls();
  assert.equal(calls.length, 2);

  // Call 1
  assert.equal(calls[0]!.args.goal, 'Goal 1');
  assert.equal(calls[0]!.args.compiledPrompt, compiled);
  assert.equal(calls[0]!.args.systemInstruction, 'System instructions');
  assert.equal(calls[0]!.args.userPrompt, 'TASK GOAL:\nGoal 1');

  // Call 2
  assert.equal(calls[1]!.args.goal, 'Goal 2');
  assert.equal(calls[1]!.args.context, 'Legacy context body');
  assert.equal(calls[1]!.args.compiledPrompt, undefined);
});
