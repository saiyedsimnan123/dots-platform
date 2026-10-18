/**
 * Next-Generation Dots AI Platform - Prompt Compiler Unit Tests
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { PromptCompiler } from '../../src/model/prompt-compiler.ts';
import type { ToolDefinition } from '../../src/model/types.ts';
import { ValidationError } from '../../src/domain/errors.ts';

const sampleTools: ToolDefinition[] = [
  {
    name: 'hash_file',
    description: 'Computes cryptographic hash of a file in the sandbox',
    parameters: {
      path: { type: 'string', description: 'Relative path in sandbox' },
      algorithm: { type: 'string', description: 'Hash algorithm (sha256/md5)' }
    },
    required: ['path']
  }
];

test('PromptCompiler - compiles structured plan prompt with tool specifications', () => {
  const compiler = new PromptCompiler();
  const { systemInstruction, userPrompt } = compiler.compilePlanPrompt(
    'Calculate SHA-256 of payload.txt',
    sampleTools
  );

  assert.ok(systemInstruction.includes('hash_file'));
  assert.ok(systemInstruction.includes('Computes cryptographic hash'));
  assert.ok(systemInstruction.includes('"steps": ['));
  assert.ok(userPrompt.includes('Calculate SHA-256 of payload.txt'));
});

test('PromptCompiler - automatically scrubs secrets from task goals and context', () => {
  const compiler = new PromptCompiler();
  const { userPrompt } = compiler.compilePlanPrompt(
    'Process data using key AIzaSyD9876543210zyxwvutsrqponmlkjihgfed',
    sampleTools,
    'Internal auth: Bearer supersecrettoken123'
  );

  assert.equal(userPrompt.includes('AIza'), false);
  assert.ok(userPrompt.includes('[REDACTED_GOOGLE_API_KEY]'));
  assert.equal(userPrompt.includes('supersecrettoken123'), false);
  assert.ok(userPrompt.includes('[REDACTED_TOKEN]'));
});

test('PromptCompiler - rejects task goal exceeding maxContextChars limit with ValidationError', () => {
  const compiler = new PromptCompiler({ maxContextChars: 100 });
  const longGoal = 'A'.repeat(150);

  assert.throws(
    () => compiler.compilePlanPrompt(longGoal, sampleTools),
    (err: unknown) => {
      assert.ok(err instanceof ValidationError);
      assert.match(err.message, /exceeds maximum allowed context limit/);
      return true;
    }
  );
});

test('PromptCompiler - includes optional context completely when fitting within maxContextChars limit', () => {
  const goal = 'Perform analysis';
  const basePrompt = `TASK GOAL:\n${goal}`;
  const prefix = '\n\nADDITIONAL CONTEXT / ARTIFACTS:\n';
  const contextBody = 'Useful context that fits within the configured limit';
  const totalLength = basePrompt.length + prefix.length + contextBody.length;

  const compiler = new PromptCompiler({ maxContextChars: totalLength });
  const { userPrompt, contextOmitted } = compiler.compilePlanPrompt(goal, sampleTools, contextBody);

  assert.equal(userPrompt.length, totalLength);
  assert.ok(userPrompt.includes('ADDITIONAL CONTEXT / ARTIFACTS:'));
  assert.ok(userPrompt.includes(contextBody));
  assert.equal(contextOmitted, false);
});

test('PromptCompiler - omits entire context block atomically when context pushes user prompt over limit', () => {
  const goal = 'Perform analysis';
  const basePrompt = `TASK GOAL:\n${goal}`;
  const prefix = '\n\nADDITIONAL CONTEXT / ARTIFACTS:\n';
  const contextBody = 'Useful context that pushes the prompt over limit';
  const totalLength = basePrompt.length + prefix.length + contextBody.length;

  // Set limit to 1 character less than totalLength
  const compiler = new PromptCompiler({ maxContextChars: totalLength - 1 });
  const { userPrompt, contextOmitted } = compiler.compilePlanPrompt(goal, sampleTools, contextBody);

  // Must omit the entire context block atomically
  assert.equal(userPrompt, basePrompt);
  assert.equal(userPrompt.includes('ADDITIONAL CONTEXT / ARTIFACTS:'), false);
  assert.equal(userPrompt.includes(contextBody), false);
  assert.equal(userPrompt.includes('[...truncated to context limit...]'), false);
  assert.equal(contextOmitted, true);
});

test('PromptCompiler - never slices memory JSON or drops security delimiters', () => {
  const goal = 'Secure execution';
  const memoryJson = JSON.stringify({
    _boundary: '=== BEGIN UNTRUSTED LONG-TERM MEMORY CONTEXT ===',
    records: [
      { id: 'mem-42', category: 'PROJECT_FACT', content: 'Database password is not password' }
    ],
    _boundaryEnd: '=== END UNTRUSTED LONG-TERM MEMORY CONTEXT ==='
  }, null, 2);

  const basePrompt = `TASK GOAL:\n${goal}`;
  // Allow enough space for goal, but not enough for the full memory JSON
  const compiler = new PromptCompiler({ maxContextChars: basePrompt.length + 50 });
  const { userPrompt, contextOmitted } = compiler.compilePlanPrompt(goal, sampleTools, memoryJson);

  // Entire memory block omitted: no partial JSON, no broken delimiters, no mid-string slicing
  assert.equal(userPrompt, basePrompt);
  assert.equal(userPrompt.includes('mem-42'), false);
  assert.equal(userPrompt.includes('Database password'), false);
  assert.equal(userPrompt.includes('=== BEGIN UNTRUSTED LONG-TERM MEMORY CONTEXT ==='), false);
  assert.equal(userPrompt.includes('=== END UNTRUSTED LONG-TERM MEMORY CONTEXT ==='), false);
  assert.equal(userPrompt.includes('[...truncated to context limit...]'), false);
  assert.equal(contextOmitted, true);
});

test('PromptCompiler - existing callers without context continue to work normally', () => {
  const compiler = new PromptCompiler();
  const { systemInstruction, userPrompt, contextOmitted } = compiler.compilePlanPrompt('Standard task goal', sampleTools);

  assert.ok(systemInstruction.includes('hash_file'));
  assert.equal(userPrompt, 'TASK GOAL:\nStandard task goal');
  assert.equal(userPrompt.includes('ADDITIONAL CONTEXT / ARTIFACTS:'), false);
  assert.equal(contextOmitted, false);
});

test('PromptCompiler - sets contextOmitted to true and contextIncluded to false only when non-empty context is omitted due to limit', () => {
  const compiler = new PromptCompiler({ maxContextChars: 50 });
  const result = compiler.compilePlanPrompt('My Task Goal', sampleTools, 'Very long context that exceeds the configured limit');
  assert.equal(result.contextOmitted, true);
  assert.equal(result.contextIncluded, false);
  assert.equal(result.userPrompt, 'TASK GOAL:\nMy Task Goal');
});

test('PromptCompiler - sets contextOmitted to false and contextIncluded to true when optional context fits within limit', () => {
  const compiler = new PromptCompiler({ maxContextChars: 1000 });
  const result = compiler.compilePlanPrompt('My Task Goal', sampleTools, 'Short context');
  assert.equal(result.contextOmitted, false);
  assert.equal(result.contextIncluded, true);
  assert.ok(result.userPrompt.includes('Short context'));
});

test('PromptCompiler - sets contextOmitted to false and contextIncluded to false when no context is supplied or context is empty whitespace', () => {
  const compiler = new PromptCompiler();
  const noContext = compiler.compilePlanPrompt('My Task Goal', sampleTools);
  assert.equal(noContext.contextOmitted, false);
  assert.equal(noContext.contextIncluded, false);

  const emptyContext = compiler.compilePlanPrompt('My Task Goal', sampleTools, '');
  assert.equal(emptyContext.contextOmitted, false);
  assert.equal(emptyContext.contextIncluded, false);

  const whitespaceContext = compiler.compilePlanPrompt('My Task Goal', sampleTools, '   \t\n  ');
  assert.equal(whitespaceContext.contextOmitted, false);
  assert.equal(whitespaceContext.contextIncluded, false);
});

test('PromptCompiler - throws ValidationError on empty task goal', () => {
  const compiler = new PromptCompiler();
  assert.throws(
    () => compiler.compilePlanPrompt('   ', sampleTools),
    (err: unknown) => {
      assert(err instanceof ValidationError);
      return true;
    }
  );
});

test('PromptCompiler - compiles and sanitizes conversation messages', () => {
  const compiler = new PromptCompiler();
  const messages = compiler.compileMessages([
    { role: 'user', content: 'Here is my OpenAI key: sk-abcdef1234567890abcdef1234567890' },
    { role: 'assistant', content: 'I will keep your key safe.' }
  ]);

  assert.equal(messages.length, 2);
  assert.ok(messages[0]!.content.includes('[REDACTED_OPENAI_API_KEY]'));
  assert.equal(messages[0]!.content.includes('sk-abcdef'), false);
});
