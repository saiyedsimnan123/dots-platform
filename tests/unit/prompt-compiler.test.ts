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

test('PromptCompiler - truncates user context exceeding maxContextChars limit', () => {
  const compiler = new PromptCompiler({ maxContextChars: 100 });
  const longGoal = 'A'.repeat(150);
  const { userPrompt } = compiler.compilePlanPrompt(longGoal, sampleTools);

  assert.ok(userPrompt.includes('[...truncated to context limit...]'));
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
