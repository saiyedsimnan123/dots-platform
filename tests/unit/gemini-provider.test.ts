/**
 * Next-Generation Dots AI Platform - Gemini Provider Unit Tests
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { GeminiProvider } from '../../src/model/gemini-provider.ts';
import { ValidationError } from '../../src/domain/errors.ts';

test('GeminiProvider - constructor initializes with default configuration', () => {
  const provider = new GeminiProvider({ apiKey: 'fake-test-key-12345', modelId: 'gemini-2.5-flash' });
  assert.equal(provider.name, 'google-gemini');
  assert.equal(provider.modelId, 'gemini-2.5-flash');
});

test('GeminiProvider - throws ValidationError when API key is missing', async () => {
  const originalEnv = process.env.GEMINI_API_KEY;
  delete process.env.GEMINI_API_KEY;

  try {
    const provider = new GeminiProvider({ apiKey: '' });
    await assert.rejects(
      async () => {
        await provider.generatePlan('Test goal', []);
      },
      (err: unknown) => {
        assert(err instanceof ValidationError);
        assert.ok((err as ValidationError).message.includes('Gemini API key is not configured'));
        return true;
      }
    );
  } finally {
    if (originalEnv) {
      process.env.GEMINI_API_KEY = originalEnv;
    }
  }
});
