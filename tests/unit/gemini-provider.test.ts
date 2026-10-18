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

test('GeminiProvider - generatePlan uses pre-compiled systemInstruction and userPrompt in actual HTTP request body', async () => {
  const originalFetch = globalThis.fetch;
  let interceptedUrl: string | undefined;
  let interceptedBody: any;

  globalThis.fetch = (async (url: string | URL | Request, init?: RequestInit) => {
    interceptedUrl = String(url);
    interceptedBody = JSON.parse(init?.body as string);
    return {
      ok: true,
      status: 200,
      json: async () => ({
        candidates: [
          {
            content: {
              parts: [{ text: JSON.stringify({ steps: [{ stepOrder: 1, description: 'S1', toolName: 't1', arguments: {}, expectedOutcome: 'O1' }] }) }]
            }
          }
        ],
        usageMetadata: { promptTokenCount: 50, candidatesTokenCount: 20, totalTokenCount: 70 }
      })
    } as Response;
  }) as typeof globalThis.fetch;

  try {
    const provider = new GeminiProvider({ apiKey: 'test-api-key', modelId: 'gemini-2.5-flash' });
    const compiledPrompt = {
      systemInstruction: 'Scrubbed system instruction with custom tools',
      userPrompt: 'TASK GOAL:\nSolve problem\n\nADDITIONAL CONTEXT / ARTIFACTS:\n{"records":[]}',
      contextOmitted: false,
      contextIncluded: true
    };

    const result = await provider.generatePlan(
      'Solve problem',
      [],
      undefined,
      compiledPrompt
    );

    assert.equal(result.steps.length, 1);
    assert.ok(interceptedUrl?.includes('gemini-2.5-flash'));
    assert.ok(interceptedUrl?.includes('test-api-key'));

    // Assert that the compiled prompt directly populated the actual Gemini API request
    assert.equal(interceptedBody.systemInstruction.parts[0].text, 'Scrubbed system instruction with custom tools');
    assert.equal(interceptedBody.contents[0].parts[0].text, 'TASK GOAL:\nSolve problem\n\nADDITIONAL CONTEXT / ARTIFACTS:\n{"records":[]}');
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('GeminiProvider - generatePlan supports 3-argument compiledPrompt path: generatePlan(goal, tools, compiledPrompt)', async () => {
  const originalFetch = globalThis.fetch;
  let interceptedBody: any;

  globalThis.fetch = (async (_url: string | URL | Request, init?: RequestInit) => {
    interceptedBody = JSON.parse(init?.body as string);
    return {
      ok: true,
      status: 200,
      json: async () => ({
        candidates: [{ content: { parts: [{ text: JSON.stringify({ steps: [] }) }] } }],
        usageMetadata: { promptTokenCount: 10, candidatesTokenCount: 10, totalTokenCount: 20 }
      })
    } as Response;
  }) as typeof globalThis.fetch;

  try {
    const provider = new GeminiProvider({ apiKey: 'test-api-key' });
    const compiledPrompt = {
      systemInstruction: 'Instruction via 3-arg call',
      userPrompt: 'TASK GOAL:\nGoal via 3-arg call',
      contextOmitted: false,
      contextIncluded: false
    };

    await provider.generatePlan('Goal via 3-arg call', [], compiledPrompt as any);

    assert.equal(interceptedBody.systemInstruction.parts[0].text, 'Instruction via 3-arg call');
    assert.equal(interceptedBody.contents[0].parts[0].text, 'TASK GOAL:\nGoal via 3-arg call');
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('GeminiProvider - generatePlan preserves legacy call paths without pre-compiled prompt', async () => {
  const originalFetch = globalThis.fetch;
  let interceptedBody: any;

  globalThis.fetch = (async (_url: string | URL | Request, init?: RequestInit) => {
    interceptedBody = JSON.parse(init?.body as string);
    return {
      ok: true,
      status: 200,
      json: async () => ({
        candidates: [{ content: { parts: [{ text: JSON.stringify({ steps: [] }) }] } }],
        usageMetadata: { promptTokenCount: 10, candidatesTokenCount: 10, totalTokenCount: 20 }
      })
    } as Response;
  }) as typeof globalThis.fetch;

  try {
    const provider = new GeminiProvider({ apiKey: 'test-api-key' });

    // 1. Legacy 2-argument call
    await provider.generatePlan('Legacy goal without context', []);
    assert.ok(interceptedBody.systemInstruction.parts[0].text.includes('AVAILABLE TOOLS:'));
    assert.equal(interceptedBody.contents[0].parts[0].text, 'TASK GOAL:\nLegacy goal without context');

    // 2. Legacy 3-argument call with context string
    await provider.generatePlan('Legacy goal with context', [], 'Extra historical context string');
    assert.ok(interceptedBody.contents[0].parts[0].text.includes('TASK GOAL:\nLegacy goal with context'));
    assert.ok(interceptedBody.contents[0].parts[0].text.includes('ADDITIONAL CONTEXT / ARTIFACTS:\nExtra historical context string'));
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('GeminiProvider - generatePlan ignores legacy context argument when pre-compiled prompt is provided', async () => {
  const originalFetch = globalThis.fetch;
  let interceptedBody: any;

  globalThis.fetch = (async (_url: string | URL | Request, init?: RequestInit) => {
    interceptedBody = JSON.parse(init?.body as string);
    return {
      ok: true,
      status: 200,
      json: async () => ({
        candidates: [{ content: { parts: [{ text: JSON.stringify({ steps: [] }) }] } }],
        usageMetadata: { promptTokenCount: 10, candidatesTokenCount: 10, totalTokenCount: 20 }
      })
    } as Response;
  }) as typeof globalThis.fetch;

  try {
    const provider = new GeminiProvider({ apiKey: 'test-api-key' });
    const compiledPrompt = {
      systemInstruction: 'Compiled instruction',
      userPrompt: 'TASK GOAL:\nGoal with compiled prompt',
      contextOmitted: false,
      contextIncluded: true
    };

    // Even if raw context string was passed as 3rd arg alongside compiledPrompt
    await provider.generatePlan('Goal with compiled prompt', [], 'raw-unscrubbed-context' as any, compiledPrompt);

    assert.equal(interceptedBody.systemInstruction.parts[0].text, 'Compiled instruction');
    assert.equal(interceptedBody.contents[0].parts[0].text, 'TASK GOAL:\nGoal with compiled prompt');
    assert.ok(!JSON.stringify(interceptedBody).includes('raw-unscrubbed-context'));
  } finally {
    globalThis.fetch = originalFetch;
  }
});
