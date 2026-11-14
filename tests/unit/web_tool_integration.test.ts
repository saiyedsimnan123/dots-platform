/**
 * Next-Generation Dots AI Platform - Milestone 2C Unit Tests
 * Verification of Web Search Providers, Security Controls, and Agent Tool Context
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  DuckDuckGoSearchProvider,
  SearxngSearchProvider,
  createConfiguredWebSearchProvider,
  webSearchTool,
  setWebSearchProvider,
  isPrivateOrReservedIp,
  isLoopbackIp,
  validateTargetUrl,
  isSupportedContentType
} from '../../src/tools/web-tools.ts';
import { ToolRegistry } from '../../src/tools/registry.ts';
import { standardTools } from '../../src/tools/sandbox-tools.ts';
import { PolicyEngine } from '../../src/security/policy-engine.ts';
import { createAgentExecutionContext, scrubAndBoundOutput } from '../../src/agents/context.ts';
import {
  AgentCancelledError,
  ToolExecutionError,
  ValidationError
} from '../../src/domain/errors.ts';
import type { CallerContext } from '../../src/domain/types.ts';

const testCaller: CallerContext = {
  actor: 'USER',
  scope: { scopeType: 'WORKSPACE', scopeId: 'ws-unit-test' },
  permissions: ['READ', 'WRITE']
};

test('DuckDuckGoSearchProvider - parses structured Instant Answer response correctly', async () => {
  const mockFetcher = async () => ({
    url: 'https://api.duckduckgo.com/?q=dots&format=json',
    finalUrl: 'https://api.duckduckgo.com/?q=dots&format=json',
    status: 200,
    contentType: 'application/x-javascript',
    byteSize: 1024,
    durationMs: 10,
    title: '',
    content: JSON.stringify({
      Heading: 'Dots AI Platform',
      Abstract: 'Dots is an autonomous agent platform with verified evidence.',
      AbstractURL: 'https://dots.dev',
      Results: [
        {
          Text: 'Dots Documentation - Comprehensive guides',
          FirstURL: 'https://docs.dots.dev'
        }
      ],
      RelatedTopics: [
        {
          Text: 'Agent Architecture - Modular and secure',
          FirstURL: 'https://dots.dev/agents'
        },
        {
          Name: 'Advanced',
          Topics: [
            {
              Text: 'Deterministic Verification Subsystem',
              FirstURL: 'https://dots.dev/verifier'
            }
          ]
        }
      ]
    })
  });

  const provider = new DuckDuckGoSearchProvider({
    fetchFn: mockFetcher as any
  });

  const response = await provider.search('dots ai', 5);
  assert.equal(response.results.length, 4);

  // 1st result: Abstract
  assert.equal(response.results[0].title, 'Dots AI Platform');
  assert.equal(response.results[0].url, 'https://dots.dev/');
  assert.ok(response.results[0].snippet.includes('autonomous agent platform'));
  assert.equal(response.results[0].domain, 'dots.dev');

  // 2nd result: Results[0]
  assert.equal(response.results[1].url, 'https://docs.dots.dev/');

  // 3rd result: RelatedTopics[0]
  assert.equal(response.results[2].url, 'https://dots.dev/agents');

  // 4th result: Nested Topics[0]
  assert.equal(response.results[3].url, 'https://dots.dev/verifier');
});

test('DuckDuckGoSearchProvider - respects limit and handles empty/malformed responses', async () => {
  const emptyFetcher = async () => ({
    url: 'https://api.duckduckgo.com',
    finalUrl: 'https://api.duckduckgo.com',
    status: 200,
    contentType: 'application/json',
    byteSize: 2,
    durationMs: 5,
    title: '',
    content: JSON.stringify({})
  });

  const emptyProvider = new DuckDuckGoSearchProvider({
    fetchFn: emptyFetcher as any
  });

  const emptyResponse = await emptyProvider.search('nonexistent', 5);
  assert.deepEqual(emptyResponse.results, []);

  // Respects limit
  const multiFetcher = async () => ({
    url: 'https://api.duckduckgo.com',
    finalUrl: 'https://api.duckduckgo.com',
    status: 200,
    contentType: 'application/json',
    byteSize: 500,
    durationMs: 5,
    title: '',
    content: JSON.stringify({
      Abstract: 'Main abstract',
      AbstractURL: 'https://main.example.com',
      Results: [
        { Text: 'R1', FirstURL: 'https://r1.example.com' },
        { Text: 'R2', FirstURL: 'https://r2.example.com' },
        { Text: 'R3', FirstURL: 'https://r3.example.com' }
      ]
    })
  });

  const multiProvider = new DuckDuckGoSearchProvider({
    fetchFn: multiFetcher as any
  });

  const limitedResponse = await multiProvider.search('test', 2);
  assert.equal(limitedResponse.results.length, 2);

  // Throws on fetch failure
  const errorFetcher = async () => {
    throw new Error('500 Internal Server Error');
  };

  const errorProvider = new DuckDuckGoSearchProvider({
    fetchFn: errorFetcher as any
  });

  await assert.rejects(
    async () => errorProvider.search('fail', 5),
    (err: unknown) => {
      assert.ok(err instanceof ToolExecutionError);
      assert.ok(err.message.includes('500'));
      return true;
    }
  );
});

test('SearxngSearchProvider - parses standard SearXNG JSON API response', async () => {
  const mockFetcher = async (url: string) => {
    assert.ok(url.startsWith('https://search.example.internal'));
    return {
      url,
      finalUrl: url,
      status: 200,
      contentType: 'application/json',
      byteSize: 500,
      durationMs: 10,
      title: '',
      content: JSON.stringify({
        query: 'dots platform',
        number_of_results: 2,
        results: [
          {
            title: 'Dots Platform Home',
            url: 'https://dots.dev',
            content: 'Next-gen verified agent platform.'
          },
          {
            title: 'Dots Platform GitHub',
            url: 'https://github.com/dots/dots',
            content: 'Source code and documentation.'
          }
        ]
      })
    };
  };

  const provider = new SearxngSearchProvider({
    baseUrl: 'https://search.example.internal',
    fetchFn: mockFetcher as any
  });

  const response = await provider.search('dots platform', 10);
  assert.equal(response.results.length, 2);
  assert.equal(response.results[0].title, 'Dots Platform Home');
  assert.equal(response.results[0].url, 'https://dots.dev/');
  assert.equal(response.results[0].snippet, 'Next-gen verified agent platform.');
  assert.equal(response.results[0].domain, 'dots.dev');
  assert.equal(response.results[1].domain, 'github.com');
});

test('SearxngSearchProvider - handles missing results array and HTTP errors gracefully', async () => {
  const emptyFetcher = async () => ({
    url: 'https://search.example.org',
    finalUrl: 'https://search.example.org',
    status: 200,
    contentType: 'application/json',
    byteSize: 20,
    durationMs: 5,
    title: '',
    content: JSON.stringify({ query: 'empty' })
  });

  const provider = new SearxngSearchProvider({
    baseUrl: 'https://search.example.org',
    fetchFn: emptyFetcher as any
  });

  await assert.rejects(
    async () => provider.search('empty', 5),
    (err: unknown) => {
      assert.ok(err instanceof ToolExecutionError);
      assert.ok(err.message.includes('missing expected results array'));
      return true;
    }
  );

  const failFetcher = async () => {
    throw new Error('503 Service Unavailable');
  };

  const failProvider = new SearxngSearchProvider({
    baseUrl: 'https://search.example.org',
    fetchFn: failFetcher as any
  });

  await assert.rejects(
    async () => failProvider.search('test', 5),
    (err: unknown) => {
      assert.ok(err instanceof ToolExecutionError);
      assert.ok(err.message.includes('503'));
      return true;
    }
  );
});

test('createConfiguredWebSearchProvider - correctly resolves providers and handles errors', () => {
  const ddg = createConfiguredWebSearchProvider('duckduckgo');
  assert.ok(ddg instanceof DuckDuckGoSearchProvider);

  const none = createConfiguredWebSearchProvider('none');
  assert.equal(none, null);

  const undefinedMode = createConfiguredWebSearchProvider(undefined);
  assert.equal(undefinedMode, null);

  const searxng = createConfiguredWebSearchProvider('searxng', {
    searxngUrl: 'https://searx.example.com'
  });
  assert.ok(searxng instanceof SearxngSearchProvider);

  // Missing URL for searxng throws ValidationError
  assert.throws(
    () => createConfiguredWebSearchProvider('searxng', {}),
    (err: unknown) => {
      assert.ok(err instanceof ValidationError);
      assert.ok(err.message.includes('DOTS_SEARXNG_URL'));
      return true;
    }
  );
});

test('webSearchTool - throws clear actionable error when unconfigured and does not fabricate results', async () => {
  setWebSearchProvider(null);
  try {
    await assert.rejects(
      async () => {
        await webSearchTool.handler({ query: 'quantum computing' }, {
          taskId: 't1',
          stepId: 's1',
          workspaceRoot: process.cwd()
        });
      },
      (err: unknown) => {
        assert.ok(err instanceof ToolExecutionError);
        assert.ok(err.message.includes('Web search provider is not configured'));
        assert.ok(err.message.includes('DOTS_WEB_SEARCH_PROVIDER'));
        return true;
      }
    );
  } finally {
    setWebSearchProvider(null);
  }
});

test('NAT64 IPv4-mapped and IPv4-translated addresses are strictly blocked', () => {
  // RFC 6052 Well-Known Prefix: 64:ff9b::/96
  // 127.0.0.1 in hex is 7f000001 -> 64:ff9b::7f00:1 or 64:ff9b::127.0.0.1
  assert.equal(isLoopbackIp('64:ff9b::7f00:1'), true);
  assert.equal(isPrivateOrReservedIp('64:ff9b::7f00:1'), true);

  // AWS/GCP cloud metadata IP: 169.254.169.254 (a9fe:a9fe)
  assert.equal(isPrivateOrReservedIp('64:ff9b::a9fe:a9fe'), true);

  // Private network 10.0.0.1 (0a00:0001)
  assert.equal(isPrivateOrReservedIp('64:ff9b::a00:1'), true);

  // Private network 192.168.1.1 (c0a8:0101)
  assert.equal(isPrivateOrReservedIp('64:ff9b::c0a8:101'), true);

  // RFC 8215 Local-Use Prefix: 64:ff9b:1::/48
  assert.equal(isPrivateOrReservedIp('64:ff9b:1::7f00:1'), true);
  assert.equal(isPrivateOrReservedIp('64:ff9b:1::a9fe:a9fe'), true);

  // Legitimate public IP through NAT64 (e.g. 8.8.8.8 -> 0808:0808) is not blocked as private
  assert.equal(isPrivateOrReservedIp('64:ff9b::808:808'), false);
  assert.equal(isLoopbackIp('64:ff9b::808:808'), false);
});

test('validateTargetUrl - strips userinfo to prevent credential leakage in HTTP requests', () => {
  const sanitized = validateTargetUrl('https://admin:supersecret@example.com/api/data?query=test#frag');
  assert.equal(sanitized.username, '');
  assert.equal(sanitized.password, '');
  assert.equal(sanitized.hostname, 'example.com');
  assert.equal(sanitized.pathname, '/api/data');
  assert.equal(sanitized.search, '?query=test');
});

test('isSupportedContentType - correctly allows text, json, html and js types, rejects binary', () => {
  assert.equal(isSupportedContentType('text/html; charset=utf-8'), true);
  assert.equal(isSupportedContentType('application/json'), true);
  assert.equal(isSupportedContentType('application/x-javascript'), true);
  assert.equal(isSupportedContentType('application/javascript'), true);
  assert.equal(isSupportedContentType('text/javascript'), true);
  assert.equal(isSupportedContentType('text/plain'), true);

  assert.equal(isSupportedContentType('application/zip'), false);
  assert.equal(isSupportedContentType('image/jpeg'), false);
  assert.equal(isSupportedContentType('application/octet-stream'), false);
});

test('scrubAndBoundOutput - bounds large structures and scrubs secrets', () => {
  // 1. Long string bounding
  const hugeString = 'X'.repeat(60000);
  const boundedString = scrubAndBoundOutput(hugeString) as string;
  assert.ok(boundedString.length < 51000);
  assert.ok(boundedString.endsWith('[output truncated at limit]'));

  // 2. Secret scrubbing in output (Google API key: 39 chars: AIza + 35 chars)
  const secretKey = 'AIzaSyFakeKey12345678901234567890123';
  assert.equal(secretKey.length, 36); // Let's ensure 39 chars: AIza + 35
  const validSecretKey = 'AIzaSyFakeKey12345678901234567890123456'; // 39 chars
  const secretString = `Configuration with secret ${validSecretKey} included`;
  const scrubbedString = scrubAndBoundOutput(secretString) as string;
  assert.ok(!scrubbedString.includes(validSecretKey));
  assert.ok(scrubbedString.includes('[REDACTED_GOOGLE_API_KEY]'));

  // 3. Array bounding
  const hugeArray = Array.from({ length: 300 }, (_, i) => `item-${i}`);
  const boundedArray = scrubAndBoundOutput(hugeArray) as unknown[];
  assert.equal(boundedArray.length, 201);
  assert.ok(String(boundedArray[200]).includes('TRUNCATED'));

  // 4. Object keys bounding
  const hugeObj: Record<string, number> = {};
  for (let i = 0; i < 150; i++) {
    hugeObj[`key_${i}`] = i;
  }
  const boundedObj = scrubAndBoundOutput(hugeObj) as Record<string, unknown>;
  const keys = Object.keys(boundedObj);
  assert.ok(keys.length <= 101);
  assert.equal(boundedObj._truncatedKeysCount, 50);
});

test('createAgentExecutionContext - lists and discovers registered tools correctly', () => {
  const registry = new ToolRegistry(standardTools);
  const policyEngine = new PolicyEngine({ workspaceRoot: process.cwd(), autoApproveTier2: true });

  const context = createAgentExecutionContext({
    taskId: 'task-tool-discovery',
    workspaceRoot: process.cwd(),
    toolRegistry: registry,
    policyEngine,
    agentCaller: testCaller
  });

  const tools = context.listTools();
  assert.ok(tools.length >= 8);

  const toolNames = new Set(tools.map((t) => t.name));
  assert.ok(toolNames.has('file_read'));
  assert.ok(toolNames.has('file_write'));
  assert.ok(toolNames.has('web_fetch'));
  assert.ok(toolNames.has('web_search'));

  const fetchTool = context.getTool('web_fetch');
  assert.ok(fetchTool);
  assert.equal(fetchTool.name, 'web_fetch');
  assert.ok(fetchTool.parameters.url);

  const nonexistent = context.getTool('nonexistent_tool');
  assert.equal(nonexistent, undefined);
});

test('createAgentExecutionContext - aborts immediately on cancellation signal', async () => {
  const registry = new ToolRegistry(standardTools);
  const policyEngine = new PolicyEngine({ workspaceRoot: process.cwd(), autoApproveTier2: true });

  const abortController = new AbortController();
  abortController.abort(); // pre-aborted

  const context = createAgentExecutionContext({
    taskId: 'task-abort',
    workspaceRoot: process.cwd(),
    toolRegistry: registry,
    policyEngine,
    agentCaller: testCaller,
    signal: abortController.signal
  });

  await assert.rejects(
    async () => context.executeTool('calculate', { expression: '1 + 1' }),
    (err: unknown) => {
      assert.ok(err instanceof AgentCancelledError);
      return true;
    }
  );
});

test('createAgentExecutionContext - wraps failures safely in ToolExecutionError', async () => {
  const registry = new ToolRegistry(standardTools);
  registry.register({
    definition: {
      name: 'exploding_tool',
      description: 'Throws unexpected runtime error',
      parameters: {}
    },
    handler: async () => {
      throw new Error('Database connection reset and server failed.');
    },
    riskTier: 'TIER_0'
  });

  const policyEngine = new PolicyEngine({ workspaceRoot: process.cwd(), autoApproveTier2: true });

  const context = createAgentExecutionContext({
    taskId: 'task-safe-error',
    workspaceRoot: process.cwd(),
    toolRegistry: registry,
    policyEngine,
    agentCaller: testCaller
  });

  await assert.rejects(
    async () => context.executeTool('exploding_tool', {}),
    (err: unknown) => {
      assert.ok(err instanceof ToolExecutionError);
      assert.equal(err.toolName, 'exploding_tool');
      assert.ok(err.message.includes('server failed'));
      return true;
    }
  );
});
