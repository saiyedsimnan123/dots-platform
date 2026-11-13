/**
 * Next-Generation Dots AI Platform - Web Tools Unit & Security Tests
 * Milestone 1B: Secure Web Search & Web Fetch Verification Suite
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type Server } from 'node:http';
import { resolve } from 'node:path';
import {
  webSearchTool,
  webFetchTool,
  webTools,
  setWebSearchProvider,
  getWebSearchProvider,
  MockWebSearchProvider,
  safeFetch,
  isPrivateOrReservedIp,
  isBlockedHostname,
  isSupportedContentType,
  extractHtmlText
} from '../../src/tools/web-tools.ts';
import { ToolRegistry } from '../../src/tools/registry.ts';
import { PolicyEngine } from '../../src/security/policy-engine.ts';
import { ApprovalBroker } from '../../src/security/approval-broker.ts';
import { DatabaseManager } from '../../src/storage/db.ts';
import { TaskRepository } from '../../src/storage/task-repository.ts';
import {
  ValidationError,
  SecurityViolationError,
  ToolExecutionError
} from '../../src/domain/errors.ts';

const testWorkspace = resolve('test_web_tools_workspace');

// --- Helper: Ephemeral Local Test Server ---

interface TestServerContext {
  readonly server: Server;
  readonly port: number;
  readonly url: string;
  readonly close: () => Promise<void>;
}

async function startEphemeralServer(): Promise<TestServerContext> {
  return new Promise((resolveServer, rejectServer) => {
    const server = createServer((req, res) => {
      const url = new URL(req.url || '/', 'http://127.0.0.1');

      if (url.pathname === '/html') {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(`
          <!DOCTYPE html>
          <html>
            <head>
              <title>Safe Public Article &amp; Insights</title>
              <style>body { background: #fff; }</style>
            </head>
            <body>
              <header><h1>Welcome to Dots Platform</h1></header>
              <script>alert('malicious_eval');</script>
              <p>Autonomous AI runtime with verified evidence.</p>
              <p>Second paragraph with &lt;entities&gt; and &quot;quotes&quot;.</p>
            </body>
          </html>
        `);
        return;
      }

      if (url.pathname === '/json') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'ok', items: [1, 2, 3] }));
        return;
      }

      if (url.pathname === '/secret-leak') {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end('System diagnostic: AIzaSyFakeGoogleKey12345678901234567890 is present.');
        return;
      }

      if (url.pathname === '/binary-image') {
        res.writeHead(200, { 'Content-Type': 'image/png' });
        res.end(Buffer.from([0x89, 0x50, 0x4e, 0x47]));
        return;
      }

      if (url.pathname === '/binary-stream') {
        res.writeHead(200, { 'Content-Type': 'application/octet-stream' });
        res.end(Buffer.from('binary-data'));
        return;
      }

      if (url.pathname === '/oversized') {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end('A'.repeat(5000));
        return;
      }

      if (url.pathname === '/oversized-header') {
        res.writeHead(200, {
          'Content-Type': 'text/plain',
          'Content-Length': '104857600' // 100 MiB
        });
        res.end('small');
        return;
      }

      if (url.pathname === '/hanging-timeout') {
        // Intentionally never finish response to trigger client timeout
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.write('part...');
        return;
      }

      if (url.pathname === '/redirect-to-private') {
        res.writeHead(302, { Location: 'http://169.254.169.254/latest/meta-data/' });
        res.end();
        return;
      }

      if (url.pathname === '/redirect-to-file') {
        res.writeHead(302, { Location: 'file:///etc/passwd' });
        res.end();
        return;
      }

      if (url.pathname === '/redirect-loop') {
        res.writeHead(302, { Location: '/redirect-loop' });
        res.end();
        return;
      }

      if (url.pathname === '/redirect-valid') {
        res.writeHead(302, { Location: '/html' });
        res.end();
        return;
      }

      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Not found');
    });

    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      if (typeof addr === 'object' && addr) {
        const port = addr.port;
        resolveServer({
          server,
          port,
          url: `http://127.0.0.1:${port}`,
          close: async () => {
            await new Promise<void>((r) => server.close(() => r()));
          }
        });
      } else {
        rejectServer(new Error('Failed to bind server address'));
      }
    });
  });
}

// ============================================================================
// 1. Web Search Tests
// ============================================================================

test('web_search - throws ToolExecutionError when provider is not configured', async () => {
  setWebSearchProvider(null);

  await assert.rejects(
    async () => {
      await webSearchTool.handler(
        { query: 'test query' },
        { taskId: 't1', stepId: 's1', workspaceRoot: testWorkspace }
      );
    },
    (err: unknown) => {
      assert.ok(err instanceof ToolExecutionError);
      assert.equal((err as ToolExecutionError).toolName, 'web_search');
      assert.ok((err as ToolExecutionError).message.includes('Web search provider is not configured'));
      return true;
    }
  );
});

test('web_search - rejects empty or invalid query arguments', async () => {
  const mock = new MockWebSearchProvider();
  setWebSearchProvider(mock);

  try {
    await assert.rejects(
      async () => {
        await webSearchTool.handler(
          { query: '' },
          { taskId: 't1', stepId: 's1', workspaceRoot: testWorkspace }
        );
      },
      (err: unknown) => {
        assert.ok(err instanceof ValidationError);
        assert.ok((err as ValidationError).message.includes('non-empty string'));
        return true;
      }
    );

    await assert.rejects(
      async () => {
        await webSearchTool.handler(
          { query: 'valid', limit: -5 },
          { taskId: 't1', stepId: 's1', workspaceRoot: testWorkspace }
        );
      },
      (err: unknown) => {
        assert.ok(err instanceof ValidationError);
        assert.ok((err as ValidationError).message.includes('positive integer'));
        return true;
      }
    );
  } finally {
    setWebSearchProvider(null);
  }
});

test('web_search - executes structured search via MockWebSearchProvider and honors limits', async () => {
  const mock = new MockWebSearchProvider('custom-test-search');
  mock.registerResults('dots platform', [
    {
      title: 'Dots AI Platform',
      url: 'https://dots.dev/docs',
      snippet: 'Secure, durable, provider-independent agent runtime.',
      domain: 'dots.dev'
    },
    {
      title: 'GitHub - dots-platform',
      url: 'https://github.com/dots/dots-platform',
      snippet: 'Next-Generation AI Platform repository.',
      domain: 'github.com'
    },
    {
      title: 'Dots Architecture Overview',
      url: 'https://dots.dev/architecture',
      snippet: 'Modular monolith with transactional persistence.',
      domain: 'dots.dev'
    }
  ]);
  setWebSearchProvider(mock);

  try {
    // Request with limit = 2
    const result = await webSearchTool.handler(
      { query: 'dots platform', limit: 2 },
      { taskId: 't1', stepId: 's1', workspaceRoot: testWorkspace }
    );

    assert.equal(result.exitCode, 0);
    const out = result.output as any;
    assert.equal(out.query, 'dots platform');
    assert.equal(out.provider, 'custom-test-search');
    assert.equal(out.count, 2);
    assert.equal(out.results.length, 2);
    assert.equal(out.results[0].title, 'Dots AI Platform');
    assert.equal(out.results[0].domain, 'dots.dev');
    assert.equal(out.results[1].title, 'GitHub - dots-platform');
    assert.equal(out.results[1].domain, 'github.com');
  } finally {
    setWebSearchProvider(null);
  }
});

test('web_search - scrubs secrets from search queries, titles, and snippets', async () => {
  const mock = new MockWebSearchProvider();
  mock.setDefaultResults([
    {
      title: 'Found key: sk-proj-12345678901234567890123456789012',
      url: 'https://example.com/item',
      snippet: 'Authorization: Bearer mySecretToken12345',
      domain: 'example.com'
    }
  ]);
  setWebSearchProvider(mock);

  try {
    const result = await webSearchTool.handler(
      { query: 'search with ghp_fakeGitHubToken1234567890123456789012345678' },
      { taskId: 't1', stepId: 's1', workspaceRoot: testWorkspace }
    );

    const out = result.output as any;
    assert.ok(!out.query.includes('ghp_fakeGitHubToken'));
    assert.ok(out.query.includes('[REDACTED_GITHUB_TOKEN]'));

    assert.ok(!out.results[0].title.includes('sk-proj-'));
    assert.ok(out.results[0].title.includes('[REDACTED_OPENAI_API_KEY]'));

    assert.ok(!out.results[0].snippet.includes('mySecretToken12345'));
    assert.ok(out.results[0].snippet.includes('Bearer [REDACTED_TOKEN]'));
  } finally {
    setWebSearchProvider(null);
  }
});

// ============================================================================
// 2. Web Fetch Security: URL Scheme & SSRF Blocklist Tests
// ============================================================================

test('web_fetch - successfully performs safe fetch on public HTTP and HTTPS destinations', async () => {
  try {
    const res = await safeFetch('https://example.com', {
      extractText: true,
      timeoutMs: 10_000
    });

    assert.equal(res.status, 200);
    assert.equal(res.title, 'Example Domain');
    assert.ok(res.content.includes('Example Domain'));
    assert.ok(res.byteSize > 0);
    assert.ok(res.durationMs >= 0);
  } catch (err) {
    // If running in an air-gapped environment without external DNS, skip gracefully
    if (err instanceof ToolExecutionError && err.message.includes('DNS')) {
      return;
    }
    throw err;
  }
});

test('web_fetch - strictly blocks invalid URL schemes', async () => {
  const illegalUrls = [
    'file:///etc/passwd',
    'file:///C:/Windows/System32/cmd.exe',
    'gopher://127.0.0.1:70/',
    'ftp://public.mirror.org/files',
    'data:text/html,<h1>Hello</h1>',
    'javascript:alert(1)',
    'ws://echo.websocket.org'
  ];

  for (const rawUrl of illegalUrls) {
    await assert.rejects(
      async () => {
        await safeFetch(rawUrl);
      },
      (err: unknown) => {
        assert.ok(err instanceof SecurityViolationError);
        assert.equal((err as SecurityViolationError).violationType, 'UNSUPPORTED_PROTOCOL');
        return true;
      }
    );
  }
});

test('web_fetch - strictly blocks localhost, loopback, and private IP destinations', async () => {
  const blockedDestinations = [
    'http://localhost',
    'http://localhost:8080',
    'http://sub.localhost',
    'http://127.0.0.1',
    'http://127.0.0.1:3000',
    'http://127.1.2.3',
    'http://0.0.0.0',
    'http://[::1]',
    'http://[::ffff:127.0.0.1]',
    'http://2130706433', // Dword integer 127.0.0.1
    'http://0177.0.0.1', // Octal 127.0.0.1
    'http://10.0.0.1',
    'http://10.255.255.254',
    'http://172.16.0.1',
    'http://172.31.255.255',
    'http://192.168.1.1',
    'http://192.168.0.254',
    'http://[fc00::1]',
    'http://[fd12:3456::1]'
  ];

  for (const rawUrl of blockedDestinations) {
    await assert.rejects(
      async () => {
        await safeFetch(rawUrl);
      },
      (err: unknown) => {
        assert.ok(err instanceof SecurityViolationError);
        assert.equal((err as SecurityViolationError).violationType, 'SSRF_DESTINATION_BLOCKED');
        return true;
      }
    );
  }
});

test('web_fetch - strictly blocks cloud metadata and link-local destinations', async () => {
  const metadataDestinations = [
    'http://169.254.169.254/latest/meta-data/',
    'http://169.254.169.254/computeMetadata/v1/',
    'http://169.254.170.2/v2/metadata', // AWS ECS
    'http://100.100.100.100/', // Alibaba Cloud
    'http://169.254.1.1/',
    'http://[fe80::1]/', // IPv6 Link-Local
    'http://metadata.google.internal/computeMetadata/v1/',
    'http://metadata/',
    'http://instance-data/'
  ];

  for (const rawUrl of metadataDestinations) {
    await assert.rejects(
      async () => {
        await safeFetch(rawUrl);
      },
      (err: unknown) => {
        assert.ok(err instanceof SecurityViolationError);
        assert.equal((err as SecurityViolationError).violationType, 'SSRF_DESTINATION_BLOCKED');
        return true;
      }
    );
  }
});

// ============================================================================
// 3. DNS Rebinding Immunity & Redirect Safety
// ============================================================================

test('web_fetch - blocks hostnames that resolve to private or metadata IP addresses via DNS', async () => {
  // Simulates domain resolving to AWS metadata service IP
  await assert.rejects(
    async () => {
      await safeFetch('http://malicious-rebinding-domain.com/secret', {
        dnsLookup: async () => [{ address: '169.254.169.254', family: 4 }]
      });
    },
    (err: unknown) => {
      assert.ok(err instanceof SecurityViolationError);
      assert.equal((err as SecurityViolationError).violationType, 'SSRF_DESTINATION_BLOCKED');
      assert.ok((err as SecurityViolationError).message.includes('169.254.169.254'));
      return true;
    }
  );

  // Simulates domain resolving to a mixed list containing loopback
  await assert.rejects(
    async () => {
      await safeFetch('http://mixed-records-domain.com/test', {
        dnsLookup: async () => [
          { address: '93.184.216.34', family: 4 },
          { address: '127.0.0.1', family: 4 }
        ]
      });
    },
    (err: unknown) => {
      assert.ok(err instanceof SecurityViolationError);
      assert.equal((err as SecurityViolationError).violationType, 'SSRF_DESTINATION_BLOCKED');
      assert.ok((err as SecurityViolationError).message.includes('127.0.0.1'));
      return true;
    }
  );
});

test('web_fetch - revalidates every redirect hop and blocks redirects to prohibited destinations', async () => {
  const testServer = await startEphemeralServer();

  try {
    // 1. Redirect to private/cloud metadata
    await assert.rejects(
      async () => {
        await safeFetch(`${testServer.url}/redirect-to-private`, {
          _allowLoopbackForTesting: true // Allows first hop to test server; second hop to 169.254 must fail!
        });
      },
      (err: unknown) => {
        assert.ok(err instanceof SecurityViolationError);
        assert.equal((err as SecurityViolationError).violationType, 'SSRF_DESTINATION_BLOCKED');
        return true;
      }
    );

    // 2. Redirect to file:/// scheme
    await assert.rejects(
      async () => {
        await safeFetch(`${testServer.url}/redirect-to-file`, {
          _allowLoopbackForTesting: true
        });
      },
      (err: unknown) => {
        assert.ok(err instanceof SecurityViolationError);
        assert.equal((err as SecurityViolationError).violationType, 'UNSUPPORTED_PROTOCOL');
        return true;
      }
    );

    // 3. Infinite redirect loop
    await assert.rejects(
      async () => {
        await safeFetch(`${testServer.url}/redirect-loop`, {
          _allowLoopbackForTesting: true,
          maxRedirects: 3
        });
      },
      (err: unknown) => {
        assert.ok(err instanceof ValidationError);
        assert.ok((err as ValidationError).message.includes('redirect depth'));
        return true;
      }
    );

    // 4. Valid redirect follows to /html and succeeds
    const validRedirect = await safeFetch(`${testServer.url}/redirect-valid`, {
      _allowLoopbackForTesting: true
    });
    assert.equal(validRedirect.status, 200);
    assert.ok(validRedirect.finalUrl.endsWith('/html'));
    assert.equal(validRedirect.title, 'Safe Public Article & Insights');
  } finally {
    await testServer.close();
  }
});

// ============================================================================
// 4. Content-Type, Size Limits & Timeouts
// ============================================================================

test('web_fetch - rejects unsupported binary content types', async () => {
  const testServer = await startEphemeralServer();

  try {
    await assert.rejects(
      async () => {
        await safeFetch(`${testServer.url}/binary-image`, {
          _allowLoopbackForTesting: true
        });
      },
      (err: unknown) => {
        assert.ok(err instanceof ValidationError);
        assert.ok((err as ValidationError).message.includes('image/png'));
        return true;
      }
    );

    await assert.rejects(
      async () => {
        await safeFetch(`${testServer.url}/binary-stream`, {
          _allowLoopbackForTesting: true
        });
      },
      (err: unknown) => {
        assert.ok(err instanceof ValidationError);
        assert.ok((err as ValidationError).message.includes('application/octet-stream'));
        return true;
      }
    );
  } finally {
    await testServer.close();
  }
});

test('web_fetch - enforces response size limits (streaming truncation and Content-Length)', async () => {
  const testServer = await startEphemeralServer();

  try {
    // 1. Content-Length check
    await assert.rejects(
      async () => {
        await safeFetch(`${testServer.url}/oversized-header`, {
          _allowLoopbackForTesting: true,
          maxBytes: 1024
        });
      },
      (err: unknown) => {
        assert.ok(err instanceof ValidationError);
        assert.ok((err as ValidationError).message.includes('Content-Length'));
        return true;
      }
    );

    // 2. Stream chunk accumulation limit
    await assert.rejects(
      async () => {
        await safeFetch(`${testServer.url}/oversized`, {
          _allowLoopbackForTesting: true,
          maxBytes: 500
        });
      },
      (err: unknown) => {
        assert.ok(err instanceof ValidationError);
        assert.ok((err as ValidationError).message.includes('exceeded maximum limit of 500 bytes'));
        return true;
      }
    );
  } finally {
    await testServer.close();
  }
});

test('web_fetch - aborts and throws on request timeout', async () => {
  const testServer = await startEphemeralServer();

  try {
    await assert.rejects(
      async () => {
        await safeFetch(`${testServer.url}/hanging-timeout`, {
          _allowLoopbackForTesting: true,
          timeoutMs: 300 // Short 300ms timeout for test
        });
      },
      (err: unknown) => {
        assert.ok(err instanceof ToolExecutionError);
        assert.ok((err as ToolExecutionError).message.includes('timed out'));
        return true;
      }
    );
  } finally {
    await testServer.close();
  }
});

// ============================================================================
// 5. HTML Parsing, Text Extraction & Secret Scrubbing
// ============================================================================

test('web_fetch - correctly extracts title, strips scripts/styles, and returns clean text', async () => {
  const testServer = await startEphemeralServer();

  try {
    const res = await safeFetch(`${testServer.url}/html`, {
      _allowLoopbackForTesting: true,
      extractText: true
    });

    assert.equal(res.status, 200);
    assert.equal(res.title, 'Safe Public Article & Insights');
    assert.ok(!res.content.includes('<script>'));
    assert.ok(!res.content.includes('malicious_eval'));
    assert.ok(!res.content.includes('background: #fff'));
    assert.ok(res.content.includes('Welcome to Dots Platform'));
    assert.ok(res.content.includes('Autonomous AI runtime with verified evidence.'));
    assert.ok(res.content.includes('entities> and "quotes"'));
  } finally {
    await testServer.close();
  }
});

test('web_fetch - automatically scrubs API keys and secrets from fetched content', async () => {
  const testServer = await startEphemeralServer();

  try {
    const res = await safeFetch(`${testServer.url}/secret-leak`, {
      _allowLoopbackForTesting: true
    });

    assert.equal(res.status, 200);
    assert.ok(!res.content.includes('AIzaSyFakeGoogleKey'));
    assert.ok(res.content.includes('[REDACTED_GOOGLE_API_KEY]'));
  } finally {
    await testServer.close();
  }
});

// ============================================================================
// 6. Policy Engine, Risk Tier (Tier 3) & Approval Enforcement Integration
// ============================================================================

test('ToolRegistry & PolicyEngine - web_search and web_fetch are Tier 3 and require approval', async () => {
  const db = new DatabaseManager(':memory:');
  const taskRepo = new TaskRepository(db);
  const approvalBroker = new ApprovalBroker(taskRepo);
  const registry = new ToolRegistry();
  const policyEngine = new PolicyEngine({ workspaceRoot: testWorkspace });

  // 1. Verify tools are registered with Risk Tier 3
  const searchToolDef = registry.get('web_search');
  assert.ok(searchToolDef);
  assert.equal(searchToolDef.riskTier, 'TIER_3');

  const fetchToolDef = registry.get('web_fetch');
  assert.ok(fetchToolDef);
  assert.equal(fetchToolDef.riskTier, 'TIER_3');

  // 2. Policy evaluation must flag REQUIRES_APPROVAL
  const searchPolicy = policyEngine.evaluate('web_search', { query: 'test' }, 'TIER_3');
  assert.equal(searchPolicy.decision, 'REQUIRES_APPROVAL');
  assert.equal(searchPolicy.approvalRequired, true);

  const fetchPolicy = policyEngine.evaluate('web_fetch', { url: 'https://example.com' }, 'TIER_3');
  assert.equal(fetchPolicy.decision, 'REQUIRES_APPROVAL');
  assert.equal(fetchPolicy.approvalRequired, true);

  // 3. Execution without approval token is rejected with APPROVAL_REQUIRED
  await assert.rejects(
    async () => {
      await registry.execute(
        'web_search',
        { query: 'test' },
        { taskId: 'task-1', stepId: 'step-1', workspaceRoot: testWorkspace },
        policyEngine
      );
    },
    (err: unknown) => {
      assert.ok(err instanceof SecurityViolationError);
      assert.equal((err as SecurityViolationError).violationType, 'APPROVAL_REQUIRED');
      return true;
    }
  );

  // 4. Execution with valid approval token is permitted
  const mockProvider = new MockWebSearchProvider();
  mockProvider.setDefaultResults([{ title: 'T1', url: 'https://dots.dev', snippet: 'S1', domain: 'dots.dev' }]);
  setWebSearchProvider(mockProvider);

  try {
    const task = taskRepo.createTask({ goal: 'Search web' });
    const step = taskRepo.createStep({
      taskId: task.id,
      stepOrder: 1,
      description: 'Run web search',
      toolName: 'web_search',
      toolArguments: { query: 'test' }
    });

    const approval = approvalBroker.requestApproval({
      taskId: task.id,
      stepId: step.id,
      riskTier: 'TIER_3',
      actionSummary: 'Execute web search',
      targetResource: 'web_search',
      parameterDiff: { query: 'test' }
    });

    approvalBroker.submitDecision(approval.approvalToken, 'APPROVED', 'admin-user');

    const execResult = await registry.execute(
      'web_search',
      { query: 'test' },
      { taskId: task.id, stepId: step.id, workspaceRoot: testWorkspace },
      policyEngine,
      approvalBroker,
      approval.approvalToken
    );

    assert.equal(execResult.exitCode, 0);
    const out = execResult.output as any;
    assert.equal(out.count, 1);
    assert.equal(out.results[0].title, 'T1');
  } finally {
    setWebSearchProvider(null);
  }
});
