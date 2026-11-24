/**
 * Next-Generation Dots AI Platform - Runtime Evidence Verification Activation Tests
 * Phase 4D.3D.4C.3C: Explicit Runtime Opt-In, Provider Readiness, and Health Reporting
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DotsRuntime } from '../../src/runtime/app.ts';
import { loadRuntimeConfig } from '../../src/runtime/config.ts';
import { GeminiProvider } from '../../src/model/gemini-provider.ts';
import { MockModelProvider } from '../../src/model/mock-provider.ts';
import { MockWebSearchProvider, setWebSearchProvider } from '../../src/tools/web-tools.ts';
import { MockAgent } from '../../src/agents/base-agent.ts';
import { AgentRegistry } from '../../src/agents/registry.ts';
import type { IModelProvider } from '../../src/model/types.ts';
import {
  EvidenceVerificationEngine
} from '../../src/memory/evidence-verifier.ts';
import { ValidationError } from '../../src/domain/errors.ts';

const TEST_TOKENS = [
  {
    token: 'runtime-admin-token',
    principalId: 'runtime-admin',
    role: 'ADMIN' as const,
    permittedScopes: [{ scopeType: 'GLOBAL' as const, scopeId: 'default' }]
  }
];

function createScriptedResearchAgent(report: Record<string, unknown>): MockAgent {
  return new MockAgent({
    id: 'research-agent',
    name: 'Scripted Targeted Research Agent',
    description: 'Produces deterministic targeted research reports for runtime verification tests.',
    capabilities: ['research'],
    executeMock: async (input, context) => ({
      agentId: 'research-agent',
      taskId: input.taskId ?? context.taskId,
      status: 'COMPLETED',
      result: { report },
      summary: `Completed targeted research for: ${input.goal}`,
      stepsExecuted: 1,
      durationMs: 1
    })
  });
}

function buildTargetedResearchReport(question: string) {
  return {
    completionStatus: 'COMPLETED',
    researchQuestion: question,
    keyFindings: [
      'PostgreSQL MVCC preserves snapshots for concurrent transactions.'
    ],
    evidenceAndSources: [
      {
        id: 'src-pg-mvcc',
        title: 'PostgreSQL Concurrency Control Docs',
        url: 'https://www.postgresql.org/docs/current/mvcc-intro.html',
        domain: 'www.postgresql.org',
        relationship: 'SUPPORTS',
        targetFindingIndex: 0,
        relevantEvidence: [
          'Each transaction sees a snapshot of data as of transaction start regardless of concurrent writers.'
        ]
      }
    ]
  };
}

function buildEchoModelProvider(
  override: {
    readonly name?: string;
    readonly modelId?: string;
    readonly forceUnavailable?: boolean;
    readonly throwError?: Error;
    readonly returnMalformed?: boolean;
  } = {}
): { provider: IModelProvider; getCompletionCalls: () => number } {
  let completionCalls = 0;

  const provider: IModelProvider = {
    name: override.name ?? 'echo-test-provider',
    modelId: override.modelId ?? 'echo-test-v1',
    isConfigured() {
      return true;
    },
    async isAvailable() {
      return !override.forceUnavailable;
    },
    async generatePlan() {
      return {
        steps: [],
        rawResponse: '{"steps":[]}',
        usage: { promptTokens: 0, completionTokens: 0, totalTokens: 0, estimatedCostUsd: 0 }
      };
    },
    async generateCompletion(messages) {
      completionCalls++;
      if (override.throwError) {
        throw override.throwError;
      }
      if (override.returnMalformed) {
        return {
          content: 'NOT_VALID_JSON_AT_ALL',
          usage: { promptTokens: 10, completionTokens: 5, totalTokens: 15, estimatedCostUsd: 0 }
        };
      }
      const userPrompt = messages.find((m) => m.role === 'user')?.content ?? '';
      const begin = '=== BEGIN UNTRUSTED CLAIM AND EVIDENCE DATA ===';
      const end = '=== END UNTRUSTED CLAIM AND EVIDENCE DATA ===';
      const startIdx = userPrompt.indexOf(begin);
      const endIdx = userPrompt.indexOf(end);
      const parsed = JSON.parse(
        userPrompt.slice(startIdx + begin.length, endIdx).trim()
      ) as {
        claim: { claimId: string };
        evidence: { evidenceId: string };
      };

      return {
        content: JSON.stringify({
          claimId: parsed.claim.claimId,
          evidenceId: parsed.evidence.evidenceId,
          proposedRelationship: 'SUPPORTS',
          outcome: 'PROPOSED',
          confidence: 0.94,
          explanation: 'PostgreSQL MVCC documentation directly confirms snapshot isolation.'
        }),
        usage: { promptTokens: 50, completionTokens: 30, totalTokens: 80, estimatedCostUsd: 0.0001 }
      };
    }
  };

  return {
    provider,
    getCompletionCalls: () => completionCalls
  };
}

// ============================================================================
// 1. Default configuration keeps verification disabled
// ============================================================================
test('1. Default runtime configuration keeps evidence verification disabled and rejects invalid non-boolean values', () => {
  const defaultCfg = loadRuntimeConfig({
    requireTokens: false,
    tokens: TEST_TOKENS,
    env: {}
  });
  assert.equal(defaultCfg.enableEvidenceVerification, false);

  const emptyEnvCfg = loadRuntimeConfig({
    requireTokens: false,
    tokens: TEST_TOKENS,
    env: { DOTS_ENABLE_EVIDENCE_VERIFICATION: '' }
  });
  assert.equal(emptyEnvCfg.enableEvidenceVerification, false);

  // Invalid config strings or non-boolean overrides throw ValidationError and never silently enable
  assert.throws(
    () =>
      loadRuntimeConfig({
        requireTokens: false,
        tokens: TEST_TOKENS,
        env: { DOTS_ENABLE_EVIDENCE_VERIFICATION: 'maybe' }
      }),
    (err) => err instanceof ValidationError
  );
  assert.throws(
    () =>
      loadRuntimeConfig({
        requireTokens: false,
        tokens: TEST_TOKENS,
        enableEvidenceVerification: 'true' as any,
        env: {}
      }),
    (err) => err instanceof ValidationError
  );
  assert.throws(
    () =>
      loadRuntimeConfig({
        requireTokens: false,
        tokens: TEST_TOKENS,
        enableEvidenceVerification: {} as any,
        env: {}
      }),
    (err) => err instanceof ValidationError
  );

  const runtime = new DotsRuntime({
    dbPath: ':memory:',
    tokens: TEST_TOKENS,
    env: {},
    silentLogs: true
  });
  assert.equal(runtime.config.enableEvidenceVerification, false);
  assert.equal(runtime.evidenceVerifier, null);
  assert.equal(runtime.coordinator.enableEvidenceVerification, false);
  assert.equal(runtime.coordinator.evidenceVerifier, undefined);
});

// ============================================================================
// 2. Explicit runtime opt-in enables the feature
// ============================================================================
test('2. Explicit runtime opt-in via override and env enables evidence verification without making live startup calls', () => {
  const envCfg = loadRuntimeConfig({
    requireTokens: false,
    tokens: TEST_TOKENS,
    env: { DOTS_ENABLE_EVIDENCE_VERIFICATION: 'true' }
  });
  assert.equal(envCfg.enableEvidenceVerification, true);

  const mockProvider = new MockModelProvider('opt-in-model');
  const runtime = new DotsRuntime({
    dbPath: ':memory:',
    tokens: TEST_TOKENS,
    env: {},
    enableEvidenceVerification: true,
    modelProvider: mockProvider,
    silentLogs: true
  });

  assert.equal(runtime.config.enableEvidenceVerification, true);
  assert.ok(runtime.evidenceVerifier instanceof EvidenceVerificationEngine);
  assert.equal(runtime.coordinator.enableEvidenceVerification, true);
  assert.equal(runtime.coordinator.evidenceVerifier, runtime.evidenceVerifier);
  // Zero live API calls made during runtime construction or health check
  assert.equal(mockProvider.getRecordedCalls().length, 0);

  const envRuntime = new DotsRuntime({
    dbPath: ':memory:',
    tokens: TEST_TOKENS,
    env: { DOTS_ENABLE_EVIDENCE_VERIFICATION: '1' },
    modelProvider: new MockModelProvider('env-opt-in-model'),
    silentLogs: true
  });
  assert.equal(envRuntime.config.enableEvidenceVerification, true);
  assert.ok(envRuntime.evidenceVerifier !== null);
  assert.equal(envRuntime.coordinator.enableEvidenceVerification, true);
});

// ============================================================================
// 3. Configuration reaches TaskCoordinator and the verification pipeline
// ============================================================================
test('3. Runtime opt-in flows from DotsRuntime through TaskCoordinator into KnowledgeProposalPipeline', async () => {
  const { provider, getCompletionCalls } = buildEchoModelProvider();
  const registry = new AgentRegistry();
  registry.register(
    createScriptedResearchAgent(
      buildTargetedResearchReport('PostgreSQL MVCC snapshot isolation')
    )
  );

  const runtime = new DotsRuntime({
    dbPath: ':memory:',
    tokens: TEST_TOKENS,
    env: {},
    enableEvidenceVerification: true,
    modelProvider: provider,
    agentRegistry: registry,
    silentLogs: true
  });

  await runtime.start();
  try {
    const { caller } = runtime.authenticateUser('runtime-admin-token');
    const output = await runtime.coordinator.executeAgent('research-agent', {
      goal: 'Verify PostgreSQL MVCC snapshot isolation',
      caller
    });

    assert.equal(output.status, 'COMPLETED');
    assert.equal(getCompletionCalls(), 1, 'Enabled runtime must invoke verification model once');

    const claims = runtime.memoryService.listClaims(caller, {});
    assert.equal(claims.length, 1);

    const verifications = runtime.memoryService.getClaimVerificationsByClaimId(caller, claims[0]!.id);
    assert.equal(verifications.length, 1);
    assert.equal(verifications[0]!.proposedRelationship, 'SUPPORTS');
    assert.equal(verifications[0]!.verificationOutcome, 'PROPOSED');
    assert.equal(verifications[0]!.verifierId, 'echo-test-provider');

    const proposals = runtime.memoryService.listMemories(caller, { status: 'PENDING_APPROVAL' });
    assert.equal(proposals.length, 1);
    assert.equal(proposals[0]!.status, 'PENDING_APPROVAL', 'Verification never auto-approves proposal');
  } finally {
    await runtime.stop();
  }
});

// ============================================================================
// 4. Explicit opt-out prevents verification from running
// ============================================================================
test('4. Explicit opt-out keeps verification inactive even if provider or custom verifier is supplied', async () => {
  const { provider, getCompletionCalls } = buildEchoModelProvider();
  const registry = new AgentRegistry();
  registry.register(
    createScriptedResearchAgent(
      buildTargetedResearchReport('Opt-out isolation test')
    )
  );

  const runtime = new DotsRuntime({
    dbPath: ':memory:',
    tokens: TEST_TOKENS,
    env: { DOTS_ENABLE_EVIDENCE_VERIFICATION: 'true' },
    enableEvidenceVerification: false,
    modelProvider: provider,
    agentRegistry: registry,
    silentLogs: true
  });

  assert.equal(runtime.config.enableEvidenceVerification, false);
  assert.equal(runtime.evidenceVerifier, null);
  assert.equal(runtime.coordinator.enableEvidenceVerification, false);
  assert.equal(runtime.coordinator.evidenceVerifier, undefined);

  const { caller } = runtime.authenticateUser('runtime-admin-token');
  const output = await runtime.coordinator.executeAgent('research-agent', {
    goal: 'Opt-out verification test',
    caller
  });

  assert.equal(output.status, 'COMPLETED');
  assert.equal(getCompletionCalls(), 0, 'Verification must NOT execute when explicitly opted out');

  const proposals = runtime.memoryService.listMemories(caller, { status: 'PENDING_APPROVAL' });
  assert.equal(proposals.length, 1);
  const claims = runtime.memoryService.getClaimsByMemoryId(caller, proposals[0]!.id);
  assert.equal(claims.length, 1);
  assert.equal(runtime.memoryService.getClaimVerificationsByClaimId(caller, claims[0]!.id).length, 0);
});

// ============================================================================
// 5. Missing provider credentials fail safely
// ============================================================================
test('5. Missing provider credentials fail safely at startup and during research without leaking secrets', async () => {
  const originalGeminiKey = process.env.GEMINI_API_KEY;
  delete process.env.GEMINI_API_KEY;

  try {
    const missingKeyGemini = new GeminiProvider({ apiKey: '' });
    const registry = new AgentRegistry();
    registry.register(
      createScriptedResearchAgent(
        buildTargetedResearchReport('Missing credentials safety check')
      )
    );

    let networkCalled = false;
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async () => {
      networkCalled = true;
      throw new Error('Network call must not be made during startup');
    }) as typeof fetch;

    try {
      const runtime = new DotsRuntime({
        dbPath: ':memory:',
        tokens: TEST_TOKENS,
        env: {},
        enableEvidenceVerification: true,
        modelProvider: missingKeyGemini,
        agentRegistry: registry,
        silentLogs: true
      });

      assert.equal(networkCalled, false, 'Zero live HTTP calls permitted on startup');
      assert.equal(runtime.config.enableEvidenceVerification, true);
      assert.equal(runtime.evidenceVerifier, null);

      const health = runtime.getHealth();
      const evHealth = health.evidenceVerification as Record<string, unknown>;
      assert.equal(health.evidenceVerificationEnabled, true);
      assert.equal(health.evidenceVerificationStatus, 'unavailable');
      assert.equal(evHealth.status, 'unavailable');
      assert.equal(evHealth.configured, false);
      assert.equal(evHealth.liveCheckPerformed, false);
      assert.ok(String(evHealth.reason).includes('missing'));

      // Direct engine check also fails closed without network call if constructed directly
      const directEngine = new EvidenceVerificationEngine({
        modelProvider: missingKeyGemini,
        memoryRepo: runtime.memoryRepo,
        authorizer: runtime.authorizer,
        auditRepo: runtime.auditRepo,
        taskRepo: runtime.taskRepo
      });
      assert.equal(directEngine.getOperationalStatus().configured, false);

      // Research task still completes cleanly and submits proposal
      const { caller } = runtime.authenticateUser('runtime-admin-token');
      const output = await runtime.coordinator.executeAgent('research-agent', {
        goal: 'Missing credentials research execution',
        caller
      });
      assert.equal(output.status, 'COMPLETED');
      assert.equal(networkCalled, false);

      const proposals = runtime.memoryService.listMemories(caller, { status: 'PENDING_APPROVAL' });
      assert.equal(proposals.length, 1);
      assert.equal(runtime.memoryService.listClaimVerifications(caller).length, 0);
    } finally {
      globalThis.fetch = originalFetch;
    }
  } finally {
    if (originalGeminiKey !== undefined) {
      process.env.GEMINI_API_KEY = originalGeminiKey;
    }
  }
});

// ============================================================================
// 6. Provider initialization or availability failures are reported accurately
// ============================================================================
test('6. Provider capability gaps, initialization errors, and runtime availability failures are reported accurately and scrub secrets', async () => {
  // 6a. Unsupported provider lacking generateCompletion capability
  const unsupportedProvider = {
    name: 'plan-only-provider',
    modelId: 'plan-only-v1',
    async generatePlan() {
      return {
        steps: [],
        rawResponse: '{"steps":[]}',
        usage: { promptTokens: 0, completionTokens: 0, totalTokens: 0, estimatedCostUsd: 0 }
      };
    }
  } as unknown as IModelProvider;

  const runtimeUnsupported = new DotsRuntime({
    dbPath: ':memory:',
    tokens: TEST_TOKENS,
    env: {},
    enableEvidenceVerification: true,
    modelProvider: unsupportedProvider,
    silentLogs: true
  });

  const unsupportedHealth = runtimeUnsupported.getHealth();
  const unsupportedEv = unsupportedHealth.evidenceVerification as Record<string, unknown>;
  assert.equal(unsupportedHealth.evidenceVerificationStatus, 'unavailable');
  assert.equal(unsupportedEv.configured, false);
  assert.ok(String(unsupportedEv.reason).includes('does not support completion generation'));

  // 6b. Initialization/configuration check throwing an error with embedded credentials gets scrubbed
  const secretLeak = 'AIzaSyTestSecretKey12345678901234567890123';
  const throwingConfigProvider: IModelProvider = {
    name: 'leaky-provider',
    modelId: 'leaky-v1',
    isConfigured() {
      throw new Error(`Init failed for https://api.example.org?key=raw-query-secret-999 with ${secretLeak}`);
    },
    async generatePlan() {
      return {
        steps: [],
        rawResponse: '{"steps":[]}',
        usage: { promptTokens: 0, completionTokens: 0, totalTokens: 0, estimatedCostUsd: 0 }
      };
    },
    async generateCompletion() {
      return {
        content: '',
        usage: { promptTokens: 0, completionTokens: 0, totalTokens: 0, estimatedCostUsd: 0 }
      };
    }
  };

  const runtimeThrowing = new DotsRuntime({
    dbPath: ':memory:',
    tokens: TEST_TOKENS,
    env: {},
    enableEvidenceVerification: true,
    modelProvider: throwingConfigProvider,
    silentLogs: true
  });
  const throwingHealth = JSON.stringify(runtimeThrowing.getHealth());
  assert.equal(throwingHealth.includes(secretLeak), false, 'API keys must never appear in health output');
  assert.equal(throwingHealth.includes('raw-query-secret-999'), false, 'Query key secrets must never appear in health output');
  assert.equal(runtimeThrowing.getHealth().evidenceVerificationStatus, 'unavailable');

  // 6c. Custom broken evidenceVerifier override fails safely without crashing runtime startup
  const brokenVerifierOverride = {
    getOperationalStatus() {
      throw new Error('Verifier backend init failed with Bearer super-secret-bearer-token-xyz');
    },
    async verifyProposalClaims() {
      return [];
    }
  } as unknown as EvidenceVerificationEngine;

  const runtimeBrokenOverride = new DotsRuntime({
    dbPath: ':memory:',
    tokens: TEST_TOKENS,
    env: {},
    enableEvidenceVerification: true,
    evidenceVerifier: brokenVerifierOverride,
    silentLogs: true
  });
  assert.equal(runtimeBrokenOverride.evidenceVerifier, null);
  const brokenHealth = runtimeBrokenOverride.getHealth();
  assert.equal(brokenHealth.evidenceVerificationStatus, 'unavailable');
  assert.equal(JSON.stringify(brokenHealth).includes('super-secret-bearer-token-xyz'), false);

  // 6d. Runtime availability failure (isAvailable returns false at verification time) updates health status
  const { provider: unavailableRuntimeProvider } = buildEchoModelProvider({
    name: 'flaky-runtime-provider',
    forceUnavailable: true
  });
  const registry = new AgentRegistry();
  registry.register(
    createScriptedResearchAgent(
      buildTargetedResearchReport('Runtime availability check')
    )
  );
  const runtimeFlaky = new DotsRuntime({
    dbPath: ':memory:',
    tokens: TEST_TOKENS,
    env: {},
    enableEvidenceVerification: true,
    modelProvider: unavailableRuntimeProvider,
    agentRegistry: registry,
    silentLogs: true
  });
  assert.equal(runtimeFlaky.getHealth().evidenceVerificationStatus, 'configured');

  const { caller } = runtimeFlaky.authenticateUser('runtime-admin-token');
  const output = await runtimeFlaky.coordinator.executeAgent('research-agent', {
    goal: 'Run research when verification provider reports unavailable',
    caller
  });
  assert.equal(output.status, 'COMPLETED');
  assert.equal(runtimeFlaky.getHealth().evidenceVerificationStatus, 'unavailable');
  assert.equal(runtimeFlaky.getHealth().evidenceVerification && (runtimeFlaky.getHealth().evidenceVerification as Record<string, unknown>).liveCheckPerformed, false);
});

// ============================================================================
// 7. Health information distinguishes disabled, configured, and unavailable states
// ============================================================================
test('7. Health output clearly distinguishes disabled, configured, and unavailable states without live checks or sensitive leaks', () => {
  const disabledRuntime = new DotsRuntime({
    dbPath: ':memory:',
    tokens: TEST_TOKENS,
    env: {},
    silentLogs: true
  });
  const disabledHealth = disabledRuntime.getHealth();
  assert.equal(disabledHealth.evidenceVerificationEnabled, false);
  assert.equal(disabledHealth.evidenceVerificationStatus, 'disabled');
  assert.deepEqual(disabledHealth.evidenceVerification, {
    enabled: false,
    status: 'disabled',
    configured: false,
    liveCheckPerformed: false
  });

  const configuredRuntime = new DotsRuntime({
    dbPath: ':memory:',
    tokens: TEST_TOKENS,
    env: {},
    enableEvidenceVerification: true,
    geminiApiKey: 'AIzaSyFakeConfiguredButUntested12345678901234',
    provider: 'gemini',
    silentLogs: true
  });
  const configuredHealth = configuredRuntime.getHealth();
  assert.equal(configuredHealth.evidenceVerificationEnabled, true);
  assert.equal(configuredHealth.evidenceVerificationStatus, 'configured');
  assert.deepEqual(configuredHealth.evidenceVerification, {
    enabled: true,
    status: 'configured',
    configured: true,
    liveCheckPerformed: false,
    provider: 'google-gemini',
    modelId: 'gemini-2.5-flash'
  });
  // Must NEVER expose the Gemini API key in health output or make live calls
  assert.equal(
    JSON.stringify(configuredHealth).includes('AIzaSyFakeConfiguredButUntested12345678901234'),
    false
  );

  const unavailableRuntime = new DotsRuntime({
    dbPath: ':memory:',
    tokens: TEST_TOKENS,
    env: {},
    enableEvidenceVerification: true,
    modelProvider: new GeminiProvider({ apiKey: '' }),
    silentLogs: true
  });
  const unavailableHealth = unavailableRuntime.getHealth();
  assert.equal(unavailableHealth.evidenceVerificationEnabled, true);
  assert.equal(unavailableHealth.evidenceVerificationStatus, 'unavailable');
  const unavailableDetail = unavailableHealth.evidenceVerification as Record<string, unknown>;
  assert.equal(unavailableDetail.enabled, true);
  assert.equal(unavailableDetail.status, 'unavailable');
  assert.equal(unavailableDetail.configured, false);
  assert.equal(unavailableDetail.liveCheckPerformed, false);
});

// ============================================================================
// 8. Disabled verification preserves existing research behavior
// ============================================================================
test('8. Disabled verification preserves standard ResearchAgent workflow, proposals, claims, and approval', async () => {
  const tmpDir = mkdtempSync(join(tmpdir(), 'dots-runtime-ev-disabled-'));
  const mockSearch = new MockWebSearchProvider();
  mockSearch.setDefaultResults([
    {
      title: 'Quantum Key Distribution Standards',
      url: 'https://qkd-standards.example/overview',
      snippet: 'QKD uses quantum mechanics to guarantee secure cryptographic communication. Practical deployment achieved 100km fiber range.',
      domain: 'qkd-standards.example'
    },
    {
      title: 'Post-Quantum Cryptography Migration Guide',
      url: 'https://pqc-guide.example/migration',
      snippet: 'NIST selected lattice-based algorithms for general encryption and digital signatures to counter quantum threats.',
      domain: 'pqc-guide.example'
    }
  ]);

  const mockModel = new MockModelProvider('mock-research-model');
  const runtime = new DotsRuntime({
    dbPath: join(tmpDir, 'test.db'),
    workspaceRoot: tmpDir,
    tokens: TEST_TOKENS,
    env: {},
    modelProvider: mockModel,
    webSearchProvider: mockSearch,
    autoApproveTier2: true,
    autoApproveTier3: true,
    enableScheduler: false,
    silentLogs: true
  });

  try {
    const { caller } = runtime.authenticateUser('runtime-admin-token');
    const output = await runtime.coordinator.executeAgent('research-agent', {
      goal: 'Evaluate Quantum Key Distribution vs Post-Quantum Cryptography',
      caller,
      parameters: { depth: 'standard' }
    });

    assert.equal(output.status, 'COMPLETED');
    assert.equal(mockModel.getRecordedCalls().length, 0);

    const pending = runtime.memoryService.listMemories(caller, { status: 'PENDING_APPROVAL' });
    assert.ok(pending.length >= 1);
    const finding = pending.find((m) => m.key.startsWith('research.finding.'));
    assert.ok(finding);
    assert.ok(runtime.memoryService.getClaimsByMemoryId(caller, finding.id).length >= 1);
    assert.equal(runtime.memoryService.listClaimVerifications(caller).length, 0);

    const approved = runtime.memoryService.decideProposal(caller, {
      memoryId: finding.id,
      decision: 'APPROVE_NEW'
    });
    assert.equal(approved.status, 'ACTIVE');
  } finally {
    setWebSearchProvider(null);
    await runtime.stop();
    rmSync(tmpDir, { recursive: true, force: true });
  }
});

// ============================================================================
// 9. Verification failures do not fail completed research
// ============================================================================
test('9. Verification provider errors and malformed responses do not fail completed research tasks or lose proposals', async () => {
  // 9a. Provider throws HTTP 503 during verification
  const { provider: failingProvider } = buildEchoModelProvider({
    name: 'outage-provider',
    throwError: new Error('Service Unavailable (HTTP 503)')
  });
  const registry503 = new AgentRegistry();
  registry503.register(
    createScriptedResearchAgent(
      buildTargetedResearchReport('Resilience under verification outage')
    )
  );
  const runtime503 = new DotsRuntime({
    dbPath: ':memory:',
    tokens: TEST_TOKENS,
    env: {},
    enableEvidenceVerification: true,
    modelProvider: failingProvider,
    agentRegistry: registry503,
    silentLogs: true
  });

  const { caller: caller503 } = runtime503.authenticateUser('runtime-admin-token');
  const submittedTask = await runtime503.submitTask(caller503, {
    goal: 'Research task during verification outage',
    agentId: 'research-agent'
  });
  const taskResult = await runtime503.runTask(caller503, submittedTask.id);
  assert.equal(taskResult.status, 'COMPLETED', 'Research task must complete despite 503 verification failure');

  const proposals503 = runtime503.memoryService.listMemories(caller503, { status: 'PENDING_APPROVAL' });
  assert.equal(proposals503.length, 1);
  assert.equal(runtime503.memoryService.getEvidenceByMemoryId(caller503, proposals503[0]!.id).length, 1);
  assert.equal(runtime503.memoryService.getClaimsByMemoryId(caller503, proposals503[0]!.id).length, 1);
  assert.equal(runtime503.memoryService.listClaimVerifications(caller503).length, 0);
  assert.equal(runtime503.getHealth().evidenceVerificationStatus, 'unavailable');

  // 9b. Verification engine throws unexpected error directly inside KnowledgeProposalPipeline
  const crashingVerifier = {
    async verifyProposalClaims() {
      throw new Error('Unexpected verification subsystem crash');
    }
  } as unknown as EvidenceVerificationEngine;
  const registryCrash = new AgentRegistry();
  registryCrash.register(
    createScriptedResearchAgent(
      buildTargetedResearchReport('Resilience when verifier throws')
    )
  );
  const runtimeCrash = new DotsRuntime({
    dbPath: ':memory:',
    tokens: TEST_TOKENS,
    env: {},
    enableEvidenceVerification: true,
    evidenceVerifier: crashingVerifier,
    agentRegistry: registryCrash,
    silentLogs: true
  });
  const { caller: callerCrash } = runtimeCrash.authenticateUser('runtime-admin-token');
  const crashOutput = await runtimeCrash.coordinator.executeAgent('research-agent', {
    goal: 'Research task when verifier throws',
    caller: callerCrash
  });
  assert.equal(crashOutput.status, 'COMPLETED');
  assert.equal(runtimeCrash.memoryService.listMemories(callerCrash, { status: 'PENDING_APPROVAL' }).length, 1);

  // Also test verifier returning malformed JSON (fails closed without failing task)
  const { provider: malformedProvider } = buildEchoModelProvider({
    name: 'malformed-provider',
    returnMalformed: true
  });
  const registryMalformed = new AgentRegistry();
  registryMalformed.register(
    createScriptedResearchAgent(
      buildTargetedResearchReport('Malformed verification response tolerance')
    )
  );
  const runtimeMalformed = new DotsRuntime({
    dbPath: ':memory:',
    tokens: TEST_TOKENS,
    env: {},
    enableEvidenceVerification: true,
    modelProvider: malformedProvider,
    agentRegistry: registryMalformed,
    silentLogs: true
  });
  const { caller: callerMalformed } = runtimeMalformed.authenticateUser('runtime-admin-token');
  const malformedOutput = await runtimeMalformed.coordinator.executeAgent('research-agent', {
    goal: 'Research task with malformed verification response',
    caller: callerMalformed
  });
  assert.equal(malformedOutput.status, 'COMPLETED');
  assert.equal(runtimeMalformed.memoryService.listMemories(callerMalformed, { status: 'PENDING_APPROVAL' }).length, 1);
  assert.equal(runtimeMalformed.memoryService.listClaimVerifications(callerMalformed).length, 0);
});
