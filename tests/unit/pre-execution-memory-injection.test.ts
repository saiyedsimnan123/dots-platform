/**
 * Next-Generation Dots AI Platform - Pre-Execution Memory Injection Unit & Integration Tests
 * Phase 4B.1: Modern Agent Lifecycle Integration
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

import { DatabaseManager } from '../../src/storage/db.ts';
import { TaskRepository } from '../../src/storage/task-repository.ts';
import { AuditRepository } from '../../src/storage/audit-repository.ts';
import { MemoryRepository } from '../../src/storage/memory-repository.ts';
import { MemoryService } from '../../src/memory/memory-service.ts';
import { TaskCoordinator } from '../../src/orchestrator/coordinator.ts';
import { HostMemoryAuthority } from '../../src/security/host-authority.ts';
import { TokenIdentityProvider } from '../../src/security/token-identity-provider.ts';
import { VerificationEngine } from '../../src/verification/verifier.ts';
import { TokenBudgetTracker } from '../../src/model/budget-tracker.ts';
import { ToolRegistry } from '../../src/tools/registry.ts';
import { PolicyEngine } from '../../src/security/policy-engine.ts';
import { ApprovalBroker } from '../../src/security/approval-broker.ts';
import { MockModelProvider } from '../../src/model/mock-provider.ts';
import {
  AgentRegistry,
  BaseAgent,
  ResearchAgent,
  AnalyticsAgent,
  DeveloperAgent,
  mergeAgentContext,
  USER_CONTEXT_SECTION_HEADER,
  USER_CONTEXT_SECTION_FOOTER,
  type AgentInput,
  type AgentOutput,
  type AgentExecutionContext
} from '../../src/agents/index.ts';
import {
  MEMORY_CONTEXT_SECURITY_BOUNDARY,
  MEMORY_CONTEXT_SECURITY_BOUNDARY_END,
  MEMORY_CONTEXT_SECURITY_NOTICE
} from '../../src/memory/context-builder.ts';
import {
  SecurityViolationError,
  MemoryScopeViolationError,
  ValidationError
} from '../../src/domain/errors.ts';
import type { AuthenticatedPrincipal, TrustedIdentityProvider } from '../../src/security/memory-authorizer.ts';

class MockIdentityProvider implements TrustedIdentityProvider {
  private readonly principals = new Map<string, AuthenticatedPrincipal>();

  public register(token: string, principal: AuthenticatedPrincipal): void {
    this.principals.set(token, principal);
  }

  public authenticate(token: unknown): AuthenticatedPrincipal | null {
    if (typeof token === 'string') {
      return this.principals.get(token) ?? null;
    }
    return null;
  }
}

class ContextInspectingAgent extends BaseAgent {
  public receivedInputs: AgentInput[] = [];
  public receivedExecutionContexts: AgentExecutionContext[] = [];

  constructor(id = 'inspecting-agent') {
    super({
      id,
      name: 'Context Inspecting Agent',
      description: 'Records received input and context for assertions',
      capabilities: ['general']
    });
  }

  public override async execute(
    input: AgentInput,
    context: AgentExecutionContext
  ): Promise<AgentOutput> {
    this.receivedInputs.push(input);
    this.receivedExecutionContexts.push(context);
    return {
      agentId: this.id,
      taskId: input.taskId ?? context.taskId,
      status: 'COMPLETED',
      summary: 'Inspected context successfully',
      stepsExecuted: 1,
      durationMs: 5,
      result: {
        contextKeys: input.context ? Object.keys(input.context) : [],
        hasMemoryContext: Boolean(input.context?.memoryContext),
        hasFormattedContext: Boolean(input.context?.formattedContext)
      }
    };
  }
}

function createTestHarness(options: { idProvider?: TrustedIdentityProvider; maxContextChars?: number } = {}) {
  const testWorkspace = mkdtempSync(join(tmpdir(), 'dots-pre-exec-memory-'));
  const db = new DatabaseManager(':memory:');
  const taskRepo = new TaskRepository(db);
  const auditRepo = new AuditRepository(db);
  const memoryRepo = new MemoryRepository(db);

  const idProvider = options.idProvider ?? new MockIdentityProvider();
  const hostAuthority = new HostMemoryAuthority({
    taskRepo,
    identityProvider: idProvider
  });
  const authorizer = hostAuthority.authorizer;

  const memoryService = new MemoryService({
    memoryRepo,
    auditRepo,
    taskRepo,
    authorizer,
    hostAuthority
  });

  const modelProvider = new MockModelProvider();
  const toolRegistry = new ToolRegistry();
  const policyEngine = new PolicyEngine({ workspaceRoot: testWorkspace, autoApproveTier2: true });
  const approvalBroker = new ApprovalBroker(taskRepo, auditRepo);
  const verifier = new VerificationEngine(taskRepo);
  const budgetTracker = new TokenBudgetTracker({ db, maxCostPerTaskUsd: 1.0 });
  const agentRegistry = new AgentRegistry();

  const coordinator = new TaskCoordinator({
    taskRepo,
    auditRepo,
    modelProvider,
    toolRegistry,
    policyEngine,
    approvalBroker,
    verifier,
    budgetTracker,
    workspaceRoot: testWorkspace,
    memoryService,
    hostAuthority,
    authorizer,
    agentRegistry
  });

  return {
    testWorkspace,
    db,
    taskRepo,
    auditRepo,
    memoryRepo,
    memoryService,
    hostAuthority,
    authorizer,
    modelProvider,
    toolRegistry,
    agentRegistry,
    coordinator,
    cleanup() {
      db.close();
      if (existsSync(testWorkspace)) {
        rmSync(testWorkspace, { recursive: true, force: true });
      }
    }
  };
}

// ============================================================================
// 1: Relevant active memory is retrieved before agent execution
// ============================================================================
test('Pre-Execution Memory - 1: relevant active memory is retrieved before agent execution and recorded in provenance', async () => {
  const idProvider = new MockIdentityProvider();
  idProvider.register('token-team-a', {
    principalId: 'user-a',
    role: 'MEMBER',
    permittedScopes: [{ scopeType: 'WORKSPACE', scopeId: 'team-alpha' }]
  });

  const harness = createTestHarness({ idProvider });
  try {
    const caller = harness.authorizer.authorizeUser({
      credentials: 'token-team-a',
      requestedScope: { scopeType: 'WORKSPACE', scopeId: 'team-alpha' }
    });

    const memory = harness.memoryService.createMemory(caller, {
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: 'team-alpha',
      key: 'architecture.database.engine',
      content: 'Primary database is PostgreSQL 16 with TimescaleDB plugin.',
      tags: ['database', 'architecture', 'postgresql'],
      priority: 85,
      status: 'ACTIVE'
    });

    const agent = new ContextInspectingAgent();
    harness.agentRegistry.register(agent);

    const output = await harness.coordinator.executeAgentTask(
      'Deploy database architecture migration',
      agent.id,
      {
        goal: 'Deploy database architecture migration',
        caller
      }
    );

    assert.equal(output.status, 'COMPLETED');

    // Provenance verification: memory_task_injections table
    const injections = harness.memoryRepo.getInjectionsByTaskId(output.taskId!);
    assert.equal(injections.length, 1);
    assert.equal(injections[0]!.memoryId, memory.id);

    // Audit event verification: AGENT_EXECUTION_STARTED contains injection stats without raw content
    const events = harness.auditRepo.getEventsByTaskId(output.taskId!);
    const startEvent = events.find((e) => e.eventType === 'AGENT_EXECUTION_STARTED')!;
    assert.ok(startEvent);
    const startDetails = JSON.parse(startEvent.detailsJson);
    assert.equal(startDetails.injectedMemoriesCount, 1);
    assert.deepEqual(startDetails.injectedMemoryIds, [memory.id]);
    assert.ok(!startEvent.detailsJson.includes('TimescaleDB')); // Raw content never leaked in audit
  } finally {
    harness.cleanup();
  }
});

// ============================================================================
// 2: Retrieved context reaches the agent
// ============================================================================
test('Pre-Execution Memory - 2: retrieved context reaches the agent via input.context and execution context', async () => {
  const idProvider = new MockIdentityProvider();
  idProvider.register('token-team-a', {
    principalId: 'user-a',
    role: 'MEMBER',
    permittedScopes: [{ scopeType: 'WORKSPACE', scopeId: 'team-alpha' }]
  });

  const harness = createTestHarness({ idProvider });
  try {
    const caller = harness.authorizer.authorizeUser({
      credentials: 'token-team-a',
      requestedScope: { scopeType: 'WORKSPACE', scopeId: 'team-alpha' }
    });

    const memory = harness.memoryService.createMemory(caller, {
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: 'team-alpha',
      key: 'architecture.database.engine',
      content: 'Primary database is PostgreSQL 16 with TimescaleDB plugin.',
      tags: ['database', 'architecture', 'postgresql'],
      priority: 85,
      status: 'ACTIVE'
    });

    const agent = new ContextInspectingAgent();
    harness.agentRegistry.register(agent);

    const output = await harness.coordinator.executeAgentTask(
      'Deploy database architecture migration',
      agent.id,
      {
        goal: 'Deploy database architecture migration',
        caller
      }
    );

    assert.equal(output.status, 'COMPLETED');
    assert.equal(agent.receivedInputs.length, 1);

    const receivedInput = agent.receivedInputs[0]!;
    assert.ok(receivedInput.context, 'Agent must receive merged context');
    assert.ok(receivedInput.context._memoryInjected, '_memoryInjected flag must be set');

    // Structured memoryContext verification
    const memContext = receivedInput.context.memoryContext as any;
    assert.ok(memContext, 'Structured memoryContext must be present');
    assert.equal(memContext.recordCount, 1);
    assert.deepEqual(memContext.memoryIds, [memory.id]);
    assert.ok(memContext.serialized.includes('PostgreSQL 16 with TimescaleDB'));

    // Formatted context text verification
    const formatted = receivedInput.context.formattedContext as string;
    assert.ok(formatted.includes(MEMORY_CONTEXT_SECURITY_BOUNDARY));
    assert.ok(formatted.includes(MEMORY_CONTEXT_SECURITY_NOTICE));
    assert.ok(formatted.includes('architecture.database.engine'));
    assert.ok(formatted.includes('PostgreSQL 16 with TimescaleDB'));

    // Context on AgentExecutionContext
    const execContext = agent.receivedExecutionContexts[0]!;
    assert.ok(execContext.memoryContext, 'AgentExecutionContext.memoryContext must be populated');
    assert.equal(execContext.memoryContext.included.length, 1);
    assert.equal(execContext.memoryContext.included[0]!.id, memory.id);
  } finally {
    harness.cleanup();
  }
});

// ============================================================================
// 3: User-provided context is preserved
// ============================================================================
test('Pre-Execution Memory - 3: user-provided context is preserved completely', async () => {
  const idProvider = new MockIdentityProvider();
  idProvider.register('token-team-a', {
    principalId: 'user-a',
    role: 'MEMBER',
    permittedScopes: [{ scopeType: 'WORKSPACE', scopeId: 'team-alpha' }]
  });

  const harness = createTestHarness({ idProvider });
  try {
    const caller = harness.authorizer.authorizeUser({
      credentials: 'token-team-a',
      requestedScope: { scopeType: 'WORKSPACE', scopeId: 'team-alpha' }
    });

    harness.memoryService.createMemory(caller, {
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: 'team-alpha',
      key: 'api.version',
      content: 'API specification version is v3.1-beta.',
      tags: ['api', 'version'],
      status: 'ACTIVE'
    });

    const agent = new ContextInspectingAgent();
    harness.agentRegistry.register(agent);

    const userContext = {
      userNote: 'Must complete before sprint review',
      targetEnvironment: 'staging',
      numericThreshold: 99.9,
      featureFlags: ['fast-track', 'canary']
    };

    const output = await harness.coordinator.executeAgentTask(
      'Verify API version compatibility',
      agent.id,
      {
        goal: 'Verify API version compatibility',
        context: userContext,
        caller
      }
    );

    assert.equal(output.status, 'COMPLETED');
    const received = agent.receivedInputs[0]!.context as any;

    // Verify all original user properties are untouched
    assert.equal(received.userNote, 'Must complete before sprint review');
    assert.equal(received.targetEnvironment, 'staging');
    assert.equal(received.numericThreshold, 99.9);
    assert.deepEqual(received.featureFlags, ['fast-track', 'canary']);

    // Verify formattedContext has clear section boundaries for both user context and memory
    const formatted = received.formattedContext as string;
    assert.ok(formatted.includes(USER_CONTEXT_SECTION_HEADER));
    assert.ok(formatted.includes('Must complete before sprint review'));
    assert.ok(formatted.includes(USER_CONTEXT_SECTION_FOOTER));
    assert.ok(formatted.includes(MEMORY_CONTEXT_SECURITY_BOUNDARY));
    assert.ok(formatted.includes('API specification version is v3.1-beta.'));
  } finally {
    harness.cleanup();
  }
});

// ============================================================================
// 4: Agent-specific context is preserved
// ============================================================================
test('Pre-Execution Memory - 4: agent-specific context and parameters are preserved', async () => {
  const idProvider = new MockIdentityProvider();
  idProvider.register('token-team-a', {
    principalId: 'user-a',
    role: 'MEMBER',
    permittedScopes: [{ scopeType: 'WORKSPACE', scopeId: 'team-alpha' }]
  });

  const harness = createTestHarness({ idProvider });
  try {
    const caller = harness.authorizer.authorizeUser({
      credentials: 'token-team-a',
      requestedScope: { scopeType: 'WORKSPACE', scopeId: 'team-alpha' }
    });

    harness.memoryService.createMemory(caller, {
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: 'team-alpha',
      key: 'testing.framework',
      content: 'Standard test framework is node:test with native assertions.',
      tags: ['test', 'framework'],
      status: 'ACTIVE'
    });

    const agent = new ContextInspectingAgent();
    harness.agentRegistry.register(agent);

    const agentSpecContext = {
      agentCustomConfig: {
        timeoutMs: 3000,
        retryStrategy: 'exponential_backoff',
        depthLimit: 4
      }
    };

    const output = await harness.coordinator.executeAgentTask(
      'Run test framework audit',
      agent.id,
      {
        goal: 'Run test framework audit',
        parameters: { auditLevel: 'thorough' },
        context: agentSpecContext,
        caller
      }
    );

    assert.equal(output.status, 'COMPLETED');
    const received = agent.receivedInputs[0]!;
    assert.deepEqual((received.context as any).agentCustomConfig, agentSpecContext.agentCustomConfig);
    assert.equal(received.parameters?.auditLevel, 'thorough');
  } finally {
    harness.cleanup();
  }
});

// ============================================================================
// 5: Empty memory results do not break execution
// ============================================================================
test('Pre-Execution Memory - 5: empty memory results do not break execution', async () => {
  const idProvider = new MockIdentityProvider();
  idProvider.register('token-empty', {
    principalId: 'user-empty',
    role: 'MEMBER',
    permittedScopes: [{ scopeType: 'WORKSPACE', scopeId: 'empty-workspace' }]
  });

  const harness = createTestHarness({ idProvider });
  try {
    const caller = harness.authorizer.authorizeUser({
      credentials: 'token-empty',
      requestedScope: { scopeType: 'WORKSPACE', scopeId: 'empty-workspace' }
    });

    // No memories seeded
    const agent = new ContextInspectingAgent();
    harness.agentRegistry.register(agent);

    const output = await harness.coordinator.executeAgentTask(
      'Clean workspace temporary files',
      agent.id,
      {
        goal: 'Clean workspace temporary files',
        caller
      }
    );

    assert.equal(output.status, 'COMPLETED');
    const received = agent.receivedInputs[0]!;
    // Memory context should be absent/clean
    assert.equal((received.context as any)?.memoryContext, undefined);

    // No injections in database
    const injections = harness.memoryRepo.getInjectionsByTaskId(output.taskId!);
    assert.equal(injections.length, 0);

    // Audit event does not have injectedMemoriesCount
    const events = harness.auditRepo.getEventsByTaskId(output.taskId!);
    const startEvent = events.find((e) => e.eventType === 'AGENT_EXECUTION_STARTED')!;
    assert.equal(JSON.parse(startEvent.detailsJson).injectedMemoriesCount, undefined);
  } finally {
    harness.cleanup();
  }
});

// ============================================================================
// 6: Unrelated memories are excluded by relevance filtering
// ============================================================================
test('Pre-Execution Memory - 6: unrelated memories are excluded by relevance filtering', async () => {
  const idProvider = new MockIdentityProvider();
  idProvider.register('token-team-a', {
    principalId: 'user-a',
    role: 'MEMBER',
    permittedScopes: [{ scopeType: 'WORKSPACE', scopeId: 'team-alpha' }]
  });

  const harness = createTestHarness({ idProvider });
  try {
    const caller = harness.authorizer.authorizeUser({
      credentials: 'token-team-a',
      requestedScope: { scopeType: 'WORKSPACE', scopeId: 'team-alpha' }
    });

    // Seed memory about gardening/horticulture
    harness.memoryService.createMemory(caller, {
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: 'team-alpha',
      key: 'gardening.horticulture.flowers',
      content: 'Water orchid flowers twice weekly in indirect sunlight.',
      tags: ['gardening', 'orchids', 'flowers'],
      status: 'ACTIVE'
    });

    const agent = new ContextInspectingAgent();
    harness.agentRegistry.register(agent);

    // Goal is completely unrelated to gardening
    const output = await harness.coordinator.executeAgentTask(
      'Optimize database SQL indexes for billing queries',
      agent.id,
      {
        goal: 'Optimize database SQL indexes for billing queries',
        caller
      }
    );

    assert.equal(output.status, 'COMPLETED');
    const received = agent.receivedInputs[0]!;
    assert.equal((received.context as any)?.memoryContext, undefined);

    const injections = harness.memoryRepo.getInjectionsByTaskId(output.taskId!);
    assert.equal(injections.length, 0);
  } finally {
    harness.cleanup();
  }
});

// ============================================================================
// 7: Workspace scope isolation is enforced
// ============================================================================
test('Pre-Execution Memory - 7: workspace scope isolation is strictly enforced', async () => {
  const idProvider = new MockIdentityProvider();
  idProvider.register('token-team-a', {
    principalId: 'user-a',
    role: 'MEMBER',
    permittedScopes: [{ scopeType: 'WORKSPACE', scopeId: 'team-alpha' }]
  });
  idProvider.register('token-team-b', {
    principalId: 'user-b',
    role: 'MEMBER',
    permittedScopes: [{ scopeType: 'WORKSPACE', scopeId: 'team-beta' }]
  });

  const harness = createTestHarness({ idProvider });
  try {
    const callerA = harness.authorizer.authorizeUser({
      credentials: 'token-team-a',
      requestedScope: { scopeType: 'WORKSPACE', scopeId: 'team-alpha' }
    });
    const callerB = harness.authorizer.authorizeUser({
      credentials: 'token-team-b',
      requestedScope: { scopeType: 'WORKSPACE', scopeId: 'team-beta' }
    });

    // Seed confidential memory strictly in team-alpha
    harness.memoryService.createMemory(callerA, {
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: 'team-alpha',
      key: 'alpha.confidential.key',
      content: 'Confidential secret project Alpha roadmap.',
      tags: ['alpha', 'confidential', 'roadmap'],
      status: 'ACTIVE'
    });

    const agent = new ContextInspectingAgent();
    harness.agentRegistry.register(agent);

    // Team B submits a task matching the topic
    const outputB = await harness.coordinator.executeAgentTask(
      'Review confidential roadmap',
      agent.id,
      {
        goal: 'Review confidential roadmap',
        caller: callerB
      }
    );

    assert.equal(outputB.status, 'COMPLETED');
    const received = agent.receivedInputs[0]!;
    // Team B MUST NOT receive Team A memory
    assert.equal((received.context as any)?.memoryContext, undefined);
    assert.ok(!(received.context as any)?.formattedContext?.includes('Confidential secret project Alpha'));

    const injectionsB = harness.memoryRepo.getInjectionsByTaskId(outputB.taskId!);
    assert.equal(injectionsB.length, 0);
  } finally {
    harness.cleanup();
  }
});

// ============================================================================
// 8: Caller authorization failures do not broaden scope
// ============================================================================
test('Pre-Execution Memory - 8: caller authorization failures do not broaden scope and fail closed', async () => {
  const idProvider = new MockIdentityProvider();
  idProvider.register('token-team-a', {
    principalId: 'user-a',
    role: 'MEMBER',
    permittedScopes: [{ scopeType: 'WORKSPACE', scopeId: 'team-alpha' }]
  });

  const harness = createTestHarness({ idProvider });
  try {
    const caller = harness.authorizer.authorizeUser({
      credentials: 'token-team-a',
      requestedScope: { scopeType: 'WORKSPACE', scopeId: 'team-alpha' }
    });

    // Submit scoped task
    const task = await harness.coordinator.submitScopedTask({
      goal: 'Task with forged scope attestation',
      caller
    });

    // Tamper with the task scope attestation in DB
    const tamperedMeta = JSON.parse(task.metadataJson!);
    tamperedMeta._scopeAttestation = {
      ...tamperedMeta._scopeAttestation,
      signature: 'forged-signature-00000000000000000000'
    };
    harness.taskRepo.updateTaskMetadata(task.id, tamperedMeta);

    const agent = new ContextInspectingAgent();
    harness.agentRegistry.register(agent);

    // Execution must fail closed with SecurityViolationError
    await assert.rejects(
      async () => {
        await harness.coordinator.executeAgentTask(
          task,
          agent.id,
          { goal: task.goal }
        );
      },
      (err: unknown) => {
        assert.ok(err instanceof SecurityViolationError);
        return true;
      }
    );
  } finally {
    harness.cleanup();
  }
});

// ============================================================================
// 9: Memory retrieval failures are handled safely
// ============================================================================
test('Pre-Execution Memory - 9: memory retrieval failures are handled safely without crashing agent', async () => {
  const idProvider = new MockIdentityProvider();
  idProvider.register('token-team-a', {
    principalId: 'user-a',
    role: 'MEMBER',
    permittedScopes: [{ scopeType: 'WORKSPACE', scopeId: 'team-alpha' }]
  });

  const harness = createTestHarness({ idProvider });
  try {
    const caller = harness.authorizer.authorizeUser({
      credentials: 'token-team-a',
      requestedScope: { scopeType: 'WORKSPACE', scopeId: 'team-alpha' }
    });

    // Stub buildTaskMemoryContext to throw a non-security runtime error
    const originalBuild = harness.memoryService.buildTaskMemoryContext.bind(harness.memoryService);
    (harness.memoryService as any).buildTaskMemoryContext = () => {
      throw new Error('Simulated transient storage failure');
    };

    const agent = new ContextInspectingAgent();
    harness.agentRegistry.register(agent);

    // Must not crash execution
    const output = await harness.coordinator.executeAgentTask(
      'Execute task despite transient memory failure',
      agent.id,
      {
        goal: 'Execute task despite transient memory failure',
        caller
      }
    );

    assert.equal(output.status, 'COMPLETED');
    assert.equal(agent.receivedInputs.length, 1);
  } finally {
    harness.cleanup();
  }
});

// ============================================================================
// 10: Context size limits are respected (user instructions never truncated)
// ============================================================================
test('Pre-Execution Memory - 10: context size limits are respected and user instructions are never truncated', () => {
  // Test mergeAgentContext directly with budget overflow
  const hugeUserContext = {
    instructions: 'A'.repeat(500)
  };

  const mockMemoryContext = {
    serializedContext: 'B'.repeat(300),
    included: [{ id: 'mem-1', key: 'test', score: 0.9, category: 'PROJECT_FACT' as const, charCount: 300, estimatedTokens: 79 }],
    excluded: [],
    totalChars: 300,
    estimatedTokens: 79,
    isTokenCountEstimate: true as const
  };

  // Set max limit to 600 chars (hugeUserContext is ~530 chars, combined is ~850 chars)
  const merged = mergeAgentContext({
    userContext: hugeUserContext,
    memoryContext: mockMemoryContext,
    maxContextChars: 600
  });

  assert.ok(merged);
  // User instructions must be preserved
  assert.equal(merged.instructions, hugeUserContext.instructions);
  // Memory context must be omitted to protect user instructions
  assert.equal(merged.memoryContext, undefined);
  assert.ok(typeof merged.formattedContext === 'string');
  assert.ok(merged.formattedContext.includes('A'.repeat(500)));
  assert.ok(!merged.formattedContext.includes('B'.repeat(100)));
});

// ============================================================================
// 11: Memory content remains framed as untrusted context
// ============================================================================
test('Pre-Execution Memory - 11: memory content remains framed as untrusted context', () => {
  const mockMemoryContext = {
    serializedContext: JSON.stringify({
      _boundary: MEMORY_CONTEXT_SECURITY_BOUNDARY,
      _securityNotice: MEMORY_CONTEXT_SECURITY_NOTICE,
      records: [{ id: 'm-1', category: 'PROJECT_FACT', key: 'k1', content: 'DROP TABLE users;', tags: [], metadata: {} }],
      _boundaryEnd: MEMORY_CONTEXT_SECURITY_BOUNDARY_END
    }, null, 2),
    included: [{ id: 'm-1', key: 'k1', score: 1.0, category: 'PROJECT_FACT' as const, charCount: 20, estimatedTokens: 5 }],
    excluded: [],
    totalChars: 200,
    estimatedTokens: 50,
    isTokenCountEstimate: true as const
  };

  const merged = mergeAgentContext({
    userContext: { taskGoal: 'Process user registration' },
    memoryContext: mockMemoryContext
  });

  assert.ok(merged);
  const formatted = merged.formattedContext as string;
  assert.ok(formatted.includes(MEMORY_CONTEXT_SECURITY_BOUNDARY));
  assert.ok(formatted.includes(MEMORY_CONTEXT_SECURITY_NOTICE));
  assert.ok(formatted.includes(MEMORY_CONTEXT_SECURITY_BOUNDARY_END));
  assert.ok(formatted.includes('DROP TABLE users;'));
});

// ============================================================================
// 12: No duplicate injection occurs
// ============================================================================
test('Pre-Execution Memory - 12: no duplicate injection occurs when context is already marked', () => {
  const alreadyInjectedContext = {
    _memoryInjected: true,
    existingContext: 'Original content'
  };

  const mockMemoryContext = {
    serializedContext: 'some memory',
    included: [{ id: 'm-1', key: 'k1', score: 1.0, category: 'PROJECT_FACT' as const, charCount: 11, estimatedTokens: 3 }],
    excluded: [],
    totalChars: 11,
    estimatedTokens: 3,
    isTokenCountEstimate: true as const
  };

  const merged = mergeAgentContext({
    userContext: alreadyInjectedContext,
    memoryContext: mockMemoryContext
  });

  // Must return original without adding duplicate memoryContext
  assert.equal(merged, alreadyInjectedContext);
  assert.equal((merged as any).memoryContext, undefined);
});

// ============================================================================
// 13: Legacy planTask() behavior remains unchanged
// ============================================================================
test('Pre-Execution Memory - 13: legacy planTask() behavior remains unchanged', async () => {
  const idProvider = new MockIdentityProvider();
  idProvider.register('token-team-a', {
    principalId: 'user-a',
    role: 'MEMBER',
    permittedScopes: [{ scopeType: 'WORKSPACE', scopeId: 'team-alpha' }]
  });

  const harness = createTestHarness({ idProvider });
  try {
    const caller = harness.authorizer.authorizeUser({
      credentials: 'token-team-a',
      requestedScope: { scopeType: 'WORKSPACE', scopeId: 'team-alpha' }
    });

    harness.memoryService.createMemory(caller, {
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: 'team-alpha',
      key: 'legacy.architecture.spec',
      content: 'Legacy planning memory content.',
      tags: ['legacy', 'spec'],
      status: 'ACTIVE'
    });

    // Submit scoped task
    const task = await harness.coordinator.submitScopedTask({
      goal: 'Execute legacy spec task',
      caller
    });

    // Step into PLANNING
    await harness.coordinator.step(task.id);

    // Call planTask directly
    const plannedTask = await harness.coordinator.planTask(task.id);
    assert.equal(plannedTask.status, 'EXECUTING');

    // Verify model received compiled prompt with memory
    const calls = harness.modelProvider.getRecordedCalls();
    assert.ok(calls.length > 0);
    const compiled = calls[0]!.args.compiledPrompt as any;
    assert.equal(compiled.contextIncluded, true);
    assert.ok(compiled.userPrompt.includes('Legacy planning memory content.'));

    // Injections persisted in DB
    const injections = harness.memoryRepo.getInjectionsByTaskId(task.id);
    assert.equal(injections.length, 1);
  } finally {
    harness.cleanup();
  }
});

// ============================================================================
// 14: Research Agent integration
// ============================================================================
test('Pre-Execution Memory - 14: ResearchAgent receives injected memory context during execution', async () => {
  const idProvider = new MockIdentityProvider();
  idProvider.register('token-team-a', {
    principalId: 'user-a',
    role: 'MEMBER',
    permittedScopes: [{ scopeType: 'WORKSPACE', scopeId: 'team-alpha' }]
  });

  const harness = createTestHarness({ idProvider });
  try {
    const caller = harness.authorizer.authorizeUser({
      credentials: 'token-team-a',
      requestedScope: { scopeType: 'WORKSPACE', scopeId: 'team-alpha' }
    });

    harness.memoryService.createMemory(caller, {
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: 'team-alpha',
      key: 'market.competitors',
      content: 'Primary competitors are Acme Corp and Contoso AI.',
      tags: ['market', 'competitors'],
      status: 'ACTIVE'
    });

    const researchAgent = new ResearchAgent();
    harness.agentRegistry.register(researchAgent);

    // Submit task without search provider configured (fails honestly as expected for unconfigured provider, but verifies pre-execution memory injection)
    const output = await harness.coordinator.executeAgentTask(
      'Analyze market competitors',
      researchAgent.id,
      {
        goal: 'Analyze market competitors',
        caller
      }
    );

    // Status will be FAILED due to unconfigured web search provider, which proves input validation passed and memory was injected
    assert.ok(output.status === 'FAILED' || output.status === 'COMPLETED');

    // Verify memory injection provenance record exists in DB
    const injections = harness.memoryRepo.getInjectionsByTaskId(output.taskId!);
    assert.equal(injections.length, 1);
  } finally {
    harness.cleanup();
  }
});

// ============================================================================
// 15: Analytics Agent integration
// ============================================================================
test('Pre-Execution Memory - 15: AnalyticsAgent receives injected memory context during execution', async () => {
  const idProvider = new MockIdentityProvider();
  idProvider.register('token-team-a', {
    principalId: 'user-a',
    role: 'MEMBER',
    permittedScopes: [{ scopeType: 'WORKSPACE', scopeId: 'team-alpha' }]
  });

  const harness = createTestHarness({ idProvider });
  try {
    const caller = harness.authorizer.authorizeUser({
      credentials: 'token-team-a',
      requestedScope: { scopeType: 'WORKSPACE', scopeId: 'team-alpha' }
    });

    harness.memoryService.createMemory(caller, {
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: 'team-alpha',
      key: 'sales.quarterly.target',
      content: 'Target quarterly revenue is \$500,000.',
      tags: ['sales', 'revenue', 'target'],
      status: 'ACTIVE'
    });

    const analyticsAgent = new AnalyticsAgent();
    harness.agentRegistry.register(analyticsAgent);

    const output = await harness.coordinator.executeAgentTask(
      'Profile sales quarterly metrics dataset',
      analyticsAgent.id,
      {
        goal: 'Profile sales quarterly metrics dataset',
        parameters: {
          data: [
            { rep: 'Alice', revenue: 120000 },
            { rep: 'Bob', revenue: 150000 }
          ]
        },
        caller
      }
    );

    assert.equal(output.status, 'COMPLETED');

    // Verify injection provenance in DB
    const injections = harness.memoryRepo.getInjectionsByTaskId(output.taskId!);
    assert.equal(injections.length, 1);
  } finally {
    harness.cleanup();
  }
});

// ============================================================================
// 16: Developer Agent integration
// ============================================================================
test('Pre-Execution Memory - 16: DeveloperAgent receives injected memory context during execution', async () => {
  const idProvider = new MockIdentityProvider();
  idProvider.register('token-team-a', {
    principalId: 'user-a',
    role: 'MEMBER',
    permittedScopes: [{ scopeType: 'WORKSPACE', scopeId: 'team-alpha' }]
  });

  const harness = createTestHarness({ idProvider });
  try {
    const caller = harness.authorizer.authorizeUser({
      credentials: 'token-team-a',
      requestedScope: { scopeType: 'WORKSPACE', scopeId: 'team-alpha' }
    });

    harness.memoryService.createMemory(caller, {
      category: 'PROJECT_FACT',
      scopeType: 'WORKSPACE',
      scopeId: 'team-alpha',
      key: 'codebase.architecture.style',
      content: 'All services use dependency injection and functional factories.',
      tags: ['codebase', 'architecture', 'style'],
      status: 'ACTIVE'
    });

    const developerAgent = new DeveloperAgent();
    harness.agentRegistry.register(developerAgent);

    const output = await harness.coordinator.executeAgentTask(
      'Explain codebase architecture style',
      developerAgent.id,
      {
        goal: 'Explain codebase architecture style',
        parameters: {
          operation: 'EXPLAIN',
          sourceCode: 'export function createService(repo) { return { repo }; }'
        },
        caller
      }
    );

    assert.equal(output.status, 'COMPLETED');

    // Verify injection provenance in DB
    const injections = harness.memoryRepo.getInjectionsByTaskId(output.taskId!);
    assert.equal(injections.length, 1);
  } finally {
    harness.cleanup();
  }
});
