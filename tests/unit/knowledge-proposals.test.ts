/**
 * Next-Generation Dots AI Platform - Automatic Knowledge Proposals Tests
 * Phase 4B.3: Post-Execution Knowledge Proposal Pipeline
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseManager } from '../../src/storage/db.ts';
import { TaskRepository } from '../../src/storage/task-repository.ts';
import { AuditRepository } from '../../src/storage/audit-repository.ts';
import { MemoryRepository } from '../../src/storage/memory-repository.ts';
import { HostMemoryAuthority } from '../../src/security/host-authority.ts';
import { MemoryService } from '../../src/memory/memory-service.ts';
import { ToolRegistry } from '../../src/tools/registry.ts';
import { PolicyEngine } from '../../src/security/policy-engine.ts';
import { ApprovalBroker } from '../../src/security/approval-broker.ts';
import { VerificationEngine } from '../../src/verification/verifier.ts';
import { TokenBudgetTracker } from '../../src/model/budget-tracker.ts';
import { MockModelProvider } from '../../src/model/mock-provider.ts';
import { TaskCoordinator } from '../../src/orchestrator/coordinator.ts';
import {
  KnowledgeProposalPipeline,
  extractResearchProposals,
  extractAnalyticsProposals,
  extractDeveloperProposals,
  extractCandidateProposals,
  slugify,
  tokenizeKeyWords
} from '../../src/memory/knowledge-pipeline.ts';
import {
  createMemoryProposeTool,
  createMemorySearchTool
} from '../../src/tools/memory-tools.ts';
import {
  AgentRegistry,
  ResearchAgent,
  AnalyticsAgent,
  DeveloperAgent,
  type AgentOutput
} from '../../src/agents/index.ts';
import type { ScopeIdentifier, CallerContext, Task } from '../../src/domain/types.ts';
import { SecurityViolationError } from '../../src/domain/errors.ts';

function setupPipelineTestEnv() {
  const db = new DatabaseManager(':memory:');
  const taskRepo = new TaskRepository(db);
  const auditRepo = new AuditRepository(db);
  const memoryRepo = new MemoryRepository(db);

  const scopeAlpha: ScopeIdentifier = { scopeType: 'WORKSPACE', scopeId: 'ws-alpha' };
  const scopeBeta: ScopeIdentifier = { scopeType: 'WORKSPACE', scopeId: 'ws-beta' };
  const scopeGlobal: ScopeIdentifier = { scopeType: 'GLOBAL', scopeId: 'default' };

  const identityProvider = {
    authenticate(credentials: unknown) {
      if (typeof credentials !== 'string') return null;
      if (credentials === 'token-admin-alpha') {
        return {
          principalId: 'admin-alpha',
          role: 'ADMIN' as const,
          permittedScopes: [scopeAlpha, scopeGlobal]
        };
      }
      if (credentials === 'token-admin-beta') {
        return {
          principalId: 'admin-beta',
          role: 'ADMIN' as const,
          permittedScopes: [scopeBeta]
        };
      }
      return null;
    }
  };

  const hostAuthority = new HostMemoryAuthority({
    taskRepo,
    identityProvider
  });
  const authorizer = hostAuthority.authorizer;

  const memoryService = new MemoryService({
    memoryRepo,
    auditRepo,
    taskRepo,
    authorizer,
    hostAuthority
  });

  const toolRegistry = new ToolRegistry();
  toolRegistry.register(createMemoryProposeTool(memoryService, authorizer));
  toolRegistry.register(createMemorySearchTool(memoryService, authorizer));

  const policyEngine = new PolicyEngine({ workspaceRoot: '/fake/workspace', autoApproveTier2: true });
  const approvalBroker = new ApprovalBroker(taskRepo, auditRepo);
  const verifier = new VerificationEngine(taskRepo);
  const budgetTracker = new TokenBudgetTracker({ maxTokensPerTask: 100_000 });
  const agentRegistry = new AgentRegistry();
  const pipeline = new KnowledgeProposalPipeline();

  const coordinator = new TaskCoordinator({
    taskRepo,
    auditRepo,
    modelProvider: new MockModelProvider(),
    toolRegistry,
    policyEngine,
    approvalBroker,
    verifier,
    budgetTracker,
    workspaceRoot: '/fake/workspace',
    memoryService,
    hostAuthority,
    agentRegistry,
    knowledgePipeline: pipeline
  });

  const adminAlpha = authorizer.authorizeUser({ credentials: 'token-admin-alpha', requestedScope: scopeAlpha });
  const adminBeta = authorizer.authorizeUser({ credentials: 'token-admin-beta', requestedScope: scopeBeta });

  const taskAlpha = hostAuthority.createTask(taskRepo, {
    id: 'task-pipeline-alpha',
    goal: 'Analyze architecture for distributed cache',
    scope: scopeAlpha
  });

  const agentCallerAlpha = authorizer.authorizeAgent({ taskId: taskAlpha.id });

  return {
    db,
    taskRepo,
    auditRepo,
    memoryRepo,
    hostAuthority,
    authorizer,
    memoryService,
    toolRegistry,
    policyEngine,
    approvalBroker,
    verifier,
    budgetTracker,
    agentRegistry,
    coordinator,
    pipeline,
    scopeAlpha,
    scopeBeta,
    adminAlpha,
    adminBeta,
    taskAlpha,
    agentCallerAlpha
  };
}

// ============================================================================
// 1. Slugify & Tokenizer Utilities
// ============================================================================
test('knowledge-pipeline - slugify and keyword tokenizer utilities operate cleanly', () => {
  assert.equal(slugify('Distributed Caching Best Practices! (2026)'), 'distributed-caching-best-practices-2026');
  assert.equal(slugify('', 20), 'item');
  assert.equal(slugify('a'.repeat(60), 30), 'a'.repeat(30));

  const tokens = tokenizeKeyWords('What are the key differences between redis and memcached?');
  assert.ok(tokens.includes('differences'));
  assert.ok(tokens.includes('redis'));
  assert.ok(tokens.includes('memcached'));
  assert.ok(!tokens.includes('the'));
  assert.ok(!tokens.includes('and'));
});

// ============================================================================
// 2. Research Agent Knowledge Extraction
// ============================================================================
test('knowledge-pipeline - extractResearchProposals extracts findings and preserves evidence', () => {
  const output: AgentOutput = {
    agentId: 'research-agent',
    status: 'COMPLETED',
    result: {
      report: {
        researchQuestion: 'PostgreSQL vs SQLite for embedded microservices',
        executiveSummary: 'SQLite provides superior read latency and zero operational overhead for single-node embedded microservices.',
        keyFindings: [
          'SQLite achieves sub-millisecond read latency via direct shared-memory IPC.',
          'PostgreSQL requires TCP loopback communication adding 1-2ms overhead.'
        ],
        evidenceAndSources: [
          { domain: 'sqlite.org', url: 'https://sqlite.org/whentouse.html', title: 'Appropriate Uses for SQLite' },
          { domain: 'postgresql.org', url: 'https://www.postgresql.org/docs/benchmarks', title: 'PostgreSQL Architecture' }
        ],
        agreements: ['Both engines guarantee ACID transactional integrity with WAL mode.'],
        conflictingEvidence: ['PostgreSQL scales better with high concurrent multi-client writers.'],
        limitationsAndUncertainty: ['Benchmarks were measured on NVMe storage; network storage results may vary.'],
        openQuestions: ['How does SQLite handle concurrent writes under high connection pools?'],
        completionStatus: 'SUCCESS'
      }
    },
    summary: 'Executive summary',
    stepsExecuted: 3,
    durationMs: 150
  };

  const proposals = extractResearchProposals(output, 'Compare SQLite and PostgreSQL');
  assert.equal(proposals.length, 2);

  // Finding proposal
  const finding = proposals.find((p) => p.key.startsWith('research.finding.'));
  assert.ok(finding, 'Must extract research finding proposal');
  assert.equal(finding.category, 'PROJECT_FACT');
  assert.ok(finding.content.includes('SQLite achieves sub-millisecond read latency'));
  assert.ok(finding.content.includes('https://sqlite.org/whentouse.html'));
  assert.ok(finding.content.includes('ACID transactional integrity'));
  assert.ok(finding.content.includes('Differing Perspectives / Conflicting Evidence'));
  assert.ok(finding.tags?.includes('research'));
  assert.ok(finding.tags?.includes('finding'));

  // Limitation proposal
  const limitation = proposals.find((p) => p.key.startsWith('research.limitations.'));
  assert.ok(limitation, 'Must extract research limitation proposal');
  assert.equal(limitation.category, 'PROJECT_FACT');
  assert.ok(limitation.content.includes('NVMe storage'));
  assert.ok(limitation.content.includes('high connection pools'));
});

test('knowledge-pipeline - extractResearchProposals skips extraction on failed or insufficient evidence runs', () => {
  const failedOutput: AgentOutput = {
    agentId: 'research-agent',
    status: 'COMPLETED',
    result: {
      report: {
        researchQuestion: 'Obscure unpublished proprietary algorithm',
        executiveSummary: 'Search returned zero results.',
        keyFindings: [],
        evidenceAndSources: [],
        completionStatus: 'INSUFFICIENT_EVIDENCE'
      }
    },
    summary: 'No evidence',
    stepsExecuted: 1,
    durationMs: 50
  };

  const proposals = extractResearchProposals(failedOutput, 'Obscure query');
  assert.equal(proposals.length, 0, 'Must not propose unverified or empty findings as facts');
});

// ============================================================================
// 3. Analytics Agent Knowledge Extraction
// ============================================================================
test('knowledge-pipeline - extractAnalyticsProposals extracts schema, quality, and statistical trends', () => {
  const output: AgentOutput = {
    agentId: 'analytics-agent',
    status: 'COMPLETED',
    result: {
      report: {
        objective: 'Analyze transaction dataset',
        datasetProfile: {
          rowCount: 5000,
          columnCount: 4,
          columnNames: ['id', 'amount', 'status', 'created_at'],
          numericColumns: ['amount'],
          categoricalColumns: ['status'],
          dateColumns: ['created_at']
        },
        dataQuality: {
          totalMissingValues: 12,
          duplicateRowsCount: 3,
          anomalousValuesCount: 2,
          qualityWarnings: ['Found 2 negative amount values in transactions']
        },
        insights: [
          'Average transaction value is $45.20 with a right-skewed distribution.',
          '98% of transactions have status COMPLETED.'
        ],
        correlations: [
          { columnA: 'amount', columnB: 'id', pearsonCorrelation: 0.82, strength: 'strong' }
        ],
        temporalTrends: [
          { metricColumn: 'amount', timeColumn: 'created_at', direction: 'increasing over time' }
        ],
        summary: 'Dataset analysis summary'
      }
    },
    summary: 'Analytics completed',
    stepsExecuted: 2,
    durationMs: 80
  };

  const proposals = extractAnalyticsProposals(output, 'Analyze transaction dataset');
  assert.equal(proposals.length, 3);

  // 1. Schema profile (no raw data rows)
  const schema = proposals.find((p) => p.key.startsWith('analytics.dataset.'));
  assert.ok(schema);
  assert.equal(schema.category, 'PROJECT_FACT');
  assert.ok(schema.content.includes('Total Rows: 5000'));
  assert.ok(schema.content.includes('Numeric Columns: amount'));
  assert.ok(!schema.content.includes('[{')); // Zero raw JSON row dumps!

  // 2. Data quality
  const quality = proposals.find((p) => p.key.startsWith('analytics.quality.'));
  assert.ok(quality);
  assert.ok(quality.content.includes('Total Missing Values: 12'));
  assert.ok(quality.content.includes('Found 2 negative amount values'));

  // 3. Insights & correlations
  const insights = proposals.find((p) => p.key.startsWith('analytics.insights.'));
  assert.ok(insights);
  assert.ok(insights.content.includes('Average transaction value is $45.20'));
  assert.ok(insights.content.includes('amount vs id: r=0.82'));
});

// ============================================================================
// 4. Developer Agent Knowledge Extraction
// ============================================================================
test('knowledge-pipeline - extractDeveloperProposals extracts debug solutions, patterns, and test procedures', () => {
  // DEBUG operation
  const debugOutput: AgentOutput = {
    agentId: 'developer-agent',
    status: 'COMPLETED',
    result: {
      report: {
        objective: 'Resolve connection timeout in database pool',
        operation: 'DEBUG',
        completionStatus: 'SUCCESS',
        summary: 'Identified connection leak in transaction rollback block.',
        bugsOrRisksIdentified: ['Connections were not released on uncaught transaction error.'],
        findings: [
          { title: 'Missing finally block', severity: 'HIGH', description: 'client.release() was missing in catch' }
        ],
        suggestedChanges: [
          { filePath: 'src/db.ts', description: 'Ensure client.release() is invoked inside finally block.' }
        ]
      }
    },
    summary: 'Debug complete',
    stepsExecuted: 2,
    durationMs: 60
  };

  const debugProposals = extractDeveloperProposals(debugOutput, 'Debug database pool');
  assert.equal(debugProposals.length, 1);
  assert.equal(debugProposals[0].category, 'LEARNED_PROCEDURE');
  assert.ok(debugProposals[0].content.includes('Confirmed Debugging Solution'));
  assert.ok(debugProposals[0].content.includes('Missing finally block'));
  assert.ok(debugProposals[0].content.includes('client.release()'));

  // ANALYZE operation
  const analyzeOutput: AgentOutput = {
    agentId: 'developer-agent',
    status: 'COMPLETED',
    result: {
      report: {
        objective: 'Design repository pattern',
        operation: 'ANALYZE',
        completionStatus: 'SUCCESS',
        summary: 'Repository layer isolates SQLite database details from domain entities.',
        filesInspected: ['src/storage/db.ts', 'src/storage/task-repository.ts'],
        findings: [
          { title: 'Decoupling', description: 'Use interfaces for all storage access.' }
        ],
        recommendedNextSteps: ['Create MemoryRepository following same pattern.']
      }
    },
    summary: 'Analysis complete',
    stepsExecuted: 1,
    durationMs: 40
  };

  const patternProposals = extractDeveloperProposals(analyzeOutput, 'Repository pattern');
  assert.equal(patternProposals.length, 1);
  assert.equal(patternProposals[0].category, 'LEARNED_PROCEDURE');
  assert.ok(patternProposals[0].content.includes('Verified Implementation Pattern'));
  assert.ok(patternProposals[0].content.includes('src/storage/db.ts'));

  // GENERATE operation without verifications -> MUST NOT PROPOSE
  const unverifiedGenOutput: AgentOutput = {
    agentId: 'developer-agent',
    status: 'COMPLETED',
    result: {
      report: {
        objective: 'Generate payment processing function',
        operation: 'GENERATE',
        completionStatus: 'SUCCESS',
        summary: 'Generated chargeCard function',
        generatedCode: 'function chargeCard() { return true; }',
        verificationResults: [] // No verification!
      }
    },
    summary: 'Code generated',
    stepsExecuted: 1,
    durationMs: 20
  };

  const unverifiedProposals = extractDeveloperProposals(unverifiedGenOutput, 'Generate payment code');
  assert.equal(unverifiedProposals.length, 0, 'Unverified generated code must NEVER be proposed as a proven solution');

  // GENERATE operation with all verifications passing -> Proposes verified solution
  const verifiedGenOutput: AgentOutput = {
    agentId: 'developer-agent',
    status: 'COMPLETED',
    result: {
      report: {
        objective: 'Generate sha256 checksum helper',
        operation: 'GENERATE',
        completionStatus: 'SUCCESS',
        summary: 'Generated verified sha256 helper with unit tests.',
        generatedCode: 'export function hash(data: string) { return crypto.createHash("sha256").update(data).digest("hex"); }',
        verificationResults: [
          { name: 'Unit test suite', passed: true, details: '5 test assertions passed' }
        ]
      }
    },
    summary: 'Code verified',
    stepsExecuted: 2,
    durationMs: 90
  };

  const verifiedProposals = extractDeveloperProposals(verifiedGenOutput, 'Generate sha256 helper');
  assert.equal(verifiedProposals.length, 1);
  assert.ok(verifiedProposals[0].content.includes('Verified Implementation Solution'));
  assert.ok(verifiedProposals[0].content.includes('All 1 independent assertions passed'));
});

// ============================================================================
// 5. Shared Pipeline Submission & Invariant Enforcement
// ============================================================================
test('knowledge-pipeline - processCompletedTask submits proposals in PENDING_APPROVAL and blocks self-approval', async () => {
  const env = setupPipelineTestEnv();

  const output: AgentOutput = {
    agentId: 'research-agent',
    status: 'COMPLETED',
    result: {
      report: {
        researchQuestion: 'Event-driven architecture guidelines',
        executiveSummary: 'Idempotency keys must accompany all asynchronous event payloads.',
        keyFindings: ['Idempotency keys prevent duplicate processing on network retries.'],
        evidenceAndSources: [
          { domain: 'martinfowler.com', url: 'https://martinfowler.com/articles/patterns-of-distributed-systems', title: 'Distributed Systems' }
        ],
        completionStatus: 'SUCCESS'
      }
    },
    summary: 'Research completed',
    stepsExecuted: 2,
    durationMs: 120
  };

  const submitted = await env.pipeline.processCompletedTask({
    task: env.taskAlpha,
    agentId: 'research-agent',
    output,
    caller: env.agentCallerAlpha,
    memoryService: env.memoryService
  });

  assert.equal(submitted.length, 1);
  const proposal = submitted[0];
  assert.equal(proposal.status, 'PENDING_APPROVAL', 'All proposals must be submitted with status PENDING_APPROVAL');
  assert.equal(proposal.scopeType, 'WORKSPACE');
  assert.equal(proposal.scopeId, 'ws-alpha');

  // Verify stored in repository
  const stored = env.memoryRepo.getMemoryById(proposal.id, env.scopeAlpha);
  assert.ok(stored);
  assert.equal(stored.status, 'PENDING_APPROVAL');

  // Audit event must be recorded
  const auditEvents = env.auditRepo.getEventsByTaskId(env.taskAlpha.id);
  const proposalEvent = auditEvents.find((e) => e.eventType === 'MEMORY_PROPOSAL_SUBMITTED');
  assert.ok(proposalEvent, 'MEMORY_PROPOSAL_SUBMITTED audit event must be emitted');

  // Agent caller CANNOT approve its own proposal
  assert.throws(
    () => env.memoryService.decideProposal(env.agentCallerAlpha, { memoryId: proposal.id, decision: 'APPROVED' }),
    SecurityViolationError,
    'Agent must NEVER be allowed to approve its own proposal'
  );

  // Human administrator CAN approve the proposal
  const approved = env.memoryService.decideProposal(env.adminAlpha, { memoryId: proposal.id, decision: 'APPROVED' });
  assert.equal(approved.status, 'ACTIVE', 'Human approval transitions proposal to ACTIVE');
});

// ============================================================================
// 6. Duplicate Suppression in Scope
// ============================================================================
test('knowledge-pipeline - duplicate suppression skips existing keys and identical content', async () => {
  const env = setupPipelineTestEnv();

  const output: AgentOutput = {
    agentId: 'research-agent',
    status: 'COMPLETED',
    result: {
      report: {
        researchQuestion: 'Caching strategies for fast APIs',
        executiveSummary: 'Redis cache-aside pattern reduces database read load by 80%.',
        keyFindings: ['Cache-aside pattern with TTL is optimal for read-heavy workloads.'],
        evidenceAndSources: [
          { domain: 'redis.io', url: 'https://redis.io/docs/manual/patterns', title: 'Cache-Aside' }
        ],
        completionStatus: 'SUCCESS'
      }
    },
    summary: 'Research complete',
    stepsExecuted: 2,
    durationMs: 100
  };

  // First run: submits proposal
  const firstBatch = await env.pipeline.processCompletedTask({
    task: env.taskAlpha,
    agentId: 'research-agent',
    output,
    caller: env.agentCallerAlpha,
    memoryService: env.memoryService
  });
  assert.equal(firstBatch.length, 1);

  // Second run with identical output: duplicate suppressed!
  const secondBatch = await env.pipeline.processCompletedTask({
    task: env.taskAlpha,
    agentId: 'research-agent',
    output,
    caller: env.agentCallerAlpha,
    memoryService: env.memoryService
  });
  assert.equal(secondBatch.length, 0, 'Must suppress duplicate proposals in same scope');
});

// ============================================================================
// 7. Secret Scrubbing Across Proposals
// ============================================================================
test('knowledge-pipeline - scrubs sensitive credentials from keys, content, and metadata', async () => {
  const env = setupPipelineTestEnv();

  const output: AgentOutput = {
    agentId: 'developer-agent',
    status: 'COMPLETED',
    result: {
      report: {
        objective: 'Fix leak with token sk-ant-api03-abcdef1234567890 in auth',
        operation: 'DEBUG',
        completionStatus: 'SUCCESS',
        summary: 'Fixed secret leak involving Bearer ghp_1234567890abcdefghijklmnopqrstuvwxyz12.',
        bugsOrRisksIdentified: ['Leaked sk-ant-api03-abcdef1234567890 in headers'],
        findings: [
          { title: 'Credential disclosure', severity: 'CRITICAL', description: 'Found API key sk-ant-api03-abcdef1234567890' }
        ],
        suggestedChanges: [
          { filePath: 'src/auth.ts', description: 'Remove sk-ant-api03-abcdef1234567890 from log outputs' }
        ]
      }
    },
    summary: 'Fixed secret',
    stepsExecuted: 1,
    durationMs: 30
  };

  const submitted = await env.pipeline.processCompletedTask({
    task: env.taskAlpha,
    agentId: 'developer-agent',
    output,
    caller: env.agentCallerAlpha,
    memoryService: env.memoryService
  });

  assert.equal(submitted.length, 1);
  const memory = submitted[0];

  assert.ok(!memory.key.includes('sk-ant-api03-abcdef1234567890'));
  assert.ok(!memory.content.includes('sk-ant-api03-abcdef1234567890'));
  assert.ok(!memory.content.includes('ghp_1234567890abcdefghijklmnopqrstuvwxyz12'));
  assert.ok(memory.content.includes('[REDACTED_ANTHROPIC_API_KEY]'));
  assert.ok(memory.content.includes('[REDACTED_GITHUB_TOKEN]'));
});

// ============================================================================
// 8. End-to-End Coordinator Integration with AnalyticsAgent (Full Lifecycle)
// ============================================================================
test('knowledge-pipeline - coordinator end-to-end: AnalyticsAgent task completion automatically proposes memory and enables closed-loop retrieval', async () => {
  const env = setupPipelineTestEnv();

  const analyticsAgent = new AnalyticsAgent({ id: 'analytics-agent' });
  env.agentRegistry.register(analyticsAgent);

  // Submit and execute task through coordinator
  const task = await env.coordinator.submitScopedTask({
    goal: 'Analyze sales quarterly distribution dataset',
    caller: env.adminAlpha,
    metadata: {
      agentId: 'analytics-agent',
      parameters: {
        data: [
          { rep: 'Alice', revenue: 120000, region: 'North' },
          { rep: 'Bob', revenue: 150000, region: 'South' },
          { rep: 'Charlie', revenue: 95000, region: 'East' }
        ]
      }
    }
  });

  // Execute agent task
  const output = await env.coordinator.executeAgentTask(
    task,
    'analytics-agent',
    {
      goal: task.goal,
      caller: env.adminAlpha,
      parameters: {
        data: [
          { rep: 'Alice', revenue: 120000, region: 'North' },
          { rep: 'Bob', revenue: 150000, region: 'South' },
          { rep: 'Charlie', revenue: 95000, region: 'East' }
        ]
      }
    }
  );

  assert.equal(output.status, 'COMPLETED');

  // Verify proposals were created in PENDING_APPROVAL
  const pendingProposals = env.memoryService.listMemories(env.adminAlpha, {
    status: 'PENDING_APPROVAL'
  });
  assert.ok(pendingProposals.length > 0, 'Coordinator must automatically trigger knowledge proposals on completion');

  const datasetProposal = pendingProposals.find((p) => p.key.startsWith('analytics.dataset.'));
  assert.ok(datasetProposal, 'Analytics dataset proposal must be created');
  assert.equal(datasetProposal.status, 'PENDING_APPROVAL');
  assert.equal(datasetProposal.scopeId, 'ws-alpha');

  // Verify coordinator logged KNOWLEDGE_PROPOSALS_GENERATED audit event
  const events = env.auditRepo.getEventsByTaskId(task.id);
  const generatedEvent = events.find((e) => e.eventType === 'KNOWLEDGE_PROPOSALS_GENERATED');
  assert.ok(generatedEvent, 'Coordinator must record KNOWLEDGE_PROPOSALS_GENERATED audit event');
  const eventDetails = JSON.parse(generatedEvent.detailsJson);
  assert.ok(eventDetails.proposalCount > 0);
  assert.equal(eventDetails.scopeId, 'ws-alpha');

  // Human administrator approves proposal
  const approved = env.memoryService.decideProposal(env.adminAlpha, {
    memoryId: datasetProposal.id,
    decision: 'APPROVED'
  });
  assert.equal(approved.status, 'ACTIVE');

  // The newly activated memory is now searchable via memory_search tool!
  const searchResult = await env.toolRegistry.get('memory_search')!.handler(
    { query: 'sales quarterly distribution dataset revenue' },
    { taskId: task.id, stepId: 'step-verify', workspaceRoot: '/fake/workspace' }
  );

  assert.equal(searchResult.output.success, true);
  assert.ok((searchResult.output.count as number) >= 1);
  const foundMem = (searchResult.output.memories as any[])[0];
  assert.equal(foundMem.id, datasetProposal.id);
  assert.equal(foundMem.key, datasetProposal.key);
});

// ============================================================================
// 9. End-to-End Coordinator Integration with DeveloperAgent (Full Lifecycle)
// ============================================================================
test('knowledge-pipeline - coordinator end-to-end: DeveloperAgent task completion automatically proposes pattern memory', async () => {
  const env = setupPipelineTestEnv();

  const devAgent = new DeveloperAgent({ id: 'developer-agent' });
  env.agentRegistry.register(devAgent);

  const task = await env.coordinator.submitScopedTask({
    goal: 'Analyze repository pattern implementation',
    caller: env.adminAlpha,
    metadata: {
      agentId: 'developer-agent',
      parameters: {
        objective: 'Analyze repository pattern implementation',
        operation: 'ANALYZE',
        inlineCode: 'export interface IRepository<T> { findById(id: string): T | null; }'
      }
    }
  });

  const output = await env.coordinator.executeAgentTask(
    task,
    'developer-agent',
    {
      goal: task.goal,
      caller: env.adminAlpha,
      parameters: {
        objective: 'Analyze repository pattern implementation',
        operation: 'ANALYZE',
        inlineCode: 'export interface IRepository<T> { findById(id: string): T | null; }'
      }
    }
  );

  assert.equal(output.status, 'COMPLETED');

  const pendingProposals = env.memoryService.listMemories(env.adminAlpha, {
    status: 'PENDING_APPROVAL'
  });
  const patternProposal = pendingProposals.find((p) => p.key.startsWith('developer.pattern.'));
  assert.ok(patternProposal, 'Developer pattern proposal must be created in PENDING_APPROVAL');
  assert.equal(patternProposal.status, 'PENDING_APPROVAL');

  // Approve proposal
  const approved = env.memoryService.decideProposal(env.adminAlpha, {
    memoryId: patternProposal.id,
    decision: 'APPROVED'
  });
  assert.equal(approved.status, 'ACTIVE');

  // Search retrieved memory
  const searchResult = await env.toolRegistry.get('memory_search')!.handler(
    { query: 'repository pattern implementation' },
    { taskId: task.id, stepId: 'step-verify', workspaceRoot: '/fake/workspace' }
  );

  assert.equal(searchResult.output.success, true);
  assert.ok((searchResult.output.count as number) >= 1);
  const foundMem = (searchResult.output.memories as any[])[0];
  assert.equal(foundMem.id, patternProposal.id);
});
