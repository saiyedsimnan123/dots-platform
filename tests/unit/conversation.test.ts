/**
 * Next-Generation Dots AI Platform - Conversation System Unit Tests
 * Milestone 2A: Persistent Conversation System
 */

import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  DatabaseManager,
  ConversationRepository,
  ConversationService,
  MockModelProvider,
  TokenIdentityProvider,
  AgentRegistry,
  MockAgent,
  TaskCoordinator,
  TaskRepository,
  AuditRepository,
  ToolRegistry,
  standardTools,
  PolicyEngine,
  ApprovalBroker,
  VerificationEngine,
  TokenBudgetTracker,
  MemoryService,
  MemoryRepository,
  BaseAgent,
  type AgentInput,
  type AgentOutput,
  type AgentExecutionContext,
  type CallerContext
} from '../../src/index.ts';
import { HostMemoryAuthority } from '../../src/security/host-authority.ts';
import {
  AgentCapabilityError,
  AgentNotFoundError,
  ConversationNotFoundError,
  ConversationScopeViolationError,
  SecurityViolationError,
  ValidationError
} from '../../src/domain/errors.ts';

const ADMIN_TOKEN = 'admin-secret-token-123456';
const MEMBER_TOKEN = 'member-secret-token-123456';
const VIEWER_TOKEN = 'viewer-secret-token-123456';
const WS2_MEMBER_TOKEN = 'ws2-member-secret-token-123456';

function createTempDir(): string {
  return mkdtempSync(join(tmpdir(), 'dots-conv-test-'));
}

describe('Milestone 2A: Conversation System - Unit Tests', () => {
  const tempDirs: string[] = [];

  afterEach(() => {
    while (tempDirs.length > 0) {
      const dir = tempDirs.pop()!;
      rmSync(dir, { recursive: true, force: true });
    }
  });

  function setupEnvironment(options: { dbPath?: string } = {}) {
    const dir = createTempDir();
    tempDirs.push(dir);
    const dbPath = options.dbPath ?? join(dir, 'dots.db');

    const db = new DatabaseManager(dbPath);
    const conversationRepo = new ConversationRepository(db);
    const taskRepo = new TaskRepository(db);
    const auditRepo = new AuditRepository(db);
    const memoryRepo = new MemoryRepository(db);

    const identityProvider = new TokenIdentityProvider([
      {
        token: ADMIN_TOKEN,
        principalId: 'alice-admin',
        role: 'ADMIN',
        permittedScopes: [
          { scopeType: 'WORKSPACE', scopeId: 'ws-alpha' },
          { scopeType: 'GLOBAL', scopeId: 'default' }
        ]
      },
      {
        token: MEMBER_TOKEN,
        principalId: 'bob-member',
        role: 'MEMBER',
        permittedScopes: [{ scopeType: 'WORKSPACE', scopeId: 'ws-alpha' }]
      },
      {
        token: VIEWER_TOKEN,
        principalId: 'carol-viewer',
        role: 'VIEWER',
        permittedScopes: [{ scopeType: 'WORKSPACE', scopeId: 'ws-alpha' }]
      },
      {
        token: WS2_MEMBER_TOKEN,
        principalId: 'dave-ws2',
        role: 'MEMBER',
        permittedScopes: [{ scopeType: 'WORKSPACE', scopeId: 'ws-beta' }]
      }
    ]);

    const hostAuthority = new HostMemoryAuthority({
      hostSecret: 'test-host-secret-12345678901234567890',
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
    for (const tool of standardTools) {
      toolRegistry.register(tool);
    }

    const policyEngine = new PolicyEngine({
      workspaceRoot: dir,
      autoApproveTier2: true
    });
    const approvalBroker = new ApprovalBroker(taskRepo, auditRepo);
    const verifier = new VerificationEngine();
    const budgetTracker = new TokenBudgetTracker({ db, maxCostPerTaskUsd: 1.0 });
    const mockProvider = new MockModelProvider();
    const agentRegistry = new AgentRegistry();

    const coordinator = new TaskCoordinator({
      taskRepo,
      auditRepo,
      modelProvider: mockProvider,
      toolRegistry,
      policyEngine,
      approvalBroker,
      verifier,
      budgetTracker,
      workspaceRoot: dir,
      memoryService,
      hostAuthority,
      authorizer,
      agentRegistry
    });

    const conversationService = new ConversationService({
      conversationRepo,
      modelProvider: mockProvider,
      agentRegistry,
      coordinator,
      authorizer,
      hostAuthority,
      maxHistoryMessages: 10
    });

    const memberCaller = authorizer.authorizeUser({ credentials: MEMBER_TOKEN });
    const adminCaller = authorizer.authorizeUser({
      credentials: ADMIN_TOKEN,
      requestedScope: { scopeType: 'WORKSPACE', scopeId: 'ws-alpha' }
    });
    const viewerCaller = authorizer.authorizeUser({ credentials: VIEWER_TOKEN });
    const ws2Caller = authorizer.authorizeUser({ credentials: WS2_MEMBER_TOKEN });

    return {
      dir,
      dbPath,
      db,
      conversationRepo,
      taskRepo,
      auditRepo,
      mockProvider,
      agentRegistry,
      coordinator,
      conversationService,
      memberCaller,
      adminCaller,
      viewerCaller,
      ws2Caller
    };
  }

  it('creates, retrieves, updates, archives, and deletes conversations', () => {
    const { conversationRepo } = setupEnvironment();

    // 1. Create conversation
    const conv = conversationRepo.createConversation({
      title: 'Architectural Review',
      scopeType: 'WORKSPACE',
      scopeId: 'ws-alpha',
      createdBy: 'bob-member',
      metadataJson: JSON.stringify({ priority: 'high' })
    });

    assert.ok(conv.id);
    assert.equal(conv.title, 'Architectural Review');
    assert.equal(conv.status, 'ACTIVE');
    assert.equal(conv.scopeType, 'WORKSPACE');
    assert.equal(conv.scopeId, 'ws-alpha');
    assert.equal(conv.createdBy, 'bob-member');
    assert.equal(conv.agentId, null);
    assert.ok(conv.createdAt);
    assert.ok(conv.updatedAt);

    // 2. Retrieve conversation
    const retrieved = conversationRepo.getConversationByIdOrThrow(conv.id);
    assert.equal(retrieved.id, conv.id);
    assert.equal(retrieved.title, 'Architectural Review');

    // 3. Update conversation
    const updated = conversationRepo.updateConversation(conv.id, {
      title: 'Updated Architectural Review',
      agentId: 'mock-agent'
    });
    assert.equal(updated.title, 'Updated Architectural Review');
    assert.equal(updated.agentId, 'mock-agent');

    // 4. Archive conversation (soft delete)
    const archived = conversationRepo.archiveConversation(conv.id);
    assert.equal(archived.status, 'ARCHIVED');

    // 5. Delete conversation (hard delete)
    const deleted = conversationRepo.deleteConversation(conv.id);
    assert.equal(deleted, true);
    assert.equal(conversationRepo.getConversationById(conv.id), null);
    assert.throws(
      () => conversationRepo.getConversationByIdOrThrow(conv.id),
      ConversationNotFoundError
    );
  });

  it('preserves conversation and messages across runtime restarts', () => {
    const dir = createTempDir();
    tempDirs.push(dir);
    const dbPath = join(dir, 'persisted.db');

    let convId: string;
    let msg1Id: string;
    let msg2Id: string;

    // First session: create database and add conversation + messages
    {
      const db1 = new DatabaseManager(dbPath);
      const repo1 = new ConversationRepository(db1);

      const conv = repo1.createConversation({
        title: 'Restart Test Chat',
        scopeType: 'WORKSPACE',
        scopeId: 'ws-alpha',
        createdBy: 'bob-member'
      });
      convId = conv.id;

      const m1 = repo1.addMessage({
        conversationId: conv.id,
        role: 'user',
        content: 'Persisted question across restart'
      });
      msg1Id = m1.id;

      const m2 = repo1.addMessage({
        conversationId: conv.id,
        role: 'assistant',
        content: 'Persisted answer across restart'
      });
      msg2Id = m2.id;

      db1.close();
    }

    // Second session: simulate runtime reboot with brand new DatabaseManager on the same DB file
    {
      const db2 = new DatabaseManager(dbPath);
      const repo2 = new ConversationRepository(db2);

      const conv = repo2.getConversationByIdOrThrow(convId);
      assert.equal(conv.id, convId);
      assert.equal(conv.title, 'Restart Test Chat');

      const messagesResult = repo2.listMessages(convId);
      assert.equal(messagesResult.total, 2);
      assert.equal(messagesResult.messages[0].id, msg1Id);
      assert.equal(messagesResult.messages[0].content, 'Persisted question across restart');
      assert.equal(messagesResult.messages[1].id, msg2Id);
      assert.equal(messagesResult.messages[1].content, 'Persisted answer across restart');

      db2.close();
    }
  });

  it('inserts messages and retrieves them in chronological order with pagination', () => {
    const { conversationRepo } = setupEnvironment();

    const conv = conversationRepo.createConversation({
      title: 'Ordering Test',
      scopeType: 'WORKSPACE',
      scopeId: 'ws-alpha',
      createdBy: 'bob-member'
    });

    const m1 = conversationRepo.addMessage({
      conversationId: conv.id,
      role: 'user',
      content: 'Message 1',
      createdAt: '2026-11-14T10:00:00.000Z'
    });

    const m2 = conversationRepo.addMessage({
      conversationId: conv.id,
      role: 'assistant',
      content: 'Message 2',
      createdAt: '2026-11-14T10:01:00.000Z'
    });

    const m3 = conversationRepo.addMessage({
      conversationId: conv.id,
      role: 'user',
      content: 'Message 3',
      createdAt: '2026-11-14T10:02:00.000Z'
    });

    // Chronological retrieval (default ASC)
    const listAsc = conversationRepo.listMessages(conv.id);
    assert.equal(listAsc.total, 3);
    assert.equal(listAsc.messages.length, 3);
    assert.equal(listAsc.messages[0].id, m1.id);
    assert.equal(listAsc.messages[1].id, m2.id);
    assert.equal(listAsc.messages[2].id, m3.id);

    // Pagination: limit 2, offset 1
    const paged = conversationRepo.listMessages(conv.id, { limit: 2, offset: 1 });
    assert.equal(paged.total, 3);
    assert.equal(paged.messages.length, 2);
    assert.equal(paged.messages[0].id, m2.id);
    assert.equal(paged.messages[1].id, m3.id);

    // Reverse order (DESC)
    const listDesc = conversationRepo.listMessages(conv.id, { order: 'DESC' });
    assert.equal(listDesc.messages[0].id, m3.id);
    assert.equal(listDesc.messages[2].id, m1.id);
  });

  it('enforces caller ownership and scope isolation', () => {
    const { conversationService, memberCaller, ws2Caller, viewerCaller } = setupEnvironment();

    // 1. Member in ws-alpha creates conversation
    const conv = conversationService.createConversation(memberCaller, {
      title: 'Alpha Internal Chat'
    });
    assert.equal(conv.scopeId, 'ws-alpha');

    // 2. Caller in ws-beta attempts to read -> ConversationScopeViolationError
    assert.throws(
      () => conversationService.getConversation(ws2Caller, conv.id),
      ConversationScopeViolationError
    );

    // 3. Caller in ws-beta attempts to send message -> ConversationScopeViolationError
    assert.rejects(
      async () => conversationService.sendMessage(ws2Caller, conv.id, { content: 'Intrusion attempt' }),
      ConversationScopeViolationError
    );

    // 4. Viewer in ws-alpha has READ but not WRITE
    const viewed = conversationService.getConversation(viewerCaller, conv.id);
    assert.equal(viewed.id, conv.id);

    // 5. Viewer attempts to create conversation -> SecurityViolationError
    assert.throws(
      () => conversationService.createConversation(viewerCaller, { title: 'Viewer Created' }),
      SecurityViolationError
    );

    // 6. Viewer attempts to send message -> SecurityViolationError
    assert.rejects(
      async () => conversationService.sendMessage(viewerCaller, conv.id, { content: 'Unauthorized write' }),
      SecurityViolationError
    );
  });

  it('executes default general-purpose conversation path via mock provider', async () => {
    const { conversationService, mockProvider, memberCaller } = setupEnvironment();

    mockProvider.enqueueCompletion('Hello! How can I assist you with Dots today?');

    const conv = conversationService.createConversation(memberCaller, {
      title: 'General Chat'
    });

    const response = await conversationService.sendMessage(memberCaller, conv.id, {
      content: 'Hello AI assistant',
      clientMessageId: 'msg-client-1'
    });

    assert.equal(response.conversation.id, conv.id);
    assert.equal(response.userMessage.content, 'Hello AI assistant');
    assert.equal(response.userMessage.role, 'user');
    assert.equal(response.userMessage.clientMessageId, 'msg-client-1');

    assert.ok(response.assistantMessage);
    assert.equal(response.assistantMessage.content, 'Hello! How can I assist you with Dots today?');
    assert.equal(response.assistantMessage.role, 'assistant');
    assert.ok(response.usage);

    // Verify messages persisted in repo
    const msgs = conversationService.getMessages(memberCaller, conv.id);
    assert.equal(msgs.total, 2);
    assert.equal(msgs.messages[0].content, 'Hello AI assistant');
    assert.equal(msgs.messages[1].content, 'Hello! How can I assist you with Dots today?');
  });

  it('bounds conversation history to maxHistoryMessages to avoid unbounded prompts', async () => {
    const { conversationService, mockProvider, memberCaller, conversationRepo } = setupEnvironment();

    const conv = conversationService.createConversation(memberCaller, {
      title: 'Bounded History Test'
    });

    // Populate conversation with 15 prior messages (service has maxHistoryMessages = 10)
    for (let i = 1; i <= 15; i++) {
      conversationRepo.addMessage({
        conversationId: conv.id,
        role: i % 2 === 1 ? 'user' : 'assistant',
        content: `Historic message ${i}`
      });
    }

    mockProvider.clearHistory();

    await conversationService.sendMessage(memberCaller, conv.id, {
      content: 'Current message 16'
    });

    // Check calls recorded by MockModelProvider
    const recordedCalls = mockProvider.getRecordedCalls();
    assert.equal(recordedCalls.length, 1);
    assert.equal(recordedCalls[0].method, 'generateCompletion');

    const passedMessages = recordedCalls[0].args.messages as Array<{ role: string; content: string }>;
    // The history limit is 10, so at most 10 messages should be passed to the model
    assert.ok(passedMessages.length <= 10);
    // The last message in the passed history must be the current user message
    assert.equal(passedMessages[passedMessages.length - 1].content, 'Current message 16');
  });

  it('handles provider failures safely without corrupting conversation history', async () => {
    const { conversationService, mockProvider, memberCaller } = setupEnvironment();

    const conv = conversationService.createConversation(memberCaller, {
      title: 'Failure Recovery Chat'
    });

    // Simulate provider failure
    mockProvider.simulateFailureNext(new Error('Cloud endpoint quota exceeded (503 Service Unavailable)'));

    await assert.rejects(
      async () => conversationService.sendMessage(memberCaller, conv.id, { content: 'Will fail' }),
      /Cloud endpoint quota exceeded/
    );

    // Crucial check: user message was preserved, but NO assistant message was fabricated!
    const msgs = conversationService.getMessages(memberCaller, conv.id);
    assert.equal(msgs.total, 1);
    assert.equal(msgs.messages[0].role, 'user');
    assert.equal(msgs.messages[0].content, 'Will fail');

    // Subsequent message succeeds when provider recovers
    mockProvider.enqueueCompletion('Recovered response');
    const response = await conversationService.sendMessage(memberCaller, conv.id, { content: 'Retry now' });

    assert.equal(response.assistantMessage?.content, 'Recovered response');
    const msgsAfter = conversationService.getMessages(memberCaller, conv.id);
    assert.equal(msgsAfter.total, 3); // User 1, User 2, Assistant 1
  });

  it('supports idempotency deduplication with clientMessageId', async () => {
    const { conversationService, mockProvider, memberCaller } = setupEnvironment();

    const conv = conversationService.createConversation(memberCaller, {
      title: 'Idempotency Chat'
    });

    mockProvider.enqueueCompletion('Idempotent response 1');

    // First attempt
    const res1 = await conversationService.sendMessage(memberCaller, conv.id, {
      content: 'Charge card $10',
      clientMessageId: 'idempotency-key-abc'
    });
    assert.equal(res1.assistantMessage?.content, 'Idempotent response 1');

    // Second attempt with exact same clientMessageId
    const res2 = await conversationService.sendMessage(memberCaller, conv.id, {
      content: 'Charge card $10',
      clientMessageId: 'idempotency-key-abc'
    });

    // Should return existing user & assistant message without creating duplicates
    assert.equal(res2.userMessage.id, res1.userMessage.id);
    assert.equal(res2.assistantMessage?.id, res1.assistantMessage?.id);

    const msgs = conversationService.getMessages(memberCaller, conv.id);
    assert.equal(msgs.total, 2); // exactly 1 user + 1 assistant
  });

  it('associates conversation with registered agent and preserves TaskCoordinator lifecycle', async () => {
    const { conversationService, agentRegistry, memberCaller, taskRepo } = setupEnvironment();

    // Register a mock agent with 'conversation' capability
    const mockAgent = new MockAgent({
      id: 'support-agent',
      name: 'Customer Support Agent',
      capabilities: ['general', 'conversation'],
      executeMock: async (input, context) => {
        return {
          agentId: 'support-agent',
          taskId: context.taskId,
          status: 'COMPLETED',
          result: {
            response: `Support agent response to: "${input.goal}"`
          },
          summary: `Support agent processed: "${input.goal}"`,
          stepsExecuted: 1,
          durationMs: 15
        };
      }
    });
    agentRegistry.register(mockAgent);

    // Create conversation bound to 'support-agent'
    const conv = conversationService.createConversation(memberCaller, {
      title: 'Agent Support Chat',
      agentId: 'support-agent'
    });
    assert.equal(conv.agentId, 'support-agent');

    // Send message to agent-backed conversation
    const res = await conversationService.sendMessage(memberCaller, conv.id, {
      content: 'How do I configure persistent storage?'
    });

    assert.ok(res.assistantMessage);
    assert.equal(res.assistantMessage.role, 'assistant');
    assert.equal(res.assistantMessage.name, 'support-agent');
    assert.equal(
      res.assistantMessage.content,
      'Support agent response to: "How do I configure persistent storage?"'
    );

    // Verify task lifecycle: Task was created in TaskRepository and completed
    const meta = JSON.parse(res.assistantMessage.metadataJson!);
    assert.ok(meta.taskId);
    const task = taskRepo.getTaskById(meta.taskId);
    assert.ok(task);
    assert.equal(task.status, 'COMPLETED');
  });

  it('rejects unknown agents and unsupported capabilities cleanly', async () => {
    const { conversationService, agentRegistry, memberCaller } = setupEnvironment();

    // 1. Unknown agent rejection
    assert.throws(
      () => conversationService.createConversation(memberCaller, { title: 'Unknown', agentId: 'non-existent' }),
      AgentNotFoundError
    );

    // 2. Unsupported capability rejection
    // Define an agent that only has 'analytics' capability (neither 'conversation' nor 'general')
    class AnalyticsOnlyAgent extends BaseAgent {
      constructor() {
        super({
          id: 'analytics-only',
          name: 'Analytics Agent',
          description: 'Runs offline batch data analysis only',
          capabilities: ['analytics', 'decision_support']
        });
      }
      public async execute(input: AgentInput, context: AgentExecutionContext): Promise<AgentOutput> {
        return {
          agentId: this.id,
          status: 'COMPLETED',
          result: {},
          summary: 'Done',
          stepsExecuted: 0,
          durationMs: 0
        };
      }
    }

    agentRegistry.register(new AnalyticsOnlyAgent());

    // Creating conversation with analytics-only agent must be rejected with AgentCapabilityError
    assert.throws(
      () => conversationService.createConversation(memberCaller, { title: 'Analytics Chat', agentId: 'analytics-only' }),
      AgentCapabilityError
    );
  });

  it('enforces tool approvals and security policies for agent tool executions', async () => {
    const { conversationService, agentRegistry, memberCaller, taskRepo } = setupEnvironment();

    // Register an agent that attempts to call a Tier 3 tool (web_fetch) without approval
    const writingAgent = new MockAgent({
      id: 'writer-agent',
      name: 'Writer Agent',
      capabilities: ['conversation'],
      executeMock: async (input, context) => {
        // Calling web_fetch requires Tier 3 human approval
        const toolResult = await context.executeTool('web_fetch', {
          url: 'https://example.com'
        });
        return {
          agentId: 'writer-agent',
          taskId: context.taskId,
          status: 'COMPLETED',
          result: { toolResult },
          summary: 'Fetch requested',
          stepsExecuted: 1,
          durationMs: 10
        };
      }
    });
    agentRegistry.register(writingAgent);

    const conv = conversationService.createConversation(memberCaller, {
      title: 'Writer Agent Chat',
      agentId: 'writer-agent'
    });

    // Calling executeTool on Tier 3 without approvalToken will cause agent execution to fail with approval requirement
    await assert.rejects(
      async () => conversationService.sendMessage(memberCaller, conv.id, { content: 'Please fetch URL' }),
      (err: unknown) => err instanceof Error && /approval/i.test(err.message)
    );

    // Verify conversation history is NOT corrupted with a fake success message
    const msgs = conversationService.getMessages(memberCaller, conv.id);
    assert.equal(msgs.total, 1);
    assert.equal(msgs.messages[0].role, 'user');
  });
});
