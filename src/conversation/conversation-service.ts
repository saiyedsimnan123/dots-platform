/**
 * Next-Generation Dots AI Platform - Conversation Service
 * Milestone 2A: Persistent Conversation System
 *
 * Architectural Mandate:
 * Dedicated service responsible for:
 * 1. Managing persistent conversation sessions with scope isolation.
 * 2. Ingesting user messages with deduplication and idempotency keys.
 * 3. Loading bounded chronological conversation history.
 * 4. General-purpose model completion via universal IModelProvider.
 * 5. Delegating conversations to registered agents via AgentRegistry and TaskCoordinator.
 * 6. Preserving task lifecycle, tool registry policy evaluation, and approval gates.
 * 7. Graceful error handling without corrupting history or fabricating responses.
 */

import type {
  Conversation,
  ConversationMessage,
  ConversationResponse,
  CreateConversationInput,
  ListConversationsFilter,
  ListMessagesFilter,
  SendConversationMessageInput,
  UpdateConversationInput,
  CallerContext,
  MemoryPermission
} from '../domain/types.ts';
import {
  AgentCapabilityError,
  AgentNotFoundError,
  ConversationScopeViolationError,
  DomainError,
  SecurityViolationError,
  ValidationError
} from '../domain/errors.ts';
import { defaultSecretScrubber } from '../model/secret-scrubber.ts';
import type { IModelProvider, ModelConfig, ModelMessage } from '../model/types.ts';
import type { ConversationRepository } from '../storage/conversation-repository.ts';
import { MemoryAuthorizer, validateScope } from '../security/memory-authorizer.ts';
import type { HostMemoryAuthority } from '../security/host-authority.ts';
import { AgentRegistry, type AgentInput } from '../agents/index.ts';
import type { TaskCoordinator } from '../orchestrator/coordinator.ts';

export interface ConversationServiceOptions {
  readonly conversationRepo: ConversationRepository;
  readonly modelProvider: IModelProvider;
  readonly agentRegistry?: AgentRegistry;
  readonly coordinator?: TaskCoordinator;
  readonly authorizer?: MemoryAuthorizer;
  readonly hostAuthority?: HostMemoryAuthority;
  readonly maxHistoryMessages?: number;
  readonly defaultModelConfig?: ModelConfig;
}

const MAX_MESSAGE_LENGTH = 32_768;
const MAX_TITLE_LENGTH = 256;

export class ConversationService {
  public readonly conversationRepo: ConversationRepository;
  public readonly modelProvider: IModelProvider;
  public readonly agentRegistry: AgentRegistry;
  public readonly coordinator?: TaskCoordinator;
  public readonly maxHistoryMessages: number;
  public readonly defaultModelConfig?: ModelConfig;

  readonly #authorizer: MemoryAuthorizer;
  readonly #hostAuthority?: HostMemoryAuthority;

  constructor(options: ConversationServiceOptions) {
    if (!options || typeof options !== 'object') {
      throw new ValidationError('ConversationServiceOptions must be an object.');
    }
    if (!options.conversationRepo) {
      throw new ValidationError('conversationRepo is required for ConversationService.');
    }
    if (!options.modelProvider) {
      throw new ValidationError('modelProvider is required for ConversationService.');
    }

    this.conversationRepo = options.conversationRepo;
    this.modelProvider = options.modelProvider;
    this.agentRegistry = options.agentRegistry ?? new AgentRegistry();
    this.coordinator = options.coordinator;
    this.maxHistoryMessages = Math.max(1, options.maxHistoryMessages ?? 50);
    this.defaultModelConfig = options.defaultModelConfig;

    this.#authorizer =
      options.authorizer ??
      options.hostAuthority?.authorizer ??
      new MemoryAuthorizer();
    this.#hostAuthority = options.hostAuthority;
  }

  // --- Public Operations ---

  /**
   * Creates a new conversation session within the authorized caller scope.
   */
  public createConversation(
    caller: CallerContext,
    input: CreateConversationInput = {}
  ): Conversation {
    const verified = this.validateCaller(caller, 'WRITE');

    const title = input.title ? input.title.trim() : 'New Conversation';
    if (title.length === 0) {
      throw new ValidationError('Conversation title cannot be empty.');
    }
    if (title.length > MAX_TITLE_LENGTH) {
      throw new ValidationError(`Conversation title exceeds maximum length of ${MAX_TITLE_LENGTH} characters.`);
    }

    const scope = input.scope ?? verified.scope;
    if (scope.scopeType !== verified.scope.scopeType || scope.scopeId !== verified.scope.scopeId) {
      throw new ConversationScopeViolationError(
        `${verified.scope.scopeType}:${verified.scope.scopeId}`,
        `${scope.scopeType}:${scope.scopeId}`
      );
    }

    let agentId: string | null = null;
    if (input.agentId !== undefined && input.agentId !== null && input.agentId.trim() !== '') {
      const normalizedAgentId = input.agentId.trim();
      this.validateAgentEligibility(normalizedAgentId);
      agentId = normalizedAgentId;
    }

    const metadataJson = input.metadata ? JSON.stringify(input.metadata) : null;

    return this.conversationRepo.createConversation({
      id: input.id,
      title,
      status: 'ACTIVE',
      scopeType: verified.scope.scopeType,
      scopeId: verified.scope.scopeId,
      createdBy: verified.actor,
      agentId,
      metadataJson
    });
  }

  /**
   * Retrieves a conversation by ID, enforcing scope isolation and READ permission.
   */
  public getConversation(caller: CallerContext, conversationId: string): Conversation {
    const verified = this.validateCaller(caller, 'READ');
    const conversation = this.conversationRepo.getConversationByIdOrThrow(conversationId);
    this.assertScopeAccess(verified, conversation);
    return conversation;
  }

  /**
   * Lists conversations within the authorized caller scope.
   */
  public listConversations(
    caller: CallerContext,
    filter: ListConversationsFilter = {}
  ): { conversations: Conversation[]; total: number } {
    const verified = this.validateCaller(caller, 'READ');
    return this.conversationRepo.listConversations({
      ...filter,
      scope: verified.scope
    });
  }

  /**
   * Updates conversation metadata or associated agent.
   */
  public updateConversation(
    caller: CallerContext,
    conversationId: string,
    input: UpdateConversationInput
  ): Conversation {
    const verified = this.validateCaller(caller, 'WRITE');
    const existing = this.conversationRepo.getConversationByIdOrThrow(conversationId);
    this.assertScopeAccess(verified, existing);

    let title: string | undefined;
    if (input.title !== undefined) {
      title = input.title.trim();
      if (title.length === 0) {
        throw new ValidationError('Conversation title cannot be empty.');
      }
      if (title.length > MAX_TITLE_LENGTH) {
        throw new ValidationError(`Conversation title exceeds maximum length of ${MAX_TITLE_LENGTH} characters.`);
      }
    }

    let agentId: string | null | undefined = undefined;
    if (input.agentId !== undefined) {
      if (input.agentId === null || input.agentId.trim() === '') {
        agentId = null;
      } else {
        const normalized = input.agentId.trim();
        this.validateAgentEligibility(normalized);
        agentId = normalized;
      }
    }

    const metadataJson = input.metadata !== undefined ? JSON.stringify(input.metadata) : undefined;

    return this.conversationRepo.updateConversation(existing.id, {
      title,
      agentId,
      metadataJson
    });
  }

  /**
   * Archives a conversation (soft delete).
   */
  public archiveConversation(caller: CallerContext, conversationId: string): Conversation {
    const verified = this.validateCaller(caller, 'WRITE');
    const existing = this.conversationRepo.getConversationByIdOrThrow(conversationId);
    this.assertScopeAccess(verified, existing);
    return this.conversationRepo.archiveConversation(existing.id);
  }

  /**
   * Deletes a conversation and all its messages (hard delete).
   */
  public deleteConversation(caller: CallerContext, conversationId: string): boolean {
    const verified = this.validateCaller(caller, 'DELETE');
    const existing = this.conversationRepo.getConversationByIdOrThrow(conversationId);
    this.assertScopeAccess(verified, existing);
    return this.conversationRepo.deleteConversation(existing.id);
  }

  /**
   * Retrieves messages for a conversation with pagination.
   */
  public getMessages(
    caller: CallerContext,
    conversationId: string,
    filter: ListMessagesFilter = {}
  ): { messages: ConversationMessage[]; total: number } {
    const verified = this.validateCaller(caller, 'READ');
    const conversation = this.conversationRepo.getConversationByIdOrThrow(conversationId);
    this.assertScopeAccess(verified, conversation);
    return this.conversationRepo.listMessages(conversationId, filter);
  }

  /**
   * Sends a user message to a conversation, executes the assistant response
   * via general model completion or registered agent, and persists both messages.
   */
  public async sendMessage(
    caller: CallerContext,
    conversationId: string,
    input: SendConversationMessageInput
  ): Promise<ConversationResponse> {
    const verified = this.validateCaller(caller, 'WRITE');

    if (!input || typeof input !== 'object') {
      throw new ValidationError('SendConversationMessageInput must be an object.');
    }
    if (!input.content || typeof input.content !== 'string' || input.content.trim() === '') {
      throw new ValidationError("Message 'content' must be a non-empty string.");
    }
    if (input.content.length > MAX_MESSAGE_LENGTH) {
      throw new ValidationError(
        `Message length (${input.content.length}) exceeds maximum allowed of ${MAX_MESSAGE_LENGTH} characters.`
      );
    }

    const conversation = this.conversationRepo.getConversationByIdOrThrow(conversationId);
    this.assertScopeAccess(verified, conversation);

    if (conversation.status === 'ARCHIVED') {
      throw new ValidationError(`Cannot send message to archived conversation '${conversation.id}'.`);
    }

    const role = input.role ?? 'user';
    const content = input.content.trim();
    const clientMessageId = input.clientMessageId?.trim() || undefined;

    // --- Idempotency Check ---
    let userMessage: ConversationMessage | null = null;
    if (clientMessageId) {
      const existing = this.conversationRepo.getMessageByClientId(conversation.id, clientMessageId);
      if (existing) {
        // User message already stored. Check if assistant response exists after it.
        const recent = this.conversationRepo.listMessages(conversation.id, { limit: 10, order: 'DESC' });
        const latestMsg = recent.messages[0];
        if (latestMsg && latestMsg.role === 'assistant' && latestMsg.createdAt >= existing.createdAt) {
          return {
            conversation,
            userMessage: existing,
            assistantMessage: latestMsg
          };
        }
        // User message exists from a prior attempt that did not complete assistant generation
        userMessage = existing;
      }
    }

    // Persist user message if not already persisted
    if (!userMessage) {
      userMessage = this.conversationRepo.addMessage({
        conversationId: conversation.id,
        role,
        content,
        name: input.name?.trim() || undefined,
        clientMessageId,
        metadataJson: input.metadata ? JSON.stringify(input.metadata) : null
      });
    }

    // --- Generate Assistant Response ---
    if (conversation.agentId) {
      return await this.executeAgentConversation(verified, conversation, userMessage, input);
    } else {
      return await this.executeGeneralConversation(verified, conversation, userMessage);
    }
  }

  // --- Private Execution Handlers ---

  /**
   * Executes the default general-purpose conversation path via IModelProvider.generateCompletion().
   */
  private async executeGeneralConversation(
    caller: CallerContext,
    conversation: Conversation,
    userMessage: ConversationMessage
  ): Promise<ConversationResponse> {
    // 1. Load recent history bounded by maxHistoryMessages
    const historyResult = this.conversationRepo.listMessages(conversation.id, {
      limit: this.maxHistoryMessages,
      order: 'DESC'
    });
    // Reverse to chronological order (ASC)
    const historyAsc = historyResult.messages.reverse();

    // 2. Build sanitized ModelMessage array
    const modelMessages: ModelMessage[] = historyAsc.map((m) => ({
      role: m.role,
      content: defaultSecretScrubber.scrub(m.content),
      ...(m.name ? { name: m.name } : {}),
      ...(m.toolCallId ? { toolCallId: m.toolCallId } : {})
    }));

    // 3. Call model provider (do NOT catch and fabricate assistant response on failure)
    const completion = await this.modelProvider.generateCompletion(
      modelMessages,
      undefined,
      this.defaultModelConfig
    );

    // 4. Persist assistant response
    const assistantMessage = this.conversationRepo.addMessage({
      conversationId: conversation.id,
      role: 'assistant',
      content: completion.content,
      metadataJson: completion.usage ? JSON.stringify({ usage: completion.usage }) : null
    });

    return {
      conversation: this.conversationRepo.getConversationByIdOrThrow(conversation.id),
      userMessage,
      assistantMessage,
      usage: completion.usage
    };
  }

  /**
   * Executes an agent-backed conversation via AgentRegistry and TaskCoordinator.
   */
  private async executeAgentConversation(
    caller: CallerContext,
    conversation: Conversation,
    userMessage: ConversationMessage,
    input: SendConversationMessageInput
  ): Promise<ConversationResponse> {
    const agentId = conversation.agentId!;
    this.validateAgentEligibility(agentId);

    // 1. Load history for context
    const historyResult = this.conversationRepo.listMessages(conversation.id, {
      limit: this.maxHistoryMessages,
      order: 'DESC'
    });
    const historyAsc = historyResult.messages.reverse();

    // 2. Build AgentInput with authorized conversation context
    const agentInput: AgentInput = {
      goal: userMessage.content,
      caller,
      parameters: input.metadata ?? {},
      context: {
        conversationId: conversation.id,
        conversationTitle: conversation.title,
        messages: historyAsc.map((m) => ({
          role: m.role,
          content: defaultSecretScrubber.scrub(m.content),
          ...(m.name ? { name: m.name } : {})
        })),
        scope: {
          scopeType: conversation.scopeType,
          scopeId: conversation.scopeId
        }
      }
    };

    // 3. Execute via TaskCoordinator if present
    if (this.coordinator) {
      const output = await this.coordinator.executeAgent(agentId, agentInput);

      if (output.status !== 'COMPLETED') {
        const errorMsg = output.error || output.summary || `Agent '${agentId}' execution ${output.status}.`;
        throw new DomainError(
          defaultSecretScrubber.scrub(errorMsg),
          'AGENT_EXECUTION_FAILED',
          { agentId, status: output.status, taskId: output.taskId }
        );
      }

      // Format response text from agent output
      const responseText = this.extractAgentResponseText(output.result, output.summary);

      const assistantMessage = this.conversationRepo.addMessage({
        conversationId: conversation.id,
        role: 'assistant',
        content: responseText,
        name: agentId,
        metadataJson: JSON.stringify({
          agentId,
          taskId: output.taskId,
          usage: output.usage,
          stepsExecuted: output.stepsExecuted
        })
      });

      return {
        conversation: this.conversationRepo.getConversationByIdOrThrow(conversation.id),
        userMessage,
        assistantMessage,
        usage: output.usage
      };
    } else {
      // Fallback: AgentRegistry direct execution (e.g. isolated test environments)
      const agent = this.agentRegistry.getOrThrow(agentId);
      const output = await this.agentRegistry.execute(agentId, agentInput, {
        workspaceRoot: process.cwd(),
        toolRegistry: undefined as any,
        policyEngine: undefined as any,
        modelProvider: this.modelProvider,
        agentCaller: caller,
        listTools: () => [],
        getTool: () => undefined,
        executeTool: async () => {
          throw new SecurityViolationError('Direct tool execution without coordinator is disallowed.', 'TOOL_EXECUTION_DISALLOWED');
        }
      });

      if (output.status !== 'COMPLETED') {
        throw new DomainError(
          output.error || output.summary,
          'AGENT_EXECUTION_FAILED',
          { agentId, status: output.status }
        );
      }

      const responseText = this.extractAgentResponseText(output.result, output.summary);

      const assistantMessage = this.conversationRepo.addMessage({
        conversationId: conversation.id,
        role: 'assistant',
        content: responseText,
        name: agentId,
        metadataJson: JSON.stringify({
          agentId,
          usage: output.usage,
          stepsExecuted: output.stepsExecuted
        })
      });

      return {
        conversation: this.conversationRepo.getConversationByIdOrThrow(conversation.id),
        userMessage,
        assistantMessage,
        usage: output.usage
      };
    }
  }

  private extractAgentResponseText(result: Record<string, unknown>, summary: string): string {
    if (typeof result.response === 'string' && result.response.trim() !== '') {
      return result.response.trim();
    }
    if (typeof result.message === 'string' && result.message.trim() !== '') {
      return result.message.trim();
    }
    if (typeof result.echo === 'string' && result.echo.trim() !== '') {
      return result.echo.trim();
    }
    if (summary && summary.trim() !== '') {
      return summary.trim();
    }
    return JSON.stringify(result);
  }

  // --- Validation Helpers ---

  /**
   * Validates that an agent exists and supports conversation or general capability.
   */
  private validateAgentEligibility(agentId: string): void {
    if (!this.agentRegistry.has(agentId)) {
      throw new AgentNotFoundError(agentId);
    }
    const agent = this.agentRegistry.getOrThrow(agentId);
    if (!agent.supportsCapability('conversation') && !agent.supportsCapability('general')) {
      throw new AgentCapabilityError(agentId, 'conversation', {
        supportedCapabilities: agent.capabilities
      });
    }
  }

  /**
   * Validates caller context via host authorizer and enforces required permission.
   */
  private validateCaller(
    caller: CallerContext,
    requiredPermission?: MemoryPermission
  ): CallerContext {
    const verified = this.#authorizer.verify(caller);
    validateScope(verified.scope.scopeType, verified.scope.scopeId);

    const permissions =
      verified.permissions instanceof Set
        ? (verified.permissions as Set<MemoryPermission>)
        : new Set(verified.permissions);

    if (requiredPermission && !permissions.has(requiredPermission)) {
      throw new SecurityViolationError(
        `Caller '${verified.actor}' lacks required '${requiredPermission}' permission for conversations.`,
        'INSUFFICIENT_PERMISSIONS',
        { actor: verified.actor, requiredPermission, scope: verified.scope }
      );
    }

    return verified;
  }

  /**
   * Enforces scope isolation: caller scope must match conversation scope.
   */
  private assertScopeAccess(caller: CallerContext, conversation: Conversation): void {
    if (
      conversation.scopeType !== caller.scope.scopeType ||
      conversation.scopeId !== caller.scope.scopeId
    ) {
      throw new ConversationScopeViolationError(
        `${caller.scope.scopeType}:${caller.scope.scopeId}`,
        `${conversation.scopeType}:${conversation.scopeId}`,
        conversation.id
      );
    }
  }
}
