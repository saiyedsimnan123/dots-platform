/**
 * Next-Generation Dots AI Platform - Agent Execution Context Factory
 * Phase 1 / Phase 3 Agent Architecture Foundation
 * 
 * Architectural Mandate:
 * Constructs a secure execution context for agents. Guarantees that all
 * tool invocations route strictly through ToolRegistry, PolicyEngine,
 * and ApprovalBroker.
 */

import type {
  AgentExecutionContext,
  CreateAgentExecutionContextOptions
} from './types.ts';
import type { ToolContext, ToolExecutionResult } from '../tools/types.ts';
import { AgentCancelledError, ValidationError } from '../domain/errors.ts';

/**
 * Creates an immutable AgentExecutionContext for an agent execution session.
 */
export function createAgentExecutionContext(
  options: CreateAgentExecutionContextOptions
): AgentExecutionContext {
  if (!options || typeof options !== 'object') {
    throw new ValidationError('CreateAgentExecutionContextOptions must be an object.');
  }
  if (!options.workspaceRoot || typeof options.workspaceRoot !== 'string') {
    throw new ValidationError('workspaceRoot must be a valid non-empty string.');
  }
  if (!options.toolRegistry) {
    throw new ValidationError('toolRegistry must be provided in AgentExecutionContext.');
  }
  if (!options.policyEngine) {
    throw new ValidationError('policyEngine must be provided in AgentExecutionContext.');
  }

  const {
    taskId,
    workspaceRoot,
    toolRegistry,
    policyEngine,
    approvalBroker,
    modelProvider,
    memoryService,
    authorizer,
    hostAuthority,
    taskRepo,
    auditRepo,
    signal,
    logger,
    agentCaller
  } = options;

  return {
    taskId,
    workspaceRoot,
    toolRegistry,
    policyEngine,
    approvalBroker,
    modelProvider,
    memoryService,
    authorizer,
    hostAuthority,
    taskRepo,
    auditRepo,
    signal,
    logger,
    agentCaller,

    /**
     * Safely executes a registered tool through policy and approval gates.
     */
    async executeTool(
      toolName: string,
      args: Record<string, unknown>,
      approvalToken?: string
    ): Promise<ToolExecutionResult> {
      if (signal?.aborted) {
        throw new AgentCancelledError(
          `Tool execution cancelled by signal: ${signal.reason ? String(signal.reason) : 'aborted'}`
        );
      }

      const toolCtx: ToolContext = {
        taskId: taskId ?? 'unscoped-agent-task',
        stepId: 'agent-tool-step',
        workspaceRoot
      };

      const result = await toolRegistry.execute(
        toolName,
        args,
        toolCtx,
        policyEngine,
        approvalBroker,
        approvalToken
      );

      return result;
    }
  };
}
