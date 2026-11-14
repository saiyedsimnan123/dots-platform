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
import type { ToolDefinition } from '../model/types.ts';
import type { ToolContext, ToolExecutionResult } from '../tools/types.ts';
import {
  AgentCancelledError,
  SecurityViolationError,
  ToolExecutionError,
  ValidationError
} from '../domain/errors.ts';
import { defaultSecretScrubber } from '../model/secret-scrubber.ts';

const MAX_OUTPUT_STRING_LENGTH = 50_000;
const MAX_OUTPUT_ARRAY_ITEMS = 200;
const MAX_OUTPUT_OBJECT_KEYS = 100;

export function scrubAndBoundOutput(value: unknown, depth: number = 0): unknown {
  if (depth > 8) {
    return '[TRUNCATED_DEPTH]';
  }
  if (typeof value === 'string') {
    const scrubbed = defaultSecretScrubber.scrub(value);
    if (scrubbed.length > MAX_OUTPUT_STRING_LENGTH) {
      return scrubbed.slice(0, MAX_OUTPUT_STRING_LENGTH) + '\n... [output truncated at limit]';
    }
    return scrubbed;
  }
  if (Array.isArray(value)) {
    const sliced = value.slice(0, MAX_OUTPUT_ARRAY_ITEMS);
    const mapped = sliced.map((item) => scrubAndBoundOutput(item, depth + 1));
    if (value.length > MAX_OUTPUT_ARRAY_ITEMS) {
      mapped.push(`[TRUNCATED: ${value.length - MAX_OUTPUT_ARRAY_ITEMS} items omitted]`);
    }
    return mapped;
  }
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    const entries = Object.entries(value as Record<string, unknown>);
    const sliced = entries.slice(0, MAX_OUTPUT_OBJECT_KEYS);
    for (const [k, v] of sliced) {
      out[k] = scrubAndBoundOutput(v, depth + 1);
    }
    if (entries.length > MAX_OUTPUT_OBJECT_KEYS) {
      out['_truncatedKeysCount'] = entries.length - MAX_OUTPUT_OBJECT_KEYS;
    }
    return out;
  }
  return value;
}

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
     * Discovers all registered tool definitions available in this execution context.
     */
    listTools(): readonly ToolDefinition[] {
      return toolRegistry.listDefinitions();
    },

    /**
     * Retrieves a registered tool definition by name, or undefined if not found.
     */
    getTool(name: string): ToolDefinition | undefined {
      return toolRegistry.get(name)?.definition;
    },

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

      try {
        const result = await toolRegistry.execute(
          toolName,
          args,
          toolCtx,
          policyEngine,
          approvalBroker,
          approvalToken
        );

        if (signal?.aborted) {
          throw new AgentCancelledError(
            `Tool execution cancelled by signal: ${signal.reason ? String(signal.reason) : 'aborted'}`
          );
        }

        return {
          output: scrubAndBoundOutput(result.output) as Record<string, unknown>,
          exitCode: result.exitCode,
          durationMs: result.durationMs
        };
      } catch (err) {
        if (
          err instanceof SecurityViolationError ||
          err instanceof ValidationError ||
          err instanceof AgentCancelledError ||
          err instanceof ToolExecutionError
        ) {
          throw err;
        }
        const safeMsg = defaultSecretScrubber.scrub(err instanceof Error ? err.message : String(err));
        throw new ToolExecutionError(toolName, safeMsg);
      }
    }
  };
}
