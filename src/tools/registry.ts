/**
 * Next-Generation Dots AI Platform - Tool Registry
 * 
 * Architectural Mandate:
 * Strongly-typed catalog and invocation gateway for agent capabilities.
 * Enforces:
 * 1. Verification of tool registration before execution.
 * 2. Compulsory policy evaluation and path sanitization prior to execution.
 * 3. Human approval verification for Tier 3 and Tier 4 operations.
 */

import type { ToolDefinition } from '../model/types.ts';
import type { RegisteredTool, ToolContext, ToolExecutionResult } from './types.ts';
import { standardTools } from './sandbox-tools.ts';
import type { PolicyEngine } from '../security/policy-engine.ts';
import type { ApprovalBroker } from '../security/approval-broker.ts';
import { ValidationError, SecurityViolationError } from '../domain/errors.ts';

export class ToolRegistry {
  private readonly tools: Map<string, RegisteredTool> = new Map();

  constructor(initialTools: readonly RegisteredTool[] = standardTools) {
    for (const tool of initialTools) {
      this.register(tool);
    }
  }

  /**
   * Registers a new tool into the registry.
   */
  public register(tool: RegisteredTool): void {
    if (!tool.definition.name) {
      throw new ValidationError('Tool definition must have a valid name.');
    }
    this.tools.set(tool.definition.name, tool);
  }

  /**
   * Retrieves a registered tool by name.
   */
  public get(name: string): RegisteredTool | undefined {
    return this.tools.get(name);
  }

  /**
   * Returns definitions for all registered tools (used by prompt compiler).
   */
  public listDefinitions(): ToolDefinition[] {
    return Array.from(this.tools.values()).map((t) => t.definition);
  }

  /**
   * Safely executes a tool through the policy gate and sandbox.
   */
  public async execute(
    toolName: string,
    rawArgs: Record<string, unknown>,
    context: ToolContext,
    policyEngine: PolicyEngine,
    approvalBroker?: ApprovalBroker,
    approvalToken?: string
  ): Promise<ToolExecutionResult> {
    const tool = this.get(toolName);
    if (!tool) {
      throw new ValidationError(`Tool '${toolName}' is not registered in the tool registry.`);
    }

    // 1. Evaluate policy
    const policy = policyEngine.evaluate(toolName, rawArgs, tool.riskTier);

    if (policy.decision === 'DENIED') {
      throw new SecurityViolationError(
        `Policy Denied: ${policy.reason}`,
        'POLICY_REJECTION',
        { toolName, rawArgs }
      );
    }

    // 2. Enforce human approval for Tier 3 / Tier 4 actions
    if (policy.decision === 'REQUIRES_APPROVAL') {
      if (!approvalBroker || !approvalToken || !approvalBroker.isApproved(approvalToken)) {
        throw new SecurityViolationError(
          `Action requires explicit human approval before execution (${toolName}).`,
          'APPROVAL_REQUIRED',
          { toolName, riskTier: tool.riskTier, reason: policy.reason }
        );
      }
    }

    // 3. Execute the tool with sanitized arguments
    return await tool.handler(policy.sanitizedArguments, context);
  }
}
