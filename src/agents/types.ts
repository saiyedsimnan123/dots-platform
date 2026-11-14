/**
 * Next-Generation Dots AI Platform - Shared Agent Interface Types
 * Phase 1 / Phase 3 Agent Architecture Foundation
 * 
 * Architectural Mandate:
 * Strongly-typed universal agent interface contract.
 * Unifies specialized agents (Research, Developer, Analytics, etc.) under
 * a common lifecycle, capability system, execution context, and safety perimeter.
 */

import type { CallerContext, BuiltMemoryContext } from '../domain/types.ts';
import type { IModelProvider, ModelConfig, ModelUsage, ToolDefinition } from '../model/types.ts';
import type { ToolRegistry } from '../tools/registry.ts';
import type { ToolExecutionResult } from '../tools/types.ts';
import type { PolicyEngine } from '../security/policy-engine.ts';
import type { ApprovalBroker } from '../security/approval-broker.ts';
import type { MemoryService } from '../memory/memory-service.ts';
import type { MemoryAuthorizer } from '../security/memory-authorizer.ts';
import type { HostMemoryAuthority } from '../security/host-authority.ts';
import type { TaskRepository } from '../storage/task-repository.ts';
import type { AuditRepository } from '../storage/audit-repository.ts';
import type { OperationalLogger } from '../runtime/logger.ts';

/**
 * Standard agent capability classifications matching platform roadmap phases.
 * Uses (string & {}) to preserve autocomplete while allowing extensible custom domain capabilities.
 */
export type AgentCapability =
  | 'general'
  | 'research'
  | 'developer'
  | 'analytics'
  | 'conversation'
  | 'planning'
  | 'decision_support'
  | 'data_engineering'
  | 'verification'
  | (string & {});

/**
 * High-level lifecycle states of an agent instance.
 */
export type AgentStatus =
  | 'IDLE'
  | 'EXECUTING'
  | 'PAUSED'
  | 'COMPLETED'
  | 'FAILED'
  | 'CANCELLED';

/**
 * Terminal execution status returned in AgentOutput.
 */
export type AgentExecutionStatus = 'COMPLETED' | 'FAILED' | 'CANCELLED';

/**
 * Metadata descriptor for an agent definition in the registry catalog.
 */
export interface AgentMetadata {
  readonly id: string;
  readonly name: string;
  readonly description: string;
  readonly version?: string;
  readonly capabilities: readonly string[];
  readonly author?: string;
  readonly tags?: readonly string[];
}

/**
 * Configuration parameters for initializing or customizing an agent.
 */
export interface AgentConfig {
  readonly modelProvider?: IModelProvider;
  readonly modelConfig?: ModelConfig;
  readonly temperature?: number;
  readonly maxSteps?: number;
  readonly timeoutMs?: number;
  readonly customSettings?: Readonly<Record<string, unknown>>;
}

/**
 * Standard input payload delivered to an agent for task execution.
 */
export interface AgentInput {
  readonly goal: string;
  readonly taskId?: string;
  readonly parameters?: Readonly<Record<string, unknown>>;
  readonly context?: Readonly<Record<string, unknown>>;
  readonly caller?: CallerContext;
  readonly signal?: AbortSignal;
}

/**
 * Standard structured execution outcome returned by an agent.
 */
export interface AgentOutput {
  readonly agentId: string;
  readonly taskId?: string;
  readonly status: AgentExecutionStatus;
  readonly result: Record<string, unknown>;
  readonly summary: string;
  readonly error?: string;
  readonly stepsExecuted: number;
  readonly durationMs: number;
  readonly usage?: ModelUsage;
  readonly metadata?: Record<string, unknown>;
}

/**
 * Execution context provided to an agent during task execution.
 * Grants safe access to tools, memory, security policies, and task persistence.
 */
export interface AgentExecutionContext {
  readonly taskId?: string;
  readonly workspaceRoot: string;
  readonly toolRegistry: ToolRegistry;
  readonly policyEngine: PolicyEngine;
  readonly approvalBroker?: ApprovalBroker;
  readonly modelProvider?: IModelProvider;
  readonly memoryService?: MemoryService;
  readonly authorizer?: MemoryAuthorizer;
  readonly hostAuthority?: HostMemoryAuthority;
  readonly taskRepo?: TaskRepository;
  readonly auditRepo?: AuditRepository;
  readonly signal?: AbortSignal;
  readonly logger?: OperationalLogger;
  readonly agentCaller?: CallerContext;
  readonly memoryContext?: BuiltMemoryContext;

  /**
   * Discovers all registered tool definitions available in this execution context.
   */
  listTools(): readonly ToolDefinition[];

  /**
   * Retrieves a registered tool definition by name, or undefined if not found.
   */
  getTool(name: string): ToolDefinition | undefined;

  /**
   * Safely executes a registered tool through the platform PolicyEngine and ApprovalBroker.
   * Enforces risk tiers, workspace jail confinement, path traversal prevention,
   * and human approval verification for Tier 3 and Tier 4 operations.
   */
  executeTool(
    toolName: string,
    args: Record<string, unknown>,
    approvalToken?: string
  ): Promise<ToolExecutionResult>;
}

/**
 * Options for constructing an AgentExecutionContext instance.
 */
export interface CreateAgentExecutionContextOptions {
  readonly taskId?: string;
  readonly workspaceRoot: string;
  readonly toolRegistry: ToolRegistry;
  readonly policyEngine: PolicyEngine;
  readonly approvalBroker?: ApprovalBroker;
  readonly modelProvider?: IModelProvider;
  readonly memoryService?: MemoryService;
  readonly authorizer?: MemoryAuthorizer;
  readonly hostAuthority?: HostMemoryAuthority;
  readonly taskRepo?: TaskRepository;
  readonly auditRepo?: AuditRepository;
  readonly signal?: AbortSignal;
  readonly logger?: OperationalLogger;
  readonly agentCaller?: CallerContext;
  readonly memoryContext?: BuiltMemoryContext;
}

/**
 * Universal Shared Agent Contract.
 * All platform agents (Research, Developer, Analytics, etc.) must adhere to this interface.
 */
export interface IAgent {
  readonly id: string;
  readonly name: string;
  readonly description: string;
  readonly version: string;
  readonly capabilities: readonly string[];
  readonly config?: AgentConfig;
  readonly status: AgentStatus;

  /**
   * Checks whether this agent supports the specified capability.
   */
  supportsCapability(capability: string): boolean;

  /**
   * Executes the agent on the given input within the provided execution context.
   */
  execute(input: AgentInput, context: AgentExecutionContext): Promise<AgentOutput>;
}
