/**
 * Next-Generation Dots AI Platform - Agent Registry
 * Phase 1 / Phase 3 Agent Architecture Foundation
 * 
 * Architectural Mandate:
 * Central catalog, capability validator, and safe execution gateway for all agents.
 * Guarantees:
 * 1. Strict duplicate registration rejection.
 * 2. Capability verification before dispatch.
 * 3. Consistent execution interface with cancellation, timeout, and error containment.
 */

import type {
  IAgent,
  AgentMetadata,
  AgentInput,
  AgentOutput,
  AgentExecutionContext
} from './types.ts';
import {
  AgentNotFoundError,
  DuplicateAgentRegistrationError,
  AgentCapabilityError,
  AgentCancelledError,
  ValidationError
} from '../domain/errors.ts';

export class AgentRegistry {
  private readonly agents: Map<string, IAgent> = new Map();

  constructor(initialAgents: readonly IAgent[] = []) {
    for (const agent of initialAgents) {
      this.register(agent);
    }
  }

  /**
   * Registers an agent into the platform catalog.
   * Throws DuplicateAgentRegistrationError if an agent with the same ID already exists.
   */
  public register(agent: IAgent): void {
    if (!agent || typeof agent !== 'object') {
      throw new ValidationError('Agent must be a valid IAgent object.');
    }
    if (!agent.id || typeof agent.id !== 'string' || agent.id.trim() === '') {
      throw new ValidationError('Agent ID must be a non-empty string.');
    }

    const normalizedId = agent.id.trim();
    if (this.agents.has(normalizedId)) {
      throw new DuplicateAgentRegistrationError(normalizedId);
    }

    this.agents.set(normalizedId, agent);
  }

  /**
   * Unregisters an agent by ID. Returns true if removed, false if not found.
   */
  public unregister(agentId: string): boolean {
    if (!agentId || typeof agentId !== 'string') {
      return false;
    }
    return this.agents.delete(agentId.trim());
  }

  /**
   * Retrieves an agent by its unique ID. Returns undefined if not found.
   */
  public get(agentId: string): IAgent | undefined {
    if (!agentId || typeof agentId !== 'string') {
      return undefined;
    }
    return this.agents.get(agentId.trim());
  }

  /**
   * Retrieves an agent by its unique ID or throws AgentNotFoundError.
   */
  public getOrThrow(agentId: string): IAgent {
    const agent = this.get(agentId);
    if (!agent) {
      throw new AgentNotFoundError(agentId);
    }
    return agent;
  }

  /**
   * Returns true if an agent with the given ID is registered.
   */
  public has(agentId: string): boolean {
    if (!agentId || typeof agentId !== 'string') {
      return false;
    }
    return this.agents.has(agentId.trim());
  }

  /**
   * Lists all registered agent instances.
   */
  public list(): readonly IAgent[] {
    return Array.from(this.agents.values());
  }

  /**
   * Returns metadata descriptors for all registered agents.
   */
  public listDefinitions(): readonly AgentMetadata[] {
    return Array.from(this.agents.values()).map((agent) => ({
      id: agent.id,
      name: agent.name,
      description: agent.description,
      version: agent.version,
      capabilities: [...agent.capabilities]
    }));
  }

  /**
   * Finds all registered agents supporting the specified capability.
   */
  public findByCapability(capability: string): readonly IAgent[] {
    if (!capability || typeof capability !== 'string') {
      return [];
    }
    return Array.from(this.agents.values()).filter((agent) =>
      agent.supportsCapability(capability)
    );
  }

  /**
   * Validates that a registered agent exists and supports the required capability.
   * Throws AgentNotFoundError if agent does not exist.
   * Throws AgentCapabilityError if capability is not supported.
   */
  public validateCapability(agentId: string, capability: string): boolean {
    const agent = this.getOrThrow(agentId);
    if (!agent.supportsCapability(capability)) {
      throw new AgentCapabilityError(agentId, capability);
    }
    return true;
  }

  /**
   * Safely executes a registered agent with standardized error handling and cancellation support.
   */
  public async execute(
    agentId: string,
    input: AgentInput,
    context: AgentExecutionContext
  ): Promise<AgentOutput> {
    const agent = this.getOrThrow(agentId);

    if (!input || typeof input !== 'object') {
      throw new ValidationError('AgentInput must be an object.');
    }
    if (!input.goal || typeof input.goal !== 'string' || input.goal.trim() === '') {
      throw new ValidationError('Agent input goal must be a non-empty string.');
    }

    const signal = input.signal ?? context.signal;

    // Check pre-flight cancellation
    if (signal?.aborted) {
      const reason = signal.reason ? String(signal.reason) : 'Execution cancelled before start.';
      return {
        agentId: agent.id,
        taskId: input.taskId ?? context.taskId,
        status: 'CANCELLED',
        result: {},
        summary: `Agent execution was cancelled before start: ${reason}`,
        error: reason,
        stepsExecuted: 0,
        durationMs: 0
      };
    }

    const startMs = Date.now();
    try {
      const output = await agent.execute(input, context);
      if (signal?.aborted && output.status !== 'CANCELLED') {
        return {
          ...output,
          status: 'CANCELLED',
          summary: `Agent execution was cancelled: ${signal.reason ? String(signal.reason) : 'aborted'}`,
          error: signal.reason ? String(signal.reason) : 'Execution cancelled'
        };
      }
      return output;
    } catch (err) {
      const durationMs = Math.max(0, Date.now() - startMs);

      if (err instanceof AgentCancelledError || (signal && signal.aborted)) {
        const errorMsg = err instanceof Error ? err.message : String(err);
        return {
          agentId: agent.id,
          taskId: input.taskId ?? context.taskId,
          status: 'CANCELLED',
          result: {},
          summary: `Agent execution was cancelled: ${errorMsg}`,
          error: errorMsg,
          stepsExecuted: 0,
          durationMs
        };
      }

      const errorMessage = err instanceof Error ? err.message : String(err);
      return {
        agentId: agent.id,
        taskId: input.taskId ?? context.taskId,
        status: 'FAILED',
        result: {},
        summary: `Agent execution failed: ${errorMessage}`,
        error: errorMessage,
        stepsExecuted: 0,
        durationMs
      };
    }
  }
}
