/**
 * Next-Generation Dots AI Platform - Base Agent & Mock Agent
 * Phase 1 / Phase 3 Agent Architecture Foundation
 * 
 * Architectural Mandate:
 * Base abstract class providing shared lifecycle management, capability
 * resolution, input verification, and cancellation checks for all agents.
 */

import type {
  IAgent,
  AgentStatus,
  AgentConfig,
  AgentInput,
  AgentOutput,
  AgentExecutionContext
} from './types.ts';
import { AgentCancelledError, ValidationError } from '../domain/errors.ts';

export interface BaseAgentOptions {
  readonly id: string;
  readonly name: string;
  readonly description: string;
  readonly version?: string;
  readonly capabilities: readonly string[];
  readonly config?: AgentConfig;
}

/**
 * Abstract foundation for all Dots AI Platform agents.
 */
export abstract class BaseAgent implements IAgent {
  public readonly id: string;
  public readonly name: string;
  public readonly description: string;
  public readonly version: string;
  public readonly capabilities: readonly string[];
  public readonly config: AgentConfig;
  private _status: AgentStatus = 'IDLE';

  constructor(options: BaseAgentOptions) {
    if (!options || typeof options !== 'object') {
      throw new ValidationError('Agent options must be an object.');
    }
    if (!options.id || typeof options.id !== 'string' || options.id.trim() === '') {
      throw new ValidationError('Agent ID must be a non-empty string.');
    }
    if (!options.name || typeof options.name !== 'string' || options.name.trim() === '') {
      throw new ValidationError('Agent name must be a non-empty string.');
    }
    if (typeof options.description !== 'string') {
      throw new ValidationError('Agent description must be a string.');
    }
    if (!Array.isArray(options.capabilities)) {
      throw new ValidationError('Agent capabilities must be an array of strings.');
    }

    this.id = options.id.trim();
    this.name = options.name.trim();
    this.description = options.description.trim();
    this.version = options.version?.trim() || '1.0.0';
    this.capabilities = Object.freeze(
      options.capabilities.map((c) => {
        if (typeof c !== 'string' || c.trim() === '') {
          throw new ValidationError('Agent capability must be a non-empty string.');
        }
        return c.trim();
      })
    );
    this.config = Object.freeze({ ...options.config });
  }

  /**
   * Current lifecycle state of the agent.
   */
  public get status(): AgentStatus {
    return this._status;
  }

  /**
   * Internal helper to update lifecycle state.
   */
  protected setStatus(status: AgentStatus): void {
    this._status = status;
  }

  /**
   * Checks whether the agent supports a given capability (case-insensitive).
   */
  public supportsCapability(capability: string): boolean {
    if (!capability || typeof capability !== 'string') {
      return false;
    }
    const normalized = capability.trim().toLowerCase();
    return this.capabilities.some((c) => c.toLowerCase() === normalized);
  }

  /**
   * Checks whether the execution has been aborted by an AbortSignal.
   * Throws AgentCancelledError if cancellation was requested.
   */
  protected checkCancellation(signal?: AbortSignal): void {
    if (signal?.aborted) {
      this.setStatus('CANCELLED');
      throw new AgentCancelledError(
        `Agent execution was cancelled: ${signal.reason ? String(signal.reason) : 'AbortSignal received'}`,
        { agentId: this.id }
      );
    }
  }

  /**
   * Executes the agent's logic. Must be implemented by subclasses.
   */
  public abstract execute(
    input: AgentInput,
    context: AgentExecutionContext
  ): Promise<AgentOutput>;
}

export interface MockAgentOptions {
  readonly id?: string;
  readonly name?: string;
  readonly description?: string;
  readonly version?: string;
  readonly capabilities?: readonly string[];
  readonly config?: AgentConfig;
  readonly executeMock?: (
    input: AgentInput,
    context: AgentExecutionContext
  ) => Promise<AgentOutput>;
}

/**
 * Concrete agent implementation for unit tests, mocking, and fallback execution.
 */
export class MockAgent extends BaseAgent {
  public executeMock?: (
    input: AgentInput,
    context: AgentExecutionContext
  ) => Promise<AgentOutput>;

  constructor(options: MockAgentOptions = {}) {
    super({
      id: options.id ?? 'mock-agent',
      name: options.name ?? 'Mock Agent',
      description: options.description ?? 'General mock agent for testing',
      version: options.version ?? '1.0.0',
      capabilities: options.capabilities ?? ['general', 'testing'],
      config: options.config
    });
    this.executeMock = options.executeMock;
  }

  public async execute(
    input: AgentInput,
    context: AgentExecutionContext
  ): Promise<AgentOutput> {
    const startMs = Date.now();
    this.checkCancellation(input.signal ?? context.signal);
    this.setStatus('EXECUTING');

    if (this.executeMock) {
      try {
        const output = await this.executeMock(input, context);
        if (input.signal?.aborted || context.signal?.aborted) {
          this.setStatus('CANCELLED');
          return {
            ...output,
            status: 'CANCELLED',
            summary: `Agent execution was cancelled: ${input.signal?.reason || context.signal?.reason || 'aborted'}`
          };
        }
        this.setStatus(output.status === 'COMPLETED' ? 'COMPLETED' : 'FAILED');
        return output;
      } catch (err) {
        if (err instanceof AgentCancelledError || (input.signal?.aborted ?? context.signal?.aborted)) {
          this.setStatus('CANCELLED');
        } else {
          this.setStatus('FAILED');
        }
        throw err;
      }
    }

    const durationMs = Date.now() - startMs;
    this.setStatus('COMPLETED');
    return {
      agentId: this.id,
      taskId: input.taskId ?? context.taskId,
      status: 'COMPLETED',
      result: {
        echo: input.goal,
        parameters: input.parameters ?? {}
      },
      summary: `Successfully executed MockAgent for goal: "${input.goal}"`,
      stepsExecuted: 1,
      durationMs: Math.max(1, durationMs)
    };
  }
}
