/**
 * Next-Generation Dots AI Platform - Deterministic Mock Model Provider
 * 
 * Architectural Mandate:
 * Enables 100% offline, zero-cost, deterministic testing of the agent runtime.
 * Allows test suites to script planned steps, simulate API failures, and verify
 * token accounting without contacting external cloud endpoints.
 */

import type {
  IModelProvider,
  ToolDefinition,
  ModelMessage,
  ModelConfig,
  PlanStepProposal,
  PlanGenerationResult,
  CompletionResult,
  ToolCallProposal,
  ModelUsage
} from './types.ts';

export interface RecordedCall {
  readonly method: 'generatePlan' | 'generateCompletion';
  readonly args: Record<string, unknown>;
  readonly timestamp: string;
}

export class MockModelProvider implements IModelProvider {
  public readonly name: string = 'mock-provider';
  public readonly modelId: string;

  private planQueue: PlanStepProposal[][] = [];
  private completionQueue: CompletionResult[] = [];
  private failureQueue: Error[] = [];
  private readonly calls: RecordedCall[] = [];

  constructor(modelId: string = 'mock-deterministic-v1') {
    this.modelId = modelId;
  }

  /**
   * Enqueues a scripted plan to be returned on the next generatePlan() call.
   */
  public enqueuePlan(steps: PlanStepProposal[]): void {
    this.planQueue.push(steps);
  }

  /**
   * Enqueues a scripted completion result to be returned on the next generateCompletion() call.
   */
  public enqueueCompletion(content: string, toolCalls?: ToolCallProposal[]): void {
    const promptLen = 100;
    const compLen = content.length;
    this.completionQueue.push({
      content,
      toolCalls: toolCalls ? [...toolCalls] : undefined,
      usage: {
        promptTokens: Math.ceil(promptLen / 4),
        completionTokens: Math.ceil(compLen / 4),
        totalTokens: Math.ceil((promptLen + compLen) / 4),
        estimatedCostUsd: 0.00001
      }
    });
  }

  /**
   * Enqueues an error to be thrown on the next call.
   */
  public simulateFailureNext(error: Error): void {
    this.failureQueue.push(error);
  }

  /**
   * Generates a plan using either an enqueued plan or a deterministic default.
   */
  public async generatePlan(
    goal: string,
    availableTools: readonly ToolDefinition[],
    context?: string
  ): Promise<PlanGenerationResult> {
    this.recordCall('generatePlan', { goal, availableTools, context });

    if (this.failureQueue.length > 0) {
      const err = this.failureQueue.shift();
      if (err) throw err;
    }

    let steps: PlanStepProposal[];
    if (this.planQueue.length > 0) {
      steps = this.planQueue.shift()!;
    } else {
      // Deterministic fallback plan calling the first available tool
      const defaultTool = availableTools.length > 0 ? availableTools[0]!.name : 'noop';
      steps = [
        {
          stepOrder: 1,
          description: `Execute deterministic default action for: ${goal}`,
          toolName: defaultTool,
          arguments: { target: 'default_payload' },
          expectedOutcome: 'Operation completed successfully'
        }
      ];
    }

    const rawResponse = JSON.stringify({ steps }, null, 2);
    const promptChars = goal.length + (context?.length ?? 0);
    const compChars = rawResponse.length;

    const usage: ModelUsage = {
      promptTokens: Math.ceil(promptChars / 4) + 50,
      completionTokens: Math.ceil(compChars / 4),
      totalTokens: Math.ceil(promptChars / 4) + 50 + Math.ceil(compChars / 4),
      estimatedCostUsd: 0.00005
    };

    return {
      steps,
      rawResponse,
      usage
    };
  }

  /**
   * Generates a completion using either an enqueued completion or a deterministic default.
   */
  public async generateCompletion(
    messages: readonly ModelMessage[],
    tools?: readonly ToolDefinition[],
    config?: ModelConfig
  ): Promise<CompletionResult> {
    this.recordCall('generateCompletion', { messages, tools, config });

    if (this.failureQueue.length > 0) {
      const err = this.failureQueue.shift();
      if (err) throw err;
    }

    if (this.completionQueue.length > 0) {
      return this.completionQueue.shift()!;
    }

    const lastMessage = messages.length > 0 ? messages[messages.length - 1]!.content : '';
    const content = `Mock response to: ${lastMessage}`;

    return {
      content,
      usage: {
        promptTokens: 25,
        completionTokens: 15,
        totalTokens: 40,
        estimatedCostUsd: 0.00001
      }
    };
  }

  /**
   * Returns a copy of the recorded call log.
   */
  public getRecordedCalls(): readonly RecordedCall[] {
    return [...this.calls];
  }

  /**
   * Clears recorded call history.
   */
  public clearHistory(): void {
    this.calls.length = 0;
  }

  private recordCall(method: 'generatePlan' | 'generateCompletion', args: Record<string, unknown>): void {
    this.calls.push({
      method,
      args,
      timestamp: new Date().toISOString()
    });
  }
}
