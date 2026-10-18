/**
 * Next-Generation Dots AI Platform - Model Gateway Types
 * 
 * Architectural Mandate:
 * Provider-independent model abstraction. Orchestration reasoning interacts solely
 * with these interfaces, allowing zero-code-change switching between Google Gemini,
 * OpenAI, Anthropic, local Ollama, and offline Mock providers.
 */

export type ModelRole = 'system' | 'user' | 'assistant' | 'tool';

export interface ModelMessage {
  readonly role: ModelRole;
  readonly content: string;
  readonly name?: string;
  readonly toolCallId?: string;
}

export interface ToolParameterProperty {
  readonly type: string;
  readonly description: string;
  readonly enum?: readonly string[];
}

export interface ToolDefinition {
  readonly name: string;
  readonly description: string;
  readonly parameters: Record<string, ToolParameterProperty>;
  readonly required?: readonly string[];
}

export interface ToolCallProposal {
  readonly id: string;
  readonly toolName: string;
  readonly arguments: Record<string, unknown>;
}

export interface PlanStepProposal {
  readonly stepOrder: number;
  readonly description: string;
  readonly toolName: string;
  readonly arguments: Record<string, unknown>;
  readonly expectedOutcome: string;
}

export interface ModelUsage {
  readonly promptTokens: number;
  readonly completionTokens: number;
  readonly totalTokens: number;
  readonly estimatedCostUsd: number;
}

export interface PlanGenerationResult {
  readonly steps: readonly PlanStepProposal[];
  readonly rawResponse: string;
  readonly usage: ModelUsage;
}

export interface CompletionResult {
  readonly content: string;
  readonly toolCalls?: readonly ToolCallProposal[];
  readonly usage: ModelUsage;
}

export interface ModelConfig {
  readonly temperature?: number;
  readonly maxTokens?: number;
  readonly stopSequences?: readonly string[];
}

export interface CompiledPlanPrompt {
  readonly systemInstruction: string;
  readonly userPrompt: string;
  readonly contextOmitted: boolean;
  readonly contextIncluded: boolean;
}

/**
 * Universal interface for all AI model providers.
 */
export interface IModelProvider {
  readonly name: string;
  readonly modelId: string;

  /**
   * Generates a structured multi-step plan for the given goal and available tools.
   * Supports both legacy callers passing optional context string, and callers passing
   * a pre-compiled, scrubbed, bounded prompt (CompiledPlanPrompt).
   */
  generatePlan(
    goal: string,
    availableTools: readonly ToolDefinition[],
    context?: string | CompiledPlanPrompt,
    compiledPrompt?: CompiledPlanPrompt
  ): Promise<PlanGenerationResult>;

  /**
   * Generates a single completion step with optional tool calling.
   */
  generateCompletion(
    messages: readonly ModelMessage[],
    tools?: readonly ToolDefinition[],
    config?: ModelConfig
  ): Promise<CompletionResult>;
}
