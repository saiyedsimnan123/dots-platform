/**
 * Next-Generation Dots AI Platform - Google Gemini Model Provider
 * 
 * Architectural Mandate:
 * Concrete adapter for Google Gemini models using standard fetch().
 * Eliminates heavy third-party vendor SDKs, operates with zero extra dependencies,
 * and maintains strict secret masking and cost calculation.
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
  ModelUsage,
  CompiledPlanPrompt
} from './types.ts';
import { PromptCompiler } from './prompt-compiler.ts';
import { ValidationError, DatabaseError } from '../domain/errors.ts';

export interface GeminiProviderOptions {
  readonly apiKey?: string;
  readonly modelId?: string;
  readonly baseUrl?: string;
  readonly promptCompiler?: PromptCompiler;
}

interface GeminiContent {
  role: 'user' | 'model';
  parts: Array<{ text?: string; functionCall?: { name: string; args: Record<string, unknown> } }>;
}

interface GeminiResponse {
  candidates?: Array<{
    content?: {
      parts?: Array<{
        text?: string;
        functionCall?: { name: string; args: Record<string, unknown> };
      }>;
    };
    finishReason?: string;
  }>;
  usageMetadata?: {
    promptTokenCount?: number;
    candidatesTokenCount?: number;
    totalTokenCount?: number;
  };
  error?: {
    code: number;
    message: string;
    status: string;
  };
}

export class GeminiProvider implements IModelProvider {
  public readonly name: string = 'google-gemini';
  public readonly modelId: string;

  private readonly apiKey: string;
  private readonly baseUrl: string;
  private readonly compiler: PromptCompiler;

  constructor(options: GeminiProviderOptions = {}) {
    this.apiKey = options.apiKey || process.env.GEMINI_API_KEY || '';
    this.modelId = options.modelId || 'gemini-2.5-flash';
    this.baseUrl = options.baseUrl || 'https://generativelanguage.googleapis.com/v1beta';
    this.compiler = options.promptCompiler || new PromptCompiler();
  }

  /**
   * Generates a structured plan via Gemini's JSON mode.
   * Uses pre-compiled prompt when provided; otherwise compiles from goal, tools, and context.
   */
  public async generatePlan(
    goal: string,
    availableTools: readonly ToolDefinition[],
    contextOrCompiledPrompt?: string | CompiledPlanPrompt,
    compiledPrompt?: CompiledPlanPrompt
  ): Promise<PlanGenerationResult> {
    this.assertApiKey();

    let effectiveCompiled: CompiledPlanPrompt | undefined;
    let effectiveContext: string | undefined;

    if (compiledPrompt) {
      effectiveCompiled = compiledPrompt;
      effectiveContext = typeof contextOrCompiledPrompt === 'string' ? contextOrCompiledPrompt : undefined;
    } else if (
      contextOrCompiledPrompt &&
      typeof contextOrCompiledPrompt === 'object' &&
      'systemInstruction' in contextOrCompiledPrompt
    ) {
      effectiveCompiled = contextOrCompiledPrompt;
      effectiveContext = undefined;
    } else if (typeof contextOrCompiledPrompt === 'string') {
      effectiveContext = contextOrCompiledPrompt;
    }

    const { systemInstruction, userPrompt } = effectiveCompiled ??
      this.compiler.compilePlanPrompt(goal, availableTools, effectiveContext);

    const endpoint = `${this.baseUrl}/models/${this.modelId}:generateContent?key=${this.apiKey}`;
    const payload = {
      systemInstruction: {
        parts: [{ text: systemInstruction }]
      },
      contents: [
        {
          role: 'user',
          parts: [{ text: userPrompt }]
        }
      ],
      generationConfig: {
        responseMimeType: 'application/json',
        temperature: 0.1
      }
    };

    const response = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    if (!response.ok) {
      const errText = await response.text();
      throw new DatabaseError(`Gemini API error (HTTP ${response.status}): ${errText}`);
    }

    const data = (await response.json()) as GeminiResponse;
    if (data.error) {
      throw new DatabaseError(`Gemini error: ${data.error.message} (${data.error.status})`);
    }

    const rawText = data.candidates?.[0]?.content?.parts?.[0]?.text || '{}';
    let steps: PlanStepProposal[] = [];

    try {
      const parsed = JSON.parse(rawText) as { steps?: PlanStepProposal[] };
      if (Array.isArray(parsed.steps)) {
        steps = parsed.steps.map((s, idx) => ({
          stepOrder: s.stepOrder ?? idx + 1,
          description: s.description || `Step ${idx + 1}`,
          toolName: s.toolName || 'noop',
          arguments: s.arguments || {},
          expectedOutcome: s.expectedOutcome || 'Step completed'
        }));
      }
    } catch {
      throw new ValidationError(`Failed to parse structured plan from Gemini output: ${rawText}`);
    }

    const promptTokens = data.usageMetadata?.promptTokenCount ?? 0;
    const completionTokens = data.usageMetadata?.candidatesTokenCount ?? 0;
    const totalTokens = data.usageMetadata?.totalTokenCount ?? promptTokens + completionTokens;
    // Gemini 2.5/1.5 Flash pricing: ~$0.075/1M input, ~$0.30/1M output
    const estimatedCostUsd = (promptTokens * 0.000000075) + (completionTokens * 0.00000030);

    return {
      steps,
      rawResponse: rawText,
      usage: {
        promptTokens,
        completionTokens,
        totalTokens,
        estimatedCostUsd
      }
    };
  }

  /**
   * Generates a conversational completion with optional function declarations.
   */
  public async generateCompletion(
    messages: readonly ModelMessage[],
    tools?: readonly ToolDefinition[],
    config?: ModelConfig
  ): Promise<CompletionResult> {
    this.assertApiKey();

    const sanitizedMessages = this.compiler.compileMessages(messages);
    const contents: GeminiContent[] = [];

    for (const msg of sanitizedMessages) {
      const role: 'user' | 'model' = msg.role === 'assistant' ? 'model' : 'user';
      contents.push({
        role,
        parts: [{ text: msg.content }]
      });
    }

    const endpoint = `${this.baseUrl}/models/${this.modelId}:generateContent?key=${this.apiKey}`;
    const payload: Record<string, unknown> = {
      contents,
      generationConfig: {
        temperature: config?.temperature ?? 0.2,
        maxOutputTokens: config?.maxTokens ?? 2048,
        stopSequences: config?.stopSequences
      }
    };

    if (tools && tools.length > 0) {
      payload.tools = [
        {
          functionDeclarations: tools.map((t) => ({
            name: t.name,
            description: t.description,
            parameters: {
              type: 'OBJECT',
              properties: t.parameters,
              required: t.required ? [...t.required] : []
            }
          }))
        }
      ];
    }

    const response = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    if (!response.ok) {
      const errText = await response.text();
      throw new DatabaseError(`Gemini completion error (HTTP ${response.status}): ${errText}`);
    }

    const data = (await response.json()) as GeminiResponse;
    const part = data.candidates?.[0]?.content?.parts?.[0];
    const textContent = part?.text || '';

    const toolCalls: ToolCallProposal[] = [];
    if (part?.functionCall) {
      toolCalls.push({
        id: `call_${Date.now()}`,
        toolName: part.functionCall.name,
        arguments: part.functionCall.args || {}
      });
    }

    const promptTokens = data.usageMetadata?.promptTokenCount ?? 0;
    const completionTokens = data.usageMetadata?.candidatesTokenCount ?? 0;
    const totalTokens = data.usageMetadata?.totalTokenCount ?? promptTokens + completionTokens;
    const estimatedCostUsd = (promptTokens * 0.000000075) + (completionTokens * 0.00000030);

    return {
      content: textContent,
      toolCalls: toolCalls.length > 0 ? toolCalls : undefined,
      usage: {
        promptTokens,
        completionTokens,
        totalTokens,
        estimatedCostUsd
      }
    };
  }

  private assertApiKey(): void {
    if (!this.apiKey || this.apiKey.trim() === '') {
      throw new ValidationError(
        'Gemini API key is not configured. Set GEMINI_API_KEY environment variable or supply apiKey in options.'
      );
    }
  }
}
