/**
 * Next-Generation Dots AI Platform - Prompt Compiler
 * 
 * Architectural Mandate:
 * Assembles structured, safe prompts for model providers.
 * Enforces:
 * 1. Separation of trusted system instructions and untrusted user content.
 * 2. Mandatory secret scrubbing before any prompt is emitted.
 * 3. Context window length bounding to prevent memory/token exhaustion.
 */

import type { ToolDefinition, ModelMessage } from './types.ts';
import { SecretScrubber, defaultSecretScrubber } from './secret-scrubber.ts';
import { ValidationError } from '../domain/errors.ts';

export interface PromptCompilerOptions {
  readonly maxContextChars?: number;
  readonly scrubber?: SecretScrubber;
  readonly defaultSystemPrompt?: string;
}

export interface CompiledPlanPrompt {
  readonly systemInstruction: string;
  readonly userPrompt: string;
  readonly contextOmitted: boolean;
}

export class PromptCompiler {
  public static readonly DEFAULT_SYSTEM_PROMPT =
    'You are the execution engine of the Dots AI Platform. Formulate concise, bounded, verifiable plans. ' +
    'Never exceed the maximum plan depth. Only invoke registered tools with strictly validated arguments.';

  private readonly maxContextChars: number;
  private readonly scrubber: SecretScrubber;
  private readonly defaultSystemPrompt: string;

  constructor(options: PromptCompilerOptions = {}) {
    this.maxContextChars = options.maxContextChars ?? 32_000;
    this.scrubber = options.scrubber ?? defaultSecretScrubber;
    this.defaultSystemPrompt = options.defaultSystemPrompt ?? PromptCompiler.DEFAULT_SYSTEM_PROMPT;
  }

  /**
   * Compiles the planning prompt instructing the model to generate a structured JSON plan.
   */
  public compilePlanPrompt(
    goal: string,
    availableTools: readonly ToolDefinition[],
    context?: string
  ): CompiledPlanPrompt {
    if (!goal || goal.trim() === '') {
      throw new ValidationError('Task goal cannot be empty for plan compilation.');
    }

    const scrubbedGoal = this.scrubber.scrub(goal.trim());
    const scrubbedContext = context ? this.scrubber.scrub(context.trim()) : '';

    const toolSummary = availableTools.map((t) => {
      const paramList = Object.entries(t.parameters)
        .map(([k, v]) => `  - ${k} (${v.type}): ${v.description}`)
        .join('\n');
      return `Tool: ${t.name}\nDescription: ${t.description}\nParameters:\n${paramList || '  (none)'}`;
    }).join('\n\n');

    const systemInstruction =
      `${this.defaultSystemPrompt}\n\n` +
      `AVAILABLE TOOLS:\n${toolSummary}\n\n` +
      'INSTRUCTIONS:\n' +
      'Analyze the goal and generate a discrete plan with at most 8 steps. ' +
      'Output your plan strictly as a JSON object matching this schema:\n' +
      '{\n' +
      '  "steps": [\n' +
      '    {\n' +
      '      "stepOrder": 1,\n' +
      '      "description": "Short explanation of the step",\n' +
      '      "toolName": "name_of_tool",\n' +
      '      "arguments": { "arg1": "value" },\n' +
      '      "expectedOutcome": "Criteria that must be true upon step completion"\n' +
      '    }\n' +
      '  ]\n' +
      '}';

    const baseUserPrompt = `TASK GOAL:\n${scrubbedGoal}`;
    if (baseUserPrompt.length > this.maxContextChars) {
      throw new ValidationError(
        `Task goal prompt length (${baseUserPrompt.length} chars) exceeds maximum allowed context limit (${this.maxContextChars} chars).`
      );
    }

    let userPrompt = baseUserPrompt;
    let contextOmitted = false;
    if (scrubbedContext) {
      const fullUserPrompt = `${baseUserPrompt}\n\nADDITIONAL CONTEXT / ARTIFACTS:\n${scrubbedContext}`;
      if (fullUserPrompt.length <= this.maxContextChars) {
        userPrompt = fullUserPrompt;
      } else {
        contextOmitted = true;
      }
      // If optional context would exceed limit, omit the entire context block atomically
    }

    return {
      systemInstruction: this.scrubber.scrub(systemInstruction),
      userPrompt: this.scrubber.scrub(userPrompt),
      contextOmitted
    };
  }

  /**
   * Compiles and sanitizes an array of conversational messages.
   */
  public compileMessages(messages: readonly ModelMessage[]): ModelMessage[] {
    return messages.map((m) => ({
      role: m.role,
      content: this.scrubber.scrub(m.content),
      name: m.name ? this.scrubber.scrub(m.name) : undefined,
      toolCallId: m.toolCallId
    }));
  }
}
