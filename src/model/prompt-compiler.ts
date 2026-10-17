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
  ): { systemInstruction: string; userPrompt: string } {
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

    let userPrompt = `TASK GOAL:\n${scrubbedGoal}`;
    if (scrubbedContext) {
      userPrompt += `\n\nADDITIONAL CONTEXT / ARTIFACTS:\n${scrubbedContext}`;
    }

    // Enforce bounds
    if (userPrompt.length > this.maxContextChars) {
      userPrompt = userPrompt.slice(0, this.maxContextChars) + '\n[...truncated to context limit...]';
    }

    return {
      systemInstruction: this.scrubber.scrub(systemInstruction),
      userPrompt: this.scrubber.scrub(userPrompt)
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
