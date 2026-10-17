/**
 * Next-Generation Dots AI Platform - Variable Resolver
 * 
 * Architectural Mandate:
 * Enables multi-step workflow dependency chaining. Interpolates outputs from
 * previously verified steps into the arguments of subsequent steps.
 * Prevents prompt/tool confusion by strictly resolving typed values.
 */

import { WorkflowExecutionError } from '../domain/errors.ts';

export interface StepOutputContext {
  readonly stepOrder: number;
  readonly toolName: string;
  readonly output: Record<string, unknown>;
}

export class VariableResolver {
  private static readonly VARIABLE_REGEX = /\{\{\s*([a-zA-Z0-9_.\[\]]+)\s*\}\}/g;

  /**
   * Resolves template expressions in an arguments object using verified step outputs.
   */
  public static resolve(
    args: Record<string, unknown>,
    completedSteps: readonly StepOutputContext[],
    currentStepOrder?: number
  ): Record<string, unknown> {
    const contextMap = new Map<number, Record<string, unknown>>();
    for (const step of completedSteps) {
      contextMap.set(step.stepOrder, step.output);
    }

    return this.resolveValue(args, contextMap, currentStepOrder) as Record<string, unknown>;
  }

  /**
   * Recursively resolves values in strings, arrays, and objects.
   */
  private static resolveValue(
    value: unknown,
    contextMap: Map<number, Record<string, unknown>>,
    currentStepOrder?: number
  ): unknown {
    if (typeof value === 'string') {
      return this.resolveString(value, contextMap, currentStepOrder);
    }

    if (Array.isArray(value)) {
      return value.map((item) => this.resolveValue(item, contextMap, currentStepOrder));
    }

    if (value !== null && typeof value === 'object') {
      const result: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
        result[k] = this.resolveValue(v, contextMap, currentStepOrder);
      }
      return result;
    }

    return value;
  }

  /**
   * Resolves expressions within a single string value.
   * If the string consists entirely of a single template expression, returns the raw typed value.
   */
  private static resolveString(
    str: string,
    contextMap: Map<number, Record<string, unknown>>,
    currentStepOrder?: number
  ): unknown {
    const trimmed = str.trim();
    const singleMatch = /^\s*\{\{\s*([a-zA-Z0-9_.\[\]]+)\s*\}\}\s*$/.exec(trimmed);

    if (singleMatch) {
      const expression = singleMatch[1]!;
      return this.evaluateExpression(expression, contextMap, currentStepOrder);
    }

    // String interpolation for embedded templates
    return str.replace(this.VARIABLE_REGEX, (_match, expression: string) => {
      const val = this.evaluateExpression(expression, contextMap, currentStepOrder);
      if (typeof val === 'object' && val !== null) {
        return JSON.stringify(val);
      }
      return String(val ?? '');
    });
  }

  /**
   * Evaluates an expression path such as:
   * - steps[1].result
   * - steps[1].output.result
   * - step1.output.result
   * - step1.result
   * - steps.1.result
   */
  private static evaluateExpression(
    expression: string,
    contextMap: Map<number, Record<string, unknown>>,
    currentStepOrder?: number
  ): unknown {
    // Normalize path tokens:
    // e.g. steps[1].result -> ["steps", "1", "result"]
    // e.g. step1.result -> ["steps", "1", "result"]
    const normalized = expression
      .replace(/^step(\d+)/i, 'steps.$1')
      .replace(/\[(\d+)\]/g, '.$1')
      .split('.')
      .filter((token) => token.length > 0);

    if (normalized[0] !== 'steps' || normalized.length < 3) {
      throw new WorkflowExecutionError(
        `Invalid variable syntax '${expression}'. Expected format: '{{steps[stepOrder].property}}' or '{{stepN.property}}'.`,
        currentStepOrder
      );
    }

    const stepOrder = parseInt(normalized[1]!, 10);
    if (Number.isNaN(stepOrder)) {
      throw new WorkflowExecutionError(
        `Invalid step order in variable '${expression}'.`,
        currentStepOrder
      );
    }

    const stepOutput = contextMap.get(stepOrder);
    if (!stepOutput) {
      throw new WorkflowExecutionError(
        `Cannot resolve variable '${expression}': step ${stepOrder} has not completed or has no output.`,
        currentStepOrder
      );
    }

    // Remainder path: handle optional 'output' segment
    let propTokens = normalized.slice(2);
    if (propTokens[0] === 'output') {
      propTokens = propTokens.slice(1);
    }

    if (propTokens.length === 0) {
      return stepOutput;
    }

    let current: unknown = stepOutput;
    for (const token of propTokens) {
      if (current === null || typeof current !== 'object') {
        throw new WorkflowExecutionError(
          `Cannot resolve property '${token}' in variable '${expression}': parent is not an object.`,
          currentStepOrder
        );
      }

      const record = current as Record<string, unknown>;
      if (!(token in record)) {
        throw new WorkflowExecutionError(
          `Property '${token}' not found in output of step ${stepOrder} (evaluating '${expression}'). Available keys: ${Object.keys(record).join(', ')}`,
          currentStepOrder
        );
      }

      current = record[token];
    }

    return current;
  }
}
