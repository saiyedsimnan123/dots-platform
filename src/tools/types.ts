/**
 * Next-Generation Dots AI Platform - Tool Capability Types
 */

import type { ToolDefinition } from '../model/types.ts';
import type { RiskTier } from '../domain/types.ts';

export interface ToolContext {
  readonly taskId: string;
  readonly stepId: string;
  readonly workspaceRoot: string;
}

export interface ToolExecutionResult {
  readonly output: Record<string, unknown>;
  readonly exitCode: number;
  readonly durationMs: number;
}

export type ToolHandler = (
  args: Record<string, unknown>,
  context: ToolContext
) => Promise<ToolExecutionResult>;

export interface RegisteredTool {
  readonly definition: ToolDefinition;
  readonly riskTier: RiskTier;
  readonly handler: ToolHandler;
}
