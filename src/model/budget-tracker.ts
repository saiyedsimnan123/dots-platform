/**
 * Next-Generation Dots AI Platform - Token & Cost Budget Tracker
 * 
 * Architectural Mandate:
 * Enforces per-task financial and token usage limits.
 * Protects against runaway hallucination loops, unconstrained API calls,
 * and unexpected billings by aborting tasks before budget ceilings are violated.
 */

import { randomUUID } from 'node:crypto';
import type { ModelUsage } from './types.ts';
import type { DatabaseManager } from '../storage/db.ts';
import { DomainError } from '../domain/errors.ts';

export class BudgetExceededError extends DomainError {
  public readonly taskId: string;
  public readonly currentCostUsd: number;
  public readonly maxCostUsd: number;

  constructor(taskId: string, currentCostUsd: number, maxCostUsd: number, reason: string) {
    super(
      `Budget ceiling exceeded for task '${taskId}': ${reason} (Spent: $${currentCostUsd.toFixed(4)}, Max: $${maxCostUsd.toFixed(4)})`,
      'BUDGET_EXCEEDED',
      { taskId, currentCostUsd, maxCostUsd, reason }
    );
    this.taskId = taskId;
    this.currentCostUsd = currentCostUsd;
    this.maxCostUsd = maxCostUsd;
  }
}

export interface BudgetTrackerOptions {
  readonly db?: DatabaseManager;
  readonly maxCostPerTaskUsd?: number;
  readonly maxTokensPerTask?: number;
}

export interface TaskUsageSummary {
  readonly promptTokens: number;
  readonly completionTokens: number;
  readonly totalTokens: number;
  readonly totalCostUsd: number;
}

export class TokenBudgetTracker {
  private readonly db?: DatabaseManager;
  private readonly maxCostPerTaskUsd: number;
  private readonly maxTokensPerTask: number;
  private readonly memoryTotals: Map<string, TaskUsageSummary> = new Map();

  constructor(options: BudgetTrackerOptions = {}) {
    this.db = options.db;
    this.maxCostPerTaskUsd = options.maxCostPerTaskUsd ?? 1.0; // Default $1.00 per task
    this.maxTokensPerTask = options.maxTokensPerTask ?? 100_000;
  }

  /**
   * Records a model invocation's token usage, validates against budget ceilings,
   * and persists the record to SQLite if a database manager is attached.
   */
  public recordUsage(
    taskId: string,
    provider: string,
    model: string,
    usage: ModelUsage
  ): TaskUsageSummary {
    const existing = this.getUsageForTask(taskId);
    const newPrompt = existing.promptTokens + usage.promptTokens;
    const newCompletion = existing.completionTokens + usage.completionTokens;
    const newTotalTokens = existing.totalTokens + usage.totalTokens;
    const newTotalCost = existing.totalCostUsd + usage.estimatedCostUsd;

    // 1. Guard against token count ceiling
    if (newTotalTokens > this.maxTokensPerTask) {
      throw new BudgetExceededError(
        taskId,
        newTotalCost,
        this.maxCostPerTaskUsd,
        `Token limit breached (${newTotalTokens} > ${this.maxTokensPerTask} tokens)`
      );
    }

    // 2. Guard against cost ceiling
    if (newTotalCost > this.maxCostPerTaskUsd) {
      throw new BudgetExceededError(
        taskId,
        newTotalCost,
        this.maxCostPerTaskUsd,
        `Financial cost ceiling breached ($${newTotalCost.toFixed(4)} > $${this.maxCostPerTaskUsd.toFixed(4)})`
      );
    }

    const updated: TaskUsageSummary = {
      promptTokens: newPrompt,
      completionTokens: newCompletion,
      totalTokens: newTotalTokens,
      totalCostUsd: newTotalCost
    };

    this.memoryTotals.set(taskId, updated);

    // 3. Persist to SQLite if DB manager is connected
    if (this.db && this.db.isOpen) {
      const id = randomUUID();
      const now = new Date().toISOString();
      const stmt = this.db.prepare(`
        INSERT INTO token_usages (
          id, task_id, provider, model, prompt_tokens, completion_tokens,
          estimated_cost_usd, timestamp
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `);
      stmt.run(
        id,
        taskId,
        provider,
        model,
        usage.promptTokens,
        usage.completionTokens,
        usage.estimatedCostUsd,
        now
      );
    }

    return updated;
  }

  /**
   * Retrieves cumulative token usage and cost for a task.
   */
  public getUsageForTask(taskId: string): TaskUsageSummary {
    const memory = this.memoryTotals.get(taskId);
    if (memory) {
      return memory;
    }

    // Fall back to database query if DB is available
    if (this.db && this.db.isOpen) {
      const stmt = this.db.prepare(`
        SELECT 
          COALESCE(SUM(prompt_tokens), 0) as prompt_tokens,
          COALESCE(SUM(completion_tokens), 0) as completion_tokens,
          COALESCE(SUM(estimated_cost_usd), 0.0) as total_cost
        FROM token_usages
        WHERE task_id = ?
      `);
      const row = stmt.get(taskId) as {
        prompt_tokens: number;
        completion_tokens: number;
        total_cost: number;
      } | undefined;

      if (row) {
        const summary: TaskUsageSummary = {
          promptTokens: Number(row.prompt_tokens),
          completionTokens: Number(row.completion_tokens),
          totalTokens: Number(row.prompt_tokens) + Number(row.completion_tokens),
          totalCostUsd: Number(row.total_cost)
        };
        this.memoryTotals.set(taskId, summary);
        return summary;
      }
    }

    return {
      promptTokens: 0,
      completionTokens: 0,
      totalTokens: 0,
      totalCostUsd: 0.0
    };
  }

  /**
   * Resets tracking state for a task.
   */
  public resetTask(taskId: string): void {
    this.memoryTotals.delete(taskId);
  }
}
