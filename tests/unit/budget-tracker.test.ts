/**
 * Next-Generation Dots AI Platform - Token Budget Tracker Unit Tests
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { TokenBudgetTracker, BudgetExceededError } from '../../src/model/budget-tracker.ts';
import { DatabaseManager } from '../../src/storage/db.ts';

test('TokenBudgetTracker - accumulates usage across multiple calls', () => {
  const tracker = new TokenBudgetTracker({ maxCostPerTaskUsd: 1.0, maxTokensPerTask: 10_000 });

  tracker.recordUsage('task-1', 'mock-provider', 'mock-v1', {
    promptTokens: 100,
    completionTokens: 50,
    totalTokens: 150,
    estimatedCostUsd: 0.002
  });

  tracker.recordUsage('task-1', 'mock-provider', 'mock-v1', {
    promptTokens: 200,
    completionTokens: 100,
    totalTokens: 300,
    estimatedCostUsd: 0.004
  });

  const summary = tracker.getUsageForTask('task-1');
  assert.equal(summary.promptTokens, 300);
  assert.equal(summary.completionTokens, 150);
  assert.equal(summary.totalTokens, 450);
  assert.equal(Math.round(summary.totalCostUsd * 1000) / 1000, 0.006);
});

test('TokenBudgetTracker - throws BudgetExceededError when token ceiling is breached', () => {
  const tracker = new TokenBudgetTracker({ maxCostPerTaskUsd: 10.0, maxTokensPerTask: 500 });

  assert.throws(
    () => {
      tracker.recordUsage('task-token-limit', 'mock', 'v1', {
        promptTokens: 400,
        completionTokens: 200,
        totalTokens: 600,
        estimatedCostUsd: 0.01
      });
    },
    (err: unknown) => {
      assert(err instanceof BudgetExceededError);
      assert.equal(err.code, 'BUDGET_EXCEEDED');
      assert.equal(err.taskId, 'task-token-limit');
      return true;
    }
  );
});

test('TokenBudgetTracker - throws BudgetExceededError when cost ceiling is breached', () => {
  const tracker = new TokenBudgetTracker({ maxCostPerTaskUsd: 0.05, maxTokensPerTask: 100_000 });

  assert.throws(
    () => {
      tracker.recordUsage('task-cost-limit', 'mock', 'v1', {
        promptTokens: 1000,
        completionTokens: 1000,
        totalTokens: 2000,
        estimatedCostUsd: 0.06
      });
    },
    (err: unknown) => {
      assert(err instanceof BudgetExceededError);
      assert.equal(err.code, 'BUDGET_EXCEEDED');
      assert.equal(err.taskId, 'task-cost-limit');
      return true;
    }
  );
});

test('TokenBudgetTracker - persists usage records to SQLite database', () => {
  const db = new DatabaseManager(':memory:');
  // First insert a task to satisfy foreign key constraint on token_usages
  db.prepare(`
    INSERT INTO tasks (id, goal, status, created_at, updated_at)
    VALUES ('db-task-1', 'Goal', 'SUBMITTED', '2026-10-17T00:00:00Z', '2026-10-17T00:00:00Z')
  `).run();

  const tracker = new TokenBudgetTracker({ db, maxCostPerTaskUsd: 1.0 });

  tracker.recordUsage('db-task-1', 'mock-provider', 'model-a', {
    promptTokens: 120,
    completionTokens: 80,
    totalTokens: 200,
    estimatedCostUsd: 0.005
  });

  // Verify database record exists
  const rows = db.prepare('SELECT * FROM token_usages WHERE task_id = ?').all('db-task-1') as Array<{
    provider: string;
    prompt_tokens: number;
    completion_tokens: number;
  }>;

  assert.equal(rows.length, 1);
  assert.equal(rows[0]!.provider, 'mock-provider');
  assert.equal(rows[0]!.prompt_tokens, 120);
  assert.equal(rows[0]!.completion_tokens, 80);

  db.close();
});
