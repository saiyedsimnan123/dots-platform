/**
 * Next-Generation Dots AI Platform - Analytics Agent Unit Tests
 * Phase 3B: Local-First Deterministic Analytics Agent
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  AnalyticsAgent,
  type AnalyticsReport,
  type ColumnStatistics
} from '../../src/agents/analytics-agent.ts';
import { AgentRegistry } from '../../src/agents/registry.ts';
import { createAgentExecutionContext } from '../../src/agents/context.ts';
import { ToolRegistry } from '../../src/tools/registry.ts';
import { standardTools } from '../../src/tools/sandbox-tools.ts';
import { PolicyEngine } from '../../src/security/policy-engine.ts';
import { ApprovalBroker } from '../../src/security/approval-broker.ts';
import { DatabaseManager } from '../../src/storage/db.ts';
import { TaskRepository } from '../../src/storage/task-repository.ts';
import {
  AgentCancelledError,
  SecurityViolationError,
  ValidationError
} from '../../src/domain/errors.ts';
import type { CallerContext } from '../../src/domain/types.ts';
import { writeFileSync, unlinkSync, existsSync } from 'node:fs';
import { join } from 'node:path';

const testCaller: CallerContext = {
  actor: 'USER',
  scope: { scopeType: 'WORKSPACE', scopeId: 'ws-analytics-test' },
  permissions: ['READ', 'WRITE']
};

function createTestContext(options: {
  autoApproveTier2?: boolean;
  abortSignal?: AbortSignal;
} = {}) {
  const registry = new ToolRegistry(standardTools);
  const policyEngine = new PolicyEngine({
    workspaceRoot: process.cwd(),
    autoApproveTier2: options.autoApproveTier2 ?? true
  });
  const db = new DatabaseManager(':memory:');
  const taskRepo = new TaskRepository(db);
  const approvalBroker = new ApprovalBroker(taskRepo);

  return {
    context: createAgentExecutionContext({
      taskId: 'task-analytics-test',
      workspaceRoot: process.cwd(),
      toolRegistry: registry,
      policyEngine,
      approvalBroker,
      agentCaller: testCaller,
      signal: options.abortSignal
    }),
    taskRepo,
    approvalBroker,
    policyEngine
  };
}

test('AnalyticsAgent - registration, capabilities, and metadata descriptors', () => {
  const agent = new AnalyticsAgent();

  assert.equal(agent.id, 'analytics-agent');
  assert.equal(agent.name, 'Analytics Agent');
  assert.ok(agent.description.includes('analytics agent'));
  assert.equal(agent.version, '1.0.0');

  // Capabilities
  assert.equal(agent.supportsCapability('analytics'), true);
  assert.equal(agent.supportsCapability('data-analysis'), true);
  assert.equal(agent.supportsCapability('general'), true);
  assert.equal(agent.supportsCapability('conversation'), true);
  assert.equal(agent.supportsCapability('non-existent'), false);

  // Alias registration check
  const aliasAgent = new AnalyticsAgent({ id: 'analytics' });
  assert.equal(aliasAgent.id, 'analytics');
  assert.equal(aliasAgent.supportsCapability('analytics'), true);

  // Register in AgentRegistry
  const reg = new AgentRegistry();
  reg.register(agent);
  reg.register(aliasAgent);
  assert.equal(reg.has('analytics-agent'), true);
  assert.equal(reg.has('analytics'), true);
  assert.equal(reg.findByCapability('data-analysis').length, 2);
});

test('AnalyticsAgent - input validation rejects empty, missing, or malformed inputs', async () => {
  const agent = new AnalyticsAgent();
  const { context } = createTestContext();

  // Null / non-object input
  await assert.rejects(
    () => agent.execute(null as any, context),
    (err: unknown) => err instanceof ValidationError
  );

  // Non-object parameters
  await assert.rejects(
    () => agent.execute({ goal: 'Analyze', parameters: 'invalid' as any }, context),
    (err: unknown) => err instanceof ValidationError
  );

  // Missing dataset
  await assert.rejects(
    () => agent.execute({ goal: 'Analyze sales revenue' }, context),
    (err: unknown) => {
      assert.ok(err instanceof ValidationError);
      assert.ok(err.message.includes('dataset must be provided'));
      return true;
    }
  );

  // Empty string CSV dataset
  await assert.rejects(
    () => agent.execute({ goal: 'Analyze', parameters: { data: '   ' } }, context),
    (err: unknown) => {
      assert.ok(err instanceof ValidationError);
      assert.ok(err.message.includes('Dataset is empty'));
      return true;
    }
  );

  // Empty array dataset
  await assert.rejects(
    () => agent.execute({ goal: 'Analyze', parameters: { data: [] } }, context),
    (err: unknown) => {
      assert.ok(err instanceof ValidationError);
      assert.ok(err.message.includes('Dataset is empty'));
      return true;
    }
  );

  // Malformed JSON string
  await assert.rejects(
    () =>
      agent.execute(
        { goal: 'Analyze', parameters: { data: '[{"name": "Alice", bad json]' } },
        context
      ),
    (err: unknown) => {
      assert.ok(err instanceof ValidationError);
      assert.ok(err.message.includes('Invalid JSON dataset'));
      return true;
    }
  );
});

test('AnalyticsAgent - robust CSV parsing with quotes, commas, and CRLF', () => {
  const agent = new AnalyticsAgent();

  const csv =
    'id,product_name,category,price,in_stock\r\n' +
    '1,"Widget, Standard",Electronics,19.99,true\r\n' +
    '2,"Deluxe ""Pro"" Kit",Electronics,99.50,false\r\n' +
    '3,Basic Cable,Accessories,4.99,true\r\n';

  const records = agent.parseCsv(csv);
  assert.equal(records.length, 3);

  assert.equal(records[0]!['id'], '1');
  assert.equal(records[0]!['product_name'], 'Widget, Standard');
  assert.equal(records[0]!['category'], 'Electronics');
  assert.equal(records[0]!['price'], '19.99');
  assert.equal(records[0]!['in_stock'], 'true');

  assert.equal(records[1]!['id'], '2');
  assert.equal(records[1]!['product_name'], 'Deluxe "Pro" Kit');
  assert.equal(records[1]!['price'], '99.50');
  assert.equal(records[1]!['in_stock'], 'false');
});

test('AnalyticsAgent - column type inference and dataset profiling', async () => {
  const agent = new AnalyticsAgent();
  const { context } = createTestContext();

  const data = [
    { id: '101', name: 'Alice', active: true, score: 92.5, enrolled_at: '2024-01-15' },
    { id: '102', name: 'Bob', active: false, score: 78.0, enrolled_at: '2024-02-20' },
    { id: '103', name: 'Charlie', active: true, score: 85.0, enrolled_at: '2024-03-10' },
    { id: '104', name: 'Diana', active: true, score: 96.0, enrolled_at: '2024-04-05' }
  ];

  const output = await agent.execute(
    {
      goal: 'Profile student performance',
      parameters: { data }
    },
    context
  );

  assert.equal(output.status, 'COMPLETED');
  const report = output.result.report as AnalyticsReport;

  assert.equal(report.datasetProfile.rowCount, 4);
  assert.equal(report.datasetProfile.columnCount, 5);

  // Inferred types
  const types = Object.fromEntries(
    report.datasetProfile.columns.map((c) => [c.name, c.type])
  );
  assert.equal(types['id'], 'numeric');
  assert.equal(types['name'], 'categorical');
  assert.equal(types['active'], 'boolean');
  assert.equal(types['score'], 'numeric');
  assert.equal(types['enrolled_at'], 'date');

  // Identifiers
  assert.ok(report.datasetProfile.identifierColumns.includes('id'));
});

test('AnalyticsAgent - verified mathematical accuracy for descriptive statistics', async () => {
  const agent = new AnalyticsAgent();
  const { context } = createTestContext();

  // Test dataset with known ground-truth statistics:
  // Values for 'val': [2, 4, 4, 4, 5, 5, 7, 9] (N = 8)
  // Sum = 40
  // Mean = 5.0
  // Min = 2, Max = 9, Range = 7
  // Sorted: [2, 4, 4, 4, 5, 5, 7, 9]
  // Median = (4 + 5) / 2 = 4.5 (or via linear interpolation at p=0.5 -> index=3.5 -> (4+5)/2 = 4.5)
  // Q1: p=0.25 -> index = 0.25 * 7 = 1.75 -> 4 + 0.75*(4-4) = 4.0
  // Q3: p=0.75 -> index = 0.75 * 7 = 5.25 -> 5 + 0.25*(7-5) = 5.5
  // IQR = 5.5 - 4.0 = 1.5
  // Sum of squared diffs from mean 5.0:
  // (2-5)^2 + 3*(4-5)^2 + 2*(5-5)^2 + (7-5)^2 + (9-5)^2
  // = 9 + 3*1 + 0 + 4 + 16 = 32
  // Sample Variance = 32 / (8 - 1) = 32 / 7 = 4.571428...
  // Sample StdDev = sqrt(32/7) = 2.1380899...
  // Population Variance = 32 / 8 = 4.0
  // Population StdDev = sqrt(4.0) = 2.0
  const csv =
    'val\n' +
    '2\n' +
    '4\n' +
    '4\n' +
    '4\n' +
    '5\n' +
    '5\n' +
    '7\n' +
    '9\n';

  const output = await agent.execute(
    {
      goal: 'Compute descriptive stats',
      parameters: { csv }
    },
    context
  );

  assert.equal(output.status, 'COMPLETED');
  const report = output.result.report as AnalyticsReport;
  const stats = report.numericStatistics['val']!;

  assert.equal(stats.count, 8);
  assert.equal(stats.sum, 40);
  assert.equal(stats.mean, 5.0);
  assert.equal(stats.min, 2);
  assert.equal(stats.max, 9);
  assert.equal(stats.range, 7);
  assert.equal(stats.median, 4.5);
  assert.equal(stats.q1, 4.0);
  assert.equal(stats.q3, 5.5);
  assert.equal(stats.iqr, 1.5);
  assert.ok(Math.abs(stats.sampleVariance - 32 / 7) < 1e-6);
  assert.ok(Math.abs(stats.sampleStdDev - Math.sqrt(32 / 7)) < 1e-6);
  assert.equal(stats.populationVariance, 4.0);
  assert.equal(stats.populationStdDev, 2.0);
});

test('AnalyticsAgent - outlier detection using Tukey 1.5x IQR method', async () => {
  const agent = new AnalyticsAgent();
  const { context } = createTestContext();

  // Dataset with 2 clear outliers: 100 and -50
  // Normal distribution around 10-15: [10, 11, 12, 12, 13, 13, 14, 15]
  const data = [
    { x: -50 }, // Outlier
    { x: 10 },
    { x: 11 },
    { x: 12 },
    { x: 12 },
    { x: 13 },
    { x: 13 },
    { x: 14 },
    { x: 15 },
    { x: 100 }  // Outlier
  ];

  const output = await agent.execute(
    {
      goal: 'Detect outliers',
      parameters: { data }
    },
    context
  );

  const report = output.result.report as AnalyticsReport;
  const stats = report.numericStatistics['x']!;

  assert.equal(stats.outlierCount, 2);
  assert.ok(stats.outliers.includes(-50));
  assert.ok(stats.outliers.includes(100));

  // Verify outliers appear in dataQualityReport
  const xOutlier = report.dataQuality.outliersDetected.find((o) => o.column === 'x');
  assert.ok(xOutlier);
  assert.equal(xOutlier.count, 2);
  assert.ok(report.dataQuality.warnings.some((w) => w.includes("outlier(s)")));
});

test('AnalyticsAgent - categorical distributions and proportions', async () => {
  const agent = new AnalyticsAgent();
  const { context } = createTestContext();

  const data = [
    { dept: 'Engineering' },
    { dept: 'Engineering' },
    { dept: 'Engineering' },
    { dept: 'Engineering' },
    { dept: 'Sales' },
    { dept: 'Sales' },
    { dept: 'Marketing' }
  ];

  const output = await agent.execute(
    {
      goal: 'Detect outliers',
      parameters: { data }
    },
    context
  );

  const report = output.result.report as AnalyticsReport;
  const cat = report.categoricalStatistics['dept']!;

  assert.equal(cat.uniqueCount, 3);
  assert.equal(cat.totalValid, 7);

  // Top category: Engineering (4/7 = 57.1%)
  assert.equal(cat.topCategories[0]!.category, 'Engineering');
  assert.equal(cat.topCategories[0]!.count, 4);
  assert.ok(Math.abs(cat.topCategories[0]!.percentage - (4 / 7) * 100) < 1e-2);

  // Second category: Sales (2/7 = 28.6%)
  assert.equal(cat.topCategories[1]!.category, 'Sales');
  assert.equal(cat.topCategories[1]!.count, 2);

  // Bottom category: Marketing (1/7 = 14.3%)
  assert.equal(cat.bottomCategories[0]!.category, 'Marketing');
});

test('AnalyticsAgent - data quality checks: missingness, duplicates, and constant columns', async () => {
  const agent = new AnalyticsAgent();
  const { context } = createTestContext();

  const data = [
    { a: 1, b: 'active', c: null },
    { a: 1, b: 'active', c: null }, // Duplicate of row 1
    { a: 2, b: 'active', c: 'N/A' },
    { a: 3, b: 'active', c: 10 },
    { a: 4, b: 'active', c: 'null' }
  ];

  const output = await agent.execute(
    {
      goal: 'Detect outliers',
      parameters: { data }
    },
    context
  );

  const report = output.result.report as AnalyticsReport;
  const q = report.dataQuality;

  assert.equal(q.totalRows, 5);
  assert.equal(q.duplicateRowsCount, 1);
  assert.equal(q.duplicateRowsPercentage, 20);

  // Constant column 'b' (all 'active')
  assert.ok(q.constantColumns.includes('b'));

  // High missing column 'c' (missing in 4 out of 5 rows = 80%)
  assert.ok(q.highMissingColumns.includes('c'));
  assert.ok(q.warnings.some((w) => w.includes("Column 'c' has high missingness")));
  assert.ok(q.warnings.some((w) => w.includes("Column 'b' is constant")));
});

test('AnalyticsAgent - Pearson correlation calculation and causality disclaimer', async () => {
  const agent = new AnalyticsAgent();
  const { context } = createTestContext();

  // Test data with perfect positive correlation (y = 2x) and perfect negative correlation (z = -3x)
  const data = [
    { x: 1, y: 2, z: -3 },
    { x: 2, y: 4, z: -6 },
    { x: 3, y: 6, z: -9 },
    { x: 4, y: 8, z: -12 },
    { x: 5, y: 10, z: -15 }
  ];

  const output = await agent.execute(
    {
      goal: 'Detect outliers',
      parameters: { data }
    },
    context
  );

  const report = output.result.report as AnalyticsReport;
  const corrXY = report.correlations.find(
    (c) => (c.columnA === 'x' && c.columnB === 'y') || (c.columnA === 'y' && c.columnB === 'x')
  );
  assert.ok(corrXY);
  assert.equal(corrXY.coefficient, 1.0);
  assert.equal(corrXY.strength, 'STRONG_POSITIVE');

  const corrXZ = report.correlations.find(
    (c) => (c.columnA === 'x' && c.columnB === 'z') || (c.columnA === 'z' && c.columnB === 'x')
  );
  assert.ok(corrXZ);
  assert.equal(corrXZ.coefficient, -1.0);
  assert.equal(corrXZ.strength, 'STRONG_NEGATIVE');

  // Verify markdown report contains causality disclaimer
  assert.ok(output.result.reportMarkdown);
  assert.ok(
    (output.result.reportMarkdown as string).includes('Correlation does NOT imply causation')
  );
});

test('AnalyticsAgent - temporal trends and group comparisons', async () => {
  const agent = new AnalyticsAgent();
  const { context } = createTestContext();

  const data = [
    { date: '2024-01-01', region: 'North', sales: 100 },
    { date: '2024-01-02', region: 'North', sales: 150 },
    { date: '2024-01-03', region: 'South', sales: 200 },
    { date: '2024-01-04', region: 'South', sales: 250 },
    { date: '2024-01-05', region: 'North', sales: 300 }
  ];

  const output = await agent.execute(
    {
      goal: 'Analyze regional sales trends over time',
      parameters: { data }
    },
    context
  );

  const report = output.result.report as AnalyticsReport;

  // Temporal trend: sales increases from 100 to 300
  const trend = report.temporalTrends.find((t) => t.metricColumn === 'sales');
  assert.ok(trend);
  assert.equal(trend.direction, 'INCREASING');
  assert.equal(trend.startValue, 100);
  assert.equal(trend.endValue, 300);

  // Group comparison: region by sales
  const group = report.groupComparisons.find((g) => g.groupColumn === 'region');
  assert.ok(group);
  assert.equal(group.groups.length, 2);
  const south = group.groups.find((g) => g.group === 'South');
  assert.ok(south);
  assert.equal(south.mean, 225); // (200 + 250) / 2
});

test('AnalyticsAgent - sandboxed file ingestion via file_read tool', async () => {
  const agent = new AnalyticsAgent();
  const { context } = createTestContext();

  const filePath = join(process.cwd(), 'temp-analytics-test.csv');
  const csvContent = 'metric_a,metric_b\n10,20\n30,40\n50,60\n';

  try {
    writeFileSync(filePath, csvContent, 'utf8');

    const output = await agent.execute(
      {
        goal: 'Read dataset from file',
        parameters: { filePath: 'temp-analytics-test.csv' }
      },
      context
    );

    assert.equal(output.status, 'COMPLETED');
    const report = output.result.report as AnalyticsReport;
    assert.equal(report.datasetProfile.rowCount, 3);
    assert.equal(report.numericStatistics['metric_a']!.mean, 30);
    assert.equal(report.numericStatistics['metric_b']!.mean, 40);
  } finally {
    if (existsSync(filePath)) {
      unlinkSync(filePath);
    }
  }
});

test('AnalyticsAgent - aborts immediately on cooperative cancellation signal', async () => {
  const agent = new AnalyticsAgent();
  const controller = new AbortController();
  controller.abort(); // Pre-aborted

  const { context } = createTestContext({ abortSignal: controller.signal });

  await assert.rejects(
    () =>
      agent.execute(
        {
          goal: 'Cancelled execution',
          parameters: { data: [{ a: 1 }, { a: 2 }] },
          signal: controller.signal
        },
        context
      ),
    (err: unknown) => err instanceof AgentCancelledError
  );
});

test('AnalyticsAgent - column selection filters active analysis subset', async () => {
  const agent = new AnalyticsAgent();
  const { context } = createTestContext();

  const data = [
    { id: 1, keep_metric: 10, ignored_col: 'xyz' },
    { id: 2, keep_metric: 20, ignored_col: 'abc' }
  ];

  const output = await agent.execute(
    {
      goal: 'Filter columns',
      parameters: {
        data,
        columns: ['keep_metric']
      }
    },
    context
  );

  const report = output.result.report as AnalyticsReport;
  assert.equal(report.datasetProfile.columnCount, 1);
  assert.ok(report.numericStatistics['keep_metric']);
  assert.equal(report.numericStatistics['ignored_col'], undefined);
});
