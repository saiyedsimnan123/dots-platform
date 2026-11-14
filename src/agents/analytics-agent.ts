/**
 * Next-Generation Dots AI Platform - Analytics Agent (Phase 3B)
 *
 * Architectural Mandate:
 * Reliable, secure, local-first analytics agent implementing the shared IAgent contract.
 *
 * Guarantees:
 * 1. Deterministic mathematical and statistical calculations (zero hallucinations or approximations).
 * 2. Pure local execution with zero external paid APIs or network dependencies.
 * 3. Robust dataset ingestion: inline CSV, JSON record arrays, and sandboxed file ingestion.
 * 4. Comprehensive dataset profiling, descriptive statistics, categorical distributions,
 *    data quality evaluation (IQR outliers, missingness, duplicates, constant columns),
 *    Pearson correlations (with explicit correlation != causation distinction),
 *    temporal trends, and group comparisons.
 * 5. Full compliance with PolicyEngine, ApprovalBroker, cancellation signals, and secret scrubbing.
 */

import { BaseAgent, type BaseAgentOptions } from './base-agent.ts';
import type {
  AgentInput,
  AgentOutput,
  AgentExecutionContext,
  AgentExecutionStatus
} from './types.ts';
import { defaultSecretScrubber } from '../model/secret-scrubber.ts';
import {
  AgentCancelledError,
  SecurityViolationError,
  ToolExecutionError,
  ValidationError
} from '../domain/errors.ts';

/**
 * Inferred column data types.
 */
export type ColumnDataType = 'numeric' | 'categorical' | 'boolean' | 'date';

/**
 * Metadata profile of an individual dataset column.
 */
export interface ColumnProfile {
  readonly name: string;
  readonly type: ColumnDataType;
  readonly totalCount: number;
  readonly validCount: number;
  readonly missingCount: number;
  readonly missingPercentage: number;
  readonly uniqueCount: number;
  readonly isUnique: boolean;
  readonly isPotentialIdentifier: boolean;
  readonly isConstant: boolean;
  readonly sampleValues: readonly unknown[];
}

/**
 * High-level profile of the entire ingested dataset.
 */
export interface DatasetProfile {
  readonly rowCount: number;
  readonly columnCount: number;
  readonly columns: readonly ColumnProfile[];
  readonly numericColumns: readonly string[];
  readonly categoricalColumns: readonly string[];
  readonly booleanColumns: readonly string[];
  readonly dateColumns: readonly string[];
  readonly identifierColumns: readonly string[];
  readonly emptyDataset: boolean;
}

/**
 * Comprehensive descriptive statistics for a numeric column.
 */
export interface ColumnStatistics {
  readonly column: string;
  readonly count: number;
  readonly missingCount: number;
  readonly missingPercentage: number;
  readonly sum: number;
  readonly mean: number;
  readonly median: number;
  readonly min: number;
  readonly max: number;
  readonly range: number;
  readonly sampleVariance: number;
  readonly sampleStdDev: number;
  readonly populationVariance: number;
  readonly populationStdDev: number;
  readonly q1: number;
  readonly q2: number;
  readonly q3: number;
  readonly iqr: number;
  readonly outlierCount: number;
  readonly outlierPercentage: number;
  readonly outliers: readonly number[];
}

/**
 * Distribution item for a category.
 */
export interface CategoryDistribution {
  readonly category: string;
  readonly count: number;
  readonly percentage: number;
}

/**
 * Categorical analysis and frequency distribution for non-numeric columns.
 */
export interface CategoricalStatistics {
  readonly column: string;
  readonly totalValid: number;
  readonly uniqueCount: number;
  readonly topCategories: readonly CategoryDistribution[];
  readonly bottomCategories: readonly CategoryDistribution[];
  readonly isHighCardinality: boolean;
  readonly distribution: readonly CategoryDistribution[];
}

/**
 * Data quality evaluation metrics and detected anomalies.
 */
export interface DataQualityReport {
  readonly totalRows: number;
  readonly totalColumns: number;
  readonly totalCells: number;
  readonly missingCells: number;
  readonly missingPercentage: number;
  readonly duplicateRowsCount: number;
  readonly duplicateRowsPercentage: number;
  readonly constantColumns: readonly string[];
  readonly highMissingColumns: readonly string[];
  readonly outliersDetected: readonly {
    readonly column: string;
    readonly count: number;
    readonly percentage: number;
    readonly bounds: { readonly lower: number; readonly upper: number };
  }[];
  readonly overallQualityScore: 'EXCELLENT' | 'GOOD' | 'FAIR' | 'POOR';
  readonly warnings: readonly string[];
}

/**
 * Pearson correlation metric between two numeric columns.
 */
export interface CorrelationItem {
  readonly columnA: string;
  readonly columnB: string;
  readonly coefficient: number;
  readonly strength:
    | 'STRONG_POSITIVE'
    | 'MODERATE_POSITIVE'
    | 'WEAK'
    | 'MODERATE_NEGATIVE'
    | 'STRONG_NEGATIVE';
  readonly sampleSize: number;
}

/**
 * Directional trend over time for a numeric metric.
 */
export interface TrendAnalysis {
  readonly dateColumn: string;
  readonly metricColumn: string;
  readonly direction: 'INCREASING' | 'DECREASING' | 'STABLE';
  readonly startValue: number;
  readonly endValue: number;
  readonly change: number;
  readonly percentageChange: number;
  readonly slope: number;
}

/**
 * Group aggregation comparison across categories.
 */
export interface GroupComparison {
  readonly groupColumn: string;
  readonly metricColumn: string;
  readonly groups: readonly {
    readonly group: string;
    readonly count: number;
    readonly sum: number;
    readonly mean: number;
    readonly min: number;
    readonly max: number;
  }[];
}

/**
 * Formal structured report generated by the Analytics Agent.
 */
export interface AnalyticsReport {
  readonly objective: string;
  readonly datasetProfile: DatasetProfile;
  readonly dataQuality: DataQualityReport;
  readonly numericStatistics: Record<string, ColumnStatistics>;
  readonly categoricalStatistics: Record<string, CategoricalStatistics>;
  readonly correlations: readonly CorrelationItem[];
  readonly temporalTrends: readonly TrendAnalysis[];
  readonly groupComparisons: readonly GroupComparison[];
  readonly insights: readonly string[];
  readonly recommendations: readonly string[];
  readonly limitations: readonly string[];
  readonly summary: string;
}

/**
 * Optional preferences and configuration for analytics execution.
 */
export interface AnalyticsPreferences {
  readonly maxCategories?: number;
  readonly correlationThreshold?: number;
  readonly outlierMultiplier?: number;
  readonly dateFormat?: string;
  readonly precision?: number;
}

/**
 * Parameters accepted by the Analytics Agent.
 */
export interface AnalyticsAgentParameters {
  readonly data?: string | readonly Record<string, unknown>[];
  readonly csv?: string;
  readonly json?: string | readonly Record<string, unknown>[];
  readonly records?: readonly Record<string, unknown>[];
  readonly filePath?: string;
  readonly path?: string;
  readonly file?: string;
  readonly objective?: string;
  readonly query?: string;
  readonly instructions?: string;
  readonly columns?: readonly string[];
  readonly selectedColumns?: readonly string[];
  readonly preferences?: AnalyticsPreferences;
  readonly options?: Record<string, unknown>;
  readonly approvalToken?: string;
}

export interface AnalyticsAgentOptions extends Partial<BaseAgentOptions> {
  readonly defaultPreferences?: AnalyticsPreferences;
}

/**
 * Deterministic local-first analytics agent.
 */
export class AnalyticsAgent extends BaseAgent {
  public static readonly DEFAULT_ID = 'analytics-agent';
  private readonly defaultPreferences: AnalyticsPreferences;

  constructor(options: AnalyticsAgentOptions = {}) {
    super({
      id: options.id ?? AnalyticsAgent.DEFAULT_ID,
      name: options.name ?? 'Analytics Agent',
      description:
        options.description ??
        'Specialized autonomous analytics agent for deterministic dataset profiling, descriptive statistics, quality auditing, correlations, and trends.',
      version: options.version ?? '1.0.0',
      capabilities: options.capabilities ?? [
        'analytics',
        'data-analysis',
        'general',
        'conversation'
      ],
      config: options.config
    });
    this.defaultPreferences = options.defaultPreferences ?? {
      maxCategories: 10,
      correlationThreshold: 0.3,
      outlierMultiplier: 1.5,
      precision: 4
    };
  }

  /**
   * Executes deterministic analytics pipeline.
   */
  public async execute(
    input: AgentInput,
    context: AgentExecutionContext
  ): Promise<AgentOutput> {
    const startMs = Date.now();
    const signal = input?.signal ?? context?.signal;
    this.checkCancellation(signal);

    let stepsExecuted = 0;

    // 1. Parse and validate input request & parameters
    const {
      objective,
      selectedColumns,
      preferences,
      rawInlineData,
      filePath,
      approvalToken
    } = this.parseAndValidateInput(input);

    // 2. Ingest dataset: either from sandboxed file read or inline data
    let records: Record<string, unknown>[] = [];
    if (filePath) {
      this.checkCancellation(signal);
      stepsExecuted++;
      records = await this.ingestFromFile(filePath, context, approvalToken);
    } else if (rawInlineData !== undefined) {
      records = this.ingestFromInline(rawInlineData);
    } else {
      throw new ValidationError(
        "A dataset must be provided via 'parameters.data', 'parameters.csv', 'parameters.json', or 'parameters.filePath'."
      );
    }

    if (records.length === 0) {
      throw new ValidationError(
        'Dataset is empty: at least 1 row and 1 column of data are required for analysis.'
      );
    }

    // 3. Extract and filter columns
    const allColumns = this.extractColumnNames(records);
    if (allColumns.length === 0) {
      throw new ValidationError(
        'Dataset has no valid column headers or properties.'
      );
    }

    let activeColumns = allColumns;
    if (selectedColumns && selectedColumns.length > 0) {
      const selectedSet = new Set(selectedColumns);
      const filtered = allColumns.filter((col) => selectedSet.has(col));
      if (filtered.length > 0) {
        activeColumns = filtered;
      }
    }

    this.checkCancellation(signal);
    stepsExecuted++;

    // 4. Dataset Profiling
    const datasetProfile = this.profileDataset(records, activeColumns);

    // 5. Descriptive Statistics for numeric columns
    const numericStatistics: Record<string, ColumnStatistics> = {};
    for (const numCol of datasetProfile.numericColumns) {
      this.checkCancellation(signal);
      numericStatistics[numCol] = this.computeDescriptiveStatistics(
        records,
        numCol,
        preferences.outlierMultiplier ?? 1.5
      );
    }

    // 6. Categorical Analysis for categorical and boolean columns
    const categoricalStatistics: Record<string, CategoricalStatistics> = {};
    const categoricalTargetColumns = [
      ...datasetProfile.categoricalColumns,
      ...datasetProfile.booleanColumns
    ];
    for (const catCol of categoricalTargetColumns) {
      this.checkCancellation(signal);
      categoricalStatistics[catCol] = this.computeCategoricalStatistics(
        records,
        catCol,
        preferences.maxCategories ?? 10
      );
    }

    // 7. Data Quality Evaluation
    this.checkCancellation(signal);
    const dataQuality = this.evaluateDataQuality(
      records,
      activeColumns,
      datasetProfile,
      numericStatistics
    );

    // 8. Relationships & Correlations (Pearson r)
    this.checkCancellation(signal);
    const correlations = this.computeCorrelations(
      records,
      datasetProfile.numericColumns,
      preferences.correlationThreshold ?? 0.3
    );

    // 9. Temporal Trends
    this.checkCancellation(signal);
    const temporalTrends = this.analyzeTemporalTrends(
      records,
      datasetProfile.dateColumns,
      datasetProfile.numericColumns
    );

    // 10. Group Comparisons
    this.checkCancellation(signal);
    const groupComparisons = this.computeGroupComparisons(
      records,
      datasetProfile.categoricalColumns,
      datasetProfile.numericColumns
    );

    // 11. Synthesize Insights, Recommendations, and Limitations
    const { insights, recommendations, limitations, summary } =
      this.synthesizeFindings(
        objective,
        datasetProfile,
        dataQuality,
        numericStatistics,
        categoricalStatistics,
        correlations,
        temporalTrends,
        groupComparisons
      );

    const report: AnalyticsReport = {
      objective,
      datasetProfile,
      dataQuality,
      numericStatistics,
      categoricalStatistics,
      correlations,
      temporalTrends,
      groupComparisons,
      insights,
      recommendations,
      limitations,
      summary
    };

    return this.formatAgentOutput(input, context, report, stepsExecuted, startMs);
  }

  // --- Input Ingestion & Parsing ---

  private parseAndValidateInput(input: AgentInput): {
    objective: string;
    selectedColumns?: readonly string[];
    preferences: AnalyticsPreferences;
    rawInlineData?: string | readonly Record<string, unknown>[];
    filePath?: string;
    approvalToken?: string;
  } {
    if (!input || typeof input !== 'object') {
      throw new ValidationError('AgentInput must be an object.');
    }

    const params = (input.parameters ?? {}) as AnalyticsAgentParameters;
    if (
      input.parameters !== undefined &&
      (typeof input.parameters !== 'object' || Array.isArray(input.parameters))
    ) {
      throw new ValidationError("Analytics agent 'parameters' must be a valid JSON object.");
    }

    // Objective extraction
    const rawObjective =
      params.objective ??
      params.query ??
      params.instructions ??
      (typeof input.goal === 'string' &&
      !this.looksLikeRawData(input.goal)
        ? input.goal
        : undefined);

    const objective =
      rawObjective && typeof rawObjective === 'string' && rawObjective.trim() !== ''
        ? defaultSecretScrubber.scrub(rawObjective.trim())
        : 'Dataset Exploratory Data Analysis';

    // File path extraction
    const rawPath = params.filePath ?? params.path ?? params.file;
    const filePath =
      typeof rawPath === 'string' && rawPath.trim() !== ''
        ? rawPath.trim()
        : undefined;

    // Inline data extraction
    let rawInlineData: string | readonly Record<string, unknown>[] | undefined;
    if (params.data !== undefined) {
      rawInlineData = params.data;
    } else if (typeof params.csv === 'string') {
      rawInlineData = params.csv;
    } else if (params.json !== undefined) {
      rawInlineData = params.json;
    } else if (Array.isArray(params.records)) {
      rawInlineData = params.records;
    } else if (
      typeof input.goal === 'string' &&
      this.looksLikeRawData(input.goal)
    ) {
      rawInlineData = input.goal;
    }

    // Column selection
    const rawCols = params.columns ?? params.selectedColumns;
    let selectedColumns: string[] | undefined;
    if (Array.isArray(rawCols)) {
      selectedColumns = rawCols
        .map((c) => String(c).trim())
        .filter((c) => c.length > 0);
    }

    // Preferences
    const preferences: AnalyticsPreferences = {
      ...this.defaultPreferences,
      ...(params.preferences ?? {})
    };

    // Approval token
    const approvalToken =
      typeof params.approvalToken === 'string' && params.approvalToken.trim() !== ''
        ? params.approvalToken.trim()
        : undefined;

    return {
      objective,
      selectedColumns,
      preferences,
      rawInlineData,
      filePath,
      approvalToken
    };
  }

  /**
   * Detects whether a string is raw CSV or JSON data rather than a natural language goal.
   */
  private looksLikeRawData(text: string): boolean {
    const trimmed = text.trim();
    if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
      return true;
    }
    if (trimmed.startsWith('{') && trimmed.endsWith('}')) {
      return true;
    }
    const lines = trimmed.split(/\r?\n/).filter((l) => l.trim().length > 0);
    if (lines.length >= 2 && lines[0]!.includes(',') && lines[1]!.includes(',')) {
      return true;
    }
    return false;
  }

  /**
   * Ingests and parses inline data (CSV string, JSON string, or record array).
   */
  private ingestFromInline(
    data: string | readonly Record<string, unknown>[]
  ): Record<string, unknown>[] {
    if (Array.isArray(data)) {
      if (data.length === 0) {
        return [];
      }
      return data.map((item) => {
        if (!item || typeof item !== 'object' || Array.isArray(item)) {
          throw new ValidationError(
            'JSON record array items must be key-value objects.'
          );
        }
        return { ...(item as Record<string, unknown>) };
      });
    }

    if (typeof data !== 'string') {
      throw new ValidationError(
        "Dataset 'data' must be a CSV string, JSON string, or array of records."
      );
    }

    const trimmed = data.trim();
    if (trimmed === '') {
      return [];
    }

    // Check if JSON array
    if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
      try {
        const parsed = JSON.parse(trimmed);
        if (Array.isArray(parsed)) {
          return this.ingestFromInline(parsed);
        }
      } catch (err) {
        throw new ValidationError(
          `Invalid JSON dataset: ${err instanceof Error ? err.message : String(err)}`
        );
      }
    }

    // Parse as CSV
    return this.parseCsv(trimmed);
  }

  /**
   * Safely reads and ingests data from a file inside the jailed workspace sandbox.
   */
  private async ingestFromFile(
    filePath: string,
    context: AgentExecutionContext,
    approvalToken?: string
  ): Promise<Record<string, unknown>[]> {
    const availableTools = context.listTools();
    const hasReadTool =
      availableTools.some((t) => t.name === 'file_read') ||
      !!context.getTool('file_read');

    if (!hasReadTool) {
      throw new ToolExecutionError(
        'file_read',
        "Tool 'file_read' is not available in the current execution context to read file dataset."
      );
    }

    try {
      const result = await context.executeTool(
        'file_read',
        { path: filePath },
        approvalToken
      );

      const output = result.output as { content?: string } | undefined;
      const content = output?.content;
      if (typeof content !== 'string') {
        throw new ToolExecutionError(
          'file_read',
          `File '${filePath}' returned empty or non-string content.`
        );
      }

      return this.ingestFromInline(content);
    } catch (err) {
      if (
        err instanceof AgentCancelledError ||
        err instanceof SecurityViolationError ||
        err instanceof ValidationError
      ) {
        throw err;
      }
      throw new ToolExecutionError(
        'file_read',
        `Failed to safely ingest file dataset from '${filePath}': ${err instanceof Error ? err.message : String(err)}`
      );
    }
  }

  /**
   * Robust RFC 4180-compliant CSV parser with quotes, commas, CRLF, and escaped quotes.
   */
  public parseCsv(csvText: string): Record<string, unknown>[] {
    const rows: string[][] = [];
    let currentRow: string[] = [];
    let currentField = '';
    let insideQuotes = false;

    let i = 0;
    const len = csvText.length;

    while (i < len) {
      const char = csvText[i];

      if (insideQuotes) {
        if (char === '"') {
          if (i + 1 < len && csvText[i + 1] === '"') {
            // Escaped quote "" -> "
            currentField += '"';
            i += 2;
            continue;
          } else {
            // Closing quote
            insideQuotes = false;
            i++;
            continue;
          }
        } else {
          currentField += char;
          i++;
          continue;
        }
      } else {
        if (char === '"') {
          insideQuotes = true;
          i++;
          continue;
        } else if (char === ',') {
          currentRow.push(currentField.trim());
          currentField = '';
          i++;
          continue;
        } else if (char === '\r') {
          if (i + 1 < len && csvText[i + 1] === '\n') {
            i++;
          }
          currentRow.push(currentField.trim());
          currentField = '';
          if (currentRow.some((f) => f.length > 0)) {
            rows.push(currentRow);
          }
          currentRow = [];
          i++;
          continue;
        } else if (char === '\n') {
          currentRow.push(currentField.trim());
          currentField = '';
          if (currentRow.some((f) => f.length > 0)) {
            rows.push(currentRow);
          }
          currentRow = [];
          i++;
          continue;
        } else {
          currentField += char;
          i++;
          continue;
        }
      }
    }

    if (currentField.length > 0 || currentRow.length > 0) {
      currentRow.push(currentField.trim());
      if (currentRow.some((f) => f.length > 0)) {
        rows.push(currentRow);
      }
    }

    if (rows.length === 0) {
      return [];
    }

    const rawHeaders = rows[0]!;
    // Normalize headers and ensure uniqueness
    const headers: string[] = [];
    const headerCounts = new Map<string, number>();

    for (let c = 0; c < rawHeaders.length; c++) {
      let name = rawHeaders[c]!.trim();
      if (!name) {
        name = `column_${c + 1}`;
      }
      const count = headerCounts.get(name) ?? 0;
      headerCounts.set(name, count + 1);
      if (count > 0) {
        headers.push(`${name}_${count + 1}`);
      } else {
        headers.push(name);
      }
    }

    const records: Record<string, unknown>[] = [];
    for (let r = 1; r < rows.length; r++) {
      const row = rows[r]!;
      const record: Record<string, unknown> = {};
      for (let h = 0; h < headers.length; h++) {
        const header = headers[h]!;
        const val = row[h];
        if (val === undefined || this.isMissingValue(val)) {
          record[header] = null;
        } else {
          record[header] = val;
        }
      }
      records.push(record);
    }

    return records;
  }

  private isMissingValue(val: unknown): boolean {
    if (val === null || val === undefined) return true;
    if (typeof val === 'string') {
      const s = val.trim().toLowerCase();
      return (
        s === '' ||
        s === 'null' ||
        s === 'none' ||
        s === 'na' ||
        s === 'n/a' ||
        s === 'nan' ||
        s === 'undefined'
      );
    }
    if (typeof val === 'number') {
      return isNaN(val);
    }
    return false;
  }

  private extractColumnNames(records: readonly Record<string, unknown>[]): string[] {
    const keys = new Set<string>();
    for (const rec of records) {
      for (const k of Object.keys(rec)) {
        keys.add(k);
      }
    }
    return Array.from(keys);
  }

  // --- Dataset Profiling ---

  private profileDataset(
    records: readonly Record<string, unknown>[],
    columns: readonly string[]
  ): DatasetProfile {
    const rowCount = records.length;
    const columnCount = columns.length;

    if (rowCount === 0 || columnCount === 0) {
      return {
        rowCount,
        columnCount,
        columns: [],
        numericColumns: [],
        categoricalColumns: [],
        booleanColumns: [],
        dateColumns: [],
        identifierColumns: [],
        emptyDataset: true
      };
    }

    const columnProfiles: ColumnProfile[] = [];
    const numericCols: string[] = [];
    const categoricalCols: string[] = [];
    const booleanCols: string[] = [];
    const dateCols: string[] = [];
    const identifierCols: string[] = [];

    for (const col of columns) {
      let missingCount = 0;
      let validCount = 0;
      const distinctValues = new Set<unknown>();
      const sampleValues: unknown[] = [];

      for (const rec of records) {
        const val = rec[col];
        if (this.isMissingValue(val)) {
          missingCount++;
        } else {
          validCount++;
          distinctValues.add(val);
          if (sampleValues.length < 5) {
            sampleValues.push(val);
          }
        }
      }

      const inferredType = this.inferColumnType(records, col);
      const isUnique = validCount === rowCount && distinctValues.size === rowCount;
      const isConstant = distinctValues.size <= 1;
      const isPotentialIdentifier =
        isUnique &&
        (inferredType === 'categorical' || inferredType === 'numeric') &&
        /(?:^id$|_id$|key|uuid|code|sku)/i.test(col);

      columnProfiles.push({
        name: col,
        type: inferredType,
        totalCount: rowCount,
        validCount,
        missingCount,
        missingPercentage: rowCount > 0 ? (missingCount / rowCount) * 100 : 0,
        uniqueCount: distinctValues.size,
        isUnique,
        isPotentialIdentifier,
        isConstant,
        sampleValues
      });

      if (inferredType === 'numeric') numericCols.push(col);
      else if (inferredType === 'categorical') categoricalCols.push(col);
      else if (inferredType === 'boolean') booleanCols.push(col);
      else if (inferredType === 'date') dateCols.push(col);

      if (isPotentialIdentifier || (isUnique && validCount === rowCount)) {
        identifierCols.push(col);
      }
    }

    return {
      rowCount,
      columnCount,
      columns: columnProfiles,
      numericColumns: numericCols,
      categoricalColumns: categoricalCols,
      booleanColumns: booleanCols,
      dateColumns: dateCols,
      identifierColumns: identifierCols,
      emptyDataset: false
    };
  }

  /**
   * Deterministic type inference for a column.
   */
  private inferColumnType(
    records: readonly Record<string, unknown>[],
    column: string
  ): ColumnDataType {
    let nonNullCount = 0;
    let numericCount = 0;
    let booleanCount = 0;
    let dateCount = 0;

    const dateRegex =
      /^\d{4}[-/]\d{1,2}[-/]\d{1,2}(?:[T\s]\d{1,2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?)?$/;

    for (const rec of records) {
      const val = rec[column];
      if (this.isMissingValue(val)) continue;

      nonNullCount++;

      // Boolean check
      if (
        typeof val === 'boolean' ||
        (typeof val === 'string' &&
          /^(?:true|false|yes|no)$/i.test(val.trim()))
      ) {
        booleanCount++;
        continue;
      }

      // Numeric check (strict numbers, avoiding boolean conversion or pure dates)
      if (typeof val === 'number' && !isNaN(val) && isFinite(val)) {
        numericCount++;
        continue;
      }

      if (typeof val === 'string') {
        const s = val.trim();
        // Check if recognizable date format first
        if (dateRegex.test(s) && !isNaN(Date.parse(s))) {
          dateCount++;
          continue;
        }

        // Check if numeric string
        const num = Number(s);
        if (!isNaN(num) && isFinite(num) && !/^\s*$/i.test(s)) {
          numericCount++;
          continue;
        }
      }
    }

    if (nonNullCount === 0) {
      return 'categorical';
    }

    if (booleanCount === nonNullCount) {
      return 'boolean';
    }

    if (numericCount === nonNullCount) {
      return 'numeric';
    }

    if (dateCount === nonNullCount) {
      return 'date';
    }

    // High threshold (>90%) for numeric or date with minimal dirty data
    if (numericCount / nonNullCount >= 0.9) {
      return 'numeric';
    }

    if (dateCount / nonNullCount >= 0.9) {
      return 'date';
    }

    return 'categorical';
  }

  // --- Descriptive Statistics (Numeric) ---

  private computeDescriptiveStatistics(
    records: readonly Record<string, unknown>[],
    column: string,
    outlierMultiplier: number
  ): ColumnStatistics {
    const totalRows = records.length;
    const values: number[] = [];
    let missingCount = 0;

    for (const rec of records) {
      const val = rec[column];
      if (this.isMissingValue(val)) {
        missingCount++;
      } else {
        const num = typeof val === 'number' ? val : Number(val);
        if (!isNaN(num) && isFinite(num)) {
          values.push(num);
        } else {
          missingCount++;
        }
      }
    }

    const count = values.length;
    const missingPercentage = totalRows > 0 ? (missingCount / totalRows) * 100 : 0;

    if (count === 0) {
      return {
        column,
        count: 0,
        missingCount,
        missingPercentage,
        sum: 0,
        mean: 0,
        median: 0,
        min: 0,
        max: 0,
        range: 0,
        sampleVariance: 0,
        sampleStdDev: 0,
        populationVariance: 0,
        populationStdDev: 0,
        q1: 0,
        q2: 0,
        q3: 0,
        iqr: 0,
        outlierCount: 0,
        outlierPercentage: 0,
        outliers: []
      };
    }

    values.sort((a, b) => a - b);

    const sum = values.reduce((acc, v) => acc + v, 0);
    const mean = sum / count;
    const min = values[0]!;
    const max = values[count - 1]!;
    const range = max - min;

    // Percentiles using linear interpolation
    const q1 = this.calculatePercentile(values, 0.25);
    const median = this.calculatePercentile(values, 0.5);
    const q3 = this.calculatePercentile(values, 0.75);
    const iqr = q3 - q1;

    // Variance & Standard Deviation
    let sumSquaredDiff = 0;
    for (const v of values) {
      const diff = v - mean;
      sumSquaredDiff += diff * diff;
    }

    const sampleVariance = count > 1 ? sumSquaredDiff / (count - 1) : 0;
    const sampleStdDev = Math.sqrt(sampleVariance);
    const populationVariance = sumSquaredDiff / count;
    const populationStdDev = Math.sqrt(populationVariance);

    // IQR Outlier Detection
    const lowerBound = q1 - outlierMultiplier * iqr;
    const upperBound = q3 + outlierMultiplier * iqr;
    const outliers = values.filter((v) => v < lowerBound || v > upperBound);
    const outlierCount = outliers.length;
    const outlierPercentage = (outlierCount / count) * 100;

    return {
      column,
      count,
      missingCount,
      missingPercentage,
      sum,
      mean,
      median,
      min,
      max,
      range,
      sampleVariance,
      sampleStdDev,
      populationVariance,
      populationStdDev,
      q1,
      q2: median,
      q3,
      iqr,
      outlierCount,
      outlierPercentage,
      outliers: outliers.slice(0, 10) // Bound to top 10 representatives
    };
  }

  /**
   * Deterministic percentile calculation using standard linear interpolation.
   */
  private calculatePercentile(sorted: readonly number[], p: number): number {
    const n = sorted.length;
    if (n === 0) return 0;
    if (n === 1) return sorted[0]!;
    if (p <= 0) return sorted[0]!;
    if (p >= 1) return sorted[n - 1]!;

    const index = p * (n - 1);
    const lower = Math.floor(index);
    const upper = Math.ceil(index);
    const weight = index - lower;

    return sorted[lower]! * (1 - weight) + sorted[upper]! * weight;
  }

  // --- Categorical Analysis ---

  private computeCategoricalStatistics(
    records: readonly Record<string, unknown>[],
    column: string,
    maxCategories: number
  ): CategoricalStatistics {
    const totalRows = records.length;
    const counts = new Map<string, number>();
    let totalValid = 0;

    for (const rec of records) {
      const val = rec[column];
      if (this.isMissingValue(val)) continue;

      totalValid++;
      const strVal = String(val).trim();
      counts.set(strVal, (counts.get(strVal) ?? 0) + 1);
    }

    const distribution: CategoryDistribution[] = Array.from(counts.entries())
      .map(([category, count]) => ({
        category,
        count,
        percentage: totalValid > 0 ? (count / totalValid) * 100 : 0
      }))
      .sort((a, b) => b.count - a.count);

    const uniqueCount = counts.size;
    const isHighCardinality =
      uniqueCount > 50 || (totalRows > 10 && uniqueCount / totalRows > 0.5);

    const topCategories = distribution.slice(0, maxCategories);
    const bottomCategories = [...distribution]
      .reverse()
      .slice(0, Math.min(5, distribution.length));

    return {
      column,
      totalValid,
      uniqueCount,
      topCategories,
      bottomCategories,
      isHighCardinality,
      distribution
    };
  }

  // --- Data Quality Evaluation ---

  private evaluateDataQuality(
    records: readonly Record<string, unknown>[],
    columns: readonly string[],
    datasetProfile: DatasetProfile,
    numericStats: Record<string, ColumnStatistics>
  ): DataQualityReport {
    const totalRows = datasetProfile.rowCount;
    const totalColumns = columns.length;
    const totalCells = totalRows * totalColumns;

    let missingCells = 0;
    const highMissingColumns: string[] = [];
    const constantColumns: string[] = [];
    const warnings: string[] = [];

    // Missingness & constant columns
    for (const colProf of datasetProfile.columns) {
      missingCells += colProf.missingCount;
      if (colProf.missingPercentage > 20) {
        highMissingColumns.push(colProf.name);
        warnings.push(
          `Column '${colProf.name}' has high missingness (${colProf.missingPercentage.toFixed(1)}%).`
        );
      }
      if (colProf.isConstant) {
        constantColumns.push(colProf.name);
        warnings.push(
          `Column '${colProf.name}' is constant (zero variance; all values identical or null).`
        );
      }
    }

    const missingPercentage = totalCells > 0 ? (missingCells / totalCells) * 100 : 0;

    // Duplicate rows detection
    let duplicateRowsCount = 0;
    const seenRowSignatures = new Set<string>();

    for (const rec of records) {
      const sig = columns.map((col) => String(rec[col] ?? '')).join('|');
      if (seenRowSignatures.has(sig)) {
        duplicateRowsCount++;
      } else {
        seenRowSignatures.add(sig);
      }
    }

    const duplicateRowsPercentage =
      totalRows > 0 ? (duplicateRowsCount / totalRows) * 100 : 0;
    if (duplicateRowsCount > 0) {
      warnings.push(
        `Dataset contains ${duplicateRowsCount} duplicate record(s) (${duplicateRowsPercentage.toFixed(1)}%).`
      );
    }

    // Outliers compilation
    const outliersDetected: {
      column: string;
      count: number;
      percentage: number;
      bounds: { lower: number; upper: number };
    }[] = [];

    for (const [colName, stats] of Object.entries(numericStats)) {
      if (stats.outlierCount > 0) {
        const lowerBound = stats.q1 - 1.5 * stats.iqr;
        const upperBound = stats.q3 + 1.5 * stats.iqr;
        outliersDetected.push({
          column: colName,
          count: stats.outlierCount,
          percentage: stats.outlierPercentage,
          bounds: { lower: lowerBound, upper: upperBound }
        });
        warnings.push(
          `Column '${colName}' has ${stats.outlierCount} outlier(s) (${stats.outlierPercentage.toFixed(1)}%) exceeding 1.5x IQR bounds.`
        );
      }
    }

    // Overall quality score
    let overallQualityScore: 'EXCELLENT' | 'GOOD' | 'FAIR' | 'POOR' = 'EXCELLENT';
    if (missingPercentage > 25 || duplicateRowsPercentage > 15) {
      overallQualityScore = 'POOR';
    } else if (
      missingPercentage > 10 ||
      duplicateRowsPercentage > 5 ||
      outliersDetected.length > 2
    ) {
      overallQualityScore = 'FAIR';
    } else if (missingPercentage > 2 || duplicateRowsPercentage > 0) {
      overallQualityScore = 'GOOD';
    }

    return {
      totalRows,
      totalColumns,
      totalCells,
      missingCells,
      missingPercentage,
      duplicateRowsCount,
      duplicateRowsPercentage,
      constantColumns,
      highMissingColumns,
      outliersDetected,
      overallQualityScore,
      warnings
    };
  }

  // --- Relationships & Correlations (Pearson r) ---

  private computeCorrelations(
    records: readonly Record<string, unknown>[],
    numericColumns: readonly string[],
    threshold: number
  ): readonly CorrelationItem[] {
    const correlations: CorrelationItem[] = [];
    const nCols = numericColumns.length;
    if (nCols < 2 || records.length < 2) {
      return correlations;
    }

    for (let i = 0; i < nCols; i++) {
      for (let j = i + 1; j < nCols; j++) {
        const colA = numericColumns[i]!;
        const colB = numericColumns[j]!;

        const pairs: Array<{ x: number; y: number }> = [];
        for (const rec of records) {
          const valA = rec[colA];
          const valB = rec[colB];
          if (this.isMissingValue(valA) || this.isMissingValue(valB)) continue;

          const numA = typeof valA === 'number' ? valA : Number(valA);
          const numB = typeof valB === 'number' ? valB : Number(valB);

          if (!isNaN(numA) && isFinite(numA) && !isNaN(numB) && isFinite(numB)) {
            pairs.push({ x: numA, y: numB });
          }
        }

        const sampleSize = pairs.length;
        if (sampleSize < 2) continue;

        const meanX = pairs.reduce((acc, p) => acc + p.x, 0) / sampleSize;
        const meanY = pairs.reduce((acc, p) => acc + p.y, 0) / sampleSize;

        let cov = 0;
        let varX = 0;
        let varY = 0;

        for (const p of pairs) {
          const dx = p.x - meanX;
          const dy = p.y - meanY;
          cov += dx * dy;
          varX += dx * dx;
          varY += dy * dy;
        }

        let coefficient = 0;
        if (varX > 1e-12 && varY > 1e-12) {
          coefficient = cov / Math.sqrt(varX * varY);
          // Bound floating point inaccuracies
          coefficient = Math.max(-1, Math.min(1, coefficient));
        }

        let strength: CorrelationItem['strength'] = 'WEAK';
        if (coefficient >= 0.7) strength = 'STRONG_POSITIVE';
        else if (coefficient >= 0.3) strength = 'MODERATE_POSITIVE';
        else if (coefficient <= -0.7) strength = 'STRONG_NEGATIVE';
        else if (coefficient <= -0.3) strength = 'MODERATE_NEGATIVE';

        if (Math.abs(coefficient) >= threshold) {
          correlations.push({
            columnA: colA,
            columnB: colB,
            coefficient: Number(coefficient.toFixed(4)),
            strength,
            sampleSize
          });
        }
      }
    }

    // Sort by absolute correlation strength descending
    correlations.sort((a, b) => Math.abs(b.coefficient) - Math.abs(a.coefficient));
    return correlations;
  }

  // --- Temporal Trends Analysis ---

  private analyzeTemporalTrends(
    records: readonly Record<string, unknown>[],
    dateColumns: readonly string[],
    numericColumns: readonly string[]
  ): readonly TrendAnalysis[] {
    const trends: TrendAnalysis[] = [];
    if (dateColumns.length === 0 || numericColumns.length === 0) {
      return trends;
    }

    const primaryDateCol = dateColumns[0]!;

    // Sort records chronologically
    const validDateRecords = records
      .map((r) => {
        const dVal = r[primaryDateCol];
        const timestamp = typeof dVal === 'string' ? Date.parse(dVal) : NaN;
        return { record: r, timestamp };
      })
      .filter((item) => !isNaN(item.timestamp))
      .sort((a, b) => a.timestamp - b.timestamp);

    if (validDateRecords.length < 3) {
      return trends;
    }

    // Evaluate trends for top numeric columns
    for (const numCol of numericColumns.slice(0, 5)) {
      const series: Array<{ t: number; y: number }> = [];
      for (const item of validDateRecords) {
        const val = item.record[numCol];
        if (this.isMissingValue(val)) continue;
        const num = typeof val === 'number' ? val : Number(val);
        if (!isNaN(num) && isFinite(num)) {
          series.push({ t: item.timestamp, y: num });
        }
      }

      const n = series.length;
      if (n < 3) continue;

      const startValue = series[0]!.y;
      const endValue = series[n - 1]!.y;
      const change = endValue - startValue;
      const percentageChange =
        startValue !== 0 ? (change / Math.abs(startValue)) * 100 : 0;

      // Linear regression slope against normalized index [0..n-1]
      const meanX = (n - 1) / 2;
      const meanY = series.reduce((acc, s) => acc + s.y, 0) / n;

      let numerator = 0;
      let denominator = 0;
      for (let i = 0; i < n; i++) {
        const dx = i - meanX;
        const dy = series[i]!.y - meanY;
        numerator += dx * dy;
        denominator += dx * dx;
      }

      const slope = denominator > 0 ? numerator / denominator : 0;

      let direction: 'INCREASING' | 'DECREASING' | 'STABLE' = 'STABLE';
      if (slope > 0.05 && percentageChange > 5) {
        direction = 'INCREASING';
      } else if (slope < -0.05 && percentageChange < -5) {
        direction = 'DECREASING';
      }

      trends.push({
        dateColumn: primaryDateCol,
        metricColumn: numCol,
        direction,
        startValue: Number(startValue.toFixed(2)),
        endValue: Number(endValue.toFixed(2)),
        change: Number(change.toFixed(2)),
        percentageChange: Number(percentageChange.toFixed(2)),
        slope: Number(slope.toFixed(4))
      });
    }

    return trends;
  }

  // --- Group Comparisons ---

  private computeGroupComparisons(
    records: readonly Record<string, unknown>[],
    categoricalColumns: readonly string[],
    numericColumns: readonly string[]
  ): readonly GroupComparison[] {
    const comparisons: GroupComparison[] = [];
    if (categoricalColumns.length === 0 || numericColumns.length === 0) {
      return comparisons;
    }

    // Select candidate categorical column with manageable cardinality (2 to 15)
    for (const catCol of categoricalColumns.slice(0, 2)) {
      const distinctGroups = new Set<string>();
      for (const rec of records) {
        const v = rec[catCol];
        if (!this.isMissingValue(v)) {
          distinctGroups.add(String(v).trim());
        }
      }

      if (distinctGroups.size < 2 || distinctGroups.size > 15) {
        continue;
      }

      for (const numCol of numericColumns.slice(0, 2)) {
        const groupMap = new Map<string, number[]>();

        for (const rec of records) {
          const gVal = rec[catCol];
          const mVal = rec[numCol];
          if (this.isMissingValue(gVal) || this.isMissingValue(mVal)) continue;

          const group = String(gVal).trim();
          const num = typeof mVal === 'number' ? mVal : Number(mVal);
          if (!isNaN(num) && isFinite(num)) {
            let list = groupMap.get(group);
            if (!list) {
              list = [];
              groupMap.set(group, list);
            }
            list.push(num);
          }
        }

        const groups = Array.from(groupMap.entries())
          .map(([group, vals]) => {
            const count = vals.length;
            const sum = vals.reduce((a, b) => a + b, 0);
            const mean = count > 0 ? sum / count : 0;
            const min = count > 0 ? Math.min(...vals) : 0;
            const max = count > 0 ? Math.max(...vals) : 0;
            return {
              group,
              count,
              sum: Number(sum.toFixed(2)),
              mean: Number(mean.toFixed(2)),
              min: Number(min.toFixed(2)),
              max: Number(max.toFixed(2))
            };
          })
          .sort((a, b) => b.mean - a.mean);

        if (groups.length >= 2) {
          comparisons.push({
            groupColumn: catCol,
            metricColumn: numCol,
            groups
          });
        }
      }
    }

    return comparisons;
  }

  // --- Synthesis of Insights, Recommendations & Limitations ---

  private synthesizeFindings(
    objective: string,
    profile: DatasetProfile,
    quality: DataQualityReport,
    numStats: Record<string, ColumnStatistics>,
    catStats: Record<string, CategoricalStatistics>,
    correlations: readonly CorrelationItem[],
    trends: readonly TrendAnalysis[],
    groupComparisons: readonly GroupComparison[]
  ): {
    insights: readonly string[];
    recommendations: readonly string[];
    limitations: readonly string[];
    summary: string;
  } {
    const insights: string[] = [];
    const recommendations: string[] = [];
    const limitations: string[] = [];

    // Core dataset overview insight
    insights.push(
      `Dataset contains ${profile.rowCount.toLocaleString()} record(s) and ${profile.columnCount} feature(s) (${profile.numericColumns.length} numeric, ${profile.categoricalColumns.length} categorical, ${profile.dateColumns.length} date, ${profile.booleanColumns.length} boolean).`
    );

    // Identifier insight
    if (profile.identifierColumns.length > 0) {
      insights.push(
        `Primary identifier candidate(s) detected: ${profile.identifierColumns.map((c) => `\`${c}\``).join(', ')}.`
      );
    }

    // Quality insight & recommendation
    if (quality.overallQualityScore === 'EXCELLENT') {
      insights.push(
        'Data quality is Excellent: zero severe missingness or structural duplicate issues.'
      );
    } else {
      insights.push(
        `Data quality rated as ${quality.overallQualityScore}: missing cell rate is ${quality.missingPercentage.toFixed(1)}% with ${quality.duplicateRowsCount} duplicate row(s).`
      );
      if (quality.highMissingColumns.length > 0) {
        recommendations.push(
          `Impute or handle missing values for high-missingness feature(s): ${quality.highMissingColumns.map((c) => `\`${c}\``).join(', ')}.`
        );
      }
      if (quality.duplicateRowsCount > 0) {
        recommendations.push(
          `Deduplicate dataset before downstream modeling (${quality.duplicateRowsCount} redundant record(s) identified).`
        );
      }
    }

    // Numeric statistics insights
    for (const [col, stats] of Object.entries(numStats)) {
      if (stats.outlierCount > 0) {
        insights.push(
          `Metric \`${col}\` displays notable variance (mean: ${stats.mean.toFixed(2)}, median: ${stats.median.toFixed(2)}) with ${stats.outlierCount} outlier(s) outside 1.5x IQR.`
        );
        recommendations.push(
          `Apply robust scaling or investigate outlier records in \`${col}\` (IQR: ${stats.iqr.toFixed(2)}, bounds: [${(stats.q1 - 1.5 * stats.iqr).toFixed(2)}, ${(stats.q3 + 1.5 * stats.iqr).toFixed(2)}]).`
        );
      }
    }

    // Categorical distribution insights
    for (const [col, stats] of Object.entries(catStats)) {
      if (stats.topCategories.length > 0) {
        const top = stats.topCategories[0]!;
        insights.push(
          `Feature \`${col}\` is dominated by category "${top.category}" accounting for ${top.percentage.toFixed(1)}% of valid observations.`
        );
      }
      if (stats.isHighCardinality) {
        recommendations.push(
          `Feature \`${col}\` exhibits high cardinality (${stats.uniqueCount} distinct values); consider grouping infrequent categories.`
        );
      }
    }

    // Correlation insights (with correlation != causation warning)
    if (correlations.length > 0) {
      const topCorr = correlations[0]!;
      insights.push(
        `Strongest statistical relationship detected between \`${topCorr.columnA}\` and \`${topCorr.columnB}\` (Pearson r = ${topCorr.coefficient.toFixed(3)}, ${topCorr.strength.replace('_', ' ').toLowerCase()}).`
      );
    }

    // Temporal trends
    for (const tr of trends) {
      if (tr.direction !== 'STABLE') {
        insights.push(
          `Temporal trend identified: \`${tr.metricColumn}\` has a ${tr.direction.toLowerCase()} trajectory (${tr.percentageChange > 0 ? '+' : ''}${tr.percentageChange.toFixed(1)}% change over period).`
        );
      }
    }

    // Group comparisons
    for (const gc of groupComparisons) {
      if (gc.groups.length >= 2) {
        const topGroup = gc.groups[0]!;
        const lowestGroup = gc.groups[gc.groups.length - 1]!;
        insights.push(
          `Segmentation by \`${gc.groupColumn}\` reveals highest average \`${gc.metricColumn}\` in group "${topGroup.group}" (${topGroup.mean.toFixed(2)}) versus "${lowestGroup.group}" (${lowestGroup.mean.toFixed(2)}).`
        );
      }
    }

    // Analytical limitations
    limitations.push(
      'Correlation coefficients measure linear statistical co-occurrence only and do not establish causal relationships.'
    );
    limitations.push(
      'Outlier detection utilizes standard Tukey 1.5x IQR fences; non-normal or skewed distributions may exhibit natural extreme values.'
    );
    if (profile.rowCount < 30) {
      limitations.push(
        'Small sample size (N < 30) increases sampling variance and limits generalizability of statistical inferences.'
      );
    }

    // Executive summary paragraph
    const summary =
      `Analytics completed for "${objective}". Analyzed ${profile.rowCount.toLocaleString()} record(s) ` +
      `across ${profile.columnCount} feature(s). Overall data quality is rated as ${quality.overallQualityScore} ` +
      `(missing cell rate: ${quality.missingPercentage.toFixed(1)}%, duplicates: ${quality.duplicateRowsCount}). ` +
      `Identified ${profile.numericColumns.length} numeric distribution(s), ${correlations.length} significant correlation pair(s), ` +
      `and ${insights.length} actionable domain insight(s).`;

    return {
      insights,
      recommendations,
      limitations,
      summary
    };
  }

  // --- Markdown Report Generator ---

  public formatMarkdownReport(report: AnalyticsReport): string {
    const lines: string[] = [];

    lines.push(`# Analytics Report: ${report.objective}`);
    lines.push('');
    lines.push(
      `**Status**: \`COMPLETED\` | **Rows**: ${report.datasetProfile.rowCount.toLocaleString()} | **Columns**: ${report.datasetProfile.columnCount} | **Quality**: \`${report.dataQuality.overallQualityScore}\``
    );
    lines.push('');
    lines.push('---');
    lines.push('');

    // Executive Summary
    lines.push('## Executive Summary');
    lines.push(report.summary);
    lines.push('');

    // Dataset Profile
    lines.push('## Dataset Profile');
    lines.push(
      `The dataset contains **${report.datasetProfile.rowCount.toLocaleString()}** rows and **${report.datasetProfile.columnCount}** columns.`
    );
    lines.push('');
    lines.push('| Column | Type | Valid Rows | Missing | Missing % | Unique | Characteristics |');
    lines.push('|---|---|---|---|---|---|---|');

    for (const col of report.datasetProfile.columns) {
      const tags: string[] = [];
      if (col.isPotentialIdentifier) tags.push('`Identifier`');
      if (col.isConstant) tags.push('`Constant`');
      if (col.uniqueCount === col.totalCount && col.validCount === col.totalCount) tags.push('`Unique`');
      const charStr = tags.length > 0 ? tags.join(' ') : '—';

      lines.push(
        `| \`${col.name}\` | \`${col.type}\` | ${col.validCount.toLocaleString()} | ${col.missingCount.toLocaleString()} | ${col.missingPercentage.toFixed(1)}% | ${col.uniqueCount.toLocaleString()} | ${charStr} |`
      );
    }
    lines.push('');

    // Data Quality Assessment
    lines.push('## Data Quality Assessment');
    lines.push(`- **Overall Quality Rating**: \`${report.dataQuality.overallQualityScore}\``);
    lines.push(`- **Total Cells**: ${report.dataQuality.totalCells.toLocaleString()}`);
    lines.push(
      `- **Missing Cells**: ${report.dataQuality.missingCells.toLocaleString()} (${report.dataQuality.missingPercentage.toFixed(2)}%)`
    );
    lines.push(
      `- **Duplicate Rows**: ${report.dataQuality.duplicateRowsCount.toLocaleString()} (${report.dataQuality.duplicateRowsPercentage.toFixed(2)}%)`
    );

    if (report.dataQuality.constantColumns.length > 0) {
      lines.push(
        `- **Constant Columns**: ${report.dataQuality.constantColumns.map((c) => `\`${c}\``).join(', ')}`
      );
    }
    if (report.dataQuality.warnings.length > 0) {
      lines.push('');
      lines.push('### Quality Alerts & Anomalies');
      for (const w of report.dataQuality.warnings) {
        lines.push(`- ⚠️ ${w}`);
      }
    }
    lines.push('');

    // Descriptive Statistics
    const numCols = Object.keys(report.numericStatistics);
    if (numCols.length > 0) {
      lines.push('## Descriptive Statistics (Numeric Features)');
      lines.push(
        '| Feature | Count | Mean | Std Dev | Min | Q1 (25%) | Median | Q3 (75%) | Max | IQR | Outliers |'
      );
      lines.push(
        '|---|---|---|---|---|---|---|---|---|---|---|'
      );

      for (const col of numCols) {
        const s = report.numericStatistics[col]!;
        lines.push(
          `| \`${col}\` | ${s.count} | ${s.mean.toFixed(2)} | ${s.sampleStdDev.toFixed(2)} | ${s.min.toFixed(2)} | ${s.q1.toFixed(2)} | ${s.median.toFixed(2)} | ${s.q3.toFixed(2)} | ${s.max.toFixed(2)} | ${s.iqr.toFixed(2)} | ${s.outlierCount} |`
        );
      }
      lines.push('');
    }

    // Categorical Distributions
    const catCols = Object.keys(report.categoricalStatistics);
    if (catCols.length > 0) {
      lines.push('## Categorical Analysis & Frequency Distributions');
      for (const col of catCols) {
        const cs = report.categoricalStatistics[col]!;
        lines.push(`### Feature: \`${col}\` (Cardinality: ${cs.uniqueCount})`);
        lines.push('| Category | Frequency | Proportion |');
        lines.push('|---|---|---|');
        for (const dist of cs.topCategories) {
          lines.push(`| ${dist.category} | ${dist.count.toLocaleString()} | ${dist.percentage.toFixed(1)}% |`);
        }
        lines.push('');
      }
    }

    // Relationships & Correlations
    if (report.correlations.length > 0) {
      lines.push('## Relationships & Pearson Correlations');
      lines.push(
        '> [!IMPORTANT]\n> **Statistical Note**: Correlation does NOT imply causation. High correlation indicates a linear statistical association between variables, not that changes in one variable cause changes in the other.'
      );
      lines.push('');
      lines.push('| Variable A | Variable B | Pearson r | Strength | Sample Size |');
      lines.push('|---|---|---|---|---|');

      for (const corr of report.correlations) {
        lines.push(
          `| \`${corr.columnA}\` | \`${corr.columnB}\` | ${corr.coefficient > 0 ? '+' : ''}${corr.coefficient.toFixed(3)} | \`${corr.strength}\` | ${corr.sampleSize} |`
        );
      }
      lines.push('');
    }

    // Temporal Trends
    if (report.temporalTrends.length > 0) {
      lines.push('## Temporal Trends');
      lines.push('| Date Column | Metric | Direction | Start Value | End Value | Total Change | % Change |');
      lines.push('|---|---|---|---|---|---|---|');

      for (const tr of report.temporalTrends) {
        lines.push(
          `| \`${tr.dateColumn}\` | \`${tr.metricColumn}\` | \`${tr.direction}\` | ${tr.startValue.toFixed(2)} | ${tr.endValue.toFixed(2)} | ${tr.change.toFixed(2)} | ${tr.percentageChange > 0 ? '+' : ''}${tr.percentageChange.toFixed(1)}% |`
        );
      }
      lines.push('');
    }

    // Group Comparisons
    if (report.groupComparisons.length > 0) {
      lines.push('## Group Comparisons & Segmentation');
      for (const gc of report.groupComparisons) {
        lines.push(`### \`${gc.metricColumn}\` grouped by \`${gc.groupColumn}\``);
        lines.push('| Group | Count | Mean | Sum | Min | Max |');
        lines.push('|---|---|---|---|---|---|');
        for (const g of gc.groups) {
          lines.push(
            `| ${g.group} | ${g.count} | ${g.mean.toFixed(2)} | ${g.sum.toFixed(2)} | ${g.min.toFixed(2)} | ${g.max.toFixed(2)} |`
          );
        }
        lines.push('');
      }
    }

    // Key Insights & Actionable Recommendations
    lines.push('## Key Insights & Actionable Recommendations');
    lines.push('### Key Insights');
    for (const ins of report.insights) {
      lines.push(`- ${ins}`);
    }
    lines.push('');

    if (report.recommendations.length > 0) {
      lines.push('### Actionable Recommendations');
      for (const rec of report.recommendations) {
        lines.push(`1. ${rec}`);
      }
      lines.push('');
    }

    // Limitations
    if (report.limitations.length > 0) {
      lines.push('## Analytical Limitations & Assumptions');
      for (const lim of report.limitations) {
        lines.push(`- ${lim}`);
      }
      lines.push('');
    }

    return lines.join('\n');
  }

  // --- Output Formatting ---

  private formatAgentOutput(
    input: AgentInput,
    context: AgentExecutionContext,
    report: AnalyticsReport,
    stepsExecuted: number,
    startMs: number
  ): AgentOutput {
    const reportMarkdown = this.formatMarkdownReport(report);

    return {
      agentId: this.id,
      taskId: input.taskId ?? context.taskId,
      status: 'COMPLETED',
      result: {
        report,
        reportMarkdown,
        response: reportMarkdown,
        summary: report.summary,
        totalRows: report.datasetProfile.rowCount,
        totalColumns: report.datasetProfile.columnCount,
        numericColumns: report.datasetProfile.numericColumns,
        categoricalColumns: report.datasetProfile.categoricalColumns,
        qualityScore: report.dataQuality.overallQualityScore
      },
      summary: report.summary,
      stepsExecuted,
      durationMs: Math.max(0, Date.now() - startMs)
    };
  }
}
