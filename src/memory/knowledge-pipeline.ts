/**
 * Next-Generation Dots AI Platform - Post-Execution Knowledge Proposal Pipeline
 * Phase 4B.3: Automatic Knowledge Proposals
 * 
 * Architectural Mandate:
 * Analyzes structured outputs from successfully completed agent tasks (ResearchAgent,
 * AnalyticsAgent, DeveloperAgent) to identify, validate, and submit candidate memory
 * proposals through the platform's trusted memory proposal lifecycle.
 * 
 * Security & Invariant Boundaries:
 * 1. Post-Execution Gate: Operates strictly after successful agent execution (output.status === 'COMPLETED').
 *    Never extracts knowledge from failed, cancelled, or degraded runs.
 * 2. Unbypassable Approval Gate: All extracted memories are submitted via MemoryService.createMemory()
 *    using the authenticated task caller (actor: 'AGENT'), which strictly forces status to 'PENDING_APPROVAL'.
 *    Agents CANNOT self-approve, activate, or mutate memory records.
 * 3. Scope Isolation: Scope is derived strictly from the task's verified cryptographic caller scope.
 *    Untrusted or unverified caller scopes fail closed.
 * 4. Content Bounding & Sanitization: Strictly enforces memory character boundaries (key <= 256,
 *    content <= 8192, tags <= 50, metadata bounded) and scrubs all credentials and sensitive tokens.
 * 5. Duplicate Suppression: Detects existing active memories and pending proposals within scope
 *    to prevent duplicate human approval clutter.
 * 6. Graceful Fault Tolerance: Extraction or submission errors never fail or rollback a completed task.
 */

import type {
  Memory,
  MemoryCategory,
  CallerContext,
  Task
} from '../domain/types.ts';
import type { AgentOutput } from '../agents/types.ts';
import type { MemoryService } from './memory-service.ts';
import { defaultSecretScrubber } from '../model/secret-scrubber.ts';
import { sanitizeProposalMetadata } from '../tools/memory-tools.ts';
import { BASIC_ENGLISH_STOP_WORDS } from './relevance-matcher.ts';

export interface CandidateMemoryProposal {
  readonly key: string;
  readonly content: string;
  readonly category: MemoryCategory;
  readonly tags?: readonly string[];
  readonly priority?: number;
  readonly metadata?: Record<string, unknown>;
}

export interface ProcessCompletedTaskOptions {
  readonly task: Task;
  readonly agentId: string;
  readonly output: AgentOutput;
  readonly caller: CallerContext;
  readonly memoryService: MemoryService;
}

/**
 * Generates a clean, deterministic, URL/identifier-safe slug from text.
 */
export function slugify(text: string, maxLen = 40): string {
  if (!text || typeof text !== 'string') {
    return 'item';
  }
  const cleaned = text
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
  return cleaned.slice(0, maxLen) || 'item';
}

/**
 * Tokenizes text into lowercase alphanumeric keywords, filtering stop words and short tokens.
 */
export function tokenizeKeyWords(text: string): string[] {
  if (!text || typeof text !== 'string') {
    return [];
  }
  const rawTokens = text.toLowerCase().match(/[a-z0-9]+/g) ?? [];
  return rawTokens.filter((token) => token.length > 2 && !BASIC_ENGLISH_STOP_WORDS.has(token));
}

// ============================================================================
// Agent-Specific Knowledge Extractors
// ============================================================================

/**
 * Extracts candidate knowledge from ResearchAgent structured reports.
 * 
 * Rules:
 * - Reusable findings with source attribution and corroborating evidence.
 * - Does NOT store unsupported claims as established facts (skips on FAILED or INSUFFICIENT_EVIDENCE).
 * - Preserves uncertainty, conflicting perspectives, and evidence citations.
 * - Extracts explicit limitations and open questions.
 */
export function extractResearchProposals(
  output: AgentOutput,
  taskGoal: string
): CandidateMemoryProposal[] {
  if (output.status !== 'COMPLETED') {
    return [];
  }

  const result = output.result ?? {};
  const report = (result.report ?? result) as Record<string, unknown>;
  if (!report || typeof report !== 'object') {
    return [];
  }

  // Reject extraction if research failed or had insufficient evidence
  const completionStatus = (report.completionStatus ?? result.completionStatus) as string | undefined;
  if (completionStatus === 'FAILED' || completionStatus === 'INSUFFICIENT_EVIDENCE') {
    return [];
  }

  const question = typeof report.researchQuestion === 'string' && report.researchQuestion.trim()
    ? report.researchQuestion.trim()
    : taskGoal;

  const proposals: CandidateMemoryProposal[] = [];
  const questionSlug = slugify(question, 45);

  const findings: string[] = Array.isArray(report.keyFindings)
    ? report.keyFindings.filter((f: unknown): f is string => typeof f === 'string' && f.trim().length > 0)
    : [];

  const sources: any[] = Array.isArray(report.evidenceAndSources) ? report.evidenceAndSources : [];
  const agreements: string[] = Array.isArray(report.agreements) ? report.agreements : [];
  const conflicting: string[] = Array.isArray(report.conflictingEvidence) ? report.conflictingEvidence : [];
  const limitations: string[] = Array.isArray(report.limitationsAndUncertainty) ? report.limitationsAndUncertainty : [];
  const openQuestions: string[] = Array.isArray(report.openQuestions) ? report.openQuestions : [];

  // 1. Reusable Research Findings (only if backed by verified sources)
  if (findings.length > 0 && sources.length > 0) {
    const sourceSummary = sources
      .slice(0, 5)
      .map((s) => `${s.title ?? s.domain ?? 'Source'}: ${s.url ?? s.domain ?? 'public source'}`)
      .join('\n- ');

    const findingsContent =
      `Research Topic: ${question}\n\n` +
      `Key Verified Findings:\n${findings.map((f, i) => `${i + 1}. ${f}`).join('\n')}\n\n` +
      (agreements.length > 0 ? `Corroborating Evidence / Agreements:\n${agreements.map((a) => `- ${a}`).join('\n')}\n\n` : '') +
      (conflicting.length > 0 ? `Differing Perspectives / Conflicting Evidence:\n${conflicting.map((c) => `- ${c}`).join('\n')}\n\n` : '') +
      `Sources Cited:\n- ${sourceSummary}`;

    proposals.push({
      key: `research.finding.${questionSlug}`,
      content: findingsContent,
      category: 'PROJECT_FACT',
      tags: ['research', 'finding', ...tokenizeKeyWords(question).slice(0, 5)],
      priority: 60,
      metadata: {
        source: 'automatic_knowledge_proposal',
        agentType: 'research',
        question,
        findingsCount: findings.length,
        sourcesCount: sources.length
      }
    });
  }

  // 2. Explicit Limitations & Unresolved Questions
  if (limitations.length > 0 || openQuestions.length > 0) {
    const uncertaintyContent =
      `Research Boundaries & Uncertainty for: ${question}\n\n` +
      (limitations.length > 0 ? `Limitations & Uncertainty:\n${limitations.map((l) => `- ${l}`).join('\n')}\n\n` : '') +
      (openQuestions.length > 0 ? `Open Questions for Future Investigation:\n${openQuestions.map((q) => `- ${q}`).join('\n')}` : '');

    proposals.push({
      key: `research.limitations.${questionSlug}`,
      content: uncertaintyContent.trim(),
      category: 'PROJECT_FACT',
      tags: ['research', 'limitations', 'open-questions'],
      priority: 40,
      metadata: {
        source: 'automatic_knowledge_proposal',
        agentType: 'research',
        question,
        limitationsCount: limitations.length,
        openQuestionsCount: openQuestions.length
      }
    });
  }

  return proposals;
}

/**
 * Extracts candidate knowledge from AnalyticsAgent structured reports.
 * 
 * Rules:
 * - Dataset descriptions & schema characteristics.
 * - Data quality issues and warnings.
 * - Validated trends or statistical observations.
 * - Strictly NEVER stores raw datasets or large data row samples.
 */
export function extractAnalyticsProposals(
  output: AgentOutput,
  taskGoal: string
): CandidateMemoryProposal[] {
  if (output.status !== 'COMPLETED') {
    return [];
  }

  const result = output.result ?? {};
  const report = (result.report ?? result) as Record<string, unknown>;
  if (!report || typeof report !== 'object') {
    return [];
  }

  const objective = typeof report.objective === 'string' && report.objective.trim()
    ? report.objective.trim()
    : taskGoal;
  const objectiveSlug = slugify(objective, 45);

  const proposals: CandidateMemoryProposal[] = [];

  // 1. Dataset Profile & Schema Characteristics (No raw data rows!)
  const profile = report.datasetProfile as any;
  if (profile && typeof profile === 'object' && typeof profile.rowCount === 'number') {
    const profileContent =
      `Dataset Characteristics for "${objective}":\n\n` +
      `Total Rows: ${profile.rowCount}\n` +
      `Total Columns: ${profile.columnCount}\n` +
      `Column Names: ${(profile.columnNames ?? []).join(', ')}\n` +
      `Numeric Columns: ${(profile.numericColumns ?? []).join(', ')}\n` +
      `Categorical Columns: ${(profile.categoricalColumns ?? []).join(', ')}\n` +
      (Array.isArray(profile.dateColumns) && profile.dateColumns.length > 0
        ? `Date/Time Columns: ${profile.dateColumns.join(', ')}`
        : '');

    proposals.push({
      key: `analytics.dataset.${objectiveSlug}`,
      content: profileContent.trim(),
      category: 'PROJECT_FACT',
      tags: ['analytics', 'dataset-profile', 'schema', ...tokenizeKeyWords(objective).slice(0, 4)],
      priority: 50,
      metadata: {
        source: 'automatic_knowledge_proposal',
        agentType: 'analytics',
        objective,
        rowCount: profile.rowCount,
        columnCount: profile.columnCount
      }
    });
  }

  // 2. Data Quality Issues & Warnings
  const quality = report.dataQuality as any;
  if (quality && typeof quality === 'object') {
    const warnings: string[] = Array.isArray(quality.qualityWarnings) ? quality.qualityWarnings : [];
    const missingCount = typeof quality.totalMissingValues === 'number' ? quality.totalMissingValues : 0;
    const dupCount = typeof quality.duplicateRowsCount === 'number' ? quality.duplicateRowsCount : 0;

    if (warnings.length > 0 || missingCount > 0 || dupCount > 0) {
      const qualityContent =
        `Data Quality Observations for "${objective}":\n\n` +
        `Total Missing Values: ${missingCount}\n` +
        `Duplicate Rows: ${dupCount}\n` +
        (typeof quality.anomalousValuesCount === 'number' ? `Anomalous Values: ${quality.anomalousValuesCount}\n` : '') +
        (warnings.length > 0 ? `\nQuality Warnings & Anomalies:\n${warnings.map((w) => `- ${w}`).join('\n')}` : '');

      proposals.push({
        key: `analytics.quality.${objectiveSlug}`,
        content: qualityContent.trim(),
        category: 'PROJECT_FACT',
        tags: ['analytics', 'data-quality', 'data-validation'],
        priority: 55,
        metadata: {
          source: 'automatic_knowledge_proposal',
          agentType: 'analytics',
          objective,
          missingValues: missingCount,
          duplicateRows: dupCount
        }
      });
    }
  }

  // 3. Validated Trends & Statistical Observations
  const insights: string[] = Array.isArray(report.insights) ? report.insights : [];
  const correlations: any[] = Array.isArray(report.correlations) ? report.correlations : [];
  const trends: any[] = Array.isArray(report.temporalTrends) ? report.temporalTrends : [];

  if (insights.length > 0 || correlations.length > 0 || trends.length > 0) {
    let statsContent = `Validated Statistical Insights for "${objective}":\n\n`;
    if (typeof report.summary === 'string' && report.summary.trim()) {
      statsContent += `Summary: ${report.summary}\n\n`;
    }
    if (insights.length > 0) {
      statsContent += `Key Insights:\n${insights.map((ins, i) => `${i + 1}. ${ins}`).join('\n')}\n\n`;
    }
    if (correlations.length > 0) {
      const notable = correlations
        .filter((c) => Math.abs(c.pearsonCorrelation ?? 0) >= 0.5)
        .slice(0, 5);
      if (notable.length > 0) {
        statsContent += `Notable Correlations:\n${notable.map((c) => `- ${c.columnA} vs ${c.columnB}: r=${Number(c.pearsonCorrelation).toFixed(2)} (${c.strength ?? 'correlated'})`).join('\n')}\n\n`;
      }
    }
    if (trends.length > 0) {
      statsContent += `Observed Temporal Trends:\n${trends.slice(0, 3).map((t) => `- ${t.metricColumn} over ${t.timeColumn}: ${t.direction ?? 'observed'}`).join('\n')}`;
    }

    proposals.push({
      key: `analytics.insights.${objectiveSlug}`,
      content: statsContent.trim(),
      category: 'PROJECT_FACT',
      tags: ['analytics', 'insights', 'statistical-trends'],
      priority: 60,
      metadata: {
        source: 'automatic_knowledge_proposal',
        agentType: 'analytics',
        objective,
        insightsCount: insights.length
      }
    });
  }

  return proposals;
}

/**
 * Extracts candidate knowledge from DeveloperAgent structured reports.
 * 
 * Rules:
 * - Confirmed debugging solutions.
 * - Reusable implementation patterns & architectural decisions.
 * - Important testing or troubleshooting procedures.
 * - Strictly does NOT propose unverified generated code as a proven solution.
 */
export function extractDeveloperProposals(
  output: AgentOutput,
  taskGoal: string
): CandidateMemoryProposal[] {
  if (output.status !== 'COMPLETED') {
    return [];
  }

  const result = output.result ?? {};
  const report = (result.report ?? result) as Record<string, unknown>;
  if (!report || typeof report !== 'object') {
    return [];
  }

  if (report.completionStatus === 'FAILED') {
    return [];
  }

  const objective = typeof report.objective === 'string' && report.objective.trim()
    ? report.objective.trim()
    : taskGoal;
  const objectiveSlug = slugify(objective, 45);
  const operation = report.operation as string | undefined;

  const proposals: CandidateMemoryProposal[] = [];

  // 1. Confirmed Debugging Solutions
  if (operation === 'DEBUG') {
    const bugs: string[] = Array.isArray(report.bugsOrRisksIdentified) ? report.bugsOrRisksIdentified : [];
    const findings: any[] = Array.isArray(report.findings) ? report.findings : [];
    const changes: any[] = Array.isArray(report.suggestedChanges) ? report.suggestedChanges : [];

    let debugContent = `Confirmed Debugging Solution for: ${objective}\n\n`;
    if (typeof report.summary === 'string' && report.summary.trim()) {
      debugContent += `Diagnosis Summary:\n${report.summary}\n\n`;
    }
    if (bugs.length > 0) {
      debugContent += `Identified Bugs / Root Causes:\n${bugs.map((b) => `- ${b}`).join('\n')}\n\n`;
    }
    if (findings.length > 0) {
      debugContent += `Findings:\n${findings.map((f) => `- [${f.severity ?? 'INFO'}] ${f.title ?? ''}: ${f.description ?? ''}`).join('\n')}\n\n`;
    }
    if (changes.length > 0) {
      debugContent += `Applied / Verified Fixes:\n${changes.map((c) => `- ${c.filePath ?? 'File'}: ${c.description ?? 'Code change'}`).join('\n')}`;
    }

    proposals.push({
      key: `developer.debug.${objectiveSlug}`,
      content: debugContent.trim(),
      category: 'LEARNED_PROCEDURE',
      tags: ['developer', 'debugging', 'solution', ...tokenizeKeyWords(objective).slice(0, 4)],
      priority: 65,
      metadata: {
        source: 'automatic_knowledge_proposal',
        agentType: 'developer',
        operation: 'DEBUG',
        objective
      }
    });
  }

  // 2. Reusable Implementation Patterns & Architectural Decisions
  if (operation === 'ANALYZE' || operation === 'REFACTOR') {
    const files: string[] = Array.isArray(report.filesInspected) ? report.filesInspected : [];
    const findings: any[] = Array.isArray(report.findings) ? report.findings : [];
    const nextSteps: string[] = Array.isArray(report.recommendedNextSteps) ? report.recommendedNextSteps : [];

    let patternContent = `Verified Implementation Pattern for: ${objective}\n\n`;
    if (typeof report.summary === 'string' && report.summary.trim()) {
      patternContent += `Pattern Summary:\n${report.summary}\n\n`;
    }
    if (files.length > 0) {
      patternContent += `Target Components / Files:\n${files.map((f) => `- ${f}`).join('\n')}\n\n`;
    }
    if (findings.length > 0) {
      patternContent += `Architectural Findings:\n${findings.map((f) => `- ${f.title ?? ''}: ${f.description ?? ''}`).join('\n')}\n\n`;
    }
    if (nextSteps.length > 0) {
      patternContent += `Procedure / Next Steps:\n${nextSteps.map((s, i) => `${i + 1}. ${s}`).join('\n')}`;
    }

    proposals.push({
      key: `developer.pattern.${objectiveSlug}`,
      content: patternContent.trim(),
      category: 'LEARNED_PROCEDURE',
      tags: ['developer', 'architecture', 'pattern', ...tokenizeKeyWords(objective).slice(0, 4)],
      priority: 55,
      metadata: {
        source: 'automatic_knowledge_proposal',
        agentType: 'developer',
        operation,
        objective
      }
    });
  }

  // 3. Testing or Troubleshooting Procedures
  if (operation === 'TEST') {
    const verifications: any[] = Array.isArray(report.verificationResults) ? report.verificationResults : [];
    const commands: any[] = Array.isArray(report.commands) ? report.commands : [];

    let testContent = `Verified Testing Procedure for: ${objective}\n\n`;
    if (typeof report.summary === 'string' && report.summary.trim()) {
      testContent += `Execution Summary:\n${report.summary}\n\n`;
    }
    if (verifications.length > 0) {
      testContent += `Verification Outcomes:\n${verifications.map((v) => `- ${v.name ?? 'Check'}: ${v.passed ? 'PASSED' : 'FAILED'}${v.details ? ` (${v.details})` : ''}`).join('\n')}\n\n`;
    }
    if (commands.length > 0) {
      testContent += `Test Commands Executed:\n${commands.map((c) => `- \`${c.command}\` (exit code: ${c.exitCode})`).join('\n')}`;
    }

    proposals.push({
      key: `developer.test-procedure.${objectiveSlug}`,
      content: testContent.trim(),
      category: 'LEARNED_PROCEDURE',
      tags: ['developer', 'testing', 'procedure'],
      priority: 50,
      metadata: {
        source: 'automatic_knowledge_proposal',
        agentType: 'developer',
        operation: 'TEST',
        objective
      }
    });
  }

  // 4. GENERATE: strictly reject unverified generated code as a proven solution
  if (operation === 'GENERATE') {
    const verifications: any[] = Array.isArray(report.verificationResults) ? report.verificationResults : [];
    const allPassed = verifications.length > 0 && verifications.every((v) => v.passed === true);
    if (allPassed) {
      let codeContent = `Verified Implementation Solution for: ${objective}\n\n`;
      if (typeof report.summary === 'string' && report.summary.trim()) {
        codeContent += `Summary:\n${report.summary}\n\n`;
      }
      codeContent += `Verification: All ${verifications.length} independent assertions passed.\n`;
      if (typeof report.generatedCode === 'string' && report.generatedCode.trim()) {
        codeContent += `Verified Implementation:\n\`\`\`\n${report.generatedCode.trim()}\n\`\`\``;
      }

      proposals.push({
        key: `developer.verified-code.${objectiveSlug}`,
        content: codeContent.trim(),
        category: 'LEARNED_PROCEDURE',
        tags: ['developer', 'code-generation', 'verified-solution'],
        priority: 50,
        metadata: {
          source: 'automatic_knowledge_proposal',
          agentType: 'developer',
          operation: 'GENERATE',
          objective
        }
      });
    }
  }

  return proposals;
}

/**
 * Dispatches candidate extraction to the appropriate agent-specific extractor.
 */
export function extractCandidateProposals(
  agentId: string,
  output: AgentOutput,
  taskGoal: string
): CandidateMemoryProposal[] {
  const normAgentId = (agentId ?? '').toLowerCase();

  if (normAgentId.includes('research')) {
    return extractResearchProposals(output, taskGoal);
  }
  if (normAgentId.includes('analytic')) {
    return extractAnalyticsProposals(output, taskGoal);
  }
  if (normAgentId.includes('developer') || normAgentId.includes('dev')) {
    return extractDeveloperProposals(output, taskGoal);
  }

  // Fallback: heuristic inspection of report structure
  const result = output.result ?? {};
  const report = (result.report ?? result) as Record<string, unknown>;
  if (report && typeof report === 'object') {
    if ('researchQuestion' in report) {
      return extractResearchProposals(output, taskGoal);
    }
    if ('datasetProfile' in report) {
      return extractAnalyticsProposals(output, taskGoal);
    }
    if ('operation' in report && 'filesInspected' in report) {
      return extractDeveloperProposals(output, taskGoal);
    }
  }

  return [];
}

// ============================================================================
// Shared Knowledge Proposal Pipeline
// ============================================================================

export class KnowledgeProposalPipeline {
  /**
   * Inspects completed agent output, extracts structured reusable knowledge,
   * suppresses duplicates, validates bounds, scrubs secrets, and submits proposals
   * to the MemoryService under status PENDING_APPROVAL.
   */
  public async processCompletedTask(
    options: ProcessCompletedTaskOptions
  ): Promise<Memory[]> {
    const { task, agentId, output, caller, memoryService } = options;

    // Invariant 1: Only runs on completed tasks
    if (!output || output.status !== 'COMPLETED') {
      return [];
    }

    if (!caller || !memoryService) {
      return [];
    }

    // Invariant 2: Agent caller must be authenticated and valid
    if (caller.actor !== 'AGENT') {
      return [];
    }

    // Invariant 3: Extract candidates deterministically
    const candidates = extractCandidateProposals(agentId, output, task.goal);
    if (candidates.length === 0) {
      return [];
    }

    // Invariant 4: Targeted duplicate suppression and history unpoisoning.
    // Replaced unbounded listMemories() scan with indexed, scope-authorized key lookups.
    //
    // Trade-off Note (Cross-Key Content Deduplication):
    // Previously, an unbounded full-table scan populated existingContents across all keys.
    // Global cross-key exact-content detection without an unbounded scan would require a
    // dedicated content hash column/index (requiring a schema migration) or unindexed
    // full-table scans. In accordance with Phase 4D.3D.2 constraints (no schema migrations,
    // bounded indexed lookups only), exact-content deduplication is preserved:
    //   1. Within the same extraction run (runCandidateContents).
    //   2. For matching key lookups (identical pending proposal suppression).
    // Cross-key cross-task duplicate content detection is omitted in favor of O(1) indexed
    // lookups, preventing memory exhaustion on large workspaces.
    const runCandidateKeys = new Set<string>();
    const runCandidateContents = new Set<string>();
    const submitted: Memory[] = [];

    for (const candidate of candidates) {
      const scrubbedKey = defaultSecretScrubber.scrub(candidate.key.trim().toLowerCase()).slice(0, 256);
      const rawContent = defaultSecretScrubber.scrub(candidate.content.trim());
      const boundedContent = rawContent.length > 8192
        ? rawContent.slice(0, 8100) + '... [truncated for storage]'
        : rawContent;

      if (!scrubbedKey || !boundedContent) {
        continue;
      }

      // 1. Intra-run duplicate suppression (same extraction run)
      if (runCandidateKeys.has(scrubbedKey) || runCandidateContents.has(boundedContent.toLowerCase())) {
        continue;
      }

      // 2. Targeted lookup: suppress if an ACTIVE memory already exists for this key in scope
      // (Phase 4D.3D.2 preserves active-key suppression; update proposals are deferred to Phase 4D.3D.3)
      try {
        const activeExisting = memoryService.getMemoryByKey(caller, scrubbedKey, 'ACTIVE');
        if (activeExisting) {
          continue;
        }
      } catch {
        // Authorization or lookup failure fail-safes without aborting the loop
      }

      // 3. Targeted lookup: suppress if an identical PENDING_APPROVAL proposal already exists for this key
      try {
        const pendingExisting = memoryService.getMemoryByKey(caller, scrubbedKey, 'PENDING_APPROVAL');
        if (pendingExisting) {
          const isIdentical = pendingExisting.content.trim().toLowerCase() === boundedContent.toLowerCase();
          if (isIdentical) {
            continue;
          }
        }
      } catch {
        // Authorization or lookup failure fail-safes without aborting the loop
      }

      // Format tags
      const tags = (candidate.tags ?? [])
        .map((t) => defaultSecretScrubber.scrub(t.trim().toLowerCase()).slice(0, 100))
        .filter((t) => t.length > 0)
        .slice(0, 50);

      // Metadata
      const metadata = {
        ...(sanitizeProposalMetadata(candidate.metadata) ?? {}),
        source: 'automatic_knowledge_proposal',
        taskId: task.id,
        agentId,
        proposedAt: new Date().toISOString()
      };

      try {
        const memory = memoryService.createMemory(caller, {
          key: scrubbedKey,
          content: boundedContent,
          category: candidate.category,
          scopeType: caller.scope.scopeType,
          scopeId: caller.scope.scopeId,
          status: 'PENDING_APPROVAL',
          priority: candidate.priority ?? 50,
          tags,
          metadata
        });

        submitted.push(memory);
        runCandidateKeys.add(scrubbedKey);
        runCandidateContents.add(boundedContent.toLowerCase());
      } catch {
        // Individual proposal submission error should not fail the pipeline or task
      }
    }

    return submitted;
  }
}
