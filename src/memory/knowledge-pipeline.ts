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

import { createHash } from 'node:crypto';
import type {
  Memory,
  MemoryCategory,
  CallerContext,
  Task,
  CandidateEvidence,
  EvidenceSourceType,
  EvidenceRelationship,
  CandidateClaim
} from '../domain/types.ts';
import type { AgentOutput } from '../agents/types.ts';
import type { MemoryService } from './memory-service.ts';
import type { EvidenceVerificationEngine } from './evidence-verifier.ts';
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
  readonly evidence?: readonly CandidateEvidence[];
  readonly claims?: readonly CandidateClaim[];
}

export interface ProcessCompletedTaskOptions {
  readonly task: Task;
  readonly agentId: string;
  readonly output: AgentOutput;
  readonly caller: CallerContext;
  readonly memoryService: MemoryService;
  readonly verificationEngine?: EvidenceVerificationEngine;
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
 * Normalizes a domain name, stripping protocols, ports, and trailing paths.
 */
export function normalizeDomain(domain: string | null | undefined): string | undefined {
  if (!domain || typeof domain !== 'string') return undefined;
  const trimmed = domain.trim().toLowerCase();
  if (!trimmed) return undefined;
  try {
    if (trimmed.startsWith('http://') || trimmed.startsWith('https://')) {
      return new URL(trimmed).hostname.toLowerCase();
    }
  } catch {
    // continue
  }
  const clean = trimmed.replace(/^https?:\/\//i, '').split('/')[0].split(':')[0];
  return clean || undefined;
}

/**
 * Extracts a normalized domain from a URL string.
 */
export function extractDomainFromUrl(url: string | null | undefined): string | undefined {
  if (!url || typeof url !== 'string') return undefined;
  const trimmed = url.trim();
  if (!trimmed) return undefined;
  try {
    const parsed = new URL(trimmed.includes('://') ? trimmed : `https://${trimmed}`);
    return parsed.hostname.toLowerCase();
  } catch {
    return normalizeDomain(trimmed);
  }
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

  // Helper: extract CandidateEvidence records from a source ONLY if relationship is explicitly established
  function extractSourceEvidence(s: any): CandidateEvidence[] {
    if (!s || typeof s !== 'object') return [];
    if (s.relationship !== 'SUPPORTS' && s.relationship !== 'CONTRADICTS' && s.relationship !== 'LIMITATION') {
      return [];
    }

    const rawUrl = typeof s.url === 'string' && s.url.trim() ? s.url.trim() : undefined;
    const rawDomain = normalizeDomain(s.domain) ?? extractDomainFromUrl(rawUrl);
    const rawTitle = typeof s.title === 'string' && s.title.trim() ? s.title.trim() : undefined;

    const snippets: string[] = [];
    if (Array.isArray(s.relevantEvidence)) {
      for (const item of s.relevantEvidence) {
        if (typeof item === 'string' && item.trim()) {
          snippets.push(item.trim());
        }
      }
    }
    if (typeof s.snippet === 'string' && s.snippet.trim()) {
      snippets.push(s.snippet.trim());
    }
    if (snippets.length === 0 && typeof s.summary === 'string' && s.summary.trim()) {
      snippets.push(s.summary.trim());
    }

    const results: CandidateEvidence[] = [];
    if (snippets.length > 0) {
      for (const snippet of snippets) {
        results.push({
          sourceType: 'WEB_RESEARCH',
          sourceUrl: rawUrl,
          sourceDomain: rawDomain,
          sourceTitle: rawTitle,
          snippet,
          snippetHash: createHash('sha256').update(snippet, 'utf8').digest('hex'),
          relationship: s.relationship
        });
      }
    } else if (rawUrl || rawDomain || rawTitle) {
      const fallback = rawUrl ?? rawDomain ?? rawTitle ?? '';
      results.push({
        sourceType: 'WEB_RESEARCH',
        sourceUrl: rawUrl,
        sourceDomain: rawDomain,
        sourceTitle: rawTitle,
        snippet: undefined,
        snippetHash: createHash('sha256').update(fallback, 'utf8').digest('hex'),
        relationship: s.relationship
      });
    }
    return results;
  }

  function sourceTargetsFinding(s: any, findingIndex: number, allFindings: readonly string[]): boolean {
    if (!s || typeof s !== 'object') return false;

    // Numerical index matching
    if (typeof s.targetFindingIndex === 'number' && Number.isInteger(s.targetFindingIndex)) {
      return s.targetFindingIndex === findingIndex;
    }

    // Array of indices matching
    if (Array.isArray(s.targetFindingIndices)) {
      return s.targetFindingIndices.includes(findingIndex);
    }

    // String / title / slug matching
    if (typeof s.targetFinding === 'string' && s.targetFinding.trim()) {
      const tf = s.targetFinding.trim().toLowerCase();
      const claim = (allFindings[findingIndex] ?? '').toLowerCase();
      if (tf === claim || tf === String(findingIndex) || tf === `finding-${findingIndex + 1}`) {
        return true;
      }
    }

    return false;
  }

  function hasExplicitFindingTarget(s: any, numFindings: number): boolean {
    if (!s || typeof s !== 'object') return false;
    if (typeof s.targetFindingIndex === 'number' && Number.isInteger(s.targetFindingIndex)) {
      // Must be within valid bounds to count as a valid target
      return s.targetFindingIndex >= 0 && s.targetFindingIndex < numFindings;
    }
    if (Array.isArray(s.targetFindingIndices)) {
      return s.targetFindingIndices.some((idx: unknown) => typeof idx === 'number' && idx >= 0 && idx < numFindings);
    }
    if (typeof s.targetFinding === 'string' && s.targetFinding.trim()) {
      return true;
    }
    return false;
  }

  // 1. Reusable Research Findings
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

    if (findings.length === 1) {
      // Single finding: proposal is research.finding.${questionSlug}
      const evidenceList: CandidateEvidence[] = [];
      for (const s of sources) {
        if (!s || typeof s !== 'object') continue;

        // If source has an explicit finding target specified:
        if (hasExplicitFindingTarget(s, 1)) {
          // Must target finding 0; if it targets another finding, reject
          if (!sourceTargetsFinding(s, 0, findings)) {
            continue;
          }
        } else if (typeof s.targetFindingIndex === 'number' || Array.isArray(s.targetFindingIndices)) {
          // Malformed or out-of-bounds numerical target index (e.g. 999 or -1): reject
          continue;
        } else if (s.relationship === 'CONTRADICTS') {
          // CONTRADICTS requires an explicit validated target finding; reject if untargeted
          continue;
        }

        evidenceList.push(...extractSourceEvidence(s));
      }

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
          findingsCount: 1,
          sourcesCount: sources.length
        },
        evidence: evidenceList.length > 0 ? evidenceList : undefined,
        claims: [{ originalText: findings[0]! }]
      });
    } else {
      // Multiple findings: check for explicit source-to-finding references
      const hasTargeted = sources.some((s) => hasExplicitFindingTarget(s, findings.length));

      if (hasTargeted) {
        // Emit individual finding proposals with isolated, dedicated evidence
        for (let i = 0; i < findings.length; i++) {
          const claim = findings[i]!;
          const findingSlug = slugify(claim, 35);
          const targetedSources = sources.filter((s) => sourceTargetsFinding(s, i, findings));
          const findingEvidence: CandidateEvidence[] = [];
          for (const s of targetedSources) {
            findingEvidence.push(...extractSourceEvidence(s));
          }

          const cited = targetedSources
            .map((s) => `${s.title ?? s.domain ?? 'Source'}: ${s.url ?? s.domain ?? 'public source'}`)
            .join('\n- ');

          const findingContent =
            `Research Topic: ${question}\n\n` +
            `Verified Finding ${i + 1}:\n${claim}\n\n` +
            (cited ? `Sources Cited:\n- ${cited}` : `Sources Cited:\n- ${sourceSummary}`);

          proposals.push({
            key: `research.finding.${questionSlug}.${findingSlug}`,
            content: findingContent.trim(),
            category: 'PROJECT_FACT',
            tags: ['research', 'finding', ...tokenizeKeyWords(question).slice(0, 3), ...tokenizeKeyWords(claim).slice(0, 2)],
            priority: 60,
            metadata: {
              source: 'automatic_knowledge_proposal',
              agentType: 'research',
              question,
              findingIndex: i,
              finding: claim,
              sourcesCount: targetedSources.length
            },
            evidence: findingEvidence.length > 0 ? findingEvidence : undefined,
            claims: [{ originalText: claim }]
          });
        }

        // Also emit the composite summary proposal with preserved markdown content.
        // Dedicated finding evidence is NOT attached to the composite proposal.
        const generalSources = sources.filter((s) => !hasExplicitFindingTarget(s, findings.length));
        const generalEvidence: CandidateEvidence[] = [];
        for (const s of generalSources) {
          // General sources lack specific finding attribution; CONTRADICTS is never allowed without a target finding
          if (s?.relationship === 'CONTRADICTS') {
            continue;
          }
          generalEvidence.push(...extractSourceEvidence(s));
        }

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
          },
          evidence: generalEvidence.length > 0 ? generalEvidence : undefined,
          claims: findings.map((f) => ({ originalText: f }))
        });
      } else {
        // No explicit source-to-finding targets: preserve composite proposal.
        // Sources cannot be reliably associated with individual findings, so no false SUPPORTS evidence is attached.
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
          },
          evidence: undefined,
          claims: findings.map((f) => ({ originalText: f }))
        });
      }
    }
  }

  // 2. Explicit Limitations & Unresolved Questions
  if (limitations.length > 0 || openQuestions.length > 0) {
    const uncertaintyContent =
      `Research Boundaries & Uncertainty for: ${question}\n\n` +
      (limitations.length > 0 ? `Limitations & Uncertainty:\n${limitations.map((l) => `- ${l}`).join('\n')}\n\n` : '') +
      (openQuestions.length > 0 ? `Open Questions for Future Investigation:\n${openQuestions.map((q) => `- ${q}`).join('\n')}` : '');

    // Never attach SUPPORTS evidence to limitations.
    // Only attach sources explicitly established as LIMITATION targeting limitations.
    const limitationEvidence: CandidateEvidence[] = [];
    for (const s of sources) {
      if (s && s.relationship === 'LIMITATION' && (s.targetFinding === 'limitations' || s.targetFinding === 'uncertainty')) {
        limitationEvidence.push(...extractSourceEvidence(s));
      }
    }

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
      },
      evidence: limitationEvidence.length > 0 ? limitationEvidence : undefined
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
    const verifications: any[] = Array.isArray(report.verificationResults) ? report.verificationResults : [];

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

    const evidenceList: CandidateEvidence[] = [];
    for (const v of verifications) {
      if (!v || typeof v !== 'object') continue;
      const title = (typeof v.target === 'string' && v.target.trim())
        ? v.target.trim()
        : ((typeof v.name === 'string' && v.name.trim())
          ? v.name.trim()
          : ((typeof v.description === 'string' && v.description.trim()) ? v.description.trim() : undefined));

      const snippet = (typeof v.evidence === 'string' && v.evidence.trim())
        ? v.evidence.trim()
        : ((typeof v.details === 'string' && v.details.trim())
          ? v.details.trim()
          : ((typeof v.description === 'string' && v.description.trim()) ? v.description.trim() : undefined));

      const passed = v.status === 'PASSED' || v.passed === true;
      const failed = v.status === 'FAILED' || v.passed === false;
      const relationship: EvidenceRelationship = passed ? 'SUPPORTS' : (failed ? 'CONTRADICTS' : 'LIMITATION');

      if (title || snippet) {
        const hashContent = snippet ?? title ?? '';
        evidenceList.push({
          sourceType: 'CODE_VERIFICATION',
          sourceTitle: title,
          snippet,
          snippetHash: createHash('sha256').update(hashContent, 'utf8').digest('hex'),
          relationship
        });
      }
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
      },
      evidence: evidenceList.length > 0 ? evidenceList : undefined
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

    const evidenceList: CandidateEvidence[] = [];
    for (const v of verifications) {
      if (!v || typeof v !== 'object') continue;
      const title = (typeof v.target === 'string' && v.target.trim())
        ? v.target.trim()
        : ((typeof v.name === 'string' && v.name.trim())
          ? v.name.trim()
          : ((typeof v.description === 'string' && v.description.trim()) ? v.description.trim() : undefined));

      const snippet = (typeof v.evidence === 'string' && v.evidence.trim())
        ? v.evidence.trim()
        : ((typeof v.details === 'string' && v.details.trim())
          ? v.details.trim()
          : ((typeof v.description === 'string' && v.description.trim()) ? v.description.trim() : undefined));

      const passed = v.status === 'PASSED' || v.passed === true;
      const failed = v.status === 'FAILED' || v.passed === false;
      const relationship: EvidenceRelationship = passed ? 'SUPPORTS' : (failed ? 'CONTRADICTS' : 'LIMITATION');

      if (title || snippet) {
        const hashContent = snippet ?? title ?? '';
        evidenceList.push({
          sourceType: 'CODE_VERIFICATION',
          sourceTitle: title,
          snippet,
          snippetHash: createHash('sha256').update(hashContent, 'utf8').digest('hex'),
          relationship
        });
      }
    }

    for (const c of commands) {
      if (!c || typeof c !== 'object') continue;
      if (typeof c.command === 'string' && c.command.trim()) {
        const cmd = c.command.trim();
        const exitCode = typeof c.exitCode === 'number' ? c.exitCode : 0;
        const snippetText = `Command: ${cmd}\nExit Code: ${exitCode}` +
          (typeof c.stdout === 'string' && c.stdout.trim() ? `\nStdout: ${c.stdout.trim()}` : '');
        evidenceList.push({
          sourceType: 'TOOL_EXECUTION',
          sourceTitle: cmd,
          snippet: snippetText,
          snippetHash: createHash('sha256').update(snippetText, 'utf8').digest('hex'),
          relationship: exitCode === 0 ? 'SUPPORTS' : 'CONTRADICTS'
        });
      }
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
      },
      evidence: evidenceList.length > 0 ? evidenceList : undefined
    });
  }

  // 4. GENERATE: strictly reject unverified generated code as a proven solution
  if (operation === 'GENERATE') {
    const verifications: any[] = Array.isArray(report.verificationResults) ? report.verificationResults : [];
    const allPassed = verifications.length > 0 && verifications.every((v) => v.passed === true || v.status === 'PASSED');
    if (allPassed) {
      let codeContent = `Verified Implementation Solution for: ${objective}\n\n`;
      if (typeof report.summary === 'string' && report.summary.trim()) {
        codeContent += `Summary:\n${report.summary}\n\n`;
      }
      codeContent += `Verification: All ${verifications.length} independent assertions passed.\n`;
      if (typeof report.generatedCode === 'string' && report.generatedCode.trim()) {
        codeContent += `Verified Implementation:\n\`\`\`\n${report.generatedCode.trim()}\n\`\`\``;
      }

      const evidenceList: CandidateEvidence[] = [];
      for (const v of verifications) {
        if (!v || typeof v !== 'object') continue;
        const title = (typeof v.target === 'string' && v.target.trim())
          ? v.target.trim()
          : ((typeof v.name === 'string' && v.name.trim())
            ? v.name.trim()
            : ((typeof v.description === 'string' && v.description.trim()) ? v.description.trim() : undefined));

        const snippet = (typeof v.evidence === 'string' && v.evidence.trim())
          ? v.evidence.trim()
          : ((typeof v.details === 'string' && v.details.trim())
            ? v.details.trim()
            : ((typeof v.description === 'string' && v.description.trim()) ? v.description.trim() : undefined));

        if (title || snippet) {
          const hashContent = snippet ?? title ?? '';
          evidenceList.push({
            sourceType: 'CODE_VERIFICATION',
            sourceTitle: title,
            snippet,
            snippetHash: createHash('sha256').update(hashContent, 'utf8').digest('hex'),
            relationship: 'SUPPORTS'
          });
        }
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
        },
        evidence: evidenceList.length > 0 ? evidenceList : undefined
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

    // Executing agent identity validation: attested agentId must match the executing agent
    if (caller.agentId && caller.agentId !== agentId) {
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

      // 2. Targeted lookup: check if an ACTIVE memory exists for this key in scope
      let activeExisting: Memory | null = null;
      try {
        activeExisting = memoryService.getMemoryByKey(caller, scrubbedKey, 'ACTIVE');
      } catch {
        // Authorization or lookup failure fail-safes without aborting the loop
      }

      let isUpdateProposal = false;

      if (activeExisting) {
        // If the active memory is inherited from another scope (e.g. GLOBAL memory inherited into WORKSPACE):
        // Workspace callers cannot modify or supersede global memories.
        // The inherited active memory satisfies and suppresses this key for the workspace.
        if (
          activeExisting.scopeType !== caller.scope.scopeType ||
          activeExisting.scopeId !== caller.scope.scopeId
        ) {
          continue;
        }

        // Active memory is in caller's own scope. Check if candidate content is identical
        const isIdenticalToActive =
          activeExisting.content.trim().toLowerCase() === boundedContent.toLowerCase();
        if (isIdenticalToActive) {
          // Suppress duplicate: active memory already contains this exact knowledge
          continue;
        }

        // Active memory in caller's scope has differing content -> candidate is an UPDATE proposal
        isUpdateProposal = true;
      }

      // 3. Targeted lookup: check matching PENDING_APPROVAL proposals for this key
      try {
        const pendingProposals = memoryService.getPendingProposalsByKey(caller, scrubbedKey);
        if (isUpdateProposal && activeExisting) {
          // For update proposals: suppress duplicate pending updates targeting the same memory with identical content
          let isDuplicatePendingUpdate = false;
          for (const pending of pendingProposals) {
            let pendingMeta: Record<string, unknown> | undefined;
            if (pending.metadataJson) {
              try {
                pendingMeta = JSON.parse(pending.metadataJson);
              } catch {
                // ignore
              }
            }
            if (
              pendingMeta?.proposalType === 'UPDATE' &&
              pendingMeta?.targetMemoryId === activeExisting.id &&
              pending.content.trim().toLowerCase() === boundedContent.toLowerCase()
            ) {
              isDuplicatePendingUpdate = true;
              break;
            }
          }
          if (isDuplicatePendingUpdate) {
            continue;
          }
        } else {
          // For ordinary new proposals: suppress if an identical pending proposal exists
          const isDuplicatePending = pendingProposals.some(
            (p) => p.content.trim().toLowerCase() === boundedContent.toLowerCase()
          );
          if (isDuplicatePending) {
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
      const sanitizedMeta = sanitizeProposalMetadata(candidate.metadata) ?? {};
      const metadata: Record<string, unknown> = {
        ...sanitizedMeta,
        source: 'automatic_knowledge_proposal',
        taskId: task.id,
        agentId,
        proposedAt: new Date().toISOString()
      };

      if (isUpdateProposal && activeExisting) {
        metadata.proposalType = 'UPDATE';
        metadata.targetMemoryId = activeExisting.id;
        metadata.targetVersion = activeExisting.version;
      }

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
          metadata,
          evidence: candidate.evidence,
          claims: candidate.claims
        });

        submitted.push(memory);
        runCandidateKeys.add(scrubbedKey);
        runCandidateContents.add(boundedContent.toLowerCase());

        // Optional bounded evidence verification (fail-safe: unavailability never fails proposal submission or task)
        if (
          options.verificationEngine &&
          memory.status === 'PENDING_APPROVAL' &&
          candidate.claims &&
          candidate.claims.length > 0 &&
          candidate.evidence &&
          candidate.evidence.length > 0
        ) {
          try {
            await options.verificationEngine.verifyProposalClaims(caller, memory.id);
          } catch {
            // Verification failure or unavailability must never fail proposal creation or the research task
          }
        }
      } catch {
        // Individual proposal submission error should not fail the pipeline or task
      }
    }

    return submitted;
  }
}
