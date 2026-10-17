/**
 * Next-Generation Dots AI Platform - Deterministic Relevance Matcher
 * Phase 7.2: Memory Subsystem
 * 
 * Architectural Mandate:
 * Evaluates candidate memories against a task query deterministically without LLM calls
 * or direct database access. Produces explainable component breakdowns and guarantees
 * reproducible ranking.
 * 
 * Component Scoring (all normalized to [0.0, 1.0]):
 * 1. Key Match (Default weight: 0.50):
 *    - 1.0 if normalized query strictly equals normalized key or contains the key as a bounded phrase.
 *    - Proportional ratio (matchedKeyTokens / totalKeyTokens) if non-stop key tokens match query tokens.
 *    - 0.0 if no key tokens match or key is empty.
 * 2. Tag Match (Default weight: 0.30):
 *    - Proportional ratio (matchedTags / totalCandidateTags) of candidate tags present in query.
 *    - 0.0 if candidate has no tags or none match.
 * 3. Word Overlap (Default weight: 0.20):
 *    - Query term recall: (|queryTokens ∩ candidateContentTokens| / |queryTokens|).
 *    - Independent of memory length bias; evaluates how thoroughly the candidate answers query terms.
 *    - 0.0 if query has no non-stop tokens or no words overlap.
 * 
 * Composite Score:
 *    score = (0.50 * keyMatch) + (0.30 * tagMatch) + (0.20 * wordOverlap)
 *    Rounded to 4 decimal places for floating-point stability.
 *    Strict Zero-Relevance Guarantee: If keyMatch === 0, tagMatch === 0, and wordOverlap === 0,
 *    the score is strictly 0.0 (no relevance is invented for unrelated memories).
 * 
 * Tie-Breaking Order (Stable & Deterministic):
 *    1. Relevance Score (DESC)
 *    2. Priority (DESC: 100 before 50 before 0)
 *    3. Created Timestamp (DESC: newer memories first)
 *    4. Key (ASC: alphabetical comparison)
 *    5. ID (ASC: absolute deterministic fallback)
 */

import type { Memory, ScoredMemory, RelevanceBreakdown } from '../domain/types.ts';
import { ValidationError } from '../domain/errors.ts';

/**
 * Standard basic English stop-word list.
 * Words that provide grammatical structure rather than domain-specific semantic relevance.
 */
export const BASIC_ENGLISH_STOP_WORDS: ReadonlySet<string> = new Set([
  'a', 'about', 'above', 'after', 'again', 'against', 'all', 'am', 'an', 'and',
  'any', 'are', 'aren\'t', 'arent', 'as', 'at', 'be', 'because', 'been', 'before',
  'being', 'below', 'between', 'both', 'but', 'by', 'can', 'cannot', 'could',
  'couldn\'t', 'couldnt', 'did', 'didn\'t', 'didnt', 'do', 'does', 'doesn\'t',
  'doesnt', 'doing', 'don\'t', 'dont', 'down', 'during', 'each', 'few', 'for',
  'from', 'further', 'had', 'hadn\'t', 'hadnt', 'has', 'hasn\'t', 'hasnt', 'have',
  'haven\'t', 'havent', 'having', 'he', 'he\'d', 'he\'ll', 'he\'s', 'her', 'here',
  'here\'s', 'hers', 'herself', 'him', 'himself', 'his', 'how', 'how\'s', 'i',
  'i\'d', 'i\'ll', 'i\'m', 'i\'ve', 'if', 'in', 'into', 'is', 'isn\'t', 'isnt',
  'it', 'it\'s', 'its', 'itself', 'let\'s', 'lets', 'me', 'more', 'most',
  'mustn\'t', 'mustnt', 'my', 'myself', 'no', 'nor', 'not', 'of', 'off', 'on',
  'once', 'only', 'or', 'other', 'ought', 'our', 'ours', 'ourselves', 'out',
  'over', 'own', 'same', 'shan\'t', 'shant', 'she', 'she\'d', 'she\'ll', 'she\'s',
  'should', 'shouldn\'t', 'shouldnt', 'so', 'some', 'such', 'than', 'that',
  'that\'s', 'thats', 'the', 'their', 'theirs', 'them', 'themselves', 'then',
  'there', 'there\'s', 'theres', 'these', 'they', 'they\'d', 'they\'ll', 'they\'re',
  'they\'ve', 'theyve', 'this', 'those', 'through', 'to', 'too', 'under', 'until',
  'up', 'very', 'was', 'wasn\'t', 'wasnt', 'we', 'we\'d', 'we\'ll', 'we\'re',
  'we\'ve', 'were', 'weren\'t', 'werent', 'what', 'what\'s', 'whats', 'when',
  'when\'s', 'whens', 'where', 'where\'s', 'wheres', 'which', 'while', 'who',
  'who\'s', 'whos', 'whom', 'why', 'why\'s', 'whys', 'with', 'won\'t', 'wont',
  'would', 'wouldn\'t', 'wouldnt', 'you', 'you\'d', 'you\'ll', 'you\'re',
  'you\'ve', 'youve', 'your', 'yours', 'yourself', 'yourselves'
]);

/**
 * Tokenizes text into lowercase alphanumeric word tokens, filtering out stop words.
 */
export function tokenizeText(
  text: string,
  stopWords: ReadonlySet<string> = BASIC_ENGLISH_STOP_WORDS
): string[] {
  if (!text || typeof text !== 'string') {
    return [];
  }
  const rawTokens = text.toLowerCase().match(/[a-z0-9]+/g) ?? [];
  return rawTokens.filter((token) => token.length > 0 && !stopWords.has(token));
}

/**
 * Escapes characters with special meaning in regular expressions.
 */
function escapeRegExp(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Checks whether phrase appears in text as a properly bounded phrase.
 * Prevents partial-word false positives (e.g. "database" matching inside "databases",
 * or "docker.build.target" matching inside "mydocker.build.target").
 * 
 * Uses lookaround assertions:
 * - Lookbehind (?<![a-z0-9]): not preceded by an alphanumeric character
 * - Lookahead (?![a-z0-9]): not followed by an alphanumeric character
 */
export function isBoundedPhraseMatch(text: string, phrase: string): boolean {
  if (!text || !phrase) {
    return false;
  }
  const trimmedPhrase = phrase.trim();
  if (trimmedPhrase.length === 0) {
    return false;
  }
  const pattern = new RegExp(`(?<![a-z0-9])${escapeRegExp(trimmedPhrase)}(?![a-z0-9])`, 'i');
  return pattern.test(text);
}

export interface RelevanceMatcherOptions {
  readonly keyWeight?: number;
  readonly tagWeight?: number;
  readonly wordWeight?: number;
  readonly stopWords?: ReadonlySet<string>;
}

export class RelevanceMatcher {
  public static readonly DEFAULT_KEY_WEIGHT = 0.50;
  public static readonly DEFAULT_TAG_WEIGHT = 0.30;
  public static readonly DEFAULT_WORD_WEIGHT = 0.20;
  public static readonly WEIGHT_TOLERANCE = 0.0001;

  public readonly keyWeight: number;
  public readonly tagWeight: number;
  public readonly wordWeight: number;
  public readonly stopWords: ReadonlySet<string>;

  constructor(options: RelevanceMatcherOptions = {}) {
    const keyWeight = options.keyWeight ?? RelevanceMatcher.DEFAULT_KEY_WEIGHT;
    const tagWeight = options.tagWeight ?? RelevanceMatcher.DEFAULT_TAG_WEIGHT;
    const wordWeight = options.wordWeight ?? RelevanceMatcher.DEFAULT_WORD_WEIGHT;

    this.validateWeight('keyWeight', keyWeight);
    this.validateWeight('tagWeight', tagWeight);
    this.validateWeight('wordWeight', wordWeight);

    const totalWeight = keyWeight + tagWeight + wordWeight;
    if (Math.abs(totalWeight - 1.0) > RelevanceMatcher.WEIGHT_TOLERANCE) {
      throw new ValidationError(
        `Scoring weights must sum to 1.0 within tolerance of ${RelevanceMatcher.WEIGHT_TOLERANCE} ` +
        `(received total of ${totalWeight.toFixed(4)} with keyWeight=${keyWeight}, tagWeight=${tagWeight}, wordWeight=${wordWeight}).`
      );
    }

    this.keyWeight = keyWeight;
    this.tagWeight = tagWeight;
    this.wordWeight = wordWeight;
    this.stopWords = options.stopWords ?? BASIC_ENGLISH_STOP_WORDS;
  }

  private validateWeight(name: string, value: unknown): void {
    if (
      typeof value !== 'number' ||
      !Number.isFinite(value) ||
      Number.isNaN(value) ||
      value < 0
    ) {
      throw new ValidationError(
        `Scoring weight '${name}' must be a finite, non-negative number, received: ${String(value)}`
      );
    }
  }

  /**
   * Computes component scores, composite relevance, and explainability breakdown for a single candidate.
   */
  public score(query: string, candidate: Memory): ScoredMemory {
    if (!query || typeof query !== 'string' || query.trim() === '') {
      return {
        memory: candidate,
        score: 0.0,
        breakdown: {
          keyMatch: 0.0,
          tagMatch: 0.0,
          wordOverlap: 0.0,
          matchedTags: [],
          matchedWords: [],
          keyMatched: false
        }
      };
    }

    const trimmedQuery = query.trim().toLowerCase();
    const queryTokens = tokenizeText(query, this.stopWords);
    const queryTokenSet = new Set(queryTokens);

    // 1. Key Match Calculation
    const keyMatchResult = this.calculateKeyMatch(trimmedQuery, queryTokenSet, candidate.key);

    // 2. Tag Match Calculation
    const tagMatchResult = this.calculateTagMatch(trimmedQuery, queryTokenSet, candidate.tagsJson);

    // 3. Word Overlap Calculation
    const wordOverlapResult = this.calculateWordOverlap(queryTokens, queryTokenSet, candidate.content);

    // 4. Weighted Composite Score
    const rawScore =
      (keyMatchResult.score * this.keyWeight) +
      (tagMatchResult.score * this.tagWeight) +
      (wordOverlapResult.score * this.wordWeight);

    // Strict no-invention guarantee: if no component matched, score is strictly 0.0
    const hasAnyMatch = keyMatchResult.score > 0 || tagMatchResult.score > 0 || wordOverlapResult.score > 0;
    const score = hasAnyMatch ? Math.round(rawScore * 10_000) / 10_000 : 0.0;

    return {
      memory: candidate,
      score,
      breakdown: {
        keyMatch: keyMatchResult.score,
        tagMatch: tagMatchResult.score,
        wordOverlap: wordOverlapResult.score,
        matchedTags: tagMatchResult.matchedTags,
        matchedWords: wordOverlapResult.matchedWords,
        keyMatched: keyMatchResult.matched
      }
    };
  }

  /**
   * Evaluates and sorts candidate memories in deterministic rank order.
   */
  public rank(query: string, candidates: readonly Memory[]): ScoredMemory[] {
    const scored = candidates.map((c) => this.score(query, c));

    return scored.sort((a, b) => {
      // 1. Relevance Score (DESC)
      if (b.score !== a.score) {
        return b.score - a.score;
      }
      // 2. Priority (DESC)
      if (b.memory.priority !== a.memory.priority) {
        return b.memory.priority - a.memory.priority;
      }
      // 3. Creation Timestamp (DESC - newer records break ties)
      const timeB = new Date(b.memory.createdAt).getTime();
      const timeA = new Date(a.memory.createdAt).getTime();
      if (timeB !== timeA) {
        return timeB - timeA;
      }
      // 4. Key (ASC - alphabetical for stability)
      const keyComp = a.memory.key.localeCompare(b.memory.key);
      if (keyComp !== 0) {
        return keyComp;
      }
      // 5. ID (ASC - absolute deterministic tie-breaker)
      return a.memory.id.localeCompare(b.memory.id);
    });
  }

  // --- Private Component Calculators ---

  private calculateKeyMatch(
    normalizedQuery: string,
    queryTokenSet: Set<string>,
    key: string
  ): { score: number; matched: boolean } {
    if (!key || typeof key !== 'string') {
      return { score: 0.0, matched: false };
    }

    const normalizedKey = key.trim().toLowerCase();
    if (normalizedKey.length === 0) {
      return { score: 0.0, matched: false };
    }

    // Exact string equality
    if (normalizedQuery === normalizedKey) {
      return { score: 1.0, matched: true };
    }

    // Bounded phrase match of the full key (e.g. query mentions "docker.build.target" as a distinct phrase)
    if (isBoundedPhraseMatch(normalizedQuery, normalizedKey)) {
      return { score: 1.0, matched: true };
    }

    // Key token containment
    const keyTokens = tokenizeText(key, this.stopWords);
    if (keyTokens.length === 0) {
      return { score: 0.0, matched: false };
    }

    const matchedKeyTokens = keyTokens.filter((t) => queryTokenSet.has(t));
    if (matchedKeyTokens.length === 0) {
      return { score: 0.0, matched: false };
    }

    const score = Math.round((matchedKeyTokens.length / keyTokens.length) * 10_000) / 10_000;
    return { score, matched: true };
  }

  private calculateTagMatch(
    normalizedQuery: string,
    queryTokenSet: Set<string>,
    tagsJson: string
  ): { score: number; matchedTags: string[] } {
    if (!tagsJson || typeof tagsJson !== 'string') {
      return { score: 0.0, matchedTags: [] };
    }

    let parsedTags: unknown;
    try {
      parsedTags = JSON.parse(tagsJson);
    } catch {
      return { score: 0.0, matchedTags: [] };
    }

    if (!Array.isArray(parsedTags) || parsedTags.length === 0) {
      return { score: 0.0, matchedTags: [] };
    }

    const candidateTags = parsedTags
      .filter((t): t is string => typeof t === 'string' && t.trim().length > 0)
      .map((t) => t.trim().toLowerCase());

    if (candidateTags.length === 0) {
      return { score: 0.0, matchedTags: [] };
    }

    const matchedTags: string[] = [];
    for (const tag of candidateTags) {
      if (queryTokenSet.has(tag) || isBoundedPhraseMatch(normalizedQuery, tag)) {
        matchedTags.push(tag);
      }
    }

    if (matchedTags.length === 0) {
      return { score: 0.0, matchedTags: [] };
    }

    const score = Math.round((matchedTags.length / candidateTags.length) * 10_000) / 10_000;
    return { score, matchedTags };
  }

  private calculateWordOverlap(
    queryTokens: string[],
    queryTokenSet: Set<string>,
    content: string
  ): { score: number; matchedWords: string[] } {
    if (!content || typeof content !== 'string' || queryTokenSet.size === 0) {
      return { score: 0.0, matchedWords: [] };
    }

    const contentTokens = tokenizeText(content, this.stopWords);
    if (contentTokens.length === 0) {
      return { score: 0.0, matchedWords: [] };
    }

    const contentTokenSet = new Set(contentTokens);
    const matchedWords = Array.from(queryTokenSet).filter((word) => contentTokenSet.has(word));

    if (matchedWords.length === 0) {
      return { score: 0.0, matchedWords: [] };
    }

    // Recall of query terms in candidate content
    const score = Math.round((matchedWords.length / queryTokenSet.size) * 10_000) / 10_000;
    return { score, matchedWords };
  }
}
