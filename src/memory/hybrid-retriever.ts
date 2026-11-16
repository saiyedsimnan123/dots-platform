/**
 * Next-Generation Dots AI Platform - Hybrid Semantic and Lexical Memory Retriever
 * Phase 4C.5: Hybrid Semantic Retrieval
 * 
 * Architectural Mandate:
 * Combines deterministic lexical relevance (from RelevanceMatcher) with semantic similarity
 * (from cosine similarity over L2-normalized Float32Array embeddings).
 * 
 * Guarantees:
 * 1. Deterministic Hybrid Ranking:
 *    hybridScore = Math.round(((lexicalScore * lexicalWeight) + (calibratedSemantic * semanticWeight)) * 10_000) / 10_000.
 * 2. Strict Weight Normalization:
 *    Default weights: lexical 0.40, semantic 0.60.
 *    Weights must be finite, non-negative numbers summing to 1.0 within tolerance (0.0001).
 * 3. Calibration & Negative Cosine Protection:
 *    Raw cosine similarity is in [-1.0, 1.0]. Negative similarities are clamped to 0.0:
 *    calibratedSemantic = Math.max(0.0, Math.min(1.0, rawCosineSim)).
 *    Negative cosine similarities never produce artificially positive relevance.
 * 4. Zero-Lexical Recall:
 *    Candidates with zero lexical match (lexicalScore === 0.0) remain eligible for retrieval
 *    if their semantic similarity is sufficiently high (e.g., hybridScore > 0.0).
 * 5. Explainable Retrieval Provenance:
 *    - 'HYBRID': both lexical > 0 and semantic > 0 contributed.
 *    - 'SEMANTIC_ONLY': lexical === 0 and semantic > 0.
 *    - 'LEXICAL_ONLY': lexical > 0 and semantic === 0 (or no provider configured).
 *    - 'LEXICAL_FALLBACK': semantic retrieval was attempted or candidate vector was missing/failed,
 *      so score safely fell back to lexical score.
 * 6. Deterministic Tie-Breaking (Matching RelevanceMatcher):
 *    1. Score DESC (hybrid score)
 *    2. Priority DESC (100 before 50 before 0)
 *    3. CreatedAt DESC (newer memories first)
 *    4. Key ASC (alphabetical)
 *    5. ID ASC (alphabetical tie-breaker)
 * 7. Defensive Immutability:
 *    Never mutates candidate memories or input vector buffers.
 */

import type { Memory, ScoredMemory, RelevanceBreakdown } from '../domain/types.ts';
import type { MemoryEmbedding } from './embedding-types.ts';
import { ValidationError } from '../domain/errors.ts';
import { RelevanceMatcher } from './relevance-matcher.ts';
import { cosineSimilarity } from './vector-utils.ts';

export type RetrievalProvenance =
  | 'HYBRID'
  | 'LEXICAL_ONLY'
  | 'SEMANTIC_ONLY'
  | 'LEXICAL_FALLBACK';

export interface HybridScoredMemory extends ScoredMemory {
  /** The composite ranking score (equals hybridScore) */
  readonly score: number;
  /** Lexical component score from RelevanceMatcher [0.0, 1.0] */
  readonly lexicalScore: number;
  /** Semantic component score [0.0, 1.0] or null if semantic retrieval fell back */
  readonly semanticScore: number | null;
  /** Combined hybrid score [0.0, 1.0] */
  readonly hybridScore: number;
  /** Explainable retrieval provenance indicating which signals contributed */
  readonly provenance: RetrievalProvenance;
  /** Uncalibrated raw cosine similarity in [-1.0, 1.0], or null if unavailable */
  readonly cosineSimilarity?: number | null;
}

export interface HybridRetrieverOptions {
  readonly lexicalWeight?: number;
  readonly semanticWeight?: number;
  readonly matcher?: RelevanceMatcher;
}

export interface RankHybridOptions {
  readonly modelId?: string;
  readonly modelRevision?: string;
  readonly modelDimensions?: number;
  readonly fallbackProvenance?: RetrievalProvenance;
}

export class HybridRetriever {
  public static readonly DEFAULT_LEXICAL_WEIGHT = 0.40;
  public static readonly DEFAULT_SEMANTIC_WEIGHT = 0.60;
  public static readonly WEIGHT_TOLERANCE = 0.0001;

  public readonly lexicalWeight: number;
  public readonly semanticWeight: number;
  public readonly matcher: RelevanceMatcher;

  constructor(options: HybridRetrieverOptions = {}) {
    const lexicalWeight = options.lexicalWeight ?? HybridRetriever.DEFAULT_LEXICAL_WEIGHT;
    const semanticWeight = options.semanticWeight ?? HybridRetriever.DEFAULT_SEMANTIC_WEIGHT;

    this.validateWeight('lexicalWeight', lexicalWeight);
    this.validateWeight('semanticWeight', semanticWeight);

    const sum = lexicalWeight + semanticWeight;
    if (Math.abs(sum - 1.0) > HybridRetriever.WEIGHT_TOLERANCE) {
      throw new ValidationError(
        `Hybrid scoring weights must sum to 1.0 within tolerance of ${HybridRetriever.WEIGHT_TOLERANCE} ` +
        `(received total of ${sum.toFixed(4)} with lexicalWeight=${lexicalWeight}, semanticWeight=${semanticWeight}).`
      );
    }

    if (options.matcher !== undefined && !(options.matcher instanceof RelevanceMatcher)) {
      throw new ValidationError('Matcher must be an instance of RelevanceMatcher.');
    }

    this.lexicalWeight = lexicalWeight;
    this.semanticWeight = semanticWeight;
    this.matcher = options.matcher ?? new RelevanceMatcher();
  }

  private validateWeight(name: string, value: unknown): void {
    if (
      typeof value !== 'number' ||
      !Number.isFinite(value) ||
      Number.isNaN(value) ||
      value < 0
    ) {
      throw new ValidationError(
        `Hybrid scoring weight '${name}' must be a finite, non-negative number, received: ${String(value)}`
      );
    }
  }

  /**
   * Ranks candidate memories by combining lexical relevance and semantic similarity.
   * 
   * @param query The user or task search query string.
   * @param candidates Authorized candidate memories.
   * @param queryEmbedding Optional L2-normalized Float32Array embedding for the query.
   * @param candidateEmbeddings Optional map or array of stored memory embeddings.
   * @param options Execution and validation options (model identity, dimensions, fallback provenance).
   * @returns Deterministically ranked HybridScoredMemory array.
   */
  public rank(
    query: string,
    candidates: readonly Memory[],
    queryEmbedding?: Float32Array | null,
    candidateEmbeddings?: ReadonlyMap<string, Float32Array> | readonly MemoryEmbedding[] | null,
    options?: RankHybridOptions
  ): HybridScoredMemory[] {
    if (!candidates || candidates.length === 0) {
      return [];
    }

    // 1. Validate query embedding
    const validQueryVector = this.extractValidQueryVector(queryEmbedding, options?.modelDimensions);

    // 2. Build candidate vector lookup map
    const vectorMap = this.buildCandidateVectorMap(
      candidateEmbeddings,
      options?.modelId,
      options?.modelRevision,
      options?.modelDimensions
    );

    // 3. Score each candidate
    const scoredList: HybridScoredMemory[] = [];

    for (const candidate of candidates) {
      const lexicalScored = this.matcher.score(query, candidate);
      const lexicalScore = lexicalScored.score;

      const candidateVector = vectorMap.get(candidate.id);

      if (validQueryVector && candidateVector) {
        // Semantic retrieval available for this candidate
        try {
          if (validQueryVector.length !== candidateVector.length) {
            throw new Error('Dimension mismatch between query and candidate vector');
          }

          const rawCosine = cosineSimilarity(validQueryVector, candidateVector);
          const cosineSim = Number.isFinite(rawCosine) ? rawCosine : 0.0;
          // Protect against negative cosine similarities producing artificially positive relevance
          const calibratedSemantic = Math.max(0.0, Math.min(1.0, cosineSim));
          const semanticScore = Math.round(calibratedSemantic * 10_000) / 10_000;

          const rawHybrid = (lexicalScore * this.lexicalWeight) + (semanticScore * this.semanticWeight);
          const hybridScore = Math.round(rawHybrid * 10_000) / 10_000;

          let provenance: RetrievalProvenance;
          if (lexicalScore > 0 && semanticScore > 0) {
            provenance = 'HYBRID';
          } else if (lexicalScore === 0 && semanticScore > 0) {
            provenance = 'SEMANTIC_ONLY';
          } else {
            provenance = 'LEXICAL_ONLY';
          }

          scoredList.push({
            memory: candidate,
            score: hybridScore,
            lexicalScore,
            semanticScore,
            hybridScore,
            cosineSimilarity: Math.round(cosineSim * 10_000) / 10_000,
            provenance,
            breakdown: lexicalScored.breakdown,
            isInherited: (candidate as any)._isInherited ?? candidate.scopeType === 'GLOBAL'
          });
        } catch {
          // Fall back gracefully for this individual candidate
          scoredList.push({
            memory: candidate,
            score: lexicalScore,
            lexicalScore,
            semanticScore: null,
            hybridScore: lexicalScore,
            cosineSimilarity: null,
            provenance: 'LEXICAL_FALLBACK',
            breakdown: lexicalScored.breakdown,
            isInherited: (candidate as any)._isInherited ?? candidate.scopeType === 'GLOBAL'
          });
        }
      } else {
        // Vector missing, query vector missing, or semantic retrieval unavailable
        const defaultFallback: RetrievalProvenance = validQueryVector ? 'LEXICAL_FALLBACK' : 'LEXICAL_ONLY';
        const provenance = options?.fallbackProvenance ?? defaultFallback;

        scoredList.push({
          memory: candidate,
          score: lexicalScore,
          lexicalScore,
          semanticScore: null,
          hybridScore: lexicalScore,
          cosineSimilarity: null,
          provenance,
          breakdown: lexicalScored.breakdown,
          isInherited: (candidate as any)._isInherited ?? candidate.scopeType === 'GLOBAL'
        });
      }
    }

    // 4. Deterministic tie-breaking (identical to RelevanceMatcher)
    return scoredList.sort((a, b) => {
      // 1. Composite / Hybrid Score (DESC)
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

  private extractValidQueryVector(
    queryEmbedding?: Float32Array | null,
    expectedDimensions?: number
  ): Float32Array | null {
    if (!queryEmbedding || !(queryEmbedding instanceof Float32Array) || queryEmbedding.length === 0) {
      return null;
    }

    if (expectedDimensions !== undefined && queryEmbedding.length !== expectedDimensions) {
      return null;
    }

    for (let i = 0; i < queryEmbedding.length; i++) {
      if (!Number.isFinite(queryEmbedding[i])) {
        return null;
      }
    }

    return queryEmbedding;
  }

  private buildCandidateVectorMap(
    candidateEmbeddings?: ReadonlyMap<string, Float32Array> | readonly MemoryEmbedding[] | null,
    expectedModelId?: string,
    expectedModelRevision?: string,
    expectedDimensions?: number
  ): Map<string, Float32Array> {
    const map = new Map<string, Float32Array>();
    if (!candidateEmbeddings) {
      return map;
    }

    if (candidateEmbeddings instanceof Map) {
      for (const [id, vec] of candidateEmbeddings.entries()) {
        if (vec instanceof Float32Array && vec.length > 0) {
          if (expectedDimensions === undefined || vec.length === expectedDimensions) {
            map.set(id, vec);
          }
        }
      }
      return map;
    }

    if (Array.isArray(candidateEmbeddings)) {
      for (const item of candidateEmbeddings) {
        if (!item || typeof item !== 'object') {
          continue;
        }

        // Validate model identity matching
        if (expectedModelId !== undefined && item.modelId !== expectedModelId) {
          continue;
        }
        if (expectedModelRevision !== undefined && item.modelRevision !== expectedModelRevision) {
          continue;
        }
        if (expectedDimensions !== undefined && item.dimensions !== expectedDimensions) {
          continue;
        }

        if (item.embedding instanceof Float32Array && item.embedding.length > 0) {
          if (expectedDimensions === undefined || item.embedding.length === expectedDimensions) {
            map.set(item.memoryId, item.embedding);
          }
        }
      }
    }

    return map;
  }
}
