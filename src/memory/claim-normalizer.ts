/**
 * Next-Generation Dots AI Platform - Atomic Claim Normalizer
 * Phase 4D.3D.4C.2: Atomic Claim Extraction & Scope-Aware Normalization
 * 
 * Architectural Mandate:
 * Implements deterministic canonicalization and hashing for atomic claims.
 * Claims are decoupled from specific source documents and report formatting.
 * 
 * Core Guarantees:
 * 1. Strips recognized inline citation markers without mutating original claim text.
 * 2. Normalizes casing and whitespace for stable hashing.
 * 3. Scope-aware claim ID derivation ensures cross-workspace isolation.
 * 4. Preserves semantic differences: paraphrases or distinct sentences produce distinct hashes.
 * 5. Does not fabricate subject, predicate, or qualifier when not reliably provided.
 */

import { createHash } from 'node:crypto';
import type { MemoryScopeType, MemoryClaim, CreateClaimInput } from '../domain/types.ts';
import { ValidationError } from '../domain/errors.ts';

/**
 * Recognized inline citation markers in research outputs:
 * 1. Bracketed source/ref/citation tags: [Source: redis.io], [Ref: 1], [Citation: arXiv:1234]
 * 2. Parenthetical source/ref tags: (Source: redis.io), (Ref: RFC 9000)
 * 3. Academic numeric citations: [1], [2], [1, 2]
 * 4. Markdown citation links: [Source](https://...), [1](https://...)
 */
const CITATION_MARKER_PATTERNS: readonly RegExp[] = [
  /\[(?:source|ref(?:erence)?|citation)\s*:[^\]]+\]/gi,
  /\((?:source|ref(?:erence)?|citation)\s*:[^)]+\)/gi,
  /\[\d+(?:\s*,\s*\d+)*\]/g,
  /\[(?:source|ref(?:erence)?|citation|\d+)\]\([^)]+\)/gi
];

/**
 * Strips recognized inline citation markers from text.
 * Returns clean text with citation placeholders removed.
 */
export function stripCitationMarkers(text: string): string {
  if (!text || typeof text !== 'string') return '';
  let result = text;
  for (const pattern of CITATION_MARKER_PATTERNS) {
    result = result.replace(pattern, ' ');
  }
  return result;
}

/**
 * Normalizes claim text deterministically:
 * - Strips recognized inline citation markers
 * - Standardizes unicode quotation marks to ASCII
 * - Collapses consecutive whitespace (spaces, tabs, newlines) into a single space
 * - Lowercases for case-insensitive matching
 * - Trims trailing sentence punctuation (. ! ? ; ,)
 * 
 * Invariants:
 * - Preserves internal word order, punctuation (hyphens, dots in version numbers), and vocabulary.
 * - Distinct sentences or paraphrases produce distinct canonical outputs and distinct hashes.
 */
export function canonicalizeClaimText(text: string): string {
  if (!text || typeof text !== 'string') return '';

  // 1. Strip recognized citation markers
  let cleaned = stripCitationMarkers(text);

  // 2. Standardize quotation marks
  cleaned = cleaned.replace(/[\u201C\u201D]/g, '"').replace(/[\u2018\u2019]/g, "'");

  // 3. Normalize whitespace
  cleaned = cleaned.replace(/\s+/g, ' ').trim();

  // 4. Lowercase
  cleaned = cleaned.toLowerCase();

  // 5. Trim trailing sentence punctuation
  cleaned = cleaned.replace(/[.!?;,]+$/, '').trim();

  return cleaned;
}

/**
 * Computes a deterministic SHA-256 hash of canonicalized claim text.
 */
export function computeClaimHash(canonicalText: string): string {
  if (!canonicalText || typeof canonicalText !== 'string' || canonicalText.trim() === '') {
    throw new ValidationError('Canonical claim text cannot be empty for hash computation.');
  }
  return createHash('sha256').update(canonicalText.trim(), 'utf8').digest('hex');
}

/**
 * Computes a scope-bound claim ID.
 * Incorporating scopeType and scopeId ensures that the identical factual proposition
 * evaluated in two different workspaces receives two completely distinct, isolated claim IDs.
 */
export function computeClaimId(
  scopeType: MemoryScopeType,
  scopeId: string,
  claimHash: string
): string {
  if (!scopeType || !scopeId || !claimHash) {
    throw new ValidationError('scopeType, scopeId, and claimHash are required to compute claim ID.');
  }
  return createHash('sha256')
    .update(`${scopeType}:${scopeId}:${claimHash}`, 'utf8')
    .digest('hex');
}

/**
 * Parses and validates an atomic claim structure from raw text.
 */
export function createAtomicClaim(input: CreateClaimInput): MemoryClaim {
  if (!input || typeof input !== 'object') {
    throw new ValidationError('CreateClaimInput must be provided.');
  }

  const originalText = typeof input.originalText === 'string' ? input.originalText.trim() : '';
  if (originalText === '') {
    throw new ValidationError('Original claim text must be a non-empty string.');
  }

  const canonicalText = input.canonicalText && input.canonicalText.trim() !== ''
    ? input.canonicalText.trim()
    : canonicalizeClaimText(originalText);

  if (canonicalText === '') {
    throw new ValidationError('Claim text cannot be empty or consist solely of citation markers.');
  }

  const claimHash = input.claimHash && input.claimHash.trim() !== ''
    ? input.claimHash.trim()
    : computeClaimHash(canonicalText);

  const scopeType = input.scopeType;
  const scopeId = typeof input.scopeId === 'string' ? input.scopeId.trim() : '';
  if (!scopeType || !scopeId) {
    throw new ValidationError('Valid scopeType and scopeId are required for claim creation.');
  }

  const id = input.id && input.id.trim() !== ''
    ? input.id.trim()
    : computeClaimId(scopeType, scopeId, claimHash);

  const taskId = typeof input.taskId === 'string' ? input.taskId.trim() : '';
  if (taskId === '') {
    throw new ValidationError('Originating taskId must be provided.');
  }

  const createdAt = input.createdAt && input.createdAt.trim() !== ''
    ? input.createdAt.trim()
    : new Date().toISOString();

  // Subject, predicate, qualifier: only include if provided non-empty; never invent
  const subject = typeof input.subject === 'string' && input.subject.trim() !== ''
    ? input.subject.trim()
    : null;
  const predicate = typeof input.predicate === 'string' && input.predicate.trim() !== ''
    ? input.predicate.trim()
    : null;
  const qualifier = typeof input.qualifier === 'string' && input.qualifier.trim() !== ''
    ? input.qualifier.trim()
    : null;

  return {
    id,
    memoryId: input.memoryId ?? null,
    scopeType,
    scopeId,
    originalText,
    canonicalText,
    claimHash,
    subject,
    predicate,
    qualifier,
    taskId,
    createdAt
  };
}
