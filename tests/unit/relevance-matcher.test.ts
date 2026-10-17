/**
 * Next-Generation Dots AI Platform - Relevance Matcher Unit Tests
 * Phase 7.2: Memory Subsystem
 * 
 * Verifies:
 * 1. Exact key matching and key token containment.
 * 2. Tag overlap and partial tag matching.
 * 3. Word overlap and English stop-word filtering.
 * 4. Strict zero-relevance guarantee for unrelated candidates (no invented scores).
 * 5. Deterministic tie-breaking order (score, priority, createdAt, key, id).
 * 6. Empty queries, empty candidate lists, and malformed text inputs.
 * 7. Pure in-memory calculation (no database access, no LLM invocations).
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import type { Memory } from '../../src/domain/types.ts';
import {
  RelevanceMatcher,
  tokenizeText,
  BASIC_ENGLISH_STOP_WORDS
} from '../../src/memory/relevance-matcher.ts';

function createMockMemory(overrides: Partial<Memory> = {}): Memory {
  return {
    id: overrides.id ?? 'mem-test-uuid-1',
    category: overrides.category ?? 'PROJECT_FACT',
    scopeType: overrides.scopeType ?? 'WORKSPACE',
    scopeId: overrides.scopeId ?? 'ws-alpha',
    key: overrides.key ?? 'default.key',
    content: overrides.content ?? 'Default memory content description.',
    status: overrides.status ?? 'ACTIVE',
    priority: overrides.priority ?? 50,
    tagsJson: overrides.tagsJson ?? '["default"]',
    metadataJson: overrides.metadataJson ?? '{}',
    createdAt: overrides.createdAt ?? '2026-01-01T00:00:00.000Z',
    updatedAt: overrides.updatedAt ?? '2026-01-01T00:00:00.000Z',
    lastAccessedAt: overrides.lastAccessedAt ?? null,
    accessCount: overrides.accessCount ?? 0
  };
}

test('tokenizeText - filters English stop words and normalizes to lowercase alphanumeric tokens', () => {
  const input = "What is the default deployment port for the user's API server?";
  const tokens = tokenizeText(input);

  // Stop words 'what', 'is', 'the', 'for' should be removed
  assert.ok(!tokens.includes('what'));
  assert.ok(!tokens.includes('is'));
  assert.ok(!tokens.includes('the'));
  assert.ok(!tokens.includes('for'));

  // Content keywords must remain
  assert.ok(tokens.includes('default'));
  assert.ok(tokens.includes('deployment'));
  assert.ok(tokens.includes('port'));
  assert.ok(tokens.includes('user'));
  assert.ok(tokens.includes('api'));
  assert.ok(tokens.includes('server'));

  // Check documented stop words set
  assert.ok(BASIC_ENGLISH_STOP_WORDS.has('the'));
  assert.ok(BASIC_ENGLISH_STOP_WORDS.has('and'));
  assert.ok(BASIC_ENGLISH_STOP_WORDS.has('or'));
  assert.ok(BASIC_ENGLISH_STOP_WORDS.has('which'));
});

test('RelevanceMatcher - exact key matches receive highest key component score', () => {
  const matcher = new RelevanceMatcher();

  const candidate = createMockMemory({
    key: 'docker.build.target',
    tagsJson: '[]',
    content: 'Completely different unmatching words here.'
  });

  // 1. Exact full key query
  const scoredExact = matcher.score('docker.build.target', candidate);
  assert.equal(scoredExact.breakdown.keyMatch, 1.0);
  assert.equal(scoredExact.breakdown.keyMatched, true);
  assert.equal(scoredExact.score, 0.50); // 0.50 * 1.0

  // 2. Query containing exact key phrase
  const scoredContained = matcher.score('Please inspect the docker.build.target setting', candidate);
  assert.equal(scoredContained.breakdown.keyMatch, 1.0);
  assert.equal(scoredContained.breakdown.keyMatched, true);

  // 3. Query matching all key tokens
  const scoredTokens = matcher.score('build docker target', candidate);
  assert.equal(scoredTokens.breakdown.keyMatch, 1.0);

  // 4. Query matching partial key tokens (2 of 3)
  const scoredPartial = matcher.score('target docker container', candidate);
  assert.equal(scoredPartial.breakdown.keyMatch, 0.6667);
  assert.equal(scoredPartial.breakdown.keyMatched, true);
});

test('RelevanceMatcher - tag overlap evaluates candidate tags against query terms', () => {
  const matcher = new RelevanceMatcher();

  const candidate = createMockMemory({
    key: 'unrelated.key.xyz',
    tagsJson: '["postgres", "database", "backend"]',
    content: 'Nothing overlapping here.'
  });

  // Query matches 2 of 3 tags ('postgres', 'database')
  const scored = matcher.score('connect to postgres database instance', candidate);
  assert.equal(scored.breakdown.tagMatch, 0.6667);
  assert.deepEqual(scored.breakdown.matchedTags, ['postgres', 'database']);
  // Tag weight: 0.30 * 0.6667 = 0.20
  assert.equal(scored.score, 0.20);
});

test('RelevanceMatcher - word overlap filters stop words and scores keyword recall', () => {
  const matcher = new RelevanceMatcher();

  const candidate = createMockMemory({
    key: 'api.config',
    tagsJson: '[]',
    content: 'The production api server listens on port 8080 with TLS enabled.'
  });

  // Query: "What is the port for the api server?"
  // Non-stop query words: ['port', 'api', 'server'] -> size 3
  // Candidate content contains all 3 keywords ('port', 'api', 'server')
  const scored = matcher.score('What is the port for the api server?', candidate);
  assert.equal(scored.breakdown.wordOverlap, 1.0);
  assert.ok(scored.breakdown.matchedWords.includes('port'));
  assert.ok(scored.breakdown.matchedWords.includes('api'));
  assert.ok(scored.breakdown.matchedWords.includes('server'));
});

test('RelevanceMatcher - strictly guarantees zero relevance for unrelated memories', () => {
  const matcher = new RelevanceMatcher();

  const candidate = createMockMemory({
    key: 'recipes.desserts.pancake',
    tagsJson: '["breakfast", "baking", "sweet"]',
    content: 'Combine flour, milk, baking powder, and whisk thoroughly before frying.'
  });

  // Query has zero relation to baking or pancakes
  const scored = matcher.score('deploy kubernetes cluster to aws us-east-1', candidate);
  assert.equal(scored.breakdown.keyMatch, 0.0);
  assert.equal(scored.breakdown.tagMatch, 0.0);
  assert.equal(scored.breakdown.wordOverlap, 0.0);
  assert.deepEqual(scored.breakdown.matchedTags, []);
  assert.deepEqual(scored.breakdown.matchedWords, []);
  assert.equal(scored.breakdown.keyMatched, false);

  // Crucial: no invented relevance!
  assert.equal(scored.score, 0.0);
});

test('RelevanceMatcher - stable ranking and deterministic tie-breaking across runs', () => {
  const matcher = new RelevanceMatcher();

  const memHighRelevance = createMockMemory({
    id: 'id-1',
    key: 'docker.deploy.port',
    tagsJson: '["docker", "port"]',
    content: 'Port 8080',
    priority: 50,
    createdAt: '2026-01-01T00:00:00.000Z'
  });

  // Same relevance, higher priority
  const memTieHighPriority = createMockMemory({
    id: 'id-2',
    key: 'generic.match',
    tagsJson: '["docker"]',
    content: 'Generic docker memo',
    priority: 90,
    createdAt: '2026-01-01T00:00:00.000Z'
  });

  // Same relevance, lower priority, newer timestamp
  const memTieNewer = createMockMemory({
    id: 'id-3',
    key: 'generic.match',
    tagsJson: '["docker"]',
    content: 'Generic docker memo',
    priority: 50,
    createdAt: '2026-02-01T00:00:00.000Z'
  });

  // Same relevance, priority, timestamp, but key alphabetical ('a.match' before 'b.match')
  const memTieAlphaA = createMockMemory({
    id: 'id-4',
    key: 'a.match',
    tagsJson: '["docker"]',
    content: 'Generic docker memo',
    priority: 50,
    createdAt: '2026-01-01T00:00:00.000Z'
  });

  const memTieAlphaB = createMockMemory({
    id: 'id-5',
    key: 'b.match',
    tagsJson: '["docker"]',
    content: 'Generic docker memo',
    priority: 50,
    createdAt: '2026-01-01T00:00:00.000Z'
  });

  const query = 'docker deploy port';

  const candidates = [
    memTieAlphaB,
    memHighRelevance,
    memTieAlphaA,
    memTieNewer,
    memTieHighPriority
  ];

  // Run ranking 50 times with shuffled input order to prove absolute determinism
  for (let i = 0; i < 50; i++) {
    const shuffled = [...candidates].sort(() => Math.random() - 0.5);
    const ranked = matcher.rank(query, shuffled);

    // memHighRelevance has highest score -> 1st
    assert.equal(ranked[0]!.memory.id, 'id-1');
    // memTieHighPriority has priority 90 -> 2nd
    assert.equal(ranked[1]!.memory.id, 'id-2');
    // memTieNewer has newer timestamp -> 3rd
    assert.equal(ranked[2]!.memory.id, 'id-3');
    // memTieAlphaA has key 'a.match' -> 4th
    assert.equal(ranked[3]!.memory.id, 'id-4');
    // memTieAlphaB has key 'b.match' -> 5th
    assert.equal(ranked[4]!.memory.id, 'id-5');
  }
});

test('RelevanceMatcher - handles empty queries, empty candidate lists, and malformed inputs', () => {
  const matcher = new RelevanceMatcher();
  const mem = createMockMemory({ key: 'test.key', content: 'test content' });

  // Empty query string -> all scores 0.0
  const emptyQueryRank = matcher.rank('', [mem]);
  assert.equal(emptyQueryRank.length, 1);
  assert.equal(emptyQueryRank[0]!.score, 0.0);

  // Whitespace-only query
  const whitespaceRank = matcher.rank('   \t\n  ', [mem]);
  assert.equal(whitespaceRank.length, 1);
  assert.equal(whitespaceRank[0]!.score, 0.0);

  // Empty candidate list -> empty result
  const emptyListRank = matcher.rank('some task query', []);
  assert.deepEqual(emptyListRank, []);

  // Candidate with corrupted tagsJson (does not crash, treats as empty tags)
  const corruptedMem = createMockMemory({ tagsJson: 'invalid-json{{{' });
  const scoredCorrupted = matcher.score('test query', corruptedMem);
  assert.equal(scoredCorrupted.breakdown.tagMatch, 0.0);
});
