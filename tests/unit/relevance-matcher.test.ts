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
import { ValidationError } from '../../src/domain/errors.ts';
import {
  RelevanceMatcher,
  tokenizeText,
  isBoundedPhraseMatch,
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

  // Phase 4D.2A: Query non-stop tokens are ['connect', 'postgres', 'database', 'instance'] (size 4).
  // Candidate tags match 2 query tokens ('postgres', 'database').
  // Tag coverage formula: |matchedTags| / |queryTokenSet| = 2 / 4 = 0.5000 (replacing old buggy 2/3 candidate tag ratio).
  const scored = matcher.score('connect to postgres database instance', candidate);
  assert.equal(scored.breakdown.tagMatch, 0.5000);
  assert.deepEqual(scored.breakdown.matchedTags, ['postgres', 'database']);
  // Tag weight: 0.30 * 0.5000 = 0.1500
  assert.equal(scored.score, 0.1500);
});

test('RelevanceMatcher - Phase 4D.2A: richly tagged memories are not penalized vs sparsely tagged memories', () => {
  const matcher = new RelevanceMatcher();

  const sparseCandidate = createMockMemory({
    id: 'mem-sparse',
    key: 'unrelated.key.sparse',
    tagsJson: '["database"]',
    content: 'Nothing overlapping here.'
  });

  const richCandidate = createMockMemory({
    id: 'mem-rich',
    key: 'unrelated.key.rich',
    tagsJson: '["postgres", "database", "sql", "rdbms", "storage", "backend", "cluster", "replication", "migrations", "acid"]',
    content: 'Nothing overlapping here.'
  });

  const query = 'connect to postgres database';
  // Query non-stop tokens: ['connect', 'postgres', 'database'] (size 3)

  const sparseScore = matcher.score(query, sparseCandidate);
  const richScore = matcher.score(query, richCandidate);

  // Sparse matches 1 tag ('database') -> coverage: 1 / 3 = 0.3333
  assert.equal(sparseScore.breakdown.tagMatch, 0.3333);
  assert.deepEqual(sparseScore.breakdown.matchedTags, ['database']);

  // Rich matches 2 tags ('postgres', 'database') -> coverage: 2 / 3 = 0.6667
  assert.equal(richScore.breakdown.tagMatch, 0.6667);
  assert.deepEqual(richScore.breakdown.matchedTags, ['postgres', 'database']);

  // Acceptance Test 1: Rich candidate matching 2 query terms MUST NOT score below sparse candidate matching 1!
  assert.ok(
    richScore.breakdown.tagMatch > sparseScore.breakdown.tagMatch,
    `Rich tag score (${richScore.breakdown.tagMatch}) must exceed sparse tag score (${sparseScore.breakdown.tagMatch})`
  );
  assert.ok(richScore.score > sparseScore.score);
});

test('RelevanceMatcher - Phase 4D.2A: adding unrelated tags to candidate never reduces tag score', () => {
  const matcher = new RelevanceMatcher();

  const baselineCandidate = createMockMemory({
    key: 'unrelated.key',
    tagsJson: '["docker", "container"]',
    content: 'Nothing here.'
  });

  const augmentedCandidate = createMockMemory({
    key: 'unrelated.key',
    tagsJson: '["docker", "container", "unrelated1", "unrelated2", "unrelated3", "noise", "metadata", "extra"]',
    content: 'Nothing here.'
  });

  const query = 'docker container deployment';
  const scoreBase = matcher.score(query, baselineCandidate);
  const scoreAugmented = matcher.score(query, augmentedCandidate);

  // Acceptance Test 2: Adding 6 unrelated tags must NOT reduce the tag score!
  assert.equal(scoreBase.breakdown.tagMatch, scoreAugmented.breakdown.tagMatch);
  assert.equal(scoreBase.score, scoreAugmented.score);
});

test('RelevanceMatcher - Phase 4D.2A: adding relevant matching tags strictly increases or saturates tag score', () => {
  const matcher = new RelevanceMatcher();

  const cand1 = createMockMemory({
    key: 'unrelated.key',
    tagsJson: '["docker"]',
    content: 'Nothing here.'
  });

  const cand2 = createMockMemory({
    key: 'unrelated.key',
    tagsJson: '["docker", "container"]',
    content: 'Nothing here.'
  });

  const cand3 = createMockMemory({
    key: 'unrelated.key',
    tagsJson: '["docker", "container", "deployment"]',
    content: 'Nothing here.'
  });

  const query = 'docker container deployment';
  // Query non-stop tokens: ['docker', 'container', 'deployment'] (size 3)

  const s1 = matcher.score(query, cand1);
  const s2 = matcher.score(query, cand2);
  const s3 = matcher.score(query, cand3);

  // Acceptance Test 3: Monotonically increasing score with additional matching tags
  assert.equal(s1.breakdown.tagMatch, 0.3333); // 1 / 3
  assert.equal(s2.breakdown.tagMatch, 0.6667); // 2 / 3
  assert.equal(s3.breakdown.tagMatch, 1.0000); // 3 / 3
  assert.ok(s1.breakdown.tagMatch < s2.breakdown.tagMatch);
  assert.ok(s2.breakdown.tagMatch < s3.breakdown.tagMatch);
});

test('RelevanceMatcher - Phase 4D.2A: empty tags, empty queries, and malformed tags never cause division by zero', () => {
  const matcher = new RelevanceMatcher();

  const emptyCandidate = createMockMemory({ tagsJson: '[]', content: 'content' });
  const malformedCandidate = createMockMemory({ tagsJson: '{malformed json}', content: 'content' });
  const nonArrayCandidate = createMockMemory({ tagsJson: '"string-not-array"', content: 'content' });

  // Empty query
  const resEmptyQuery = matcher.score('', emptyCandidate);
  assert.equal(resEmptyQuery.breakdown.tagMatch, 0.0);
  assert.equal(resEmptyQuery.score, 0.0);

  // Stop-word-only query
  const resStopOnly = matcher.score('what is the and or', emptyCandidate);
  assert.equal(resStopOnly.breakdown.tagMatch, 0.0);

  // Empty tags on candidate
  const resEmptyTags = matcher.score('docker container', emptyCandidate);
  assert.equal(resEmptyTags.breakdown.tagMatch, 0.0);

  // Malformed JSON tags
  const resMalformed = matcher.score('docker container', malformedCandidate);
  assert.equal(resMalformed.breakdown.tagMatch, 0.0);

  // Non-array JSON tags
  const resNonArray = matcher.score('docker container', nonArrayCandidate);
  assert.equal(resNonArray.breakdown.tagMatch, 0.0);
});

test('RelevanceMatcher - Phase 4D.2A.1: query token tag coverage regression tests', () => {
  const matcher = new RelevanceMatcher();
  const query = 'connect to postgres database';
  // Non-stop query tokens: ['connect', 'postgres', 'database'] (size 3)

  // 1. Query "connect to postgres database" with tag ["postgres database"] scores 0.6667
  const candMultiwordPhrase = createMockMemory({
    tagsJson: '["postgres database"]',
    content: 'Unrelated body text'
  });
  const resMultiwordPhrase = matcher.score(query, candMultiwordPhrase);
  assert.equal(resMultiwordPhrase.breakdown.tagMatch, 0.6667);
  assert.deepEqual(resMultiwordPhrase.breakdown.matchedTags, ['postgres database']);

  // 2. The same query with tags ["postgres", "database"] also scores 0.6667
  const candSeparateTags = createMockMemory({
    tagsJson: '["postgres", "database"]',
    content: 'Unrelated body text'
  });
  const resSeparateTags = matcher.score(query, candSeparateTags);
  assert.equal(resSeparateTags.breakdown.tagMatch, 0.6667);
  assert.deepEqual(resSeparateTags.breakdown.matchedTags, ['postgres', 'database']);

  // 3. Tag ["connect to postgres database"] scores 1.0
  const candFullPhrase = createMockMemory({
    tagsJson: '["connect to postgres database"]',
    content: 'Unrelated body text'
  });
  const resFullPhrase = matcher.score(query, candFullPhrase);
  assert.equal(resFullPhrase.breakdown.tagMatch, 1.0000);
  assert.deepEqual(resFullPhrase.breakdown.matchedTags, ['connect to postgres database']);

  // 4. Adding unrelated tags does not reduce the score
  const candWithUnrelated = createMockMemory({
    tagsJson: '["postgres", "database", "unrelated1", "noise_tag", "random"]',
    content: 'Unrelated body text'
  });
  const resWithUnrelated = matcher.score(query, candWithUnrelated);
  assert.equal(resWithUnrelated.breakdown.tagMatch, 0.6667);

  // 5. Duplicate tags and duplicate words do not inflate the score
  const candDuplicateTags = createMockMemory({
    tagsJson: '["postgres", "postgres", "database", "database"]',
    content: 'Unrelated body text'
  });
  const resDuplicateTags = matcher.score(query, candDuplicateTags);
  assert.equal(resDuplicateTags.breakdown.tagMatch, 0.6667);

  const candDuplicateWords = createMockMemory({
    tagsJson: '["postgres postgres", "database database"]',
    content: 'Unrelated body text'
  });
  const resDuplicateWords = matcher.score(query, candDuplicateWords);
  assert.equal(resDuplicateWords.breakdown.tagMatch, 0.6667);

  // 6. Tag ["to"] scores zero for the query above
  const candStopWordTag = createMockMemory({
    tagsJson: '["to"]',
    content: 'Unrelated body text'
  });
  const resStopWordTag = matcher.score(query, candStopWordTag);
  assert.equal(resStopWordTag.breakdown.tagMatch, 0.0);
  assert.deepEqual(resStopWordTag.breakdown.matchedTags, []);

  // 7. Case and punctuation variations normalize consistently
  const candCasePunct = createMockMemory({
    tagsJson: '["  POSTGRES  ", "DATABASE!!!", "Connect."]',
    content: 'Unrelated body text'
  });
  const resCasePunct = matcher.score(query, candCasePunct);
  assert.equal(resCasePunct.breakdown.tagMatch, 1.0000);

  // 8. Hyphenated and underscored tags cover their constituent query tokens
  const candHyphenated = createMockMemory({
    tagsJson: '["postgres-database"]',
    content: 'Unrelated body text'
  });
  const resHyphenated = matcher.score(query, candHyphenated);
  assert.equal(resHyphenated.breakdown.tagMatch, 0.6667);

  const candUnderscored = createMockMemory({
    tagsJson: '["postgres_database"]',
    content: 'Unrelated body text'
  });
  const resUnderscored = matcher.score(query, candUnderscored);
  assert.equal(resUnderscored.breakdown.tagMatch, 0.6667);

  const candPartialHyphen = createMockMemory({
    tagsJson: '["postgres-db"]',
    content: 'Unrelated body text'
  });
  const resPartialHyphen = matcher.score(query, candPartialHyphen);
  // 'postgres' covers 1 query token out of 3 = 1 / 3 = 0.3333
  assert.equal(resPartialHyphen.breakdown.tagMatch, 0.3333);

  // 9. Empty and stop-word-only queries safely return zero
  assert.equal(matcher.score('', candSeparateTags).breakdown.tagMatch, 0.0);
  assert.equal(matcher.score('   ', candSeparateTags).breakdown.tagMatch, 0.0);
  assert.equal(matcher.score('to and the or in at', candSeparateTags).breakdown.tagMatch, 0.0);
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

test('RelevanceMatcher - regression: bounded phrase matching prevents partial-word false positives for keys', () => {
  const matcher = new RelevanceMatcher();

  const candidateKey = 'docker.build.target';
  const candidate = createMockMemory({
    key: candidateKey,
    tagsJson: '[]',
    content: 'Unrelated content payload here.'
  });

  // 1. Valid bounded phrase match in query -> keyMatch === 1.0
  const validQueries = [
    'Inspect the docker.build.target configuration',
    'docker.build.target',
    'Please run (docker.build.target) right now',
    'Check "docker.build.target" value',
    'Use docker.build.target:latest image',
    'docker.build.target.'
  ];

  for (const q of validQueries) {
    const scored = matcher.score(q, candidate);
    assert.equal(
      scored.breakdown.keyMatch,
      1.0,
      `Expected keyMatch 1.0 for valid phrase in query: "${q}"`
    );
    assert.equal(scored.breakdown.keyMatched, true);
  }

  // 2. Embedded in longer alphanumeric words -> MUST NOT match as full key phrase
  const embeddedQueries = [
    'run mydocker.build.target now',       // preceded by 'm' in longer alphanumeric word 'mydocker'
    'run docker.build.targets now',         // followed by 's' in longer alphanumeric word 'targets'
    'run mydocker.build.targets now',       // both sides embedded in longer alphanumeric words
    'run querywithdocker.build.targetembedded' // completely embedded in longer alphanumeric words
  ];

  for (const q of embeddedQueries) {
    const scored = matcher.score(q, candidate);
    assert.notEqual(
      scored.breakdown.keyMatch,
      1.0,
      `Expected keyMatch < 1.0 (not a full bounded match) for embedded query: "${q}"`
    );
  }

  // 3. Single-token key test (e.g. key: 'target')
  const singleTokenMem = createMockMemory({
    key: 'target',
    tagsJson: '[]',
    content: 'Unrelated body text.'
  });

  // "targets" must NOT match "target"
  const scoredEmbeddedWord = matcher.score('Check the multiple targets in production', singleTokenMem);
  assert.equal(scoredEmbeddedWord.breakdown.keyMatch, 0.0);
  assert.equal(scoredEmbeddedWord.breakdown.keyMatched, false);

  // Exact word "target" must match "target"
  const scoredExactWord = matcher.score('Check the single target in production', singleTokenMem);
  assert.equal(scoredExactWord.breakdown.keyMatch, 1.0);
  assert.equal(scoredExactWord.breakdown.keyMatched, true);
});

test('RelevanceMatcher - regression: bounded phrase matching prevents partial-word false positives for tags (database vs databases)', () => {
  const matcher = new RelevanceMatcher();

  const memSingular = createMockMemory({
    key: 'unrelated.key.1',
    tagsJson: '["database"]',
    content: 'Unrelated text here.'
  });

  const memPlural = createMockMemory({
    key: 'unrelated.key.2',
    tagsJson: '["databases"]',
    content: 'Unrelated text here.'
  });

  // Query: "we need multiple databases"
  // Must match memPlural ('databases') with tagMatch 1.0
  // Must NOT match memSingular ('database') merely because "database" is a substring of "databases"
  const scoredPluralQueryOnSingular = matcher.score('we need multiple databases', memSingular);
  assert.equal(
    scoredPluralQueryOnSingular.breakdown.tagMatch,
    0.0,
    'Tag "database" must not match query "we need multiple databases"'
  );
  assert.deepEqual(scoredPluralQueryOnSingular.breakdown.matchedTags, []);

  const scoredPluralQueryOnPlural = matcher.score('we need multiple databases', memPlural);
  // Phase 4D.2A: Query tokens are ['need', 'multiple', 'databases'] (size 3). 1 matched tag yields 1/3 = 0.3333.
  assert.equal(scoredPluralQueryOnPlural.breakdown.tagMatch, 0.3333);
  assert.deepEqual(scoredPluralQueryOnPlural.breakdown.matchedTags, ['databases']);

  // Query: "connect to database"
  // Must match memSingular ('database') with tagMatch > 0
  // Must NOT match memPlural ('databases')
  const scoredSingularQueryOnSingular = matcher.score('connect to database', memSingular);
  // Phase 4D.2A: Query tokens are ['connect', 'database'] (size 2). 1 matched tag yields 1/2 = 0.5000.
  assert.equal(scoredSingularQueryOnSingular.breakdown.tagMatch, 0.5000);
  assert.deepEqual(scoredSingularQueryOnSingular.breakdown.matchedTags, ['database']);

  const scoredSingularQueryOnPlural = matcher.score('connect to database', memPlural);
  assert.equal(scoredSingularQueryOnPlural.breakdown.tagMatch, 0.0);
  assert.deepEqual(scoredSingularQueryOnPlural.breakdown.matchedTags, []);
});

test('RelevanceMatcher - preserves legitimate multiword and punctuation-separated tag matches', () => {
  const matcher = new RelevanceMatcher();

  const memMultiword = createMockMemory({
    key: 'unrelated.key.3',
    tagsJson: '["cloud infra", "postgres-db"]',
    content: 'Unrelated text here.'
  });

  // Multiword tag "cloud infra" matches when present as bounded phrase
  const scoredMultiword = matcher.score('deploy services on cloud infra today', memMultiword);
  assert.ok(scoredMultiword.breakdown.matchedTags.includes('cloud infra'));

  // Multiword tag "cloud infra" does NOT match inside "cloud infrastructure"
  const scoredEmbeddedMultiword = matcher.score('deploy services on cloud infrastructure today', memMultiword);
  assert.ok(!scoredEmbeddedMultiword.breakdown.matchedTags.includes('cloud infra'));

  // Punctuation-separated tag "postgres-db" matches when properly bounded
  const scoredPunct = matcher.score('connect to (postgres-db); now', memMultiword);
  assert.ok(scoredPunct.breakdown.matchedTags.includes('postgres-db'));

  // Punctuation-separated tag does not match when prefixed with alphanumeric
  const scoredPrefixed = matcher.score('connect to mypostgres-db now', memMultiword);
  assert.ok(!scoredPrefixed.breakdown.matchedTags.includes('postgres-db'));
});

test('RelevanceMatcher - validates scoring configuration and rejects invalid weights', () => {
  // 1. Valid custom configurations summing to 1.0
  const valid1 = new RelevanceMatcher({ keyWeight: 0.40, tagWeight: 0.40, wordWeight: 0.20 });
  assert.equal(valid1.keyWeight, 0.40);
  assert.equal(valid1.tagWeight, 0.40);
  assert.equal(valid1.wordWeight, 0.20);

  const valid2 = new RelevanceMatcher({ keyWeight: 1.0, tagWeight: 0.0, wordWeight: 0.0 });
  assert.equal(valid2.keyWeight, 1.0);
  assert.equal(valid2.tagWeight, 0.0);
  assert.equal(valid2.wordWeight, 0.0);

  // Minor floating point tolerance test
  const valid3 = new RelevanceMatcher({ keyWeight: 0.33333, tagWeight: 0.33333, wordWeight: 0.33334 });
  assert.ok(valid3);

  // 2. Negative weight rejection
  assert.throws(
    () => new RelevanceMatcher({ keyWeight: -0.1, tagWeight: 0.6, wordWeight: 0.5 }),
    (err: unknown) => err instanceof ValidationError && /finite, non-negative/.test((err as Error).message)
  );

  assert.throws(
    () => new RelevanceMatcher({ keyWeight: 0.5, tagWeight: -0.2, wordWeight: 0.7 }),
    (err: unknown) => err instanceof ValidationError && /finite, non-negative/.test((err as Error).message)
  );

  assert.throws(
    () => new RelevanceMatcher({ keyWeight: 0.5, tagWeight: 0.6, wordWeight: -0.1 }),
    (err: unknown) => err instanceof ValidationError && /finite, non-negative/.test((err as Error).message)
  );

  // 3. NaN weight rejection
  assert.throws(
    () => new RelevanceMatcher({ keyWeight: NaN, tagWeight: 0.5, wordWeight: 0.5 }),
    (err: unknown) => err instanceof ValidationError && /finite, non-negative/.test((err as Error).message)
  );

  // 4. Infinite weight rejection
  assert.throws(
    () => new RelevanceMatcher({ keyWeight: Infinity, tagWeight: 0.5, wordWeight: 0.5 }),
    (err: unknown) => err instanceof ValidationError && /finite, non-negative/.test((err as Error).message)
  );

  assert.throws(
    () => new RelevanceMatcher({ keyWeight: 0.5, tagWeight: -Infinity, wordWeight: 0.5 }),
    (err: unknown) => err instanceof ValidationError && /finite, non-negative/.test((err as Error).message)
  );

  // 5. Non-normalized weights rejection (sum != 1.0)
  assert.throws(
    () => new RelevanceMatcher({ keyWeight: 0.8, tagWeight: 0.5, wordWeight: 0.2 }),
    (err: unknown) => err instanceof ValidationError && /must sum to 1.0/.test((err as Error).message)
  );

  assert.throws(
    () => new RelevanceMatcher({ keyWeight: 0.1, tagWeight: 0.1, wordWeight: 0.1 }),
    (err: unknown) => err instanceof ValidationError && /must sum to 1.0/.test((err as Error).message)
  );

  assert.throws(
    () => new RelevanceMatcher({ keyWeight: 0.0, tagWeight: 0.0, wordWeight: 0.0 }),
    (err: unknown) => err instanceof ValidationError && /must sum to 1.0/.test((err as Error).message)
  );
});

