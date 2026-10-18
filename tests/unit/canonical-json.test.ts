/**
 * Next-Generation Dots AI Platform - RFC 8785 Canonical JSON & SHA-256 Tests
 * Phase 7.5: Substep 1
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  canonicalJsonStringify,
  computeCanonicalSha256,
  verifyBundleChecksum
} from '../../src/memory/canonical-json.ts';
import { ValidationError } from '../../src/domain/errors.ts';
import type { MemoryExportBundle } from '../../src/domain/types.ts';

test('canonicalJsonStringify - eliminates whitespace outside string literals', () => {
  const input = {
    title: 'Hello World',
    list: [1, 2, 3],
    nested: {
      active: true,
      count: 0
    }
  };

  const canonical = canonicalJsonStringify(input);
  assert.equal(canonical, '{"list":[1,2,3],"nested":{"active":true,"count":0},"title":"Hello World"}');
});

test('canonicalJsonStringify - sorts object keys by UTF-16 code units (RFC 8785 Section 3.2.3)', () => {
  // 1. Reverse insertion order
  const obj1 = { z: 1, y: 2, x: 3, a: 4 };
  assert.equal(canonicalJsonStringify(obj1), '{"a":4,"x":3,"y":2,"z":1}');

  // 2. Prefix comparison: shorter prefix must come first
  const objPrefix = { foobar: 2, foo: 1 };
  assert.equal(canonicalJsonStringify(objPrefix), '{"foo":1,"foobar":2}');

  // 3. ASCII digit comparison: "10" comes before "2" because '1' (0x31) < '2' (0x32)
  const objDigits = { '2': 'two', '10': 'ten' };
  assert.equal(canonicalJsonStringify(objDigits), '{"10":"ten","2":"two"}');

  // 4. Unicode code-unit order: "z" (0x007A) < "\u00e9" (0x00E9) < "\u20ac" (0x20AC)
  const objUnicode = {
    '\u20ac': 'euro',
    '\u00e9': 'e-acute',
    z: 'ascii-z'
  };
  assert.equal(canonicalJsonStringify(objUnicode), '{"z":"ascii-z","\u00e9":"e-acute","\u20ac":"euro"}');

  // 5. Surrogate pairs: high surrogate 0xD83D comes before private-use 0xE000
  // "\uD83D\uDE00" (😀) has first code unit 0xD83D (55296), which is < 0xE000 (57344)
  const objSurrogates = {
    '\uE000': 'private-use',
    '😀': 'emoji'
  };
  assert.equal(canonicalJsonStringify(objSurrogates), '{"😀":"emoji","\uE000":"private-use"}');
});

test('canonicalJsonStringify - number serialization conforms to RFC 8785 Section 3.2.2.3', () => {
  // -0 serialized as 0
  assert.equal(canonicalJsonStringify(-0), '0');
  assert.equal(canonicalJsonStringify({ val: -0 }), '{"val":0}');
  assert.equal(canonicalJsonStringify([-0, 0]), '[0,0]');

  // Integers and floating point
  assert.equal(canonicalJsonStringify(0), '0');
  assert.equal(canonicalJsonStringify(42), '42');
  assert.equal(canonicalJsonStringify(-100), '-100');
  assert.equal(canonicalJsonStringify(3.14159), '3.14159');
  assert.equal(canonicalJsonStringify(1e21), '1e+21');

  // Non-finite numbers throw ValidationError
  assert.throws(
    () => canonicalJsonStringify(NaN),
    (err: unknown) => err instanceof ValidationError && err.message.includes('non-finite number')
  );
  assert.throws(
    () => canonicalJsonStringify(Infinity),
    (err: unknown) => err instanceof ValidationError && err.message.includes('non-finite number')
  );
  assert.throws(
    () => canonicalJsonStringify(-Infinity),
    (err: unknown) => err instanceof ValidationError && err.message.includes('non-finite number')
  );
});

test('canonicalJsonStringify - string escaping and UTF-8 preservation (RFC 8785 Section 3.2.2.2)', () => {
  // Preserves UTF-8 characters without escaping
  assert.equal(canonicalJsonStringify('Hello 世界 € 🚀'), '"Hello 世界 € 🚀"');

  // Escapes quotes and backslashes
  assert.equal(canonicalJsonStringify('Quote: " and Backslash: \\'), '"Quote: \\" and Backslash: \\\\"');

  // Escapes control characters U+0000 through U+001F
  assert.equal(canonicalJsonStringify('Line1\nLine2\tTab\rReturn\bBackspace\fFormfeed'), '"Line1\\nLine2\\tTab\\rReturn\\bBackspace\\fFormfeed"');
  assert.equal(canonicalJsonStringify('\u0000\u001f'), '"\\u0000\\u001f"');

  // Rejects lone surrogates
  assert.throws(
    () => canonicalJsonStringify('\uD800'),
    (err: unknown) => err instanceof ValidationError && err.message.includes('lone surrogates')
  );
  assert.throws(
    () => canonicalJsonStringify('\uDC00'),
    (err: unknown) => err instanceof ValidationError && err.message.includes('lone surrogates')
  );
  assert.throws(
    () => canonicalJsonStringify('prefix\uD800suffix'),
    (err: unknown) => err instanceof ValidationError && err.message.includes('lone surrogates')
  );
  assert.throws(
    () => canonicalJsonStringify({ '\uD800': 'bad key' }),
    (err: unknown) => err instanceof ValidationError && err.message.includes('lone surrogates')
  );
});

test('canonicalJsonStringify - booleans, null, undefined, functions, and symbols', () => {
  assert.equal(canonicalJsonStringify(true), 'true');
  assert.equal(canonicalJsonStringify(false), 'false');
  assert.equal(canonicalJsonStringify(null), 'null');
  assert.equal(canonicalJsonStringify(undefined), undefined);

  // In objects: undefined, function, symbol are omitted
  const obj = {
    valid: 'yes',
    undef: undefined,
    fn: () => 42,
    sym: Symbol('test')
  };
  assert.equal(canonicalJsonStringify(obj), '{"valid":"yes"}');

  // In arrays: undefined, function, symbol are converted to null
  const arr = ['yes', undefined, () => 42, Symbol('test'), null];
  assert.equal(canonicalJsonStringify(arr), '["yes",null,null,null,null]');
});

test('canonicalJsonStringify - supports toJSON() method on objects', () => {
  const date = new Date('2026-10-19T00:00:00.000Z');
  assert.equal(canonicalJsonStringify({ date }), '{"date":"2026-10-19T00:00:00.000Z"}');

  const custom = {
    hidden: 'secret',
    toJSON() {
      return { exposed: 'data' };
    }
  };
  assert.equal(canonicalJsonStringify(custom), '{"exposed":"data"}');
});

test('canonicalJsonStringify - detects circular references and throws ValidationError', () => {
  const circularObj: Record<string, unknown> = { a: 1 };
  circularObj.self = circularObj;

  assert.throws(
    () => canonicalJsonStringify(circularObj),
    (err: unknown) => err instanceof ValidationError && err.message.includes('cyclic object')
  );

  const circularArr: unknown[] = [1, 2];
  circularArr.push(circularArr);

  assert.throws(
    () => canonicalJsonStringify(circularArr),
    (err: unknown) => err instanceof ValidationError && err.message.includes('cyclic object')
  );
});

test('canonicalJsonStringify - rejects BigInt with ValidationError', () => {
  assert.throws(
    () => canonicalJsonStringify(100n),
    (err: unknown) => err instanceof ValidationError && err.message.includes('BigInt is not supported')
  );
});

test('computeCanonicalSha256 - deterministic digest across key ordering differences', () => {
  const payload1 = {
    b: 'bravo',
    a: 'alpha',
    c: {
      y: 2,
      x: 1
    }
  };

  const payload2 = {
    c: {
      x: 1,
      y: 2
    },
    a: 'alpha',
    b: 'bravo'
  };

  const hash1 = computeCanonicalSha256(payload1);
  const hash2 = computeCanonicalSha256(payload2);

  assert.equal(typeof hash1, 'string');
  assert.equal(hash1.length, 64);
  assert.equal(/^[a-f0-9]{64}$/.test(hash1), true);
  assert.equal(hash1, hash2, 'Identical data with different key insertion order must produce exact same SHA-256');

  // Modified content produces different hash
  const modifiedPayload = { ...payload1, a: 'alpha-modified' };
  const modifiedHash = computeCanonicalSha256(modifiedPayload);
  assert.notEqual(hash1, modifiedHash);
});

test('computeCanonicalSha256 - throws ValidationError for undefined value', () => {
  assert.throws(
    () => computeCanonicalSha256(undefined),
    (err: unknown) => err instanceof ValidationError && err.message.includes('undefined value')
  );
});

test('verifyBundleChecksum - validates authentic checksum and detects corruption/tampering', () => {
  const bundlePayload = {
    version: '1.0' as const,
    exportedAt: '2026-10-19T01:00:00.000Z',
    sourceScope: { scopeType: 'WORKSPACE' as const, scopeId: 'ws-alpha' },
    count: 1,
    memories: [
      {
        key: 'db_host',
        content: 'db.internal.local',
        category: 'PROJECT_FACT' as const,
        tags: ['database'],
        priority: 80,
        metadata: { env: 'prod' },
        status: 'ACTIVE' as const,
        createdAt: '2026-10-19T00:00:00.000Z',
        updatedAt: '2026-10-19T00:00:00.000Z'
      }
    ]
  };

  const checksum = computeCanonicalSha256(bundlePayload);
  const validBundle: MemoryExportBundle = {
    ...bundlePayload,
    checksum
  };

  // Valid bundle passes
  assert.equal(verifyBundleChecksum(validBundle), true);

  // Tampered payload content fails
  const tamperedContentBundle: MemoryExportBundle = {
    ...validBundle,
    memories: [
      {
        ...validBundle.memories[0],
        content: 'malicious.attacker.com'
      }
    ]
  };
  assert.equal(verifyBundleChecksum(tamperedContentBundle), false);

  // Altered count fails
  const tamperedCountBundle: MemoryExportBundle = {
    ...validBundle,
    count: 999
  };
  assert.equal(verifyBundleChecksum(tamperedCountBundle), false);

  // Corrupted checksum fails
  const corruptedChecksumBundle: MemoryExportBundle = {
    ...validBundle,
    checksum: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
  };
  assert.equal(verifyBundleChecksum(corruptedChecksumBundle), false);

  // Invalid bundles fail
  assert.equal(verifyBundleChecksum(null as unknown as MemoryExportBundle), false);
  assert.equal(verifyBundleChecksum({} as unknown as MemoryExportBundle), false);
  assert.equal(verifyBundleChecksum({ ...validBundle, checksum: '' }), false);
});
