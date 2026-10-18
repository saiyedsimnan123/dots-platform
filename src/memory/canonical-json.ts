/**
 * Next-Generation Dots AI Platform - Canonical JSON & Integrity Hasher
 * Phase 7.5: Substep 1
 * 
 * Architectural Mandate:
 * Implements deterministic canonical JSON serialization following RFC 8785
 * (JSON Canonicalization Scheme / JCS) principles and SHA-256 integrity checksums
 * without third-party dependencies.
 * 
 * Guarantees:
 * 1. Whitespace: Zero whitespace outside string literals.
 * 2. Key Ordering: Object properties sorted lexicographically by UTF-16 code unit values.
 * 3. Number Serialization: Strictly compliant with ECMAScript 6 ToString applied to numbers;
 *    -0 is serialized as 0; NaN, Infinity, and -Infinity are rejected with ValidationError.
 * 4. Strings: Control characters U+0000..U+001F escaped using short escapes or lowercase \u00xx;
 *    unpaired lone surrogates are rejected with ValidationError; UTF-8 characters are preserved verbatim.
 * 5. Structural Determinism: Unordered properties and maps produce byte-for-byte identical output.
 * 6. Cycle Detection: Circular object structures are rejected with ValidationError.
 * 7. Integrity: SHA-256 hash serves as a corruption/tampering check across environments.
 */

import { createHash } from 'node:crypto';
import { ValidationError } from '../domain/errors.ts';
import type { MemoryExportBundle } from '../domain/types.ts';

/**
 * Checks whether a string contains any unpaired lone surrogates.
 * Conforming RFC 8785 JSON text must not contain lone surrogates.
 */
function containsLoneSurrogate(str: string): boolean {
  for (let i = 0; i < str.length; i++) {
    const code = str.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      if (i + 1 >= str.length) {
        return true;
      }
      const next = str.charCodeAt(i + 1);
      if (next < 0xdc00 || next > 0xdfff) {
        return true;
      }
      i++; // Valid surrogate pair
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return true;
    }
  }
  return false;
}

/**
 * Internal recursive stringifier tracking visited objects for cycle detection.
 */
function stringifyValue(val: unknown, seen: WeakSet<object>): string | undefined {
  // 1. Handle toJSON() if present (e.g. Date)
  let currentVal = val;
  if (
    currentVal !== null &&
    (typeof currentVal === 'object' || typeof currentVal === 'function') &&
    typeof (currentVal as { toJSON?: unknown }).toJSON === 'function'
  ) {
    currentVal = (currentVal as { toJSON: () => unknown }).toJSON();
  }

  // 2. Primitives
  if (currentVal === null) {
    return 'null';
  }

  const type = typeof currentVal;

  if (type === 'boolean') {
    return currentVal ? 'true' : 'false';
  }

  if (type === 'number') {
    const num = currentVal as number;
    if (!Number.isFinite(num)) {
      throw new ValidationError(
        `Cannot serialize non-finite number '${num}' to canonical JSON.`
      );
    }
    // RFC 8785: -0 must be serialized as 0
    if (Object.is(num, -0)) {
      return '0';
    }
    return JSON.stringify(num);
  }

  if (type === 'string') {
    const str = currentVal as string;
    if (containsLoneSurrogate(str)) {
      throw new ValidationError(
        'Cannot serialize string containing lone surrogates to canonical JSON.'
      );
    }
    return JSON.stringify(str);
  }

  if (type === 'bigint') {
    throw new ValidationError('BigInt is not supported in canonical JSON serialization.');
  }

  if (type === 'undefined' || type === 'function' || type === 'symbol') {
    return undefined;
  }

  // 3. Arrays
  if (Array.isArray(currentVal)) {
    if (seen.has(currentVal)) {
      throw new ValidationError('Cannot serialize cyclic object to canonical JSON.');
    }
    seen.add(currentVal);
    try {
      const elements: string[] = [];
      for (let i = 0; i < currentVal.length; i++) {
        const item = currentVal[i];
        const serialized = stringifyValue(item, seen);
        elements.push(serialized === undefined ? 'null' : serialized);
      }
      return `[${elements.join(',')}]`;
    } finally {
      seen.delete(currentVal);
    }
  }

  // 4. Objects
  if (type === 'object') {
    const obj = currentVal as Record<string, unknown>;
    if (seen.has(obj)) {
      throw new ValidationError('Cannot serialize cyclic object to canonical JSON.');
    }
    seen.add(obj);
    try {
      // RFC 8785: Object keys sorted lexicographically by UTF-16 code units
      const keys = Object.keys(obj).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
      const entries: string[] = [];

      for (const key of keys) {
        if (containsLoneSurrogate(key)) {
          throw new ValidationError(
            `Cannot serialize object key containing lone surrogates: '${key}'.`
          );
        }
        const propVal = obj[key];
        if (
          propVal === undefined ||
          typeof propVal === 'function' ||
          typeof propVal === 'symbol'
        ) {
          continue; // Omit undefined, function, symbol properties
        }
        const serializedProp = stringifyValue(propVal, seen);
        if (serializedProp !== undefined) {
          entries.push(`${JSON.stringify(key)}:${serializedProp}`);
        }
      }

      return `{${entries.join(',')}}`;
    } finally {
      seen.delete(obj);
    }
  }

  throw new ValidationError(`Unsupported type for canonical JSON: ${type}`);
}

/**
 * Serializes a JavaScript value to deterministic canonical JSON (RFC 8785 compliant).
 * 
 * Returns undefined if the top-level value is undefined, function, or symbol.
 */
export function canonicalJsonStringify(val: unknown): string | undefined {
  const seen = new WeakSet<object>();
  return stringifyValue(val, seen);
}

/**
 * Computes a deterministic SHA-256 digest of any value using canonical JSON serialization.
 */
export function computeCanonicalSha256(val: unknown): string {
  const canonical = canonicalJsonStringify(val);
  if (canonical === undefined) {
    throw new ValidationError('Cannot compute canonical SHA-256 for undefined value.');
  }
  return createHash('sha256').update(canonical, 'utf8').digest('hex');
}

/**
 * Verifies that a memory export bundle's SHA-256 checksum accurately reflects its canonical payload.
 * 
 * Note: The SHA-256 checksum serves as an integrity and anti-corruption check across transfer
 * and persistence. It does not prove cryptographic author authenticity without host signing.
 */
export function verifyBundleChecksum(bundle: MemoryExportBundle): boolean {
  if (!bundle || typeof bundle !== 'object') {
    return false;
  }
  if (typeof bundle.checksum !== 'string' || bundle.checksum.trim() === '') {
    return false;
  }

  const { checksum, ...payload } = bundle;
  try {
    const expected = computeCanonicalSha256(payload);
    return checksum === expected;
  } catch {
    return false;
  }
}
