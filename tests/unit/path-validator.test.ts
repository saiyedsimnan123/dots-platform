/**
 * Next-Generation Dots AI Platform - Path Validator Unit Tests
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { resolve, join } from 'node:path';
import { existsSync, rmSync, mkdirSync, symlinkSync } from 'node:fs';
import { PathValidator } from '../../src/security/path-validator.ts';
import { SecurityViolationError } from '../../src/domain/errors.ts';

const testRoot = resolve('test_path_val_root');
const siblingRoot = resolve('test_path_val_root_sibling');
const externalTarget = resolve('test_path_val_external');

function setupDirs() {
  cleanupDirs();
  mkdirSync(testRoot, { recursive: true });
  mkdirSync(siblingRoot, { recursive: true });
  mkdirSync(externalTarget, { recursive: true });
}

function cleanupDirs() {
  if (existsSync(testRoot)) rmSync(testRoot, { recursive: true, force: true });
  if (existsSync(siblingRoot)) rmSync(siblingRoot, { recursive: true, force: true });
  if (existsSync(externalTarget)) rmSync(externalTarget, { recursive: true, force: true });
}

test('PathValidator - permits valid paths and nested subdirectories within workspace', () => {
  setupDirs();
  try {
    const validRelative = 'subdir/file.txt';
    const canonical = PathValidator.assertContained(validRelative, testRoot);
    assert.equal(canonical, resolve(testRoot, 'subdir/file.txt'));

    const validAbsolute = resolve(testRoot, 'nested/deep/file.json');
    const canonicalAbs = PathValidator.assertContained(validAbsolute, testRoot);
    assert.equal(canonicalAbs, validAbsolute);
  } finally {
    cleanupDirs();
  }
});

test('PathValidator - strictly rejects directory traversal attacks', () => {
  setupDirs();
  try {
    const attacks = [
      '../escape.txt',
      '../../escape.txt',
      'subdir/../../escape.txt',
      'subdir/nested/../../../escape.txt'
    ];

    for (const attack of attacks) {
      assert.throws(
        () => PathValidator.assertContained(attack, testRoot),
        (err: unknown) => {
          assert.ok(err instanceof SecurityViolationError);
          return true;
        }
      );
    }
  } finally {
    cleanupDirs();
  }
});

test('PathValidator - rejects sibling prefix directory spoofing', () => {
  setupDirs();
  try {
    // Sibling directory with identical prefix (test_path_val_root_sibling vs test_path_val_root)
    const siblingFile = join(siblingRoot, 'evil.txt');

    assert.throws(
      () => PathValidator.assertContained(siblingFile, testRoot),
      (err: unknown) => {
        assert.ok(err instanceof SecurityViolationError);
        return true;
      }
    );

    const check = PathValidator.checkContained(siblingFile, testRoot);
    assert.equal(check.isContained, false);
    assert.ok(check.violationReason?.includes('sibling prefix') || check.violationReason?.includes('Path traversal'));
  } finally {
    cleanupDirs();
  }
});

test('PathValidator - rejects absolute external system paths', () => {
  setupDirs();
  try {
    const externalPaths = [
      'C:\\Windows\\System32\\cmd.exe',
      'C:\\Windows\\notepad.exe',
      '/etc/passwd',
      '/var/log/syslog'
    ];

    for (const ext of externalPaths) {
      const check = PathValidator.checkContained(ext, testRoot);
      assert.equal(check.isContained, false);
    }
  } finally {
    cleanupDirs();
  }
});

test('PathValidator - rejects null byte injection in paths', () => {
  setupDirs();
  try {
    const check = PathValidator.checkContained('safe_file.txt\0evil.bat', testRoot);
    assert.equal(check.isContained, false);
    assert.ok(check.violationReason?.includes('null byte'));
  } finally {
    cleanupDirs();
  }
});

test('PathValidator - detects symlink escapes pointing outside workspace', () => {
  setupDirs();
  try {
    const linkPath = join(testRoot, 'external_symlink');
    let symlinkCreated = false;
    try {
      symlinkSync(externalTarget, linkPath, 'junction');
      symlinkCreated = true;
    } catch {
      // Non-admin windows or unsupported environment
    }

    if (symlinkCreated) {
      const escapedFile = join(linkPath, 'stolen.txt');
      const check = PathValidator.checkContained(escapedFile, testRoot);
      assert.equal(check.isContained, false);
      assert.ok(check.violationReason?.includes('Symlink') || check.violationReason?.includes('escapes'));
    }
  } finally {
    cleanupDirs();
  }
});
