/**
 * Next-Generation Dots AI Platform - Secret Scrubber Unit Tests
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { SecretScrubber, defaultSecretScrubber } from '../../src/model/secret-scrubber.ts';

test('SecretScrubber - redacts Google AI API keys', () => {
  const text = 'Using key AIzaSyD1234567890abcdefghijklmnopqrstuv to connect';
  const scrubbed = defaultSecretScrubber.scrub(text);
  assert.equal(scrubbed, 'Using key [REDACTED_GOOGLE_API_KEY] to connect');
  assert.equal(defaultSecretScrubber.containsSecret(text), true);
});

test('SecretScrubber - redacts OpenAI API keys', () => {
  const text = 'Authorization: sk-abc1234567890def1234567890ghij';
  const scrubbed = defaultSecretScrubber.scrub(text);
  assert.equal(scrubbed, 'Authorization: [REDACTED_OPENAI_API_KEY]');
  assert.equal(defaultSecretScrubber.containsSecret(text), true);
});

test('SecretScrubber - redacts Anthropic API keys', () => {
  const text = 'x-api-key: sk-ant-api03-abcdef1234567890abcdef1234567890';
  const scrubbed = defaultSecretScrubber.scrub(text);
  assert.equal(scrubbed, 'x-api-key: [REDACTED_ANTHROPIC_API_KEY]');
  assert.equal(defaultSecretScrubber.containsSecret(text), true);
});

test('SecretScrubber - redacts Bearer authorization tokens', () => {
  const text = 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.signature';
  const scrubbed = defaultSecretScrubber.scrub(text);
  assert.equal(scrubbed, 'Authorization: Bearer [REDACTED_TOKEN]');
});

test('SecretScrubber - redacts private key blocks', () => {
  const text = 'Config:\n-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----\nDone';
  const scrubbed = defaultSecretScrubber.scrub(text);
  assert.equal(scrubbed, 'Config:\n[REDACTED_PRIVATE_KEY]\nDone');
});

test('SecretScrubber - allows clean text without modification', () => {
  const clean = 'This is a normal goal: create a file named report.txt and save 100 bytes.';
  assert.equal(defaultSecretScrubber.scrub(clean), clean);
  assert.equal(defaultSecretScrubber.containsSecret(clean), false);
});

test('SecretScrubber - supports registering custom patterns', () => {
  const scrubber = new SecretScrubber();
  scrubber.addPattern({
    name: 'Custom Secret',
    regex: /SECRET_[A-Z0-9]{8}/g,
    replacement: '[REDACTED_CUSTOM]'
  });

  const text = 'Found secret SECRET_1234ABCD in config';
  assert.equal(scrubber.scrub(text), 'Found secret [REDACTED_CUSTOM] in config');
  assert.equal(scrubber.containsSecret(text), true);
});
