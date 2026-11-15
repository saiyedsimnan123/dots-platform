/**
 * Next-Generation Dots AI Platform - Deterministic Mock Embedding Provider
 * Phase 4C.2: Embedding Provider Interface and Deterministic Test Provider
 * 
 * Architectural Mandate:
 * Enables 100% offline, zero-cost, deterministic testing of vector embeddings and semantic
 * retrieval pipelines without contacting external cloud endpoints or downloading large models.
 * 
 * Guarantees:
 * 1. Deterministic & Repeatable: Identical input strings always produce identical vectors.
 * 2. Contract Compliance: All output vectors are unit-normalized (L2 norm = 1.0) Float32Array instances.
 * 3. Batch Consistency: embedBatch() produces results identical to sequential embed() calls.
 * 4. Controlled Semantics: Supports registering predefined vectors for specific text inputs
 *    to enable reliable, predictable semantic similarity test cases (orthogonal, similar, opposite).
 * 5. Simulation Hooks: Supports configurable unavailability, queued errors, and cancellation checks.
 * 
 * IMPORTANT NOTICE:
 * Mock vectors generated from text hashes are pseudo-random and DO NOT understand semantic
 * meaning or natural language intent. Similar phrases (e.g. "car" and "automobile") will NOT
 * have high similarity by default unless explicitly configured via registerPredefinedVector().
 * This mock provider is strictly for testing and validation, NOT for production semantic search.
 */

import { createHash } from 'node:crypto';
import type { IEmbeddingProvider, EmbeddingOptions } from './embedding-types.ts';
import { MAX_EMBEDDING_TEXT_LENGTH, MAX_EMBEDDING_BATCH_SIZE } from './embedding-types.ts';
import {
  ValidationError,
  EmbeddingProviderUnavailableError,
  AgentCancelledError
} from '../domain/errors.ts';
import {
  validateVector,
  normalizeVector,
  cloneVector
} from './vector-utils.ts';

export interface RecordedEmbeddingCall {
  readonly method: 'embed' | 'embedBatch';
  readonly texts: readonly string[];
  readonly timestamp: string;
}

export interface MockEmbeddingProviderOptions {
  readonly name?: string;
  readonly modelId?: string;
  readonly dimensions?: number;
  readonly available?: boolean;
}

export class DeterministicMockEmbeddingProvider implements IEmbeddingProvider {
  public readonly name: string;
  public readonly modelId: string;
  public readonly dimensions: number;

  private _available: boolean;
  private readonly predefinedVectors = new Map<string, Float32Array>();
  private readonly failureQueue: Error[] = [];
  private simulatedFailure: Error | null = null;
  private readonly recordedCalls: RecordedEmbeddingCall[] = [];

  constructor(options: MockEmbeddingProviderOptions = {}) {
    this.name = options.name ?? 'mock-embedding-provider';
    this.modelId = options.modelId ?? 'mock-deterministic-v1';
    this.dimensions = options.dimensions ?? 384;
    this._available = options.available ?? true;

    if (!Number.isInteger(this.dimensions) || this.dimensions <= 0) {
      throw new ValidationError(`Embedding dimensions must be a positive integer, received '${String(this.dimensions)}'.`);
    }
  }

  /**
   * Reports whether the mock provider is available.
   */
  public async isAvailable(): Promise<boolean> {
    return this._available;
  }

  /**
   * Toggles the availability state of this provider.
   */
  public setAvailable(available: boolean): void {
    this._available = Boolean(available);
  }

  /**
   * Registers a predefined, controlled vector for a specific input text.
   * Enables exact semantic similarity tests (e.g. known identical, orthogonal, or opposite pairs).
   */
  public registerPredefinedVector(text: string, vector: Float32Array): void {
    if (typeof text !== 'string' || text.trim() === '') {
      throw new ValidationError('Predefined vector text must be a non-empty string.');
    }
    validateVector(vector, this.dimensions, 'Predefined vector');
    // Ensure the registered vector is normalized and stored as a defensive clone
    this.predefinedVectors.set(text.trim(), normalizeVector(vector));
  }

  /**
   * Clears all registered predefined vectors.
   */
  public clearPredefinedVectors(): void {
    this.predefinedVectors.clear();
  }

  /**
   * Enqueues a transient failure to be thrown on the next embed() or embedBatch() invocation.
   */
  public enqueueFailure(error: Error): void {
    this.failureQueue.push(error);
  }

  /**
   * Sets a persistent simulated failure that will be thrown on every call until cleared with null.
   */
  public setSimulatedFailure(error: Error | null): void {
    this.simulatedFailure = error;
  }

  /**
   * Returns a copy of the recorded call history.
   */
  public getRecordedCalls(): readonly RecordedEmbeddingCall[] {
    return [...this.recordedCalls];
  }

  /**
   * Clears recorded call history.
   */
  public clearHistory(): void {
    this.recordedCalls.length = 0;
  }

  /**
   * Generates a deterministic, unit-normalized vector for a single text string.
   */
  public async embed(text: string, options?: EmbeddingOptions): Promise<Float32Array> {
    this.checkCancellation(options?.signal);
    this.checkAvailability();
    this.checkSimulatedFailure();

    this.validateInputText(text);

    this.recordCall('embed', [text]);

    return this.generateVector(text);
  }

  /**
   * Generates deterministic, unit-normalized vectors for a batch of text strings.
   * Results are guaranteed to be identical to calling embed() on each item individually.
   */
  public async embedBatch(texts: readonly string[], options?: EmbeddingOptions): Promise<Float32Array[]> {
    this.checkCancellation(options?.signal);
    this.checkAvailability();
    this.checkSimulatedFailure();

    if (!Array.isArray(texts)) {
      throw new ValidationError('Batch embedding input must be an array of strings.');
    }

    if (texts.length === 0) {
      throw new ValidationError('Batch embedding input array must not be empty.');
    }

    if (texts.length > MAX_EMBEDDING_BATCH_SIZE) {
      throw new ValidationError(
        `Batch size ${texts.length} exceeds maximum allowed limit of ${MAX_EMBEDDING_BATCH_SIZE}.`
      );
    }

    // Pre-validate all texts before processing any embeddings
    for (let i = 0; i < texts.length; i++) {
      this.validateInputText(texts[i], `at index ${i}`);
    }

    this.recordCall('embedBatch', texts);

    const results: Float32Array[] = [];
    for (const text of texts) {
      this.checkCancellation(options?.signal);
      results.push(this.generateVector(text));
    }

    return results;
  }

  /**
   * Generates or retrieves the deterministic normalized vector for the given text.
   */
  private generateVector(text: string): Float32Array {
    const trimmed = text.trim();

    // Check predefined controlled vectors first
    const predefined = this.predefinedVectors.get(trimmed);
    if (predefined) {
      return cloneVector(predefined);
    }

    // Generate deterministic pseudo-random floats using Mulberry32 seeded by SHA-256 of text
    const hash = createHash('sha256').update(trimmed).digest();
    let seed = hash.readUInt32LE(0) ^ hash.readUInt32LE(4) ^ hash.readUInt32LE(8) ^ hash.readUInt32LE(12);
    if (seed === 0) seed = 0x12345678;

    const raw = new Float32Array(this.dimensions);
    for (let i = 0; i < this.dimensions; i++) {
      // Mulberry32 step
      seed = (seed + 0x6d2b79f5) >>> 0;
      let t = seed;
      t = Math.imul(t ^ (t >>> 15), t | 1);
      t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
      const rand = ((t ^ (t >>> 14)) >>> 0) / 4294967296;
      raw[i] = rand * 2.0 - 1.0;
    }

    return normalizeVector(raw);
  }

  private validateInputText(text: unknown, contextDesc?: string): asserts text is string {
    const prefix = contextDesc ? `Embedding input text ${contextDesc}` : 'Embedding input text';

    if (typeof text !== 'string') {
      throw new ValidationError(`${prefix} must be a string.`);
    }

    if (text.trim() === '') {
      throw new ValidationError(`${prefix} must not be empty or whitespace-only.`);
    }

    if (text.length > MAX_EMBEDDING_TEXT_LENGTH) {
      throw new ValidationError(
        `${prefix} exceeds maximum length of ${MAX_EMBEDDING_TEXT_LENGTH} characters (${text.length} > ${MAX_EMBEDDING_TEXT_LENGTH}).`
      );
    }
  }

  private checkCancellation(signal?: AbortSignal): void {
    if (signal?.aborted) {
      const reason = signal.reason ? String(signal.reason) : 'Embedding operation was cancelled.';
      throw new AgentCancelledError(reason);
    }
  }

  private checkAvailability(): void {
    if (!this._available) {
      throw new EmbeddingProviderUnavailableError(this.name);
    }
  }

  private checkSimulatedFailure(): void {
    if (this.simulatedFailure) {
      throw this.simulatedFailure;
    }
    if (this.failureQueue.length > 0) {
      const err = this.failureQueue.shift()!;
      throw err;
    }
  }

  private recordCall(method: 'embed' | 'embedBatch', texts: readonly string[]): void {
    this.recordedCalls.push({
      method,
      texts: [...texts],
      timestamp: new Date().toISOString()
    });
  }
}
