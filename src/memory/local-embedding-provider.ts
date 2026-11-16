/**
 * Next-Generation Dots AI Platform - Optional Local Embedding Provider
 * Phase 4C.3: Optional Local Embedding Provider
 * 
 * Architectural Mandate:
 * Implements a local-first sentence embedding provider powered by `@huggingface/transformers`
 * and ONNX Runtime CPU/WASM execution.
 * 
 * Invariants & Boundaries:
 * 1. Zero Mandatory Dependencies: The core platform does not require `@huggingface/transformers`
 *    to be installed. The package is dynamically loaded on demand only when this provider is used.
 * 2. Explicit Local-Only Mode: By default, `allowRemoteModels = false`. The provider NEVER
 *    performs automatic remote model downloads. The user must explicitly obtain model weights.
 * 3. Lazy Single-Instance Loading: The model pipeline is initialized lazily upon first use and
 *    shared across all calls to that provider instance with concurrent initialization protection.
 * 4. Contract Compliance: Output vectors are unit-normalized (L2 norm = 1.0) Float32Arrays
 *    matching the advertised dimensionality (default: 384 for all-MiniLM-L6-v2-ONNX).
 * 5. Bounded Resources & Safety: Inputs are bounded (text <= 8192, batch <= 100), outputs are
 *    defensively copied, and cooperative cancellation (AbortSignal) is respected.
 * 6. Injected Pipeline Loader: Supports dependency injection of the pipeline loader so unit
 *    and integration tests run deterministically without internet access or package installation.
 */

import { existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import type { IEmbeddingProvider, EmbeddingOptions } from './embedding-types.ts';
import { MAX_EMBEDDING_TEXT_LENGTH, MAX_EMBEDDING_BATCH_SIZE } from './embedding-types.ts';
import {
  ValidationError,
  EmbeddingProviderUnavailableError,
  EmbeddingInferenceError,
  InvalidVectorError,
  AgentCancelledError
} from '../domain/errors.ts';
import {
  validateVector,
  normalizeVector,
  isNormalized,
  cloneVector
} from './vector-utils.ts';

/**
 * Standard Hugging Face ONNX sentence embedding model.
 * License: Apache-2.0. Dimension: 384. Context: 256 tokens.
 */
export const DEFAULT_LOCAL_EMBEDDING_MODEL = 'onnx-community/all-MiniLM-L6-v2-ONNX';
export const DEFAULT_LOCAL_EMBEDDING_DIMENSIONS = 384;
export const DEFAULT_LOCAL_EMBEDDING_REVISION = 'main';
export const DEFAULT_LOCAL_RUNTIME_VERSION = '@huggingface/transformers-v3';

export interface FeatureExtractionTensor {
  readonly data: Float32Array | ArrayLike<number>;
  readonly dims?: readonly number[];
  tolist?(): number[][];
}

export type FeatureExtractorOutput =
  | FeatureExtractionTensor
  | Float32Array
  | Float32Array[]
  | number[]
  | number[][];

export type FeatureExtractorFn = (
  texts: string | readonly string[],
  options?: {
    pooling?: 'mean' | 'none' | 'cls';
    normalize?: boolean;
    [key: string]: unknown;
  }
) => Promise<FeatureExtractorOutput>;

export type PipelineLoaderFn = (
  task: 'feature-extraction',
  modelId: string,
  options?: Record<string, unknown>
) => Promise<FeatureExtractorFn>;

export interface LocalEmbeddingProviderOptions {
  /**
   * Unique name of this provider instance (defaults to 'transformers-local').
   */
  readonly name?: string;

  /**
   * Hugging Face model identifier (defaults to 'onnx-community/all-MiniLM-L6-v2-ONNX').
   */
  readonly modelId?: string;

  /**
   * Pinned model git revision or commit tag (defaults to 'main').
   */
  readonly modelRevision?: string;

  /**
   * Expected output vector dimensions (defaults to 384).
   */
  readonly dimensions?: number;

  /**
   * File path to local directory containing pre-downloaded model assets.
   */
  readonly localModelPath?: string;

  /**
   * Whether to permit downloading model weights from Hugging Face Hub.
   * STRICT DEFAULT: false. Prevents automatic unexpected remote network access.
   */
  readonly allowRemoteModels?: boolean;

  /**
   * Target execution device for ONNX Runtime ('cpu', 'wasm', or 'auto'). Defaults to 'cpu'.
   */
  readonly device?: 'cpu' | 'wasm' | 'auto';

  /**
   * Dependency injection for the feature extraction pipeline loader.
   * Allows unit tests to provide mock extractors without installing `@huggingface/transformers`.
   */
  readonly pipelineLoader?: PipelineLoaderFn;
}

export interface EmbeddingModelDescriptor {
  readonly providerName: string;
  readonly modelId: string;
  readonly modelRevision: string;
  readonly dimensions: number;
  readonly runtimeVersion: string;
  readonly localModelPath?: string;
  readonly allowRemoteModels: boolean;
  readonly canonicalId: string;
}

/**
 * Resolves the default local directory where pre-downloaded model assets reside.
 * Checks DOTS_EMBEDDING_LOCAL_MODEL_PATH first, then ~/.cache/dots-models.
 */
export function resolveDefaultLocalModelPath(): string | undefined {
  if (process.env.DOTS_EMBEDDING_LOCAL_MODEL_PATH?.trim()) {
    return process.env.DOTS_EMBEDDING_LOCAL_MODEL_PATH.trim();
  }
  try {
    const defaultDir = join(homedir(), '.cache', 'dots-models');
    if (existsSync(defaultDir)) {
      return defaultDir;
    }
  } catch {
    // Graceful fallback if filesystem access is restricted
  }
  return undefined;
}

/**
 * Production pipeline loader that dynamically loads `@huggingface/transformers` at runtime.
 * Fails safely with EmbeddingProviderUnavailableError if the package is not installed.
 */
export async function defaultTransformersPipelineLoader(
  task: 'feature-extraction',
  modelId: string,
  options: Record<string, unknown> = {}
): Promise<FeatureExtractorFn> {
  let transformers: any;
  try {
    const pkgName = '@huggingface/transformers';
    // @ts-ignore - Optional dependency dynamically resolved at runtime
    transformers = await import(pkgName);
  } catch (err) {
    throw new EmbeddingProviderUnavailableError(
      'transformers-local',
      `Optional package '@huggingface/transformers' is not installed. To use the local embedding provider, install it with: npm install --save-optional @huggingface/transformers`,
      { originalError: err instanceof Error ? err.message : String(err) }
    );
  }

  const allowRemote = Boolean(options.allowRemoteModels ?? false);
  if (transformers.env) {
    transformers.env.allowRemoteModels = allowRemote;
    transformers.env.allowLocalModels = true;
    if (typeof options.localModelPath === 'string') {
      transformers.env.localModelPath = options.localModelPath;
    }
  }

  try {
    const pipeline = await transformers.pipeline(task, modelId, {
      device: options.device ?? 'cpu',
      ...options
    });
    return pipeline;
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    if (
      !allowRemote &&
      (message.includes('not found') ||
        message.includes('ENOENT') ||
        message.includes('does not exist') ||
        message.includes('Could not locate') ||
        message.includes('404'))
    ) {
      throw new EmbeddingProviderUnavailableError(
        'transformers-local',
        `Local embedding model '${modelId}' was not found. Remote downloads are disabled (allowRemoteModels=false). Please ensure model files are downloaded locally to '${String(options.localModelPath ?? transformers.env?.localModelPath ?? './models')}' before using local inference.`,
        { modelId, localModelPath: options.localModelPath, originalError: message }
      );
    }
    throw new EmbeddingInferenceError(
      `Failed to initialize Transformers.js feature extraction pipeline for '${modelId}': ${message}`,
      { modelId, providerName: 'transformers-local', originalError: message }
    );
  }
}

export class LocalEmbeddingProvider implements IEmbeddingProvider {
  public readonly name: string;
  public readonly modelId: string;
  public readonly modelRevision: string;
  public readonly dimensions: number;
  public readonly runtimeVersion: string;
  public readonly localModelPath?: string;
  public readonly allowRemoteModels: boolean;
  public readonly device: 'cpu' | 'wasm' | 'auto';

  private readonly pipelineLoader: PipelineLoaderFn;
  private extractor: FeatureExtractorFn | null = null;
  private initPromise: Promise<FeatureExtractorFn> | null = null;

  constructor(options: LocalEmbeddingProviderOptions = {}) {
    this.name = options.name ?? 'transformers-local';
    this.modelId = options.modelId ?? DEFAULT_LOCAL_EMBEDDING_MODEL;
    this.modelRevision = options.modelRevision ?? DEFAULT_LOCAL_EMBEDDING_REVISION;
    this.dimensions = options.dimensions ?? DEFAULT_LOCAL_EMBEDDING_DIMENSIONS;
    this.runtimeVersion = DEFAULT_LOCAL_RUNTIME_VERSION;
    this.localModelPath = options.localModelPath ?? resolveDefaultLocalModelPath();
    this.allowRemoteModels = options.allowRemoteModels ?? false;
    this.device = options.device ?? 'cpu';
    this.pipelineLoader = options.pipelineLoader ?? defaultTransformersPipelineLoader;

    if (!Number.isInteger(this.dimensions) || this.dimensions <= 0) {
      throw new ValidationError(
        `Embedding dimensions must be a positive integer, received '${String(this.dimensions)}'.`
      );
    }
  }

  /**
   * Returns a complete, immutable descriptor of the model identity, version, dimensions, and runtime.
   */
  public getModelDescriptor(): EmbeddingModelDescriptor {
    return {
      providerName: this.name,
      modelId: this.modelId,
      modelRevision: this.modelRevision,
      dimensions: this.dimensions,
      runtimeVersion: this.runtimeVersion,
      localModelPath: this.localModelPath,
      allowRemoteModels: this.allowRemoteModels,
      canonicalId: `${this.name}:${this.modelId}@${this.modelRevision}:d${this.dimensions}`
    };
  }

  /**
   * Reports whether the local provider and model pipeline are initialized and ready for inference.
   */
  public async isAvailable(): Promise<boolean> {
    if (this.extractor) {
      return true;
    }
    try {
      await this.getExtractor();
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Generates a unit-normalized Float32Array vector embedding for the given text.
   */
  public async embed(text: string, options?: EmbeddingOptions): Promise<Float32Array> {
    this.checkCancellation(options?.signal);
    this.validateInputText(text);

    const extractor = await this.getExtractor();
    this.checkCancellation(options?.signal);

    let rawOutput: FeatureExtractorOutput;
    try {
      rawOutput = await extractor(text, {
        pooling: 'mean',
        normalize: true
      });
    } catch (err) {
      throw new EmbeddingInferenceError(
        `Local embedding inference failed for model '${this.modelId}': ${err instanceof Error ? err.message : String(err)}`,
        {
          modelId: this.modelId,
          providerName: this.name,
          originalError: err instanceof Error ? err.message : String(err)
        }
      );
    }

    this.checkCancellation(options?.signal);

    const vectors = this.parseAndValidateOutput(rawOutput, 1);
    const vector = vectors[0]!;

    return cloneVector(vector);
  }

  /**
   * Generates unit-normalized Float32Array vector embeddings for a batch of text inputs.
   */
  public async embedBatch(texts: readonly string[], options?: EmbeddingOptions): Promise<Float32Array[]> {
    this.checkCancellation(options?.signal);

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

    for (let i = 0; i < texts.length; i++) {
      this.validateInputText(texts[i], `at index ${i}`);
    }

    const extractor = await this.getExtractor();
    this.checkCancellation(options?.signal);

    let rawOutput: FeatureExtractorOutput;
    try {
      rawOutput = await extractor(texts, {
        pooling: 'mean',
        normalize: true
      });
    } catch (err) {
      throw new EmbeddingInferenceError(
        `Local batch embedding inference failed for model '${this.modelId}': ${err instanceof Error ? err.message : String(err)}`,
        {
          modelId: this.modelId,
          providerName: this.name,
          batchSize: texts.length,
          originalError: err instanceof Error ? err.message : String(err)
        }
      );
    }

    this.checkCancellation(options?.signal);

    const vectors = this.parseAndValidateOutput(rawOutput, texts.length);

    return vectors.map((v) => cloneVector(v));
  }

  /**
   * Lazily loads and caches the shared feature extraction pipeline instance, protecting
   * against concurrent duplicate initialization.
   */
  private async getExtractor(): Promise<FeatureExtractorFn> {
    if (this.extractor) {
      return this.extractor;
    }

    if (!this.initPromise) {
      this.initPromise = (async () => {
        try {
          const extractor = await this.pipelineLoader('feature-extraction', this.modelId, {
            localModelPath: this.localModelPath,
            allowRemoteModels: this.allowRemoteModels,
            device: this.device,
            revision: this.modelRevision
          });

          if (typeof extractor !== 'function') {
            throw new EmbeddingInferenceError(
              `Pipeline loader returned invalid extractor (expected function, received ${typeof extractor}).`,
              { providerName: this.name, modelId: this.modelId }
            );
          }

          this.extractor = extractor;
          return extractor;
        } catch (err) {
          // Reset initPromise so future attempts can re-try if model files become available
          this.initPromise = null;
          throw err;
        }
      })();
    }

    return this.initPromise;
  }

  /**
   * Parses raw pipeline output and extracts strictly validated unit-normalized vectors.
   */
  private parseAndValidateOutput(
    rawOutput: FeatureExtractorOutput,
    expectedCount: number
  ): Float32Array[] {
    if (!rawOutput) {
      throw new InvalidVectorError('Model returned null or undefined tensor output.');
    }

    const results: Float32Array[] = [];

    // Case 1: Standard Tensor output with .data and optional .dims
    if (typeof rawOutput === 'object' && 'data' in rawOutput && (rawOutput as FeatureExtractionTensor).data) {
      const tensor = rawOutput as FeatureExtractionTensor;
      const rawData = tensor.data;
      const totalElements = rawData.length;
      const expectedTotal = expectedCount * this.dimensions;

      if (totalElements !== expectedTotal) {
        throw new InvalidVectorError(
          `Model output length mismatch: expected ${expectedTotal} elements (${expectedCount} x ${this.dimensions}), received ${totalElements}.`,
          { expectedTotal, actualTotal: totalElements }
        );
      }

      for (let i = 0; i < expectedCount; i++) {
        const offset = i * this.dimensions;
        let slice: Float32Array;
        if (rawData instanceof Float32Array) {
          slice = rawData.subarray(offset, offset + this.dimensions);
        } else {
          slice = new Float32Array(this.dimensions);
          for (let j = 0; j < this.dimensions; j++) {
            slice[j] = Number(rawData[offset + j]);
          }
        }
        results.push(this.sanitizeAndNormalizeVector(slice));
      }

      return results;
    }

    // Case 2: Array of Float32Arrays or Array of number arrays
    if (Array.isArray(rawOutput)) {
      if (rawOutput.length !== expectedCount) {
        throw new InvalidVectorError(
          `Model output batch count mismatch: expected ${expectedCount} items, received ${rawOutput.length}.`,
          { expectedCount, actualCount: rawOutput.length }
        );
      }

      for (let i = 0; i < expectedCount; i++) {
        const item = rawOutput[i];
        let vec: Float32Array;
        if (item instanceof Float32Array) {
          vec = item;
        } else if (Array.isArray(item)) {
          vec = new Float32Array(item);
        } else {
          throw new InvalidVectorError(`Model output at index ${i} is not a valid vector.`);
        }
        results.push(this.sanitizeAndNormalizeVector(vec));
      }

      return results;
    }

    // Case 3: Single Float32Array for a batch of 1
    if (rawOutput instanceof Float32Array && expectedCount === 1) {
      results.push(this.sanitizeAndNormalizeVector(rawOutput));
      return results;
    }

    throw new InvalidVectorError('Unrecognized model tensor output structure.');
  }

  private sanitizeAndNormalizeVector(vector: Float32Array): Float32Array {
    validateVector(vector, this.dimensions, 'Model output vector');

    if (!isNormalized(vector)) {
      return normalizeVector(vector);
    }

    return cloneVector(vector);
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
}
