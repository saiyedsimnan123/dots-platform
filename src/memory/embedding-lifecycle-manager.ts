/**
 * Next-Generation Dots AI Platform - Embedding Lifecycle Manager
 * Phase 4C.6B: Durable Asynchronous Embedding Lifecycle Manager
 * 
 * Architectural Mandate:
 * Orchestrates background, asynchronous, resource-bounded generation and regeneration
 * of vector embeddings following memory lifecycle mutations.
 * 
 * Security & Resource Invariants:
 * 1. Default concurrency: strictly 1 worker at a time.
 * 2. Never trusts mutable payloads: reads memory key and content directly from SQLite.
 * 3. Enforces authoritative relational scope verification; cross-workspace or forged jobs fail closed.
 * 4. Model inference executes strictly OUTSIDE SQLite database write transactions.
 * 5. Pre-persist revalidation: detects concurrent memory deletion, archiving, or content modification,
 *    safely discarding stale embeddings.
 * 6. Bounded retry backoff: reschedules transient errors with exponential backoff; marks terminally FAILED
 *    when maxAttempts is reached.
 * 7. Graceful offline handling: if embedding provider is unavailable, preserves jobs for retry without
 *    crashing the runtime or exhausting retry budgets.
 * 8. Safe shutdown: stops claiming new jobs and allows in-flight execution to finish cleanly.
 * 9. Recovers interrupted RUNNING jobs on startup.
 */

import type { DatabaseManager } from '../storage/db.ts';
import type { MemoryRepository } from '../storage/memory-repository.ts';
import type { MemoryEmbeddingRepository } from '../storage/memory-embedding-repository.ts';
import type { EmbeddingJobRepository } from '../storage/embedding-job-repository.ts';
import type { IEmbeddingProvider, EmbeddingJob, PruneTerminalJobsResult } from './embedding-types.ts';
import type { AuditRepository } from '../storage/audit-repository.ts';
import type { Memory } from '../domain/types.ts';
import { validateVector } from './vector-utils.ts';
import { ValidationError, MemoryScopeViolationError } from '../domain/errors.ts';

export interface EmbeddingLifecycleManagerOptions {
  readonly db: DatabaseManager;
  readonly jobRepo: EmbeddingJobRepository;
  readonly memoryRepo: MemoryRepository;
  readonly embeddingRepo: MemoryEmbeddingRepository;
  readonly provider: IEmbeddingProvider;
  readonly auditRepo?: AuditRepository;
  /** Polling interval in ms for checking pending jobs (default: 1000) */
  readonly pollIntervalMs?: number;
  /** Base delay in ms for exponential backoff retry (default: 1000) */
  readonly baseRetryDelayMs?: number;
  /** Maximum delay in ms for backoff retry (default: 60000) */
  readonly maxRetryDelayMs?: number;
  /** Maximum retry attempts before marking a job terminally FAILED (default: 5) */
  readonly maxAttempts?: number;
  /** Automatically start the polling loop upon construction (default: false) */
  readonly autoStart?: boolean;
  /** Terminal job retention in ms (default: 14 days = 1,209,600,000 ms) */
  readonly retentionMs?: number;
  /** Interval in ms between automatic queue maintenance passes (default: 1 hour = 3,600,000 ms) */
  readonly maintenanceIntervalMs?: number;
  /** Maximum number of terminal jobs deleted per maintenance pass (default: 500) */
  readonly maxPruneBatchSize?: number;
  /** Optional logger for recording operational and maintenance events */
  readonly logger?: {
    info?: (domain: string, event: string, details?: Record<string, unknown>) => void;
    warn?: (domain: string, event: string, details?: Record<string, unknown>) => void;
    error?: (domain: string, event: string, details?: Record<string, unknown>) => void;
    debug?: (domain: string, event: string, details?: Record<string, unknown>) => void;
  };
}

export class EmbeddingLifecycleManager {
  public static readonly DEFAULT_RETENTION_MS = 14 * 24 * 60 * 60 * 1000; // 14 days
  public static readonly DEFAULT_MAINTENANCE_INTERVAL_MS = 60 * 60 * 1000; // 1 hour
  public static readonly DEFAULT_MAX_PRUNE_BATCH_SIZE = 500;

  public readonly db: DatabaseManager;
  public readonly jobRepo: EmbeddingJobRepository;
  public readonly memoryRepo: MemoryRepository;
  public readonly embeddingRepo: MemoryEmbeddingRepository;
  public readonly provider: IEmbeddingProvider;
  public readonly auditRepo?: AuditRepository;

  public readonly pollIntervalMs: number;
  public readonly baseRetryDelayMs: number;
  public readonly maxRetryDelayMs: number;
  public readonly maxAttempts: number;
  public readonly retentionMs: number;
  public readonly maintenanceIntervalMs: number;
  public readonly maxPruneBatchSize: number;
  public readonly logger?: EmbeddingLifecycleManagerOptions['logger'];

  private isRunning = false;
  private isStopping = false;
  private isStopped = false;
  private isProcessing = false;
  private isMaintaining = false;
  private pollTimer: NodeJS.Timeout | null = null;
  private maintenanceTimer: NodeJS.Timeout | null = null;
  private inFlightPromise: Promise<void> | null = null;
  private maintenancePromise: Promise<PruneTerminalJobsResult | null> | null = null;

  constructor(options: EmbeddingLifecycleManagerOptions) {
    if (!options || typeof options !== 'object') {
      throw new ValidationError('EmbeddingLifecycleManagerOptions must be provided.');
    }
    if (!options.db) throw new ValidationError('DatabaseManager must be provided.');
    if (!options.jobRepo) throw new ValidationError('EmbeddingJobRepository must be provided.');
    if (!options.memoryRepo) throw new ValidationError('MemoryRepository must be provided.');
    if (!options.embeddingRepo) throw new ValidationError('MemoryEmbeddingRepository must be provided.');
    if (!options.provider) throw new ValidationError('EmbeddingProvider must be provided.');

    if (options.retentionMs !== undefined) {
      if (typeof options.retentionMs !== 'number' || !Number.isFinite(options.retentionMs) || options.retentionMs < 0) {
        throw new ValidationError(`Configuration 'retentionMs' must be a non-negative number, received '${String(options.retentionMs)}'.`);
      }
    }
    if (options.maintenanceIntervalMs !== undefined) {
      if (typeof options.maintenanceIntervalMs !== 'number' || !Number.isFinite(options.maintenanceIntervalMs) || options.maintenanceIntervalMs < 1000) {
        throw new ValidationError(`Configuration 'maintenanceIntervalMs' must be at least 1000 ms, received '${String(options.maintenanceIntervalMs)}'.`);
      }
    }
    if (options.maxPruneBatchSize !== undefined) {
      if (typeof options.maxPruneBatchSize !== 'number' || !Number.isInteger(options.maxPruneBatchSize) || options.maxPruneBatchSize <= 0) {
        throw new ValidationError(`Configuration 'maxPruneBatchSize' must be a positive integer, received '${String(options.maxPruneBatchSize)}'.`);
      }
    }

    this.db = options.db;
    this.jobRepo = options.jobRepo;
    this.memoryRepo = options.memoryRepo;
    this.embeddingRepo = options.embeddingRepo;
    this.provider = options.provider;
    this.auditRepo = options.auditRepo;

    this.pollIntervalMs = Math.max(options.pollIntervalMs ?? 1000, 10);
    this.baseRetryDelayMs = Math.max(options.baseRetryDelayMs ?? 1000, 1);
    this.maxRetryDelayMs = Math.max(options.maxRetryDelayMs ?? 60000, 100);
    this.maxAttempts = Math.max(options.maxAttempts ?? 5, 1);
    this.retentionMs = options.retentionMs ?? EmbeddingLifecycleManager.DEFAULT_RETENTION_MS;
    this.maintenanceIntervalMs = options.maintenanceIntervalMs ?? EmbeddingLifecycleManager.DEFAULT_MAINTENANCE_INTERVAL_MS;
    this.maxPruneBatchSize = options.maxPruneBatchSize ?? EmbeddingLifecycleManager.DEFAULT_MAX_PRUNE_BATCH_SIZE;
    this.logger = options.logger;

    if (options.autoStart) {
      void this.start();
    }
  }

  /**
   * Reports whether the lifecycle manager's polling loop is currently running.
   */
  public get active(): boolean {
    return this.isRunning;
  }

  /**
   * Starts the asynchronous job execution loop.
   * Recovers any interrupted jobs left in 'RUNNING' status from previous runs,
   * schedules periodic queue maintenance, and performs an initial maintenance pass.
   */
  public async start(): Promise<void> {
    if (this.isRunning) {
      return;
    }

    this.isRunning = true;
    this.isStopping = false;
    this.isStopped = false;

    // 1. Recover any jobs left in 'RUNNING' state before starting new processing
    this.jobRepo.recoverInterruptedJobs();

    // 2. Schedule maintenance tick and run initial maintenance pass safely in background
    this.scheduleMaintenanceTick();
    void this.runMaintenance();

    // 3. Start periodic polling
    this.schedulePollTick();

    // 4. Immediately trigger first check
    this.trigger();
  }

  /**
   * Performs an immediate maintenance pass: prunes terminal embedding jobs
   * (COMPLETED, FAILED, CANCELLED) older than retentionMs, bounded by maxPruneBatchSize.
   * Safe against concurrent calls (no-op if already maintaining or stopping/stopped).
   */
  public async runMaintenance(now = Date.now()): Promise<PruneTerminalJobsResult | null> {
    if (!this.db.isOpen || this.isStopped || this.isStopping || this.isMaintaining) {
      return null;
    }

    this.isMaintaining = true;
    const maintenanceExecution = (async (): Promise<PruneTerminalJobsResult | null> => {
      try {
        const result = this.jobRepo.pruneTerminalJobs({
          limit: this.maxPruneBatchSize,
          olderThanMs: this.retentionMs,
          now
        });

        if (result.total > 0) {
          this.logger?.info?.('memory', 'embedding_queue_pruned', {
            completed: result.completed,
            failed: result.failed,
            cancelled: result.cancelled,
            total: result.total
          });
        }

        return result;
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        this.logger?.error?.('memory', 'embedding_queue_prune_failed', { error: message });
        return null;
      } finally {
        this.isMaintaining = false;
        this.maintenancePromise = null;
      }
    })();

    this.maintenancePromise = maintenanceExecution;
    return maintenanceExecution;
  }

  /**
   * Stops the lifecycle worker gracefully:
   * 1. Stops accepting or claiming new jobs immediately.
   * 2. Clears polling and maintenance timers.
   * 3. Awaits completion of any in-flight inference/persistence and maintenance up to timeoutMs.
   * Returns true if all in-flight work drained successfully; false if timed out while in-flight work is still active.
   */
  public async stop(timeoutMs = 5000): Promise<boolean> {
    if (!this.isRunning && !this.isStopping && !this.isProcessing && !this.isMaintaining) {
      return true;
    }

    this.isStopping = true;
    this.isRunning = false;

    if (this.pollTimer) {
      clearTimeout(this.pollTimer);
      this.pollTimer = null;
    }

    if (this.maintenanceTimer) {
      clearTimeout(this.maintenanceTimer);
      this.maintenanceTimer = null;
    }

    let drained = true;
    const inFlightWork: Promise<unknown>[] = [];
    if (this.inFlightPromise) inFlightWork.push(this.inFlightPromise);
    if (this.maintenancePromise) inFlightWork.push(this.maintenancePromise);

    if (inFlightWork.length > 0) {
      let timer: NodeJS.Timeout | null = null;
      const timeoutPromise = new Promise<'timeout'>((resolve) => {
        timer = setTimeout(() => resolve('timeout'), Math.max(1, timeoutMs));
      });

      const outcome = await Promise.race([
        Promise.allSettled(inFlightWork).then(() => 'drained' as const),
        timeoutPromise
      ]);

      if (timer) {
        clearTimeout(timer);
      }

      if (outcome === 'timeout') {
        drained = false;
      }
    }

    if (drained) {
      this.isStopping = false;
      this.isStopped = true;
    }

    return drained;
  }

  /**
   * Unconditionally waits for any currently active in-flight embedding operation or maintenance to finish.
   * Guarantees that the worker has completely finished interacting with SQLite before database closure.
   */
  public async waitForInFlight(): Promise<void> {
    const inFlightWork: Promise<unknown>[] = [];
    if (this.inFlightPromise) inFlightWork.push(this.inFlightPromise);
    if (this.maintenancePromise) inFlightWork.push(this.maintenancePromise);

    if (inFlightWork.length > 0) {
      try {
        await Promise.allSettled(inFlightWork);
      } catch {
        // Prevent unhandled rejections during shutdown
      }
    }
    this.isStopping = false;
    this.isStopped = true;
  }

  /**
   * Reports whether there is currently an in-flight job or maintenance task being processed.
   */
  public get hasInFlightWork(): boolean {
    return (
      this.isProcessing ||
      this.isMaintaining ||
      this.inFlightPromise !== null ||
      this.maintenancePromise !== null
    );
  }

  /**
   * Wakes up the worker immediately when a new job is enqueued.
   */
  public trigger(): void {
    if (!this.isRunning || this.isStopping || this.isProcessing) {
      return;
    }

    setImmediate(() => {
      void this.processNextJob();
    });
  }

  /**
   * Atomically claims and processes the next eligible pending job.
   * Returns true if a job was processed; false if the queue was empty or worker is busy.
   */
  public async processNextJob(now = new Date().toISOString()): Promise<boolean> {
    if (this.isStopped || this.isStopping || this.isProcessing || !this.db.isOpen) {
      return false;
    }

    this.isProcessing = true;
    let claimedJob: EmbeddingJob | null = null;

    try {
      // Concurrency Gate: Atomically claim next eligible job under model constraint
      claimedJob = this.jobRepo.claimNextJob(now, this.provider.modelId);
      if (!claimedJob) {
        return false;
      }

      const executionPromise = this.executeJob(claimedJob);
      this.inFlightPromise = executionPromise;
      await executionPromise;
      return true;
    } finally {
      this.inFlightPromise = null;
      this.isProcessing = false;
    }
  }

  /**
   * Helper for deterministic testing or manual draining:
   * Processes all pending jobs sequentially until queue is drained or maxJobs limit reached.
   */
  public async processPendingJobs(maxJobs = 100, now = new Date().toISOString()): Promise<number> {
    let processed = 0;
    while (processed < maxJobs) {
      const didProcess = await this.processNextJob(now);
      if (!didProcess) {
        break;
      }
      processed++;
    }
    return processed;
  }

  /**
   * Executes a single claimed embedding job end-to-end.
   */
  private async executeJob(job: EmbeddingJob): Promise<void> {
    // 1. Authoritative pre-inference retrieval: fetch memory directly from SQLite
    let memory: Memory | null = null;
    try {
      memory = this.memoryRepo.getMemoryById(job.memoryId, {
        scopeType: job.scopeType,
        scopeId: job.scopeId
      });
    } catch (err) {
      if (err instanceof MemoryScopeViolationError) {
        // Scope violation: job's asserted scope does not match relational memory ownership
        this.jobRepo.markJobFailed(
          job.id,
          job.attemptCount + 1,
          `MemoryScopeViolation: Relational scope does not match job scope: ${err.message}`
        );
        return;
      }
      throw err;
    }

    // 2. Lifecycle Checks:
    // If memory is deleted: skip and complete job
    if (!memory) {
      this.jobRepo.markJobCompleted(job.id);
      return;
    }

    // If memory is not ACTIVE (e.g. ARCHIVED or PENDING_APPROVAL proposal): skip and complete job
    if (memory.status !== 'ACTIVE') {
      this.jobRepo.markJobCompleted(job.id);
      return;
    }

    // Verify relational scope match
    if (memory.scopeType !== job.scopeType || memory.scopeId !== job.scopeId) {
      this.jobRepo.markJobFailed(
        job.id,
        job.attemptCount + 1,
        'MemoryScopeViolation: Relational memory scope does not match job scope'
      );
      return;
    }

    // 3. Provider Availability Check:
    let isAvailable = false;
    try {
      isAvailable = await this.provider.isAvailable();
    } catch {
      isAvailable = false;
    }

    if (!isAvailable) {
      // Preserve job for retry without crashing runtime or consuming retry attempt budget
      const nextScheduledAt = new Date(Date.now() + this.baseRetryDelayMs).toISOString();
      this.jobRepo.rescheduleJob(
        job.id,
        job.attemptCount,
        nextScheduledAt,
        `Embedding provider '${this.provider.name}' is currently unavailable`
      );
      return;
    }

    // 4. Capture pre-inference state for concurrency revalidation
    const preUpdatedAt = memory.updatedAt;
    const preContent = memory.content;
    const textToEmbed = `${memory.key}: ${memory.content}`;

    // 5. Model Inference: EXECUTED STRICTLY OUTSIDE SQLITE TRANSACTION
    let vector: Float32Array;
    try {
      vector = await this.provider.embed(textToEmbed);
      validateVector(vector, this.provider.dimensions, `embedding for memory ${memory.id}`);
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : String(err);
      const nextAttempt = job.attemptCount + 1;
      if (nextAttempt >= job.maxAttempts) {
        this.jobRepo.markJobFailed(
          job.id,
          nextAttempt,
          `Inference failure (exhausted attempts): ${errorMsg}`
        );
      } else {
        const backoff = Math.min(
          this.baseRetryDelayMs * Math.pow(2, nextAttempt - 1),
          this.maxRetryDelayMs
        );
        const nextScheduledAt = new Date(Date.now() + backoff).toISOString();
        this.jobRepo.rescheduleJob(job.id, nextAttempt, nextScheduledAt, errorMsg);
      }
      return;
    }

    // 6. Post-Inference Revalidation & Atomic Persistence:
    if (!this.db.isOpen || this.isStopped) {
      return;
    }

    this.db.transaction(() => {
      // Check if job itself was cancelled or deleted during inference
      const currentJob = this.jobRepo.getJobById(job.id);
      if (!currentJob || currentJob.status === 'CANCELLED') {
        return;
      }

      let postMemory: Memory | null = null;
      try {
        postMemory = this.memoryRepo.getMemoryById(job.memoryId, {
          scopeType: job.scopeType,
          scopeId: job.scopeId
        });
      } catch {
        // Discard stale result if scope violated
        this.jobRepo.markJobCompleted(job.id);
        return;
      }

      if (!postMemory) {
        // Memory deleted concurrently during inference: discard stale result
        this.jobRepo.markJobCompleted(job.id);
        return;
      }

      if (postMemory.status !== 'ACTIVE') {
        // Memory archived concurrently during inference: discard stale result
        this.jobRepo.markJobCompleted(job.id);
        return;
      }

      if (postMemory.updatedAt !== preUpdatedAt || postMemory.content !== preContent) {
        // Memory content or timestamp updated concurrently: discard stale result!
        // A replacement job was enqueued by the updateMemory call.
        this.jobRepo.markJobCompleted(job.id);
        return;
      }

      // Persist valid embedding
      this.embeddingRepo.upsertEmbedding({
        memoryId: postMemory.id,
        modelId: job.modelId,
        modelRevision: job.modelRevision,
        dimensions: this.provider.dimensions,
        embedding: vector
      });

      this.jobRepo.markJobCompleted(job.id);
    });
  }

  private schedulePollTick(): void {
    if (!this.isRunning || this.isStopping) {
      return;
    }

    this.pollTimer = setTimeout(async () => {
      if (!this.isRunning || this.isStopping) {
        return;
      }

      try {
        await this.processNextJob();
      } catch {
        // Prevent unhandled rejection in background tick
      } finally {
        this.schedulePollTick();
      }
    }, this.pollIntervalMs);
  }

  private scheduleMaintenanceTick(): void {
    if (!this.isRunning || this.isStopping) {
      return;
    }

    this.maintenanceTimer = setTimeout(async () => {
      if (!this.isRunning || this.isStopping) {
        return;
      }

      try {
        await this.runMaintenance();
      } catch {
        // Prevent unhandled rejection in background maintenance tick
      } finally {
        if (this.isRunning && !this.isStopping) {
          this.scheduleMaintenanceTick();
        }
      }
    }, this.maintenanceIntervalMs);

    this.maintenanceTimer.unref?.();
  }
}
