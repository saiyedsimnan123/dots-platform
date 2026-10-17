/**
 * Next-Generation Dots AI Platform - Compensation & Rollback Manager
 * 
 * Architectural Mandate:
 * Provides bounded rollback and safe cleanup for partially failed workflow tasks.
 * Strictly guarantees data safety:
 * 1. Reverse execution order: compensates mutations from latest to oldest, unwinding multi-write chains.
 * 2. Rejects path traversal, sibling prefix spoofing, and symlink escapes via PathValidator.
 * 3. Never deletes pre-existing files that were overwritten during the task.
 * 4. Never recreates missing pre-existing files; reports SKIPPED when state differs from expected post-write state.
 * 5. Explicit missing-value checks allowing empty files ("") to be safely restored.
 * 6. Protects post-write edits: verifies file on disk matches expected written hash before reverting or deleting.
 * 7. Correct isComplete semantics: marks complete only when zero actions were SKIPPED or FAILED.
 * 8. Idempotent across repeated compensation runs.
 * 9. Records detailed audit events for every reverted, skipped, or failed action.
 */

import { existsSync, unlinkSync, writeFileSync, readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import type { TaskRepository } from '../storage/task-repository.ts';
import type { AuditRepository } from '../storage/audit-repository.ts';
import type { TaskStep, ToolExecution } from '../domain/types.ts';
import { PathValidator } from '../security/path-validator.ts';

export interface CompensationAction {
  readonly action: 'file_delete' | 'file_restore';
  readonly resource: string;
  readonly status: 'REVERTED' | 'FAILED' | 'SKIPPED';
  readonly details?: string;
}

export interface CompensationResult {
  readonly taskId: string;
  readonly actions: readonly CompensationAction[];
  readonly totalReverted: number;
  readonly totalSkipped: number;
  readonly totalFailed: number;
  readonly isComplete: boolean;
}

export class CompensationManager {
  private readonly taskRepo: TaskRepository;
  private readonly auditRepo: AuditRepository;
  private readonly workspaceRoot: string;

  constructor(
    taskRepo: TaskRepository,
    auditRepo: AuditRepository,
    workspaceRoot: string
  ) {
    this.taskRepo = taskRepo;
    this.auditRepo = auditRepo;
    this.workspaceRoot = workspaceRoot;
  }

  /**
   * Reverts mutations created by a failed task within the sandboxed workspace.
   * Executed in reverse execution order.
   */
  public async compensate(taskId: string): Promise<CompensationResult> {
    const steps = this.taskRepo.getStepsByTaskId(taskId);
    const actions: CompensationAction[] = [];

    try {
      // 1. Gather all file_write executions in chronological order
      const sortedSteps = [...steps].sort((a, b) => a.stepOrder - b.stepOrder);
      const writeExecutions: { step: TaskStep; exec: ToolExecution }[] = [];

      for (const step of sortedSteps) {
        const executions = this.taskRepo.getToolExecutionsByStepId(step.id);
        const sortedExecs = [...executions].sort((a, b) => a.createdAt.localeCompare(b.createdAt));
        for (const exec of sortedExecs) {
          if (exec.toolName === 'file_write') {
            writeExecutions.push({ step, exec });
          }
        }
      }

      // 2. Reverse execution order: compensate most recent writes first!
      writeExecutions.reverse();

      // 3. Compensate each mutation
      for (const item of writeExecutions) {
        await this.compensateFileWrite(item.exec.inputJson, item.exec.outputJson, actions);
      }
    } catch (err) {
      actions.push({
        action: 'file_delete',
        resource: 'workflow',
        status: 'FAILED',
        details: `Unexpected error during compensation traversal: ${err instanceof Error ? err.message : String(err)}`
      });
    }

    const totalReverted = actions.filter((a) => a.status === 'REVERTED').length;
    const totalSkipped = actions.filter((a) => a.status === 'SKIPPED').length;
    const totalFailed = actions.filter((a) => a.status === 'FAILED').length;
    const isComplete = totalFailed === 0 && totalSkipped === 0;

    this.auditRepo.appendEvent({
      taskId,
      eventType: 'COMPENSATION_EXECUTED',
      actor: 'SYSTEM',
      details: {
        actions,
        totalReverted,
        totalSkipped,
        totalFailed,
        isComplete
      }
    });

    return {
      taskId,
      actions,
      totalReverted,
      totalSkipped,
      totalFailed,
      isComplete
    };
  }

  /**
   * Safely rolls back a single file_write mutation in reverse execution sequence.
   */
  private async compensateFileWrite(
    inputJson: string,
    outputJson: string,
    actions: CompensationAction[]
  ): Promise<void> {
    let input: { path?: string; content?: string };
    let output: {
      path?: string;
      bytesWritten?: number;
      writtenHash?: string;
      existedBefore?: boolean;
      previousContent?: string;
      previousHash?: string;
    };

    try {
      input = JSON.parse(inputJson) as typeof input;
      output = JSON.parse(outputJson) as typeof output;
    } catch {
      actions.push({
        action: 'file_delete',
        resource: 'unknown',
        status: 'FAILED',
        details: 'Corrupted tool execution log: unable to parse JSON payload.'
      });
      return;
    }

    const rawPath = output.path || input.path;
    if (!rawPath) return;

    // 1. Strict workspace containment check
    const containment = PathValidator.checkContained(rawPath, this.workspaceRoot);
    if (!containment.isContained) {
      actions.push({
        action: 'file_delete',
        resource: rawPath,
        status: 'SKIPPED',
        details: containment.violationReason || 'Path escapes workspace jail.'
      });
      return;
    }

    const canonicalPath = containment.canonicalPath;

    // Determine expected content hash written by this execution
    const expectedWrittenHash = output.writtenHash || (typeof input.content === 'string'
      ? createHash('sha256').update(input.content).digest('hex')
      : undefined);

    // 2. Protect pre-existing files vs newly created files
    if (output.existedBefore === true) {
      // Overwritten pre-existing file: NEVER delete. Attempt restore only if verified backup exists.
      // Explicit missing-value check allows empty file string ("") as a valid backup
      if (
        output.previousContent === undefined ||
        output.previousContent === null ||
        typeof output.previousContent !== 'string' ||
        output.previousHash === undefined ||
        output.previousHash === null ||
        typeof output.previousHash !== 'string'
      ) {
        actions.push({
          action: 'file_restore',
          resource: rawPath,
          status: 'SKIPPED',
          details: 'Pre-existing file left untouched: missing backup snapshot.'
        });
        return;
      }

      // If file is missing during compensation, do not recreate it automatically
      if (!existsSync(canonicalPath)) {
        actions.push({
          action: 'file_restore',
          resource: rawPath,
          status: 'SKIPPED',
          details: 'Pre-existing file is missing on disk; current state differs from expected post-write state, not recreating.'
        });
        return;
      }

      // File exists on disk: verify if it was modified after workflow wrote it
      try {
        const currentContent = readFileSync(canonicalPath, 'utf8');
        const currentHash = createHash('sha256').update(currentContent).digest('hex');

        // If current hash doesn't match what this execution wrote, external/post-write modifications occurred!
        if (expectedWrittenHash && currentHash !== expectedWrittenHash) {
          actions.push({
            action: 'file_restore',
            resource: rawPath,
            status: 'SKIPPED',
            details: 'Pre-existing file was modified after workflow execution; left untouched to prevent overwriting external changes.'
          });
          return;
        }
      } catch (err) {
        actions.push({
          action: 'file_restore',
          resource: rawPath,
          status: 'FAILED',
          details: `Failed to inspect current file state on disk: ${err instanceof Error ? err.message : String(err)}`
        });
        return;
      }

      // Verify backup integrity
      const computedHash = createHash('sha256').update(output.previousContent).digest('hex');
      if (computedHash !== output.previousHash) {
        actions.push({
          action: 'file_restore',
          resource: rawPath,
          status: 'SKIPPED',
          details: 'Pre-existing file left untouched: backup hash mismatch.'
        });
        return;
      }

      try {
        writeFileSync(canonicalPath, output.previousContent, 'utf8');
        actions.push({
          action: 'file_restore',
          resource: rawPath,
          status: 'REVERTED',
          details: 'Restored pre-existing content from verified backup.'
        });
      } catch (err) {
        actions.push({
          action: 'file_restore',
          resource: rawPath,
          status: 'FAILED',
          details: `Failed to restore pre-existing file: ${err instanceof Error ? err.message : String(err)}`
        });
      }
      return;
    }

    if (output.existedBefore === false) {
      // Newly created file during task: safe to delete if it has not been modified post-write
      if (!existsSync(canonicalPath)) {
        // Idempotency: already deleted or not created
        actions.push({
          action: 'file_delete',
          resource: rawPath,
          status: 'SKIPPED',
          details: 'File does not exist (already removed or not created).'
        });
        return;
      }

      try {
        const currentContent = readFileSync(canonicalPath, 'utf8');
        const currentHash = createHash('sha256').update(currentContent).digest('hex');

        // Protect post-write edits: if file differs from what workflow wrote, leave untouched!
        if (expectedWrittenHash && currentHash !== expectedWrittenHash) {
          actions.push({
            action: 'file_delete',
            resource: rawPath,
            status: 'SKIPPED',
            details: 'Newly created file was modified after workflow execution; left untouched to prevent data loss.'
          });
          return;
        }

        unlinkSync(canonicalPath);
        actions.push({
          action: 'file_delete',
          resource: rawPath,
          status: 'REVERTED',
          details: 'Removed newly created scratch file.'
        });
      } catch (err) {
        actions.push({
          action: 'file_delete',
          resource: rawPath,
          status: 'FAILED',
          details: `Failed to delete file: ${err instanceof Error ? err.message : String(err)}`
        });
      }
      return;
    }

    // Pre-existing state unknown or unrecorded: fail-safe by leaving untouched
    actions.push({
      action: 'file_delete',
      resource: rawPath,
      status: 'SKIPPED',
      details: 'Pre-existing state unknown; left untouched to prevent data loss.'
    });
  }
}
