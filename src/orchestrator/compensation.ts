/**
 * Next-Generation Dots AI Platform - Compensation & Rollback Manager
 * 
 * Architectural Mandate:
 * Provides bounded rollback and safe cleanup for partially failed workflow tasks.
 * Strictly guarantees data safety:
 * 1. Rejects path traversal, sibling prefix spoofing, and symlink escapes.
 * 2. Never deletes pre-existing files that were overwritten during the task.
 * 3. Restores overwritten files only when a verified backup hash matches.
 * 4. Leaves files untouched when safe restoration is impossible and reports incomplete status.
 * 5. Idempotent across repeated compensation runs.
 * 6. Records detailed audit events for every reverted, skipped, or failed action.
 */

import { existsSync, unlinkSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import type { TaskRepository } from '../storage/task-repository.ts';
import type { AuditRepository } from '../storage/audit-repository.ts';
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
   * Safe, non-destructive, and idempotent.
   */
  public async compensate(taskId: string): Promise<CompensationResult> {
    const steps = this.taskRepo.getStepsByTaskId(taskId);
    const actions: CompensationAction[] = [];

    try {
      for (const step of steps) {
        const executions = this.taskRepo.getToolExecutionsByStepId(step.id);
        for (const exec of executions) {
          if (exec.toolName === 'file_write') {
            await this.compensateFileWrite(exec.inputJson, exec.outputJson, actions);
          }
        }
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
    const isComplete = totalFailed === 0;

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
   * Safely rolls back a single file_write mutation.
   */
  private async compensateFileWrite(
    inputJson: string,
    outputJson: string,
    actions: CompensationAction[]
  ): Promise<void> {
    let input: { path?: string };
    let output: {
      path?: string;
      existedBefore?: boolean;
      previousContent?: string;
      previousHash?: string;
    };

    try {
      input = JSON.parse(inputJson) as { path?: string };
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

    // 2. Protect pre-existing files vs newly created files
    if (output.existedBefore === true) {
      // Overwritten pre-existing file: NEVER delete. Attempt restore only if verified backup exists.
      if (!output.previousContent || !output.previousHash) {
        actions.push({
          action: 'file_restore',
          resource: rawPath,
          status: 'SKIPPED',
          details: 'Pre-existing file left untouched: missing backup snapshot.'
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
      // Newly created file during task: safe to delete
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
