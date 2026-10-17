/**
 * Next-Generation Dots AI Platform - Compensation & Rollback Manager
 * 
 * Architectural Mandate:
 * Provides bounded rollback and cleanup for partially failed workflow tasks.
 * Ensures mutations within the jailed workspace are cleaned up on unrecoverable failure
 * when compensation is enabled, leaving no orphaned artifacts.
 */

import { existsSync, unlinkSync } from 'node:fs';
import { resolve, normalize } from 'node:path';
import type { TaskRepository } from '../storage/task-repository.ts';
import type { AuditRepository } from '../storage/audit-repository.ts';

export interface CompensationAction {
  readonly action: string;
  readonly resource: string;
  readonly status: 'REVERTED' | 'FAILED' | 'SKIPPED';
  readonly details?: string;
}

export interface CompensationResult {
  readonly taskId: string;
  readonly actions: readonly CompensationAction[];
  readonly totalReverted: number;
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
    this.workspaceRoot = normalize(resolve(workspaceRoot));
  }

  /**
   * Reverts mutations created by a failed task within the sandboxed workspace.
   */
  public async compensate(taskId: string): Promise<CompensationResult> {
    const steps = this.taskRepo.getStepsByTaskId(taskId);
    const actions: CompensationAction[] = [];

    for (const step of steps) {
      const executions = this.taskRepo.getToolExecutionsByStepId(step.id);
      for (const exec of executions) {
        if (exec.toolName === 'file_write') {
          const input = JSON.parse(exec.inputJson) as { path?: string };
          const filePath = input.path;
          if (!filePath) continue;

          const canonicalPath = normalize(resolve(filePath));

          // Ensure path is strictly inside workspaceRoot before deletion
          if (!canonicalPath.startsWith(this.workspaceRoot)) {
            actions.push({
              action: 'file_delete',
              resource: filePath,
              status: 'SKIPPED',
              details: 'File is outside workspace root; skipping for safety.'
            });
            continue;
          }

          if (existsSync(canonicalPath)) {
            try {
              unlinkSync(canonicalPath);
              actions.push({
                action: 'file_delete',
                resource: filePath,
                status: 'REVERTED'
              });
            } catch (err) {
              actions.push({
                action: 'file_delete',
                resource: filePath,
                status: 'FAILED',
                details: err instanceof Error ? err.message : String(err)
              });
            }
          }
        }
      }
    }

    const totalReverted = actions.filter((a) => a.status === 'REVERTED').length;

    this.auditRepo.appendEvent({
      taskId,
      eventType: 'COMPENSATION_EXECUTED',
      actor: 'SYSTEM',
      details: {
        actions,
        totalReverted
      }
    });

    return {
      taskId,
      actions,
      totalReverted
    };
  }
}
