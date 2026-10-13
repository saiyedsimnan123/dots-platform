/**
 * Next-Generation Dots AI Platform - Crash Recovery Engine
 * 
 * Architectural Mandate:
 * Guarantees state rehydration and clean reconciliation after abrupt process
 * termination (kill -9, power loss, or unhandled exception).
 * 
 * On boot, this engine scans SQLite for active tasks that were left in non-terminal
 * executing/planning states, logs audit records, and transitions tasks to
 * RECOVERING or FAILED within bounded limits.
 */

import { TaskRepository } from './task-repository.ts';
import { AuditRepository } from './audit-repository.ts';
import type { TaskStatus } from '../domain/types.ts';

export interface ReconciledTaskResult {
  readonly taskId: string;
  readonly previousStatus: TaskStatus;
  readonly newStatus: TaskStatus;
  readonly actionTaken: string;
}

export interface RecoveryReport {
  readonly scannedCount: number;
  readonly reconciledTasks: ReconciledTaskResult[];
}

export class CrashRecoveryEngine {
  private readonly taskRepo: TaskRepository;
  private readonly auditRepo: AuditRepository;

  constructor(taskRepo: TaskRepository, auditRepo: AuditRepository) {
    this.taskRepo = taskRepo;
    this.auditRepo = auditRepo;
  }

  /**
   * Reconciles all interrupted tasks upon application startup.
   */
  public reconcileInterruptedTasks(): RecoveryReport {
    const activeStatuses: TaskStatus[] = [
      'PLANNING',
      'EXECUTING',
      'VERIFYING',
      'RECOVERING'
    ];

    const results: ReconciledTaskResult[] = [];
    const processedTaskIds = new Set<string>();
    let scannedCount = 0;

    for (const status of activeStatuses) {
      const tasks = this.taskRepo.listTasks({ status, limit: 100 });

      for (const task of tasks) {
        if (processedTaskIds.has(task.id)) {
          continue;
        }
        processedTaskIds.add(task.id);
        scannedCount++;

        const steps = this.taskRepo.getStepsByTaskId(task.id);
        const latestStep = steps.length > 0 ? steps[steps.length - 1] : null;

        if (latestStep && latestStep.status === 'EXECUTING') {
          // The process was abruptly terminated while a tool was executing
          if (latestStep.retryCount < latestStep.maxRetries) {
            const nextRetry = latestStep.retryCount + 1;
            this.taskRepo.updateStepStatus(latestStep.id, 'FAILED', nextRetry);
            
            const updatedTask = this.taskRepo.updateTaskStatus(
              task.id,
              task.status,
              'RECOVERING',
              `Process interrupted during step ${latestStep.stepOrder} execution. Recovery scheduled (retry ${nextRetry}/${latestStep.maxRetries}).`
            );

            this.auditRepo.appendEvent({
              taskId: task.id,
              eventType: 'CRASH_INTERRUPTION_DETECTED',
              actor: 'SYSTEM',
              details: {
                previousStatus: task.status,
                newStatus: updatedTask.status,
                interruptedStepId: latestStep.id,
                retryCount: nextRetry,
                maxRetries: latestStep.maxRetries
              }
            });

            results.push({
              taskId: task.id,
              previousStatus: task.status,
              newStatus: updatedTask.status,
              actionTaken: `Step ${latestStep.stepOrder} marked for bounded retry ${nextRetry}/${latestStep.maxRetries}.`
            });
          } else {
            // Retries exhausted on crash
            this.taskRepo.updateStepStatus(latestStep.id, 'FAILED');
            
            const updatedTask = this.taskRepo.updateTaskStatus(
              task.id,
              task.status,
              'FAILED',
              `Process interrupted during step ${latestStep.stepOrder} execution. Max retries exhausted.`
            );

            this.auditRepo.appendEvent({
              taskId: task.id,
              eventType: 'CRASH_INTERRUPTION_DETECTED',
              actor: 'SYSTEM',
              details: {
                previousStatus: task.status,
                newStatus: updatedTask.status,
                interruptedStepId: latestStep.id,
                reason: 'MAX_RETRIES_EXHAUSTED_AFTER_CRASH'
              }
            });

            results.push({
              taskId: task.id,
              previousStatus: task.status,
              newStatus: updatedTask.status,
              actionTaken: `Task marked FAILED because step ${latestStep.stepOrder} exhausted retries.`
            });
          }
        } else {
          // Task was in PLANNING or RECOVERING with no running step
          const updatedTask = this.taskRepo.updateTaskStatus(
            task.id,
            task.status,
            'FAILED',
            'Process interrupted during planning/coordination phase.'
          );

          this.auditRepo.appendEvent({
            taskId: task.id,
            eventType: 'CRASH_INTERRUPTION_DETECTED',
            actor: 'SYSTEM',
            details: {
              previousStatus: task.status,
              newStatus: updatedTask.status,
              reason: 'PROCESS_TERMINATION_DURING_COORDINATION'
            }
          });

          results.push({
            taskId: task.id,
            previousStatus: task.status,
            newStatus: updatedTask.status,
            actionTaken: 'Interrupted coordination marked FAILED.'
          });
        }
      }
    }

    return {
      scannedCount,
      reconciledTasks: results
    };
  }
}
