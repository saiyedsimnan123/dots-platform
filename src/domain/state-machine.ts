/**
 * Next-Generation Dots AI Platform - Task State Machine
 * 
 * Architectural Mandate:
 * Enforces deterministic task lifecycle transitions. Task state transitions
 * are NEVER controlled directly by LLM outputs; they are validated in trusted
 * host application code before committing to SQLite.
 */

import type { TaskStatus } from './types.ts';
import { InvalidStateTransitionError } from './errors.ts';

/**
 * Valid directed state transitions in the task lifecycle.
 * Any transition not explicitly listed in this table is strictly forbidden.
 */
export const VALID_TRANSITIONS: Record<TaskStatus, readonly TaskStatus[]> = {
  SUBMITTED: ['PLANNING', 'CANCELLED'],
  PLANNING: ['AWAITING_APPROVAL', 'EXECUTING', 'FAILED', 'CANCELLED'],
  AWAITING_APPROVAL: ['EXECUTING', 'CANCELLED', 'TIMED_OUT'],
  EXECUTING: ['VERIFYING', 'RECOVERING', 'FAILED', 'CANCELLED'],
  VERIFYING: ['PLANNING', 'COMPLETED', 'RECOVERING', 'FAILED'],
  RECOVERING: ['EXECUTING', 'PLANNING', 'FAILED', 'CANCELLED'],
  COMPLETED: [],  // Terminal: immutable once completed
  FAILED: [],     // Terminal: immutable once failed
  CANCELLED: [],  // Terminal: immutable once cancelled
  TIMED_OUT: []   // Terminal: immutable once timed out
};

/**
 * Terminal states from which no further transitions are allowed.
 */
export const TERMINAL_STATES: ReadonlySet<TaskStatus> = new Set([
  'COMPLETED',
  'FAILED',
  'CANCELLED',
  'TIMED_OUT'
]);

export class TaskStateMachine {
  /**
   * Evaluates whether a proposed transition from `from` to `to` is legally permitted.
   */
  public static canTransition(from: TaskStatus, to: TaskStatus): boolean {
    const allowed = VALID_TRANSITIONS[from];
    if (!allowed) {
      return false;
    }
    return allowed.includes(to);
  }

  /**
   * Asserts that a state transition is legal.
   * Throws InvalidStateTransitionError if the transition is prohibited.
   */
  public static assertCanTransition(
    from: TaskStatus,
    to: TaskStatus,
    taskId?: string
  ): void {
    if (!this.canTransition(from, to)) {
      throw new InvalidStateTransitionError(from, to, taskId);
    }
  }

  /**
   * Returns true if the status is a terminal (final) state.
   */
  public static isTerminal(status: TaskStatus): boolean {
    return TERMINAL_STATES.has(status);
  }

  /**
   * Returns the list of permitted next states for the given status.
   */
  public static getAllowedNextStates(currentStatus: TaskStatus): readonly TaskStatus[] {
    return VALID_TRANSITIONS[currentStatus] ?? [];
  }
}
