/**
 * Next-Generation Dots AI Platform - Task State Machine Unit Tests
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { TaskStateMachine, VALID_TRANSITIONS, TERMINAL_STATES } from '../../src/domain/state-machine.ts';
import type { TaskStatus } from '../../src/domain/types.ts';
import { InvalidStateTransitionError } from '../../src/domain/errors.ts';

test('TaskStateMachine - allows all valid directed transitions', () => {
  for (const [fromState, allowedNext] of Object.entries(VALID_TRANSITIONS)) {
    for (const toState of allowedNext) {
      assert.equal(
        TaskStateMachine.canTransition(fromState as TaskStatus, toState),
        true,
        `Expected valid transition: ${fromState} -> ${toState}`
      );
      assert.doesNotThrow(() => {
        TaskStateMachine.assertCanTransition(fromState as TaskStatus, toState, 'test-task-1');
      });
    }
  }
});

test('TaskStateMachine - strictly rejects illegal transitions', () => {
  const illegalPairs: Array<[TaskStatus, TaskStatus]> = [
    ['SUBMITTED', 'COMPLETED'],
    ['SUBMITTED', 'EXECUTING'],
    ['SUBMITTED', 'VERIFYING'],
    ['PLANNING', 'COMPLETED'],
    ['AWAITING_APPROVAL', 'PLANNING'],
    ['EXECUTING', 'SUBMITTED'],
    ['EXECUTING', 'COMPLETED'], // must go through VERIFYING first!
    ['VERIFYING', 'SUBMITTED'],
    ['COMPLETED', 'PLANNING'],
    ['COMPLETED', 'EXECUTING'],
    ['FAILED', 'EXECUTING'],
    ['FAILED', 'RECOVERING'],
    ['CANCELLED', 'SUBMITTED'],
    ['TIMED_OUT', 'PLANNING']
  ];

  for (const [fromState, toState] of illegalPairs) {
    assert.equal(
      TaskStateMachine.canTransition(fromState, toState),
      false,
      `Expected illegal transition to be rejected: ${fromState} -> ${toState}`
    );

    assert.throws(
      () => {
        TaskStateMachine.assertCanTransition(fromState, toState, 'test-task-id');
      },
      (err: unknown) => {
        assert(err instanceof InvalidStateTransitionError);
        assert.equal(err.fromStatus, fromState);
        assert.equal(err.toStatus, toState);
        assert.equal(err.code, 'INVALID_STATE_TRANSITION');
        return true;
      }
    );
  }
});

test('TaskStateMachine - correctly identifies terminal states', () => {
  const terminalList: TaskStatus[] = ['COMPLETED', 'FAILED', 'CANCELLED', 'TIMED_OUT'];
  for (const status of terminalList) {
    assert.equal(TaskStateMachine.isTerminal(status), true, `Expected ${status} to be terminal`);
    assert.equal(TERMINAL_STATES.has(status), true);
    assert.deepEqual(TaskStateMachine.getAllowedNextStates(status), []);
  }

  const activeList: TaskStatus[] = [
    'SUBMITTED',
    'PLANNING',
    'AWAITING_APPROVAL',
    'EXECUTING',
    'VERIFYING',
    'RECOVERING'
  ];
  for (const status of activeList) {
    assert.equal(TaskStateMachine.isTerminal(status), false, `Expected ${status} to NOT be terminal`);
    assert.notDeepEqual(TaskStateMachine.getAllowedNextStates(status), []);
  }
});
