import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  DatabaseManager,
  TaskRepository,
  AuditRepository,
  ScheduleRepository,
  TokenIdentityProvider,
  TaskCoordinator,
  TaskScheduler,
  ToolRegistry,
  standardTools,
  PolicyEngine,
  ApprovalBroker,
  VerificationEngine,
  TokenBudgetTracker,
  MockModelProvider
} from '../../src/index.ts';
import { HostMemoryAuthority } from '../../src/security/host-authority.ts';

function createSchedulerHarness(options: {
  dbPath?: string;
  workspaceRoot: string;
  hostSecret?: string;
  faultHooks?: ConstructorParameters<typeof TaskScheduler>[0]['_faultHooks'];
}) {
  const db = new DatabaseManager(options.dbPath ?? ':memory:');
  const taskRepo = new TaskRepository(db);
  const auditRepo = new AuditRepository(db);
  const scheduleRepo = new ScheduleRepository(db);
  const identityProvider = new TokenIdentityProvider([
    {
      token: 'admin-token-123456',
      principalId: 'admin-user',
      role: 'ADMIN',
      permittedScopes: [{ scopeType: 'WORKSPACE', scopeId: 'ws-1' }]
    },
    {
      token: 'ws2-token-1234567',
      principalId: 'ws2-user',
      role: 'ADMIN',
      permittedScopes: [{ scopeType: 'WORKSPACE', scopeId: 'ws-2' }]
    }
  ]);

  const hostAuthority = new HostMemoryAuthority({
    hostSecret: options.hostSecret ?? '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
    taskRepo,
    identityProvider
  });

  const toolRegistry = new ToolRegistry();
  for (const tool of standardTools) {
    toolRegistry.register(tool);
  }

  const mockProvider = new MockModelProvider();
  const approvalBroker = new ApprovalBroker(taskRepo, auditRepo);

  const coordinator = new TaskCoordinator({
    taskRepo,
    auditRepo,
    modelProvider: mockProvider,
    toolRegistry,
    policyEngine: new PolicyEngine({ workspaceRoot: options.workspaceRoot, autoApproveTier2: false }),
    approvalBroker,
    verifier: new VerificationEngine(),
    budgetTracker: new TokenBudgetTracker({ db }),
    workspaceRoot: options.workspaceRoot,
    hostAuthority,
    authorizer: hostAuthority.authorizer
  });

  const scheduler = new TaskScheduler({
    scheduleRepo,
    taskRepo,
    auditRepo,
    coordinator,
    authorizer: hostAuthority.authorizer,
    hostAuthority,
    pollIntervalMs: 1000,
    oneTimeMissedGraceMs: 5000,
    defaultMaxConsecutiveFailures: 3,
    _faultHooks: options.faultHooks
  });

  const ws1Caller = hostAuthority.authorizer.authorizeUser({ credentials: 'admin-token-123456' });
  const ws2Caller = hostAuthority.authorizer.authorizeUser({ credentials: 'ws2-token-1234567' });

  return {
    db,
    taskRepo,
    auditRepo,
    scheduleRepo,
    mockProvider,
    approvalBroker,
    coordinator,
    scheduler,
    ws1Caller,
    ws2Caller
  };
}

describe('Phase 8B: Persistent Scheduler Reliability & Recovery', () => {
  const dirs: string[] = [];

  afterEach(() => {
    while (dirs.length > 0) {
      rmSync(dirs.pop()!, { recursive: true, force: true });
    }
  });

  function mkWorkDir(): string {
    const d = mkdtempSync(join(tmpdir(), 'dots-p8b-'));
    dirs.push(d);
    return d;
  }

  it('executes ONE_TIME and INTERVAL schedules, enforces pause/resume/cancel and scope isolation', async () => {
    const dir = mkWorkDir();
    const h = createSchedulerHarness({ workspaceRoot: dir });

    try {
      const oneTime = h.scheduler.createSchedule(h.ws1Caller, {
        name: 'one-time-calc',
        goal: 'Compute 10 + 5',
        scheduleType: 'ONE_TIME',
        runAt: '2026-11-12T10:00:00.000Z'
      });

      // Scope isolation: ws2 cannot read or pause ws1 schedule
      assert.throws(() => h.scheduler.getSchedule(h.ws2Caller, oneTime.id));
      assert.throws(() => h.scheduler.pauseSchedule(h.ws2Caller, oneTime.id));
      assert.equal(h.scheduler.listSchedules(h.ws2Caller).length, 0);

      h.mockProvider.enqueuePlan([
        {
          stepOrder: 1,
          description: 'Calc',
          toolName: 'calculate',
          arguments: { expression: '10 + 5' },
          expectedOutcome: '15'
        }
      ]);

      await h.scheduler.tick(new Date('2026-11-12T10:00:01.000Z'));
      const completedOneTime = h.scheduler.getSchedule(h.ws1Caller, oneTime.id);
      assert.equal(completedOneTime.status, 'COMPLETED');
      assert.equal(completedOneTime.nextRunAt, null);

      const occs = h.scheduler.listOccurrences(h.ws1Caller, oneTime.id);
      assert.equal(occs.length, 1);
      assert.equal(occs[0]!.status, 'SUCCEEDED');

      // Database-level duplicate prevention: re-claiming same occurrence_key is rejected
      const dupClaim = h.scheduleRepo.tryClaimOccurrence({
        scheduleId: oneTime.id,
        occurrenceKey: occs[0]!.occurrenceKey,
        scheduledFor: occs[0]!.scheduledFor
      });
      assert.equal(dupClaim.claimed, false);
      if (!dupClaim.claimed) {
        assert.equal(dupClaim.reason, 'DUPLICATE_KEY');
      }

      // INTERVAL schedule with pause / resume / cancel
      const interval = h.scheduler.createSchedule(h.ws1Caller, {
        name: 'interval-calc',
        goal: 'Recurring calculation',
        scheduleType: 'INTERVAL',
        intervalMs: 60_000,
        startAt: '2026-11-12T10:05:00.000Z'
      });

      h.scheduler.pauseSchedule(h.ws1Caller, interval.id, 'Maintenance');
      await h.scheduler.tick(new Date('2026-11-12T10:06:00.000Z'));
      assert.equal(h.scheduler.listOccurrences(h.ws1Caller, interval.id).length, 0);

      h.scheduler.resumeSchedule(h.ws1Caller, interval.id, new Date('2026-11-12T10:06:00.000Z'));
      h.mockProvider.enqueuePlan([
        {
          stepOrder: 1,
          description: 'Calc interval',
          toolName: 'calculate',
          arguments: { expression: '4 * 4' },
          expectedOutcome: '16'
        }
      ]);
      await h.scheduler.tick(new Date('2026-11-12T10:07:05.000Z'));
      assert.equal(h.scheduler.listOccurrences(h.ws1Caller, interval.id).length, 1);

      const cancelled = h.scheduler.cancelSchedule(h.ws1Caller, interval.id);
      assert.equal(cancelled.status, 'CANCELLED');
    } finally {
      await h.scheduler.stop();
      h.db.close();
    }
  });

  it('handles missed-run policies (SKIP vs RUN_ONCE) and overlap prevention', async () => {
    const dir = mkWorkDir();
    const h = createSchedulerHarness({ workspaceRoot: dir });

    try {
      const skipSched = h.scheduler.createSchedule(h.ws1Caller, {
        name: 'missed-skip',
        goal: 'Skip missed slots',
        scheduleType: 'INTERVAL',
        intervalMs: 10_000,
        startAt: '2026-11-12T10:00:00.000Z',
        missedRunPolicy: 'SKIP'
      });

      await h.scheduler.tick(new Date('2026-11-12T10:00:35.000Z'));
      const skipOccs = h.scheduler.listOccurrences(h.ws1Caller, skipSched.id);
      assert.equal(skipOccs.length, 1);
      assert.equal(skipOccs[0]!.status, 'SKIPPED_MISSED');
      assert.equal(h.scheduler.getSchedule(h.ws1Caller, skipSched.id).nextRunAt, '2026-11-12T10:00:40.000Z');

      const runOnceSched = h.scheduler.createSchedule(h.ws1Caller, {
        name: 'missed-run-once',
        goal: 'Run once for missed intervals',
        scheduleType: 'INTERVAL',
        intervalMs: 10_000,
        startAt: '2026-11-12T10:00:00.000Z',
        missedRunPolicy: 'RUN_ONCE'
      });

      h.mockProvider.enqueuePlan([
        {
          stepOrder: 1,
          description: 'Run latest missed',
          toolName: 'calculate',
          arguments: { expression: '5 + 5' },
          expectedOutcome: '10'
        }
      ]);
      await h.scheduler.tick(new Date('2026-11-12T10:00:35.000Z'));
      const roOccs = h.scheduler.listOccurrences(h.ws1Caller, runOnceSched.id);
      assert.equal(roOccs.length, 1);
      assert.equal(roOccs[0]!.status, 'SUCCEEDED');
      assert.equal(roOccs[0]!.scheduledFor, '2026-11-12T10:00:30.000Z');
    } finally {
      await h.scheduler.stop();
      h.db.close();
    }

    // Separate harness for overlap prevention + human approval non-bypass
    const hApproval = createSchedulerHarness({ workspaceRoot: dir });
    try {
      const approvalSched = hApproval.scheduler.createSchedule(hApproval.ws1Caller, {
        name: 'approval-overlap',
        goal: 'Write file requiring approval',
        scheduleType: 'INTERVAL',
        intervalMs: 10_000,
        startAt: '2026-11-12T11:00:00.000Z'
      });

      hApproval.mockProvider.enqueuePlan([
        {
          stepOrder: 1,
          description: 'Write file',
          toolName: 'file_write',
          arguments: { path: 'sched.txt', content: 'requires human approval' },
          expectedOutcome: 'File written'
        }
      ]);

      // First tick triggers occurrence -> pauses at AWAITING_APPROVAL
      await hApproval.scheduler.tick(new Date('2026-11-12T11:00:01.000Z'));
      let occs = hApproval.scheduler.listOccurrences(hApproval.ws1Caller, approvalSched.id);
      assert.equal(occs.length, 1);
      assert.equal(occs[0]!.status, 'AWAITING_APPROVAL');
      const taskId = occs[0]!.taskId!;
      assert.equal(hApproval.taskRepo.getTaskById(taskId)!.status, 'AWAITING_APPROVAL');

      // Second tick at next interval: must NOT auto-approve AND must skip overlap
      await hApproval.scheduler.tick(new Date('2026-11-12T11:00:11.000Z'));
      occs = hApproval.scheduler.listOccurrences(hApproval.ws1Caller, approvalSched.id);
      assert.equal(hApproval.taskRepo.getTaskById(taskId)!.status, 'AWAITING_APPROVAL');
      assert.ok(occs.some((o) => o.status === 'SKIPPED_OVERLAP'));

      // Now explicitly approve as human, next tick resumes & completes!
      const approvals = hApproval.taskRepo.getApprovalRequestsByTaskId(taskId);
      assert.equal(approvals.length, 1);
      hApproval.approvalBroker.submitDecision(approvals[0]!.approvalToken, 'APPROVED', 'admin-user');

      await hApproval.scheduler.tick(new Date('2026-11-12T11:00:15.000Z'));
      assert.equal(hApproval.taskRepo.getTaskById(taskId)!.status, 'COMPLETED');
      const updatedOcc = hApproval.scheduleRepo.getOccurrenceByTaskId(taskId)!;
      assert.equal(updatedOcc.status, 'SUCCEEDED');
    } finally {
      await hApproval.scheduler.stop();
      hApproval.db.close();
    }
  });

  it('auto-pauses after maxConsecutiveFailures', async () => {
    const dir = mkWorkDir();
    const h = createSchedulerHarness({ workspaceRoot: dir });

    try {
      const sched = h.scheduler.createSchedule(h.ws1Caller, {
        name: 'flaky-interval',
        goal: 'Fail repeatedly',
        scheduleType: 'INTERVAL',
        intervalMs: 5000,
        startAt: '2026-11-12T12:00:00.000Z',
        maxConsecutiveFailures: 2
      });

      h.mockProvider.simulateFailureNext(new Error('Model outage 1'));
      await h.scheduler.tick(new Date('2026-11-12T12:00:01.000Z'));
      let state = h.scheduler.getSchedule(h.ws1Caller, sched.id);
      assert.equal(state.status, 'ACTIVE');
      assert.equal(state.consecutiveFailures, 1);

      h.mockProvider.simulateFailureNext(new Error('Model outage 2'));
      await h.scheduler.tick(new Date('2026-11-12T12:00:06.000Z'));
      state = h.scheduler.getSchedule(h.ws1Caller, sched.id);
      assert.equal(state.status, 'PAUSED');
      assert.equal(state.consecutiveFailures, 2);
      assert.ok(state.pausedReason?.includes('2 consecutive failures'));
    } finally {
      await h.scheduler.stop();
      h.db.close();
    }
  });

  it('recovers safely across all 5 crash interruption points without duplicate task creation', async () => {
    const dir = mkWorkDir();
    const dbPath = join(dir, 'crash.db');

    // Crash Case 2: crash right after claim (before task create)
    const h1 = createSchedulerHarness({
      dbPath,
      workspaceRoot: dir,
      faultHooks: {
        afterClaim: () => {
          throw new Error('CRASH_AFTER_CLAIM');
        }
      }
    });
    const s1 = h1.scheduler.createSchedule(h1.ws1Caller, {
      name: 'crash-after-claim',
      goal: 'Recover from claim',
      scheduleType: 'ONE_TIME',
      runAt: '2026-11-12T13:00:00.000Z'
    });
    await assert.rejects(() => h1.scheduler.tick(new Date('2026-11-12T13:00:01.000Z')), /CRASH_AFTER_CLAIM/);
    h1.db.close();

    const h1Recovered = createSchedulerHarness({ dbPath, workspaceRoot: dir });
    h1Recovered.mockProvider.enqueuePlan([
      {
        stepOrder: 1,
        description: 'Calc',
        toolName: 'calculate',
        arguments: { expression: '1 + 1' },
        expectedOutcome: '2'
      }
    ]);
    await h1Recovered.scheduler.recoverInterruptedOccurrences(new Date('2026-11-12T13:00:02.000Z'));
    assert.equal(h1Recovered.scheduler.getSchedule(h1Recovered.ws1Caller, s1.id).status, 'COMPLETED');
    assert.equal(h1Recovered.scheduler.listOccurrences(h1Recovered.ws1Caller, s1.id).length, 1);
    h1Recovered.db.close();

    // Crash Case 3: crash right after task creation (before occurrence link)
    const h2 = createSchedulerHarness({
      dbPath,
      workspaceRoot: dir,
      faultHooks: {
        afterTaskCreate: () => {
          throw new Error('CRASH_AFTER_TASK_CREATE');
        }
      }
    });
    const s2 = h2.scheduler.createSchedule(h2.ws1Caller, {
      name: 'crash-after-task-create',
      goal: 'Recover without duplicate task',
      scheduleType: 'ONE_TIME',
      runAt: '2026-11-12T13:05:00.000Z'
    });
    await assert.rejects(() => h2.scheduler.tick(new Date('2026-11-12T13:05:01.000Z')), /CRASH_AFTER_TASK_CREATE/);
    h2.db.close();

    const h2Recovered = createSchedulerHarness({ dbPath, workspaceRoot: dir });
    const countTasksBefore = h2Recovered.taskRepo.listTasks({ limit: 100 }).length;
    h2Recovered.mockProvider.enqueuePlan([
      {
        stepOrder: 1,
        description: 'Calc',
        toolName: 'calculate',
        arguments: { expression: '2 + 3' },
        expectedOutcome: '5'
      }
    ]);
    await h2Recovered.scheduler.recoverInterruptedOccurrences(new Date('2026-11-12T13:05:02.000Z'));
    const countTasksAfter = h2Recovered.taskRepo.listTasks({ limit: 100 }).length;
    assert.equal(countTasksAfter, countTasksBefore); // Zero duplicate tasks!
    assert.equal(h2Recovered.scheduler.getSchedule(h2Recovered.ws1Caller, s2.id).status, 'COMPLETED');
    h2Recovered.db.close();

    // Crash Case 5: crash after task completion, before occurrence finalization
    const h3 = createSchedulerHarness({
      dbPath,
      workspaceRoot: dir,
      faultHooks: {
        beforeFinalize: () => {
          throw new Error('CRASH_BEFORE_FINALIZE');
        }
      }
    });
    const s3 = h3.scheduler.createSchedule(h3.ws1Caller, {
      name: 'crash-before-finalize',
      goal: 'Finalize completed task on restart',
      scheduleType: 'ONE_TIME',
      runAt: '2026-11-12T13:10:00.000Z'
    });
    h3.mockProvider.enqueuePlan([
      {
        stepOrder: 1,
        description: 'Calc',
        toolName: 'calculate',
        arguments: { expression: '8 + 8' },
        expectedOutcome: '16'
      }
    ]);
    await assert.rejects(() => h3.scheduler.tick(new Date('2026-11-12T13:10:01.000Z')), /CRASH_BEFORE_FINALIZE/);
    h3.db.close();

    const h3Recovered = createSchedulerHarness({ dbPath, workspaceRoot: dir });
    await h3Recovered.scheduler.recoverInterruptedOccurrences(new Date('2026-11-12T13:10:02.000Z'));
    assert.equal(h3Recovered.scheduler.getSchedule(h3Recovered.ws1Caller, s3.id).status, 'COMPLETED');
    assert.equal(h3Recovered.scheduler.listOccurrences(h3Recovered.ws1Caller, s3.id)[0]!.status, 'SUCCEEDED');

    // Crash Case 4: crash while task is mid-execution (EXECUTING task + EXECUTING step)
    const s4 = h3Recovered.scheduler.createSchedule(h3Recovered.ws1Caller, {
      name: 'crash-mid-execution',
      goal: 'Recover mid-execution step',
      scheduleType: 'ONE_TIME',
      runAt: '2026-11-12T13:15:00.000Z'
    });
    const claimed4 = h3Recovered.scheduleRepo.tryClaimOccurrence({
      scheduleId: s4.id,
      occurrenceKey: `once:${s4.runAt!}`,
      scheduledFor: s4.runAt!
    });
    assert.equal(claimed4.claimed, true);
    if (claimed4.claimed) {
      const taskId = `sched_${claimed4.occurrence.id}`;
      // Create task in EXECUTING state with an EXECUTING step
      h3Recovered.db.prepare(`
        INSERT INTO tasks (id, goal, status, current_step_index, created_at, updated_at)
        VALUES (?, ?, 'EXECUTING', 0, ?, ?)
      `).run(taskId, s4.goal, '2026-11-12T13:15:00.000Z', '2026-11-12T13:15:00.000Z');
      h3Recovered.taskRepo.createStep({
        taskId,
        stepOrder: 1,
        description: 'Interrupted calc',
        toolName: 'calculate',
        toolArguments: { expression: '9 + 1' }
      });
      const step = h3Recovered.taskRepo.getStepsByTaskId(taskId)[0]!;
      h3Recovered.taskRepo.updateStepStatus(step.id, 'EXECUTING');
      h3Recovered.scheduleRepo.linkTaskToOccurrence(claimed4.occurrence.id, taskId, 'RUNNING');
    }

    h3Recovered.db.close();

    const h4Recovered = createSchedulerHarness({ dbPath, workspaceRoot: dir });
    await h4Recovered.scheduler.recoverInterruptedOccurrences(new Date('2026-11-12T13:15:05.000Z'));
    assert.equal(h4Recovered.scheduler.getSchedule(h4Recovered.ws1Caller, s4.id).status, 'COMPLETED');
    assert.equal(h4Recovered.scheduler.listOccurrences(h4Recovered.ws1Caller, s4.id)[0]!.status, 'SUCCEEDED');
    h4Recovered.db.close();
  });
});
