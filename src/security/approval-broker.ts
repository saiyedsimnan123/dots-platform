/**
 * Next-Generation Dots AI Platform - Human Approval Broker
 * 
 * Architectural Mandate:
 * Coordinates Human-in-the-Loop (HITL) approval gates.
 * Pauses task execution, assigns cryptographic approval tokens, logs immutable
 * audit records, and resumes or aborts workflows based on explicit human decisions.
 */

import type { TaskRepository } from '../storage/task-repository.ts';
import type { AuditRepository } from '../storage/audit-repository.ts';
import type { ApprovalRequest, ApprovalDecision, RiskTier } from '../domain/types.ts';
import { ValidationError } from '../domain/errors.ts';

export interface RequestApprovalInput {
  readonly taskId: string;
  readonly stepId: string;
  readonly riskTier: RiskTier;
  readonly actionSummary: string;
  readonly targetResource: string;
  readonly parameterDiff: Record<string, unknown>;
  readonly expiresInMinutes?: number;
}

export class ApprovalBroker {
  private readonly taskRepo: TaskRepository;
  private readonly auditRepo?: AuditRepository;

  constructor(taskRepo: TaskRepository, auditRepo?: AuditRepository) {
    this.taskRepo = taskRepo;
    this.auditRepo = auditRepo;
  }

  /**
   * Generates a pending approval request and transitions the task to AWAITING_APPROVAL.
   */
  public requestApproval(input: RequestApprovalInput): ApprovalRequest {
    const minutes = input.expiresInMinutes ?? 10;
    const expiresAt = new Date(Date.now() + minutes * 60 * 1000).toISOString();

    const request = this.taskRepo.createApprovalRequest({
      taskId: input.taskId,
      stepId: input.stepId,
      riskTier: input.riskTier,
      actionSummary: input.actionSummary,
      targetResource: input.targetResource,
      parameterDiff: input.parameterDiff,
      expiresAt
    });

    // Log audit event
    if (this.auditRepo) {
      this.auditRepo.appendEvent({
        taskId: input.taskId,
        eventType: 'APPROVAL_REQUESTED',
        actor: 'POLICY_ENGINE',
        details: {
          approvalId: request.id,
          stepId: input.stepId,
          riskTier: input.riskTier,
          actionSummary: input.actionSummary,
          targetResource: input.targetResource,
          expiresAt
        }
      });
    }

    return request;
  }

  /**
   * Submits a human decision (APPROVED or REJECTED) for an active approval request.
   */
  public submitDecision(
    token: string,
    decision: 'APPROVED' | 'REJECTED',
    decidedBy: string
  ): ApprovalRequest {
    const existing = this.taskRepo.getApprovalRequestByToken(token);
    if (!existing) {
      throw new ValidationError(`Approval request token '${token}' is invalid or does not exist.`);
    }

    if (existing.decision !== 'PENDING') {
      throw new ValidationError(`Approval request '${existing.id}' has already been decided (${existing.decision}).`);
    }

    if (new Date(existing.expiresAt).getTime() < Date.now()) {
      this.taskRepo.updateApprovalDecision(existing.id, 'EXPIRED', decidedBy);
      throw new ValidationError(`Approval request '${existing.id}' has expired.`);
    }

    const updated = this.taskRepo.updateApprovalDecision(existing.id, decision, decidedBy);

    // Record audit event
    if (this.auditRepo) {
      this.auditRepo.appendEvent({
        taskId: existing.taskId,
        eventType: 'APPROVAL_DECIDED',
        actor: 'USER',
        details: {
          approvalId: existing.id,
          decision,
          decidedBy,
          decidedAt: updated.decidedAt
        }
      });
    }

    return updated;
  }

  /**
   * Checks whether an approval request token has been approved and is not expired.
   */
  public isApproved(token: string): boolean {
    const existing = this.taskRepo.getApprovalRequestByToken(token);
    if (!existing || existing.decision !== 'APPROVED') {
      return false;
    }
    return new Date(existing.expiresAt).getTime() >= Date.now();
  }
}
