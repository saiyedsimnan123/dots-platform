/**
 * Next-Generation Dots AI Platform - Verification Subsystem
 * 
 * Architectural Mandate:
 * Enforces closed-loop verification and tangible evidence collection.
 * The platform NEVER relies on an AI model's assertion that a task was completed.
 * Host-level assertions test physical side effects (file existence, byte sizes,
 * cryptographic checksums, exit codes) before a step or task is certified as VERIFIED.
 */

import { existsSync, statSync, readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import type { TaskStep, ToolExecution, VerificationRecord } from '../domain/types.ts';
import type { TaskRepository } from '../storage/task-repository.ts';

export interface VerificationAssertion {
  readonly checkType: 'FILE_EXISTS' | 'HASH_MATCH' | 'FILE_NON_EMPTY' | 'EXIT_CODE_ZERO' | 'OUTPUT_KEY_EXISTS';
  readonly target: string;
  readonly expectedValue: string;
}

export interface VerificationOutcome {
  readonly passed: boolean;
  readonly checkType: string;
  readonly expectedValue: string;
  readonly actualValue: string;
  readonly evidenceData: Record<string, unknown>;
  readonly record?: VerificationRecord;
}

export class VerificationEngine {
  private readonly taskRepo?: TaskRepository;

  constructor(taskRepo?: TaskRepository) {
    this.taskRepo = taskRepo;
  }

  /**
   * Executes an independent host verification assertion against a step's execution outputs.
   */
  public verify(
    step: TaskStep,
    execution: ToolExecution,
    assertion: VerificationAssertion
  ): VerificationOutcome {
    let passed = false;
    let actualValue = '';
    const evidenceData: Record<string, unknown> = {
      stepId: step.id,
      executionId: execution.id,
      toolName: execution.toolName,
      assertion
    };

    switch (assertion.checkType) {
      case 'FILE_EXISTS': {
        const filePath = assertion.target;
        const exists = existsSync(filePath);
        passed = exists === (assertion.expectedValue.toLowerCase() === 'true');
        actualValue = String(exists);
        if (exists) {
          const stats = statSync(filePath);
          evidenceData.fileSize = stats.size;
          evidenceData.lastModified = stats.mtime.toISOString();
        }
        break;
      }

      case 'FILE_NON_EMPTY': {
        const filePath = assertion.target;
        if (!existsSync(filePath)) {
          passed = false;
          actualValue = 'FILE_NOT_FOUND';
        } else {
          const size = statSync(filePath).size;
          passed = size > 0;
          actualValue = `${size} bytes`;
          evidenceData.byteSize = size;
        }
        break;
      }

      case 'HASH_MATCH': {
        const filePath = assertion.target;
        if (!existsSync(filePath)) {
          passed = false;
          actualValue = 'FILE_NOT_FOUND';
        } else {
          const buffer = readFileSync(filePath);
          const calculatedHash = createHash('sha256').update(buffer).digest('hex');
          passed = calculatedHash.toLowerCase() === assertion.expectedValue.toLowerCase();
          actualValue = calculatedHash;
          evidenceData.calculatedHash = calculatedHash;
          evidenceData.expectedHash = assertion.expectedValue;
          evidenceData.byteSize = buffer.length;
        }
        break;
      }

      case 'EXIT_CODE_ZERO': {
        passed = execution.exitCode === 0;
        actualValue = String(execution.exitCode);
        evidenceData.exitCode = execution.exitCode;
        break;
      }

      case 'OUTPUT_KEY_EXISTS': {
        try {
          const parsed = JSON.parse(execution.outputJson) as Record<string, unknown>;
          passed = Object.prototype.hasOwnProperty.call(parsed, assertion.target);
          actualValue = passed ? 'KEY_PRESENT' : 'KEY_MISSING';
          evidenceData.outputKeys = Object.keys(parsed);
        } catch {
          passed = false;
          actualValue = 'INVALID_OUTPUT_JSON';
        }
        break;
      }

      default: {
        passed = false;
        actualValue = `UNKNOWN_CHECK_TYPE: ${String(assertion.checkType)}`;
      }
    }

    let record: VerificationRecord | undefined;
    if (this.taskRepo) {
      record = this.taskRepo.recordVerification({
        stepId: step.id,
        checkType: assertion.checkType,
        passed,
        expectedValue: assertion.expectedValue,
        actualValue,
        evidenceData
      });
    }

    return {
      passed,
      checkType: assertion.checkType,
      expectedValue: assertion.expectedValue,
      actualValue,
      evidenceData,
      record
    };
  }
}
