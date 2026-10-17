/**
 * Next-Generation Dots AI Platform - Security & Policy Engine
 * 
 * Architectural Mandate:
 * Enforces host-level security perimeters.
 * AI models are strictly untrusted entities. The policy engine validates
 * all proposed tool calls against risk tiers, canonicalizes file paths to prevent
 * traversal outside the jailed sandbox, and triggers human approval gates.
 */

import { resolve, relative, normalize } from 'node:path';
import type { RiskTier } from '../domain/types.ts';
import { SecurityViolationError } from '../domain/errors.ts';

export type PolicyDecision = 'ALLOWED' | 'REQUIRES_APPROVAL' | 'DENIED';

export interface PolicyEvaluationResult {
  readonly decision: PolicyDecision;
  readonly riskTier: RiskTier;
  readonly reason: string;
  readonly sanitizedArguments: Record<string, unknown>;
  readonly approvalRequired: boolean;
}

export interface PolicyEngineOptions {
  readonly workspaceRoot: string;
  readonly autoApproveTier2?: boolean;
}

export class PolicyEngine {
  public readonly workspaceRoot: string;
  private readonly autoApproveTier2: boolean;

  constructor(options: PolicyEngineOptions) {
    this.workspaceRoot = resolve(options.workspaceRoot);
    this.autoApproveTier2 = options.autoApproveTier2 ?? true;
  }

  /**
   * Evaluates a proposed tool call against safety policies and canonicalizes file arguments.
   */
  public evaluate(
    toolName: string,
    args: Record<string, unknown>,
    riskTier: RiskTier
  ): PolicyEvaluationResult {
    // 1. Sanitize file path arguments if present
    const sanitizedArgs: Record<string, unknown> = { ...args };

    for (const key of ['path', 'filePath', 'targetPath', 'file', 'target']) {
      if (typeof sanitizedArgs[key] === 'string') {
        sanitizedArgs[key] = this.sanitizePath(sanitizedArgs[key] as string);
      }
    }

    // 2. Evaluate risk tier
    switch (riskTier) {
      case 'TIER_0': // Pure compute
      case 'TIER_1': // Read-only safe inspection inside jailed sandbox
        return {
          decision: 'ALLOWED',
          riskTier,
          reason: `Auto-approved safe operation (${riskTier})`,
          sanitizedArguments: sanitizedArgs,
          approvalRequired: false
        };

      case 'TIER_2': // Reversible workspace write
        if (this.autoApproveTier2) {
          return {
            decision: 'ALLOWED',
            riskTier,
            reason: 'Auto-approved sandboxed workspace write',
            sanitizedArguments: sanitizedArgs,
            approvalRequired: false
          };
        }
        return {
          decision: 'REQUIRES_APPROVAL',
          riskTier,
          reason: 'Policy requires explicit approval for workspace mutations',
          sanitizedArguments: sanitizedArgs,
          approvalRequired: true
        };

      case 'TIER_3': // Consequential (network, external scripts)
        return {
          decision: 'REQUIRES_APPROVAL',
          riskTier,
          reason: `Consequential operation requires human sign-off (${toolName})`,
          sanitizedArguments: sanitizedArgs,
          approvalRequired: true
        };

      case 'TIER_4': // High-risk / Destructive
        return {
          decision: 'REQUIRES_APPROVAL',
          riskTier,
          reason: `High-risk destructive operation mandates human sign-off (${toolName})`,
          sanitizedArguments: sanitizedArgs,
          approvalRequired: true
        };

      default:
        return {
          decision: 'DENIED',
          riskTier,
          reason: `Unrecognized or unregistered risk tier: ${String(riskTier)}`,
          sanitizedArguments: sanitizedArgs,
          approvalRequired: false
        };
    }
  }

  /**
   * Canonicalizes an input file path and verifies that it resides strictly within the workspaceRoot.
   * Throws SecurityViolationError if path attempts directory traversal outside the jail.
   */
  public sanitizePath(inputPath: string): string {
    if (!inputPath || typeof inputPath !== 'string') {
      throw new SecurityViolationError(
        'File path argument must be a non-empty string.',
        'INVALID_PATH_ARGUMENT',
        { inputPath }
      );
    }

    // Resolve path against workspace root
    const resolvedPath = resolve(this.workspaceRoot, normalize(inputPath));
    const rel = relative(this.workspaceRoot, resolvedPath);

    // If relative path starts with '..' or is root drive traversal, reject
    if (rel.startsWith('..') || rel === '..' || resolvedPath.toLowerCase() === resolve(this.workspaceRoot, '..').toLowerCase()) {
      throw new SecurityViolationError(
        `Security Violation: Path traversal outside jailed sandbox detected ('${inputPath}').`,
        'PATH_TRAVERSAL_DETECTED',
        { inputPath, resolvedPath, workspaceRoot: this.workspaceRoot }
      );
    }

    return resolvedPath;
  }
}
