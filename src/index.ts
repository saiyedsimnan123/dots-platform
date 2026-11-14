/**
 * Next-Generation Dots AI Platform - Core Exports
 * Phase 2, 3, 4, 5 Baseline
 */

// Domain Layer
export type * from './domain/types.ts';
export * from './domain/errors.ts';
export * from './domain/state-machine.ts';

// Storage Layer
export * from './storage/db.ts';
export * from './storage/task-repository.ts';
export * from './storage/audit-repository.ts';
export * from './storage/recovery.ts';
export * from './storage/memory-repository.ts';

// Model Gateway & Intelligence Layer
export type * from './model/types.ts';
export * from './model/secret-scrubber.ts';
export * from './model/prompt-compiler.ts';
export * from './model/mock-provider.ts';
export * from './model/gemini-provider.ts';
export * from './model/budget-tracker.ts';

// Security & Policy Layer (Unprivileged Public Surface)
// Note: Privileged host authority construction (HostMemoryAuthority) is internal to the host bootstrap
// module (./security/host-authority.ts) and is intentionally not exported from this public package entry point.
export * from './security/policy-engine.ts';
export * from './security/approval-broker.ts';
export {
  MemoryAuthorizer,
  type MemoryAuthorizerOptions,
  type UserRole,
  type AuthenticatedPrincipal,
  type TrustedIdentityProvider,
  type AuthorizeUserInput,
  type AuthorizeAgentInput,
  type TaskScopeAttestation
} from './security/memory-authorizer.ts';

// Tool Capabilities & Sandboxing
export type * from './tools/types.ts';
export * from './tools/sandbox-tools.ts';
export * from './tools/registry.ts';
export * from './tools/memory-tools.ts';
export * from './tools/web-tools.ts';

// Verification Subsystem
export * from './verification/verifier.ts';

// Memory Subsystem
export * from './memory/relevance-matcher.ts';
export * from './memory/context-builder.ts';
export * from './memory/memory-service.ts';
export * from './memory/canonical-json.ts';

// Orchestration Layer
export * from './orchestrator/coordinator.ts';

// Agent Architecture Layer (Milestone 1C)
export type * from './agents/types.ts';
export * from './agents/context.ts';
export * from './agents/base-agent.ts';
export * from './agents/registry.ts';
export * from './agents/research-agent.ts';

// Phase 8: Persistent Scheduler, Runtime, API & CLI
export * from './storage/schedule-repository.ts';
export * from './scheduler/task-scheduler.ts';
export * from './security/token-identity-provider.ts';
export * from './runtime/event-bus.ts';
export * from './runtime/logger.ts';
export * from './runtime/config.ts';
export * from './runtime/app.ts';
export * from './api/http-server.ts';
export { runCli, type CliIo } from './cli/main.ts';

// Milestone 2A: Persistent Conversation System
export * from './storage/conversation-repository.ts';
export * from './conversation/conversation-service.ts';

// Milestone 2B: Business Task Workflows
export * from './tasks/index.ts';
