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

// Security & Policy Layer
export * from './security/policy-engine.ts';
export * from './security/approval-broker.ts';

// Tool Capabilities & Sandboxing
export type * from './tools/types.ts';
export * from './tools/sandbox-tools.ts';
export * from './tools/registry.ts';

// Verification Subsystem
export * from './verification/verifier.ts';

// Memory Subsystem
export * from './memory/relevance-matcher.ts';
export * from './memory/context-builder.ts';

// Orchestration Layer
export * from './orchestrator/coordinator.ts';
