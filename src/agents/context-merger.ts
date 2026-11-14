/**
 * Next-Generation Dots AI Platform - Agent Context Merger
 * Phase 4B.1: Pre-Execution Memory Injection
 * 
 * Architectural Mandate:
 * Implements a safe, deterministic context merging strategy for modern agent executions.
 * 
 * Guarantees:
 * 1. Preserves original user-provided task context and agent-specific context in their entirety.
 * 2. Injects retrieved long-term memory under explicit, untrusted boundary markers.
 * 3. Enforces that untrusted memory cannot override system instructions, security policies,
 *    tool permissions, approval requirements, or user's task instructions.
 * 4. Strictly avoids duplicate context injection.
 * 5. Enforces context length limits (default 32,000 characters) without silently truncating
 *    user instructions to make room for memories.
 */

import type { BuiltMemoryContext } from '../domain/types.ts';
import {
  MEMORY_CONTEXT_SECURITY_BOUNDARY,
  MEMORY_CONTEXT_SECURITY_BOUNDARY_END,
  MEMORY_CONTEXT_SECURITY_NOTICE
} from '../memory/context-builder.ts';

export const USER_CONTEXT_SECTION_HEADER = '=== BEGIN USER INSTRUCTIONS & TASK CONTEXT ===';
export const USER_CONTEXT_SECTION_FOOTER = '=== END USER INSTRUCTIONS & TASK CONTEXT ===';

export const DEFAULT_MAX_CONTEXT_CHARS = 32_000;

export interface InjectedMemoryContextData {
  readonly serialized: string;
  readonly recordCount: number;
  readonly totalChars: number;
  readonly estimatedTokens: number;
  readonly memoryIds: readonly string[];
}

export interface MergeAgentContextOptions {
  /**
   * Original user-provided task context.
   */
  readonly userContext?: Readonly<Record<string, unknown>>;

  /**
   * Bounded memory context retrieved from MemoryService.
   */
  readonly memoryContext?: BuiltMemoryContext;

  /**
   * Maximum allowed character count for formatted context.
   * Defaults to 32,000 chars.
   */
  readonly maxContextChars?: number;
}

/**
 * Safely merges user-provided task context with authorized, untrusted memory context.
 */
export function mergeAgentContext(
  options: MergeAgentContextOptions
): Readonly<Record<string, unknown>> | undefined {
  const { userContext, memoryContext, maxContextChars = DEFAULT_MAX_CONTEXT_CHARS } = options;

  // 1. If memory was already injected, return userContext as-is to avoid duplicate context injection
  if (userContext?._memoryInjected === true) {
    return userContext;
  }

  // 2. If no memory context or zero memories were included, return original user context untouched
  if (!memoryContext || memoryContext.included.length === 0) {
    return userContext;
  }

  // 3. Prepare structured memory metadata block
  const memoryBlock: InjectedMemoryContextData = {
    serialized: memoryContext.serializedContext,
    recordCount: memoryContext.included.length,
    totalChars: memoryContext.totalChars,
    estimatedTokens: memoryContext.estimatedTokens,
    memoryIds: memoryContext.included.map((m) => m.id)
  };

  // 4. Format user instructions and untrusted memory with clear section boundaries
  let userContextText = '';
  if (userContext) {
    // Exclude internal markers if any
    const sanitizedUserEntries = Object.entries(userContext).filter(
      ([k]) => !k.startsWith('_')
    );
    if (sanitizedUserEntries.length > 0) {
      userContextText = JSON.stringify(Object.fromEntries(sanitizedUserEntries), null, 2);
    }
  }

  const sections: string[] = [];
  if (userContextText) {
    sections.push(
      `${USER_CONTEXT_SECTION_HEADER}\n${userContextText}\n${USER_CONTEXT_SECTION_FOOTER}`
    );
  }

  // Append untrusted memory context
  sections.push(memoryContext.serializedContext);
  const formattedCandidate = sections.join('\n\n');

  // 5. Enforce context size limits without silently truncating user instructions
  let finalFormatted: string | undefined = formattedCandidate;
  let finalMemoryBlock: InjectedMemoryContextData | undefined = memoryBlock;

  if (formattedCandidate.length > maxContextChars) {
    // User instructions must NEVER be truncated to make room for memories.
    // If the combined context exceeds limits, omit the memory block.
    if (userContextText.length > maxContextChars) {
      finalFormatted = `${USER_CONTEXT_SECTION_HEADER}\n${userContextText.slice(0, maxContextChars)}\n${USER_CONTEXT_SECTION_FOOTER}`;
      finalMemoryBlock = undefined;
    } else {
      finalFormatted = userContextText
        ? `${USER_CONTEXT_SECTION_HEADER}\n${userContextText}\n${USER_CONTEXT_SECTION_FOOTER}`
        : undefined;
      finalMemoryBlock = undefined;
    }
  }

  // 6. Build the merged context dictionary preserving all user fields
  const merged: Record<string, unknown> = {
    ...(userContext ?? {}),
    ...(finalMemoryBlock ? { memoryContext: finalMemoryBlock } : {}),
    ...(finalFormatted ? { formattedContext: finalFormatted } : {}),
    _memoryInjected: true
  };

  return Object.freeze(merged);
}
