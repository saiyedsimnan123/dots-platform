/**
 * Next-Generation Dots AI Platform - Scoped Runtime Event Bus
 *
 * Architectural Mandate:
 * Broadcasts real-time operational events (tasks, approvals, schedules) to SSE
 * subscribers while enforcing strict scope isolation and secret scrubbing.
 */

import { randomUUID } from 'node:crypto';
import type { ScopeIdentifier } from '../domain/types.ts';
import { defaultSecretScrubber } from '../model/secret-scrubber.ts';

export type RuntimeEventType =
  | 'task.created'
  | 'task.updated'
  | 'approval.requested'
  | 'approval.decided'
  | 'schedule.created'
  | 'schedule.updated'
  | 'occurrence.updated';

export interface RuntimeEvent {
  readonly id: string;
  readonly type: RuntimeEventType;
  readonly timestamp: string;
  readonly scope: ScopeIdentifier;
  readonly taskId?: string;
  readonly scheduleId?: string;
  readonly data: Record<string, unknown>;
}

export type RuntimeEventListener = (event: RuntimeEvent) => void;

function scrubPayload(value: unknown): unknown {
  if (typeof value === 'string') {
    return defaultSecretScrubber.scrub(value);
  }
  if (Array.isArray(value)) {
    return value.map((item) => scrubPayload(item));
  }
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (k === 'approvalToken' || k === '_scopeAttestation' || k === '_proof') {
        continue;
      }
      out[k] = scrubPayload(v);
    }
    return out;
  }
  return value;
}

export class RuntimeEventBus {
  private readonly listeners: Set<RuntimeEventListener> = new Set();

  public subscribe(listener: RuntimeEventListener): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  public emit(params: {
    readonly type: RuntimeEventType;
    readonly scope: ScopeIdentifier;
    readonly taskId?: string;
    readonly scheduleId?: string;
    readonly data: Record<string, unknown>;
  }): RuntimeEvent {
    const event: RuntimeEvent = {
      id: randomUUID(),
      type: params.type,
      timestamp: new Date().toISOString(),
      scope: {
        scopeType: params.scope.scopeType,
        scopeId: params.scope.scopeId
      },
      ...(params.taskId ? { taskId: params.taskId } : {}),
      ...(params.scheduleId ? { scheduleId: params.scheduleId } : {}),
      data: scrubPayload(params.data) as Record<string, unknown>
    };

    for (const listener of this.listeners) {
      try {
        listener(event);
      } catch {
        // Never allow a slow or failed SSE listener to break core execution
      }
    }

    return event;
  }

  public get subscriberCount(): number {
    return this.listeners.size;
  }
}
