/**
 * Next-Generation Dots AI Platform - Structured Operational Logger
 *
 * Architectural Mandate:
 * Emits compact JSON operational logs to stdout/stderr while scrubbing secrets
 * and redacting credential fields before output.
 */

import { defaultSecretScrubber } from '../model/secret-scrubber.ts';

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

export interface LogEntry {
  readonly timestamp: string;
  readonly level: LogLevel;
  readonly component: string;
  readonly event: string;
  readonly details?: Record<string, unknown>;
}

const SENSITIVE_LOG_KEY_REGEX = /(?:token|secret|password|passphrase|passwd|apikey|api_key|privatekey|authorization|credential)/i;

function scrubLogValue(value: unknown, depth: number = 0): unknown {
  if (depth > 5) {
    return '[TRUNCATED]';
  }
  if (typeof value === 'string') {
    return defaultSecretScrubber.scrub(value);
  }
  if (Array.isArray(value)) {
    return value.map((item) => scrubLogValue(item, depth + 1));
  }
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (SENSITIVE_LOG_KEY_REGEX.test(k)) {
        out[k] = '[REDACTED]';
      } else {
        out[k] = scrubLogValue(v, depth + 1);
      }
    }
    return out;
  }
  return value;
}

const LEVEL_PRIORITY: Record<LogLevel, number> = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40
};

export interface OperationalLoggerOptions {
  readonly minLevel?: LogLevel;
  readonly silent?: boolean;
  readonly sink?: (entry: LogEntry) => void;
}

export class OperationalLogger {
  private readonly minLevel: LogLevel;
  private readonly silent: boolean;
  private readonly sink?: (entry: LogEntry) => void;

  constructor(options: OperationalLoggerOptions = {}) {
    this.minLevel = options.minLevel ?? 'info';
    this.silent = options.silent ?? false;
    this.sink = options.sink;
  }

  public log(
    level: LogLevel,
    component: string,
    event: string,
    details?: Record<string, unknown>
  ): void {
    if (LEVEL_PRIORITY[level] < LEVEL_PRIORITY[this.minLevel]) {
      return;
    }

    const scrubbedDetails = details
      ? (scrubLogValue(details) as Record<string, unknown>)
      : undefined;

    const entry: LogEntry = {
      timestamp: new Date().toISOString(),
      level,
      component,
      event: defaultSecretScrubber.scrub(event),
      ...(scrubbedDetails && Object.keys(scrubbedDetails).length > 0 ? { details: scrubbedDetails } : {})
    };

    if (this.sink) {
      this.sink(entry);
      return;
    }

    if (this.silent) {
      return;
    }

    const line = JSON.stringify(entry);
    if (level === 'error' || level === 'warn') {
      process.stderr.write(`${line}\n`);
    } else {
      process.stdout.write(`${line}\n`);
    }
  }

  public debug(component: string, event: string, details?: Record<string, unknown>): void {
    this.log('debug', component, event, details);
  }

  public info(component: string, event: string, details?: Record<string, unknown>): void {
    this.log('info', component, event, details);
  }

  public warn(component: string, event: string, details?: Record<string, unknown>): void {
    this.log('warn', component, event, details);
  }

  public error(component: string, event: string, details?: Record<string, unknown>): void {
    this.log('error', component, event, details);
  }
}
