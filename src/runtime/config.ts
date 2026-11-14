/**
 * Next-Generation Dots AI Platform - Runtime Configuration (Phase 8C)
 *
 * Architectural Mandate:
 * Loads operational configuration from environment variables and explicit overrides
 * with safe local defaults, strict validation, and zero external config dependencies.
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { randomBytes } from 'node:crypto';
import type { ScopeIdentifier } from '../domain/types.ts';
import type { UserRole } from '../security/memory-authorizer.ts';
import { validateScope } from '../security/memory-authorizer.ts';
import type { TokenPrincipalConfig } from '../security/token-identity-provider.ts';
import type { LogLevel } from './logger.ts';
import { ValidationError } from '../domain/errors.ts';

export type ConfiguredProviderMode = 'mock' | 'gemini';
export type ConfiguredWebSearchProviderMode = 'duckduckgo' | 'searxng' | 'mock' | 'none';

export interface DotsRuntimeConfig {
  readonly dbPath: string;
  readonly workspaceRoot: string;
  readonly host: string;
  readonly port: number;
  readonly hostSecret: string;
  readonly tokens: readonly TokenPrincipalConfig[];
  readonly provider: ConfiguredProviderMode;
  readonly geminiApiKey?: string;
  readonly geminiModelId: string;
  readonly logLevel: LogLevel;
  readonly silentLogs: boolean;
  readonly maxBodyBytes: number;
  readonly schedulerPollIntervalMs: number;
  readonly maxTaskBudgetUsd: number;
  readonly autoApproveTier2: boolean;
  readonly enableDynamicReplan: boolean;
  readonly enableCompensation: boolean;
  readonly enableScheduler: boolean;
  readonly maxConversationHistory: number;
  readonly webSearchProvider: ConfiguredWebSearchProviderMode;
  readonly searxngUrl?: string;
}

export interface LoadRuntimeConfigOverrides {
  readonly dbPath?: string;
  readonly workspaceRoot?: string;
  readonly host?: string;
  readonly port?: number;
  readonly hostSecret?: string;
  readonly tokens?: readonly TokenPrincipalConfig[];
  readonly provider?: ConfiguredProviderMode;
  readonly geminiApiKey?: string;
  readonly geminiModelId?: string;
  readonly logLevel?: LogLevel;
  readonly silentLogs?: boolean;
  readonly maxBodyBytes?: number;
  readonly schedulerPollIntervalMs?: number;
  readonly maxTaskBudgetUsd?: number;
  readonly autoApproveTier2?: boolean;
  readonly enableDynamicReplan?: boolean;
  readonly enableCompensation?: boolean;
  readonly enableScheduler?: boolean;
  readonly maxConversationHistory?: number;
  readonly webSearchProvider?: ConfiguredWebSearchProviderMode;
  readonly searxngUrl?: string;
  readonly requireTokens?: boolean;
  readonly env?: Record<string, string | undefined>;
}

const VALID_LOG_LEVELS: ReadonlySet<string> = new Set(['debug', 'info', 'warn', 'error']);
const VALID_ROLES: ReadonlySet<string> = new Set(['ADMIN', 'MEMBER', 'VIEWER']);

function parsePositiveInt(raw: string | undefined, fallback: number, name: string): number {
  if (raw === undefined || raw.trim() === '') {
    return fallback;
  }
  const num = Number(raw);
  if (!Number.isInteger(num) || num <= 0) {
    throw new ValidationError(`Configuration '${name}' must be a positive integer. Received '${raw}'.`);
  }
  return num;
}

function parsePositiveFloat(raw: string | undefined, fallback: number, name: string): number {
  if (raw === undefined || raw.trim() === '') {
    return fallback;
  }
  const num = Number(raw);
  if (!Number.isFinite(num) || num <= 0) {
    throw new ValidationError(`Configuration '${name}' must be a positive number. Received '${raw}'.`);
  }
  return num;
}

function parseBoolean(raw: string | undefined, fallback: boolean): boolean {
  if (raw === undefined || raw.trim() === '') {
    return fallback;
  }
  const lower = raw.trim().toLowerCase();
  if (lower === 'true' || lower === '1' || lower === 'yes') {
    return true;
  }
  if (lower === 'false' || lower === '0' || lower === 'no') {
    return false;
  }
  throw new ValidationError(`Boolean configuration value expected, received '${raw}'.`);
}

export function parseScopeSpec(spec: string): ScopeIdentifier {
  const trimmed = spec.trim();
  const idx = trimmed.indexOf(':');
  if (idx === -1) {
    throw new ValidationError(`Invalid scope '${spec}'. Expected 'GLOBAL:default' or 'WORKSPACE:<id>'.`);
  }
  const scopeType = trimmed.slice(0, idx) as ScopeIdentifier['scopeType'];
  const scopeId = trimmed.slice(idx + 1);
  validateScope(scopeType, scopeId);
  return { scopeType, scopeId };
}

export function parseTokenConfigsFromEnv(
  env: Record<string, string | undefined>
): TokenPrincipalConfig[] {
  const tokensJson = env.DOTS_TOKENS_JSON;
  if (tokensJson && tokensJson.trim() !== '') {
    let parsed: unknown;
    try {
      parsed = JSON.parse(tokensJson);
    } catch (err) {
      throw new ValidationError(
        `DOTS_TOKENS_JSON is not valid JSON: ${err instanceof Error ? err.message : String(err)}`
      );
    }
    if (!Array.isArray(parsed)) {
      throw new ValidationError('DOTS_TOKENS_JSON must be a JSON array of token configurations.');
    }
    return parsed as TokenPrincipalConfig[];
  }

  const singleToken = env.DOTS_API_TOKEN;
  if (singleToken && singleToken.trim() !== '') {
    const roleRaw = (env.DOTS_TOKEN_ROLE ?? 'ADMIN').trim().toUpperCase();
    if (!VALID_ROLES.has(roleRaw)) {
      throw new ValidationError(`Invalid DOTS_TOKEN_ROLE '${roleRaw}'. Must be ADMIN, MEMBER, or VIEWER.`);
    }

    const scopesRaw = env.DOTS_TOKEN_SCOPES;
    const permittedScopes: ScopeIdentifier[] =
      scopesRaw && scopesRaw.trim() !== ''
        ? scopesRaw.split(',').map((s) => parseScopeSpec(s))
        : [{ scopeType: 'GLOBAL', scopeId: 'default' }];

    return [
      {
        token: singleToken.trim(),
        principalId: (env.DOTS_TOKEN_PRINCIPAL ?? 'local-admin').trim() || 'local-admin',
        role: roleRaw as UserRole,
        permittedScopes
      }
    ];
  }

  return [];
}

export function resolveOrCreateHostSecret(dbPath: string, configuredSecret?: string): string {
  if (configuredSecret && configuredSecret.trim() !== '') {
    const trimmed = configuredSecret.trim();
    if (!/^[0-9a-fA-F]{64}$/.test(trimmed)) {
      throw new ValidationError('DOTS_HOST_SECRET must be a 64-character hexadecimal string (32 bytes).');
    }
    return trimmed;
  }

  if (dbPath === ':memory:') {
    return randomBytes(32).toString('hex');
  }

  const resolvedDb = resolve(dbPath);
  const dataDir = dirname(resolvedDb);
  mkdirSync(dataDir, { recursive: true });

  const secretPath = resolve(dataDir, '.dots-host-secret');
  if (existsSync(secretPath)) {
    const existing = readFileSync(secretPath, 'utf8').trim();
    if (/^[0-9a-fA-F]{64}$/.test(existing)) {
      return existing;
    }
  }

  const generated = randomBytes(32).toString('hex');
  writeFileSync(secretPath, `${generated}\n`, { encoding: 'utf8', mode: 0o600 });
  return generated;
}

export function loadRuntimeConfig(overrides: LoadRuntimeConfigOverrides = {}): DotsRuntimeConfig {
  const env = overrides.env ?? process.env;

  const dbPath = overrides.dbPath ?? (env.DOTS_DB_PATH?.trim() || resolve(process.cwd(), 'data', 'dots.db'));
  const workspaceRoot = resolve(overrides.workspaceRoot ?? (env.DOTS_WORKSPACE_ROOT?.trim() || process.cwd()));
  const host = overrides.host ?? (env.DOTS_HOST?.trim() || '127.0.0.1');
  const port = overrides.port ?? parsePositiveInt(env.DOTS_PORT, 3847, 'DOTS_PORT');

  const logLevelRaw = (overrides.logLevel ?? env.DOTS_LOG_LEVEL?.trim() ?? 'info').toLowerCase();
  if (!VALID_LOG_LEVELS.has(logLevelRaw)) {
    throw new ValidationError(`Invalid log level '${logLevelRaw}'. Must be debug, info, warn, or error.`);
  }

  const geminiApiKey = overrides.geminiApiKey ?? (env.GEMINI_API_KEY?.trim() || undefined);
  const providerRaw = (
    overrides.provider ??
    env.DOTS_PROVIDER?.trim() ??
    (geminiApiKey ? 'gemini' : 'mock')
  ).toLowerCase();

  if (providerRaw !== 'mock' && providerRaw !== 'gemini') {
    throw new ValidationError(`Invalid provider '${providerRaw}'. Must be 'mock' or 'gemini'.`);
  }
  if (providerRaw === 'gemini' && !geminiApiKey) {
    throw new ValidationError("Provider 'gemini' selected but GEMINI_API_KEY is not configured.");
  }

  const tokens = overrides.tokens ? [...overrides.tokens] : parseTokenConfigsFromEnv(env);
  if ((overrides.requireTokens ?? true) && tokens.length === 0) {
    throw new ValidationError(
      'No API tokens configured. Set DOTS_API_TOKEN (min 8 chars) or DOTS_TOKENS_JSON.'
    );
  }

  if (dbPath !== ':memory:') {
    mkdirSync(dirname(resolve(dbPath)), { recursive: true });
  }

  const hostSecret = resolveOrCreateHostSecret(dbPath, overrides.hostSecret ?? env.DOTS_HOST_SECRET);

  const webSearchProviderRaw = (
    overrides.webSearchProvider ??
    env.DOTS_WEB_SEARCH_PROVIDER?.trim() ??
    (env.DOTS_SEARXNG_URL ? 'searxng' : 'none')
  ).toLowerCase();

  const VALID_WEB_SEARCH_PROVIDERS: ReadonlySet<string> = new Set(['duckduckgo', 'searxng', 'mock', 'none']);
  if (!VALID_WEB_SEARCH_PROVIDERS.has(webSearchProviderRaw)) {
    throw new ValidationError(
      `Invalid web search provider '${webSearchProviderRaw}'. Must be 'duckduckgo', 'searxng', 'mock', or 'none'.`
    );
  }

  const searxngUrl = overrides.searxngUrl ?? (env.DOTS_SEARXNG_URL?.trim() || undefined);
  if (webSearchProviderRaw === 'searxng' && (!searxngUrl || searxngUrl.trim() === '')) {
    throw new ValidationError("Web search provider 'searxng' selected but DOTS_SEARXNG_URL is not configured.");
  }

  return {
    dbPath,
    workspaceRoot,
    host,
    port,
    hostSecret,
    tokens,
    provider: providerRaw as ConfiguredProviderMode,
    geminiApiKey,
    geminiModelId: overrides.geminiModelId ?? (env.GEMINI_MODEL_ID?.trim() || 'gemini-2.5-flash'),
    logLevel: logLevelRaw as LogLevel,
    silentLogs: overrides.silentLogs ?? false,
    maxBodyBytes: overrides.maxBodyBytes ?? parsePositiveInt(env.DOTS_MAX_BODY_BYTES, 1_048_576, 'DOTS_MAX_BODY_BYTES'),
    schedulerPollIntervalMs:
      overrides.schedulerPollIntervalMs ?? parsePositiveInt(env.DOTS_SCHEDULER_POLL_MS, 1000, 'DOTS_SCHEDULER_POLL_MS'),
    maxTaskBudgetUsd:
      overrides.maxTaskBudgetUsd ?? parsePositiveFloat(env.DOTS_MAX_TASK_BUDGET_USD, 0.5, 'DOTS_MAX_TASK_BUDGET_USD'),
    autoApproveTier2: overrides.autoApproveTier2 ?? parseBoolean(env.DOTS_AUTO_APPROVE_TIER2, true),
    enableDynamicReplan: overrides.enableDynamicReplan ?? parseBoolean(env.DOTS_ENABLE_DYNAMIC_REPLAN, false),
    enableCompensation: overrides.enableCompensation ?? parseBoolean(env.DOTS_ENABLE_COMPENSATION, true),
    enableScheduler: overrides.enableScheduler ?? parseBoolean(env.DOTS_ENABLE_SCHEDULER, true),
    maxConversationHistory:
      overrides.maxConversationHistory ??
      parsePositiveInt(env.DOTS_MAX_CONVERSATION_HISTORY, 50, 'DOTS_MAX_CONVERSATION_HISTORY'),
    webSearchProvider: webSearchProviderRaw as ConfiguredWebSearchProviderMode,
    searxngUrl
  };
}
