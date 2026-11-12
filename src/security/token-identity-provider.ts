/**
 * Next-Generation Dots AI Platform - Token Identity Provider
 *
 * Architectural Mandate:
 * Implements TrustedIdentityProvider using constant-time SHA-256 digest comparison
 * to resolve authenticated principals, roles, and permitted workspace/global scopes.
 */

import { createHash, timingSafeEqual } from 'node:crypto';
import type { ScopeIdentifier } from '../domain/types.ts';
import type {
  TrustedIdentityProvider,
  AuthenticatedPrincipal,
  UserRole
} from '../security/memory-authorizer.ts';
import { validateScope } from '../security/memory-authorizer.ts';
import { ValidationError } from '../domain/errors.ts';

export interface TokenPrincipalConfig {
  readonly token: string;
  readonly principalId: string;
  readonly role: UserRole;
  readonly permittedScopes: readonly ScopeIdentifier[];
}

interface HashedTokenEntry {
  readonly digest: Buffer;
  readonly principal: AuthenticatedPrincipal;
}

const VALID_ROLES: ReadonlySet<UserRole> = new Set(['ADMIN', 'MEMBER', 'VIEWER']);

function hashToken(token: string): Buffer {
  return createHash('sha256').update(token, 'utf8').digest();
}

export class TokenIdentityProvider implements TrustedIdentityProvider {
  readonly #entries: readonly HashedTokenEntry[];

  constructor(configs: readonly TokenPrincipalConfig[]) {
    if (!Array.isArray(configs) || configs.length === 0) {
      throw new ValidationError('TokenIdentityProvider requires at least one configured token principal.');
    }

    const entries: HashedTokenEntry[] = [];
    for (const cfg of configs) {
      if (!cfg.token || typeof cfg.token !== 'string' || cfg.token.trim().length < 8) {
        throw new ValidationError('Configured API token must be a string of at least 8 characters.');
      }
      if (!cfg.principalId || typeof cfg.principalId !== 'string' || cfg.principalId.trim() === '') {
        throw new ValidationError('Configured token principalId must not be empty.');
      }
      if (!VALID_ROLES.has(cfg.role)) {
        throw new ValidationError(`Invalid role '${String(cfg.role)}' for principal '${cfg.principalId}'.`);
      }
      if (!Array.isArray(cfg.permittedScopes) || cfg.permittedScopes.length === 0) {
        throw new ValidationError(`Principal '${cfg.principalId}' must have at least one permitted scope.`);
      }

      const frozenScopes = Object.freeze(
        cfg.permittedScopes.map((s: ScopeIdentifier) => {
          validateScope(s.scopeType, s.scopeId);
          return Object.freeze({ scopeType: s.scopeType, scopeId: s.scopeId });
        })
      );

      entries.push({
        digest: hashToken(cfg.token),
        principal: Object.freeze({
          principalId: cfg.principalId.trim(),
          role: cfg.role,
          permittedScopes: frozenScopes
        })
      });
    }

    this.#entries = entries;
  }

  /**
   * Authenticates bearer/string credentials and returns the resolved principal or null.
   */
  public authenticate(credentials: unknown): AuthenticatedPrincipal | null {
    if (typeof credentials !== 'string' || credentials.trim() === '') {
      return null;
    }

    let rawToken = credentials.trim();
    if (rawToken.toLowerCase().startsWith('bearer ')) {
      rawToken = rawToken.slice(7).trim();
    }
    if (!rawToken) {
      return null;
    }

    const candidateDigest = hashToken(rawToken);

    let matched: AuthenticatedPrincipal | null = null;
    for (const entry of this.#entries) {
      if (
        entry.digest.length === candidateDigest.length &&
        timingSafeEqual(entry.digest, candidateDigest)
      ) {
        matched = entry.principal;
      }
    }

    return matched;
  }
}
