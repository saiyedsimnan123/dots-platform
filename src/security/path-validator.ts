/**
 * Next-Generation Dots AI Platform - Path Containment Validator
 * 
 * Architectural Mandate:
 * Enforces strict filesystem jail containment.
 * Rejects path traversal, sibling prefix spoofing, absolute external paths,
 * null-byte injections, and symlink escapes.
 */

import { resolve, relative, normalize, isAbsolute, sep, dirname } from 'node:path';
import { existsSync, lstatSync, realpathSync, readlinkSync } from 'node:fs';
import { SecurityViolationError } from '../domain/errors.ts';

export interface PathValidationResult {
  readonly isContained: boolean;
  readonly canonicalPath: string;
  readonly canonicalRoot: string;
  readonly violationReason?: string;
}

export class PathValidator {
  /**
   * Validates that an input path resides strictly inside the workspace root.
   * Throws SecurityViolationError if the path breaches the jail.
   * Returns the canonical, fully-resolved path.
   */
  public static assertContained(inputPath: string, workspaceRoot: string): string {
    const result = this.checkContained(inputPath, workspaceRoot);
    if (!result.isContained) {
      throw new SecurityViolationError(
        result.violationReason || `Security Violation: Path '${inputPath}' escapes workspace root.`,
        'PATH_TRAVERSAL_DETECTED',
        { inputPath, workspaceRoot, canonicalPath: result.canonicalPath }
      );
    }
    return result.canonicalPath;
  }

  /**
   * Checks whether an input path is contained within workspaceRoot without throwing.
   */
  public static checkContained(inputPath: string, workspaceRoot: string): PathValidationResult {
    if (!inputPath || typeof inputPath !== 'string') {
      return {
        isContained: false,
        canonicalPath: '',
        canonicalRoot: workspaceRoot,
        violationReason: 'File path argument must be a non-empty string.'
      };
    }

    // Reject null byte injection attacks
    if (inputPath.includes('\0')) {
      return {
        isContained: false,
        canonicalPath: '',
        canonicalRoot: workspaceRoot,
        violationReason: 'Security Violation: Path contains forbidden null byte.'
      };
    }

    // 1. Resolve canonical workspace root
    const resolvedRoot = normalize(resolve(workspaceRoot));
    let canonicalRoot = resolvedRoot;
    try {
      if (existsSync(resolvedRoot)) {
        canonicalRoot = normalize(realpathSync.native(resolvedRoot));
      }
    } catch {
      canonicalRoot = resolvedRoot;
    }

    const rootWithSep = canonicalRoot.endsWith(sep) ? canonicalRoot : canonicalRoot + sep;

    // 2. Lexical resolution against workspace root
    const resolvedTarget = normalize(resolve(canonicalRoot, inputPath));

    // Lexical relative check: must not escape via '..' or different drive letter
    const rel = relative(canonicalRoot, resolvedTarget);
    if (rel === '..' || rel.startsWith('..' + sep) || isAbsolute(rel)) {
      return {
        isContained: false,
        canonicalPath: resolvedTarget,
        canonicalRoot,
        violationReason: `Path traversal outside workspace sandbox: '${inputPath}'`
      };
    }

    // Sibling prefix protection: e.g. /workspace_sibling vs /workspace
    if (resolvedTarget !== canonicalRoot && !resolvedTarget.startsWith(rootWithSep)) {
      return {
        isContained: false,
        canonicalPath: resolvedTarget,
        canonicalRoot,
        violationReason: `Path escapes workspace sandbox via sibling prefix: '${inputPath}'`
      };
    }

    // 3. Symlink escape check
    try {
      // Check if target itself exists
      const targetLstat = lstatSync(resolvedTarget, { throwIfNoEntry: false });
      if (targetLstat) {
        if (targetLstat.isSymbolicLink()) {
          // Resolve symlink target directly
          const linkTarget = readlinkSync(resolvedTarget);
          const resolvedLink = normalize(resolve(dirname(resolvedTarget), linkTarget));
          const relLink = relative(canonicalRoot, resolvedLink);
          if (relLink === '..' || relLink.startsWith('..' + sep) || isAbsolute(relLink) || (resolvedLink !== canonicalRoot && !resolvedLink.startsWith(rootWithSep))) {
            return {
              isContained: false,
              canonicalPath: resolvedTarget,
              canonicalRoot,
              violationReason: `Symlink escape detected: '${inputPath}' points to external location '${resolvedLink}'`
            };
          }
        }

        // Target exists, check its realpath
        if (existsSync(resolvedTarget)) {
          const realTarget = normalize(realpathSync.native(resolvedTarget));
          const relReal = relative(canonicalRoot, realTarget);
          if (relReal === '..' || relReal.startsWith('..' + sep) || isAbsolute(relReal) || (realTarget !== canonicalRoot && !realTarget.startsWith(rootWithSep))) {
            return {
              isContained: false,
              canonicalPath: realTarget,
              canonicalRoot,
              violationReason: `Symlink target escapes workspace root: '${inputPath}' resolves to '${realTarget}'`
            };
          }
        }
      } else {
        // Target does not exist yet: verify intermediate directory ancestors within workspace do not escape through symlinks
        let ancestor = dirname(resolvedTarget);
        while (ancestor && ancestor !== canonicalRoot && ancestor.startsWith(rootWithSep)) {
          if (existsSync(ancestor)) {
            const realAncestor = normalize(realpathSync.native(ancestor));
            const relAncestor = relative(canonicalRoot, realAncestor);
            if (relAncestor === '..' || relAncestor.startsWith('..' + sep) || isAbsolute(relAncestor) || (realAncestor !== canonicalRoot && !realAncestor.startsWith(rootWithSep))) {
              return {
                isContained: false,
                canonicalPath: resolvedTarget,
                canonicalRoot,
                violationReason: `Parent directory symlink escapes workspace root: '${ancestor}' resolves to '${realAncestor}'`
              };
            }
            break;
          }
          ancestor = dirname(ancestor);
        }
      }

    } catch (err) {
      return {
        isContained: false,
        canonicalPath: resolvedTarget,
        canonicalRoot,
        violationReason: `Filesystem resolution error during containment check: ${err instanceof Error ? err.message : String(err)}`
      };
    }

    return {
      isContained: true,
      canonicalPath: resolvedTarget,
      canonicalRoot
    };
  }
}
