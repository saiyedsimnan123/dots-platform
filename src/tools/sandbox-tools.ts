/**
 * Next-Generation Dots AI Platform - Standard Sandboxed Tools
 * 
 * Architectural Mandate:
 * Safe, bounded capabilities operating within the jailed sandbox directory.
 * Pure computation tools (Tier 0), read-only tools (Tier 1), and sandboxed mutation tools (Tier 2).
 */

import { readFileSync, writeFileSync, readdirSync, existsSync, statSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { createHash } from 'node:crypto';
import type { RegisteredTool } from './types.ts';
import { ToolExecutionError } from '../domain/errors.ts';

/**
 * Tier 0: Pure compute calculator tool
 */
export const calculateTool: RegisteredTool = {
  definition: {
    name: 'calculate',
    description: 'Safely evaluates mathematical expressions (+, -, *, /, %, parenthesis).',
    parameters: {
      expression: {
        type: 'string',
        description: 'Mathematical expression to evaluate, e.g. "42 * 10 + 5"'
      }
    },
    required: ['expression']
  },
  riskTier: 'TIER_0',
  handler: async (args) => {
    const start = Date.now();
    const expr = String(args.expression || '').trim();

    // Whitelist allowed mathematical characters only
    if (!/^[0-9+\-*/().\s%]+$/.test(expr)) {
      throw new ToolExecutionError(
        'calculate',
        `Expression contains forbidden characters: '${expr}'. Only numbers and math operators (+-*/().%) are allowed.`
      );
    }

    try {
      // Evaluate using Function with strict mode and zero access to global scope
      const compute = new Function(`"use strict"; return (${expr});`);
      const result = Number(compute());

      if (!Number.isFinite(result)) {
        throw new Error('Expression resulted in non-finite value');
      }

      return {
        output: { expression: expr, result },
        exitCode: 0,
        durationMs: Date.now() - start
      };
    } catch (err) {
      throw new ToolExecutionError(
        'calculate',
        `Calculation error: ${err instanceof Error ? err.message : String(err)}`
      );
    }
  }
};

/**
 * Tier 1: Read-only safe file reader tool
 */
export const fileReadTool: RegisteredTool = {
  definition: {
    name: 'file_read',
    description: 'Reads text content of a file located within the jailed workspace sandbox.',
    parameters: {
      path: {
        type: 'string',
        description: 'Sanitized path to the file inside the sandbox'
      }
    },
    required: ['path']
  },
  riskTier: 'TIER_1',
  handler: async (args) => {
    const start = Date.now();
    const filePath = String(args.path || '');

    if (!existsSync(filePath)) {
      throw new ToolExecutionError('file_read', `File not found: '${filePath}'`);
    }

    try {
      const content = readFileSync(filePath, 'utf8');
      const stats = statSync(filePath);
      return {
        output: { path: filePath, content, byteSize: stats.size },
        exitCode: 0,
        durationMs: Date.now() - start
      };
    } catch (err) {
      throw new ToolExecutionError(
        'file_read',
        `Failed to read file: ${err instanceof Error ? err.message : String(err)}`
      );
    }
  }
};

/**
 * Tier 1: Directory inspector tool
 */
export const fileListTool: RegisteredTool = {
  definition: {
    name: 'file_list',
    description: 'Lists files and directories located inside the jailed workspace sandbox.',
    parameters: {
      path: {
        type: 'string',
        description: 'Directory path inside the sandbox (defaults to root)'
      }
    }
  },
  riskTier: 'TIER_1',
  handler: async (args, context) => {
    const start = Date.now();
    const dirPath = String(args.path || context.workspaceRoot);

    if (!existsSync(dirPath)) {
      throw new ToolExecutionError('file_list', `Directory not found: '${dirPath}'`);
    }

    try {
      const entries = readdirSync(dirPath);
      return {
        output: { directory: dirPath, entries, count: entries.length },
        exitCode: 0,
        durationMs: Date.now() - start
      };
    } catch (err) {
      throw new ToolExecutionError(
        'file_list',
        `Failed to list directory: ${err instanceof Error ? err.message : String(err)}`
      );
    }
  }
};

/**
 * Tier 2: Reversible workspace file writer tool
 */
export const fileWriteTool: RegisteredTool = {
  definition: {
    name: 'file_write',
    description: 'Writes text content to a file inside the jailed workspace sandbox.',
    parameters: {
      path: {
        type: 'string',
        description: 'Destination file path inside the sandbox'
      },
      content: {
        type: 'string',
        description: 'Text content to write'
      }
    },
    required: ['path', 'content']
  },
  riskTier: 'TIER_2',
  handler: async (args) => {
    const start = Date.now();
    const filePath = String(args.path || '');
    const content = String(args.content ?? '');

    try {
      const parentDir = dirname(filePath);
      if (!existsSync(parentDir)) {
        mkdirSync(parentDir, { recursive: true });
      }

      writeFileSync(filePath, content, 'utf8');
      const bytesWritten = Buffer.byteLength(content, 'utf8');

      return {
        output: { path: filePath, bytesWritten },
        exitCode: 0,
        durationMs: Date.now() - start
      };
    } catch (err) {
      throw new ToolExecutionError(
        'file_write',
        `Failed to write file: ${err instanceof Error ? err.message : String(err)}`
      );
    }
  }
};

/**
 * Tier 1: Cryptographic hash tool
 */
export const hashFileTool: RegisteredTool = {
  definition: {
    name: 'hash_file',
    description: 'Computes cryptographic digest (SHA-256 or MD5) of a file inside the sandbox.',
    parameters: {
      path: {
        type: 'string',
        description: 'Path of the file to hash'
      },
      algorithm: {
        type: 'string',
        description: 'Hash algorithm (sha256 or md5, defaults to sha256)'
      }
    },
    required: ['path']
  },
  riskTier: 'TIER_1',
  handler: async (args) => {
    const start = Date.now();
    const filePath = String(args.path || '');
    const algo = String(args.algorithm || 'sha256').toLowerCase();

    if (!existsSync(filePath)) {
      throw new ToolExecutionError('hash_file', `File not found for hashing: '${filePath}'`);
    }

    try {
      const buffer = readFileSync(filePath);
      const hash = createHash(algo).update(buffer).digest('hex');

      return {
        output: {
          path: filePath,
          algorithm: algo,
          hash,
          byteSize: buffer.length
        },
        exitCode: 0,
        durationMs: Date.now() - start
      };
    } catch (err) {
      throw new ToolExecutionError(
        'hash_file',
        `Failed to hash file: ${err instanceof Error ? err.message : String(err)}`
      );
    }
  }
};

/**
 * Tier 0: Pure in-memory text transformation tool
 */
export const textTransformTool: RegisteredTool = {
  definition: {
    name: 'text_transform',
    description: 'Performs safe text transformations (uppercase, lowercase, trim, replace, json_parse, json_stringify).',
    parameters: {
      operation: {
        type: 'string',
        description: 'Operation to perform',
        enum: ['uppercase', 'lowercase', 'trim', 'replace', 'json_parse', 'json_stringify']
      },
      text: {
        type: 'string',
        description: 'Input text to transform'
      },
      pattern: {
        type: 'string',
        description: 'Search string or regex pattern (for replace operation)'
      },
      replacement: {
        type: 'string',
        description: 'Replacement string (for replace operation)'
      }
    },
    required: ['operation', 'text']
  },
  riskTier: 'TIER_0',
  handler: async (args) => {
    const start = Date.now();
    const op = String(args.operation || '').toLowerCase();
    const text = String(args.text ?? '');

    try {
      let result: unknown;
      switch (op) {
        case 'uppercase':
          result = text.toUpperCase();
          break;
        case 'lowercase':
          result = text.toLowerCase();
          break;
        case 'trim':
          result = text.trim();
          break;
        case 'replace': {
          const pattern = String(args.pattern ?? '');
          const replacement = String(args.replacement ?? '');
          result = text.replaceAll(pattern, replacement);
          break;
        }
        case 'json_parse':
          result = JSON.parse(text);
          break;
        case 'json_stringify':
          result = JSON.stringify(JSON.parse(text), null, 2);
          break;
        default:
          throw new ToolExecutionError(
            'text_transform',
            `Unsupported text_transform operation: '${op}'`
          );
      }

      return {
        output: { operation: op, result },
        exitCode: 0,
        durationMs: Date.now() - start
      };
    } catch (err) {
      throw new ToolExecutionError(
        'text_transform',
        `Text transform error: ${err instanceof Error ? err.message : String(err)}`
      );
    }
  }
};

/**
 * Standard registry collection of built-in safe tools
 */
export const standardTools: readonly RegisteredTool[] = [
  calculateTool,
  textTransformTool,
  fileReadTool,
  fileListTool,
  fileWriteTool,
  hashFileTool
];

