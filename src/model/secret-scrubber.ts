/**
 * Next-Generation Dots AI Platform - Secret Scrubber
 * 
 * Architectural Mandate:
 * Enforces zero-leak credential hygiene. All text flowing to external model providers,
 * persistent audit logs, diagnostics, or UI streams passes through this scrubber
 * to redact detected API keys, tokens, and private credentials.
 */

export interface ScrubPattern {
  readonly name: string;
  readonly regex: RegExp;
  readonly replacement: string;
}

export class SecretScrubber {
  private static readonly DEFAULT_PATTERNS: readonly ScrubPattern[] = [
    // Google AI / Gemini API Keys
    {
      name: 'Google API Key',
      regex: /AIza[0-9A-Za-z\-_]{35}/g,
      replacement: '[REDACTED_GOOGLE_API_KEY]'
    },
    // Anthropic API Keys (ordered before OpenAI to avoid prefix collision)
    {
      name: 'Anthropic API Key',
      regex: /sk-ant-[a-zA-Z0-9_\-]{20,}/g,
      replacement: '[REDACTED_ANTHROPIC_API_KEY]'
    },
    // OpenAI API Keys
    {
      name: 'OpenAI API Key',
      regex: /sk-(?!ant-)[a-zA-Z0-9_\-]{20,}/g,
      replacement: '[REDACTED_OPENAI_API_KEY]'
    },
    // GitHub Tokens
    {
      name: 'GitHub Token',
      regex: /(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}/g,
      replacement: '[REDACTED_GITHUB_TOKEN]'
    },
    // Generic Bearer Tokens
    {
      name: 'Bearer Token',
      regex: /Bearer\s+[A-Za-z0-9\-._~+/]+=*/g,
      replacement: 'Bearer [REDACTED_TOKEN]'
    },
    // RSA / Private Keys
    {
      name: 'Private Key Block',
      regex: /-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+ PRIVATE KEY-----/g,
      replacement: '[REDACTED_PRIVATE_KEY]'
    }
  ];

  private readonly patterns: ScrubPattern[];

  constructor(customPatterns: readonly ScrubPattern[] = []) {
    this.patterns = [...SecretScrubber.DEFAULT_PATTERNS, ...customPatterns];
  }

  /**
   * Scrubs sensitive tokens from the input text, replacing them with redaction tags.
   */
  public scrub(input: string): string {
    if (!input || typeof input !== 'string') {
      return '';
    }

    let result = input;
    for (const pattern of this.patterns) {
      // Create a fresh regex instance with global flag to avoid stateful lastIndex issues
      const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
      result = result.replace(regex, pattern.replacement);
    }
    return result;
  }

  /**
   * Tests whether the input string contains any known secret patterns.
   */
  public containsSecret(input: string): boolean {
    if (!input || typeof input !== 'string') {
      return false;
    }

    for (const pattern of this.patterns) {
      const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
      if (regex.test(input)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Registers a new custom redaction pattern.
   */
  public addPattern(pattern: ScrubPattern): void {
    this.patterns.push(pattern);
  }

  /**
   * Returns a copy of the active redaction patterns.
   */
  public getPatterns(): readonly ScrubPattern[] {
    return [...this.patterns];
  }
}

// Export singleton default instance for convenience
export const defaultSecretScrubber = new SecretScrubber();
