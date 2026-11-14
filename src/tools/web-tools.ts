/**
 * Next-Generation Dots AI Platform - Secure Web Capabilities
 * Milestone 1B: Secure Web Search & Web Fetch Tools
 *
 * Architectural Mandate:
 * Implements hardened web_search and web_fetch tools integrated with the platform's
 * ToolRegistry, policy engine, and risk tier system (Tier 3: Consequential Network).
 *
 * Security Perimeters & Invariants:
 * 1. Strict Protocol Confinement: Only 'http:' and 'https:' are permitted.
 *    Rejects file:, ftp:, gopher:, data:, javascript:, and all other schemes.
 * 2. Complete SSRF Elimination:
 *    - Rejects localhost, loopback (127.0.0.0/8, ::1), private ranges (10.0.0.0/8,
 *      172.16.0.0/12, 192.168.0.0/16, fc00::/7), link-local (169.254.0.0/16, fe80::/10),
 *      cloud metadata (169.254.169.254, 169.254.170.2, 100.100.100.100, metadata.google.internal),
 *      carrier-grade NAT (100.64.0.0/10), multicast, broadcast, and reserved addresses.
 *    - Rejects IPv4-mapped and IPv4-compatible IPv6 bypass vectors.
 * 3. DNS Rebinding Immunity (Connection Pinning):
 *    - Socket connections use a custom DNS lookup that resolves all addresses, verifies
 *      none are private or reserved, and pins the connection to the validated IP.
 *    - For HTTPS, TLS SNI and certificate host validation verify the original hostname.
 * 4. Safe Redirect Enforcement:
 *    - Validates every hop in redirect chains against all security rules.
 *    - Blocks redirects to private IPs, loopback, or non-http(s) protocols.
 *    - Caps redirect depth to 5 hops.
 * 5. Bounded Resource Consumption:
 *    - Enforces maximum response byte limits (default: 2 MB, max: 10 MB) via stream truncation.
 *    - Enforces strict request timeouts (default: 10s, max: 30s).
 * 6. Content Safety & Secret Scrubbing:
 *    - Restricts content types to text and document formats (rejects binaries/executables).
 *    - Safely strips scripts, styles, and tags; decodes HTML entities into clean text.
 *    - Scrubs credentials and sensitive tokens from URLs, extracted content, and errors.
 */

import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { isIP, isIPv4, isIPv6 } from 'node:net';
import { promises as dnsPromises } from 'node:dns';
import type { RegisteredTool, ToolContext, ToolExecutionResult } from './types.ts';
import type { ToolDefinition } from '../model/types.ts';
import {
  ValidationError,
  SecurityViolationError,
  ToolExecutionError
} from '../domain/errors.ts';
import { defaultSecretScrubber } from '../model/secret-scrubber.ts';

// --- Constants & Security Boundaries ---

export const WEB_SEARCH_TOOL_NAME = 'web_search';
export const WEB_FETCH_TOOL_NAME = 'web_fetch';

export const DEFAULT_FETCH_MAX_BYTES = 2 * 1024 * 1024; // 2 MiB
export const ABSOLUTE_MAX_FETCH_BYTES = 10 * 1024 * 1024; // 10 MiB
export const DEFAULT_FETCH_TIMEOUT_MS = 10_000; // 10 seconds
export const MAX_FETCH_TIMEOUT_MS = 30_000; // 30 seconds
export const MAX_REDIRECT_DEPTH = 5;
export const MAX_EXTRACTED_TEXT_CHARS = 50_000;

export const DEFAULT_SEARCH_LIMIT = 5;
export const MAX_SEARCH_LIMIT = 20;

const BLOCKED_HOSTNAMES: ReadonlySet<string> = new Set([
  'localhost',
  'localhost.localdomain',
  'broadcasthost',
  'metadata.google.internal',
  'metadata',
  'instance-data'
]);

const BLOCKED_HOSTNAME_SUFFIXES: readonly string[] = [
  '.localhost',
  '.local',
  '.internal',
  '.lan',
  '.home',
  '.corp'
];

const SUPPORTED_CONTENT_TYPES: readonly string[] = [
  'text/html',
  'text/plain',
  'text/markdown',
  'text/csv',
  'application/json',
  'application/xml',
  'text/xml',
  'application/xhtml+xml',
  'application/x-javascript',
  'application/javascript',
  'text/javascript'
];

const BLOCKED_BINARY_MIME_PREFIXES: readonly string[] = [
  'image/',
  'video/',
  'audio/'
];

const BLOCKED_EXPLICIT_MIMES: ReadonlySet<string> = new Set([
  'application/pdf',
  'application/zip',
  'application/gzip',
  'application/x-tar',
  'application/x-bzip2',
  'application/x-7z-compressed',
  'application/octet-stream',
  'application/x-executable',
  'application/x-dosexec',
  'application/x-msdownload',
  'application/wasm'
]);

// --- IP & Hostname Validation ---

/**
 * Checks if a given IP address is private, loopback, link-local, multicast,
 * cloud metadata, or otherwise reserved.
 */
export function isPrivateOrReservedIp(ip: string): boolean {
  let cleanIp = ip.replace(/^\[|\]$/g, '').trim().toLowerCase();

  // Normalize IPv4-mapped IPv6 (::ffff:127.0.0.1 or ::ffff:7f00:1)
  if (cleanIp.startsWith('::ffff:')) {
    const rest = cleanIp.slice(7);
    if (isIPv4(rest)) {
      cleanIp = rest;
    } else {
      const parts = rest.split(':');
      if (parts.length === 2) {
        const p1 = parseInt(parts[0]!, 16);
        const p2 = parseInt(parts[1]!, 16);
        if (Number.isFinite(p1) && Number.isFinite(p2)) {
          cleanIp = [
            (p1 >> 8) & 0xff,
            p1 & 0xff,
            (p2 >> 8) & 0xff,
            p2 & 0xff
          ].join('.');
        }
      }
    }
  }

  // Normalize IPv4-compatible IPv6 (::127.0.0.1)
  if (cleanIp.startsWith('::') && cleanIp !== '::' && cleanIp !== '::1') {
    const rest = cleanIp.slice(2);
    if (isIPv4(rest)) {
      cleanIp = rest;
    }
  }

  // Normalize NAT64 IPv4-embedded IPv6 (64:ff9b::/96 or 64:ff9b:1::/48, RFC 6052 / RFC 8215)
  if (cleanIp.startsWith('64:ff9b::') || cleanIp.startsWith('64:ff9b:1::')) {
    const prefix = cleanIp.startsWith('64:ff9b:1::') ? '64:ff9b:1::' : '64:ff9b::';
    const rest = cleanIp.slice(prefix.length);
    if (isIPv4(rest)) {
      cleanIp = rest;
    } else {
      const parts = rest.split(':');
      if (parts.length === 2) {
        const p1 = parseInt(parts[0]!, 16);
        const p2 = parseInt(parts[1]!, 16);
        if (Number.isFinite(p1) && Number.isFinite(p2)) {
          cleanIp = [
            (p1 >> 8) & 0xff,
            p1 & 0xff,
            (p2 >> 8) & 0xff,
            p2 & 0xff
          ].join('.');
        }
      }
    }
  }

  // IPv4 evaluation
  if (isIPv4(cleanIp)) {
    const octets = cleanIp.split('.').map(Number);
    const b0 = octets[0]!;
    const b1 = octets[1]!;
    const b2 = octets[2]!;

    // 0.0.0.0/8 (Current network)
    if (b0 === 0) return true;
    // 10.0.0.0/8 (Private)
    if (b0 === 10) return true;
    // 127.0.0.0/8 (Loopback)
    if (b0 === 127) return true;
    // 100.64.0.0/10 (Carrier-Grade NAT)
    if (b0 === 100 && b1 >= 64 && b1 <= 127) return true;
    // 100.100.100.100 (Alibaba Cloud metadata service)
    if (cleanIp === '100.100.100.100') return true;
    // 169.254.0.0/16 (Link-Local & Cloud Metadata e.g. 169.254.169.254, 169.254.170.2)
    if (b0 === 169 && b1 === 254) return true;
    // 172.16.0.0/12 (Private: 172.16.0.0 - 172.31.255.255)
    if (b0 === 172 && b1 >= 16 && b1 <= 31) return true;
    // 192.0.0.0/24 (IETF Protocol Assignments)
    if (b0 === 192 && b1 === 0 && b2 === 0) return true;
    // 192.0.2.0/24 (TEST-NET-1)
    if (b0 === 192 && b1 === 0 && b2 === 2) return true;
    // 192.168.0.0/16 (Private)
    if (b0 === 192 && b1 === 168) return true;
    // 198.18.0.0/15 (Benchmarking)
    if (b0 === 198 && (b1 === 18 || b1 === 19)) return true;
    // 198.51.100.0/24 (TEST-NET-2)
    if (b0 === 198 && b1 === 51 && b2 === 100) return true;
    // 203.0.113.0/24 (TEST-NET-3)
    if (b0 === 203 && b1 === 0 && b2 === 113) return true;
    // 224.0.0.0/4 (Multicast: 224.0.0.0 - 239.255.255.255)
    if (b0 >= 224 && b0 <= 239) return true;
    // 240.0.0.0/4 (Reserved) and 255.255.255.255 (Broadcast)
    if (b0 >= 240) return true;

    return false;
  }

  // IPv6 evaluation
  if (isIPv6(cleanIp)) {
    // ::1 (Loopback)
    if (cleanIp === '::1' || cleanIp === '0:0:0:0:0:0:0:1') return true;
    // :: (Unspecified)
    if (cleanIp === '::' || cleanIp === '0:0:0:0:0:0:0:0') return true;
    // fc00::/7 (Unique Local Address - private)
    if (/^[fF][cCdD]/i.test(cleanIp)) return true;
    // fe80::/10 (Link-Local)
    if (/^[fF][eE][89aAbB]/i.test(cleanIp)) return true;
    // ff00::/8 (Multicast)
    if (/^[fF]{2}/i.test(cleanIp)) return true;
    // 2001:db8::/32 (Documentation)
    if (/^2001:0?db8/i.test(cleanIp)) return true;

    return false;
  }

  // Unrecognized IP format: fail closed
  return true;
}

/**
 * Checks if a given IP address is loopback.
 */
export function isLoopbackIp(ip: string): boolean {
  const cleanIp = ip.replace(/^\[|\]$/g, '').trim().toLowerCase();
  if (cleanIp === '127.0.0.1' || cleanIp === '::1' || cleanIp === 'localhost') return true;
  if (isIPv4(cleanIp) && cleanIp.startsWith('127.')) return true;
  if (cleanIp === '::ffff:127.0.0.1' || cleanIp === '::ffff:7f00:1') return true;
  if (cleanIp === '64:ff9b::127.0.0.1' || cleanIp === '64:ff9b::7f00:1') return true;
  return false;
}

/**
 * Checks if a hostname matches blocked internal/loopback/cloud metadata names.
 */
export function isBlockedHostname(hostname: string): boolean {
  const lower = hostname.trim().toLowerCase();
  if (BLOCKED_HOSTNAMES.has(lower)) {
    return true;
  }
  for (const suffix of BLOCKED_HOSTNAME_SUFFIXES) {
    if (lower.endsWith(suffix)) {
      return true;
    }
  }
  return false;
}

/**
 * Checks if a response Content-Type header represents a supported text/document format.
 */
export function isSupportedContentType(contentTypeHeader?: string): boolean {
  if (!contentTypeHeader || contentTypeHeader.trim() === '') {
    return true; // Default to permissible inspection if header is omitted
  }
  const mime = contentTypeHeader.split(';')[0]!.trim().toLowerCase();

  for (const prefix of BLOCKED_BINARY_MIME_PREFIXES) {
    if (mime.startsWith(prefix)) {
      return false;
    }
  }

  if (BLOCKED_EXPLICIT_MIMES.has(mime)) {
    return false;
  }

  return (
    SUPPORTED_CONTENT_TYPES.includes(mime) ||
    mime.endsWith('+json') ||
    mime.endsWith('+xml')
  );
}

// --- HTML Parsing & Content Extraction ---

/**
 * Decodes standard named and numeric HTML entities.
 */
export function decodeHtmlEntities(str: string): string {
  const named: Record<string, string> = {
    '&nbsp;': ' ',
    '&amp;': '&',
    '&lt;': '<',
    '&gt;': '>',
    '&quot;': '"',
    '&apos;': "'",
    '&#39;': "'",
    '&#x27;': "'",
    '&mdash;': '—',
    '&ndash;': '–',
    '&hellip;': '…'
  };

  let res = str.replace(
    /&(?:nbsp|amp|lt|gt|quot|apos|#39|#x27|mdash|ndash|hellip);/gi,
    (m) => named[m.toLowerCase()] ?? m
  );

  // Decimal entities &#123;
  res = res.replace(/&#(\d+);/g, (_, dec) => {
    const code = Number(dec);
    return Number.isFinite(code) && code > 0 && code <= 0x10ffff
      ? String.fromCodePoint(code)
      : '';
  });

  // Hexadecimal entities &#x1f600;
  res = res.replace(/&#x([0-9a-f]+);/gi, (_, hex) => {
    const code = parseInt(hex, 16);
    return Number.isFinite(code) && code > 0 && code <= 0x10ffff
      ? String.fromCodePoint(code)
      : '';
  });

  return res;
}

/**
 * Safely extracts page title and readable plain text from HTML, stripping
 * scripts, styles, noscript, SVG, comments, and raw markup.
 */
export function extractHtmlText(html: string): { title: string; text: string } {
  const titleMatch = /<title[^>]*>([\s\S]*?)<\/title>/i.exec(html);
  let title = titleMatch ? decodeHtmlEntities(titleMatch[1]!.trim()) : '';

  let cleaned = html
    .replace(/<!--[\s\S]*?-->/g, ' ')
    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, ' ')
    .replace(/<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>/gi, ' ')
    .replace(/<noscript\b[^<]*(?:(?!<\/noscript>)<[^<]*)*<\/noscript>/gi, ' ')
    .replace(/<svg\b[^<]*(?:(?!<\/svg>)<[^<]*)*<\/svg>/gi, ' ');

  // Convert block/paragraph tags into newlines
  cleaned = cleaned.replace(
    /<\/(p|div|section|article|header|footer|h[1-6]|table|tr|ul|ol|li|blockquote)>/gi,
    '\n'
  );
  cleaned = cleaned.replace(/<(br|hr)\s*\/?>/gi, '\n');

  // Remove remaining HTML tags
  cleaned = cleaned.replace(/<[^>]+>/g, ' ');

  // Decode entities
  cleaned = decodeHtmlEntities(cleaned);

  // Normalize whitespace
  const lines = cleaned
    .split(/\r?\n/)
    .map((l) => l.replace(/[\t ]+/g, ' ').trim())
    .filter((l, i, arr) => l.length > 0 || (i > 0 && arr[i - 1]!.length > 0));

  let text = lines.join('\n').trim();
  if (text.length > MAX_EXTRACTED_TEXT_CHARS) {
    text = text.slice(0, MAX_EXTRACTED_TEXT_CHARS) + '\n... [content truncated at limit]';
  }

  return { title, text };
}

// --- Web Search Provider Abstraction ---

export interface WebSearchResult {
  readonly title: string;
  readonly url: string;
  readonly snippet: string;
  readonly domain: string;
}

export interface WebSearchResponse {
  readonly query: string;
  readonly provider: string;
  readonly count: number;
  readonly results: readonly WebSearchResult[];
}

export interface IWebSearchProvider {
  readonly name: string;
  search(query: string, limit?: number): Promise<WebSearchResponse>;
}

/**
 * Mock Web Search Provider for deterministic, offline unit and integration testing.
 */
export class MockWebSearchProvider implements IWebSearchProvider {
  public readonly name: string;
  private readonly queryResults: Map<string, readonly WebSearchResult[]> = new Map();
  private defaultResults: readonly WebSearchResult[] = [];

  constructor(name: string = 'mock-search') {
    this.name = name;
  }

  public registerResults(query: string, results: readonly WebSearchResult[]): void {
    this.queryResults.set(query.trim().toLowerCase(), results);
  }

  public setDefaultResults(results: readonly WebSearchResult[]): void {
    this.defaultResults = results;
  }

  public clear(): void {
    this.queryResults.clear();
    this.defaultResults = [];
  }

  public async search(query: string, limit: number = DEFAULT_SEARCH_LIMIT): Promise<WebSearchResponse> {
    const normalized = query.trim().toLowerCase();
    const matches = this.queryResults.get(normalized) ?? this.defaultResults;
    const effectiveLimit = Math.max(1, Math.min(limit, MAX_SEARCH_LIMIT));
    const sliced = matches.slice(0, effectiveLimit);

    return {
      query,
      provider: this.name,
      count: sliced.length,
      results: sliced
    };
  }
}

export interface DuckDuckGoSearchProviderOptions {
  readonly timeoutMs?: number;
  readonly maxBytes?: number;
  readonly fetchFn?: typeof safeFetch;
}

/**
 * Free, zero-API-key live web search provider powered by DuckDuckGo's Instant Answer & Topics API.
 */
export class DuckDuckGoSearchProvider implements IWebSearchProvider {
  public readonly name: string = 'duckduckgo';
  private readonly timeoutMs: number;
  private readonly maxBytes: number;
  private readonly fetchFn: typeof safeFetch;

  constructor(options: DuckDuckGoSearchProviderOptions = {}) {
    this.timeoutMs = options.timeoutMs ?? 10_000;
    this.maxBytes = options.maxBytes ?? 2 * 1024 * 1024;
    this.fetchFn = options.fetchFn ?? safeFetch;
  }

  public async search(query: string, limit: number = DEFAULT_SEARCH_LIMIT): Promise<WebSearchResponse> {
    const effectiveLimit = Math.max(1, Math.min(limit, MAX_SEARCH_LIMIT));
    const url = `https://api.duckduckgo.com/?q=${encodeURIComponent(query)}&format=json&no_html=1&skip_disambig=1`;

    let fetchResult: SafeFetchResult;
    try {
      fetchResult = await this.fetchFn(url, {
        extractText: false,
        timeoutMs: this.timeoutMs,
        maxBytes: this.maxBytes
      });
    } catch (err) {
      throw new ToolExecutionError(
        WEB_SEARCH_TOOL_NAME,
        `DuckDuckGo search request failed: ${defaultSecretScrubber.scrub(err instanceof Error ? err.message : String(err))}`
      );
    }

    let parsedData: any;
    try {
      parsedData = JSON.parse(fetchResult.content);
    } catch {
      throw new ToolExecutionError(
        WEB_SEARCH_TOOL_NAME,
        'DuckDuckGo search provider returned invalid JSON response.'
      );
    }

    const results: WebSearchResult[] = [];
    const seenUrls = new Set<string>();

    const addResult = (title: string, rawUrl: string, snippet: string) => {
      if (!rawUrl || typeof rawUrl !== 'string') return;
      try {
        const u = new URL(rawUrl);
        if (u.protocol !== 'http:' && u.protocol !== 'https:') return;
        const normalizedUrl = u.toString();
        if (seenUrls.has(normalizedUrl)) return;
        seenUrls.add(normalizedUrl);

        results.push({
          title: defaultSecretScrubber.scrub(title.trim() || u.hostname),
          url: defaultSecretScrubber.scrub(normalizedUrl),
          snippet: defaultSecretScrubber.scrub(snippet.trim() || title.trim()),
          domain: defaultSecretScrubber.scrub(u.hostname)
        });
      } catch {
        // Skip malformed URLs
      }
    };

    // 1. Direct Abstract / Topic Answer
    if (parsedData.AbstractURL && parsedData.Abstract) {
      addResult(
        parsedData.Heading || query,
        parsedData.AbstractURL,
        parsedData.Abstract
      );
    }

    // 2. Results array (e.g. Official Site)
    if (Array.isArray(parsedData.Results)) {
      for (const r of parsedData.Results) {
        if (r && typeof r === 'object') {
          addResult(r.Text || '', r.FirstURL || '', r.Text || '');
        }
      }
    }

    // 3. RelatedTopics array (flat or grouped in Topics)
    const processTopic = (t: any) => {
      if (!t || typeof t !== 'object') return;
      if (t.FirstURL && t.Text) {
        const text = String(t.Text);
        const title = text.split(' - ')[0] || text;
        addResult(title, t.FirstURL, text);
      } else if (Array.isArray(t.Topics)) {
        for (const sub of t.Topics) {
          processTopic(sub);
        }
      }
    };

    if (Array.isArray(parsedData.RelatedTopics)) {
      for (const topic of parsedData.RelatedTopics) {
        if (results.length >= effectiveLimit) break;
        processTopic(topic);
      }
    }

    const finalResults = results.slice(0, effectiveLimit);
    return {
      query: defaultSecretScrubber.scrub(query),
      provider: this.name,
      count: finalResults.length,
      results: finalResults
    };
  }
}

export interface SearxngSearchProviderOptions {
  readonly baseUrl: string;
  readonly timeoutMs?: number;
  readonly maxBytes?: number;
  readonly fetchFn?: typeof safeFetch;
}

/**
 * Self-hostable, open-source metasearch provider using SearXNG's JSON API.
 */
export class SearxngSearchProvider implements IWebSearchProvider {
  public readonly name: string = 'searxng';
  private readonly baseUrl: string;
  private readonly timeoutMs: number;
  private readonly maxBytes: number;
  private readonly fetchFn: typeof safeFetch;

  constructor(options: SearxngSearchProviderOptions) {
    if (!options || typeof options !== 'object' || !options.baseUrl) {
      throw new ValidationError('SearxngSearchProvider requires a valid baseUrl.');
    }
    this.baseUrl = options.baseUrl.replace(/\/+$/, '');
    this.timeoutMs = options.timeoutMs ?? 10_000;
    this.maxBytes = options.maxBytes ?? 2 * 1024 * 1024;
    this.fetchFn = options.fetchFn ?? safeFetch;
  }

  public async search(query: string, limit: number = DEFAULT_SEARCH_LIMIT): Promise<WebSearchResponse> {
    const effectiveLimit = Math.max(1, Math.min(limit, MAX_SEARCH_LIMIT));
    const url = `${this.baseUrl}/search?q=${encodeURIComponent(query)}&format=json`;

    let fetchResult: SafeFetchResult;
    try {
      fetchResult = await this.fetchFn(url, {
        extractText: false,
        timeoutMs: this.timeoutMs,
        maxBytes: this.maxBytes
      });
    } catch (err) {
      throw new ToolExecutionError(
        WEB_SEARCH_TOOL_NAME,
        `SearXNG search request failed: ${defaultSecretScrubber.scrub(err instanceof Error ? err.message : String(err))}`
      );
    }

    let parsedData: any;
    try {
      parsedData = JSON.parse(fetchResult.content);
    } catch {
      throw new ToolExecutionError(
        WEB_SEARCH_TOOL_NAME,
        'SearXNG search provider returned invalid JSON response.'
      );
    }

    if (!parsedData || typeof parsedData !== 'object' || !Array.isArray(parsedData.results)) {
      throw new ToolExecutionError(
        WEB_SEARCH_TOOL_NAME,
        'SearXNG search provider response is missing expected results array.'
      );
    }

    const results: WebSearchResult[] = [];
    const seenUrls = new Set<string>();

    for (const item of parsedData.results) {
      if (results.length >= effectiveLimit) break;
      if (!item || typeof item !== 'object' || !item.url) continue;

      try {
        const u = new URL(item.url);
        if (u.protocol !== 'http:' && u.protocol !== 'https:') continue;
        const normalizedUrl = u.toString();
        if (seenUrls.has(normalizedUrl)) continue;
        seenUrls.add(normalizedUrl);

        results.push({
          title: defaultSecretScrubber.scrub(item.title || u.hostname),
          url: defaultSecretScrubber.scrub(normalizedUrl),
          snippet: defaultSecretScrubber.scrub(item.content || item.title || ''),
          domain: defaultSecretScrubber.scrub(u.hostname)
        });
      } catch {
        // Skip malformed
      }
    }

    return {
      query: defaultSecretScrubber.scrub(query),
      provider: this.name,
      count: results.length,
      results
    };
  }
}

export function createConfiguredWebSearchProvider(
  providerName?: string,
  options: { readonly searxngUrl?: string; readonly fetchFn?: typeof safeFetch } = {}
): IWebSearchProvider | null {
  if (!providerName || providerName === 'none') {
    return null;
  }
  const norm = providerName.trim().toLowerCase();
  if (norm === 'duckduckgo') {
    return new DuckDuckGoSearchProvider({ fetchFn: options.fetchFn });
  }
  if (norm === 'searxng') {
    if (!options.searxngUrl || options.searxngUrl.trim() === '') {
      throw new ValidationError("SearXNG search provider requires 'searxngUrl' or DOTS_SEARXNG_URL to be configured.");
    }
    return new SearxngSearchProvider({ baseUrl: options.searxngUrl, fetchFn: options.fetchFn });
  }
  if (norm === 'mock') {
    return new MockWebSearchProvider();
  }
  throw new ValidationError(`Unknown web search provider: '${providerName}'. Supported providers: 'duckduckgo', 'searxng', 'mock', 'none'.`);
}

let activeWebSearchProvider: IWebSearchProvider | null = null;

export function setWebSearchProvider(provider: IWebSearchProvider | null): void {
  activeWebSearchProvider = provider;
}

export function getWebSearchProvider(): IWebSearchProvider | null {
  return activeWebSearchProvider;
}

// --- Safe HTTP/HTTPS Fetch Implementation ---

export interface SafeFetchOptions {
  readonly extractText?: boolean;
  readonly maxBytes?: number;
  readonly timeoutMs?: number;
  readonly maxRedirects?: number;
  /**
   * Optional custom DNS resolver for testing SSRF and DNS rebinding protections.
   */
  readonly dnsLookup?: (hostname: string) => Promise<Array<{ address: string; family: number }>>;
  /**
   * Internal test-only option to allow loopback connections to ephemeral test servers.
   * NEVER exposed to agent tool arguments.
   */
  readonly _allowLoopbackForTesting?: boolean;
}

export interface SafeFetchResult {
  readonly url: string;
  readonly finalUrl: string;
  readonly status: number;
  readonly contentType: string;
  readonly byteSize: number;
  readonly durationMs: number;
  readonly title: string;
  readonly content: string;
}

/**
 * Validates a target URL against protocol and destination security rules.
 * Throws SecurityViolationError or ValidationError upon failure.
 */
export function validateTargetUrl(
  rawUrl: string,
  allowLoopback: boolean = false
): URL {
  if (typeof rawUrl !== 'string' || rawUrl.trim() === '') {
    throw new ValidationError('URL must be a non-empty string.');
  }

  let parsed: URL;
  try {
    parsed = new URL(rawUrl.trim());
  } catch (err) {
    throw new ValidationError(`Malformed URL: ${err instanceof Error ? err.message : String(err)}`);
  }

  // Strip userinfo (username / password) to avoid credential transmission or leakage
  if (parsed.username || parsed.password) {
    parsed.username = '';
    parsed.password = '';
  }

  const protocol = parsed.protocol.toLowerCase();
  if (protocol !== 'http:' && protocol !== 'https:') {
    throw new SecurityViolationError(
      `Security Violation: Protocol '${parsed.protocol}' is forbidden. Only 'http:' and 'https:' are allowed.`,
      'UNSUPPORTED_PROTOCOL',
      { url: defaultSecretScrubber.scrub(rawUrl), protocol: parsed.protocol }
    );
  }

  const hostname = parsed.hostname;
  if (!hostname || hostname.trim() === '') {
    throw new ValidationError('URL hostname must not be empty.');
  }

  // Pre-DNS Hostname Blocklist
  if (isBlockedHostname(hostname)) {
    if (!allowLoopback || (hostname !== 'localhost' && hostname !== 'localhost.localdomain')) {
      throw new SecurityViolationError(
        `Security Violation: Destination host '${hostname}' is a prohibited local/metadata address.`,
        'SSRF_DESTINATION_BLOCKED',
        { hostname }
      );
    }
  }

  // Pre-DNS IP Literal Check
  const strippedHost = hostname.replace(/^\[|\]$/g, '');
  if (isIP(strippedHost)) {
    if (isPrivateOrReservedIp(strippedHost)) {
      if (!allowLoopback || !isLoopbackIp(strippedHost)) {
        throw new SecurityViolationError(
          `Security Violation: Destination IP '${strippedHost}' is private, loopback, or reserved.`,
          'SSRF_DESTINATION_BLOCKED',
          { ip: strippedHost }
        );
      }
    }
  }

  return parsed;
}

/**
 * Performs a secure, SSRF-hardened, DNS-rebinding-immune HTTP/HTTPS fetch.
 */
export async function safeFetch(
  initialUrl: string,
  options: SafeFetchOptions = {}
): Promise<SafeFetchResult> {
  const startTime = Date.now();
  const maxBytes = Math.min(
    Math.max(1, options.maxBytes ?? DEFAULT_FETCH_MAX_BYTES),
    ABSOLUTE_MAX_FETCH_BYTES
  );
  const timeoutMs = Math.min(
    Math.max(500, options.timeoutMs ?? DEFAULT_FETCH_TIMEOUT_MS),
    MAX_FETCH_TIMEOUT_MS
  );
  const maxRedirects = Math.max(0, options.maxRedirects ?? MAX_REDIRECT_DEPTH);
  const extractText = options.extractText ?? true;
  const allowLoopback = options._allowLoopbackForTesting ?? false;

  let currentUrl = validateTargetUrl(initialUrl, allowLoopback);
  let redirectCount = 0;

  while (true) {
    const isHttps = currentUrl.protocol === 'https:';
    const requester = isHttps ? httpsRequest : httpRequest;
    const hostname = currentUrl.hostname;
    const strippedHost = hostname.replace(/^\[|\]$/g, '');
    const isIpLiteral = isIP(strippedHost) !== 0;

    // Pinning DNS Lookup Callback
    const customLookup = (
      lookupHost: string,
      lookupOpts: any,
      callback: (err: Error | null, addressOrAddresses?: any, family?: number) => void
    ) => {
      const runLookup = async () => {
        try {
          let addresses: Array<{ address: string; family: number }>;
          if (options.dnsLookup) {
            addresses = await options.dnsLookup(lookupHost);
          } else {
            addresses = await dnsPromises.lookup(lookupHost, { all: true });
          }

          if (!addresses || addresses.length === 0) {
            throw new ToolExecutionError('web_fetch', `DNS resolution returned no addresses for host '${lookupHost}'.`);
          }

          // Strict SSRF re-check on all resolved IP addresses
          for (const record of addresses) {
            if (isPrivateOrReservedIp(record.address)) {
              if (!allowLoopback || !isLoopbackIp(record.address)) {
                throw new SecurityViolationError(
                  `Security Violation: Host '${lookupHost}' resolved to prohibited IP address '${record.address}'.`,
                  'SSRF_DESTINATION_BLOCKED',
                  { host: lookupHost, resolvedIp: record.address }
                );
              }
            }
          }

          // Connection Pinning: return the validated records to Node's socket connect
          if (lookupOpts && lookupOpts.all) {
            callback(null, addresses);
          } else {
            const first = addresses[0]!;
            callback(null, first.address, first.family);
          }
        } catch (err) {
          callback(err instanceof Error ? err : new Error(String(err)));
        }
      };

      void runLookup();
    };

    const requestOptions: Record<string, unknown> = {
      method: 'GET',
      headers: {
        'User-Agent': 'DotsPlatform-Agent/1.0 (+https://github.com/saiyedsimnan123/dots-platform)',
        'Accept': 'text/html,application/xhtml+xml,application/json,text/plain;q=0.9,*/*;q=0.8',
        'Accept-Encoding': 'identity' // Prevent compressed streams to enforce accurate byte counters
      },
      timeout: timeoutMs
    };

    // Only apply custom lookup for hostnames (IP literals bypass DNS lookup in Node)
    if (!isIpLiteral) {
      requestOptions.lookup = customLookup;
    }

    const hopResult = await new Promise<{
      redirectUrl?: string;
      status: number;
      contentType: string;
      body: string;
      byteSize: number;
    }>((resolveHop, rejectHop) => {
      let isSettled = false;
      const timer = setTimeout(() => {
        if (!isSettled) {
          isSettled = true;
          req.destroy(new ToolExecutionError('web_fetch', `Request timed out after ${timeoutMs}ms.`));
          rejectHop(new ToolExecutionError('web_fetch', `Request timed out after ${timeoutMs}ms.`));
        }
      }, timeoutMs);
      timer.unref?.();

      const req = requester(currentUrl, requestOptions, (res) => {
        const statusCode = res.statusCode ?? 200;

        // Redirect Handling
        if ([301, 302, 303, 307, 308].includes(statusCode)) {
          clearTimeout(timer);
          res.resume(); // Discard redirect body
          const locationHeader = res.headers.location;
          if (locationHeader) {
            isSettled = true;
            resolveHop({
              redirectUrl: locationHeader,
              status: statusCode,
              contentType: '',
              body: '',
              byteSize: 0
            });
            return;
          }
        }

        const rawContentType = res.headers['content-type'] || 'text/plain';
        if (!isSupportedContentType(rawContentType)) {
          clearTimeout(timer);
          isSettled = true;
          res.destroy();
          rejectHop(
            new ValidationError(
              `Unsupported Content-Type '${rawContentType}'. Web fetch only supports text, HTML, JSON, and document formats.`,
              { contentType: rawContentType }
            )
          );
          return;
        }

        // Content-Length preliminary check
        const contentLengthHeader = res.headers['content-length'];
        if (contentLengthHeader) {
          const declaredBytes = Number(contentLengthHeader);
          if (Number.isFinite(declaredBytes) && declaredBytes > maxBytes) {
            clearTimeout(timer);
            isSettled = true;
            res.destroy();
            rejectHop(
              new ValidationError(
                `Response Content-Length (${declaredBytes} bytes) exceeds maximum limit of ${maxBytes} bytes.`,
                { maxBytes, declaredBytes }
              )
            );
            return;
          }
        }

        const chunks: Buffer[] = [];
        let accumulatedBytes = 0;

        res.on('data', (chunk: Buffer) => {
          accumulatedBytes += chunk.length;
          if (accumulatedBytes > maxBytes) {
            clearTimeout(timer);
            isSettled = true;
            res.destroy();
            rejectHop(
              new ValidationError(
                `Response body exceeded maximum limit of ${maxBytes} bytes.`,
                { maxBytes, accumulatedBytes }
              )
            );
            return;
          }
          chunks.push(chunk);
        });

        res.on('end', () => {
          clearTimeout(timer);
          if (!isSettled) {
            isSettled = true;
            const fullBuffer = Buffer.concat(chunks);
            const bodyText = fullBuffer.toString('utf8');
            resolveHop({
              status: statusCode,
              contentType: rawContentType,
              body: bodyText,
              byteSize: accumulatedBytes
            });
          }
        });

        res.on('error', (err) => {
          clearTimeout(timer);
          if (!isSettled) {
            isSettled = true;
            rejectHop(err);
          }
        });
      });

      req.on('error', (err) => {
        clearTimeout(timer);
        if (!isSettled) {
          isSettled = true;
          rejectHop(err);
        }
      });

      req.end();
    });

    if (hopResult.redirectUrl) {
      redirectCount++;
      if (redirectCount > maxRedirects) {
        throw new ValidationError(`Exceeded maximum allowed redirect depth of ${maxRedirects} hops.`);
      }

      // Re-resolve and re-validate redirect target
      const resolvedRedirect = new URL(hopResult.redirectUrl, currentUrl);
      currentUrl = validateTargetUrl(resolvedRedirect.toString(), allowLoopback);
      continue;
    }

    // Success response reached
    let extractedTitle = '';
    let extractedContent = hopResult.body;

    const mime = hopResult.contentType.split(';')[0]!.trim().toLowerCase();
    if (extractText && (mime === 'text/html' || mime === 'application/xhtml+xml')) {
      const parsed = extractHtmlText(hopResult.body);
      extractedTitle = parsed.title;
      extractedContent = parsed.text;
    }

    const cleanInitialUrl = defaultSecretScrubber.scrub(initialUrl);
    const cleanFinalUrl = defaultSecretScrubber.scrub(currentUrl.toString());
    const scrubbedTitle = defaultSecretScrubber.scrub(extractedTitle);
    const scrubbedContent = defaultSecretScrubber.scrub(extractedContent);

    return {
      url: cleanInitialUrl,
      finalUrl: cleanFinalUrl,
      status: hopResult.status,
      contentType: hopResult.contentType,
      byteSize: hopResult.byteSize,
      durationMs: Date.now() - startTime,
      title: scrubbedTitle,
      content: scrubbedContent
    };
  }
}

// --- Registered Tool Definitions & Handlers ---

export const webSearchTool: RegisteredTool = {
  definition: {
    name: WEB_SEARCH_TOOL_NAME,
    description: 'Searches the web using a configured search provider and returns structured, verified results (title, url, snippet, domain).',
    parameters: {
      query: {
        type: 'string',
        description: 'The search query to look up on the web'
      },
      limit: {
        type: 'number',
        description: 'Maximum number of results to return (default: 5, max: 20)'
      }
    },
    required: ['query']
  },
  riskTier: 'TIER_3',
  handler: async (args: Record<string, unknown>): Promise<ToolExecutionResult> => {
    const start = Date.now();
    const rawQuery = args.query;

    if (typeof rawQuery !== 'string' || rawQuery.trim() === '') {
      throw new ValidationError('Search query must be a non-empty string.');
    }
    const query = rawQuery.trim();

    let limit = DEFAULT_SEARCH_LIMIT;
    if (args.limit !== undefined && args.limit !== null) {
      const n = Number(args.limit);
      if (!Number.isInteger(n) || n < 1) {
        throw new ValidationError('Search limit must be a positive integer.');
      }
      limit = Math.min(n, MAX_SEARCH_LIMIT);
    }

    const provider = getWebSearchProvider();
    if (!provider) {
      throw new ToolExecutionError(
        WEB_SEARCH_TOOL_NAME,
        'Web search provider is not configured. Configure an active web search provider (e.g. set DOTS_WEB_SEARCH_PROVIDER=duckduckgo or DOTS_SEARXNG_URL=https://...) before executing searches.'
      );
    }

    const response = await provider.search(query, limit);

    // Validate and clean results
    const scrubbedResults: WebSearchResult[] = [];
    for (const item of response.results) {
      if (!item.url || typeof item.url !== 'string') {
        continue;
      }
      let domain = item.domain || '';
      try {
        const u = new URL(item.url);
        if (u.protocol !== 'http:' && u.protocol !== 'https:') {
          continue;
        }
        domain = u.hostname;
      } catch {
        continue;
      }

      scrubbedResults.push({
        title: defaultSecretScrubber.scrub(item.title || ''),
        url: defaultSecretScrubber.scrub(item.url),
        snippet: defaultSecretScrubber.scrub(item.snippet || ''),
        domain: defaultSecretScrubber.scrub(domain)
      });
    }

    const output: WebSearchResponse = {
      query: defaultSecretScrubber.scrub(query),
      provider: provider.name,
      count: scrubbedResults.length,
      results: scrubbedResults
    };

    return {
      output: output as unknown as Record<string, unknown>,
      exitCode: 0,
      durationMs: Date.now() - start
    };
  }
};

export const webFetchTool: RegisteredTool = {
  definition: {
    name: WEB_FETCH_TOOL_NAME,
    description: 'Safely fetches a public HTTP or HTTPS web page, validates safety (preventing SSRF and DNS rebinding), and returns extracted text and metadata.',
    parameters: {
      url: {
        type: 'string',
        description: 'The public HTTP or HTTPS URL to fetch'
      },
      extractText: {
        type: 'boolean',
        description: 'Whether to extract readable plain text from HTML (defaults to true)'
      },
      maxBytes: {
        type: 'number',
        description: 'Maximum allowed response size in bytes (defaults to 2097152 / 2MB, max 10485760 / 10MB)'
      },
      timeoutMs: {
        type: 'number',
        description: 'Request timeout in milliseconds (defaults to 10000ms / 10s, max 30000ms / 30s)'
      }
    },
    required: ['url']
  },
  riskTier: 'TIER_3',
  handler: async (args: Record<string, unknown>): Promise<ToolExecutionResult> => {
    const rawUrl = args.url;
    if (typeof rawUrl !== 'string' || rawUrl.trim() === '') {
      throw new ValidationError('URL must be a non-empty string.');
    }

    const extractText = args.extractText === undefined ? true : Boolean(args.extractText);
    const maxBytes = args.maxBytes !== undefined ? Number(args.maxBytes) : undefined;
    const timeoutMs = args.timeoutMs !== undefined ? Number(args.timeoutMs) : undefined;

    try {
      const result = await safeFetch(rawUrl, {
        extractText,
        maxBytes,
        timeoutMs
      });

      return {
        output: result as unknown as Record<string, unknown>,
        exitCode: 0,
        durationMs: result.durationMs
      };
    } catch (err) {
      if (err instanceof SecurityViolationError || err instanceof ValidationError) {
        throw err;
      }
      throw new ToolExecutionError(
        WEB_FETCH_TOOL_NAME,
        defaultSecretScrubber.scrub(err instanceof Error ? err.message : String(err))
      );
    }
  }
};

export const webTools: readonly RegisteredTool[] = [
  webSearchTool,
  webFetchTool
];
