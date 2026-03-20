import type { RiskLevel, RuleDefinition, RuleMatch, RuleSetJson } from "./types.ts";
import { VALID_CATEGORIES, VALID_RISKS } from "./types.ts";

export { defaultRuleSet } from "./default-rules.ts";

/** Default maximum input length enforced by classification and sanitization helpers. */
export const DEFAULT_MAX_INPUT_LENGTH = 16384;

/** Sort order used to rank rule matches from most to least severe. */
export const RISK_ORDER: Record<RiskLevel, number> = { high: 0, medium: 1, low: 2 };

/** Validates and returns a reusable rule set definition array. */
export function createRuleSet(definitions: RuleDefinition[]): RuleDefinition[] {
  const seenIds = new Set<string>();
  for (const rule of definitions) {
    if (seenIds.has(rule.id)) {
      throw new Error(`createRuleSet: duplicate rule id "${rule.id}"`);
    }
    seenIds.add(rule.id);
    for (let i = 0; i < rule.patterns.length; i++) {
      if (!(rule.patterns[i] instanceof RegExp)) {
        throw new Error(`createRuleSet: rule "${rule.id}" pattern[${i}] is not a RegExp`);
      }
    }
  }
  return definitions;
}

/** Returns the first high-risk match in the tail during context-exhaustion checks. */
export function findRuleMatch(canonicalInput: string, rules: RuleDefinition[], risk: RiskLevel): RuleMatch | null {
  for (const rule of rules) {
    if (rule.risk !== risk) continue;
    if (rule.patterns.some((pattern) => pattern.test(canonicalInput))) {
      return { id: rule.id, risk: rule.risk, category: rule.category, reason: rule.reason };
    }
  }
  return null;
}

/**
 * Returns ALL rule matches across all risk levels, sorted high → medium → low.
 * Use this instead of findRuleMatch to detect compound attacks.
 */
export function findAllRuleMatches(canonicalInput: string, rules: RuleDefinition[]): RuleMatch[] {
  const matches: RuleMatch[] = [];
  for (const rule of rules) {
    if (rule.patterns.some((pattern) => pattern.test(canonicalInput))) {
      matches.push({ id: rule.id, risk: rule.risk, category: rule.category, reason: rule.reason });
    }
  }
  return matches.sort((a, b) => RISK_ORDER[a.risk] - RISK_ORDER[b.risk]);
}

/**
 * Load a rule set from a portable JSON format.
 * Throws descriptively on invalid input. Fails loudly at startup, not silently at match time.
 */
export function loadRuleSetFromJson(json: string | RuleSetJson): RuleDefinition[] {
  const parsed: RuleSetJson = typeof json === "string" ? (JSON.parse(json) as RuleSetJson) : json;

  if (!parsed.rules || !Array.isArray(parsed.rules)) {
    throw new Error('loadRuleSetFromJson: missing "rules" array');
  }

  const definitions = parsed.rules.map((rule, i) => {
    const loc = `rule at index ${i}`;
    if (rule == null) throw new Error(`loadRuleSetFromJson: ${loc} is null or undefined`);
    if (!rule.id) throw new Error(`loadRuleSetFromJson: ${loc} missing "id"`);
    if (!Array.isArray(rule.patterns) || rule.patterns.length === 0) {
      throw new Error(`loadRuleSetFromJson: rule "${rule.id}" missing "patterns" array`);
    }
    if (!rule.risk) throw new Error(`loadRuleSetFromJson: rule "${rule.id}" missing "risk"`);
    if (!VALID_RISKS.has(rule.risk)) throw new Error(`loadRuleSetFromJson: rule "${rule.id}" has invalid risk "${rule.risk}"`);
    if (!rule.category) throw new Error(`loadRuleSetFromJson: rule "${rule.id}" missing "category"`);
    if (!VALID_CATEGORIES.has(rule.category)) throw new Error(`loadRuleSetFromJson: rule "${rule.id}" has invalid category "${rule.category}"`);
    if (!rule.reason) throw new Error(`loadRuleSetFromJson: rule "${rule.id}" missing "reason"`);

    const flags = rule.flags ?? "";
    if (flags.includes("g")) {
      throw new Error(
        `loadRuleSetFromJson: rule "${rule.id}" uses the "g" flag, which causes stateful bugs with RegExp.test(). Remove it.`,
      );
    }

    const patterns = rule.patterns.map((p, j) => {
      try {
        return new RegExp(p, flags);
      } catch {
        throw new Error(`loadRuleSetFromJson: rule "${rule.id}" pattern[${j}] is not a valid regex: ${p}`);
      }
    });

    return {
      id: rule.id,
      patterns,
      risk: rule.risk,
      category: rule.category,
      reason: rule.reason,
    } satisfies RuleDefinition;
  });

  return createRuleSet(definitions);
}

const SRI_ALGORITHMS: Record<string, string> = {
  sha256: "SHA-256",
  sha384: "SHA-384",
  sha512: "SHA-512",
};

function parseSriHash(integrity: string): { algorithm: string; expected: string } {
  const match = integrity.match(/^(sha\d+)-([A-Za-z0-9+/]+=*)$/);
  if (!match) throw new Error(`loadRuleSetFromUrl: malformed integrity string`);
  const [, prefix, expected] = match;
  const algorithm = SRI_ALGORITHMS[prefix];
  if (!algorithm) throw new Error(`loadRuleSetFromUrl: unsupported algorithm ${prefix}`);
  return { algorithm, expected };
}

function bufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

/**
 * Fetch a rule set from a URL with SRI integrity verification.
 * Requires Node >= 18 (globalThis.crypto.subtle).
 * Throws descriptively on network errors, integrity mismatches, and invalid rule sets.
 */
export async function loadRuleSetFromUrl(
  url: string,
  opts: { integrity: string; signal?: AbortSignal },
): Promise<RuleDefinition[]> {
  if (!opts.integrity) throw new Error("loadRuleSetFromUrl: integrity is required");
  const { algorithm, expected } = parseSriHash(opts.integrity);

  let res: Response;
  try {
    res = await fetch(url, { signal: opts.signal });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`loadRuleSetFromUrl: network error: ${msg}`);
  }

  if (!res.ok) throw new Error(`loadRuleSetFromUrl: HTTP ${res.status} from ${url}`);

  const buffer = await res.arrayBuffer();
  const hashBuffer = await globalThis.crypto.subtle.digest(algorithm, buffer);
  const actual = bufferToBase64(hashBuffer);
  if (actual !== expected) throw new Error("loadRuleSetFromUrl: integrity mismatch");

  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(buffer);
  } catch {
    throw new Error("loadRuleSetFromUrl: response is not valid UTF-8");
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error("loadRuleSetFromUrl: response is not valid JSON");
  }

  return loadRuleSetFromJson(parsed as Parameters<typeof loadRuleSetFromJson>[0]);
}

/**
 * Serialize a rule set to the portable JSON format.
 * All patterns in a rule must share the same flags — throws if they differ.
 * Use loadRuleSetFromJson to round-trip.
 */
export function exportRuleSetToJson(rules: RuleDefinition[], meta?: { name?: string; version?: string }): string {
  const json: RuleSetJson = {
    ...meta,
    rules: rules.map((r) => {
      const flags = r.patterns[0]?.flags ?? "";
      for (let i = 1; i < r.patterns.length; i++) {
        if (r.patterns[i].flags !== flags) {
          throw new Error(
            `exportRuleSetToJson: rule "${r.id}" has patterns with different flags ("${flags}" vs "${r.patterns[i].flags}"). Normalize flags before exporting.`,
          );
        }
      }
      return {
        id: r.id,
        patterns: r.patterns.map((p) => p.source),
        ...(flags ? { flags } : {}),
        risk: r.risk,
        category: r.category,
        reason: r.reason,
      };
    }),
  };
  return JSON.stringify(json, null, 2);
}
