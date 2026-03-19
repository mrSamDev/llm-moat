import type { RiskLevel, RuleDefinition, RuleMatch, RuleSetJson } from "./types";

export { defaultRuleSet } from "./default-rules";

export const DEFAULT_MAX_INPUT_LENGTH = 16384;

export const RISK_ORDER: Record<RiskLevel, number> = { high: 0, medium: 1, low: 2 };

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
    if (!rule.id) throw new Error(`loadRuleSetFromJson: ${loc} missing "id"`);
    if (!Array.isArray(rule.patterns) || rule.patterns.length === 0) {
      throw new Error(`loadRuleSetFromJson: rule "${rule.id}" missing "patterns" array`);
    }
    if (!rule.risk) throw new Error(`loadRuleSetFromJson: rule "${rule.id}" missing "risk"`);
    if (!rule.category) throw new Error(`loadRuleSetFromJson: rule "${rule.id}" missing "category"`);
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
