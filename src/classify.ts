/**
 * Synchronous rule-based classification with optional context-exhaustion checks
 * and compound-attack detection.
 */
import { canonicalize, type CanonicalizeOptions } from "./canonicalize.ts";
import { guardInputLength, safeHook } from "./errors.ts";
import { DEFAULT_MAX_INPUT_LENGTH, defaultRuleSet, findAllRuleMatches } from "./rules.ts";
import type {
  ClassificationResult,
  ClassifyTelemetryEvent,
  ClassifierOptions,
  RiskLevel,
  RuleDefinition,
  RuleMatch,
} from "./types.ts";

function getRules(options?: ClassifierOptions): RuleDefinition[] {
  return options?.ruleSet ?? defaultRuleSet;
}

const CONFIDENCE_SINGLE_MEDIUM = 0.6;
const CONFIDENCE_MULTI_MEDIUM = 0.72;
const CONFIDENCE_SINGLE_HIGH = 0.9;
const CONFIDENCE_HIGH_PLUS_MEDIUM = 0.92;
const CONFIDENCE_TWO_HIGH = 0.95;
const CONFIDENCE_THREE_HIGH = 0.98;
const CONFIDENCE_CONTEXT_EXHAUSTION = 0.95;

/**
 * Derives a confidence score from the set of matched rules.
 *   0.0  : no matches (benign)
 *   0.60 : single medium-risk match
 *   0.72 : two or more medium-risk matches
 *   0.90 : single high-risk match
 *   0.92 : high + at least one medium
 *   0.95 : two high-risk matches
 *   0.98 : three or more high-risk matches
 */
function computeConfidence(matches: RuleMatch[]): number {
  if (matches.length === 0) return 0.0;
  const high = matches.filter((m) => m.risk === "high").length;
  const med = matches.filter((m) => m.risk === "medium").length;
  if (high >= 3) return CONFIDENCE_THREE_HIGH;
  if (high >= 2) return CONFIDENCE_TWO_HIGH;
  if (high === 1 && med >= 1) return CONFIDENCE_HIGH_PLUS_MEDIUM;
  if (high === 1) return CONFIDENCE_SINGLE_HIGH;
  if (med >= 2) return CONFIDENCE_MULTI_MEDIUM;
  return CONFIDENCE_SINGLE_MEDIUM;
}

function classifyFromRules(canonicalInput: string, rawInput: string, rules: RuleDefinition[]): ClassificationResult {
  const matches = findAllRuleMatches(canonicalInput, rules);
  const top = matches[0];

  if (top && (top.risk === "high" || top.risk === "medium")) {
    const allCategories = Array.from(new Set(matches.map((m) => m.category)));

    return {
      risk: top.risk,
      category: top.category,
      reason: top.reason,
      source: "rules",
      matches,
      matchedRuleIds: matches.map((m) => m.id),
      confidence: computeConfidence(matches),
      canonicalInput,
      rawInput,
      isCompoundAttack: allCategories.length > 1,
      allCategories,
    };
  }

  return {
    risk: "low",
    category: "benign",
    reason: "No injection patterns detected",
    source: "no-match",
    matches: [],
    matchedRuleIds: [],
    confidence: 0.0,
    canonicalInput,
    rawInput,
    isCompoundAttack: false,
    allCategories: [],
  };
}

function checkContextExhaustion(
  input: string,
  canonicalInput: string,
  options?: ClassifierOptions,
): ClassificationResult | null {
  if (options?.contextExhaustion === false) return null;

  const minLength = options?.contextExhaustion?.minLength ?? 400;
  const tailLength = options?.contextExhaustion?.tailLength ?? 200;
  if (input.length < minLength) return null;

  // Scan the tail once for all matches — avoids double pass.
  const tailCanonical = canonicalize(input.slice(-tailLength));
  const tailMatches = findAllRuleMatches(tailCanonical, getRules(options));
  const highMatch = tailMatches.find((m) => m.risk === "high");
  if (!highMatch) return null;

  const allCategories = Array.from(new Set(tailMatches.map((m) => m.category)));
  return {
    risk: "high",
    category: "context-exhaustion",
    reason: "Long prefix followed by injection in tail",
    source: "rules",
    matches: tailMatches,
    matchedRuleIds: tailMatches.map((m) => m.id),
    confidence: CONFIDENCE_CONTEXT_EXHAUSTION,
    canonicalInput,
    rawInput: input,
    isCompoundAttack: allCategories.length > 1,
    allCategories,
  };
}

/** Classifies input with the built-in or provided rule set. */
// fallow-ignore-next-line complexity
export function classify(input: string, options?: ClassifierOptions): ClassificationResult {
  if (typeof input !== "string") throw new TypeError("classify: input must be a string");
  const start = Date.now();
  guardInputLength(input, options?.maxInputLength, DEFAULT_MAX_INPUT_LENGTH);
  const canonicalOptions: CanonicalizeOptions = options?.canonicalize ?? { normalization: "NFC" };
  const canonicalInput = canonicalize(input, canonicalOptions);
  const exhaustion = checkContextExhaustion(input, canonicalInput, options);
  const result = exhaustion ?? classifyFromRules(canonicalInput, input, getRules(options));
  const durationMs = Date.now() - start;
  safeHook(() => options?.hooks?.onClassify?.(result, { durationMs, inputLength: input.length }));
  safeHook(() => {
    const event: ClassifyTelemetryEvent = {
      kind: "classify",
      timestamp: Date.now(),
      durationMs,
      inputLength: input.length,
      risk: result.risk,
      category: result.category,
      confidence: result.confidence,
      matchedRuleIds: result.matchedRuleIds,
      source: result.source,
    };
    options?.hooks?.onTelemetry?.(event);
  });
  return result;
}