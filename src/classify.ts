/**
 * Classification APIs for rule-based prompt-injection detection with optional
 * semantic model fallback.
 */
import { canonicalize, type CanonicalizeOptions } from "./canonicalize.ts";
import { guardInputLength } from "./errors.ts";
import { DEFAULT_MAX_INPUT_LENGTH, defaultRuleSet, findAllRuleMatches } from "./rules.ts";
import { LRUCache } from "./cache.ts";
import type {
  AdapterClassificationResult,
  AsyncClassifierOptions,
  ClassificationResult,
  ClassifierOptions,
  ClassifyTelemetryEvent,
  RiskLevel,
  RuleDefinition,
  RuleMatch,
} from "./types.ts";

function getRules(options?: ClassifierOptions): RuleDefinition[] {
  return options?.ruleSet ?? defaultRuleSet;
}

function safeHook(fn: () => void): void {
  try {
    fn();
  } catch {
    // hooks are best-effort, never let them break classification
  }
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
  };
}

function normalizeAdapterResult(
  canonicalInput: string,
  rawInput: string,
  adapterResult: AdapterClassificationResult | null,
): ClassificationResult | null {
  if (!adapterResult?.risk || !adapterResult.category) return null;

  const risk = adapterResult.risk as RiskLevel;
  const confidenceByRisk: Record<RiskLevel, number> = { high: CONFIDENCE_SINGLE_HIGH, medium: CONFIDENCE_SINGLE_MEDIUM, low: 0.0 };

  return {
    risk,
    category: adapterResult.category,
    reason: adapterResult.reason ?? `Semantic adapter classified as ${risk}`,
    source: "semantic-adapter",
    matches: adapterResult.matches ?? [],
    matchedRuleIds: adapterResult.matchedRuleIds ?? [],
    confidence: adapterResult.confidence ?? confidenceByRisk[risk],
    canonicalInput,
    rawInput,
    errors: adapterResult.errors,
  };
}

/** Classifies input with the built-in or provided rule set. */
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

/** Circuit breaker state for adapter calls. */
type CircuitBreakerState = {
  failures: number;
  lastFailureTime: number | null;
  isOpen: boolean;
};

/** Internal state for classifyWithAdapter. */
type AdapterState = {
  cache?: LRUCache<string, ClassificationResult>;
  circuitBreaker?: CircuitBreakerState;
};

function createAdapterState(options: AsyncClassifierOptions): AdapterState {
  const state: AdapterState = {};

  if (options.cache) {
    state.cache = new LRUCache({
      maxEntries: options.cache.maxEntries,
      defaultTtlMs: options.cache.ttlMs,
    });
  }

  if (options.circuitBreaker) {
    state.circuitBreaker = {
      failures: 0,
      lastFailureTime: null,
      isOpen: false,
    };
  }

  return state;
}

function shouldAllowCircuitBreakerCall(
  state: CircuitBreakerState,
  failureThreshold: number,
  resetTimeoutMs: number,
): boolean {
  if (!state.isOpen) {
    return true;
  }

  // Check if reset timeout has passed
  if (state.lastFailureTime && Date.now() - state.lastFailureTime >= resetTimeoutMs) {
    state.isOpen = false;
    state.failures = 0;
    return true;
  }

  return false;
}

function recordCircuitBreakerSuccess(state: CircuitBreakerState): void {
  state.failures = 0;
  state.isOpen = false;
}

function recordCircuitBreakerFailure(
  state: CircuitBreakerState,
  failureThreshold: number,
): void {
  state.failures++;
  state.lastFailureTime = Date.now();
  
  if (state.failures >= failureThreshold) {
    state.isOpen = true;
  }
}

/** Classifies input with rules first, then optionally consults a semantic adapter for low-risk results. */
export async function classifyWithAdapter(
  input: string,
  options: AsyncClassifierOptions,
): Promise<ClassificationResult> {
  if (typeof input !== "string") throw new TypeError("classify: input must be a string");
  const { adapter, ...classifierOptions } = options;
  const syncResult = classify(input, classifierOptions);

  if (syncResult.risk !== "low") {
    safeHook(() => options.hooks?.onAdapterCall?.(syncResult, { durationMs: 0, skipped: true }));
    return syncResult;
  }

  const state = createAdapterState(options);
  const cacheKey = syncResult.canonicalInput;

  // Check cache first
  if (state.cache) {
    const cached = state.cache.get(cacheKey);
    if (cached) {
      safeHook(() => options.hooks?.onAdapterCall?.(cached, { durationMs: 0, skipped: false }));
      return cached;
    }
  }

  // Check circuit breaker
  if (state.circuitBreaker) {
    const { failureThreshold = 5, resetTimeoutMs = 30 * 1000 } = options.circuitBreaker!;
    if (!shouldAllowCircuitBreakerCall(state.circuitBreaker, failureThreshold, resetTimeoutMs)) {
      const fallback = { ...syncResult, errors: ["Circuit breaker open - adapter calls temporarily disabled"] };
      safeHook(() =>
        options.hooks?.onAdapterCall?.(fallback, {
          durationMs: 0,
          skipped: false,
          error: "Circuit breaker open",
        }),
      );
      return fallback;
    }
  }

  const adapterStart = Date.now();
  try {
    const adapterResult = normalizeAdapterResult(
      syncResult.canonicalInput,
      syncResult.rawInput,
      await adapter.classify(syncResult.canonicalInput),
    );
    
    if (adapterResult) {
      // Record success for circuit breaker
      if (state.circuitBreaker) {
        recordCircuitBreakerSuccess(state.circuitBreaker);
      }
      
      // Cache the result
      if (state.cache) {
        state.cache.set(cacheKey, adapterResult, options.cache?.ttlMs);
      }
      
      safeHook(() =>
        options.hooks?.onAdapterCall?.(adapterResult, { durationMs: Date.now() - adapterStart, skipped: false }),
      );
      return adapterResult;
    }
    
    const fallback = { ...syncResult, errors: ["Semantic classifier returned no usable result"] };
    safeHook(() =>
      options.hooks?.onAdapterCall?.(fallback, { durationMs: Date.now() - adapterStart, skipped: false }),
    );
    return fallback;
  } catch (error) {
    // Record failure for circuit breaker
    if (state.circuitBreaker) {
      const { failureThreshold = 5 } = options.circuitBreaker!;
      recordCircuitBreakerFailure(state.circuitBreaker, failureThreshold);
    }
    
    if (options.fallbackToRulesOnError === false) {
      throw error;
    }
    const errMsg = error instanceof Error ? error.message : "Semantic classifier error";
    const fallback = { ...syncResult, errors: [errMsg] };
    safeHook(() =>
      options.hooks?.onAdapterCall?.(fallback, {
        durationMs: Date.now() - adapterStart,
        skipped: false,
        error: errMsg,
      }),
    );
    return fallback;
  }
}
