import { LRUCache } from "./cache.ts";
import { classify } from "./classify.ts";
import { safeHook } from "./errors.ts";
import type {
  AdapterClassificationResult,
  AsyncClassifierOptions,
  ClassificationResult,
  RiskLevel,
} from "./types.ts";

const CONFIDENCE_SINGLE_HIGH = 0.9;
const CONFIDENCE_SINGLE_MEDIUM = 0.6;
const CIRCUIT_BREAKER_FAILURE_THRESHOLD = 5;
const CIRCUIT_BREAKER_RESET_TIMEOUT_MS = 30_000;
const CACHE_MAX_ENTRIES = 1000;
const CACHE_DEFAULT_TTL_MS = 300_000;

type CircuitBreakerState = { failures: number; lastFailureTime: number | null; isOpen: boolean };
type AdapterState = { cache?: LRUCache<string, ClassificationResult>; circuitBreaker?: CircuitBreakerState };

// fallow-ignore-next-line complexity
function createState(options: AsyncClassifierOptions): AdapterState {
  return {
    cache: options.cache
      ? new LRUCache({ maxEntries: options.cache.maxEntries ?? CACHE_MAX_ENTRIES, defaultTtlMs: options.cache.ttlMs ?? CACHE_DEFAULT_TTL_MS })
      : undefined,
    circuitBreaker: options.circuitBreaker ? { failures: 0, lastFailureTime: null, isOpen: false } : undefined,
  };
}

function circuitBreakerAllows(state: CircuitBreakerState, threshold: number, resetMs: number): boolean {
  if (!state.isOpen) return true;
  if (state.lastFailureTime && Date.now() - state.lastFailureTime >= resetMs) {
    state.isOpen = false;
    state.failures = 0;
    return true;
  }
  return false;
}

function recordSuccess(state: CircuitBreakerState): void {
  state.failures = 0;
  state.isOpen = false;
}

function recordFailure(state: CircuitBreakerState, threshold: number): void {
  state.failures++;
  state.lastFailureTime = Date.now();
  if (state.failures >= threshold) state.isOpen = true;
}

// fallow-ignore-next-line complexity
function normalizeResult(
  input: string,
  raw: string,
  result: AdapterClassificationResult | null,
): ClassificationResult | null {
  if (!result?.risk || !result.category) return null;
  const risk = result.risk as RiskLevel;
  const byRisk: Record<RiskLevel, number> = { high: CONFIDENCE_SINGLE_HIGH, medium: CONFIDENCE_SINGLE_MEDIUM, low: 0.0 };
  const matches = result.matches ?? [];
  const allCategories = matches.length > 0 ? [...new Set(matches.map((m) => m.category))] : [result.category];
  return {
    risk, category: result.category,
    reason: result.reason ?? `Semantic adapter classified as ${risk}`,
    source: "semantic-adapter", matches, matchedRuleIds: result.matchedRuleIds ?? [],
    confidence: result.confidence ?? byRisk[risk],
    canonicalInput: input, rawInput: raw,
    isCompoundAttack: allCategories.length > 1, allCategories, errors: result.errors,
  };
}

// Persistent state keyed on the options object so repeated calls with the
// same options instance share cache and circuit breaker. When options.id is
// provided, state is keyed by that string instead, so fresh option objects
// with the same id still share state.
const adapterStates = new WeakMap<AsyncClassifierOptions, AdapterState>();
const namedAdapterStates = new Map<string, AdapterState>();

function getState(options: AsyncClassifierOptions): AdapterState {
  if (options.id) {
    let state = namedAdapterStates.get(options.id);
    if (!state) {
      state = createState(options);
      namedAdapterStates.set(options.id, state);
    }
    return state;
  }
  let state = adapterStates.get(options);
  if (!state) {
    state = createState(options);
    adapterStates.set(options, state);
  }
  return state;
}

/**
 * Classifies input with rules first, then optionally consults a semantic adapter
 * for low-risk results. State (cache, circuit breaker) persists across calls when
 * the same options object is reused.
 */
// fallow-ignore-next-line complexity
export async function classifyWithAdapter(
  input: string,
  options: AsyncClassifierOptions,
): Promise<ClassificationResult> {
  if (typeof input !== "string") throw new TypeError("classify: input must be a string");

  const { adapter } = options;
  const syncResult = classify(input, options);

  if (syncResult.risk !== "low") {
    safeHook(() => options.hooks?.onAdapterCall?.(syncResult, { durationMs: 0, skipped: true }));
    return syncResult;
  }

  const state = getState(options);
  const cacheKey = syncResult.canonicalInput;

  const cached = state.cache?.get(cacheKey);
  if (cached) {
    safeHook(() => options.hooks?.onAdapterCall?.(cached, { durationMs: 0, skipped: false }));
    return cached;
  }

  if (state.circuitBreaker) {
    const threshold = options.circuitBreaker!.failureThreshold ?? CIRCUIT_BREAKER_FAILURE_THRESHOLD;
    const resetMs = options.circuitBreaker!.resetTimeoutMs ?? CIRCUIT_BREAKER_RESET_TIMEOUT_MS;
    if (!circuitBreakerAllows(state.circuitBreaker, threshold, resetMs)) {
      const fallback: ClassificationResult = { ...syncResult, errors: ["Circuit breaker open — adapter calls temporarily disabled"] };
      safeHook(() => options.hooks?.onAdapterCall?.(fallback, { durationMs: 0, skipped: false, error: "Circuit breaker open" }));
      return fallback;
    }
  }

  const start = Date.now();
  try {
    const adapterResult = normalizeResult(syncResult.canonicalInput, syncResult.rawInput, await adapter.classify(syncResult.canonicalInput));
    if (adapterResult) {
      state.circuitBreaker && recordSuccess(state.circuitBreaker);
      state.cache?.set(cacheKey, adapterResult, options.cache?.ttlMs);
      safeHook(() => options.hooks?.onAdapterCall?.(adapterResult, { durationMs: Date.now() - start, skipped: false }));
      return adapterResult;
    }
    const fallback: ClassificationResult = { ...syncResult, errors: ["Semantic classifier returned no usable result"] };
    safeHook(() => options.hooks?.onAdapterCall?.(fallback, { durationMs: Date.now() - start, skipped: false }));
    return fallback;
  } catch (error) {
    if (state.circuitBreaker) {
      recordFailure(state.circuitBreaker, options.circuitBreaker!.failureThreshold ?? CIRCUIT_BREAKER_FAILURE_THRESHOLD);
    }
    if (options.fallbackToRulesOnError === false) throw error;
    const errorMessage = error instanceof Error ? error.message : "Semantic classifier error";
    const fallback: ClassificationResult = { ...syncResult, errors: [errorMessage] };
    safeHook(() => options.hooks?.onAdapterCall?.(fallback, { durationMs: Date.now() - start, skipped: false, error: errorMessage }));
    return fallback;
  }
}