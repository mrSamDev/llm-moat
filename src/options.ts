import type { CanonicalizeOptions } from "./canonicalize.ts";
import type {
  ClassificationResult,
  ContextExhaustionOptions,
  RuleDefinition,
  RiskLevel,
  SemanticClassifierAdapter,
} from "./domain.ts";
import type { ClassificationHooks, SanitizationHooks, StreamHooks } from "./hooks.ts";

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

/** Options for the synchronous rule-based classifier. */
export type ClassifierOptions = {
  ruleSet?: RuleDefinition[];
  contextExhaustion?: ContextExhaustionOptions | false;
  /**
   * Maximum input length in characters before throwing InputTooLongError.
   * Set to `false` to disable (not recommended for untrusted input).
   * Default: 16384 (16KB).
   */
  maxInputLength?: number | false;
  /** Canonicalization options. Default: { normalization: "NFC" } */
  canonicalize?: CanonicalizeOptions;
  /** Observability hooks. All callbacks are best-effort — errors inside hooks are swallowed. */
  hooks?: ClassificationHooks;
};

/** Options for classification that may fall back to a semantic adapter. */
export type AsyncClassifierOptions = ClassifierOptions & {
  adapter: SemanticClassifierAdapter;
  /**
   * Explicit identifier for this classifier configuration. When provided,
   * cache and circuit-breaker state is keyed by this string instead of by
   * object identity, so fresh option objects still share persistent state.
   */
  id?: string;
  fallbackToRulesOnError?: boolean;
  /** Enable caching of adapter results. Default: false */
  cache?: {
    /** Maximum number of entries to cache. Default: 1000 */
    maxEntries?: number;
    /** TTL in milliseconds. Default: 5 minutes */
    ttlMs?: number;
  };
  /** Circuit breaker configuration. Disabled if not set. */
  circuitBreaker?: {
    /** Number of failures before opening circuit. Default: 5 */
    failureThreshold?: number;
    /** Time in ms before attempting reset. Default: 30 seconds */
    resetTimeoutMs?: number;
  };
};

/** Options for incrementally classifying a document as chunks arrive. */
export type StreamClassifierOptions = ClassifierOptions & {
  /**
   * Risk level at which the stream classifier emits a result immediately
   * without waiting for more chunks. Default: "high".
   */
  earlyExitRisk?: RiskLevel;
  /**
   * Size of the trailing window (in characters) scanned on each feed() for
   * early-exit threat detection. A larger window catches longer cross-chunk
   * patterns but increases per-chunk CPU. Default: 1024.
   *
   * Threats outside the window are caught at flush(), not on feed(). If
   * earlyExitRisk is "medium", ensure this covers the longest expected pattern.
   */
  scanWindowSize?: number;
  /** Observability hooks for streaming. All callbacks are best-effort — errors inside hooks are swallowed. */
  hooks?: StreamHooks;
};

/** Reusable stateful classifier for chunked input streams. */
export type StreamClassifier = {
  /** Feed a chunk of text. Returns a ClassificationResult immediately if a threat at or above earlyExitRisk is found, otherwise null. */
  feed(chunk: string): ClassificationResult | null;
  /** Feed multiple chunks at once. More efficient than individual feed() calls for batch processing. */
  feedBatch(chunks: string[]): ClassificationResult | null;
  /** Flush accumulated input and return the final classification result. */
  flush(): ClassificationResult;
  /** Reset the classifier to its initial state for reuse. */
  reset(): void;
};

/** Options for redacting or passing through untrusted text. */
export type SanitizationOptions = {
  redactionText?: string;
  rules?: RuleDefinition[];
  redactRiskLevels?: RiskLevel[];
  maxInputLength?: number | false;
  /** Canonicalization options. Default: { normalization: "NFC" } */
  canonicalize?: CanonicalizeOptions;
  /** Observability hooks. All callbacks are best-effort — errors inside hooks are swallowed. */
  hooks?: SanitizationHooks;
};