/** Risk levels returned by the classifier and sanitization pipeline. */
export type RiskLevel = "low" | "medium" | "high";

/** Threat categories used to label prompt-injection and related abuse patterns. */
export type ThreatCategory =
  | "direct-injection"
  | "role-escalation"
  | "tool-abuse"
  | "stored-injection"
  | "role-confusion"
  | "obfuscation"
  | "context-exhaustion"
  | "translation-attack"
  | "indirect-injection"
  | "social-engineering"
  | "prompt-leaking"
  | "jailbreak"
  | "data-exfiltration"
  | "excessive-agency"
  | "benign"
  | "custom";

/** A rule-based detection definition made of regex patterns and a classification outcome. */
export type RuleDefinition = {
  id: string;
  patterns: RegExp[];
  risk: RiskLevel;
  category: ThreatCategory;
  reason: string;
};

/** A normalized description of a rule that matched a canonicalized input. */
export type RuleMatch = {
  id: string;
  risk: RiskLevel;
  category: ThreatCategory;
  reason: string;
};

/** Final result returned by rule-based or semantic classification. */
export type ClassificationResult = {
  risk: RiskLevel;
  category: ThreatCategory;
  reason: string;
  source: "rules" | "semantic-adapter" | "no-match";
  /** All rule matches found, sorted high → medium → low. Empty when source is "no-match" or "semantic-adapter". */
  matches: RuleMatch[];
  /** All matched rule IDs. Convenience alias for matches.map(m => m.id). */
  matchedRuleIds: string[];
  /** 0.0–1.0. Derived from match count and risk levels for rule-based results; adapter-provided for semantic results. */
  confidence: number;
  canonicalInput: string;
  errors?: string[];
};

/** Tunables for detecting injection attempts hidden at the tail of long inputs. */
export type ContextExhaustionOptions = {
  minLength?: number;
  tailLength?: number;
};

// ---------------------------------------------------------------------------
// Telemetry
// ---------------------------------------------------------------------------

type TelemetryEventBase = {
  /** Unix ms timestamp at the moment the event fired. */
  timestamp: number;
  /** Elapsed time of the operation in milliseconds. */
  durationMs: number;
  /** Length of the original input string. */
  inputLength: number;
};

export type ClassifyTelemetryEvent = TelemetryEventBase & {
  kind: "classify";
  risk: RiskLevel;
  category: ThreatCategory;
  confidence: number;
  matchedRuleIds: string[];
  source: "rules" | "semantic-adapter" | "no-match";
};

export type SanitizeTelemetryEvent = TelemetryEventBase & {
  kind: "sanitize";
  redacted: boolean;
  matchedRuleIds: string[];
};

export type StreamTelemetryEvent = TelemetryEventBase & {
  kind: "stream-flush";
  risk: RiskLevel;
  category: ThreatCategory;
  confidence: number;
  matchedRuleIds: string[];
  source: "rules" | "semantic-adapter" | "no-match";
};

/** Discriminated union of all telemetry events emitted by the library. Narrow on `kind`. */
export type TelemetryEvent = ClassifyTelemetryEvent | SanitizeTelemetryEvent | StreamTelemetryEvent;

// ---------------------------------------------------------------------------
// Observability hooks
// ---------------------------------------------------------------------------

/** Timing and size metadata emitted by classification hooks. */
export type ClassifyMeta = {
  /** Elapsed time from classify() entry to return, in milliseconds. */
  durationMs: number;
  /** Length of the original (pre-canonicalization) input. */
  inputLength: number;
};

/** Metadata emitted for semantic adapter invocations or skips. */
export type AdapterMeta = {
  /** Elapsed time of the adapter call, in milliseconds. 0 when skipped. */
  durationMs: number;
  /** True when the adapter was bypassed because rules already returned non-low risk. */
  skipped: boolean;
  /** Error message if the adapter threw and fallbackToRulesOnError was true. */
  error?: string;
};

/** Lifecycle hooks for synchronous and adapter-assisted classification. */
export type ClassificationHooks = {
  /** Fired after every classify() call with the final result. */
  onClassify?: (result: ClassificationResult, meta: ClassifyMeta) => void;
  /** Fired after the semantic adapter is called (or skipped) in classifyWithAdapter(). */
  onAdapterCall?: (result: ClassificationResult, meta: AdapterMeta) => void;
  /** Fired after every classify() call with a unified telemetry event. */
  onTelemetry?: (event: ClassifyTelemetryEvent) => void;
};

/** Per-chunk metadata emitted by the streaming classifier. */
export type StreamChunkMeta = {
  /** Zero-based index of this chunk since the last reset(). */
  chunkIndex: number;
  /** Total accumulated length after this chunk was appended. */
  accumulatedLength: number;
  /** Non-null when this chunk triggered an early exit. */
  earlyResult: ClassificationResult | null;
};

/** Lifecycle hooks for streaming classification. */
export type StreamHooks = {
  /** Fired after each feed() call. */
  onChunk?: (meta: StreamChunkMeta) => void;
  /** Fired after flush() returns a result. totalDurationMs is from createStreamClassifier() or last reset(). */
  onFlush?: (result: ClassificationResult, meta: { totalDurationMs: number }) => void;
  /** Fired after flush() with a unified telemetry event. */
  onTelemetry?: (event: StreamTelemetryEvent) => void;
};

/** Timing metadata emitted by sanitization hooks. */
export type SanitizeMeta = {
  /** Elapsed time of the sanitizeUntrustedText() call, in milliseconds. */
  durationMs: number;
  /** Length of the original input. */
  inputLength: number;
};

/** Lifecycle hooks for the sanitization pipeline. */
export type SanitizationHooks = {
  /** Fired after every sanitizeUntrustedText() call with the final result. */
  onSanitize?: (result: SanitizationResult, meta: SanitizeMeta) => void;
  /** Fired after every sanitizeUntrustedText() call with a unified telemetry event. */
  onTelemetry?: (event: SanitizeTelemetryEvent) => void;
};

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
  /** Observability hooks. All callbacks are best-effort — errors inside hooks are swallowed. */
  hooks?: ClassificationHooks;
};

/** Options for classification that may fall back to a semantic adapter. */
export type AsyncClassifierOptions = ClassifierOptions & {
  adapter: SemanticClassifierAdapter;
  fallbackToRulesOnError?: boolean;
};

/** Options for incrementally classifying a document as chunks arrive. */
export type StreamClassifierOptions = ClassifierOptions & {
  /**
   * Risk level at which the stream classifier emits a result immediately
   * without waiting for more chunks. Default: "high".
   */
  earlyExitRisk?: RiskLevel;
  /** Observability hooks for streaming. All callbacks are best-effort — errors inside hooks are swallowed. */
  hooks?: StreamHooks;
};

/** Reusable stateful classifier for chunked input streams. */
export type StreamClassifier = {
  /** Feed a chunk of text. Returns a ClassificationResult immediately if a threat at or above earlyExitRisk is found, otherwise null. */
  feed(chunk: string): ClassificationResult | null;
  /** Flush accumulated input and return the final classification result. */
  flush(): ClassificationResult;
  /** Reset the classifier to its initial state for reuse. */
  reset(): void;
};

/** Contract implemented by semantic model adapters used by `classifyWithAdapter()`. */
export type SemanticClassifierAdapter = {
  classify: (canonicalInput: string) => Promise<Partial<ClassificationResult> | null>;
};

/** Labels used when wrapping untrusted content with explicit trust-boundary markers. */
export type TrustBoundaryOptions = {
  sourceLabel?: string;
  instructionAuthority?: string;
  emptyPlaceholder?: string;
};

/** Options for redacting or passing through untrusted text. */
export type SanitizationOptions = {
  redactionText?: string;
  rules?: RuleDefinition[];
  redactRiskLevels?: RiskLevel[];
  maxInputLength?: number | false;
  /** Observability hooks. All callbacks are best-effort — errors inside hooks are swallowed. */
  hooks?: SanitizationHooks;
};

/** Result returned by `sanitizeUntrustedText()`. */
export type SanitizationResult = {
  text: string;
  redacted: boolean;
  matchedRuleIds: string[];
  reason: string;
};

/**
 * Portable JSON format for sharing and loading rule sets.
 * Patterns are regex source strings (no delimiters). They are matched
 * against canonicalized (lowercased, stripped) input, so the `i` flag
 * is redundant. The `g` flag is forbidden — it causes stateful bugs with .test().
 */
export type RuleSetJson = {
  name?: string;
  version?: string;
  rules: Array<{
    id: string;
    /** Regex source strings, matched against canonicalized lowercase input. */
    patterns: string[];
    /** Regex flags. The `g` flag is not allowed. Default: "" */
    flags?: string;
    risk: RiskLevel;
    category: ThreatCategory;
    reason: string;
  }>;
};
