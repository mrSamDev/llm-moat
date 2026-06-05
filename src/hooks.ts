import type { ClassificationResult, RiskLevel, SanitizationResult, ThreatCategory } from "./domain.ts";

// ---------------------------------------------------------------------------
// Telemetry events
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