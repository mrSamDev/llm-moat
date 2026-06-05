/**
 * Streaming classification helpers for scanning long or incrementally received
 * documents for prompt-injection patterns.
 */
import { classify } from "./classify.ts";
import { safeHook } from "./errors.ts";
import { DEFAULT_MAX_INPUT_LENGTH, RISK_ORDER } from "./rules.ts";
import type { ClassificationResult, RiskLevel, StreamClassifier, StreamClassifierOptions, StreamTelemetryEvent } from "./types.ts";

/**
 * Streaming classifier for chunked documents.
 *
 * Scans a trailing window on each feed() so cross-chunk patterns are still
 * caught, but total work stays O(total_input) for clean documents instead of
 * O(n²).
 */
export function createStreamClassifier(options?: StreamClassifierOptions): StreamClassifier {
  const maxInputLength =
    options?.maxInputLength === false ? Infinity : (options?.maxInputLength ?? DEFAULT_MAX_INPUT_LENGTH);
  const earlyExitRisk: RiskLevel = options?.earlyExitRisk ?? "high";
  const scanWindowSize = options?.scanWindowSize ?? 1024;

  // Pass maxInputLength: false to classify() — the stream classifier enforces
  // its own length limit by truncating accumulated input before calling classify.
  // Strip onTelemetry so internal classify() calls don't fire stream-level telemetry;
  // the stream fires its own onTelemetry once from flush().
  const { onTelemetry: _streamTelemetry, ...classifyHooks } = options?.hooks ?? {};
  const classifyOptions = { ...options, maxInputLength: false as const, hooks: classifyHooks };
  // Window scans operate on partial text; context-exhaustion only makes sense for the full document.
  const windowClassifyOptions = { ...classifyOptions, contextExhaustion: false as const };

  let accumulated = "";
  let isCommitted = false;
  let isCommittedResult: ClassificationResult | null = null;
  let chunkIndex = 0;
  let startTime = Date.now();

  function checkAndCommit(result: ClassificationResult): ClassificationResult | null {
    if (RISK_ORDER[result.risk] <= RISK_ORDER[earlyExitRisk]) {
      isCommitted = true;
      isCommittedResult = result;
      return result;
    }
    return null;
  }

  // Scan only the trailing window for early-exit threats. If a threat is found,
  // re-run on the full accumulated text so canonicalInput, rawInput, and
  // context-exhaustion results are correct for the final verdict.
  function scanWindow(): ClassificationResult {
    const scanTarget = accumulated.length > scanWindowSize
      ? accumulated.slice(-scanWindowSize)
      : accumulated;
    const result = classify(scanTarget, windowClassifyOptions);
    if (RISK_ORDER[result.risk] <= RISK_ORDER[earlyExitRisk]) {
      return classify(accumulated, classifyOptions);
    }
    return result;
  }

  return {
    feed(chunk: string): ClassificationResult | null {
      if (isCommitted) {
        safeHook(() =>
          options?.hooks?.onChunk?.({
            chunkIndex: chunkIndex++,
            accumulatedLength: accumulated.length,
            earlyResult: isCommittedResult,
          }),
        );
        return isCommittedResult;
      }

      accumulated += chunk;

      if (accumulated.length > maxInputLength) {
        accumulated = accumulated.slice(0, maxInputLength);
        isCommitted = true;
        isCommittedResult = classify(accumulated, classifyOptions);
        safeHook(() =>
          options?.hooks?.onChunk?.({
            chunkIndex: chunkIndex++,
            accumulatedLength: accumulated.length,
            earlyResult: isCommittedResult,
          }),
        );
        return isCommittedResult;
      }

      const result = scanWindow();
      const earlyExit = checkAndCommit(result);
      
      safeHook(() =>
        options?.hooks?.onChunk?.({
          chunkIndex: chunkIndex++,
          accumulatedLength: accumulated.length,
          earlyResult: earlyExit,
        }),
      );
      
      return earlyExit;
    },

    feedBatch(chunks: string[]): ClassificationResult | null {
      if (isCommitted) {
        return isCommittedResult;
      }

      // Accumulate all chunks first, then classify once (O(n) instead of O(n²))
      for (const chunk of chunks) {
        accumulated += chunk;
        if (accumulated.length > maxInputLength) {
          accumulated = accumulated.slice(0, maxInputLength);
          break;
        }
      }

      const result = scanWindow();
      const earlyExit = checkAndCommit(result);

      // Fire onChunk for the batch (use last chunk index)
      safeHook(() =>
        options?.hooks?.onChunk?.({
          chunkIndex: chunkIndex++,
          accumulatedLength: accumulated.length,
          earlyResult: earlyExit,
        }),
      );

      return earlyExit;
    },

    flush(): ClassificationResult {
      const result = isCommittedResult ?? classify(accumulated, classifyOptions);
      const totalDurationMs = Date.now() - startTime;
      safeHook(() => options?.hooks?.onFlush?.(result, { totalDurationMs }));
      safeHook(() => {
        const event: StreamTelemetryEvent = {
          kind: "stream-flush",
          timestamp: Date.now(),
          durationMs: totalDurationMs,
          inputLength: accumulated.length,
          risk: result.risk,
          category: result.category,
          confidence: result.confidence,
          matchedRuleIds: result.matchedRuleIds,
          source: result.source,
        };
        options?.hooks?.onTelemetry?.(event);
      });
      return result;
    },

    reset(): void {
      accumulated = "";
      isCommitted = false;
      isCommittedResult = null;
      chunkIndex = 0;
      startTime = Date.now();
    },
  };
}
