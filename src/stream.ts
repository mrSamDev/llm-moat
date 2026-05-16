/**
 * Streaming classification helpers for scanning long or incrementally received
 * documents for prompt-injection patterns.
 */
import { classify } from "./classify.ts";
import { DEFAULT_MAX_INPUT_LENGTH, RISK_ORDER } from "./rules.ts";
import type { ClassificationResult, RiskLevel, StreamClassifier, StreamClassifierOptions, StreamTelemetryEvent } from "./types.ts";

function safeHook(fn: () => void): void {
  try {
    fn();
  } catch {
    // hooks are best-effort, never let them break streaming
  }
}

/**
 * Creates a streaming classifier that processes text in chunks.
 *
 * Feed chunks one at a time. The classifier:
 *   - Accumulates chunks up to maxInputLength (default 16KB)
 *   - Returns a ClassificationResult immediately when a threat at or above
 *     earlyExitRisk is detected (default "high"), so you can short-circuit
 *     large document processing early
 *   - Returns the full accumulated result on flush()
 *
 * Handles cross-chunk patterns by accumulating the full text rather than
 * processing chunks independently.
 *
 * ⚠️ Performance note: each feed() re-classifies the full accumulated buffer from
 * the start (O(n²) total work for a clean document). For large documents without
 * early exit, prefer:
 *   - Using classify() directly on the complete text
 *   - Feeding larger chunks to reduce the number of passes
 *   - Using feedBatch() for bulk processing (single classify call)
 *
 * Example:
 *   const scanner = createStreamClassifier();
 *   for await (const chunk of documentStream) {
 *     const earlyResult = scanner.feed(chunk);
 *     if (earlyResult) { // high-risk found, stop processing
 *       return earlyResult;
 *     }
 *   }
 *   const finalResult = scanner.flush();
 */
export function createStreamClassifier(options?: StreamClassifierOptions): StreamClassifier {
  const maxInputLength =
    options?.maxInputLength === false ? Infinity : (options?.maxInputLength ?? DEFAULT_MAX_INPUT_LENGTH);
  const earlyExitRisk: RiskLevel = options?.earlyExitRisk ?? "high";

  // Pass maxInputLength: false to classify() — the stream classifier enforces
  // its own length limit by truncating accumulated input before calling classify.
  // Strip onTelemetry so internal classify() calls don't fire stream-level telemetry;
  // the stream fires its own onTelemetry once from flush().
  const { onTelemetry: _streamTelemetry, ...classifyHooks } = options?.hooks ?? {};
  const classifyOptions = { ...options, maxInputLength: false as const, hooks: classifyHooks };

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

      const result = classify(accumulated, classifyOptions);
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

      const result = classify(accumulated, classifyOptions);
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
