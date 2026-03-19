/**
 * Streaming classification helpers for scanning long or incrementally received
 * documents for prompt-injection patterns.
 */
import { classify } from "./classify";
import { DEFAULT_MAX_INPUT_LENGTH, RISK_ORDER } from "./rules";
import type { ClassificationResult, RiskLevel, StreamClassifier, StreamClassifierOptions } from "./types";

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
 * Performance note: each feed() re-classifies the full accumulated buffer from
 * the start (O(n²) total work for a clean document). For large documents without
 * early exit, prefer using classify() directly on the complete text, or feed
 * larger chunks to reduce the number of passes.
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
  const classifyOptions = { ...options, maxInputLength: false as const };

  let accumulated = "";
  let isCommitted = false;
  let isCommittedResult: ClassificationResult | null = null;
  let chunkIndex = 0;
  let startTime = Date.now();

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
      if (RISK_ORDER[result.risk] <= RISK_ORDER[earlyExitRisk]) {
        isCommitted = true;
        isCommittedResult = result;
        safeHook(() =>
          options?.hooks?.onChunk?.({
            chunkIndex: chunkIndex++,
            accumulatedLength: accumulated.length,
            earlyResult: result,
          }),
        );
        return result;
      }

      safeHook(() =>
        options?.hooks?.onChunk?.({ chunkIndex: chunkIndex++, accumulatedLength: accumulated.length, earlyResult: null }),
      );
      return null;
    },

    flush(): ClassificationResult {
      const result = isCommittedResult ?? classify(accumulated, classifyOptions);
      safeHook(() => options?.hooks?.onFlush?.(result, { totalDurationMs: Date.now() - startTime }));
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
