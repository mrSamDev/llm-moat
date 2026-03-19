/**
 * Pre-built mock adapters for use in integration tests.
 */
import type { SemanticClassifierAdapter, AdapterClassificationResult } from "../../src/types";

/** Always returns the given result (or null). */
export function staticAdapter(result: AdapterClassificationResult | null): SemanticClassifierAdapter {
  return { classify: async () => result };
}

/** Always throws with the given message. */
export function failingAdapter(message: string): SemanticClassifierAdapter {
  return {
    classify: async () => {
      throw new Error(message);
    },
  };
}

/** Tracks how many times it was called. */
export function trackingAdapter(result: AdapterClassificationResult | null = null): SemanticClassifierAdapter & { callCount: number } {
  let callCount = 0;
  return {
    get callCount() { return callCount; },
    classify: async () => {
      callCount++;
      return result;
    },
  };
}

/** Returns different results for successive calls. */
export function sequenceAdapter(results: Array<AdapterClassificationResult | null>): SemanticClassifierAdapter {
  let index = 0;
  return {
    classify: async () => {
      const result = results[index] ?? null;
      index++;
      return result;
    },
  };
}
