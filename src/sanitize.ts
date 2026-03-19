/**
 * Sanitization helpers for wrapping untrusted text and redacting content that
 * matches prompt-injection rules.
 */
import { canonicalize } from "./canonicalize";
import { guardInputLength } from "./errors";
import { DEFAULT_MAX_INPUT_LENGTH, defaultRuleSet, findAllRuleMatches } from "./rules";
import type { SanitizationOptions, SanitizationResult, TrustBoundaryOptions } from "./types";

function safeHook(fn: () => void): void {
  try {
    fn();
  } catch {
    // hooks are best-effort — never let them break sanitization
  }
}

/** Wraps untrusted content in explicit boundary markers for downstream prompts. */
export function labelUntrustedText(text: string, options?: TrustBoundaryOptions): string {
  const sourceLabel = options?.sourceLabel ?? "untrusted data";
  const instructionAuthority = options?.instructionAuthority ?? "none";
  const emptyPlaceholder = options?.emptyPlaceholder ?? "(no data)";

  return [
    `--- BEGIN UNTRUSTED DATA (source: ${sourceLabel}, instruction authority: ${instructionAuthority}) ---`,
    text || emptyPlaceholder,
    "--- END UNTRUSTED DATA ---",
  ].join("\n");
}

/** Redacts untrusted text when configured risk levels match the active rule set. */
export function sanitizeUntrustedText(text: string, options?: SanitizationOptions): SanitizationResult {
  const start = Date.now();
  guardInputLength(text, options?.maxInputLength, DEFAULT_MAX_INPUT_LENGTH);

  const canonicalInput = canonicalize(text);
  const rules = options?.rules ?? defaultRuleSet;
  const redactRiskLevels = options?.redactRiskLevels ?? ["high", "medium"];
  const redactionText = options?.redactionText ?? "[content redacted by input filter]";

  const allMatches = findAllRuleMatches(canonicalInput, rules);
  const triggeredMatches = allMatches.filter((m) => redactRiskLevels.includes(m.risk));

  const result: SanitizationResult =
    triggeredMatches.length > 0
      ? {
          text: redactionText,
          redacted: true,
          matchedRuleIds: triggeredMatches.map((m) => m.id),
          reason: triggeredMatches[0].reason,
        }
      : {
          text,
          redacted: false,
          matchedRuleIds: [],
          reason: "No sanitization rules matched",
        };

  safeHook(() => options?.hooks?.onSanitize?.(result, { durationMs: Date.now() - start, inputLength: text.length }));
  return result;
}
