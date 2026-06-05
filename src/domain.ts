/** Risk levels returned by the classifier and sanitization pipeline. */
export type RiskLevel = "low" | "medium" | "high";

/** Valid risk level values for runtime validation. */
export const VALID_RISKS: Set<string> = new Set(["low", "medium", "high"]);

/** Valid threat category values for runtime validation. */
export const VALID_CATEGORIES: Set<string> = new Set([
  "direct-injection",
  "role-escalation",
  "tool-abuse",
  "stored-injection",
  "role-confusion",
  "obfuscation",
  "context-exhaustion",
  "translation-attack",
  "indirect-injection",
  "social-engineering",
  "prompt-leaking",
  "jailbreak",
  "data-exfiltration",
  "excessive-agency",
  "benign",
  "custom",
]);

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
  /** Canonicalized input used for matching. */
  canonicalInput: string;
  /** Original raw input for forensic analysis. */
  rawInput: string;
  /** True when multiple distinct threat categories detected (multi-vector attack). */
  isCompoundAttack: boolean;
  /** All unique threat categories detected. Single category for most results. */
  allCategories: ThreatCategory[];
  errors?: string[];
};

/** Tunables for detecting injection attempts hidden at the tail of long inputs. */
export type ContextExhaustionOptions = {
  minLength?: number;
  tailLength?: number;
};

/** Classification result returned by semantic adapters. Lighter weight than full ClassificationResult. */
export type AdapterClassificationResult = {
  risk: RiskLevel;
  category: ThreatCategory;
  reason?: string;
  confidence?: number;
  /** Optional rule matches if adapter provides them. */
  matches?: RuleMatch[];
  /** Optional matched rule IDs if adapter provides them. */
  matchedRuleIds?: string[];
  /** Optional errors from adapter. */
  errors?: string[];
};

/** Contract implemented by semantic model adapters used by `classifyWithAdapter()`. */
export type SemanticClassifierAdapter = {
  classify: (canonicalInput: string) => Promise<AdapterClassificationResult | null>;
};

/** Labels used when wrapping untrusted content with explicit trust-boundary markers. */
export type TrustBoundaryOptions = {
  sourceLabel?: string;
  instructionAuthority?: string;
  emptyPlaceholder?: string;
};

/** Result returned by `sanitizeUntrustedText()`. */
export type SanitizationResult = {
  text: string;
  redacted: boolean;
  matchedRuleIds: string[];
  reason: string;
  /** Original raw input for forensic analysis. */
  rawInput: string;
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