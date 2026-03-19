# Changelog

All notable changes to `prompt-defense` are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [0.2.0] — Unreleased

### Added

**Multi-match classification**
- `classify()` and `classifyWithAdapter()` now detect *all* rule matches in a single pass, not just the first.
- `ClassificationResult.matches: RuleMatch[]` — all matched rules, sorted high → medium → low.
- `matchedRuleIds` now reflects every matched rule (was previously limited to 1 entry).
- `findAllRuleMatches(canonicalInput, rules)` — exported for direct use.

**Confidence scores**
- `ClassificationResult.confidence: number` (0.0–1.0) — derived from match count and risk level for rule-based results; adapter-provided for semantic results.
- Compound attacks (multiple high-risk matches) are scored higher than single matches.

**Streaming classifier**
- `createStreamClassifier(options?)` — process text in chunks; emits early on threat detection.
- Cross-chunk patterns are detected correctly by accumulating input.
- Configurable `earlyExitRisk` (default `"high"`) and `maxInputLength`.

**Portable JSON rule format**
- `loadRuleSetFromJson(json)` — parse a JSON rule set from string or object. Validates IDs, patterns, flags, and throws descriptively on misconfiguration.
- `exportRuleSetToJson(rules, meta?)` — serialize a rule set to JSON for sharing or storage.
- The `g` flag is explicitly forbidden in JSON patterns (prevents stateful `.test()` bugs).

**Input length guard (ReDoS mitigation)**
- All entry points (`classify`, `sanitizeUntrustedText`, stream classifier) enforce a maximum input length before processing. Default: 16384 characters (16KB).
- `InputTooLongError` — typed error with `.length` and `.maxLength` fields.
- `DEFAULT_MAX_INPUT_LENGTH` — exported constant.
- Disable with `maxInputLength: false` (not recommended for untrusted input).

**New rules**
- `stored-injection` (high) — detects instructions embedded in retrieved data (database records, documents).
- `role-confusion` (high) — detects attempts to redefine the AI's identity or persona.

**ReDoS hardening**
- Eliminated all patterns with **multiple chained `{0,N}` wildcard groups**, which cause O(N²)–O(N³) backtracking attempts per match position with crafted inputs:
  - `stored-injection`: replaced `when...{0,60}...retrieved...{0,60}...database...{0,60}...execute` (3 groups, up to 216,000 attempts) with specific keyword-pair patterns (no wildcards between keywords)
  - `indirect-injection`: collapsed `summarize...{0,60}...(apply|run)...{0,60}...(update|change)` (2 groups) into a single-wildcard pattern (60 attempts max)
  - `role-confusion`: replaced `your real...{0,40}...persona...{0,40}...is` (2 groups) with specific keyword enumeration — no wildcards needed
- Single `{0,N}` wildcard groups (O(N) backtracking) are retained where necessary and are safe given the 16KB input cap.
- Added a timing-based ReDoS probe test to catch regressions.

**`createRuleSet()` validation**
- Now validates that all rule IDs are unique and all patterns are `RegExp` instances. Throws at initialization time rather than silently at match time.

### Changed

- `classifyWithAdapter(input, options)` — `adapter` is now a required field in `options` (was the second positional argument). **Breaking change** for callers of the previous signature.
- `ClassificationResult.source` — `"fallback"` renamed to `"no-match"`. **Breaking change** for callers checking this field.
- `sanitizeUntrustedText` default `redactRiskLevels` changed from `["high"]` to `["high", "medium"]`. Medium-risk threats (indirect-injection, data-exfiltration, excessive-agency) are now redacted by default.
- Tool-abuse rule patterns generalized: replaced app-specific `updaterole`/`updateemail` patterns with generic `execute/run/call/invoke the (tool|function|command)` patterns.

### Package

- Renamed from `@lab/prompt-defense` to `prompt-defense`.
- Build pipeline: tsup replaces the no-op build script. Outputs ESM, CJS, and `.d.ts` for all entry points.
- Exports: `prompt-defense`, `prompt-defense/adapters/llm`, `prompt-defense/adapters/anthropic`.
- New adapters: `createOpenAIAdapter`, `createOllamaAdapter`, `createAnthropicAdapter`.
- `createOllamaAdapter` — zero-config local inference via Ollama (`http://localhost:11434`). No API key required.
- `createOpenAIAdapter` — thin wrapper with `gpt-4o-mini` default and optional `organization` header.
- Shared adapter utilities extracted to `src/adapters/shared.ts`: `DEFAULT_CLASSIFICATION_PROMPT`, `parseClassifierJson`, `VALID_RISKS`, `VALID_CATEGORIES`.
- `DEFAULT_CLASSIFICATION_PROMPT` exported from main package for use with custom adapters.
- `@anthropic-ai/sdk` added as optional peer dependency.

---

## [0.1.0] — Unreleased (baseline)

Initial implementation extracted from internal monorepo.

### Features
- `classify()` — synchronous rule-based classification across 13 threat categories
- `classifyWithAdapter()` — async classification with semantic adapter fallback
- `sanitizeUntrustedText()` — redact untrusted text at trust boundaries
- `labelUntrustedText()` — wrap untrusted content with explicit trust boundary markers
- `canonicalize()` — normalize input (escape decoding, entity decoding, invisible char stripping, whitespace normalization)
- `createOpenAICompatibleAdapter()` — semantic classifier using any OpenAI-compatible API
- Context exhaustion detection (long prefix + injection in tail)
- Custom rule set support
