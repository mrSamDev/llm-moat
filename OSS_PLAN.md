# prompt-defense: OSS Extraction Plan

Design review completed 2026-03-19. All decisions made. Ready to implement.

## Package Identity

- **npm name:** `prompt-defense` (change from `@lab/prompt-defense`)
- **License:** MIT
- **Description:** Zero-dependency TypeScript library for detecting and sanitizing prompt injection attacks in LLM applications

---

## Decisions Made

### 1. Default sanitize risk level
**Before:** `redactRiskLevels: ["high"]`
**After:** `redactRiskLevels: ["high", "medium"]`
Medium-risk threats (indirect-injection, data-exfiltration, excessive-agency) should be redacted by default. Developers can opt down to `["high"]` if they want medium content to pass through.

### 2. Build pipeline: tsup
Replace the no-op build script with tsup. Output:
- `dist/index.js` (ESM)
- `dist/index.cjs` (CJS)
- `dist/index.d.ts` (types)

Updated `package.json` exports:
```json
{
  "main": "dist/index.cjs",
  "module": "dist/index.js",
  "types": "dist/index.d.ts",
  "exports": {
    ".": {
      "import": "./dist/index.js",
      "require": "./dist/index.cjs",
      "types": "./dist/index.d.ts"
    },
    "./adapters/llm": {
      "import": "./dist/adapters/llm.js",
      "require": "./dist/adapters/llm.cjs",
      "types": "./dist/adapters/llm.d.ts"
    },
    "./adapters/anthropic": {
      "import": "./dist/adapters/anthropic.js",
      "require": "./dist/adapters/anthropic.cjs",
      "types": "./dist/adapters/anthropic.d.ts"
    }
  },
  "files": ["dist"]
}
```

### 3. Remove app-specific tool-abuse patterns
Replace hardcoded `updaterole` / `updateemail` patterns in `rules.ts` with general-purpose patterns:
- `execute the (tool|function|command)`
- `run (the )?(tool|function|command)`
- `call (the )?(tool|function|command)`
- `invoke (the )?(tool|function|command)`

### 4. Rename `source: "fallback"` → `source: "no-match"`
In `ClassificationResult` and all places that produce `source: "fallback"`, change to `"no-match"`.

### 5. Add `stored-injection` and `role-confusion` default rules
Both categories exist in `ThreatCategory` but have no default patterns. Add:

**stored-injection** patterns:
- Content that appears to instruct when read from storage/database context
- `when.*retrieved.*from.*database.*execute`
- `this.*document.*contains.*instructions.*for.*the.*assistant`
- `[system instructions embedded in data]` variants

**role-confusion** patterns:
- `act as (a|an) (helpful|evil|unconstrained|different).*AI`
- `you are not (an AI|a language model)`
- `forget you are (an AI|claude|chatgpt|an assistant)`
- `your real.*persona.*is`

### 6. Add `adapters/anthropic.ts`
New file: `src/adapters/anthropic.ts`
Uses `@anthropic-ai/sdk` as an optional peer dependency to call Claude as a semantic classifier.
Pattern: same interface as `adapters/llm.ts` but uses the Anthropic Messages API.

```ts
export function createAnthropicAdapter(options: {
  client: Anthropic; // from @anthropic-ai/sdk
  model?: string;    // default: "claude-haiku-4-5-20251001"
  systemPrompt?: string;
}): SemanticClassifierAdapter
```

### 7. Refactor `classifyWithAdapter` signature
**Before:** `classifyWithAdapter(input, adapter, options?)`
**After:** `classifyWithAdapter(input, options)` where `AsyncClassifierOptions` gains `adapter: SemanticClassifierAdapter`

```ts
export type AsyncClassifierOptions = ClassifierOptions & {
  adapter: SemanticClassifierAdapter;
  fallbackToRulesOnError?: boolean;
};
```

### 8. Remove or fix `createRuleSet()`
`createRuleSet(definitions)` currently does `return definitions` — it's a no-op. Either:
- Add validation: check rule IDs are unique, patterns are valid RegExp
- Or remove it entirely

**Decision: add validation** — it becomes a useful constructor that catches misconfigured rule sets at initialization time rather than silently at match time.

---

## Implementation Checklist

### Packaging
- [ ] Add `tsup` to devDependencies: `pnpm add -D tsup --filter prompt-defense`
- [ ] Update `package.json`: name, version, description, keywords, license, repository, author, main, module, types, exports, files, build script
- [ ] Add `tsup.config.ts`
- [ ] Update `.gitignore` / `.npmignore` if needed
- [ ] Verify `pnpm build` produces `dist/`

### API Changes
- [ ] `sanitize.ts`: change default `redactRiskLevels` to `["high", "medium"]`
- [ ] `types.ts`: rename `source: "fallback"` → `source: "no-match"` in `ClassificationResult`
- [ ] `types.ts`: add `adapter: SemanticClassifierAdapter` to `AsyncClassifierOptions`
- [ ] `classify.ts`: update `classifyWithAdapter` signature (adapter moves into options)
- [ ] `classify.ts`: update `source: "fallback"` → `source: "no-match"` in return
- [ ] `rules.ts`: replace `updaterole`/`updateemail` patterns with generic tool invocation patterns
- [ ] `rules.ts`: add `stored-injection` rule definition with patterns
- [ ] `rules.ts`: add `role-confusion` rule definition with patterns
- [ ] `rules.ts`: add validation to `createRuleSet()` (unique IDs, valid RegExp)
- [ ] `index.ts`: ensure all new exports are included

### New Files
- [ ] `src/adapters/anthropic.ts`: Anthropic SDK adapter (peer dep: `@anthropic-ai/sdk`)
- [ ] `README.md`: full documentation (see below)
- [ ] `CHANGELOG.md`: initial entry for v0.1.0

### README Contents
- One-liner: "Zero-dependency TypeScript library for detecting and sanitizing prompt injection attacks"
- Install: `npm install prompt-defense`
- Example 1: `classify()` — basic sync detection
- Example 2: `classifyWithAdapter()` — with Anthropic semantic adapter
- Example 3: `sanitizeUntrustedText()` + `labelUntrustedText()` — trust boundary pattern
- Threat category table: all 14+ categories with description
- Custom rules example: extending the default rule set
- Adapter interface: how to write your own semantic adapter

### Tests to Add
- [ ] `canonicalize`: Base64-encoded injection, ROT13 variants, mixed encoding
- [ ] `classify`: medium-risk rules (indirect-injection, data-exfiltration, excessive-agency)
- [ ] `classify`: stored-injection patterns (new)
- [ ] `classify`: role-confusion patterns (new)
- [ ] `classify`: custom ruleSet override replaces defaults
- [ ] `classify`: context exhaustion boundary (exactly at minLength, one below)
- [ ] `sanitize`: medium-risk redaction with new default
- [ ] `sanitize`: custom `redactionText` and `rules`
- [ ] `sanitize`: `labelUntrustedText` with all options
- [ ] `adapters/llm`: happy path, null return, error throw, invalid JSON response
- [ ] `adapters/anthropic`: happy path, error throw

---

## NOT In Scope

- Moving to a separate GitHub repository (can stay in monorepo, extract to separate repo later)
- Automated npm publish CI/CD workflow (manual `pnpm publish` for v1)
- Python/Ruby/Go ports (TypeScript-only for now)
- Multi-language injection detection (current rules are English-only; worth a future ticket)
- Rate limiting / caching layer (out of scope for a pure detection library)

## What Already Exists (Leverage These)

- Clean adapter pattern in `adapters/llm.ts` — copy structure for Anthropic adapter
- `SemanticClassifierAdapter` interface is well-designed — no changes needed
- `canonicalize()` pipeline is production-quality — no changes needed
- Threat category taxonomy is complete and well-named
- Existing 4 test files provide the pattern to follow for new tests
