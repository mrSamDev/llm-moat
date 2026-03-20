# TODOS

Items deferred from plan reviews. Each item has context enough to pick up cold.

---

## P1

### Fuzz harness for canonicalize() + classify()
**What:** Add a property-based / fuzz test harness that generates adversarial inputs (random Unicode, RTL overrides, binary data, very long strings) and verifies canonicalize + classify don't crash or produce wildly inconsistent results.
**Why:** Security libraries need continuous regression testing against new evasion vectors. A ReDoS regression or a new Unicode trick could be introduced silently. Timing-based ReDoS probe already exists — extend it.
**Pros:** Catches regressions before release. Credibility signal for security-conscious adopters.
**Cons:** Property-based testing requires a test framework setup (fast-check or similar). Adds CI time.
**Context:** Existing test: `tests/unit/canonicalize.test.ts`. ReDoS timing probe already in `tests/unit/classify.test.ts`. Use fast-check with bun or a custom random input generator.
**Effort:** M (human) → S (CC+gstack)
**Priority:** P1
**Depends on:** None

---

## P2

### Null/undefined input guard in classify()
**What:** Add a runtime check at the top of `classify()` that throws a descriptive error if `input` is null or undefined.
**Why:** TypeScript callers are protected by types, but JS callers (or callers from Python FFI, edge runtime, etc.) will get a cryptic TypeError. A guard like `if (input == null) throw new Error("classify: input must be a string, got " + typeof input)` fixes this.
**Pros:** Better DX for non-TypeScript consumers. Consistent with `InputTooLongError` approach.
**Cons:** Adds 1 line. No real downside.
**Context:** `src/classify.ts` — add at the top of the exported `classify()` function. Same guard should go in `sanitizeUntrustedText()`.
**Effort:** S (human) → S (CC+gstack)
**Priority:** P2
**Depends on:** None

### Document O(n²) streaming behavior in README
**What:** Add a note in the streaming section of README.md explaining that each `feed()` call re-classifies the full accumulated buffer, making total work O(chunks × avg_buffer_size). Provide guidance: use larger chunks (≥4KB), or use `classify()` directly if you have the full document.
**Why:** Users building high-throughput document scanning pipelines will be surprised by the performance characteristic. The note exists in the code comment but not in the README.
**Pros:** Sets correct expectations. Prevents GitHub issues about "why is streaming slow?".
**Cons:** Minor README edit.
**Context:** The performance note is already in `src/stream.ts` line 32-34 JSDoc. Mirror it to README streaming section.
**Effort:** S (human) → S (CC+gstack)
**Priority:** P2
**Depends on:** None

### GitHub issue templates
**What:** Add `.github/ISSUE_TEMPLATE/` with two templates: "New evasion technique" (required fields: attack string, canonicalized form, expected category, why current rules miss it) and "Rule suggestion" (custom rule use case + pattern).
**Why:** Community rule contributions need a structured submission process. Without templates, evasion reports will be vague and hard to act on.
**Pros:** Drives quality community contributions. Aligns with the community rule pack strategy.
**Cons:** Minor setup effort.
**Context:** Create `.github/ISSUE_TEMPLATE/evasion-technique.md` and `.github/ISSUE_TEMPLATE/rule-suggestion.md`. Reference in CONTRIBUTING.md.
**Effort:** S (human) → S (CC+gstack)
**Priority:** P2
**Depends on:** Community rule packs strategy (Expansion 1)
