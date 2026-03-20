# Contributing to llm-moat

Thanks for contributing.

## Before you start

- Open an issue or discussion for significant API, rule-set, or adapter changes before writing a large patch.
- Keep changes focused. Separate refactors from behavior changes.
- Add or update tests for any behavioral change.
- Update `README.md` or docs when the public API, options, or examples change.

## Development setup

```bash
pnpm install
pnpm run check
bun test
pnpm run build
```

## Pull request guidelines

- Use clear titles and describe the user-facing impact.
- Include tests or explain why tests are not needed.
- Mention any rule additions, removals, or category changes explicitly.
- Keep generated output out of commits unless it is intentionally part of the change.

## Coding expectations

- Preserve TypeScript type safety.
- Avoid adding runtime dependencies unless there is a strong justification.
- Prefer small, composable functions over broad rewrites.
- Keep regex and rule changes ReDoS-safe and explain non-obvious detection logic.

## Rule contributions

Use the issue templates to submit evasion reports or rule proposals:

- [New evasion technique](.github/ISSUE_TEMPLATE/evasion-technique.md) — attack string that bypasses current rules
- [Rule suggestion](.github/ISSUE_TEMPLATE/rule-suggestion.md) — new detection pattern or improvement

Structured submissions make it much easier to evaluate and act on contributions.

## Reporting bugs

Include:

- input sample
- expected behavior
- actual behavior
- version used
- runtime details

## Security issues

Do not open public issues for undisclosed security problems. Follow [SECURITY.md](SECURITY.md).
