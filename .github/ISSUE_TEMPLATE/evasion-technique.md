---
name: New evasion technique
about: Report an attack string that bypasses current detection rules
labels: evasion, rules
---

## Attack string

Paste the exact input that evades detection:

```
<attack string here>
```

## Canonicalized form

What does this look like after normalization (lowercased, whitespace collapsed, unicode normalized)?

```
<canonicalized form here>
```

## Expected category

Which category should this be flagged under? (e.g. `prompt_injection`, `jailbreak`, `pii_extraction`)

## Why current rules miss it

Explain what transformation, encoding, or phrasing causes the current rules to fail. Be specific — "it uses unicode lookalikes for the word 'ignore'" is more useful than "the rules don't catch it".

## Suggested fix (optional)

If you have a regex or rule pattern in mind, include it here.
