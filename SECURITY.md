# Security Policy

## Reporting a vulnerability

Please report security vulnerabilities privately to the project maintainer. Do not open a public GitHub issue for an undisclosed vulnerability.

When reporting, include:

- affected version or commit
- reproduction steps or proof of concept
- impact assessment
- any suggested mitigation if available

## Response goals

- acknowledge receipt within a reasonable time
- validate the report
- prepare and ship a fix when confirmed
- disclose publicly after a fix or mitigation is available

## Scope

This project focuses on prompt-injection detection and sanitization. Reports are especially useful for:

- bypasses in canonicalization or classification
- ReDoS or algorithmic complexity issues
- incorrect trust-boundary handling
- unsafe adapter behavior that could mislead callers about classification results
