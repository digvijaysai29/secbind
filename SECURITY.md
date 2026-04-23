# Security Policy

SecBind is a security-focused project. We appreciate responsible disclosure.

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |
| < 0.1   | No        |

## Reporting a vulnerability

For potential vulnerabilities, please use one of these private channels:

1. GitHub private vulnerability reporting (preferred): `Security` tab -> `Report a vulnerability`
2. If private reporting is unavailable, open a minimal public issue without exploit details and request a maintainer contact.

Please include:
- Affected version/commit
- Impact summary
- Reproduction steps or proof of concept
- Suggested remediation (if known)

## Response targets

- Initial acknowledgement: within 3 business days
- Triage decision: within 7 business days
- Fix timeline: depends on severity and complexity

## Disclosure process

We follow coordinated disclosure:

1. Report received and validated privately.
2. Fix prepared and reviewed.
3. Patch released.
4. Advisory published with affected and fixed versions.

## Scope notes

High-priority areas include:
- Context/fingerprint binding bypasses
- Signature verification bypasses
- Antigen validation bypasses
- Key material handling and accidental disclosure
- Unsafe deserialization leading to code execution or secret exposure
