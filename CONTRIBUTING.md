# Contributing to SecBind

Thanks for helping improve SecBind. We welcome security reviews, bug fixes, docs improvements, and feature contributions.

## Development setup

### Prerequisites
- Rust stable toolchain (`rustup`, `cargo`)
- Node.js 20+ and `npm`
- macOS Keychain / Linux Secret Service / Windows Credential Manager access (for CLI integration tests)

### Build and test
```bash
# Rust workspace
cargo build
cargo test

# Node SDK
cd sdk/node
npm install
npm run build
```

## Workflow

1. Create a branch from `main`.
2. Keep changes scoped to one concern whenever possible.
3. Add or update tests for behavior changes.
4. Run the full local checks before opening a PR.
5. Open a PR with clear motivation, risk notes, and test evidence.

## Pull request checklist

- [ ] I described the problem and why this change is needed.
- [ ] I linked related issues (or explained why none exists).
- [ ] I added/updated tests where appropriate.
- [ ] I ran `cargo test` and `npm run build`.
- [ ] I documented user-facing changes in `README.md` or other docs.
- [ ] I called out security-sensitive logic changes explicitly.

## Testing guidance

For security-sensitive changes (crypto, context binding, antigen checks, signature verification), include at least one negative-path test. Examples:
- Wrong environment should fail.
- Expired envelope should fail.
- Tampered envelope should fail signature validation.
- Fingerprint mismatch should fail decrypt.

## Coding guidelines

- Keep code paths explicit and easy to audit.
- Prefer small, composable functions in security-critical logic.
- Avoid introducing extra dependencies in crypto paths without clear need.
- Keep backward compatibility in mind for `.secenv` wire format changes.

## Issue triage labels

Core labels used in this repository:
- `needs-triage`
- `bug`
- `enhancement`
- `security`
- `good first issue`
- `help wanted`
- `rust`
- `node-sdk`
- `documentation`
- `tests`

## Security reports

Do not open public issues for exploitable vulnerabilities. Please follow [SECURITY.md](SECURITY.md).
