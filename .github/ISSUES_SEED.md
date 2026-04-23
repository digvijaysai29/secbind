# Seed Issues (First 10)

Use these as initial GitHub issues. Each item is scoped with acceptance criteria to help contributors start quickly.

## 1) Add `secbind migrate --env <label>` for crypto crate migration

- Labels: `enhancement`, `security`, `roadmap`, `rust`, `breaking-change`
- Context: v0.2 needs migration from `pqcrypto-kyber`/`pqcrypto-dilithium` to `pqcrypto-mlkem`/`pqcrypto-mldsa`.
- Scope:
  - Introduce `migrate` command in CLI.
  - Load v1 envelope + key material, decrypt in memory, reseal with new keypair, resign, atomically write.
- Acceptance criteria:
  - Existing v1 envelopes can be migrated without plaintext written to disk.
  - New envelope version increments (e.g., `"2"`).
  - Migration command is idempotent-safe and reports clear outcomes.
- Suggested files:
  - `crates/secbind-cli/src/main.rs`
  - `crates/secbind-cli/src/cmd/`
  - `crates/secbind-core/src/envelope.rs`
  - `crates/secbind-core/src/crypto.rs`

## 2) Add version-aware reveal path (v1 + v2 compatibility)

- Labels: `enhancement`, `security`, `roadmap`, `rust`
- Context: reveal/run/export must choose the correct decrypt/signature implementation by envelope version.
- Scope:
  - Extend envelope format handling with explicit version dispatch.
  - Return actionable errors for unsupported versions.
- Acceptance criteria:
  - v1 files continue to work.
  - v2 files use new algorithm path.
  - Unsupported versions produce deterministic errors.
- Suggested files:
  - `crates/secbind-core/src/envelope.rs`
  - `crates/secbind-core/src/crypto.rs`
  - `crates/secbind-cli/src/cmd/reveal.rs`
  - `crates/secbind-cli/src/cmd/run.rs`
  - `crates/secbind-cli/src/cmd/export.rs`

## 3) Enforce `allowed_cidr` antigen

- Labels: `enhancement`, `security`, `roadmap`, `rust`
- Context: field exists but is currently not enforced.
- Scope:
  - Parse CIDR and compare runtime IP(s) against policy.
  - Fail closed when antigen is present and no match is found.
- Acceptance criteria:
  - Positive and negative integration tests for CIDR checks.
  - Clear error messages on mismatch/parse errors.
- Suggested files:
  - `crates/secbind-core/src/envelope.rs`
  - `crates/secbind-core/src/error.rs`
  - `crates/secbind-core/src/lib.rs` (tests)

## 4) Define and enforce `custom_tags` antigen semantics

- Labels: `enhancement`, `security`, `roadmap`, `rust`
- Context: `custom_tags` field exists but has no enforcement contract.
- Scope:
  - Define policy inputs and runtime source of tag values.
  - Enforce matching logic in antigen checks.
- Acceptance criteria:
  - Policy behavior documented.
  - Tag mismatches block decrypt before key operations.
  - Tests cover missing tag, mismatch, and success cases.
- Suggested files:
  - `crates/secbind-core/src/envelope.rs`
  - `README.md`
  - `IMPLEMENTATION_NOTES.md`

## 5) Add `--binding-tag` to `seal`/`reveal`/`run`/`export`

- Labels: `enhancement`, `security`, `roadmap`, `rust`
- Context: runtime context already has `binding_tag`, but CLI does not expose it.
- Scope:
  - Add CLI flags and propagate values into `RuntimeContext`.
  - Include tag in fingerprint computation where supplied.
- Acceptance criteria:
  - Secrets sealed with a binding tag only decrypt with same tag.
  - CLI help text and README document usage.
- Suggested files:
  - `crates/secbind-cli/src/cmd/*.rs`
  - `crates/secbind-core/src/fingerprint.rs`
  - `README.md`

## 6) Add `secbind check` command (no decrypt)

- Labels: `enhancement`, `security`, `roadmap`, `rust`, `good first issue`
- Context: need preflight check for CI without secret exposure.
- Scope:
  - Validate envelope signature and antigens only.
  - Return non-zero on invalid/expired/antigen mismatch.
- Acceptance criteria:
  - Command does not fetch private key from keyring.
  - Output is CI-friendly and machine-readable option is considered.
- Suggested files:
  - `crates/secbind-cli/src/main.rs`
  - `crates/secbind-cli/src/cmd/`
  - `README.md`

## 7) Normalize keyring service name for cross-platform safety

- Labels: `bug`, `security`, `rust`, `good first issue`
- Context: service name currently includes `/`, which may be problematic on some Linux secret-service backends.
- Scope:
  - Introduce deterministic sanitizer for env label in service name.
  - Maintain compatibility or provide migration path for existing keys.
- Acceptance criteria:
  - Service identifier format is stable and platform-safe.
  - Existing users do not silently lose access to keys.
- Suggested files:
  - `crates/secbind-cli/src/config.rs`
  - `crates/secbind-cli/src/cmd/*.rs`

## 8) Harden runtime context capture on Linux/container environments

- Labels: `bug`, `security`, `rust`, `help wanted`
- Context: machine UID capture can fail in minimal container hosts.
- Scope:
  - Improve context capture fallback behavior with explicit policy.
  - Keep binding guarantees strong while improving diagnosability.
- Acceptance criteria:
  - Failures produce clear, actionable errors.
  - Integration tests cover container-like environment constraints.
- Suggested files:
  - `crates/secbind-core/src/fingerprint.rs`
  - `crates/secbind-core/src/error.rs`
  - `README.md`

## 9) Node SDK: async API + richer error messages

- Labels: `enhancement`, `node-sdk`, `help wanted`
- Context: SDK is synchronous and errors from subprocess can be opaque.
- Scope:
  - Add async counterpart(s) to current API.
  - Wrap subprocess failures with actionable messages (`secbind` missing, bad env, signature fail).
- Acceptance criteria:
  - Existing sync API remains backward compatible.
  - Async API documented with examples.
  - Error messages include next-step hints.
- Suggested files:
  - `sdk/node/src/loader.ts`
  - `sdk/node/src/dotenvx.ts`
  - `sdk/node/src/index.ts`
  - `sdk/node/README.md` (new or updated)

## 10) Add automated adversarial test workflow in CI

- Labels: `tests`, `security`, `roadmap`, `help wanted`
- Context: repository has strong manual battle tests; codify them in CI for regressions.
- Scope:
  - Add integration test workflow for tamper, wrong env, expiry, fingerprint mismatch.
  - Ensure tests avoid leaking secrets in logs.
- Acceptance criteria:
  - CI fails on any security control regression.
  - Test harness is documented for local execution.
- Suggested files:
  - `.github/workflows/`
  - `crates/secbind-core/src/lib.rs` (tests)
  - `README.md`
