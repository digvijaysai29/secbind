# secbind — Claude Code Context

## Project Overview
Post-quantum, context-bound secrets manager. A stolen `.env` file is useless without the machine that sealed it. Inspired by passkeys — binding secrets to identity/context rather than just encrypting them.

## Crate Structure
- `crates/secbind-core/` — crypto primitives (Kyber768 KEM, Dilithium3 DSA, ChaCha20-Poly1305 AEAD, HKDF-SHA3-512)
- `crates/secbind-cli/` — user-facing CLI commands (init, seal, reveal, run, export, audit)

## Build & Test Commands
```bash
cargo build                        # build all crates
cargo test                         # run all tests
cargo clippy -- -D warnings        # lint (warnings = errors)
cargo fmt --check                  # format check
cargo audit                        # dependency vulnerability scan
```

## Architecture Notes
- `SecEnvFile` is the on-disk format (`.secenv`) — JSON, signed with Dilithium3
- `RuntimeContext` captures machine fingerprint (machine_id + binary_hash + env_label)
- Secrets are sealed with Kyber768 KEM + HKDF + ChaCha20-Poly1305 per-secret
- The fingerprint is mixed into the HKDF salt — wrong machine = decryption fails
- `Antigens` = metadata constraints (TTL, environment label, CIDR) checked at reveal time

## Code Conventions
- Rust edition 2021
- Error handling via `thiserror` — no `unwrap()` in library code, only in tests
- Public API functions must have doc comments with a `# Security` section
- `SecBindError` variants must be specific — avoid catch-all `KemError(String)` for new errors
- Use `BTreeMap` (not `HashMap`) anywhere output must be deterministic (signing, canonical bytes)

## Key Files
| File | Purpose |
|------|---------|
| `crates/secbind-core/src/crypto.rs` | `seal()` and `reveal()` — core encryption |
| `crates/secbind-core/src/fingerprint.rs` | `RuntimeContext` — machine binding |
| `crates/secbind-core/src/envelope.rs` | `SecEnvFile` — on-disk format + signature |
| `crates/secbind-cli/src/cmd/run.rs` | Injects secrets into child process env |
| `crates/secbind-cli/src/config.rs` | Keyring service naming |

## Known Planned Improvements
- `allowed_cidr` antigen field is defined but not yet enforced in `check_antigens()`
- `crates/secbind-core/src/context.rs` is currently a stub
- Binary hash in fingerprint uses full `fs::read()` — streaming hash planned
- `export` command outputs to stdout — shell-quoting and TTY check planned
