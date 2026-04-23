# Roadmap

This roadmap is a living plan for contribution focus areas.

## v0.2 priorities

1. Post-standardization crypto migration
- Add `secbind migrate --env <label>` to migrate v1 envelopes safely.
- Migrate crates from `pqcrypto-kyber`/`pqcrypto-dilithium` to `pqcrypto-mlkem`/`pqcrypto-mldsa`.
- Add version-aware decrypt/reveal paths for backward compatibility.

2. Policy enforcement improvements
- Enforce `allowed_cidr` antigen checks.
- Define and enforce `custom_tags` policy behavior.

3. Binding and deployment ergonomics
- Add `--binding-tag` support to `seal` and `run`.
- Add clearer diagnostics for fingerprint mismatch root causes.

4. Operational security commands
- Add `secbind check` for signature+antigen validation without decrypting.
- Add `secbind rotate --env <label>` key rotation flow.

5. Node SDK developer experience
- Add async API and stronger error handling.
- Improve local-path/`PATH` diagnostics for missing CLI binary.

## Stretch goals

- Multi-recipient sealing (developer + CI + production)
- WASM/native SDK path that does not shell out to CLI
- Supply-chain hardening guidance and reproducible builds
