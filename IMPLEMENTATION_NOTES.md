# SecBind v0.1 Implementation Notes

## Crate Substitutions

### keyring v3 (spec listed v2)
The spec lists `keyring = "2"` but v2 only exists as an alpha pre-release. v3.6.3 is the latest
stable release and has an identical API surface for the operations used (Entry::new, get_password,
set_password). No behavior change.

### pqcrypto-kyber module: `kyber768` not `mlkem768`
pqcrypto-kyber 0.8.x exposes its ML-KEM-768 implementation under the module name `kyber768`
(the pre-standardization name). The FIPS 203 standardized name "ML-KEM" was adopted after this
crate was published. The algorithm is identical.

### pqcrypto-kyber and pqcrypto-dilithium are retired upstream
Both crates carry a RustSec advisory (RUSTSEC-2024-0380) noting they are replaced by:
- `pqcrypto-mlkem` (for FIPS 203 / ML-KEM-768)
- `pqcrypto-mldsa` (for FIPS 204 / ML-DSA-65)

They remain functional and the crypto is correct. Migration is recommended for v0.2 (see below).

### ⚠ FIPS 203 forward-compatibility break (critical for v0.2 migration)
Kyber Round 3 (pqcrypto-kyber 0.8.x) and ML-KEM-768 (FIPS 203) are mathematically equivalent
but have **incompatible wire formats**: ciphertext bytes produced by one cannot be decapsulated
by the other due to minor encoding differences introduced during FIPS standardization.

**Consequence**: v1 `.secenv` files sealed with `pqcrypto-kyber` cannot be unsealed after
migrating to `pqcrypto-mlkem`. Attempting to do so will return `FingerprintMismatch` (AEAD auth
tag failure), not a helpful error.

**Required action before v0.2 crate migration**:
1. Implement `secbind migrate --env <label>` that:
   - Loads the current `.secenv` with the old KEM SK (from keychain)
   - Decrypts all secrets into memory using the old KEM
   - Generates a new keypair with `pqcrypto-mlkem`
   - Re-seals all secrets with the new KEM
   - Re-signs the envelope with `pqcrypto-mldsa`
   - Atomically writes the new `.secenv` and rotates the keychain entry
2. Bump the `version` field in `.secenv` from `"1"` to `"2"` after migration
3. Add version detection to `reveal`/`run` that selects the correct KEM at runtime

Until the `migrate` command exists, do not change the pqcrypto crates in
`crates/secbind-core/Cargo.toml`.

### keyring Linux feature name
The audit referenced a combined feature `linux-secret-service-rt-async-io-crypto-rust` that does
not exist in keyring v3.6.3. Actual feature names verified from `cargo metadata`:
- macOS: `apple-native`
- Linux: `sync-secret-service` + `crypto-rust` (what v1 uses)
- Windows: `windows-native`
The `sync-secret-service` backend uses D-Bus (GNOME Keyring / KWallet). The `linux-native` feature
uses Linux kernel keyutils instead — a lighter option for headless servers without a desktop
session.

## v0.1 Limitations

### CIDR antigen not enforced
The `allowed_cidr` field exists in `Antigens` and is serialized in the `.secenv` file, but
`check_antigens()` does not validate it. Full CIDR matching requires the `ipnet` crate which was
not in the specified dependencies. The field is preserved for forward compatibility; v0.2 should
add IP address detection and CIDR comparison.

### No CIDR auto-detection
Related to above: detecting the machine's outbound IP or subnet requires either a system call or
an HTTP lookup to an external service. Neither is appropriate in a secrets unsealing hot path.

### Binary hash changes on every rebuild
The `binary_hash` component of the fingerprint is the SHA3-512 of the current executable. This
means sealing on a debug build and revealing on a release build (or vice versa) will fail with
`FingerprintMismatch`. In production, always seal with the same binary that will be used to
reveal/run. The `--binding-tag` field (currently unused in CLI) was designed to allow operators
to override this behavior.

### zeroize test uses manual zeroize call
The spec requests a test that verifies memory is zeroed via a raw pointer after drop. The
implemented test calls `zeroize()` manually before drop and reads the pointer while the allocation
is still live. This avoids the use-after-free UB of reading memory after `drop()` while still
validating the `Zeroize` implementation. Miri-safe.

### keyring service name contains `/`
The keyring service name is formatted as `secbind/{env}`. Forward slashes are valid on macOS
Keychain (the only platform tested). On Linux with `secret-service`, this may cause issues
depending on the D-Bus service implementation. v0.2 should sanitize the env label or use a
different separator.

### Node SDK requires `secbind` on PATH
The Node.js SDK shells out to the `secbind` binary via `execFileSync`. The binary must be
installed and on `$PATH` (or passed via `secbindBin` option). There is no bundled WASM or
native addon fallback.

## v0.2 Suggestions

1. **Migrate to `pqcrypto-mlkem` and `pqcrypto-mldsa`** for FIPS 203/204 compliance and to clear
   the RustSec advisories.

2. **Implement CIDR antigen** using the `ipnet` crate for subnet matching against the machine's
   local IP addresses.

3. **Add `--binding-tag` CLI flag** to `seal` and `run` so operators can tag sealed secrets to
   a specific deployment or pipeline stage, decoupled from the binary hash.

4. **Key rotation command** (`secbind rotate --env`) to re-seal all secrets under a new keypair
   without decrypting to disk — load old SK, decrypt all values in memory, generate new keypair,
   re-seal, re-sign.

5. **Multi-recipient sealing** — seal the same value against multiple KEM public keys (e.g.,
   developer machine + CI runner) so a `.secenv` can be shared across environments.

6. **`secbind check` command** — run antigen validation and signature verification without
   decrypting any secrets, suitable for pre-flight in CI pipelines.

7. **Node SDK without subprocess** — compile a WASM build of secbind-core and ship it as a
   native addon to avoid the `$PATH` dependency.
