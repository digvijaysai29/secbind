# SecBind

**Post-quantum context-bound secrets.** A stolen `.secenv` file is cryptographically
inert on any other machine or process.

Think of it like a passkey: the secret is bound to *this machine*, *this binary*, and
*this environment label*. Quantum computers cannot break it. Copy-paste to another host
returns nothing.

## What it is

SecBind replaces `.env` files with `.secenv` files where every secret is sealed against
a runtime fingerprint (machine ID + binary hash + environment label). Unsealing requires
the correct machine, the correct binary, and the correct environment — simultaneously.
A breached server image, leaked `.secenv` file, or stolen disk image in isolation is useless.

The entire crypto stack is post-quantum:

| Algorithm | FIPS Reference | Quantum Status |
|-----------|---------------|----------------|
| ML-KEM-768 | FIPS 203 | Quantum-resistant (lattice) |
| ML-DSA-65 | FIPS 204 | Quantum-resistant (lattice) |
| ChaCha20-Poly1305 | — | Symmetric (quantum-safe at 256-bit) |
| HKDF-SHA3-512 | FIPS 202 | Quantum-safe |

No RSA. No ECC. No ed25519. No secp256k1.

## Installation

```bash
cargo install --path crates/secbind-cli
```

Node.js SDK:
```bash
cd sdk/node && npm install && npm run build
```

## Community

- [Contributing Guide](CONTRIBUTING.md)
- [Security Policy](SECURITY.md)
- [Roadmap](ROADMAP.md)
- [Seed Issues (first 10)](.github/ISSUES_SEED.md)
- [MIT License](LICENSE)

## Quickstart

```bash
# 1. Generate a keypair and create .secenv (SK stored in OS keychain)
secbind init --env prod --ttl-hours 720

# 2. Seal a secret
secbind seal -k DATABASE_URL -v "postgres://user:pass@db/prod" --env prod

# 3. Run your app with secrets injected as environment variables
secbind run --env prod -- node server.js
```

## v1 to v2 Migration

If you already have a legacy `version: "1"` `.secenv`, migrate it in place:

```bash
secbind migrate --env prod --file .secenv
```

The migration decrypts secrets in memory, re-seals with v2 crypto, re-signs the envelope,
and rotates key material in your OS keychain.

## dotenv Migration

Before (`.env`):
```bash
DATABASE_URL=postgres://user:pass@db/prod
```

After:
```bash
# .env is deleted; secrets live in .secenv (safe to git-commit)
secbind seal -k DATABASE_URL -v "postgres://user:pass@db/prod" --env prod
```

One-line diff in your app:
```diff
-require('dotenv').config()
+require('@secbind/node').config({ env: 'prod' })
```

## dotenvx Migration

dotenvx uses secp256k1 (classical elliptic curve). SecBind replaces this with ML-KEM-768
(post-quantum lattice). Your `.env.vault` or `.env.keys` files cannot be imported directly;
re-seal secrets using `secbind seal`.

```diff
-require('@dotenvx/dotenvx').config()
+require('@secbind/node').config({ env: 'prod' })
```

## How it Works

```
secbind seal -k FOO -v "hello"
  │
  ├─ Capture RuntimeContext
  │     machine_id:   IORegistry UUID (macOS) / /etc/machine-id (Linux)
  │     binary_hash:  SHA3-512(current_exe bytes)
  │     env_label:    "prod"
  │
  ├─ fingerprint = SHA3-512("secbind-v1-fingerprint\0" || machine_id || "\0" || binary_hash || "\0" || env_label)
  │
  ├─ ML-KEM-768 encapsulate(public_key) → (shared_secret, kem_ciphertext)
  │
  ├─ symmetric_key = HKDF-SHA3-512(salt=fingerprint, ikm=shared_secret, info="secbind-v1-seal")
  │
  ├─ ciphertext = ChaCha20-Poly1305(key=symmetric_key, nonce=random_12_bytes, plaintext="hello")
  │
  └─ ML-DSA-65 sign(canonical_json_of_secenv_file) → envelope_signature
```

Unsealing reverses the process. If the fingerprint differs by a single bit (different machine,
different binary, wrong env label), the AEAD auth tag fails and SecBind returns
`FingerprintMismatch`.

### Antigen Conditions

Antigens are envelope-level access controls checked *before* any decryption attempt:

| Antigen | Description |
|---------|-------------|
| `not_after` | Reject if current time is past this timestamp |
| `environment` | Reject if runtime env_label does not match |
| `allowed_cidr` | (v0.2) Reject if machine IP is outside CIDR range |
| `custom_tags` | (v0.2) Arbitrary key/value policy tags |

```bash
secbind init --env prod --ttl-hours 720   # auto-sets not_after + environment antigen
```

## Security Model

SecBind provides **context binding**: secrets cannot be decrypted outside the context
they were sealed against.

**What SecBind protects against:**
- Stolen `.secenv` file (ciphertext only, no key material)
- Leaked disk image (fingerprint mismatch on different hardware)
- Compromised CI secrets (wrong binary hash or environment label)
- Classical and quantum cryptanalysis of the ciphertext

**What SecBind does NOT protect against:**
- A live process with a running `secbind run` child — memory is decrypted in-process
- An attacker with root on the sealing machine at the time of unsealing
- Keychain compromise (the SK is stored in the OS keychain)
- Supply chain attacks on the `secbind` binary itself
- An attacker who can impersonate the machine ID (e.g., VMware UUID spoofing)

SecBind is not a HSM. It is not a key management service. It is a tamper-evident
envelope that binds secrets to a specific runtime context, replacing the plaintext
`.env` anti-pattern.

## Antigen Conditions Reference

Set during `init`, stored in `.secenv`, checked every `run`/`reveal`/`export`:

```json
{
  "antigens": {
    "not_after": "2026-12-31T00:00:00Z",
    "environment": "prod",
    "allowed_cidr": null,
    "custom_tags": {}
  }
}
```

Antigen violations return an error *before* any decryption is attempted and *before*
the private key is loaded from the keychain.

## Audit

Inspect a `.secenv` file without loading any key material:

```bash
secbind audit --file .secenv
# Version:       2
# Environment:   prod
# Secrets:       3
# Expires:       2026-12-31T00:00:00Z
# Antigen/env:   prod
# Signature:     VALID
```
