# VaultLocal — Secure Local-First Secret Manager

---

## Overview

**VaultLocal** is a local-first, cryptographically hardened secret manager written in Rust. It is designed for environments requiring strict data locality, offline operation, and deterministic security guarantees.

VaultLocal eliminates network dependencies and external trust assumptions: all secrets remain on the local machine and are never transmitted.

---

## Motivation

VaultLocal was built to explore and demonstrate:

* Local-first security architectures
* Practical cryptographic system design in Rust
* Elimination of external trust and remote attack surfaces
* Deterministic, auditable storage of sensitive data

---

## Core Design Principles

1. **Locality** — No external services, no sync layer
2. **Defense-in-depth** — Multiple independent cryptographic layers
3. **Determinism** — Explicit, reproducible behavior with no hidden state

---

## Architecture Overview

```
CLI (clap)
   ↓
Vault API (lib.rs)
   ↓
Database Layer (SQLCipher via rusqlite)
   ↓
Crypto Layer
   ├── Argon2 (password → root key)
   ├── HKDF (key separation)
   └── AES-256-GCM-SIV (data encryption)
   ↓
Secure Memory (zeroize)
```

---

## Technology Stack

### Database — SQLCipher (`rusqlite`)

* Encrypted SQLite backend
* Full database encryption at rest
* Page-level encryption

**Implication:** Raw disk access yields indistinguishable ciphertext.

---

### Key Derivation — Argon2 + HKDF

* **Argon2**: Memory-hard password → root key derivation
* **HKDF**: Domain-separated key expansion

```
Root Key
 ├── DB Key
 ├── Entry Key
 └── Validation Key
```

---

### Encryption — AES-256-GCM-SIV

* Authenticated encryption (AEAD)
* Misuse-resistant against nonce reuse

---

### Memory Safety — `zeroize`

* Explicit wiping of:

  * passwords
  * derived keys
  * decrypted plaintext

---

### CLI — `clap` + `rpassword`

* Structured command parsing
* Hidden password input

---

## Security Model

### Defense-in-Depth

1. SQLCipher (database-level encryption)
2. AES-GCM-SIV (per-entry encryption)

---

### Canary Validation

* Verifies password correctness before operations
* Prevents silent corruption from incorrect keys

---

## Security Guarantees

* No plaintext secrets stored on disk
* No network transmission
* Key separation enforced via HKDF
* Authenticated encryption for all entries

---

## Why VaultLocal

| Feature            | VaultLocal | Cloud Managers |
| ------------------ | ---------- | -------------- |
| Network dependency | None       | Required       |
| Data location      | Local      | Cloud          |
| Attack surface     | Minimal    | Large          |
| Transparency       | High       | Opaque         |
| Reproducibility    | High       | Vendor-bound   |

---

## Installation

```bash
git clone https://github.com/Dev-Nanashi/Vaultlocal.git
cd VaultLocal
cargo build --release
```

Binary:

```
target/release/vaultlocal
```

---

### Global Install

```bash
cargo install --path .
```

---

## Example Workflow

```bash
$ vaultlocal init ./my-vault
Enter password: ********

$ vaultlocal insert ./my-vault github/alice
Enter password: ********
Enter secret: ********

$ vaultlocal get ./my-vault github/alice
alice_password_123
```

---

## Usage

```bash
vaultlocal init ./my-vault
vaultlocal open ./my-vault
vaultlocal insert ./my-vault github/alice
vaultlocal get ./my-vault github/alice
vaultlocal list ./my-vault
vaultlocal delete ./my-vault github/alice
```

---

## Testing

Run full test suite:

```bash
cargo test
```

### Coverage

* Crypto correctness (encryption, KDF)
* Vault lifecycle and integrity
* Failure scenarios and edge cases

---

## Data Model

```
<label>/<identifier>
```

Examples:

```
github/alice
aws/root
email/personal
```

---

## Threat Model

### Protects Against

* Disk theft
* Offline brute-force attacks
* Database inspection
* Key reuse vulnerabilities

### Does NOT Protect Against

* Active malware
* Kernel compromise
* Keylogging

---

## Build Requirements

* Rust toolchain
* Perl (required for vendored OpenSSL)

---

## Project Structure

```
src/
 ├── crypto/
 ├── db/
 ├── secure_mem/
 ├── util/
 ├── error/
 ├── lib.rs
 └── main.rs

tests/
 ├── crypto_tests.rs
 ├── integration.rs
 └── vault_tests.rs
```

---

## Project Status

* Version: v0.1.0
* Status: Active development
* Platform: Windows / Linux

---

## Security Notice

VaultLocal uses strong, modern cryptographic primitives. However, it has not undergone independent security audit.

Do not rely on it for high-risk production secrets without review.

---

## Future Work

* Hardware-backed keys (TPM / YubiKey)
* Secure export and backup
* Optional encrypted sync layer
* CLI UX improvements

---

## Summary

VaultLocal is a deterministic, local-first cryptographic secret storage system.

It prioritizes:

* Control over convenience
* Transparency over abstraction
* Security
