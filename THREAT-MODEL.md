# Threat Model — Holder Core Security

Last updated: 2026-07-19

This document describes the trust boundaries and residual risks for the components published in this repository. It is intentionally practical: what we protect, what we assume, and what reviewers should focus on.

## Assets

| Asset | Where it lives | Criticality |
|-------|----------------|-------------|
| BIP39 seed (mnemonic) | Encrypted at rest (AES-GCM); plaintext in unlocked browser/WASM session | Critical |
| Wallet password | In-memory session only (not in this package’s vault blob) | Critical |
| Ed25519 / MPC signing material | WASM / external signer / NEAR MPC | Critical |
| API / agent subkeys | Encrypted wrappers; unwrapped for signing | High |
| On-chain spending policy | NEAR contract + server policy evaluator | High |

## Trust boundaries

```
┌─────────────────────────────────────────────────────────────┐
│ Browser tab / extension (unlocked)                          │
│  sessionSeedPhrase · React UI · WASM WalletManager          │
│  Threat: XSS, malicious extension, DevTools, shoulder-surf  │
└───────────────────────────┬─────────────────────────────────┘
                            │ encrypt / decrypt (password)
┌───────────────────────────▼─────────────────────────────────┐
│ Local storage (ciphertext only)                             │
│  AES-256-GCM + PBKDF2-HMAC-SHA256 (900k new vaults)         │
│  Threat: stolen disk → offline password brute-force         │
└───────────────────────────┬─────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────┐
│ Holder API + rust-signer-external (optional)                │
│  Subkeys, policy, job queue — not the user’s BIP39 seed     │
│  Threat: server compromise of agent keys / policy bypass    │
└───────────────────────────┬─────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────┐
│ NEAR contract + Chain Signatures MPC                        │
│  Subkey registration, spend limits, MPC orchestration       │
└─────────────────────────────────────────────────────────────┘
```

**Self-custody seed path:** the BIP39 mnemonic is generated and encrypted **in the client** (WASM). It is not uploaded to Holder servers as part of normal wallet create/unlock.

**Agent / API path:** spending uses subkeys and on-chain policy. That is a different threat surface from seed custody (see `frontend-lib/` + `near/` + `policy/`).

## Assumptions

1. The user’s device and browser profile are not already compromised.
2. Password strength is the primary defense for stolen ciphertext.
3. JavaScript cannot reliably zero `String` memory (same ceiling MetaMask documents).
4. Reviewers compare this repo’s digest against a live app that embeds the same digest (see README → Verification).

## Focus areas for reviewers

### Seed custody (`rust-wasm/`, `frontend-lib/custody/`)

- Vault encrypt/decrypt (`CryptoManager`, `encryptedSessionManager`)
- `get_mnemonic_for_backup_display` / `clear_secured_mnemonic` / `clear_wallet`
- Lock/logout clears: `sessionSeedPhrase`, `seedPhraseBackup`, WASM RAM
- Create backup UI: show → confirm quiz → strip React mnemonic
- Import: password gate, numbered words, BIP39 validate, no full-phrase paste
- No mnemonic serialized onto address records in localStorage

### Signing that may touch session seed

- Client signing lives in the private app; audit anchors here are `rust-wasm/` (derive/sign) + custody session clear/lock
- Prefer short-lived use of session mnemonic; Phase-2 goal is decrypt-in-WASM without a long-lived JS string
- Optional future: thin OSS `signUnsignedTx` helpers under `custody/` if reviewers want a TS reference without product glue

### External signer daemon (`rust-signer-external/`)

- Included in this package (open source)
- Passphrase-encrypted key store, gRPC job polling, unwrap + sign
- High-trust install surface — prefer Sigstore-verified release binaries (see README)

### Policy / subkeys (`near/`, `policy/`, `frontend-lib/` agent+MPC)

- Spend limits, core transfer templates (`frontend-lib/templates/`), auto-approval decision
- Distinct from BIP39 custody; compromise here does not automatically yield the seed
- DEX/x402/product template registry is private app surface

## Residual risks (accepted / tracked)

| Risk | Status |
|------|--------|
| Unlocked XSS / malicious extension steals session seed | Accepted browser risk; minimize lifetime |
| JS string GC leaves copies after lock | Best-effort null + WASM clear; cannot guarantee wipe |
| Weak password → offline decrypt of vault | User education; strong PBKDF2 (900k) |
| UI anti-copy is not a custody control | Documented; use confirm quiz + education |
| `/api/verify/oss` digest embed must ship with each deploy | Operational — see README Verification |

## Out of scope

- Hardware enclave / TEE guarantees
- Formal audit status (this code has **not** been formally audited — see README)
- Full product UI and non-security backend routes
