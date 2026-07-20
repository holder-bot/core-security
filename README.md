# Holder: Core Security

Open source security-critical components of [Holder](https://holder.bot) self-custody wallet.

This repository contains the cryptographic, signing, custody, and policy enforcement code that protects user funds. It is published so that anyone can audit the logic that handles keys, encrypts seeds, signs transactions, and enforces spending limits.

**NEAR contract source of truth:** developed in the private repo [holder-bot/contract-near](https://github.com/holder-bot/contract-near); the `near/` directory here is copied on publish via `cb1.2/scripts/sync-oss.sh`. See [PUBLISH.md](PUBLISH.md).

## Components

| Directory | Language | Purpose |
|-----------|----------|---------|
| `near/` | Rust | NEAR smart contract: subkey registration, policy enforcement, MPC signing orchestration |
| `rust-wasm/` | Rust → WASM | Client-side cryptography: BIP39, key derivation, AES-256-GCM vault encryption (PBKDF2 900k), memory clear APIs |
| `rust-signer-external/` | Rust | **External signer daemon** (open source): HSM/local key store, gRPC job polling, E2EE key delivery |
| `rust-signer/` | Rust | Signing library: key unwrapping (RSA-OAEP + AES-GCM), ed25519 signing |
| `frontend-lib/` | TypeScript | API key creation, subkey derivation, MPC address resolution, policy sync |
| `frontend-lib/custody/` | TypeScript | Seed vault session primitives (`sessionSeed`, vault format, confirm quiz), UI under `custody/ui/` |
| `frontend-lib/templates/` | TypeScript | Core transfer template builders + types (native/token/ERC20/BTC) — not DEX/x402 product catalog |
| `policy/` | Rust | Spending limit decision core (`decision.rs`) |
| `tests/` | TypeScript | Independently runnable PBT suite for custody security assertions (`npm test`) |

Product orchestration (Send UI submit paths, swap/x402 templates, Intents, approval routes) stays in the private app — not published here.

See also: [SECURITY.md](SECURITY.md) · [THREAT-MODEL.md](THREAT-MODEL.md)

## Security Status

**This code has not been formally audited.** Use at your own risk.

We welcome security review from the community. If you find a vulnerability, please report it responsibly — see [SECURITY.md](SECURITY.md).

## Verification — does the running app match this source?

There are **two complementary** mechanisms. They answer different questions.

### 1. Content digest (source set ↔ deployed app claim)

When maintainers run `sync-oss.sh`, every file in this repo is hashed into `.oss-manifest.txt`, and a single digest is written to `.oss-digest.txt`.

Anyone can:

```bash
git clone https://github.com/holder-bot/core-security.git
cd core-security
./verify.sh https://app.holder.bot   # or https://holder.bot when wired
```

`verify.sh` regenerates the local digest and compares it to what the live app reports at:

```http
GET /api/verify/oss  →  { "oss_digest": "<sha256>", "commit": "...", ... }
```

**What this proves:** the deployed app **claims** to have been built from the same open-source file set as this checkout (digest match).

**What this does not prove alone:** that no other private code is malicious, or that a downloaded binary was built by GitHub Actions.

### 2. Sigstore / cosign (signed release artifacts)

Tagged releases of **this repository** are signed with Sigstore keyless signing (GitHub Actions OIDC → Fulcio → Rekor). Use this when you download a **release tarball** or (when published) a **signer binary / container image**.

```bash
./scripts/verify-release.sh v1.0.0
```

**What this proves:** the artifact was built and signed by this repo’s release workflow — not that a random browser tab’s JS bundle matches.

| Question | Use |
|----------|-----|
| “Does the live wallet advertise the same OSS file digest I cloned?” | `./verify.sh` + `/api/verify/oss` |
| “Was this release tarball / signer binary built by Holder’s CI?” | Sigstore / `verify-release.sh` |

Committed `.oss-manifest.txt` and `.oss-digest.txt` are updated by `sync-oss.sh`. CI on `main` verifies they match `./scripts/generate-oss-manifest.sh`.

## Running the security PBT suite

```bash
cd tests
npm install
npm test
```

These property tests assert lock clears session mnemonic (live+backup), SRP confirm quiz, multi-word paste blocking, vault JSON shape / PBKDF2 iteration bounds, no mnemonic on address records, and `wipeBytes` zeroing. They import only `frontend-lib/custody` (no app shell).

## External signer daemon

**Yes — `rust-signer-external/` is open source** and synced into this package. It is the local/daemon signing path (passphrase-encrypted key store, gRPC job polling, unwrap + sign). Treat release binaries as a high-trust install surface; prefer Sigstore verification before first run when binaries are published.

## Segregation

Upstream inventory is `cb1.2/.oss-paths.txt`. Divergent edits fail `./scripts/check-oss-divergence.sh` in the wallet repo. Prefer adding logic under `frontend/lib/custody/` rather than enlarging app hooks.

## Release process

1. Update sources: `holder-bot/contract-near` (contract) and `cb1.2` (wallet security files).
2. From `cb1.2`, run `./scripts/sync-oss.sh` (pushes to this repo’s `main` with refreshed manifest/digest).
3. Confirm CI passes on `main` (digest check).
4. Create and push a tag like `v1.0.2`.
5. GitHub Actions workflow `.github/workflows/release-sign.yml` builds the tarball and signs with cosign keyless.

Sigstore workflows and `scripts/verify-release.sh` live in this repository only; they are **not** overwritten by sync (see `sync-oss.sh` preserve list).

## License

MIT
