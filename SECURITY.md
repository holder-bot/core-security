# Security Policy

## Reporting a vulnerability

Please report security issues **responsibly** to **info@holder.bot**.

Include:

- Affected component (`near/`, `rust-wasm/`, `rust-signer-external/`, `frontend-lib/custody/`, etc.)
- Description and impact
- Steps to reproduce or a proof-of-concept
- Whether the issue is already public

We aim to acknowledge reports within **72 hours** and will coordinate disclosure after a fix is available (or after a mutually agreed window).

**Do not** open a public GitHub issue for unfixed vulnerabilities that could lead to fund loss or seed compromise.

## Scope

This repository publishes security-critical Holder wallet components for review:

- NEAR subkey / policy contract (`near/`)
- Client WASM crypto & vault encryption (`rust-wasm/`)
- External signer daemon & signing library (`rust-signer-external/`, `rust-signer/`)
- API key / subkey / MPC derivation helpers (`frontend-lib/`)
- Seed custody / session / backup UI (`frontend-lib/custody/`)
- Policy decision engine (`policy/`)

Out of scope for this package (private product code): full Next.js app shell, marketing site, non-security UI, infrastructure secrets.

## Supported versions

Security fixes are applied to the sources synced from the wallet release line (`cb1.2`) and re-published here via `sync-oss.sh`. Tagged releases on this repo are the review checkpoints.

## Safe harbor

Good-faith research that follows this policy and avoids privacy violations, service disruption, or data destruction is welcome. Do not access other users’ funds or accounts.
