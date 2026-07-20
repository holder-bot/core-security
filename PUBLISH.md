# How this repository is updated

This is the **public** audit bundle. Do not edit `near/` here for contract development.

| Source | Path |
|--------|------|
| NEAR smart contract | [`../contract-near/`](../contract-near/) → https://github.com/holder-bot/contract-near (private) |
| Wallet security files | [`../../cb1.2/`](../../cb1.2/) via `scripts/sync-oss.sh` |

Synced slices include WASM crypto, external signer daemon, policy, API/subkey helpers, **seed custody** (`frontend-lib/custody/`), and **client signing** (`frontend-lib/signing/`).

```bash
cd ../../cb1.2
./scripts/sync-oss.sh          # commit + push to origin main
./scripts/sync-oss.sh --dry-run
```

After sync, embed `.oss-digest.txt` into the wallet build as `NEXT_PUBLIC_OSS_DIGEST` so `./verify.sh https://app.holder.bot` can match `/api/verify/oss`.

Local clone path: `safu-dev/holder-bot/core-security` · Remote: https://github.com/holder-bot/core-security

See [../INDEX.md](../INDEX.md) · [SECURITY.md](SECURITY.md) · [THREAT-MODEL.md](THREAT-MODEL.md)
