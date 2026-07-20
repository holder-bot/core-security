# custody (OSS surface)

Seed/vault session primitives published to [holder-bot/core-security](https://github.com/holder-bot/core-security) as `frontend-lib/custody/`.

## Rules

- **Do not** import app pages, `useWalletManagerState`, Intents, or Activity from here.
- App code imports `@/lib/custody` (or `@/lib/custody/...`).
- Changes require OSS sync + digest bump — see [docs2/oss-segregation-plan.md](../../../docs2/oss-segregation-plan.md).

## Contents

| File | Role |
|------|------|
| `sessionSeed.ts` | Unlocked mnemonic live + backup; clear on lock |
| `secureMemory.ts` | `wipeBytes` helpers |
| `vaultFormat.ts` | Ciphertext JSON shape / PBKDF2 iteration checks |
| `seedConfirm.ts` | SRP confirm quiz + multi-word paste block |
| `addressSanitize.ts` | No mnemonic on address records |
| `pbt/custodyProperties.ts` | Pure predicates for OSS PBT suite |
