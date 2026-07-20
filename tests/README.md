# Core-security PBT suite

Property-based tests for custody / vault security assertions.

## Run from wallet repo (`cb1.2`)

```bash
cd oss-tests
npm install
npm test
```

Imports resolve to `../frontend/lib/custody`.

## Run from published package (`core-security`)

After `sync-oss.sh`, this directory is copied to `tests/`:

```bash
cd tests
npm install
npm test
```

Imports resolve to `../frontend-lib/custody` (set automatically when parent folder is `core-security`, or override with `OSS_CUSTODY_ROOT`).

## What these tests prove

- Lock clears live + backup session mnemonic
- SRP confirm quiz accepts correct words / rejects wrong
- Multi-word clipboard paste is detectable (import/confirm UX)
- Vault JSON has no plaintext secret fields; PBKDF2 iterations in range
- Address records must not carry mnemonics
- `wipeBytes` zeros buffers
