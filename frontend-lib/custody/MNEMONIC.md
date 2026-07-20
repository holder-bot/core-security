# Mnemonic Security — Review, Design & Implementation

**Date:** 2026-07-19  
**Branches:** `cb2` (implementation), `cb1.2` (this doc / release line)  
**Scope:** Create wallet, import seed, seed backup screen, settings-seed, lock/logout, WASM vault encryption

---

## 1. Executive summary

At rest, Holder encrypts the seed with **AES-256-GCM** via WASM (`CryptoManager`), with a password-derived key (**PBKDF2-HMAC-SHA256**). That matches industry practice (MetaMask `browser-passworder`).

The main risk was **unlocked-session memory hygiene**: plaintext lived in JS module globals (`sessionSeedPhrase`, `seedPhraseBackup`), React `walletData.mnemonic`, and WASM `secured_mnemonic`, with incomplete clears on lock and overstated “memory cleared” APIs. UI anti-copy alone is not a custody control.

This work:

1. Hardens create/import/backup UX (mnemonic before `/assets`, non-copyable display, password-gated import with numbered words).
2. Aligns with MetaMask best practices where useful, and closes gaps where MetaMask is weak (no-op string “wipes”, incomplete lock clears).
3. Raises new-vault PBKDF2 to **900,000** iterations (MetaMask current default).
4. Documents remaining Phase-2 work (decrypt-in-WASM signing without a long-lived JS seed string).

---

## 2. Threat model (practical)

| Threat | Mitigation today | Residual |
|--------|------------------|----------|
| Stolen localStorage / disk | AES-GCM + PBKDF2; password strength | Offline brute-force of weak passwords |
| Casual shoulder-surf / accidental copy | Anti-select/copy UI; SRP confirm quiz | Screenshots, screen share, OCR |
| Accidental full-phrase paste on import | Block multi-word paste into word boxes | Single-word paste still allowed |
| Lock/logout leaves plaintext | Clear session + backup + WASM RAM | JS string GC not guaranteed |
| XSS / malicious extension while unlocked | CSP / extension review (ops) | Full seed theft while unlocked |
| DevTools / heap dump | Minimize lifetime; no seed logs | Same JS ceiling MetaMask documents |
| Address metadata leak | Never serialize mnemonic on address records | Legacy localStorage may still have old copies |

**Browser ceiling:** JavaScript cannot reliably zero `String` bytes. Prefer short lifetime, wipe `Uint8Array` where used, and honest APIs. Hardware enclaves are out of scope for a web wallet.

---

## 3. MetaMask open-source comparison

Sources reviewed:

- [`MetaMask/browser-passworder`](https://github.com/MetaMask/browser-passworder) — AES-GCM, PBKDF2 (**900k** default, **10k** legacy)
- KeyringController — `setLocked` clears in-memory secrets; vault persists encrypted
- SRP onboarding — show seed, then confirm random word positions
- BIP39 validation on import
- `@metamask/toprf-secure-backup` docs — avoid React state for secrets; `Uint8Array.fill(0)`; JS GC has no guarantees
- Known MetaMask weakness: mobile `wipeSensitiveData = () => ''` does not zero memory

| Practice | MetaMask | Holder (this work) |
|----------|----------|--------------------|
| Vault cipher | AES-GCM | AES-256-GCM (WASM) |
| KDF (new vaults) | PBKDF2 900k | PBKDF2 **900k** (was 100k); iterations stored in blob |
| Lock clears RAM secrets | Yes | `sessionSeedPhrase` + `seedPhraseBackup` + `clearWallet` / `clear_secured_mnemonic` |
| SRP confirm quiz | Yes | Two random word positions after backup display |
| BIP39 import check | Yes | `bip39.validateMnemonic` before submit |
| Secrets in React state | Discouraged | Strip `walletData.mnemonic` after confirm; display via ephemeral screen |
| Anti-copy UI | Limited | `ProtectedSeedPhrase` (UX only) |
| Seed logging | Avoid | Removed `SEED_TRACE` prefix logs |
| Mnemonic on address JSON | No | Removed from discovery / emergency unlock paths |

---

## 4. Architecture (custody layers)

```
At rest (KV / localStorage)
  └─ ciphertext JSON { ciphertext, nonce, salt, iterations }

WASM WalletManager
  ├─ secured_mnemonic (secrecy::Secret) — backup display only; clear after confirm / lock
  └─ current_keypair — cleared on lock

JS unlocked session
  ├─ sessionSeedPhrase — signing / derive until lock
  ├─ seedPhraseBackup — must clear on lock (was never cleared)
  └─ walletData.mnemonic — display; strip after backup confirm

UI
  ├─ SeedBackupScreen (show → confirm quiz)
  ├─ ProtectedSeedPhrase (non-selectable)
  └─ ImportSeedWordsForm (12/24 numbered boxes, no full paste)
```

### Encryption format

- Cipher: AES-256-GCM  
- KDF: PBKDF2-HMAC-SHA256  
- New encrypts: **900_000** iterations  
- Decrypt: uses `iterations` from the stored JSON (backward compatible with 100_000 vaults)

Implementation: `rust-wasm/src/crypto/encryption.rs` (`CryptoManager::encrypt_data` / `decrypt_data`).

---

## 5. UX flows

### 5.1 Create wallet

1. Password + confirm (optional 12/24 toggle for generation).
2. WASM generates wallet; JS pulls mnemonic once via `get_mnemonic_for_backup_display()` for encrypt + backup UI.
3. `currentScreen = 'seed-phrase'` → `SeedBackupScreen` (not `/assets` yet).
4. User writes seed → confirms two random words → `confirmSeedBackup()`.
5. Strip React mnemonic; clear WASM `secured_mnemonic`; navigate `/assets`.
6. `sessionSeedPhrase` remains for unlocked ops until lock.

### 5.2 Import wallet

1. Password + confirm required before Import Seed.
2. Numbered 12/24 word boxes; multi-word clipboard paste blocked.
3. BIP39 validate → encrypt vault → wallet screen (no backup quiz; user already has the seed).

### 5.3 Settings-seed / SecureSeedModal

- Decrypt with session password → `ProtectedSeedPhrase`.
- Hide clears local React string; does not re-export into address records.

### 5.4 Lock / logout

- Null `sessionSeedPhrase`, call `seedPhraseBackup.clear()`, clear session password / extension secret.
- Call `walletManager.clearWallet()` (WASM keypair + `secured_mnemonic` only — **not** the encrypted vault).
- Reset React wallet state to unlock/welcome.

---

## 6. Implementation inventory

### New / updated frontend

| Path | Role |
|------|------|
| `frontend/components/wallet/ProtectedSeedPhrase.tsx` | Non-selectable / non-copyable word grid |
| `frontend/components/wallet/ImportSeedWordsForm.tsx` | 12/24 numbered import; BIP39; paste block |
| `frontend/components/wallet/SeedBackupScreen.tsx` | Show + MetaMask-style confirm quiz |
| `frontend/components/wallet/NewWalletScreen.tsx` | Password gate; import view |
| `frontend/lib/security/secureMemory.ts` | `wipeBytes` / UTF-8 helpers (best-effort) |
| `frontend/hooks/useWalletManagerState.ts` | seed-phrase screen; confirm; lock clears; no seed logs; no mnemonic on addresses |
| `frontend/components/layout/SharedWalletLayout.tsx` | Render `SeedBackupScreen` when `currentScreen === 'seed-phrase'` |
| `frontend/app/(wallet)/settings-seed/page.tsx` | Uses `ProtectedSeedPhrase` |
| `frontend/components/accounts/modals/SecureSeedModal.tsx` | Uses `ProtectedSeedPhrase` |
| `frontend/lib/wasm/managers/walletManager.ts` | `clearSecuredMnemonic()` |

### WASM (`rust-wasm`)

| Change | Detail |
|--------|--------|
| PBKDF2 iterations | `100_000` → `900_000` for new encrypts |
| `clear_secured_mnemonic()` | Drop backup-display secret |
| `clear_wallet()` | Also clears `secured_mnemonic` |
| `clear_memory()` | Honest: stack scrub only; does not claim full secret wipe |

### Rebuild WASM

Root `Cargo.toml` must `exclude = ["rust-wasm"]` so `wasm-pack` can build the cdylib outside the native workspace.

```bash
# from repo root (cb2 or cb1.2) — requires wasm-pack + wasm32-unknown-unknown
export PATH="$HOME/.cargo/bin:$PATH"
cd rust-wasm
bash build-with-timestamp.sh          # web target → pkg/
bash build-nodejs.sh                  # node target → pkg-nodejs/ (optional, server)

cp pkg/solana_wasm_wallet_v2* ../frontend/public/wasm/
cp pkg/solana_wasm_wallet_v2* ../frontend/lib/wasm/binaries/
cp pkg/solana_wasm_wallet_v2* ../frontend/lib/wasm-static/   # if used
cp pkg-nodejs/solana_wasm_wallet_v2* ../frontend/public/wasm-nodejs/  # if built
```

**Built this delivery:** web WASM timestamp `20260719-210926` (exports `clear_secured_mnemonic`, PBKDF2 900k).

Note: `REBUILD_RUST=1` on `rb-app-full.sh` rebuilds the **native** `safu-api` binary, not the browser WASM. Ship WASM by committing the updated `frontend/public/wasm/*` artifacts (or rebuilding locally before deploy as above).

---

## 7. What “better than MetaMask” means here

Done in this pass:

- Honest clear APIs (no dummy “all secrets cleared” lie).
- Always clear `seedPhraseBackup` on lock (MetaMask-equivalent setLocked completeness).
- Anti-copy + block full-phrase paste on import/confirm.
- No mnemonic fields on address objects written to localStorage.
- No seed-prefix console logging.

Still Phase 2 (to beat MetaMask’s unlocked model further):

1. **Decrypt-in-WASM signing** — prefer `from_encrypted_seed_phrase` / sign-with-encrypted APIs; stop keeping `sessionSeedPhrase` for every op.
2. **Password verify** — verify by successful vault decrypt (MetaMask pattern), not weak 1000× SHA-256 with static salt.
3. **Uint8Array seed path** end-to-end for any short-lived display buffer with explicit `wipeBytes`.
4. **Migrate old vaults** optionally re-encrypt at 900k on next unlock (`updateVault`-style).

---

## 8. Test plan

- [ ] Create wallet → seed screen → fail confirm with wrong word → pass with correct words → `/assets`
- [ ] Create: seed text not selectable; copy blocked
- [ ] Import without password → blocked
- [ ] Import: paste full phrase into a box → blocked; BIP39 invalid → error
- [ ] Import 12 and 24 word valid phrases → unlock works after lock
- [ ] Lock → DevTools: `seedPhraseBackup` / session mnemonic not restorable via backup
- [ ] Settings-seed show/hide; copy blocked
- [ ] New wallet encrypt: blob JSON `iterations` === `900000`
- [ ] Old wallet (100000) still unlocks
- [ ] Extension pack: same flows in popup

---

## 9. Related canvases / prior notes

- Cursor canvas: `mnemonic-memory-security.canvas.tsx`
- Cursor canvas: `metamask-vs-holder-seed-security.canvas.tsx`
- Prior assessments: `cb2/security/assessment-v2-26-03-31/`, `assessment-v2-26-04-17/`

---

## 10. Change log (this delivery)

| Area | Change |
|------|--------|
| Create UX | Mnemonic backup + confirm before main wallet |
| Import UX | Password required; numbered words; 12/24; no full paste |
| Display | `ProtectedSeedPhrase` on backup + settings-seed |
| Lock | Clear backup + WASM secrets; preserve vault ciphertext |
| Crypto | PBKDF2 900k for new vaults |
| Hygiene | No seed logs; no mnemonic on address records |
| WASM | `clear_secured_mnemonic`; honest `clear_memory` |
