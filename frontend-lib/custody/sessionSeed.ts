/**
 * Unlocked-session mnemonic custody (OSS surface).
 *
 * Live + backup copies must both clear on lock. Product code (useWalletManagerState)
 * must call these helpers instead of maintaining private module globals.
 */

let sessionSeedPhrase: string | null = null;
let seedPhraseBackup: string | null = null;

/** Set unlocked mnemonic (also updates backup). */
export function setSessionMnemonic(mnemonic: string): void {
  const trimmed = typeof mnemonic === 'string' ? mnemonic.trim() : '';
  if (!trimmed) {
    clearSessionMnemonic();
    return;
  }
  sessionSeedPhrase = trimmed;
  seedPhraseBackup = trimmed;
}

/** Clear live + backup (lock / logout / reset). */
export function clearSessionMnemonic(): void {
  sessionSeedPhrase = null;
  seedPhraseBackup = null;
}

/**
 * Return live mnemonic, restoring from backup if live was lost
 * (same restore semantics as the former seedPhraseBackup helper).
 */
export function getSessionMnemonic(): string | null {
  if (!sessionSeedPhrase && seedPhraseBackup) {
    sessionSeedPhrase = seedPhraseBackup;
  }
  return sessionSeedPhrase;
}

/** Live value only — does not restore from backup. */
export function peekSessionMnemonic(): string | null {
  return sessionSeedPhrase;
}

/** Backup value only (for tests / diagnostics — never log contents). */
export function peekSessionMnemonicBackup(): string | null {
  return seedPhraseBackup;
}

/** True when neither live nor backup holds a mnemonic. */
export function isSessionMnemonicCleared(): boolean {
  return sessionSeedPhrase === null && seedPhraseBackup === null;
}
