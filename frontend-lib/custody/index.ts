/**
 * @holder/custody — OSS-published seed/vault session surface.
 * Product code may import from here; this package must not import app pages/hooks.
 */

export {
  clearSessionMnemonic,
  getSessionMnemonic,
  isSessionMnemonicCleared,
  peekSessionMnemonic,
  peekSessionMnemonicBackup,
  setSessionMnemonic,
} from './sessionSeed';

export { dropSecretRef, utf8Bytes, wipeBytes } from './secureMemory';

export {
  VAULT_PBKDF2_CURRENT,
  VAULT_PBKDF2_LEGACY_MIN,
  parseVaultBlob,
  vaultBlobHasNoPlaintextSecretFields,
  vaultIterationsAcceptable,
  vaultIterationsIsCurrent,
  type VaultBlob,
} from './vaultFormat';

export {
  answersMatchChallenges,
  isMultiWordClipboardPaste,
  isValidWordCount,
  pickSeedChallenges,
  splitMnemonicWords,
  type SeedChallenge,
} from './seedConfirm';

export {
  addressListHasNoMnemonics,
  addressRecordHasMnemonic,
  stripMnemonicFromAddress,
} from './addressSanitize';

export {
  clearSeedBackupPending,
  isSeedBackupPending,
  markSeedBackupPending,
  markSeedBackupPendingAsync,
} from './seedBackupGate';
