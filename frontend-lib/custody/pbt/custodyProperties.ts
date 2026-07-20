/**
 * Pure security property predicates for OSS / app PBT suites.
 * No WASM, React, or network — runnable in core-security/tests alone.
 */

import {
  addressListHasNoMnemonics,
  addressRecordHasMnemonic,
  stripMnemonicFromAddress,
} from '../addressSanitize';
import {
  answersMatchChallenges,
  isMultiWordClipboardPaste,
  isValidWordCount,
  pickSeedChallenges,
  splitMnemonicWords,
  type SeedChallenge,
} from '../seedConfirm';
import {
  clearSessionMnemonic,
  getSessionMnemonic,
  isSessionMnemonicCleared,
  peekSessionMnemonicBackup,
  setSessionMnemonic,
} from '../sessionSeed';
import { wipeBytes } from '../secureMemory';
import {
  parseVaultBlob,
  vaultBlobHasNoPlaintextSecretFields,
  vaultIterationsAcceptable,
  vaultIterationsIsCurrent,
  VAULT_PBKDF2_CURRENT,
  VAULT_PBKDF2_LEGACY_MIN,
} from '../vaultFormat';

export {
  VAULT_PBKDF2_CURRENT,
  VAULT_PBKDF2_LEGACY_MIN,
  addressListHasNoMnemonics,
  addressRecordHasMnemonic,
  answersMatchChallenges,
  clearSessionMnemonic,
  getSessionMnemonic,
  isMultiWordClipboardPaste,
  isSessionMnemonicCleared,
  isValidWordCount,
  parseVaultBlob,
  pickSeedChallenges,
  setSessionMnemonic,
  splitMnemonicWords,
  stripMnemonicFromAddress,
  vaultBlobHasNoPlaintextSecretFields,
  vaultIterationsAcceptable,
  vaultIterationsIsCurrent,
};

/** Lock clears both live and backup — property for PBT. */
export function lockClearsSessionMnemonic(mnemonic: string): boolean {
  setSessionMnemonic(mnemonic);
  if (!getSessionMnemonic()) return false;
  clearSessionMnemonic();
  return isSessionMnemonicCleared() && peekSessionMnemonicBackup() === null;
}

/** Wrong confirm answers must fail. */
export function wrongConfirmAnswersRejected(
  words: string[],
  challenges: SeedChallenge[],
): boolean {
  if (challenges.length === 0) return true;
  const bad = challenges.map(() => 'notaword');
  return !answersMatchChallenges(challenges, bad);
}

/** Correct confirm answers must pass. */
export function correctConfirmAnswersAccepted(
  words: string[],
  challenges: SeedChallenge[],
): boolean {
  if (challenges.length === 0) return words.length < 2;
  const good = challenges.map((c) => c.word);
  return answersMatchChallenges(challenges, good);
}

/** wipeBytes zeros every index. */
export function wipeBytesZerosAll(length: number): boolean {
  if (length <= 0) return true;
  const buf = new Uint8Array(length);
  for (let i = 0; i < length; i++) buf[i] = (i % 255) + 1;
  wipeBytes(buf);
  return buf.every((b) => b === 0);
}

/** Synthetic vault JSON shape property. */
export function syntheticVaultBlobValid(
  ciphertext: string,
  nonce: string,
  salt: string,
  iterations: number,
): boolean {
  const json = JSON.stringify({ ciphertext, nonce, salt, iterations });
  if (!vaultBlobHasNoPlaintextSecretFields(json)) return false;
  const parsed = parseVaultBlob(json);
  if (!parsed) return false;
  if (!vaultIterationsAcceptable(parsed.iterations)) return false;
  return parsed.ciphertext === ciphertext;
}
