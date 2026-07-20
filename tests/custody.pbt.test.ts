import { describe, expect, it, beforeEach } from 'vitest';
import fc from 'fast-check';
import {
  addressListHasNoMnemonics,
  addressRecordHasMnemonic,
  answersMatchChallenges,
  clearSessionMnemonic,
  correctConfirmAnswersAccepted,
  getSessionMnemonic,
  isMultiWordClipboardPaste,
  isSessionMnemonicCleared,
  isValidWordCount,
  lockClearsSessionMnemonic,
  pickSeedChallenges,
  setSessionMnemonic,
  splitMnemonicWords,
  stripMnemonicFromAddress,
  syntheticVaultBlobValid,
  vaultBlobHasNoPlaintextSecretFields,
  vaultIterationsAcceptable,
  vaultIterationsIsCurrent,
  wipeBytesZerosAll,
  wrongConfirmAnswersRejected,
  VAULT_PBKDF2_CURRENT,
  VAULT_PBKDF2_LEGACY_MIN,
} from '@custody/pbt/custodyProperties';

const bip39Word = fc.stringMatching(/^[a-z]{3,8}$/);
const mnemonicArb = fc.integer({ min: 0, max: 1 }).chain((pick) => {
  const n = pick === 0 ? 12 : 24;
  return fc.array(bip39Word, { minLength: n, maxLength: n }).map((w) => w.join(' '));
});

describe('custody PBT — session mnemonic lock', () => {
  beforeEach(() => {
    clearSessionMnemonic();
  });

  it('lock clears live and backup for arbitrary mnemonics', () => {
    fc.assert(
      fc.property(mnemonicArb, (m) => {
        expect(lockClearsSessionMnemonic(m)).toBe(true);
        expect(isSessionMnemonicCleared()).toBe(true);
      }),
      { numRuns: 50 },
    );
  });

  it('set then get round-trips trimmed mnemonic', () => {
    fc.assert(
      fc.property(mnemonicArb, (m) => {
        setSessionMnemonic(`  ${m}  `);
        expect(getSessionMnemonic()).toBe(m.trim());
        clearSessionMnemonic();
      }),
      { numRuns: 40 },
    );
  });
});

describe('custody PBT — SRP confirm quiz', () => {
  it('word counts only 12 or 24 are valid', () => {
    fc.assert(
      fc.property(fc.integer({ min: 1, max: 48 }), (n) => {
        expect(isValidWordCount(n)).toBe(n === 12 || n === 24);
      }),
      { numRuns: 48 },
    );
  });

  it('correct answers accepted; wrong rejected', () => {
    fc.assert(
      fc.property(mnemonicArb, (m) => {
        const words = splitMnemonicWords(m);
        const challenges = pickSeedChallenges(words, 2, () => 0.1);
        expect(correctConfirmAnswersAccepted(words, challenges)).toBe(true);
        expect(wrongConfirmAnswersRejected(words, challenges)).toBe(true);
        // Case-insensitive match
        if (challenges.length > 0) {
          const upper = challenges.map((c) => c.word.toUpperCase());
          expect(answersMatchChallenges(challenges, upper)).toBe(true);
        }
      }),
      { numRuns: 40 },
    );
  });

  it('multi-word paste is blocked; single word is not', () => {
    fc.assert(
      fc.property(mnemonicArb, bip39Word, (m, w) => {
        expect(isMultiWordClipboardPaste(m)).toBe(true);
        expect(isMultiWordClipboardPaste(w)).toBe(false);
      }),
      { numRuns: 30 },
    );
  });
});

describe('custody PBT — vault format', () => {
  it('synthetic vault blobs validate; plaintext fields fail', () => {
    fc.assert(
      fc.property(
        fc.base64String({ minLength: 8, maxLength: 32 }),
        fc.base64String({ minLength: 8, maxLength: 24 }),
        fc.base64String({ minLength: 8, maxLength: 24 }),
        fc.constantFrom(VAULT_PBKDF2_LEGACY_MIN, VAULT_PBKDF2_CURRENT, 150_000),
        (ciphertext, nonce, salt, iterations) => {
          expect(syntheticVaultBlobValid(ciphertext, nonce, salt, iterations)).toBe(true);
          expect(vaultIterationsAcceptable(iterations)).toBe(true);
          if (iterations === VAULT_PBKDF2_CURRENT) {
            expect(vaultIterationsIsCurrent(iterations)).toBe(true);
          }
        },
      ),
      { numRuns: 40 },
    );

    const leak = JSON.stringify({
      ciphertext: 'x',
      nonce: 'y',
      salt: 'z',
      iterations: VAULT_PBKDF2_CURRENT,
      mnemonic: 'abandon abandon abandon',
    });
    expect(vaultBlobHasNoPlaintextSecretFields(leak)).toBe(false);
  });

  it('rejects absurd iteration counts', () => {
    fc.assert(
      fc.property(fc.integer({ min: 0, max: 99_999 }), (n) => {
        expect(vaultIterationsAcceptable(n)).toBe(false);
      }),
      { numRuns: 20 },
    );
  });
});

describe('custody PBT — address sanitize + wipe', () => {
  it('strips mnemonic from address records', () => {
    fc.assert(
      fc.property(mnemonicArb, fc.stringMatching(/^0x[a-f0-9]{8}$/), (m, addr) => {
        const dirty = { id: 'primary', address: addr, mnemonic: m };
        expect(addressRecordHasMnemonic(dirty)).toBe(true);
        const clean = stripMnemonicFromAddress(dirty);
        expect(addressRecordHasMnemonic(clean)).toBe(false);
        expect(addressListHasNoMnemonics([clean])).toBe(true);
      }),
      { numRuns: 30 },
    );
  });

  it('wipeBytes zeros arbitrary lengths', () => {
    fc.assert(
      fc.property(fc.integer({ min: 1, max: 256 }), (n) => {
        expect(wipeBytesZerosAll(n)).toBe(true);
      }),
      { numRuns: 30 },
    );
  });
});
