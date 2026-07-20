/**
 * SRP backup confirmation helpers (OSS) — MetaMask-style random word check.
 */

export type SeedChallenge = { index: number; word: string };

export function splitMnemonicWords(mnemonic: string): string[] {
  return mnemonic.trim().split(/\s+/).filter(Boolean);
}

export function isValidWordCount(count: number): count is 12 | 24 {
  return count === 12 || count === 24;
}

/** Pick `n` distinct random word positions (default 2). */
export function pickSeedChallenges(
  words: string[],
  n = 2,
  random: () => number = Math.random,
): SeedChallenge[] {
  if (words.length < n) return [];
  const indices = new Set<number>();
  let guard = 0;
  while (indices.size < n && guard++ < 1000) {
    indices.add(Math.floor(random() * words.length));
  }
  return Array.from(indices)
    .sort((a, b) => a - b)
    .map((index) => ({ index, word: words[index]! }));
}

export function answersMatchChallenges(
  challenges: SeedChallenge[],
  answers: string[],
): boolean {
  if (challenges.length === 0 || challenges.length !== answers.length) return false;
  return challenges.every(
    (c, i) => (answers[i] || '').trim().toLowerCase() === c.word.toLowerCase(),
  );
}

/** Block pasting a full mnemonic into a single confirm/import box. */
export function isMultiWordClipboardPaste(text: string): boolean {
  return text.trim().split(/\s+/).filter(Boolean).length > 1;
}
