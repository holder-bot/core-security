/**
 * Pure vault ciphertext format checks (OSS).
 * Matches rust-wasm CryptoManager JSON: { ciphertext, nonce, salt, iterations }.
 */

export const VAULT_PBKDF2_LEGACY_MIN = 100_000;
export const VAULT_PBKDF2_CURRENT = 900_000;

export type VaultBlob = {
  ciphertext: string;
  nonce: string;
  salt: string;
  iterations: number;
};

const PLAINTEXT_LEAK_KEYS = [
  'mnemonic',
  'seed',
  'seedPhrase',
  'privateKey',
  'secretKey',
  'plaintext',
] as const;

export function parseVaultBlob(json: string): VaultBlob | null {
  try {
    const obj = JSON.parse(json) as Record<string, unknown>;
    if (
      typeof obj.ciphertext !== 'string' ||
      typeof obj.nonce !== 'string' ||
      typeof obj.salt !== 'string' ||
      typeof obj.iterations !== 'number'
    ) {
      return null;
    }
    return {
      ciphertext: obj.ciphertext,
      nonce: obj.nonce,
      salt: obj.salt,
      iterations: obj.iterations,
    };
  } catch {
    return null;
  }
}

/** Vault JSON must not carry plaintext secret field names at the top level. */
export function vaultBlobHasNoPlaintextSecretFields(json: string): boolean {
  try {
    const obj = JSON.parse(json) as Record<string, unknown>;
    for (const key of PLAINTEXT_LEAK_KEYS) {
      if (key in obj && obj[key] != null && obj[key] !== '') return false;
    }
    return true;
  } catch {
    return false;
  }
}

export function vaultIterationsAcceptable(iterations: number): boolean {
  return (
    Number.isInteger(iterations) &&
    iterations >= VAULT_PBKDF2_LEGACY_MIN &&
    iterations <= 10_000_000
  );
}

/** New encrypts should use current KDF (MetaMask-aligned 900k). */
export function vaultIterationsIsCurrent(iterations: number): boolean {
  return iterations === VAULT_PBKDF2_CURRENT;
}
