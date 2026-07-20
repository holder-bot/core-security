import crypto, { constants as cryptoConstants } from 'crypto';
import type { APIKey } from '@/lib/database/agentKeys';

function unwrapWithPassphrase(wrapped: string, wrapParams: string, passphrase: string): string {
  const parsed = JSON.parse(wrapParams);
  const iv = Buffer.from(parsed.iv, 'base64');
  const salt = Buffer.from(parsed.salt, 'base64');
  const data = Buffer.from(wrapped, 'base64');
  const authTag = data.slice(data.length - 16);
  const ct = data.slice(0, data.length - 16);
  const key = crypto.pbkdf2Sync(passphrase, salt, 100_000, 32, 'sha256');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(authTag);
  const plaintext = Buffer.concat([decipher.update(ct), decipher.final()]);
  return plaintext.toString('utf8');
}

async function decryptServerKey(cipher: string): Promise<string> {
  const kmsKey = process.env.SERVER_SIGNING_KMS_KEY;
  const pem = process.env.SERVER_SIGNING_PRIVATE_KEY_PEM;

  // Priority: KMS first (production on GCR), PEM fallback (local K8s / dev).
  // If both are set, KMS wins — PEM should never be used on GCR.
  if (kmsKey) {
    if (pem) {
      console.warn('[SERVER-SIGNING] Both KMS and PEM configured — using KMS (PEM ignored). Remove SERVER_SIGNING_PRIVATE_KEY_PEM on production.');
    }
    const { KeyManagementServiceClient } = await import('@google-cloud/kms');
    const client = new KeyManagementServiceClient();
    const ciphertext = Buffer.from(cipher, 'base64');
    const kmsKeyVersion = kmsKey.includes('/cryptoKeyVersions/')
      ? kmsKey
      : `${kmsKey}/cryptoKeyVersions/1`;
    const [resp] = await client.asymmetricDecrypt({
      name: kmsKeyVersion,
      ciphertext
    });
    if (!resp.plaintext) throw new Error('KMS decrypt returned empty plaintext');
    return Buffer.from(resp.plaintext).toString('utf8');
  }

  if (pem) {
    const ciphertext = Buffer.from(cipher, 'base64');
    const decrypted = crypto.privateDecrypt(
      {
        key: pem,
        padding: cryptoConstants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256'
      },
      ciphertext
    );
    return decrypted.toString('utf8');
  }

  throw new Error('Server signing key not configured (set SERVER_SIGNING_KMS_KEY for production or SERVER_SIGNING_PRIVATE_KEY_PEM for local dev)');
}

export function normalizeEd25519Key(key: string): string {
  return key.startsWith('ed25519:') ? key : `ed25519:${key}`;
}

export async function decryptSubkeyPrivateKey(apiKey: APIKey, passphrase: string): Promise<string> {
  if (!apiKey.subkeyServerWrappedPrivateKey || !apiKey.subkeyWrapParams) {
    throw new Error('Subkey not available for this API key — key may have been created without dual-layer encryption. Delete and recreate this API key.');
  }
  const cipher = unwrapWithPassphrase(apiKey.subkeyServerWrappedPrivateKey, apiKey.subkeyWrapParams, passphrase);
  const plaintext = await decryptServerKey(cipher);
  return normalizeEd25519Key(plaintext);
}

export async function decryptApiKeySigningPrivateKey(apiKey: APIKey, passphrase: string): Promise<string> {
  if (!apiKey.serverWrappedPrivateKey || !apiKey.serverWrapParams) {
    throw new Error('Server signing key not available for this API key — key may have been created without dual-layer encryption. Delete and recreate this API key.');
  }
  const cipher = unwrapWithPassphrase(apiKey.serverWrappedPrivateKey, apiKey.serverWrapParams, passphrase);
  const plaintext = await decryptServerKey(cipher);
  return normalizeEd25519Key(plaintext);
}
