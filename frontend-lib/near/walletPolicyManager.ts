import crypto, { constants as cryptoConstants } from 'crypto';
import { connect, keyStores, KeyPair } from 'near-api-js';
import type { KeyPairString } from 'near-api-js/lib/utils/key_pair';
import { resolveNearSubkeyRpcUrl } from '@/lib/rpc/nearDefaults';
import { networkIdFromContractId } from './subkeyContract';

function normalizeKey(key: string): string {
  return key.startsWith('ed25519:') ? key : `ed25519:${key}`;
}

export function wrapPolicyManagerKey(plaintext: string, secret: string): {
  ciphertext: string;
  params: string;
} {
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const key = crypto.pbkdf2Sync(secret, salt, 100_000, 32, 'sha256');
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();
  const blob = Buffer.concat([ciphertext, authTag]);
  return {
    ciphertext: blob.toString('base64'),
    params: JSON.stringify({
      iv: iv.toString('base64'),
      salt: salt.toString('base64')
    })
  };
}

export function unwrapPolicyManagerKey(ciphertext: string, params: string, secret: string): string {
  const parsed = JSON.parse(params || '{}');
  const iv = Buffer.from(parsed.iv, 'base64');
  const salt = Buffer.from(parsed.salt, 'base64');
  const data = Buffer.from(ciphertext, 'base64');
  const authTag = data.slice(data.length - 16);
  const encrypted = data.slice(0, data.length - 16);
  const key = crypto.pbkdf2Sync(secret, salt, 100_000, 32, 'sha256');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf8');
}

export function encryptPolicyManagerKeyForServer(plaintext: string): string {
  const pem =
    process.env.SERVER_SIGNING_PUBLIC_KEY_PEM ||
    process.env.NEXT_PUBLIC_SERVER_SIGNING_PUBKEY_PEM?.replace(/\\n/g, '\n');
  if (pem) {
    const encrypted = crypto.publicEncrypt(
      {
        key: pem,
        padding: cryptoConstants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256'
      },
      Buffer.from(plaintext, 'utf8')
    );
    return encrypted.toString('base64');
  }

  return Buffer.from(plaintext, 'utf8').toString('base64');
}

export async function decryptPolicyManagerKeyFromServer(ciphertext: string): Promise<string> {
  const kmsKey = process.env.SERVER_SIGNING_KMS_KEY;
  const pem = process.env.SERVER_SIGNING_PRIVATE_KEY_PEM;

  // KMS first (production), PEM fallback (local dev)
  if (kmsKey) {
    const { KeyManagementServiceClient } = await import('@google-cloud/kms');
    const client = new KeyManagementServiceClient();
    const [resp] = await client.asymmetricDecrypt({
      name: kmsKey,
      ciphertext: Buffer.from(ciphertext, 'base64')
    });
    if (!resp.plaintext) throw new Error('KMS decrypt returned empty plaintext');
    return Buffer.from(resp.plaintext).toString('utf8');
  }

  if (pem) {
    const decrypted = crypto.privateDecrypt(
      {
        key: pem,
        padding: cryptoConstants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256'
      },
      Buffer.from(ciphertext, 'base64')
    );
    return decrypted.toString('utf8');
  }

  return Buffer.from(ciphertext, 'base64').toString('utf8');
}

function rpcUrlForNetwork(networkId: 'mainnet' | 'testnet'): string {
  return resolveNearSubkeyRpcUrl(networkId);
}

function extractNearOutcomeHash(outcome: any): string | null {
  const directHash =
    typeof outcome?.transaction?.hash === 'string' && outcome.transaction.hash.trim().length > 0
      ? outcome.transaction.hash.trim()
      : null;
  if (directHash) return directHash;

  const outcomeId =
    typeof outcome?.transaction_outcome?.id === 'string' && outcome.transaction_outcome.id.trim().length > 0
      ? outcome.transaction_outcome.id.trim()
      : null;
  if (outcomeId) return outcomeId;

  return null;
}

export async function createAndGrantPolicyManagerOnChain(params: {
  accountId: string;
  rootPrivateKey: string;
  contractId: string;
  signerPublicKey: string;
}) {
  const networkId = networkIdFromContractId(params.contractId);
  const keyStore = new keyStores.InMemoryKeyStore();
  const rootPrivateKey = normalizeKey(params.rootPrivateKey);
  const keyPair = KeyPair.fromString(rootPrivateKey as KeyPairString);
  await keyStore.setKey(networkId, params.accountId, keyPair);

  const near = await connect({
    networkId,
    nodeUrl: rpcUrlForNetwork(networkId),
    deps: { keyStore }
  });
  const account = await near.account(params.accountId);
  const signerPublicKey = normalizeKey(params.signerPublicKey);
  const accessKeyAllowance = process.env.POLICY_MANAGER_ACCESS_KEY_ALLOWANCE_YOCTO || '2000000000000000000000000';

  const rootPublicKey = keyPair.getPublicKey().toString();
  console.info('[POLICY-MANAGER] addKey starting', {
    accountId: params.accountId,
    rootPublicKey,
    signerPublicKey,
    contractId: params.contractId,
    networkId,
    rpcUrl: rpcUrlForNetwork(networkId)
  });

  try {
    await account.addKey(
      signerPublicKey,
      params.contractId,
      ['set_signer_policy', 'remove_signer_policy', 'get_signer_policy'],
      BigInt(accessKeyAllowance)
    );
    console.info('[POLICY-MANAGER] addKey succeeded, waiting 3s for NEAR propagation');
    await new Promise(r => setTimeout(r, 3000));
  } catch (error: any) {
    const message = String(error?.message || error || '');
    console.error('[POLICY-MANAGER] addKey error:', message.slice(0, 200));
    if (!message.toLowerCase().includes('already exists')) {
      throw error;
    }
  }

  // Use root key explicitly for add_subkey (FullAccess, not the new FunctionCall key)
  await account.functionCall({
    contractId: params.contractId,
    methodName: 'add_subkey',
    args: {
      public_key: signerPublicKey,
      derivation_paths: [
        {
          chain: 'Solana',
          paths: ['policy-manager']
        }
      ]
    },
    gas: BigInt('200000000000000'),
    attachedDeposit: BigInt('0')
  });

  const outcome = await account.functionCall({
    contractId: params.contractId,
    methodName: 'grant_policy_manager',
    args: { public_key: signerPublicKey, can_manage_self_policy: false },
    gas: BigInt('200000000000000'),
    attachedDeposit: BigInt('0')
  });

  return {
    grantTxHash: extractNearOutcomeHash(outcome)
  };
}
