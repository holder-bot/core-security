import { connect, keyStores, KeyPair } from 'near-api-js';
import type { KeyPairString } from 'near-api-js/lib/utils/key_pair';
import { resolveNearSubkeyRpcUrl } from '@/lib/rpc/nearDefaults';
import { nearMpcFunctionCallGas } from '@/lib/near/nearMpcFunctionCallGas';
import { networkIdFromContractId } from './subkeyContract';

export interface ApiKeyPolicySyncPayload {
  version: string;
  templateId: string;
  assetType: string;
  assetId?: string | null;
  maxPerTxNative?: string | null;
  maxPerPeriodNative?: string | null;
  periodSeconds?: number | null;
  maxTxCountPerPeriod?: number | null;
  allowDestinations: string[];
  periodStartUnixSeconds?: number | null;
  spentThisPeriodNative?: string | null;
  txCountThisPeriod?: number | null;
}

function normalizeKey(key: string): string {
  return key.startsWith('ed25519:') ? key : `ed25519:${key}`;
}

function rpcUrlForNetwork(networkId: 'mainnet' | 'testnet'): string {
  return resolveNearSubkeyRpcUrl(networkId);
}

function extractNearOutcomeHash(outcome: any): string | null {
  // near-api-js 6.x returns different structures depending on the method
  const candidates = [
    outcome?.transaction?.hash,
    outcome?.transaction_outcome?.id,
    // near-api-js 6.x signAndSendTransaction returns { transaction: { hash } }
    outcome?.hash,
    // Some versions return the hash at the top level
    typeof outcome === 'string' ? outcome : null,
  ];
  for (const c of candidates) {
    if (typeof c === 'string' && c.trim().length > 0) return c.trim();
  }
  return null;
}

async function getSignerAccount(params: {
  networkId: 'mainnet' | 'testnet';
  accountId: string;
  privateKey: string;
}) {
  if (!params.accountId || !params.privateKey) {
    throw new Error('NEAR policy signer credentials are not configured');
  }

  const keyStore = new keyStores.InMemoryKeyStore();
  const keyPair = KeyPair.fromString(normalizeKey(params.privateKey) as KeyPairString);
  await keyStore.setKey(params.networkId, params.accountId, keyPair);

  const near = await connect({
    networkId: params.networkId,
    nodeUrl: rpcUrlForNetwork(params.networkId),
    deps: { keyStore }
  });

  return near.account(params.accountId);
}

export async function syncApiKeyPolicyOnChain(params: {
  contractId: string;
  signerAccountId: string;
  signerPrivateKey: string;
  targetPublicKey: string;
  policy: ApiKeyPolicySyncPayload | null;
}) {
  const networkId = networkIdFromContractId(params.contractId);
  const account = await getSignerAccount({
    networkId,
    accountId: params.signerAccountId,
    privateKey: params.signerPrivateKey
  });
  const publicKey = normalizeKey(params.targetPublicKey);

  if (params.policy) {
    const outcome = await account.functionCall({
      contractId: params.contractId,
      methodName: 'set_signer_policy',
      args: { public_key: publicKey, policy: params.policy },
      gas: nearMpcFunctionCallGas(),
      attachedDeposit: BigInt('0')
    });
    return {
      outcome,
      txHash: extractNearOutcomeHash(outcome)
    };
  }

  const outcome = await account.functionCall({
    contractId: params.contractId,
    methodName: 'remove_signer_policy',
    args: { public_key: publicKey },
    gas: nearMpcFunctionCallGas(),
    attachedDeposit: BigInt('0')
  });
  return {
    outcome,
    txHash: extractNearOutcomeHash(outcome)
  };
}
