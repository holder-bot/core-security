import { connect, keyStores, KeyPair } from 'near-api-js';
import type { KeyPairString } from 'near-api-js/lib/utils/key_pair';
import bs58 from 'bs58';
import type { RpcEndpointRole } from '@/lib/database/agentKeys';
import { rpcEndpointRegistry } from '@/lib/rpc/RpcEndpointRegistry';
import {
  DEFAULT_TESTNET_RPC,
  filterSignSubmitRpcUrls,
  normalizeNearNetworkId,
  pinNearSubkeySubmitRpcPrimary,
  prioritizeSigningRpcCandidates,
} from '@/lib/rpc/nearDefaults';
import { finishNearRpcAttempt } from '@/lib/rpc/nearRpcAttempt';
import { runSequentialRpcFallback, runStickyPollLoop } from '@/lib/rpc/RpcHealthCoordinator';
import { classifyRpcError } from '@/lib/rpc/rpcErrorClass';
import {
  orderPollEndpoints,
} from '@/lib/mpc/pollDefaults';
import { PROD_MODE } from '@/lib/featureFlags';
import { getNetworkConfig, readWalletNetworkLabel } from '@/lib/wallet/network';
import { serviceTuningRegistry } from '@/lib/tuning/ServiceTuningRegistry';

export type SubkeySignRequest = {
  /** Near uses same Eddsa path as Solana until Chain::Near is on-chain; prefer 'Near' after deploy. */
  chain: 'Solana' | 'Evm' | 'Bitcoin' | 'Near';
  derivation_path: string;
  payload: string; // base64
  memo?: string | null;
};

export type TemplateSignRequest = {
  template_id: string;
  chain: 'Solana' | 'Evm' | 'Bitcoin' | 'Near';
  derivation_path: string;
  to: string;
  amount: string; // U128 as string
  token_contract?: string | null;
  symbol?: string | null;
  evm_chain_id?: string | null;
  memo?: string | null;
  evm_tx_params?: {
    nonce: number;
    gas_limit: number;
    max_fee_per_gas: string; // U128 as string
    max_priority_fee_per_gas: string; // U128 as string
    data?: string | null; // hex-encoded calldata
  };
};

export type SignResult = {
  request_id: string;
  ok: boolean;
  payload?: string;
  error?: string;
  rpcNodeUrl?: string;
  rpcAttempt?: number;
};

/**
 * Whether an MPC poll tick should stop the loop (probe parity).
 * Pending / not-ready responses have ok:false with no error — keep polling.
 */
export function isMpcSignPollTerminal(
  value: SignResult | null,
  attemptIndex: number,
  maxAttempts: number,
): boolean {
  if (!value) return false;
  if (value.ok && value.payload) return true;
  if (!value.ok) {
    if (!value.error) return false;
    const retryableMpcFailure =
      /mpc sign failed/i.test(value.error) && attemptIndex < maxAttempts - 1;
    return !retryableMpcFailure;
  }
  return false;
}

/** Sync RPC list (cached admin config or static defaults + health ranking). */
export function resolveRpcCandidates(network?: string, role: RpcEndpointRole = 'general'): string[] {
  return rpcEndpointRegistry.getUrlsSync(network, role);
}

/** Async RPC list; refreshes from admin DB when cache is stale. */
export async function resolveRpcCandidatesAsync(
  network?: string,
  role: RpcEndpointRole = 'general'
): Promise<string[]> {
  return rpcEndpointRegistry.getUrls(network, role);
}

async function resolveSigningRpcUrls(networkId: string): Promise<string[]> {
  serviceTuningRegistry.prefetch();
  const net = normalizeNearNetworkId(networkId);
  const urls = await resolveRpcCandidatesAsync(net, 'sign_submit');
  const ranked = prioritizeSigningRpcCandidates(filterSignSubmitRpcUrls(urls));
  return pinNearSubkeySubmitRpcPrimary(net, ranked);
}

async function resolvePollRpcUrls(networkId: string): Promise<string[]> {
  serviceTuningRegistry.prefetch();
  return resolveRpcCandidatesAsync(networkId, 'sign_poll');
}

function normalizeKey(key: string): string {
  if (key.startsWith('ed25519:')) return key;
  return `ed25519:${key}`;
}

function formatUnknownError(error: unknown): string {
  if (error === undefined || error === null) {
    return 'unknown error';
  }
  if (error instanceof Error) {
    const anyErr = error as any;
    const parts = [
      error.name || 'Error',
      error.message || '',
      anyErr?.type ? `type=${String(anyErr.type)}` : '',
      anyErr?.context?.transactionHash ? `tx=${String(anyErr.context.transactionHash)}` : ''
    ].filter(Boolean);
    return parts.join(' | ');
  }
  if (typeof error === 'string') return error;
  try {
    return JSON.stringify(error);
  } catch {
    return String(error);
  }
}

/** Max wait per request_sign_v2 submit attempt (failover to next endpoint). */
export const MPC_SUBMIT_TIMEOUT_MS = 45_000;

/** Max wait per get_sign_result poll tick (matches ~8s MPC p95 + margin). */
export const MPC_POLL_CALL_TIMEOUT_MS = 8_000;

async function withTimeout<T>(promise: Promise<T>, timeoutMs: number, timeoutMessage: string): Promise<T> {
  let timeoutHandle: NodeJS.Timeout | null = null;
  try {
    return await Promise.race([
      promise,
      new Promise<T>((_, reject) => {
        timeoutHandle = setTimeout(() => reject(new Error(timeoutMessage)), timeoutMs);
      })
    ]);
  } finally {
    if (timeoutHandle) clearTimeout(timeoutHandle);
  }
}

async function viewSignResultWithTimeout(
  account: { viewFunction: (args: object) => Promise<unknown> },
  contractId: string,
  requestId: string,
  nodeUrl: string
): Promise<unknown> {
  const timeoutMs = serviceTuningRegistry.getInt('mpc_poll_call_timeout_ms', MPC_POLL_CALL_TIMEOUT_MS);
  return withTimeout(
    account.viewFunction({
      contractId,
      methodName: 'get_sign_result',
      args: { request_id: requestId },
    }),
    timeoutMs,
    `get_sign_result timed out after ${timeoutMs}ms via ${nodeUrl}`
  );
}

export function networkIdFromContractId(contractId: string): 'mainnet' | 'testnet' {
  return contractId.endsWith('.testnet') ? 'testnet' : 'mainnet';
}

/**
 * Resolve the active subkey contract based on the wallet's network setting.
 * Deployed hosts (alpha/app.holder.bot) always use mainnet contract.
 */
export function getNetworkAwareContractId(): string {
  if (typeof window === 'undefined') {
    if (PROD_MODE || (process.env.NEXT_PUBLIC_WALLET_ORIGIN || '').includes('holder.bot')) {
      return process.env.NEXT_PUBLIC_NEAR_MAINNET_SUBKEY_CONTRACT_ID
        || 'contract.saifu-network.near';
    }
    return process.env.NEXT_PUBLIC_NEAR_SUBKEY_CONTRACT_ID
      || process.env.NEAR_SUBKEY_CONTRACT_ID
      || 'saif-near.testnet';
  }

  return getNetworkConfig(readWalletNetworkLabel()).nearSubkeyContract;
}

export function getSubkeyConfig(contractIdOverride?: string) {
  const contractId =
    contractIdOverride ||
    process.env.NEXT_PUBLIC_NEAR_SUBKEY_CONTRACT_ID ||
    process.env.NEAR_SUBKEY_CONTRACT_ID ||
    'saif-near.testnet';
  const networkId: 'mainnet' | 'testnet' =
    contractIdOverride
      ? networkIdFromContractId(contractIdOverride)
      : ((process.env.NEAR_NETWORK as 'mainnet' | 'testnet') || networkIdFromContractId(contractId));
  // When a specific contractId is supplied (per-key routing), derive the MPC
  // contract purely from the key's network so that NEAR_CHAIN_SIG_CONTRACT_ID
  // (a deployment-level default) cannot silently override testnet keys on a
  // mainnet-primary host (or vice-versa).
  const mpcContractId = contractIdOverride
    ? (networkId === 'mainnet' ? 'v1.signer' : 'v1.signer-prod.testnet')
    : (process.env.NEAR_CHAIN_SIG_CONTRACT_ID ||
       (networkId === 'mainnet' ? 'v1.signer' : 'v1.signer-prod.testnet'));
  return { contractId, networkId, mpcContractId };
}

function normalizeDerivedPublicKeyToSolanaAddress(derivedKey: unknown): string | null {
  if (!derivedKey) return null;

  if (typeof derivedKey === 'string') {
    const trimmed = derivedKey.trim();
    if (trimmed.includes(':')) {
      const [curve, key] = trimmed.split(':', 2);
      if (curve.toLowerCase() !== 'ed25519') {
        // The MPC contract may return secp256k1 even with IsEd25519: true.
        // This is a known infrastructure issue (see cb1.2 commit f63de27e).
        // Throw here so the orchestrator's catch block can skip the preflight
        // and proceed to signing — the signing path uses the derivation path
        // directly and does not need the derived address.
        throw new Error(`MPC signer curve mismatch: expected ed25519, got ${curve}`);
      }
      const decoded = bs58.decode(key);
      if (decoded.length !== 32) {
        throw new Error(`Invalid ed25519 key length from MPC signer: ${decoded.length}`);
      }
      return key;
    }
    const looksBase58 = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(trimmed);
    if (looksBase58) {
      return trimmed;
    }
    const cleaned = trimmed.startsWith('0x') ? trimmed.slice(2) : trimmed;
    if (/^[0-9a-fA-F]+$/.test(cleaned) && cleaned.length >= 64) {
      let keyBytes = Buffer.from(cleaned, 'hex');
      if (keyBytes.length > 0 && keyBytes[0] === 0x04) {
        keyBytes = keyBytes.subarray(1);
      }
      if (keyBytes.length > 32) {
        keyBytes = keyBytes.subarray(0, 32);
      }
      return bs58.encode(keyBytes);
    }
  }

  const maybeArray =
    Array.isArray(derivedKey)
      ? derivedKey
      : typeof derivedKey === 'object' && derivedKey !== null && Array.isArray((derivedKey as any).data)
      ? (derivedKey as any).data
      : null;
  if (!maybeArray) return null;

  let keyBytes = Buffer.from(maybeArray);
  if (keyBytes.length > 0 && keyBytes[0] === 0x04) {
    keyBytes = keyBytes.subarray(1);
  }
  if (keyBytes.length > 32) {
    keyBytes = keyBytes.subarray(0, 32);
  }
  return bs58.encode(keyBytes);
}

const DERIVED_SOLANA_ADDRESS_TTL_MS = 60 * 60 * 1000;
const derivedSolanaAddressCache = new Map<string, { address: string; at: number }>();

function derivedSolanaCacheKey(accountId: string, derivationPath: string, subkeyContractId: string): string {
  return `${subkeyContractId}:${accountId}:${derivationPath}`;
}

export async function deriveSolanaMpcAddress(params: {
  accountId: string;
  derivationPath: string;
  subkeyContractId?: string;
  mpcContractId?: string;
}): Promise<{ address: string; rpcNodeUrl: string; rpcAttempt: number }> {
  const config = getSubkeyConfig(params.subkeyContractId);
  const subkeyContractId = params.subkeyContractId || config.contractId;
  const cacheKey = derivedSolanaCacheKey(params.accountId, params.derivationPath, subkeyContractId);
  const cached = derivedSolanaAddressCache.get(cacheKey);
  if (cached && Date.now() - cached.at < DERIVED_SOLANA_ADDRESS_TTL_MS) {
    return { address: cached.address, rpcNodeUrl: 'memory-cache', rpcAttempt: 0 };
  }
  const mpcContractId = params.mpcContractId || config.mpcContractId;
  const scopedPath = `${params.accountId}:${params.derivationPath}`;
  rpcEndpointRegistry.prefetch(config.networkId, 'general');
  const rpcUrls = await resolveRpcCandidatesAsync(config.networkId, 'general');
  let lastError: unknown;

  try {
    const chainsig = await import('chainsig.js');
    const contract = new (chainsig as any).contracts.ChainSignatureContract({
      contractId: mpcContractId,
      networkId: config.networkId,
      fallbackRpcUrls: rpcUrls
    });
    const derivedKey = await contract.getDerivedPublicKey({
      path: scopedPath,
      predecessor: subkeyContractId,
      IsEd25519: true
    });
    const address = normalizeDerivedPublicKeyToSolanaAddress(derivedKey);
    if (!address) {
      throw new Error(`Unable to normalize derived MPC key for path ${scopedPath}`);
    }
    derivedSolanaAddressCache.set(cacheKey, { address, at: Date.now() });
    return {
      address,
      rpcNodeUrl: rpcUrls[0] || DEFAULT_TESTNET_RPC,
      rpcAttempt: 1
    };
  } catch (chainsigError) {
    lastError = chainsigError;
    console.warn('[SUBKEY-CONTRACT] deriveSolanaMpcAddress chainsig lookup failed:', formatUnknownError(chainsigError));
  }

  return runSequentialRpcFallback({
    endpoints: rpcUrls,
    errorPrefix: 'deriveSolanaMpcAddress',
    formatError: formatUnknownError,
    execute: async (nodeUrl, attemptNo) => {
      const startedAt = Date.now();
      const near = await connect({
        networkId: config.networkId,
        nodeUrl,
        deps: { keyStore: new keyStores.InMemoryKeyStore() },
      });
      const account = await near.account(params.accountId);
      const derivedKey = await account.viewFunction({
        contractId: mpcContractId,
        methodName: 'derived_public_key',
        args: {
          path: scopedPath,
          predecessor: subkeyContractId,
          IsEd25519: true,
        },
      });

      const address = normalizeDerivedPublicKeyToSolanaAddress(derivedKey);
      if (!address) {
        throw new Error(`Unable to normalize derived MPC key for path ${scopedPath}`);
      }

      finishNearRpcAttempt({
        nodeUrl,
        network: config.networkId,
        role: 'general',
        opType: 'derive_solana_mpc_address',
        ok: true,
        startedAt,
        attemptNo,
      });
      derivedSolanaAddressCache.set(cacheKey, { address, at: Date.now() });
      return { address, rpcNodeUrl: nodeUrl, rpcAttempt: attemptNo };
    },
    onExecuteError: (nodeUrl, error, attemptNo) => {
      finishNearRpcAttempt({
        nodeUrl,
        network: config.networkId,
        role: 'general',
        opType: 'derive_solana_mpc_address',
        ok: false,
        startedAt: Date.now(),
        error,
        attemptNo,
      });
      console.warn('[SUBKEY-CONTRACT] deriveSolanaMpcAddress failed via RPC', {
        nodeUrl,
        rpcAttempt: attemptNo,
        errorMessage: formatUnknownError(error),
        error,
      });
    },
  });
}

export async function requestSignV2(params: {
  accountId: string;
  subkeyPrivateKey: string;
  requestId: string;
  request: SubkeySignRequest;
  contractId?: string;
}) {
  const config = getSubkeyConfig(params.contractId);
  const contractId = params.contractId || config.contractId;
  const rpcUrls = await resolveSigningRpcUrls(config.networkId);
  console.log('[SUBKEY-CONTRACT] request_sign_v2', {
    accountId: params.accountId,
    requestId: params.requestId,
    chain: params.request.chain,
    derivationPath: params.request.derivation_path,
    contractId,
    rpcUrls
  });
  const keyStore = new keyStores.InMemoryKeyStore();
  const keyPair = KeyPair.fromString(normalizeKey(params.subkeyPrivateKey) as KeyPairString);
  await keyStore.setKey(config.networkId, params.accountId, keyPair);
  await serviceTuningRegistry.refresh();
  const submitTimeoutMs = serviceTuningRegistry.getInt('mpc_submit_timeout_ms', MPC_SUBMIT_TIMEOUT_MS);
  return runSequentialRpcFallback({
    endpoints: rpcUrls,
    errorPrefix: 'request_sign_v2',
    formatError: formatUnknownError,
    execute: async (nodeUrl, attemptNo) => {
      const startedAt = Date.now();
      const near = await connect({
        networkId: config.networkId,
        nodeUrl,
        deps: { keyStore },
      });
      const account = await near.account(params.accountId);
      const outcome = await withTimeout(
        account.functionCall({
          contractId,
          methodName: 'request_sign_v2',
          args: { request_id: params.requestId, request: params.request },
          gas: BigInt('200000000000000'),
          attachedDeposit: BigInt('0'),
        }),
        submitTimeoutMs,
        `request_sign_v2 timed out after ${submitTimeoutMs}ms via ${nodeUrl}`
      );
      const txId =
        (outcome as any)?.transaction?.hash ||
        (outcome as any)?.transaction_outcome?.id ||
        undefined;
      finishNearRpcAttempt({
        nodeUrl,
        network: config.networkId,
        role: 'sign_submit',
        opType: 'request_sign_v2',
        ok: true,
        startedAt,
        requestId: params.requestId,
        txId,
        attemptNo,
      });
      try {
        return Object.assign({}, outcome, { __rpcNodeUrl: nodeUrl, __rpcAttempt: attemptNo });
      } catch {
        return outcome;
      }
    },
    onExecuteError: (nodeUrl, error, attemptNo) => {
      finishNearRpcAttempt({
        nodeUrl,
        network: config.networkId,
        role: 'sign_submit',
        opType: 'request_sign_v2',
        ok: false,
        startedAt: Date.now(),
        error,
        requestId: params.requestId,
        attemptNo,
      });
      console.warn('[SUBKEY-CONTRACT] request_sign_v2 failed via RPC', {
        nodeUrl,
        rpcAttempt: attemptNo,
        errorMessage: formatUnknownError(error),
        error,
      });
    },
  });
}

/**
 * Call request_template_sign_v2 on the subkey contract.
 * Used for EVM transactions where the contract builds the tx from template params.
 */
export async function requestTemplateSignV2(params: {
  accountId: string;
  subkeyPrivateKey: string;
  requestId: string;
  request: TemplateSignRequest;
  contractId?: string;
}) {
  const config = getSubkeyConfig(params.contractId);
  const contractId = params.contractId || config.contractId;
  const rpcUrls = await resolveSigningRpcUrls(config.networkId);
  console.log('[SUBKEY-CONTRACT] request_template_sign_v2', {
    accountId: params.accountId,
    requestId: params.requestId,
    templateId: params.request.template_id,
    chain: params.request.chain,
    to: params.request.to,
    amount: params.request.amount,
    evmChainId: params.request.evm_chain_id,
    contractId,
  });
  const keyStore = new keyStores.InMemoryKeyStore();
  const keyPair = KeyPair.fromString(normalizeKey(params.subkeyPrivateKey) as KeyPairString);
  await keyStore.setKey(config.networkId, params.accountId, keyPair);
  await serviceTuningRegistry.refresh();
  const submitTimeoutMs = serviceTuningRegistry.getInt('mpc_submit_timeout_ms', MPC_SUBMIT_TIMEOUT_MS);
  return runSequentialRpcFallback({
    endpoints: rpcUrls,
    errorPrefix: 'request_template_sign_v2',
    formatError: formatUnknownError,
    execute: async (nodeUrl, attemptNo) => {
      const startedAt = Date.now();
      const near = await connect({
        networkId: config.networkId,
        nodeUrl,
        deps: { keyStore },
      });
      const account = await near.account(params.accountId);
      const outcome = await withTimeout(
        account.functionCall({
          contractId,
          methodName: 'request_template_sign_v2',
          args: { request_id: params.requestId, request: params.request },
          gas: BigInt('200000000000000'),
          attachedDeposit: BigInt('0'),
        }),
        submitTimeoutMs,
        `request_template_sign_v2 timed out after ${submitTimeoutMs}ms via ${nodeUrl}`
      );
      const txId =
        (outcome as any)?.transaction?.hash ||
        (outcome as any)?.transaction_outcome?.id ||
        undefined;
      finishNearRpcAttempt({
        nodeUrl,
        network: config.networkId,
        role: 'sign_submit',
        opType: 'request_template_sign_v2',
        ok: true,
        startedAt,
        requestId: params.requestId,
        txId,
        attemptNo,
      });
      try {
        return Object.assign({}, outcome, { __rpcNodeUrl: nodeUrl, __rpcAttempt: attemptNo });
      } catch {
        return outcome;
      }
    },
    onExecuteError: (nodeUrl, error, attemptNo) => {
      finishNearRpcAttempt({
        nodeUrl,
        network: config.networkId,
        role: 'sign_submit',
        opType: 'request_template_sign_v2',
        ok: false,
        startedAt: Date.now(),
        error,
        requestId: params.requestId,
        attemptNo,
      });
      console.error('[SUBKEY-CONTRACT] request_template_sign_v2 failed via RPC', {
        nodeUrl,
        rpcAttempt: attemptNo,
        errorMessage: formatUnknownError(error),
        accountId: params.accountId,
        contractId,
      });
    },
  });
}

export async function getSignResult(params: {
  accountId: string;
  requestId: string;
  contractId?: string;
}) {
  const config = getSubkeyConfig(params.contractId);
  const contractId = params.contractId || config.contractId;
  const rpcUrls = await resolvePollRpcUrls(config.networkId);
  if (!rpcUrls.length) return null;

  const { raw, nodeUrl, attemptNo } = await runSequentialRpcFallback<{
    raw: unknown;
    nodeUrl: string;
    attemptNo: number;
  }>({
    endpoints: rpcUrls,
    errorPrefix: 'get_sign_result',
    formatError: formatUnknownError,
    execute: async (nodeUrl, attemptNo) => {
      const startedAt = Date.now();
      const near = await connect({
        networkId: config.networkId,
        nodeUrl,
        deps: { keyStore: new keyStores.InMemoryKeyStore() },
      });
      const account = await near.account(params.accountId);
      const raw = await viewSignResultWithTimeout(
        account,
        contractId,
        params.requestId,
        nodeUrl
      );
      finishNearRpcAttempt({
        nodeUrl,
        network: config.networkId,
        role: 'sign_poll',
        opType: 'get_sign_result',
        ok: true,
        startedAt,
        requestId: params.requestId,
        attemptNo,
      });
      return { raw, nodeUrl, attemptNo };
    },
    onExecuteError: (nodeUrl, error, attemptNo) => {
      finishNearRpcAttempt({
        nodeUrl,
        network: config.networkId,
        role: 'sign_poll',
        opType: 'get_sign_result',
        ok: false,
        startedAt: Date.now(),
        error,
        requestId: params.requestId,
        attemptNo,
      });
      console.warn('[SUBKEY-CONTRACT] get_sign_result failed via RPC', {
        nodeUrl,
        rpcAttempt: attemptNo,
        errorMessage: formatUnknownError(error),
        error,
      });
    },
  });

  if (!raw) return null;
  const payload = (raw as any).payload as string | undefined;
  return {
    request_id: (raw as any).request_id,
    ok: Boolean((raw as any).ok),
    payload,
    error: (raw as any).error || undefined,
    rpcNodeUrl: nodeUrl,
    rpcAttempt: attemptNo,
  } as SignResult;
}

/** NEAR RPC URL from a successful `requestSignV2` / `functionCall` (set in execute callback). */
export function extractSubmitRpcNodeUrl(outcome: unknown): string | undefined {
  if (!outcome || typeof outcome !== 'object') return undefined;
  const url = (outcome as { __rpcNodeUrl?: unknown }).__rpcNodeUrl;
  return typeof url === 'string' && url.trim().length > 0 ? url.trim() : undefined;
}

async function fetchSignResultAtNode(params: {
  networkId: 'mainnet' | 'testnet';
  contractId: string;
  accountId: string;
  requestId: string;
  nodeUrl: string;
  attemptNo: number;
}): Promise<SignResult | null> {
  const startedAt = Date.now();
  const near = await connect({
    networkId: params.networkId,
    nodeUrl: params.nodeUrl,
    deps: { keyStore: new keyStores.InMemoryKeyStore() },
  });
  const account = await near.account(params.accountId);
  const raw = await viewSignResultWithTimeout(
    account,
    params.contractId,
    params.requestId,
    params.nodeUrl,
  );
  finishNearRpcAttempt({
    nodeUrl: params.nodeUrl,
    network: params.networkId,
    role: 'sign_poll',
    opType: 'get_sign_result',
    ok: true,
    startedAt,
    requestId: params.requestId,
    attemptNo: params.attemptNo,
  });
  if (!raw) return null;
  const payload = (raw as { payload?: string }).payload;
  return {
    request_id: (raw as { request_id?: string }).request_id ?? params.requestId,
    ok: Boolean((raw as { ok?: boolean }).ok),
    payload,
    error: (raw as { error?: string }).error || undefined,
    rpcNodeUrl: params.nodeUrl,
    rpcAttempt: params.attemptNo,
  };
}

/** Probe-parity poll: single submit host, continue on pending (mirrors pollSignResult.mjs). */
async function pollSignResultOnSubmitHost(params: {
  networkId: 'mainnet' | 'testnet';
  contractId: string;
  accountId: string;
  requestId: string;
  nodeUrl: string;
  attempts: number;
  delayMs: number;
}): Promise<SignResult | null> {
  let lastError: string | null = null;

  for (let attempt = 0; attempt < params.attempts; attempt += 1) {
    try {
      const value = await fetchSignResultAtNode({
        networkId: params.networkId,
        contractId: params.contractId,
        accountId: params.accountId,
        requestId: params.requestId,
        nodeUrl: params.nodeUrl,
        attemptNo: attempt + 1,
      });

      if (value?.ok && value.payload) {
        return value;
      }

      if (value && value.ok === false && value.error) {
        lastError = value.error;
        const retryable =
          /mpc sign failed/i.test(lastError) && attempt < params.attempts - 1;
        if (!retryable) {
          return value;
        }
      }
    } catch (error) {
      lastError = formatUnknownError(error);
      finishNearRpcAttempt({
        nodeUrl: params.nodeUrl,
        network: params.networkId,
        role: 'sign_poll',
        opType: 'get_sign_result',
        ok: false,
        startedAt: Date.now(),
        error,
        requestId: params.requestId,
        attemptNo: attempt + 1,
      });
    }

    if (attempt < params.attempts - 1) {
      await new Promise(r => setTimeout(r, params.delayMs));
    }
  }

  if (lastError) {
    return {
      request_id: params.requestId,
      ok: false,
      error: lastError,
      rpcNodeUrl: params.nodeUrl,
    };
  }
  return null;
}

async function finalizePollSignResult(
  result: SignResult | null,
  contractId: string,
  requestId: string,
): Promise<SignResult | null> {
  if (result?.ok && result.payload) {
    const { cleanupSignResultsBestEffort } = await import('@/lib/near/signResultCleanup');
    await cleanupSignResultsBestEffort([requestId], contractId);
    return result;
  }
  return result;
}

export async function pollSignResult(params: {
  accountId: string;
  requestId: string;
  contractId?: string;
  attempts?: number;
  delayMs?: number;
  /** Pin poll to the node that accepted `send_tx` before rotating the registry. */
  preferSubmitRpcUrl?: string;
}) {
  const { mpcPollParams } = await import('@/lib/mpc/pollDefaults');
  const defaults = mpcPollParams();
  const attempts = params.attempts ?? defaults.attempts;
  const delayMs = params.delayMs ?? defaults.delayMs;

  const config = getSubkeyConfig(params.contractId);
  const contractId = params.contractId || config.contractId;
  const rpcUrls = await resolvePollRpcUrls(config.networkId);
  if (rpcUrls.length === 0) return null;

  const submitPollUrl = params.preferSubmitRpcUrl?.trim() || null;

  if (submitPollUrl) {
    console.log('[SUBKEY-CONTRACT] pollSignResult submit-host probe loop', {
      requestId: params.requestId,
      preferSubmitRpcUrl: submitPollUrl,
      attempts,
      delayMs,
    });
    const result = await pollSignResultOnSubmitHost({
      networkId: config.networkId,
      contractId,
      accountId: params.accountId,
      requestId: params.requestId,
      nodeUrl: submitPollUrl,
      attempts,
      delayMs,
    });
    return finalizePollSignResult(result, contractId, params.requestId);
  }

  const orderedEndpoints = orderPollEndpoints(rpcUrls, null);
  const stickyBurst = 3;

  const { result, lastError } = await runStickyPollLoop<SignResult>({
    endpoints: orderedEndpoints,
    maxAttempts: attempts,
    delayMs,
    stickyBurst,
    execute: async (nodeUrl, attemptNo) =>
      fetchSignResultAtNode({
        networkId: config.networkId,
        contractId,
        accountId: params.accountId,
        requestId: params.requestId,
        nodeUrl,
        attemptNo,
      }),
    isTerminal: (value, attemptIndex, maxAttempts) =>
      isMpcSignPollTerminal(value, attemptIndex, maxAttempts),
    onExecuteError: (nodeUrl, error, attemptNo) => {
      finishNearRpcAttempt({
        nodeUrl,
        network: config.networkId,
        role: 'sign_poll',
        opType: 'get_sign_result',
        ok: false,
        startedAt: Date.now(),
        error,
        requestId: params.requestId,
        attemptNo,
      });
      const errClass = classifyRpcError(error) ?? 'unknown';
      console.warn('[SUBKEY-CONTRACT] get_sign_result failed (will rotate on hard errors)', {
        nodeUrl,
        errorClass: errClass,
        errorMessage: formatUnknownError(error),
      });
    },
  });

  if (result?.ok && result.payload) {
    return finalizePollSignResult(result, contractId, params.requestId);
  }
  if (lastError) throw lastError;
  return result;
}
