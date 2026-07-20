import { getRpcCandidates, markRpcFailure, markRpcSuccess } from '@/lib/near/rpcFallback';
import { finishNearRpcAttempt } from '@/lib/rpc/nearRpcAttempt';
import { mpcKeyCreateTrace } from '@/lib/near/mpcKeyCreateTrace';
import {
  getStaticNearRpcUrlList,
  prioritizeSigningRpcCandidates,
} from '@/lib/rpc/nearDefaults';
import { resolveSubkeyChainPaths } from '@/lib/near/subkeyChains';

export type ApiKeyInfo = {
  id: string;
  publicId?: string;
  keyAlias?: string;
  publicKey: string;
  metadata: {
    name?: string;
    description?: string;
  };
  createdAt: string;
  lastUsed?: string | null;
  isActive: boolean;
  storageType: string;
  chainType?: string;
  keyNetwork?: string;
  keyStatus?: string;
  nearVaultId?: string;
  nearAccountId?: string;
  subkeyPublicKey?: string;
  policyMetadata?: Record<string, any>;
  custodyBackup?: string;
};

export type SelectedSeed = {
  type: 'main' | 'imported';
  seedNumber: number;
};

export type CreateApiKeyOptions = {
  storageType?: 'client_encrypted' | 'near_vault';
  nearVaultId?: string;
  chainType?: string;
  nearPublicKey?: string;
  keyAlias?: string;
  description?: string;
  policyMetadata?: Record<string, any>;
  accountIndex?: number;
  /** Optional session password - used as fallback if getSessionPasswordForAgent is not available */
  sessionPassword?: string;
  /** Wallet-scoped identity derived client-side: base58(sha256(index-0-public-key)) */
  walletId?: string;
  /** Per-chain scoping: e.g. 'ethereum-mpc', 'base-mpc', 'solana' */
  keyNetwork?: string;
  /** Real-time status callback for UI progress display */
  onStatus?: (msg: string) => void;
  /** External signer key pair ID (references signer_registrations.id) — mutually exclusive with passphrase */
  signerKeyPairId?: string;
};

export type ApiKeyService = {
  fetchKeys: (address: string, network?: string) => Promise<{ count: number; keys: ApiKeyInfo[] }>;
  createKey: (address: string, name?: string, options?: CreateApiKeyOptions, selectedSeed?: SelectedSeed) => Promise<any>;
  deleteKey: (address: string, apiKeyId: string, opts?: { clientNearTxHash?: string }) => Promise<any>;
  revokeSubkeyOnChain: (params: { mnemonic: string; subkeyPublicKey: string }) => Promise<string | undefined>;
};

function resolveSubkeyNetwork(): { contractId: string; networkId: 'mainnet' | 'testnet'; rpcUrl: string } {
  // Check wallet network mode — mainnet wallets must register subkeys on the mainnet contract
  const walletNetwork = typeof window !== 'undefined'
    ? localStorage.getItem('safu-wallet-network') || ''
    : '';
  const isMainnet = walletNetwork.toLowerCase().includes('mainnet');

  if (isMainnet) {
    const contractId = process.env.NEXT_PUBLIC_NEAR_MAINNET_SUBKEY_CONTRACT_ID
      || process.env.NEXT_PUBLIC_NEAR_SUBKEY_MAINNET_CONTRACT_ID
      || process.env.NEAR_SUBKEY_MAINNET_CONTRACT_ID
      || 'contract.saifu-network.near';
    const rpcUrl = process.env.NEXT_PUBLIC_NEAR_MAINNET_RPC_URL
      || process.env.NEAR_MAINNET_RPC_URL
      || 'https://rpc.mainnet.fastnear.com';
    return { contractId, networkId: 'mainnet', rpcUrl };
  }

  const contractId = process.env.NEXT_PUBLIC_NEAR_SUBKEY_CONTRACT_ID || 'saif-near.testnet';
  const networkId: 'mainnet' | 'testnet' = 'testnet';
  const rpcUrl = process.env.NEXT_PUBLIC_NEAR_SUBKEY_RPC_URL || 'https://rpc.testnet.fastnear.com';
  return { contractId, networkId, rpcUrl };
}

function getSubkeyRpcFallbacks(networkId: 'mainnet' | 'testnet'): string[] {
  const staticUrls = getStaticNearRpcUrlList(networkId, 'sign_submit');
  const ranked = getRpcCandidates(staticUrls[0], staticUrls.slice(1));
  return prioritizeSigningRpcCandidates(ranked);
}

type SubkeyOnChainStatusLabels = {
  addSubkey?: string;
  accessKey?: string;
  policy?: string;
};

const DEFAULT_SUBKEY_STATUS: SubkeyOnChainStatusLabels = {
  addSubkey: '1/3 Add subkey to NEAR storage',
  accessKey: '2/3 Add call access key to NEAR account',
  policy: '3/3 Set signing policy on NEAR contract',
};

async function registerSubkeyOnChain(params: {
  mnemonic: string;
  subkeyPublicKey: string;
  chainType: string;
  path: string;
  onStatus?: (msg: string) => void;
  statusLabels?: SubkeyOnChainStatusLabels;
}) {
  const { KeyPair, connect, keyStores } = await import('near-api-js');
  const { deriveNearKeyFromMnemonic } = await import('@/lib/near/keys');
  const bs58 = (await import('bs58')).default;
  const { contractId, networkId } = resolveSubkeyNetwork();
  const rpcUrls = getSubkeyRpcFallbacks(networkId);
  // NEAR owner account is rooted at index 0 for all MPC API keys.
  // Derivation path selects per-account Solana/EVM/BTC signer identity.
  const nearKey = deriveNearKeyFromMnemonic(params.mnemonic, 0);
  const accountId = nearKey.publicKeyHex;
  const keyStore = new keyStores.InMemoryKeyStore();
  const masterKeyPair = KeyPair.fromString(`ed25519:${bs58.encode(nearKey.secretKey)}`);
  await keyStore.setKey(networkId, accountId, masterKeyPair);
  const derivationPaths = resolveSubkeyChainPaths(params.chainType, params.path);
  const chain = derivationPaths[0]?.chain || 'Solana';
  console.log('[API-KEY] Registering subkey on-chain', {
    accountId,
    contractId,
    chain,
    path: params.path,
    rpcUrls
  });
  mpcKeyCreateTrace.mark('client_add_subkey_start', { contractId, chain, path: params.path, rpcCount: rpcUrls.length });
  const status = params.onStatus || (() => {});
  const labels = { ...DEFAULT_SUBKEY_STATUS, ...params.statusLabels };

  // Sequential RPC failover — avoids browser connection exhaustion from parallel races.
  status(labels.addSubkey!);

  const tryAddSubkey = async (url: string) => {
    const startedAt = Date.now();
    const rpcHost = new URL(url).hostname;
    mpcKeyCreateTrace.mark('client_add_subkey_rpc_attempt', { rpcHost });
    const near = await connect({ networkId, nodeUrl: url, deps: { keyStore } });
    const account = await near.account(accountId);
    mpcKeyCreateTrace.mark('client_add_subkey_function_call_start', { rpcHost });
    const outcome = await account.functionCall({
      contractId,
      methodName: 'add_subkey',
      args: {
        public_key: params.subkeyPublicKey,
        derivation_paths: derivationPaths,
      },
      gas: BigInt('200000000000000'),
      attachedDeposit: BigInt('0')
    });
    const txHash = (outcome as any)?.transaction?.hash || (outcome as any)?.transaction_outcome?.id || undefined;
    mpcKeyCreateTrace.mark('client_add_subkey_function_call_done', {
      rpcHost,
      ms: Date.now() - startedAt,
      txHash: txHash || null,
    });
    finishNearRpcAttempt({
      nodeUrl: url,
      network: networkId,
      role: 'general',
      opType: 'add_subkey',
      ok: true,
      startedAt,
      txId: txHash,
    });
    markRpcSuccess(url);
    return { rpcHost, account, txHash };
  };

  const perNodeErrors: string[] = [];
  let registrationResult: { rpcHost: string; account: any; txHash?: string } | null = null;

  for (const url of rpcUrls) {
    const startedAt = Date.now();
    try {
      registrationResult = await tryAddSubkey(url);
      mpcKeyCreateTrace.mark('client_add_subkey_rpc_ok', { rpcHost: new URL(url).hostname });
      break;
    } catch (error) {
      markRpcFailure(url, error);
      finishNearRpcAttempt({
        nodeUrl: url,
        network: networkId,
        role: 'general',
        opType: 'add_subkey',
        ok: false,
        startedAt,
        error,
      });
      const msg = error instanceof Error ? error.message : String(error);
      perNodeErrors.push(`${new URL(url).hostname}: ${msg.slice(0, 120)}`);
    }
  }

  try {
    if (!registrationResult) {
      throw new Error(`add_subkey failed on RPC fallbacks: ${perNodeErrors.join(' || ')}`);
    }
    const { rpcHost, account, txHash: registrationTxHash } = registrationResult;
    if (registrationTxHash) {
      console.log('[API-KEY] Subkey registration tx hash:', registrationTxHash);
    }
    status(labels.accessKey!);
    // addKey on the winning RPC (non-critical — doesn't block if it fails)
    try {
      const accessKeyStarted = Date.now();
      mpcKeyCreateTrace.mark('client_access_key_start', { rpcHost });
      const accessKeyAllowance = '5000000000000000000000000'; // 5 NEAR for contract calls
      await account.addKey(
        params.subkeyPublicKey,
        contractId,
        ['request_sign_v2', 'request_sign', 'request_template_sign_v2', 'request_template_sign'],
        BigInt(accessKeyAllowance)
      );
      mpcKeyCreateTrace.mark('client_access_key_done', { rpcHost, ms: Date.now() - accessKeyStarted });
      console.log('[API-KEY] Added function-call access key for subkey', {
        accountId, contractId, rpcHost,
        methods: ['request_sign_v2', 'request_sign', 'request_template_sign_v2', 'request_template_sign']
      });
    } catch (error) {
      mpcKeyCreateTrace.mark('client_access_key_failed', {
        rpcHost,
        message: (error instanceof Error ? error.message : String(error)).slice(0, 200),
      });
      console.warn('[API-KEY] Failed to add function-call access key for subkey', error);
    }
    // Set a permissive NEAR contract policy so request_sign_v2 doesn't fail
    // with policy_not_enabled. Without this the NEAR contract rejects all
    // signing requests for the subkey.
    status(labels.policy!);
    try {
      const policyStarted = Date.now();
      mpcKeyCreateTrace.mark('client_policy_set_start', { rpcHost });
      // Bootstrap on-chain policy so request_sign_v2 is not rejected with
      // policy_not_enabled. Empty allowDestinations keeps this permissive;
      // Near contract also allows NEP-141 Path C under native bootstrap policies.
      const chainLower = String(chain || '').toLowerCase();
      const bootstrapPolicy = chainLower.includes('near')
        ? {
            version: '1',
            templateId: 'near_native_transfer_v1',
            assetType: 'native',
            assetId: null,
            // 100 NEAR in yocto — effectively unlimited for Path C gas/native sends
            maxPerTxNative: '100000000000000000000000000',
            maxPerPeriodNative: null,
            periodSeconds: null,
            maxTxCountPerPeriod: null,
            allowDestinations: [],
            periodStartUnixSeconds: null,
            spentThisPeriodNative: null,
            txCountThisPeriod: null,
          }
        : {
            version: '1',
            templateId: 'sol_native_transfer_v1',
            assetType: 'native',
            assetId: null,
            maxPerTxNative: '100000000000', // 100 SOL — effectively unlimited
            maxPerPeriodNative: null,
            periodSeconds: null,
            maxTxCountPerPeriod: null,
            allowDestinations: [],
            periodStartUnixSeconds: null,
            spentThisPeriodNative: null,
            txCountThisPeriod: null,
          };
      await account.functionCall({
        contractId,
        methodName: 'owner_set_signer_policy',
        args: {
          public_key: params.subkeyPublicKey,
          policy: bootstrapPolicy,
        },
        gas: BigInt('50000000000000'),
        attachedDeposit: BigInt('0'),
      });
      mpcKeyCreateTrace.mark('client_policy_set_done', { rpcHost, ms: Date.now() - policyStarted });
      console.log('[API-KEY] Set NEAR signing policy for subkey', { accountId, contractId });
    } catch (policyErr) {
      const msg = policyErr instanceof Error ? policyErr.message : String(policyErr);
      mpcKeyCreateTrace.mark('client_policy_set_failed', { rpcHost, message: msg.slice(0, 200) });
      console.warn('[API-KEY] Failed to set signing policy for subkey (non-fatal):', msg.slice(0, 200));
    }
    mpcKeyCreateTrace.mark('client_add_subkey_done', { rpcHost, txHash: registrationTxHash || null });
    return registrationTxHash;
  } catch (aggregateError) {
    const message = aggregateError instanceof Error ? aggregateError.message : String(aggregateError);
    mpcKeyCreateTrace.mark('client_add_subkey_failed', { message: message.slice(0, 300) });
    console.warn('[API-KEY] Subkey registration failed', message);
    throw new Error(message || 'Failed to register subkey on chain');
  }
}

export function createApiKeyService(apiBase = '/api'): ApiKeyService {
  const fetchJson = async <T>(path: string, init?: RequestInit): Promise<T> => {
    // Attach wallet auth token if available
    const headers = new Headers(init?.headers);
    if (typeof window !== 'undefined') {
      const token = localStorage.getItem('safu_access_token');
      if (token && !headers.has('Authorization')) {
        headers.set('Authorization', `Bearer ${token}`);
      }
    }
    const res = await fetch(`${apiBase}${path}`, { ...init, headers, credentials: 'same-origin' });
    if (!res.ok) {
      const detail = await res.json().catch(() => ({}));
      const message = detail?.error || res.statusText || 'Request failed';
      console.error('[API-KEY] Request failed', {
        path,
        status: res.status,
        error: message,
        failureCode: detail?.failureCode,
        details: detail?.details,
      });
      const err = new Error(message) as Error & { details?: string; failureCode?: string; status?: number; hint?: string };
      if (detail?.details) err.details = String(detail.details);
      if (detail?.failureCode) err.failureCode = String(detail.failureCode);
      if (detail?.hint) err.hint = String(detail.hint);
      err.status = res.status;
      throw err;
    }
    return res.json() as Promise<T>;
  };

  const normalizeKeys = (data: any): { count: number; keys: ApiKeyInfo[] } => {
    const keys: ApiKeyInfo[] = (data?.keys || []).map((key: any) => ({
      id: key.id,
      publicId: key.publicId,
      keyAlias: key.keyAlias,
      publicKey: key.publicKey,
      metadata: key.metadata || {},
      createdAt: key.createdAt,
      lastUsed: key.lastUsed ?? null,
      isActive: key.isActive,
      storageType: key.storageType,
      chainType: key.chainType,
      keyStatus: key.keyStatus,
      nearVaultId: key.nearVaultId,
      nearAccountId: key.nearAccountId,
      policyMetadata: key.policyMetadata,
      custodyBackup: key.custodyBackup,
      keyNetwork: key.keyNetwork
    }));
    return { count: data?.count || keys.length, keys };
  };

  return {
    fetchKeys: async (address: string, network?: string) => {
      try {
        const url = network
          ? `/wallet/addresses/${address}/api-keys?network=${encodeURIComponent(network)}`
          : `/wallet/addresses/${address}/api-keys`;
        const data = await fetchJson(url);
        // console.timeEnd(`[ApiKeyService] fetchKeys:${address.slice(0,8)}`);
        return normalizeKeys(data);
      } catch (error) {
        // Soft-fail on network/resource errors to avoid noisy overlays
        if (error instanceof TypeError) {
          return { count: 0, keys: [] };
        }
        throw error;
      }
    },

    createKey: async (address: string, name = 'Default Key', options?: CreateApiKeyOptions, selectedSeed?: SelectedSeed) => {
      const requestData: Record<string, any> = { name };
      if (options?.keyAlias) {
        requestData.keyAlias = options.keyAlias;
      }
      if (options?.walletId) {
        requestData.walletId = options.walletId;
      }
      if (options?.keyNetwork) {
        requestData.keyNetwork = options.keyNetwork;
      }
      if (options?.signerKeyPairId) {
        requestData.signerKeyPairId = options.signerKeyPairId;
      }

      // Detect MPC addresses - they are Solana addresses derived via NEAR Chain Signatures
      // These addresses cannot have local private keys derived
      // Check multiple signals: explicit storageType, nearVaultId, or chainType + mpc context
      const isExplicitMpc = options?.storageType === 'near_vault';
      const hasMpcContext = options?.nearVaultId !== undefined || options?.nearPublicKey !== undefined;
      const isMpcAddress = isExplicitMpc || hasMpcContext;

      // Remote signer path: external daemon holds the ed25519 seed (ECDH-wrapped server-side)
      // Skip vault encryption steps — server generates the ed25519 seed and wraps it for the daemon
      if (options?.signerKeyPairId) {
        const status = options?.onStatus || (() => {});
        console.log('[API-KEY] Creating remote_signer API key for address:', address.slice(0, 12) + '...');
        const { contractId } = resolveSubkeyNetwork();
        requestData.storageType = 'remote_signer';
        requestData.nearContractId = contractId;
        requestData.chainType = options?.chainType || 'solana';
        requestData.nearVaultId = options?.nearVaultId || String(options?.accountIndex ?? 0);
        if (options?.description) requestData.description = options.description;
        if (options?.policyMetadata) requestData.policyMetadata = options.policyMetadata;

        // Load mnemonic upfront — needed for nearPublicKey (policy scope) and post-creation subkey registration.
        let remoteSignerMnemonic = '';
        let sessionPassword: string | undefined;
        const sessionPasswordPromise = (window as any).getSessionPasswordForAgent?.();
        if (sessionPasswordPromise) sessionPassword = await sessionPasswordPromise;
        if (!sessionPassword && options?.sessionPassword) sessionPassword = options.sessionPassword;

        if (sessionPassword) {
          try {
            const { getEncryptedSessionManager } = await import('@/lib/crypto/encryptedSessionManager');
            const { deriveNearKeyFromMnemonic } = await import('@/lib/near/keys');
            const bs58 = (await import('bs58')).default;
            const encryptedSessionManager = getEncryptedSessionManager();
            const seedNumber = selectedSeed?.seedNumber ?? 0;
            if (encryptedSessionManager.hasUnifiedStorage()) {
              remoteSignerMnemonic = await encryptedSessionManager.loadUnifiedSeed(seedNumber, sessionPassword) || '';
            } else if (selectedSeed && selectedSeed.type === 'imported') {
              remoteSignerMnemonic = await encryptedSessionManager.loadImportedSeed(seedNumber, sessionPassword) || '';
            } else {
              const walletData = await encryptedSessionManager.loadWalletData(sessionPassword);
              remoteSignerMnemonic = walletData?.mnemonic || '';
            }
            if (remoteSignerMnemonic) {
              const nearKey = deriveNearKeyFromMnemonic(remoteSignerMnemonic, 0);
              requestData.nearPublicKey = nearKey.publicKey;
              console.log('[API-KEY] remote_signer: including nearPublicKey for policy scope');
            }
          } catch (err) {
            console.warn('[API-KEY] remote_signer: could not load mnemonic for nearPublicKey', err);
          }
        }

        status('1/3 Creating remote signer key');
        mpcKeyCreateTrace.mark('remote_signer_post_start', { address: address.slice(0, 12) });
        const remotePostStarted = Date.now();
        const response = await fetchJson(`/wallet/addresses/${address}/api-keys`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(requestData),
        });
        mpcKeyCreateTrace.mark('remote_signer_post_done', { ms: Date.now() - remotePostStarted });

        // Register the server-generated subkey on the NEAR contract using owner mnemonic
        const subkeyPublicKey = (response as any)?.subkeyPublicKey;
        if (subkeyPublicKey && remoteSignerMnemonic) {
          try {
            await registerSubkeyOnChain({
              mnemonic: remoteSignerMnemonic,
              subkeyPublicKey,
              chainType: requestData.chainType || 'solana',
              path: String(requestData.nearVaultId || '0'),
              onStatus: status,
              statusLabels: {
                addSubkey: '2/3 Add subkey to NEAR storage',
                accessKey: '2/3 Add call access key to NEAR account',
                policy: '3/3 Set signing policy on NEAR contract',
              },
            });
          } catch (err) {
            console.warn('[API-KEY] remote_signer: on-chain subkey registration failed (server will retry):', err);
          }
        } else if (subkeyPublicKey) {
          console.warn('[API-KEY] remote_signer: mnemonic unavailable, skipping on-chain subkey registration');
        }

        return response;
      }

      // For near_vault storage (self-custodial MPC), we need to encrypt the mnemonic
      if (isMpcAddress) {
        const status = options?.onStatus || (() => {});
        console.log('[API-KEY] Creating MPC API key for address:', address.slice(0, 12) + '...');
        const { contractId, networkId } = resolveSubkeyNetwork();
        requestData.storageType = 'near_vault';
        requestData.nearVaultId = options?.nearVaultId || String(options?.accountIndex ?? 0);
        requestData.nearContractId = contractId;
        requestData.chainType = options?.chainType || 'solana';
        requestData.mnemonicAccountIndex = options?.accountIndex ?? 0;
        if (options?.description) requestData.description = options.description;
        if (options?.policyMetadata) requestData.policyMetadata = options.policyMetadata;

        // Get session password (0/3 policy manager runs in ApiKeyControls before this)
        let sessionPassword: string | undefined;
        const sessionPasswordPromise = (window as any).getSessionPasswordForAgent?.();
        if (sessionPasswordPromise) {
          sessionPassword = await sessionPasswordPromise;
        }
        if (!sessionPassword && options?.sessionPassword) {
          sessionPassword = options.sessionPassword;
        }

        if (!sessionPassword) {
          throw new Error('Cannot create MPC API key: Session password required. Please ensure wallet is unlocked.');
        }

        // Load mnemonic and derive NEAR key
        const { getEncryptedSessionManager } = await import('@/lib/crypto/encryptedSessionManager');
        const { deriveNearKeyFromMnemonic } = await import('@/lib/near/keys');
        const bs58 = (await import('bs58')).default;
        const { getWalletManager } = await import('@/lib/wasm/managers/walletManager');

        const encryptedSessionManager = getEncryptedSessionManager();
        const seedNumber = selectedSeed?.seedNumber ?? 0;
        let mnemonic = '';

        if (encryptedSessionManager.hasUnifiedStorage()) {
          mnemonic = await encryptedSessionManager.loadUnifiedSeed(seedNumber, sessionPassword) || '';
        } else if (selectedSeed && selectedSeed.type === 'imported') {
          mnemonic = await encryptedSessionManager.loadImportedSeed(seedNumber, sessionPassword) || '';
        } else {
          const walletData = await encryptedSessionManager.loadWalletData(sessionPassword);
          mnemonic = walletData?.mnemonic || '';
        }

        if (!mnemonic) {
          throw new Error('Cannot create MPC API key: Unable to load mnemonic. Please unlock wallet and try again.');
        }

        // Derive NEAR key
        const nearKey = deriveNearKeyFromMnemonic(mnemonic, 0);
        console.log('[API-KEY] Derived NEAR key for MPC:', nearKey.publicKey.slice(0, 16) + '...');
        requestData.nearPublicKey = nearKey.publicKey;

        const { KeyPair } = await import('near-api-js');
        const walletManager = getWalletManager();
        await walletManager.initialize();
        const subkeyPair = KeyPair.fromRandom('ed25519');
        requestData.subkeyPublicKey = subkeyPair.getPublicKey().toString();
        const { getServerSigningPublicKeyPem } = await import('@/lib/wallet/serverSigningPubkey');
        const serverPubKeyPem = await getServerSigningPublicKeyPem();

        const nearMasterPrivateKey = `ed25519:${bs58.encode(nearKey.secretKey)}`;
        const { server_ciphertext: serverMasterCiphertext } = await walletManager.encryptWithServerPublicKey(
          nearMasterPrivateKey,
          serverPubKeyPem
        );
        requestData.serverEncryptedPrivateKey = serverMasterCiphertext;
        requestData.serverKeyParams = JSON.stringify({ alg: 'rsa-oaep-sha256' });

        const { server_ciphertext } = await walletManager.encryptWithServerPublicKey(
          subkeyPair.toString(),
          serverPubKeyPem
        );
        requestData.subkeyPrivateKey = server_ciphertext;
        requestData.subkeyKeyEncrypted = true;

        let clientSubkeyRegistered = false;
        let clientNearTxHash: string | undefined;
        try {
          clientNearTxHash = await registerSubkeyOnChain({
            mnemonic,
            subkeyPublicKey: requestData.subkeyPublicKey,
            chainType: requestData.chainType || 'solana',
            path: String(requestData.nearVaultId || '0'),
            onStatus: status
          });
          clientSubkeyRegistered = true;
          // Warm owner key for Activity approve + async wallet MPC (browser cache + server memory).
          try {
            const { ensureOwnerKeyRegistered } = await import('@/lib/wallet/ownerKeyRegistration');
            await ensureOwnerKeyRegistered({ mnemonic, indices: [0, 1, 2] });
          } catch (ownerWarmErr) {
            console.warn('[API-KEY] Owner key warm after subkey reg failed (non-fatal):', ownerWarmErr);
          }
        } catch (error) {
          console.warn('[API-KEY] Client subkey registration failed; server will retry', error);
          status('1/3 Add subkey failed — server will retry');
        }
        requestData.subkeyRegisteredOnChain = clientSubkeyRegistered;
        if (clientNearTxHash) {
          requestData.clientNearTxHash = clientNearTxHash;
        }

        // MPC path is complete - send request now (on-chain steps already reported 1/3–3/3)
        status('Saving API key…');
        mpcKeyCreateTrace.mark('near_vault_post_start');
        const vaultPostStarted = Date.now();
        console.log('[API-KEY] Sending MPC API key creation request...');
        const postResult = await fetchJson(`/wallet/addresses/${address}/api-keys`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(requestData),
        });
        mpcKeyCreateTrace.mark('near_vault_post_done', { ms: Date.now() - vaultPostStarted });
        return postResult;
      } else {
        // Client-encrypted path: derive and encrypt private key
        // Try getSessionPasswordForAgent first, then fallback to options.sessionPassword
        let sessionPassword: string | undefined;
        
        const sessionPasswordPromise = (window as any).getSessionPasswordForAgent?.();
        if (sessionPasswordPromise) {
          // getSessionPasswordForAgent is async - must await it
          sessionPassword = await sessionPasswordPromise;
        }
        
        // Fallback to options.sessionPassword (for /accounts/ page which uses useWalletManager)
        if (!sessionPassword && options?.sessionPassword) {
          sessionPassword = options.sessionPassword;
        }
        
        if (!sessionPassword) {
          throw new Error('Session password not available. Please ensure wallet is unlocked.');
        }

        const { deriveAndEncryptPrivateKey } = await import('@/lib/agent/secureKeyDerivation');
        const { getEncryptedSessionManager } = await import('@/lib/crypto/encryptedSessionManager');
        const { getWalletManager } = await import('@/lib/wasm/managers/walletManager');

        const encryptedSessionManager = getEncryptedSessionManager();
        const walletManager = getWalletManager();
        await walletManager.initialize();

        const seedNumber = selectedSeed?.seedNumber ?? 0;
        const encryptedData =
          selectedSeed?.type === 'imported'
            ? await walletManager.getEncryptedImportedSeedData(seedNumber)
            : await walletManager.getEncryptedMnemonicData();

        if (!encryptedData) {
          throw new Error('Could not access encrypted seed data for API key creation');
        }

        const accountIndex = options?.accountIndex ?? 0;
        const { getServerSigningPublicKeyPem } = await import('@/lib/wallet/serverSigningPubkey');
        const serverPubKeyPem = await getServerSigningPublicKeyPem();

        let keyDerivationResult: any;
        try {
          keyDerivationResult = await walletManager.exportServerEncryptedPrivateKey(
            encryptedData,
            sessionPassword,
            accountIndex,
            serverPubKeyPem
          );
          keyDerivationResult.success = true;
          console.log(`[API-KEY] Server encryption succeeded for account index ${accountIndex}`);
        } catch (serverError) {
          console.warn(`[API-KEY] Server encryption failed for account index ${accountIndex}, falling back to client derivation:`, serverError);
          // Fallback to client-only path
          let seedPhrase = '';
          if (encryptedSessionManager.hasUnifiedStorage()) {
            seedPhrase = await encryptedSessionManager.loadUnifiedSeed(seedNumber, sessionPassword) || '';
          } else if (selectedSeed && selectedSeed.type === 'imported') {
            seedPhrase = await encryptedSessionManager.loadImportedSeed(seedNumber, sessionPassword) || '';
          } else {
            const walletData = await encryptedSessionManager.loadWalletData(sessionPassword);
            seedPhrase = walletData?.mnemonic || '';
          }
          if (!seedPhrase) {
            throw new Error('Could not decrypt seed phrase for API key creation');
          }
          keyDerivationResult = await deriveAndEncryptPrivateKey(seedPhrase, address, sessionPassword);
          console.log(`[API-KEY] Client fallback succeeded for account index ${accountIndex}`);
        }

        if (!keyDerivationResult.success) {
          throw new Error(`Private key derivation failed: ${keyDerivationResult.error}`);
        }

        requestData.encryptedPrivateKey = (keyDerivationResult as any).encryptedPrivateKey || (keyDerivationResult as any).clientEncryptedPrivateKey;
        if ((keyDerivationResult as any).serverEncryptedPrivateKey) {
          requestData.serverEncryptedPrivateKey = (keyDerivationResult as any).serverEncryptedPrivateKey;
          requestData.serverKeyParams = (keyDerivationResult as any).serverKeyParams;
        }
      }

      return fetchJson(`/wallet/addresses/${address}/api-keys`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(requestData),
      });
    },

    deleteKey: async (address: string, apiKeyId: string, opts?: { clientNearTxHash?: string; walletId?: string }) => {
      return fetchJson(`/wallet/addresses/${address}/api-keys/`, {
        method: 'DELETE',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ apiKeyId, clientNearTxHash: opts?.clientNearTxHash, walletId: opts?.walletId }),
      });
    },

    revokeSubkeyOnChain: async (params: {
      mnemonic: string;
      subkeyPublicKey: string;
    }): Promise<string | undefined> => {
      const { KeyPair, connect, keyStores } = await import('near-api-js');
      const { deriveNearKeyFromMnemonic } = await import('@/lib/near/keys');
      const bs58 = (await import('bs58')).default;
      const { contractId, networkId, rpcUrl } = resolveSubkeyNetwork();
      const rpcUrls = getSubkeyRpcFallbacks(rpcUrl, networkId);
      const nearKey = deriveNearKeyFromMnemonic(params.mnemonic, 0);
      const accountId = nearKey.publicKeyHex;
      const keyStore = new keyStores.InMemoryKeyStore();
      const masterKeyPair = KeyPair.fromString(`ed25519:${bs58.encode(nearKey.secretKey)}`);
      await keyStore.setKey(networkId, accountId, masterKeyPair);
      const normalizedSubkey = params.subkeyPublicKey.startsWith('ed25519:')
        ? params.subkeyPublicKey : `ed25519:${params.subkeyPublicKey}`;

      const raceRemove = async (url: string) => {
        const near = await connect({ networkId, nodeUrl: url, deps: { keyStore } });
        const account = await near.account(accountId);
        const outcome = await account.functionCall({
          contractId,
          methodName: 'remove_subkey',
          args: { public_key: normalizedSubkey },
          gas: BigInt('200000000000000'),
          attachedDeposit: BigInt('0')
        });
        const txHash = (outcome as any)?.transaction?.hash || (outcome as any)?.transaction_outcome?.id;
        return txHash;
      };

      try {
        const txHash = await Promise.any(rpcUrls.map(url => raceRemove(url)));
        console.log('[API-KEY] Client-side subkey revocation tx:', txHash);
        try {
          const { actionCreators } = await import('@near-js/transactions');
          const { PublicKey } = await import('@near-js/crypto');
          const near = await connect({
            networkId,
            nodeUrl: rpcUrls[0],
            deps: { keyStore },
          });
          const account = await near.account(accountId);
          await account.signAndSendTransaction({
            receiverId: accountId,
            actions: [actionCreators.deleteKey(PublicKey.fromString(normalizedSubkey))],
          });
          console.log('[API-KEY] Deleted orphaned NEAR access key for subkey');
        } catch (deleteErr) {
          const msg = deleteErr instanceof Error ? deleteErr.message : String(deleteErr);
          console.warn('[API-KEY] deleteKey after remove_subkey failed (non-fatal):', msg.slice(0, 200));
        }
        return txHash;
      } catch (err) {
        console.warn('[API-KEY] Client-side subkey revocation failed:', err);
        return undefined;
      }
    }
  };
}
