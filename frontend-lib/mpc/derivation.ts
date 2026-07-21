
// @ts-ignore – crypto-js sub-path imports lack type declarations
import SHA3 from 'crypto-js/sha3';
// @ts-ignore
import SHA256 from 'crypto-js/sha256';
// @ts-ignore
import RIPEMD160 from 'crypto-js/ripemd160';
// @ts-ignore
import Hex from 'crypto-js/enc-hex';
import bs58 from 'bs58';
import { bech32 } from 'bech32';
import { deriveNearKeyFromMnemonic } from '@/lib/near/keys';

const DEFAULT_TESTNET_MPC_CONTRACT_ID = 'v1.signer-prod.testnet';
const DEFAULT_MAINNET_MPC_CONTRACT_ID = 'v1.signer';
const DEFAULT_TESTNET_SUBKEY_CONTRACT_ID = 'saif-near.testnet';
const TESTNET_RPC = 'https://near-testnet.drpc.org';
const TESTNET_RPC_FALLBACKS = [
    'https://near-testnet.drpc.org',
    'https://testnet-rpc.intea.rs'
];
const MAINNET_RPC = 'https://near.lava.build';
const MAINNET_RPC_FALLBACKS = [
    'https://near.lava.build',
    'https://rpc.mainnet.fastnear.com',
];

const DEFAULT_MAINNET_SUBKEY_CONTRACT_ID = 'contract.saifu-network.near';

function getMpcNetworkParams(networkOverride?: string): { mpcContractId: string; subkeyContractId: string; networkId: 'mainnet' | 'testnet'; rpcUrls: string[] } {
    // If the caller explicitly requests mainnet, use mainnet contracts regardless of env vars
    const forceMainnet = networkOverride ? networkOverride.toLowerCase().includes('mainnet') : false;

    const subkeyContract = forceMainnet
        ? (process.env.NEXT_PUBLIC_NEAR_MAINNET_SUBKEY_CONTRACT_ID ||
           DEFAULT_MAINNET_SUBKEY_CONTRACT_ID)
        : (process.env.NEXT_PUBLIC_NEAR_SUBKEY_CONTRACT_ID ||
           process.env.NEAR_SUBKEY_CONTRACT_ID ||
           DEFAULT_TESTNET_SUBKEY_CONTRACT_ID);

    const isMainnet = subkeyContract.endsWith('.near') && !subkeyContract.endsWith('.testnet');
    const mpcContractId = forceMainnet
        ? (process.env.NEXT_PUBLIC_NEAR_MAINNET_CHAIN_SIG_CONTRACT_ID ||
           DEFAULT_MAINNET_MPC_CONTRACT_ID)
        : (process.env.NEXT_PUBLIC_NEAR_CHAIN_SIG_CONTRACT_ID ||
           (isMainnet ? DEFAULT_MAINNET_MPC_CONTRACT_ID : DEFAULT_TESTNET_MPC_CONTRACT_ID));
    const networkId: 'mainnet' | 'testnet' = isMainnet ? 'mainnet' : 'testnet';
    const rpcOverride = process.env.NEXT_PUBLIC_NEAR_RPC_URL || process.env.NEAR_RPC_URL;
    const defaultRpcs = isMainnet ? MAINNET_RPC_FALLBACKS : [TESTNET_RPC, ...TESTNET_RPC_FALLBACKS];
    const rpcUrls = rpcOverride ? Array.from(new Set([rpcOverride, ...defaultRpcs])) : defaultRpcs;
    return { mpcContractId, subkeyContractId: subkeyContract, networkId, rpcUrls };
}

let cachedRootKey: string | null = null;
let cachedContractKey: string | null = null;
let cachedContract: any = null;
let chainsigModule: { contracts: any } | null = null;

async function getChainSig() {
    if (typeof window === 'undefined') {
        throw new Error('chainsig.js can only be used in browser environment');
    }
    if (!chainsigModule) {
        chainsigModule = await import('chainsig.js');
    }
    return chainsigModule;
}

export type MpcChainType = 'solana' | 'ethereum' | 'bitcoin' | 'near';

export async function deriveMpcAddress(
    mnemonic: string,
    index: number,
    chain: MpcChainType,
    accountIndex: number = 0,
    networkOverride?: string
): Promise<string> {
    const nearKey = deriveNearKeyFromMnemonic(mnemonic, accountIndex);
    const implicitAccountId = nearKey.publicKeyHex;

    const path = String(index);
    const { mpcContractId, subkeyContractId, networkId, rpcUrls } = getMpcNetworkParams(networkOverride);
    console.log(`[MPC-DERIVE] chain=${chain} idx=${index} networkOverride=${networkOverride} → contract=${subkeyContractId} mpc=${mpcContractId} networkId=${networkId}`);
    const scopedPath = `${implicitAccountId}:${path}`;

    const contractCacheKey = `${mpcContractId}:${networkId}`;
    if (!cachedContract || cachedContractKey !== contractCacheKey) {
        const { contracts } = await getChainSig();
        cachedContract = new contracts.ChainSignatureContract({
            contractId: mpcContractId,
            networkId,
            fallbackRpcUrls: rpcUrls
        });
        cachedContractKey = contractCacheKey;
    }
    const contract = cachedContract;

    const isEd25519 = chain === 'solana' || chain === 'near';
    const cacheKey = `${chain}:${scopedPath}:${subkeyContractId}`;

    try {
        if ((global as any).__MPC_KEY_CACHE?.[cacheKey]) {
            return (global as any).__MPC_KEY_CACHE[cacheKey];
        }

        console.time(`[MPC] getDerivedPublicKey:${chain}:${path}`);
        console.log('[MPC Debug] Deriving for:', {
            path: scopedPath,
            predecessor: subkeyContractId,
            caller: implicitAccountId,
            isEd25519,
            contract: mpcContractId,
            networkId
        });

        const derivedKey = await contract.getDerivedPublicKey({
            path: scopedPath,
            predecessor: subkeyContractId,
            IsEd25519: isEd25519
        });
        console.timeEnd(`[MPC] getDerivedPublicKey:${chain}:${path}`);

        if (!(global as any).__MPC_KEY_CACHE) (global as any).__MPC_KEY_CACHE = {};

        let result = derivedKey as string;
        if (chain === 'solana') {
            result = formatSolanaAddress(derivedKey);
        } else if (chain === 'near') {
            result = formatNearMpcAddress(derivedKey);
        } else if (chain === 'ethereum') {
            result = formatEthAddress(derivedKey);
        } else if (chain === 'bitcoin') {
            result = await formatBitcoinAddressAsync(derivedKey, networkId === 'testnet');
        }

        if (!result || result === 'Error') {
            throw new Error('Derived address formatting failed');
        }

        (global as any).__MPC_KEY_CACHE[cacheKey] = result;
        return result;

    } catch (error) {
        console.error(`[MPC Derivation] Failed for ${path}:`, error);
        return '';
    }
}

function formatSolanaAddress(key: string | Uint8Array | any): string {
    // Use normalizePublicKeyBytes which handles ed25519:<base58>, secp256k1:<base58>,
    // 0x-prefixed hex, bare hex, Uint8Array, and {data:[...]} objects correctly.
    let raw = normalizePublicKeyBytes(key);
    if (!raw) return 'Error';
    if (raw.length > 0 && raw[0] === 0x04) {
        raw = raw.subarray(1);
    }
    if (raw.length > 32) {
        raw = raw.subarray(0, 32);
    }
    return bs58.encode(raw);
}

/** NEAR implicit account id: lowercase hex of 32-byte Ed25519 public key. */
export function formatNearMpcAddress(key: string | Uint8Array | any): string {
    let raw = normalizePublicKeyBytes(key);
    if (!raw) return 'Error';
    // Chainsig sometimes returns 33 bytes with a leading 0x04; a real Ed25519
    // pubkey is 32 bytes and may legitimately start with 0x04 — never strip then.
    if (raw.length === 33 && raw[0] === 0x04) {
        raw = raw.subarray(1);
    } else if (raw.length > 32) {
        raw = raw.subarray(0, 32);
    }
    if (raw.length !== 32) return 'Error';
    return Buffer.from(raw).toString('hex').toLowerCase();
}

function formatEthAddress(key: string | Uint8Array | any): string {
    let raw = normalizePublicKeyBytes(key);
    if (!raw) return 'Error';
    if (raw.length === 65 && raw[0] === 0x04) {
        raw = raw.subarray(1);
    }
    if (raw.length !== 64) {
        console.warn('[formatEthAddress] Unexpected key length', raw.length);
    }
    // Must parse hex as binary WordArray — passing a plain string to SHA3 hashes
    // the ASCII bytes of the string, not the actual public-key bytes.
    const hexStr = Buffer.from(raw).toString('hex');
    const hashHex = SHA3(Hex.parse(hexStr), { outputLength: 256 }).toString(Hex);
    return `0x${hashHex.slice(-40)}`;
}

// P2WPKH bech32 address (bc1q... / tb1q...).
// NEAR MPC returns secp256k1 keys as 64 raw bytes (x‖y without 0x04 prefix),
// 65 bytes (uncompressed), or 33 bytes (compressed). All cases handled.
async function formatBitcoinAddressAsync(key: string | Uint8Array | any, testnet = false): Promise<string> {
    let raw = normalizePublicKeyBytes(key);
    if (!raw) return 'Error';

    // Compress the key to 33 bytes if needed
    let compressed: Uint8Array;
    if (raw.length === 33) {
        compressed = raw;
    } else {
        try {
            const { secp256k1 } = await import('@noble/curves/secp256k1');
            let point;
            if (raw.length === 64) {
                // NEAR format: raw x‖y — prepend 0x04 to form uncompressed key
                const uncompressed = new Uint8Array(65);
                uncompressed[0] = 0x04;
                uncompressed.set(raw, 1);
                point = secp256k1.ProjectivePoint.fromHex(uncompressed);
            } else {
                point = secp256k1.ProjectivePoint.fromHex(raw);
            }
            compressed = point.toRawBytes(true); // 33-byte compressed
        } catch (e) {
            console.warn('[formatBitcoinAddress] compression failed:', e);
            return 'Error';
        }
    }

    // HASH160: RIPEMD160(SHA256(compressed_pubkey))
    const pubKeyHex = Buffer.from(compressed).toString('hex');
    const sha256WordArray = SHA256(Hex.parse(pubKeyHex));
    const ripe160Hex = RIPEMD160(sha256WordArray).toString(Hex);
    const hash160 = Buffer.from(ripe160Hex, 'hex');

    // Bech32 P2WPKH: witness version 0 + 20-byte hash160
    const words = bech32.toWords(hash160);
    const hrp = testnet ? 'tb' : 'bc';
    return bech32.encode(hrp, [0, ...words]);
}

function normalizePublicKeyBytes(key: string | Uint8Array | any): Uint8Array | null {
    if (!key) return null;
    if (typeof key === 'string') {
        // secp256k1:<base58> — format returned by direct NEAR RPC view calls
        if (key.startsWith('secp256k1:')) {
            return Buffer.from(bs58.decode(key.slice('secp256k1:'.length)));
        }
        // ed25519:<base58>
        if (key.startsWith('ed25519:')) {
            return Buffer.from(bs58.decode(key.slice('ed25519:'.length)));
        }
        // 0x-prefixed or bare hex string
        const cleaned = key.startsWith('0x') ? key.slice(2) : key;
        return Buffer.from(cleaned, 'hex');
    }
    if (Array.isArray(key)) return Uint8Array.from(key);
    if (Buffer.isBuffer(key)) return key;
    if (key instanceof Uint8Array) return key;
    if (key?.data && Array.isArray(key.data)) return Uint8Array.from(key.data);
    return null;
}
