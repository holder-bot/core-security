/**
 * evm_erc20_transfer_v1
 *
 * Sends an ERC-20 token (USDC, USDT, DAI, etc.) from one address to another.
 * Works for Ethereum, Base, Hedera, and any EVM chain.
 *
 * Gas: fixed at 65000 (conservative upper bound for a standard ERC-20 transfer).
 * Fees: EIP-1559.
 *
 * Amount: decimal string in token UI units (e.g. "10.50" for 10.50 USDC).
 * The builder converts to base units using the decimals param.
 */
import { z } from 'zod';
import {
  parseEther,
  parseUnits,
  encodeFunctionData,
  serializeTransaction,
  type TransactionSerializable,
  type Abi,
} from 'viem';
import type { TransactionTemplate, UnsignedTx } from '../../types';
import { getEvmNetwork } from '@/lib/networks/evm/networks';
import { fetchEvmEip1559Fees, fetchEvmTransactionNonce } from '@/lib/networks/evm/rpc';

export const EvmErc20TransferParams = z.object({
  fromAddress: z.string().regex(/^0x[0-9a-fA-F]{40}$/, 'invalid EVM address'),
  destination: z.string().regex(/^0x[0-9a-fA-F]{40}$/, 'invalid EVM address'),
  tokenAddress: z.string().regex(/^0x[0-9a-fA-F]{40}$/, 'invalid token contract address'),
  amount: z.string().regex(/^\d+(\.\d+)?$/, 'amount must be a decimal string in token UI units'),
  decimals: z.number().int().min(0).max(18),
  networkId: z.string().min(1),
});
export type EvmErc20TransferParamsType = z.infer<typeof EvmErc20TransferParams>;

const ERC20_GAS_LIMIT = BigInt(65_000);

// Minimal ERC-20 ABI — only transfer(address,uint256)
const ERC20_TRANSFER_ABI = [
  {
    name: 'transfer',
    type: 'function',
    stateMutability: 'nonpayable',
    inputs: [
      { name: 'to', type: 'address' },
      { name: 'value', type: 'uint256' },
    ],
    outputs: [{ name: '', type: 'bool' }],
  },
] as const satisfies Abi;

/**
 * Standalone builder: build an unsigned ERC-20 transfer.
 * Can be called from the UI send path (Path C) without the full template system.
 */
export async function buildErc20TransferTx(params: {
  fromAddress: `0x${string}`;
  destination: `0x${string}`;
  amount: string;
  tokenAddress: `0x${string}`;
  decimals: number;
  networkId: string;
  chainId: number;
}): Promise<`0x${string}`> {
  const prepared = await buildErc20TransferForMpcSign(params);
  return prepared.serializedTx;
}

/** Params for NEAR template sign + unsigned tx for signature assembly (no parse roundtrip). */
export type EvmErc20MpcPrepared = {
  serializedTx: `0x${string}`;
  templateTo: `0x${string}`;
  templateAmount: string;
  chainId: number;
  evmTxParams: {
    nonce: number;
    gas_limit: number;
    max_fee_per_gas: string;
    max_priority_fee_per_gas: string;
    data: `0x${string}` | null;
  };
};

export async function buildErc20TransferForMpcSign(
  params: {
    fromAddress: `0x${string}`;
    destination: `0x${string}`;
    amount: string;
    tokenAddress: `0x${string}`;
    decimals: number;
    networkId: string;
    chainId: number;
  },
  options?: { forceRefreshNonce?: boolean },
): Promise<EvmErc20MpcPrepared> {
  const baseUnits = parseUnits(params.amount, params.decimals);
  if (baseUnits <= BigInt(0)) throw new Error('Invalid token amount');
  const calldata = encodeFunctionData({
    abi: ERC20_TRANSFER_ABI,
    functionName: 'transfer',
    args: [params.destination, baseUnits],
  }) as `0x${string}`;

  const { resolveEvmBuildCache } = await import('@/lib/networks/evm/buildCache');
  const buildState = await resolveEvmBuildCache(
    params.networkId,
    params.fromAddress,
    { forceRefreshNonce: options?.forceRefreshNonce },
  );

  const tx: TransactionSerializable = {
    type: 'eip1559',
    chainId: params.chainId,
    nonce: Number(buildState.nonce),
    to: params.tokenAddress,
    value: BigInt(0),
    gas: ERC20_GAS_LIMIT,
    maxFeePerGas: buildState.maxFeePerGas,
    maxPriorityFeePerGas: buildState.maxPriorityFeePerGas,
    data: calldata,
  };
  const serializedTx = serializeTransaction(tx);

  return {
    serializedTx,
    templateTo: params.tokenAddress,
    templateAmount: '0',
    chainId: params.chainId,
    evmTxParams: {
      nonce: Number(buildState.nonce),
      gas_limit: Number(ERC20_GAS_LIMIT),
      max_fee_per_gas: buildState.maxFeePerGas.toString(),
      max_priority_fee_per_gas: buildState.maxPriorityFeePerGas.toString(),
      data: calldata,
    },
  };
}

export const evmErc20TransferV1: TransactionTemplate<EvmErc20TransferParamsType> = {
  id: 'evm_erc20_transfer_v1',
  version: 1,
  chain: 'ethereum',
  type: 'token_transfer',
  label: 'EVM ERC-20 Token Transfer',
  paramsSchema: EvmErc20TransferParams,
  contractSpec: {
    amountField: 'amount',
    assetField: 'tokenAddress',
    destinationField: 'destination',
    checkDestinationAllowlist: true,
    checkSpendingLimit: true,
  },
  builder: async (params, _connection): Promise<UnsignedTx> => {
    const network = getEvmNetwork(params.networkId);
    const baseUnits = parseUnits(params.amount, params.decimals);
    if (baseUnits <= BigInt(0)) throw new Error('EVM ERC-20 transfer: invalid amount');

    const calldata = encodeFunctionData({
      abi: ERC20_TRANSFER_ABI,
      functionName: 'transfer',
      args: [params.destination as `0x${string}`, baseUnits],
    });

    const [nonce, fees] = await Promise.all([
      fetchEvmTransactionNonce(params.networkId, params.fromAddress),
      fetchEvmEip1559Fees(params.networkId),
    ]);

    const tx: TransactionSerializable = {
      type: 'eip1559',
      chainId: network.chainId,
      nonce: Number(nonce),
      to: params.tokenAddress as `0x${string}`,
      value: BigInt(0),
      gas: ERC20_GAS_LIMIT,
      maxFeePerGas: fees.maxFeePerGas,
      maxPriorityFeePerGas: fees.maxPriorityFeePerGas,
      data: calldata,
    };

    const serializedTx = serializeTransaction(tx);
    return { chain: 'evm', serializedTx, chainId: network.chainId, toAddress: params.tokenAddress };
  },
};
