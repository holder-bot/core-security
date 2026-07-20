/**
 * evm_native_transfer_v1
 *
 * Sends ETH (or any EVM-native token) from one address to another.
 * Works for Ethereum, Base, Hedera, and any EVM chain in EVM_NETWORKS.
 *
 * Gas: fixed at 21000 (exact cost of a plain ETH transfer, no data).
 * Fees: EIP-1559 — fetches baseFee + priority tip from the RPC.
 */
import { z } from 'zod';
import {
  parseEther,
  serializeTransaction,
  type TransactionSerializable,
} from 'viem';
import type { TransactionTemplate, UnsignedTx } from '../../types';
import { getEvmNetwork } from '@/lib/networks/evm/networks';
import { fetchEvmEip1559Fees, fetchEvmTransactionNonce } from '@/lib/networks/evm/rpc';

export const EvmNativeTransferParams = z.object({
  fromAddress: z.string().regex(/^0x[0-9a-fA-F]{40}$/, 'invalid EVM address'),
  destination: z.string().regex(/^0x[0-9a-fA-F]{40}$/, 'invalid EVM address'),
  amount: z.string().regex(/^\d+(\.\d+)?$/, 'amount must be a decimal string in ETH'),
  networkId: z.string().min(1),
});
export type EvmNativeTransferParamsType = z.infer<typeof EvmNativeTransferParams>;

const NATIVE_TRANSFER_GAS_LIMIT = BigInt(21_000);

/**
 * Standalone builder: build an unsigned native ETH/HBAR transfer.
 * Can be called from the UI send path (Path C) without the full template system.
 */
export async function buildNativeTransferTx(params: {
  fromAddress: `0x${string}`;
  destination: `0x${string}`;
  amount: string;
  networkId: string;
  chainId: number;
}): Promise<`0x${string}`> {
  const value = parseEther(params.amount);
  if (value <= BigInt(0)) throw new Error('Invalid amount');
  const [nonce, fees] = await Promise.all([
    fetchEvmTransactionNonce(params.networkId, params.fromAddress),
    fetchEvmEip1559Fees(params.networkId),
  ]);
  const tx: TransactionSerializable = {
    type: 'eip1559',
    chainId: params.chainId,
    nonce: Number(nonce),
    to: params.destination,
    value,
    gas: NATIVE_TRANSFER_GAS_LIMIT,
    maxFeePerGas: fees.maxFeePerGas,
    maxPriorityFeePerGas: fees.maxPriorityFeePerGas,
    data: '0x',
  };
  return serializeTransaction(tx);
}

export const evmNativeTransferV1: TransactionTemplate<EvmNativeTransferParamsType> = {
  id: 'evm_native_transfer_v1',
  version: 1,
  chain: 'ethereum',
  type: 'native_transfer',
  label: 'EVM Native Transfer',
  paramsSchema: EvmNativeTransferParams,
  contractSpec: {
    amountField: 'amount',
    assetField: null,
    destinationField: 'destination',
    checkDestinationAllowlist: true,
    checkSpendingLimit: true,
  },
  builder: async (params, _connection): Promise<UnsignedTx> => {
    const network = getEvmNetwork(params.networkId);
    const value = parseEther(params.amount);
    if (value <= BigInt(0)) throw new Error('EVM native transfer: invalid amount');

    const [nonce, fees] = await Promise.all([
      fetchEvmTransactionNonce(params.networkId, params.fromAddress),
      fetchEvmEip1559Fees(params.networkId),
    ]);

    const tx: TransactionSerializable = {
      type: 'eip1559',
      chainId: network.chainId,
      nonce: Number(nonce),
      to: params.destination as `0x${string}`,
      value,
      gas: NATIVE_TRANSFER_GAS_LIMIT,
      maxFeePerGas: fees.maxFeePerGas,
      maxPriorityFeePerGas: fees.maxPriorityFeePerGas,
      data: '0x',
    };

    const serializedTx = serializeTransaction(tx);
    return { chain: 'evm', serializedTx, chainId: network.chainId, toAddress: params.destination };
  },
};
