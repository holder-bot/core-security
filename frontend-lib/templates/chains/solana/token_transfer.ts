import { z } from 'zod';
import { Connection } from '@solana/web3.js';
import type { TransactionTemplate, UnsignedTx } from '../../types';
import { buildServerTokenTransferTx } from '@/lib/networks/solana/serverTokenTransactions';

export const TokenTransferParams = z.object({
  fromPublicKey: z.string().trim().min(32),
  destination: z.string().trim().min(32),
  tokenMint: z.string().trim().min(32),
  amount: z.string().regex(/^\d+(\.\d+)?$/),
  tokenProgram: z.enum(['spl', 'token2022']).nullable().default(null),
  decimals: z.number().int().min(0).nullable().default(null),
});
export type TokenTransferParamsType = z.infer<typeof TokenTransferParams>;

export const solTokenTransferV1: TransactionTemplate<TokenTransferParamsType> = {
  id: 'sol_token_transfer_v1',
  version: 1,
  chain: 'solana',
  type: 'token_transfer',
  label: 'Solana SPL Token Transfer',
  paramsSchema: TokenTransferParams as any,
  contractSpec: {
    amountField: 'amount',
    assetField: 'tokenMint',
    destinationField: 'destination',
    checkDestinationAllowlist: true,
    checkSpendingLimit: true,
  },
  builder: async (params, connection): Promise<UnsignedTx> => {
    const amountUi = parseFloat(params.amount);
    if (!Number.isFinite(amountUi) || amountUi <= 0) {
      throw new Error('Solana token transfer: invalid amount');
    }

    const built = await buildServerTokenTransferTx(connection!, {
      fromPublicKey: params.fromPublicKey,
      destination: params.destination,
      tokenMint: params.tokenMint,
      amountUi,
      decimals: typeof params.decimals === 'number' && params.decimals !== null ? params.decimals : undefined,
      tokenProgram: params.tokenProgram ?? undefined,
    });

    return {
      chain: 'solana',
      tx: built.transaction,
      blockhash: built.blockhash,
      lastValidBlockHeight: built.lastValidBlockHeight,
      connection: connection!,
    };
  },
};
