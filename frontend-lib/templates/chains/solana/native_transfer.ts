import { z } from 'zod';
import { PublicKey, SystemProgram, Transaction, LAMPORTS_PER_SOL } from '@solana/web3.js';
import type { TransactionTemplate, UnsignedTx } from '../../types';

export const NativeTransferParams = z.object({
  fromPublicKey: z.string().trim().min(32),
  destination: z.string().trim().min(32),
  amount: z.string().regex(/^\d+(\.\d+)?$/, 'amount must be a decimal string'),
});
export type NativeTransferParamsType = z.infer<typeof NativeTransferParams>;

export const solNativeTransferV1: TransactionTemplate<NativeTransferParamsType> = {
  id: 'sol_native_transfer_v1',
  version: 1,
  chain: 'solana',
  type: 'native_transfer',
  label: 'Solana SOL Transfer',
  paramsSchema: NativeTransferParams,
  contractSpec: {
    amountField: 'amount',
    assetField: null,
    destinationField: 'destination',
    checkDestinationAllowlist: true,
    checkSpendingLimit: true,
  },
  builder: async (params, connection): Promise<UnsignedTx> => {
    const fromPublicKey = new PublicKey(params.fromPublicKey);
    const toPublicKey = new PublicKey(params.destination);

    const amountSol = parseFloat(params.amount);
    if (!Number.isFinite(amountSol) || amountSol <= 0) {
      throw new Error('Solana native transfer: invalid amount');
    }

    const lamports = Math.round(amountSol * LAMPORTS_PER_SOL);
    if (!Number.isFinite(lamports) || lamports <= 0) {
      throw new Error('Solana lamports value invalid');
    }

    const { blockhash, lastValidBlockHeight } = await connection!.getLatestBlockhash('confirmed');

    const tx = new Transaction({
      feePayer: fromPublicKey,
      recentBlockhash: blockhash,
    });

    tx.add(
      SystemProgram.transfer({
        fromPubkey: fromPublicKey,
        toPubkey: toPublicKey,
        lamports,
      })
    );

    return { chain: 'solana', tx, blockhash, lastValidBlockHeight, connection: connection! };
  },
};
