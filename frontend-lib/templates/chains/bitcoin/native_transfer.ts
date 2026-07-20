/**
 * btc_native_transfer_v1
 *
 * P2WPKH native Bitcoin transfer.
 *
 * The builder fetches UTXOs and fee rate from Blockstream, builds an unsigned
 * transaction, and returns a `{ chain: 'bitcoin' }` UnsignedTx.  The signing
 * step (MPC loop) is handled separately by sendBitcoinWithMpc or the
 * browser-approve flow.
 *
 * Amount is expressed as a decimal BTC string (e.g. "0.001") for consistency
 * with other chain templates; it is converted to satoshis internally.
 */

import { z } from 'zod';
import type { TransactionTemplate, UnsignedTx } from '../../types';
import { fetchUTXOs, fetchFeeRate } from '@/lib/networks/bitcoin/utxo';
import { buildUnsignedTx } from '@/lib/networks/bitcoin/psbt';

export const BtcNativeTransferParams = z.object({
  fromAddress:  z.string().regex(/^(bc1|tb1)[ac-hj-np-zAC-HJ-NP-Z02-9]{11,71}$/, 'invalid P2WPKH address'),
  destination:  z.string().regex(/^(bc1|tb1)[ac-hj-np-zAC-HJ-NP-Z02-9]{11,71}$/, 'invalid P2WPKH address'),
  /** Amount in BTC (decimal string, e.g. "0.001") */
  amount:       z.string().regex(/^\d+(\.\d+)?$/, 'amount must be a decimal BTC string'),
  /** pubkeyHex: 33-byte compressed public key of the sender (derived from MPC) */
  pubkeyHex:    z.string().regex(/^[0-9a-fA-F]{66}$/, 'pubkeyHex must be 33 bytes hex'),
  /** 'bitcoin-mainnet' | 'bitcoin-testnet' | 'bitcoin' */
  networkId:    z.string().min(1),
});

export type BtcNativeTransferParamsType = z.infer<typeof BtcNativeTransferParams>;

function isTestnet(networkId: string): boolean {
  return !networkId.toLowerCase().includes('mainnet');
}

const BTC_DECIMALS = 1e8;

export const btcNativeTransferV1: TransactionTemplate<BtcNativeTransferParamsType> = {
  id:      'btc_native_transfer_v1',
  version: 1,
  chain:   'bitcoin',
  type:    'native_transfer',
  label:   'Bitcoin Native Transfer',

  paramsSchema: BtcNativeTransferParams,

  contractSpec: {
    amountField:              'amount',
    assetField:               null,
    destinationField:         'destination',
    checkDestinationAllowlist: true,
    checkSpendingLimit:        true,
  },

  builder: async (params, _connection): Promise<UnsignedTx> => {
    const testnet   = isTestnet(params.networkId);
    const amountSat = Math.round(parseFloat(params.amount) * BTC_DECIMALS);

    if (!Number.isFinite(amountSat) || amountSat < 546) {
      throw new Error(`btc_native_transfer_v1: amount too small (${amountSat} sat, min 546)`);
    }

    const [utxos, feeRate] = await Promise.all([
      fetchUTXOs(params.fromAddress, testnet),
      fetchFeeRate(testnet),
    ]);

    if (utxos.length === 0) {
      throw new Error(`No confirmed UTXOs for ${params.fromAddress}`);
    }

    const built = buildUnsignedTx({
      senderAddress:      params.fromAddress,
      senderPubkeyHex:    params.pubkeyHex,
      recipientAddress:   params.destination,
      amountSat,
      feeRateSatPerVbyte: feeRate,
      utxos,
      testnet,
    });

    return {
      chain:      'bitcoin',
      tx:          built.tx,
      sighashes:   built.sighashes,
      pubkeyHex:   params.pubkeyHex,
      amountSat,
      feeSat:      built.estimatedFee,
      testnet,
      recipientAddress: params.destination,
    } as UnsignedTx;
  },
};
