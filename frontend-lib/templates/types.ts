import { Connection, Transaction as SolanaTransaction } from '@solana/web3.js';
import type { Transaction as BitcoinTransaction } from 'bitcoinjs-lib';
import { z } from 'zod';

export type Chain = 'solana' | 'ethereum' | 'bitcoin' | 'near';
export type TxType = 'native_transfer' | 'token_transfer' | 'swap' | 'contract_call' | 'bridge' | 'x402_payment';

export type UnsignedTx =
  | { chain: 'solana'; tx: SolanaTransaction; blockhash: string; lastValidBlockHeight: number; connection: Connection }
  | {
      chain: 'evm';
      serializedTx: `0x${string}`;
      chainId: number;
      toAddress: string;
      /** Optional builder display hints (e.g. V3 DEX quote amount out). */
      displayMeta?: {
        amountOutFormatted?: string;
        amountOutDecimals?: number;
        tokenOutSymbol?: string;
      };
    }
  | {
      chain:            'bitcoin';
      tx:               BitcoinTransaction;
      sighashes:        Buffer[];
      pubkeyHex:        string;   // 33-byte compressed, hex
      amountSat:        number;
      feeSat:           number;
      testnet:          boolean;
      recipientAddress: string;
    };

export interface ContractValidationSpec<P extends object = object> {
  amountField?: keyof P;
  assetField?: keyof P | null;
  destinationField?: keyof P;
  checkDestinationAllowlist: boolean;
  checkSpendingLimit: boolean;
  extra?: Record<string, unknown>;
}

export interface TransactionTemplate<P extends object = object> {
  id: string;
  version: number;
  chain: Chain;
  type: TxType;
  paramsSchema: z.ZodType<P>;
  // connection is null for EVM builders — they receive null and ignore it
  builder: (params: P, connection: Connection | null) => Promise<UnsignedTx>;
  contractSpec: ContractValidationSpec<P>;
  label: string;
  deprecated?: boolean;
}
