/**
 * Address metadata must never carry a mnemonic into localStorage (OSS assertion).
 */

export function addressRecordHasMnemonic(record: unknown): boolean {
  if (!record || typeof record !== 'object') return false;
  const m = (record as { mnemonic?: unknown }).mnemonic;
  return typeof m === 'string' && m.trim().length > 0;
}

export function stripMnemonicFromAddress<T extends Record<string, unknown>>(
  record: T,
): Omit<T, 'mnemonic'> {
  const { mnemonic: _drop, ...rest } = record;
  return rest as Omit<T, 'mnemonic'>;
}

export function addressListHasNoMnemonics(records: unknown[]): boolean {
  return records.every((r) => !addressRecordHasMnemonic(r));
}
