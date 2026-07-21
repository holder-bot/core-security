/**
 * Persist "must confirm new seed" across refresh / extension popup close so
 * /assets cannot skip backup. Cleared on confirm / logout.
 *
 * Writes both page localStorage and walletKV (chrome.storage.local in the
 * extension). Popup teardown clears in-memory React state; durable storage
 * must survive so reopen resumes seed confirmation instead of the main wallet.
 */

import { walletKVGetItem, walletKVRemoveItem, walletKVSetItem } from '@/lib/storage/walletKV';

const KEY = '__safu_seed_backup_pending';

function readLocal(): string | null {
  if (typeof localStorage === 'undefined') return null;
  try {
    return localStorage.getItem(KEY);
  } catch {
    return null;
  }
}

function writeLocal(value: string | null): void {
  if (typeof localStorage === 'undefined') return;
  try {
    if (value == null) localStorage.removeItem(KEY);
    else localStorage.setItem(KEY, value);
  } catch {
    /* ignore */
  }
}

function clearLegacySessionFlag(): void {
  if (typeof sessionStorage === 'undefined') return;
  try {
    sessionStorage.removeItem(KEY);
  } catch {
    /* ignore */
  }
}

export function markSeedBackupPending(): void {
  writeLocal('1');
  try {
    walletKVSetItem(KEY, '1');
  } catch {
    /* ignore */
  }
  clearLegacySessionFlag();
}

export function clearSeedBackupPending(): void {
  writeLocal(null);
  try {
    walletKVRemoveItem(KEY);
  } catch {
    /* ignore */
  }
  clearLegacySessionFlag();
}

export function isSeedBackupPending(): boolean {
  try {
    if (readLocal() === '1') return true;
    if (walletKVGetItem(KEY) === '1') {
      // Mirror into localStorage for sync layout gates on the next tick.
      writeLocal('1');
      return true;
    }
    if (typeof sessionStorage !== 'undefined' && sessionStorage.getItem(KEY) === '1') {
      markSeedBackupPending();
      return true;
    }
    return false;
  } catch {
    return false;
  }
}
