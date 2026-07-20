/**
 * Persist "must confirm new seed" across refresh so /assets cannot skip backup.
 * sessionStorage: tab-scoped; cleared on confirm / logout.
 */

const KEY = '__safu_seed_backup_pending';

export function markSeedBackupPending(): void {
  if (typeof sessionStorage === 'undefined') return;
  try {
    sessionStorage.setItem(KEY, '1');
  } catch {
    /* ignore */
  }
}

export function clearSeedBackupPending(): void {
  if (typeof sessionStorage === 'undefined') return;
  try {
    sessionStorage.removeItem(KEY);
  } catch {
    /* ignore */
  }
}

export function isSeedBackupPending(): boolean {
  if (typeof sessionStorage === 'undefined') return false;
  try {
    return sessionStorage.getItem(KEY) === '1';
  } catch {
    return false;
  }
}
