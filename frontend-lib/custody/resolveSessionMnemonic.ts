/**
 * Resolve the wallet mnemonic for in-browser MPC approve/sign paths.
 * Tries in-memory session first, then unified storage, then legacy encrypted wallet.
 */
import { getSessionPassword } from '@/lib/session/sessionPasswordStore';

export async function resolveSessionMnemonic(options: {
  walletData?: { mnemonic?: string | null } | null;
  sessionPassword?: string | null;
  getSessionMnemonic?: () => string | null;
}): Promise<string | null> {
  const { walletData, sessionPassword, getSessionMnemonic } = options;

  if (walletData?.mnemonic) return walletData.mnemonic;

  const fromGetter = getSessionMnemonic?.();
  if (fromGetter) return fromGetter;

  if (typeof window === 'undefined') return null;

  let password =
    sessionPassword ??
    getSessionPassword() ??
    (typeof (window as any).getSessionPasswordForAgent === 'function'
      ? (window as any).getSessionPasswordForAgent()
      : null);
  if (password && typeof (password as Promise<string>).then === 'function') {
    password = await password;
  }
  if (!password) {
    try {
      password = localStorage.getItem('__bombadilUnlockPw') || null;
    } catch {
      password = null;
    }
  }
  if (!password) return null;

  const { getEncryptedSessionManager } = await import('@/lib/crypto/encryptedSessionManager');
  const esm = getEncryptedSessionManager();

  const unified = await esm.loadUnifiedSeed(0, password);
  if (unified) return unified;

  const restored = await esm.loadWalletData(password);
  return restored?.mnemonic ?? null;
}
