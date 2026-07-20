/**
 * In-memory session password — tab lifetime only, never persisted to storage.
 * Single module instance survives React re-renders without sessionStorage exposure.
 */
let sessionPassword: string | null = null;

export function getSessionPassword(): string | null {
  return sessionPassword;
}

export function setSessionPassword(password: string | null): void {
  sessionPassword = password;
}

export function clearSessionPassword(): void {
  sessionPassword = null;
  if (typeof sessionStorage !== 'undefined') {
    try {
      sessionStorage.removeItem('__safu_sp');
    } catch {
      // ignore
    }
  }
}

/** E2E / Bombadil: inject password without sessionStorage (dev/test only). */
export function setSessionPasswordForE2E(password: string): void {
  sessionPassword = password;
}
