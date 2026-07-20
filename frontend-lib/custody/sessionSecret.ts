/**
 * Unlock password / session secret — runtime-specific custody.
 *
 * Web: in-memory module (+ optional sessionStorage fallback elsewhere).
 * Extension: background service worker memory (page never holds plaintext password).
 */

import {
  clearSessionPassword,
  getSessionPassword,
  setSessionPassword,
} from '@/lib/session/sessionPasswordStore';
import { isExtensionRuntime } from './runtimeContext';

const HOLDER_CHANNEL = 'holder/v1';

type PasswordResponse =
  | { ok: true; password: string | null }
  | { ok: false; error: string };

/** Read session password from the correct runtime custody layer. */
export async function getSessionSecret(): Promise<string | null> {
  if (!isExtensionRuntime()) {
    return getSessionPassword();
  }

  if (typeof chrome === 'undefined' || !chrome.runtime?.sendMessage) {
    return null;
  }

  try {
    const res = (await chrome.runtime.sendMessage({
      channel: HOLDER_CHANNEL,
      payload: { type: 'GET_SESSION_SECRET' },
    })) as PasswordResponse;
    return res.ok ? res.password : null;
  } catch {
    return null;
  }
}

/**
 * Store session password in the correct runtime custody layer.
 * In the extension, pass `mnemonic` when the shell already decrypted it so the
 * background can arm dApp Connect without re-reading vault storage.
 */
export async function setSessionSecret(
  password: string | null,
  mnemonic?: string | null,
): Promise<void> {
  if (!isExtensionRuntime()) {
    setSessionPassword(password);
    return;
  }

  if (typeof chrome === 'undefined' || !chrome.runtime?.sendMessage) return;

  await chrome.runtime.sendMessage({
    channel: HOLDER_CHANNEL,
    payload: password
      ? {
          type: 'SET_SESSION_SECRET',
          password,
          ...(mnemonic ? { mnemonic } : {}),
        }
      : { type: 'CLEAR_SESSION_SECRET' },
  });
}

export async function clearSessionSecret(): Promise<void> {
  if (!isExtensionRuntime()) {
    clearSessionPassword();
    return;
  }

  if (typeof chrome === 'undefined' || !chrome.runtime?.sendMessage) return;

  await chrome.runtime.sendMessage({
    channel: HOLDER_CHANNEL,
    payload: { type: 'CLEAR_SESSION_SECRET' },
  });
}
