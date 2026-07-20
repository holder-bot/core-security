/**
 * Best-effort sensitive-memory helpers (OSS).
 * JS strings cannot be reliably zeroed — prefer Uint8Array + wipeBytes.
 */

export function wipeBytes(buf: Uint8Array | null | undefined): void {
  if (!buf || buf.length === 0) return;
  buf.fill(0);
}

export function utf8Bytes(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

export function dropSecretRef<T extends { current: string | null }>(ref: T): void {
  ref.current = null;
}
