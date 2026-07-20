/// safu-signer — WASM entry points.
///
/// Phase 1 (Option B): WASM handles all key material (unwrap + signing);
/// TypeScript retains responsibility for NEAR RPC calls (submitting the
/// signed transaction, polling for the sign result).
///
/// Two entry points:
///
///   unwrap_and_sign   — full path: passphrase + PEM → unwrap both layers → sign
///   sign_with_key     — KMS path:  TypeScript did the KMS call, passes the
///                       already-decrypted ed25519 key string here for signing.
///
/// TypeScript integration (Phase 2, not yet wired):
///
///   import init, { unwrap_and_sign, sign_with_key }
///     from '../../rust-signer/pkg/safu_signer';
///
///   // PEM path (local dev / K8s)
///   const sigBytes = unwrap_and_sign(
///     apiKey.subkeyServerWrappedPrivateKey,
///     apiKey.subkeyWrapParams,
///     passphrase,
///     process.env.SERVER_SIGNING_PRIVATE_KEY_PEM,
///     nearTxBytes,          // Uint8Array — borsh-serialised unsigned NEAR tx
///   );
///
///   // KMS path (production) — TypeScript does the KMS call first
///   const ed25519KeyStr = await kmsDecrypt(apiKey, passphrase);
///   const sigBytes = sign_with_key(ed25519KeyStr, nearTxBytes);
///   ed25519KeyStr = '';     // best-effort TS-side clear
use wasm_bindgen::prelude::*;

mod error;
pub mod crypto;

/// Unwrap the double-encrypted NEAR subkey and sign a pre-built NEAR
/// transaction.
///
/// Mirrors the TypeScript call chain:
///   `decryptSubkeyPrivateKey(apiKey, passphrase)` then
///   `near-api-js` signs the transaction using the recovered key.
///
/// All key material (AES key, RSA plaintext, ed25519 seed) is zeroed inside
/// this function before it returns, whether on success or error.
///
/// # Parameters
/// - `wrapped_private_key` — `subkeyServerWrappedPrivateKey` from DB (base64)
/// - `wrap_params`         — `subkeyWrapParams` from DB (JSON `{"iv":"…","salt":"…"}`)
/// - `passphrase`          — third segment of the API key
/// - `server_rsa_pem`      — `SERVER_SIGNING_PRIVATE_KEY_PEM` env var value
///                           (PKCS8 or PKCS1 PEM string)
/// - `near_tx_bytes`       — borsh-serialised unsigned NEAR Transaction
///                           (built by TypeScript with near-api-js)
///
/// # Returns
/// 64-byte ed25519 signature as `Uint8Array`.
/// Attach it to the NEAR Transaction with near-api-js before broadcasting:
///
///   const signedTx = new transactions.SignedTransaction({
///     transaction: tx,
///     signature: new transactions.Signature({ keyType: 0, data: sigBytes }),
///   });
#[wasm_bindgen]
pub fn unwrap_and_sign(
    wrapped_private_key: &str,
    wrap_params:         &str,
    passphrase:          &str,
    server_rsa_pem:      &str,
    near_tx_bytes:       &[u8],
) -> Result<Vec<u8>, JsValue> {
    let signing_key = crypto::unwrap::unwrap_subkey(
        wrapped_private_key,
        wrap_params,
        passphrase,
        server_rsa_pem,
    )
    .map_err(JsValue::from)?;

    let sig = crypto::sign::sign_near_tx(signing_key, near_tx_bytes);
    Ok(sig.to_vec())
}

/// Sign a pre-built NEAR transaction with a pre-decrypted ed25519 key.
///
/// Use this on the KMS path where TypeScript has already called GCP KMS
/// `asymmetricDecrypt` and holds the ed25519 key string. The key is parsed
/// and zeroed inside WASM before this function returns.
///
/// The key string stays in the V8 heap until TypeScript clears its reference;
/// see the passphrase-limitation discussion in docs1/rust-server-signer.md.
///
/// # Parameters
/// - `key_str`       — `"ed25519:<base58>"` or bare `<base58>` key string,
///                     as returned by `decryptServerKey` in subkeyKeys.ts
/// - `near_tx_bytes` — borsh-serialised unsigned NEAR Transaction
///
/// # Returns
/// 64-byte ed25519 signature as `Uint8Array`.
#[wasm_bindgen]
pub fn sign_with_key(
    key_str:       &str,
    near_tx_bytes: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let signing_key = crypto::sign::parse_ed25519_key(key_str)
        .map_err(JsValue::from)?;

    let sig = crypto::sign::sign_near_tx(signing_key, near_tx_bytes);
    Ok(sig.to_vec())
}
