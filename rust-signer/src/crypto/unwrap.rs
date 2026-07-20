/// Key unwrap — mirrors subkeyKeys.ts exactly.
///
/// The double-layer scheme stored in `api_keys.subkey_server_wrapped_private_key`:
///
///   plaintext ed25519 key string
///     ──RSA-OAEP(server_private_key)──▶  rsa_ciphertext
///     ──base64 encode──▶  rsa_ciphertext_b64  (UTF-8 string)
///     ──AES-256-GCM(PBKDF2(passphrase, salt, 100_000, sha256))──▶  gcm_blob
///     ──base64 encode──▶  subkey_server_wrapped_private_key  [stored in DB]
///
/// `subkey_wrap_params` stores:  {"iv":"<base64>","salt":"<base64>"}
///
/// Decryption (this module):
///   1. base64-decode the stored blob  →  gcm_bytes (ciphertext ‖ 16-byte auth tag)
///   2. PBKDF2(passphrase, salt, 100_000 rounds, sha256, 32 bytes)  →  aes_key  [zeroized]
///   3. AES-256-GCM decrypt(aes_key, iv, gcm_bytes)  →  rsa_ciphertext_b64 bytes  [zeroized]
///   4. base64-decode rsa_ciphertext_b64  →  rsa_ciphertext bytes
///   5. RSA-OAEP decrypt(server_private_key, rsa_ciphertext)  →  ed25519 key string  [zeroized]
///   6. parse ed25519 key string  →  SigningKey  [ZeroizeOnDrop]
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use aes_gcm::aead::Aead;
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use ed25519_dalek::SigningKey;
use pbkdf2::pbkdf2_hmac;
use rsa::{RsaPrivateKey, Oaep};
use rsa::pkcs8::DecodePrivateKey;
use rsa::pkcs1::DecodeRsaPrivateKey;
use serde::Deserialize;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::SignerError;
use super::sign::parse_ed25519_key;

#[derive(Deserialize)]
struct WrapParams {
    iv:   String,
    salt: String,
}

/// Unwrap only the outer AES-GCM layer (passphrase) and return the raw RSA
/// ciphertext bytes. Use this when RSA decryption is delegated to an external
/// service (e.g. GCP KMS or a network-accessible hardware signer).
///
/// The returned bytes are the `rsa_ciphertext` that KMS expects as input to
/// `asymmetricDecrypt`. Pass the result to `parse_ed25519_key` + `sign_near_tx`
/// after obtaining the plaintext from the external service.
pub fn unwrap_aes_layer(
    wrapped:     &str,
    wrap_params: &str,
    passphrase:  &str,
) -> Result<Zeroizing<Vec<u8>>, SignerError> {
    let params: WrapParams = serde_json::from_str(wrap_params)
        .map_err(|e| SignerError::JsonParse(e.to_string()))?;

    let iv       = BASE64.decode(&params.iv)
        .map_err(|e| SignerError::Base64Decode(format!("iv: {e}")))?;
    let salt     = BASE64.decode(&params.salt)
        .map_err(|e| SignerError::Base64Decode(format!("salt: {e}")))?;
    let gcm_bytes = BASE64.decode(wrapped)
        .map_err(|e| SignerError::Base64Decode(format!("wrapped blob: {e}")))?;

    let mut aes_key = Zeroizing::new([0u8; 32]);
    pbkdf2_hmac::<Sha256>(passphrase.as_bytes(), &salt, 100_000, &mut *aes_key);

    let key    = Key::<Aes256Gcm>::from_slice(&*aes_key);
    let cipher = Aes256Gcm::new(key);
    let nonce  = Nonce::from_slice(&iv);

    // AES plaintext is base64(rsa_ciphertext) as a UTF-8 string
    let rsa_ct_b64_bytes = Zeroizing::new(
        cipher.decrypt(nonce, gcm_bytes.as_ref())
            .map_err(|_| SignerError::AesDecrypt)?
    );
    drop(aes_key);

    let rsa_ct_b64 = std::str::from_utf8(&*rsa_ct_b64_bytes)
        .map_err(|_| SignerError::KeyParse("AES plaintext is not valid UTF-8".into()))?;

    let rsa_ciphertext = BASE64.decode(rsa_ct_b64.trim())
        .map_err(|e| SignerError::Base64Decode(format!("rsa ciphertext: {e}")))?;

    Ok(Zeroizing::new(rsa_ciphertext))
}

/// Fully unwrap the double-encrypted subkey.
///
/// All intermediate secrets (`aes_key`, `rsa_ciphertext_bytes`, `key_string`)
/// are held in `Zeroizing<T>` wrappers and zeroed on drop — including on
/// early error return.
///
/// The returned `SigningKey` implements `ZeroizeOnDrop`; it is cleared when
/// the caller drops it or when it is consumed by `sign::sign_near_tx`.
///
/// # Parameters
/// - `wrapped`        — `subkeyServerWrappedPrivateKey` from the DB (base64)
/// - `wrap_params`    — `subkeyWrapParams` from the DB (JSON: `{"iv":"…","salt":"…"}`)
/// - `passphrase`     — third segment of the API key (the user-held passphrase)
/// - `server_rsa_pem` — the RSA private key PEM.
///                      PKCS8 (`BEGIN PRIVATE KEY`) or PKCS1 (`BEGIN RSA PRIVATE KEY`).
///                      For the KMS path this is unused — use `sign::parse_ed25519_key`
///                      directly after the TypeScript KMS call instead.
pub fn unwrap_subkey(
    wrapped:        &str,
    wrap_params:    &str,
    passphrase:     &str,
    server_rsa_pem: &str,
) -> Result<SigningKey, SignerError> {
    // ── Step 1: parse wrap params ─────────────────────────────────────────────
    let params: WrapParams = serde_json::from_str(wrap_params)
        .map_err(|e| SignerError::JsonParse(e.to_string()))?;

    let iv   = BASE64.decode(&params.iv)
        .map_err(|e| SignerError::Base64Decode(format!("iv: {e}")))?;
    let salt = BASE64.decode(&params.salt)
        .map_err(|e| SignerError::Base64Decode(format!("salt: {e}")))?;
    let gcm_bytes = BASE64.decode(wrapped)
        .map_err(|e| SignerError::Base64Decode(format!("wrapped blob: {e}")))?;

    // ── Step 2: PBKDF2 → AES key (zeroized on drop) ──────────────────────────
    // Matches: crypto.pbkdf2Sync(passphrase, salt, 100_000, 32, 'sha256')
    let mut aes_key = Zeroizing::new([0u8; 32]);
    pbkdf2_hmac::<Sha256>(passphrase.as_bytes(), &salt, 100_000, &mut *aes_key);

    // ── Step 3: AES-256-GCM decrypt ───────────────────────────────────────────
    // gcm_bytes = ciphertext ‖ 16-byte auth tag  (how Node.js crypto stores it)
    // aes-gcm crate expects exactly this layout — no splitting needed.
    let key    = Key::<Aes256Gcm>::from_slice(&*aes_key);
    let cipher = Aes256Gcm::new(key);
    let nonce  = Nonce::from_slice(&iv);

    let rsa_ct_b64_bytes = Zeroizing::new(
        cipher.decrypt(nonce, gcm_bytes.as_ref())
            .map_err(|_| SignerError::AesDecrypt)?
    );
    drop(aes_key); // explicit: aes key no longer needed, zeroed here

    // ── Step 4: the AES plaintext is base64(rsa_ciphertext) as a UTF-8 string ─
    let rsa_ct_b64 = std::str::from_utf8(&*rsa_ct_b64_bytes)
        .map_err(|_| SignerError::KeyParse("AES plaintext is not valid UTF-8".into()))?;

    let rsa_ciphertext = Zeroizing::new(
        BASE64.decode(rsa_ct_b64.trim())
            .map_err(|e| SignerError::Base64Decode(format!("rsa ciphertext: {e}")))?
    );
    drop(rsa_ct_b64_bytes);

    // ── Step 5: RSA-OAEP decrypt → ed25519 key bytes ─────────────────────────
    // Matches: crypto.privateDecrypt({ key: pem, padding: RSA_PKCS1_OAEP_PADDING,
    //          oaepHash: 'sha256' }, ciphertext)
    let key_bytes = Zeroizing::new(
        rsa_oaep_decrypt(server_rsa_pem, &*rsa_ciphertext)?
    );
    drop(rsa_ciphertext);

    // RSA plaintext is the ed25519 key as a UTF-8 string
    let key_str = std::str::from_utf8(&*key_bytes)
        .map_err(|_| SignerError::KeyParse("RSA plaintext is not valid UTF-8".into()))?;

    // ── Step 6: parse → SigningKey (ZeroizeOnDrop) ────────────────────────────
    let signing_key = parse_ed25519_key(key_str.trim())?;
    // key_bytes drops (zeroed) here

    Ok(signing_key)
}

/// RSA-OAEP / SHA-256 decrypt using a PEM private key.
/// Accepts PKCS8 (`BEGIN PRIVATE KEY`) or PKCS1 (`BEGIN RSA PRIVATE KEY`).
fn rsa_oaep_decrypt(pem: &str, ciphertext: &[u8]) -> Result<Vec<u8>, SignerError> {
    let private_key = parse_rsa_pem(pem)?;
    private_key
        .decrypt(Oaep::new::<Sha256>(), ciphertext)
        .map_err(|e| SignerError::RsaDecrypt(e.to_string()))
}

fn parse_rsa_pem(pem: &str) -> Result<RsaPrivateKey, SignerError> {
    let trimmed = pem.trim();
    if trimmed.contains("BEGIN PRIVATE KEY") {
        // PKCS8 — produced by `openssl genpkey -algorithm RSA`
        RsaPrivateKey::from_pkcs8_pem(trimmed)
            .map_err(|e| SignerError::RsaDecrypt(format!("PKCS8 PEM parse: {e}")))
    } else if trimmed.contains("BEGIN RSA PRIVATE KEY") {
        // PKCS1 — produced by `openssl genrsa`
        RsaPrivateKey::from_pkcs1_pem(trimmed)
            .map_err(|e| SignerError::RsaDecrypt(format!("PKCS1 PEM parse: {e}")))
    } else {
        Err(SignerError::RsaDecrypt(
            "Unrecognised PEM header — expected 'BEGIN PRIVATE KEY' or 'BEGIN RSA PRIVATE KEY'".into()
        ))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::aead::Aead;
    use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
    use rsa::{RsaPrivateKey, RsaPublicKey};
    use rsa::pkcs8::EncodePrivateKey;

    /// Build a wrapped blob identical to what TypeScript/Node.js stores.
    ///
    /// TypeScript layout:
    ///   data = ciphertext ‖ auth_tag
    ///   stored in DB as base64(data)
    ///   wrapParams = {"iv":"<b64>","salt":"<b64>"}
    fn make_test_blob_with_rsa(
        rsa_key: &RsaPrivateKey,
        ed25519_key_str: &str,
        passphrase: &str,
    ) -> (String /* wrapped b64 */, String /* wrap_params JSON */) {
        use rsa::rand_core::OsRng;

        // 2. RSA-OAEP encrypt the ed25519 key string
        let pub_key = RsaPublicKey::from(rsa_key);
        let rsa_ciphertext = pub_key
            .encrypt(&mut OsRng, Oaep::new::<Sha256>(), ed25519_key_str.as_bytes())
            .expect("rsa encrypt");

        // 3. base64-encode the RSA ciphertext (this is the AES plaintext)
        let rsa_ct_b64 = BASE64.encode(&rsa_ciphertext);

        // 4. AES-256-GCM encrypt
        use getrandom::getrandom;
        let mut iv_bytes   = [0u8; 12];
        let mut salt_bytes = [0u8; 32];
        getrandom(&mut iv_bytes).unwrap();
        getrandom(&mut salt_bytes).unwrap();

        let mut aes_key = [0u8; 32];
        pbkdf2_hmac::<Sha256>(passphrase.as_bytes(), &salt_bytes, 100_000, &mut aes_key);

        let key    = Key::<Aes256Gcm>::from_slice(&aes_key);
        let cipher = Aes256Gcm::new(key);
        let nonce  = Nonce::from_slice(&iv_bytes);

        // aes-gcm appends the 16-byte auth tag to the end of the ciphertext output
        let gcm_blob = cipher.encrypt(nonce, rsa_ct_b64.as_bytes()).expect("aes encrypt");

        let wrapped_b64   = BASE64.encode(&gcm_blob);
        let wrap_params   = serde_json::json!({
            "iv":   BASE64.encode(&iv_bytes),
            "salt": BASE64.encode(&salt_bytes),
        }).to_string();

        (wrapped_b64, wrap_params)
    }

    fn make_test_blob(
        ed25519_key_str: &str,
        passphrase: &str,
    ) -> (RsaPrivateKey, String /* wrapped b64 */, String /* wrap_params JSON */, String /* pem */) {
        use rsa::rand_core::OsRng;

        // 1. Generate a small RSA key for tests (1024-bit — do NOT use in prod)
        let rsa_key = RsaPrivateKey::new(&mut OsRng, 1024).expect("rsa keygen");
        let pem = rsa_key.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .expect("pem encode")
            .to_string();

        let (wrapped_b64, wrap_params) =
            make_test_blob_with_rsa(&rsa_key, ed25519_key_str, passphrase);

        (rsa_key, wrapped_b64, wrap_params, pem)
    }

    fn fixed_test_rsa() -> (&'static RsaPrivateKey, &'static str) {
        use std::sync::OnceLock;
        static FIXTURE: OnceLock<(RsaPrivateKey, String)> = OnceLock::new();
        let (key, pem) = FIXTURE.get_or_init(|| {
            use rsa::rand_core::OsRng;
            let rsa_key = RsaPrivateKey::new(&mut OsRng, 1024).expect("rsa keygen");
            let pem = rsa_key
                .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
                .expect("pem encode")
                .to_string();
            (rsa_key, pem)
        });
        (key, pem.as_str())
    }

    #[test]
    fn round_trip_bare_b58_key() {
        // A bare base58 seed (no "ed25519:" prefix)
        let seed = [0x42u8; 32];
        let key_str = bs58::encode(&seed).into_string();

        let passphrase = "test-passphrase-abc123";
        let (_, wrapped, params, pem) = make_test_blob(&key_str, passphrase);

        let signing_key = unwrap_subkey(&wrapped, &params, passphrase, &pem)
            .expect("unwrap failed");

        // The recovered signing key should produce the same public key
        let expected = ed25519_dalek::SigningKey::from_bytes(&seed);
        assert_eq!(
            signing_key.verifying_key().as_bytes(),
            expected.verifying_key().as_bytes(),
            "recovered public key does not match"
        );
    }

    #[test]
    fn round_trip_prefixed_key() {
        // A key with "ed25519:" prefix (as normalizeEd25519Key produces)
        let seed = [0x7fu8; 32];
        let key_str = format!("ed25519:{}", bs58::encode(&seed).into_string());

        let passphrase = "another-passphrase-xyz";
        let (_, wrapped, params, pem) = make_test_blob(&key_str, passphrase);

        let signing_key = unwrap_subkey(&wrapped, &params, passphrase, &pem)
            .expect("unwrap failed");

        let expected = ed25519_dalek::SigningKey::from_bytes(&seed);
        assert_eq!(
            signing_key.verifying_key().as_bytes(),
            expected.verifying_key().as_bytes(),
        );
    }

    #[test]
    fn wrong_passphrase_returns_err() {
        let seed = [0x01u8; 32];
        let key_str = bs58::encode(&seed).into_string();

        let (_, wrapped, params, pem) = make_test_blob(&key_str, "correct-passphrase");

        let result = unwrap_subkey(&wrapped, &params, "wrong-passphrase", &pem);
        assert!(
            matches!(result, Err(SignerError::AesDecrypt)),
            "expected AesDecrypt error, got: {result:?}"
        );
    }

    #[test]
    fn malformed_wrap_params_returns_err() {
        let seed = [0x02u8; 32];
        let key_str = bs58::encode(&seed).into_string();
        let (_, wrapped, _, pem) = make_test_blob(&key_str, "pass");

        let result = unwrap_subkey(&wrapped, "not-json", "pass", &pem);
        assert!(matches!(result, Err(SignerError::JsonParse(_))));
    }

    // ── Property-based tests ─────────────────────────────────────────────────
    // PBKDF2 100k rounds per case — keep case count low.

    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(6))]

        /// Double-wrap round-trip recovers the same ed25519 public key.
        #[test]
        fn prop_unwrap_round_trip_bare_key(
            seed in prop::array::uniform32(0u8..=255),
            passphrase in r"[a-zA-Z0-9_-]{8,24}",
        ) {
            let key_str = bs58::encode(&seed).into_string();
            let (rsa_key, pem) = fixed_test_rsa();
            let (wrapped, params) = make_test_blob_with_rsa(rsa_key, &key_str, &passphrase);

            let signing_key = unwrap_subkey(&wrapped, &params, &passphrase, pem)
                .expect("unwrap failed");
            let expected = ed25519_dalek::SigningKey::from_bytes(&seed);

            prop_assert_eq!(
                signing_key.verifying_key().to_bytes(),
                expected.verifying_key().to_bytes(),
            );
        }

        /// Prefixed ed25519:… encoding round-trips through the same wrap scheme.
        #[test]
        fn prop_unwrap_round_trip_prefixed_key(
            seed in prop::array::uniform32(0u8..=255),
            passphrase in r"[a-zA-Z0-9_-]{8,24}",
        ) {
            let key_str = format!("ed25519:{}", bs58::encode(&seed).into_string());
            let (rsa_key, pem) = fixed_test_rsa();
            let (wrapped, params) = make_test_blob_with_rsa(rsa_key, &key_str, &passphrase);

            let signing_key = unwrap_subkey(&wrapped, &params, &passphrase, pem)
                .expect("unwrap failed");
            let expected = ed25519_dalek::SigningKey::from_bytes(&seed);

            prop_assert_eq!(
                signing_key.verifying_key().to_bytes(),
                expected.verifying_key().to_bytes(),
            );
        }

        /// Wrong passphrase must not silently succeed.
        #[test]
        fn prop_wrong_passphrase_fails(
            seed in prop::array::uniform32(0u8..=255),
            passphrase in r"[a-zA-Z0-9_-]{8,24}",
            wrong in r"[a-zA-Z0-9_-]{8,24}",
        ) {
            prop_assume!(passphrase != wrong);

            let key_str = bs58::encode(&seed).into_string();
            let (rsa_key, pem) = fixed_test_rsa();
            let (wrapped, params) = make_test_blob_with_rsa(rsa_key, &key_str, &passphrase);

            let result = unwrap_subkey(&wrapped, &params, &wrong, pem);
            prop_assert!(matches!(result, Err(SignerError::AesDecrypt)));
        }
    }
}
