/// Ed25519 signing for NEAR transactions.
///
/// NEAR signing convention (from near-api-js/src/transaction.ts):
///
///   const message = transaction.encode();          // borsh-serialised Transaction
///   const hash    = sha256(message);               // SHA-256 of the borsh bytes
///   const { signature } = keyPair.sign(hash);      // ed25519(hash)
///
/// So: signature = ed25519_sign(sha256(borsh_tx_bytes), secret_key)
///
/// TypeScript call site (mpcSign.ts / subkeyContract.ts):
///   near-api-js builds the unsigned tx, sha256-hashes it internally,
///   then calls keyPair.sign(hash) using nacl.sign.detached —
///   which is standard ed25519 over the raw hash bytes.
///
/// This module produces bit-identical signatures when given the same
/// tx bytes and key as near-api-js.
use bs58;
use ed25519_dalek::{Signature, SigningKey, Signer};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::error::SignerError;

/// Parse a NEAR-style ed25519 key string into a `SigningKey`.
///
/// Accepts:
///   - `"ed25519:<base58>"` — normalizeEd25519Key output
///   - `"<base58>"`         — bare base58, 32 or 64 bytes
///
/// The base58 value may be:
///   - 32 bytes: the raw seed
///   - 64 bytes: seed ‖ public key  (near-api-js extended format)
///
/// In both cases only the first 32 bytes (the seed) are used.
/// The raw bytes are zeroed immediately after the SigningKey is constructed.
pub fn parse_ed25519_key(key_str: &str) -> Result<SigningKey, SignerError> {
    let b58 = key_str
        .strip_prefix("ed25519:")
        .unwrap_or(key_str)
        .trim();

    let mut raw = bs58::decode(b58)
        .into_vec()
        .map_err(|e| SignerError::KeyParse(format!("base58 decode: {e}")))?;

    if raw.len() < 32 {
        let got = raw.len(); // capture before zeroize clears the Vec's length
        raw.zeroize();
        return Err(SignerError::InvalidKeyLength { got, expected: 32 });
    }

    let seed: [u8; 32] = raw[..32]
        .try_into()
        .map_err(|_| SignerError::InvalidKeyLength { got: raw.len(), expected: 32 })?;

    let signing_key = SigningKey::from_bytes(&seed);
    raw.zeroize(); // zero the full decoded buffer, including any public-key tail
    Ok(signing_key)
}

/// Sign the borsh-serialised bytes of an unsigned NEAR transaction.
///
/// Returns the 64-byte ed25519 signature that near-api-js expects.
///
/// The `signing_key` is consumed by this function; `SigningKey` implements
/// `ZeroizeOnDrop` so its memory is cleared on drop.
pub fn sign_near_tx(signing_key: SigningKey, tx_bytes: &[u8]) -> [u8; 64] {
    // NEAR signs sha256(borsh_tx_bytes), not the raw bytes directly.
    let hash = Sha256::digest(tx_bytes);
    let signature: Signature = signing_key.sign(hash.as_slice());
    signature.to_bytes()
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Verifier, VerifyingKey};

    // ── parse_ed25519_key ────────────────────────────────────────────────────

    #[test]
    fn parse_bare_32_byte_seed() {
        let seed = [0x11u8; 32];
        let encoded = bs58::encode(&seed).into_string();
        let key = parse_ed25519_key(&encoded).expect("parse failed");
        // Verify the public key matches what dalek derives from this seed
        let expected = SigningKey::from_bytes(&seed);
        assert_eq!(key.verifying_key().as_bytes(), expected.verifying_key().as_bytes());
    }

    #[test]
    fn parse_prefixed_32_byte_seed() {
        let seed = [0x22u8; 32];
        let encoded = format!("ed25519:{}", bs58::encode(&seed).into_string());
        let key = parse_ed25519_key(&encoded).expect("parse failed");
        let expected = SigningKey::from_bytes(&seed);
        assert_eq!(key.verifying_key().as_bytes(), expected.verifying_key().as_bytes());
    }

    #[test]
    fn parse_64_byte_near_api_js_format() {
        // near-api-js stores seed ‖ public_key in base58
        let seed = [0x33u8; 32];
        let expected_key = SigningKey::from_bytes(&seed);
        let pub_bytes = expected_key.verifying_key().to_bytes();

        let mut full = [0u8; 64];
        full[..32].copy_from_slice(&seed);
        full[32..].copy_from_slice(&pub_bytes);

        let encoded = format!("ed25519:{}", bs58::encode(&full).into_string());
        let key = parse_ed25519_key(&encoded).expect("parse failed");
        assert_eq!(key.verifying_key().as_bytes(), expected_key.verifying_key().as_bytes());
    }

    #[test]
    fn parse_too_short_returns_err() {
        let encoded = bs58::encode(&[0u8; 16]).into_string();
        let result = parse_ed25519_key(&encoded);
        assert!(matches!(result, Err(SignerError::InvalidKeyLength { got: 16, expected: 32 })));
    }

    #[test]
    fn parse_bad_base58_returns_err() {
        let result = parse_ed25519_key("not-valid-base58!!!");
        assert!(matches!(result, Err(SignerError::KeyParse(_))));
    }

    // ── sign_near_tx ─────────────────────────────────────────────────────────

    #[test]
    fn sign_and_verify() {
        let seed = [0xaau8; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key: VerifyingKey = signing_key.verifying_key();

        // Simulate borsh-serialised tx bytes
        let tx_bytes = b"mock borsh-encoded NEAR transaction bytes 0000";

        let sig_bytes = sign_near_tx(signing_key, tx_bytes);

        // Reproduce the hash exactly as NEAR does
        let hash = Sha256::digest(tx_bytes);
        let sig  = Signature::from_bytes(&sig_bytes);
        assert!(
            verifying_key.verify(hash.as_slice(), &sig).is_ok(),
            "signature verification failed"
        );
    }

    #[test]
    fn different_tx_bytes_give_different_signatures() {
        let seed = [0xbbu8; 32];

        let sig1 = sign_near_tx(SigningKey::from_bytes(&seed), b"tx version one");
        let sig2 = sign_near_tx(SigningKey::from_bytes(&seed), b"tx version two");

        assert_ne!(sig1, sig2);
    }

    #[test]
    fn signature_is_64_bytes() {
        let seed = [0xccu8; 32];
        let sig = sign_near_tx(SigningKey::from_bytes(&seed), b"any tx");
        assert_eq!(sig.len(), 64);
    }

    /// Cross-check: sign the sha256 hash with parse_ed25519_key → sign_near_tx,
    /// then verify with the public key derived from the original seed.
    /// This is the full path that WASM callers exercise.
    #[test]
    fn full_path_parse_sign_verify() {
        let seed = [0xddu8; 32];
        let original_key = SigningKey::from_bytes(&seed);
        let verifying_key = original_key.verifying_key();

        // Encode as "ed25519:<base58(seed ‖ pub)>" — the format TypeScript produces
        let mut full = [0u8; 64];
        full[..32].copy_from_slice(&seed);
        full[32..].copy_from_slice(verifying_key.as_bytes());
        let key_str = format!("ed25519:{}", bs58::encode(&full).into_string());

        let tx_bytes = b"a realistic borsh transaction payload here";

        let parsed_key = parse_ed25519_key(&key_str).expect("parse");
        let sig_bytes  = sign_near_tx(parsed_key, tx_bytes);

        let hash = Sha256::digest(tx_bytes);
        let sig  = Signature::from_bytes(&sig_bytes);
        assert!(
            verifying_key.verify(hash.as_slice(), &sig).is_ok(),
            "full path verification failed"
        );
    }

    // ── Property-based tests ─────────────────────────────────────────────────

    use proptest::prelude::*;

    proptest! {
        /// NEAR signs sha256(tx_bytes); every signature must verify under the derived public key.
        #[test]
        fn prop_sign_near_tx_always_verifies(
            seed in prop::array::uniform32(0u8..=255),
            tx_bytes in prop::collection::vec(any::<u8>(), 0..512),
        ) {
            let signing_key = SigningKey::from_bytes(&seed);
            let verifying_key = signing_key.verifying_key();

            let sig_bytes = sign_near_tx(signing_key, &tx_bytes);
            prop_assert_eq!(sig_bytes.len(), 64);

            let hash = Sha256::digest(&tx_bytes);
            let sig = Signature::from_bytes(&sig_bytes);
            prop_assert!(verifying_key.verify(hash.as_slice(), &sig).is_ok());
        }

        /// parse_ed25519_key is deterministic for valid encodings.
        #[test]
        fn prop_parse_ed25519_key_deterministic(seed in prop::array::uniform32(0u8..=255)) {
            let encoded = bs58::encode(&seed).into_string();
            let a = parse_ed25519_key(&encoded).expect("parse");
            let b = parse_ed25519_key(&encoded).expect("parse");
            let a_pub = a.verifying_key().to_bytes();
            let b_pub = b.verifying_key().to_bytes();
            prop_assert_eq!(a_pub, b_pub);
        }

        /// 32-byte seed and 64-byte near-api-js encoding of the same seed yield the same public key.
        #[test]
        fn prop_parse_32_and_64_byte_formats_match(seed in prop::array::uniform32(0u8..=255)) {
            let signing_key = SigningKey::from_bytes(&seed);
            let pub_bytes = signing_key.verifying_key().to_bytes();

            let bare = bs58::encode(&seed).into_string();
            let mut full = [0u8; 64];
            full[..32].copy_from_slice(&seed);
            full[32..].copy_from_slice(&pub_bytes);
            let prefixed = format!("ed25519:{}", bs58::encode(&full).into_string());

            let from_bare = parse_ed25519_key(&bare).expect("bare");
            let from_full = parse_ed25519_key(&prefixed).expect("full");
            let bare_pub = from_bare.verifying_key().to_bytes();
            let full_pub = from_full.verifying_key().to_bytes();
            prop_assert_eq!(bare_pub, full_pub);
        }
    }
}
