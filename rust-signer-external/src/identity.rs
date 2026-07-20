/// Signer identity — EC P-256 keypair.
///
/// Used for:
///   - Authenticating to the server (mTLS client cert, Phase 3)
///   - Decrypting incoming subkey deliveries via ECIES (Phase 2)
///   - Generating the pairing URL shown to the user at init time
///
/// The private key is stored as a PKCS#8 PEM file at
/// `~/.holder-signer/identity.pem` (mode 0600).
use anyhow::{Context, Result};
use base64::Engine as _;
use p256::{
    pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding},
    SecretKey,
};
use std::path::{Path, PathBuf};

pub struct SignerIdentity {
    secret_key: SecretKey,
}

impl SignerIdentity {
    /// Generate a fresh EC P-256 keypair.
    pub fn generate() -> Result<Self> {
        let secret_key = SecretKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        Ok(Self { secret_key })
    }

    /// Load from the PEM file at the given path.
    pub fn load(path: &Path) -> Result<Self> {
        let pem = std::fs::read_to_string(path)
            .with_context(|| format!("Cannot read identity key from {}", path.display()))?;
        Self::load_from_pem(&pem)
    }

    /// Parse directly from a PEM string.
    pub fn load_from_pem(pem: &str) -> Result<Self> {
        let secret_key = SecretKey::from_pkcs8_pem(pem)
            .map_err(|e| anyhow::anyhow!("Failed to parse identity PEM: {e}"))?;
        Ok(Self { secret_key })
    }

    /// Save private key as PKCS#8 PEM, mode 0600.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)
                .with_context(|| format!("Cannot create dir {}", dir.display()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).ok();
            }
        }
        let pem = self.secret_key.to_pkcs8_pem(LineEnding::LF)
            .map_err(|e| anyhow::anyhow!("Failed to encode identity key: {e}"))?;
        std::fs::write(path, pem.as_bytes())
            .with_context(|| format!("Cannot write identity key to {}", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).ok();
        }
        Ok(())
    }

    /// Returns the uncompressed SEC1 public key bytes (65 bytes).
    pub fn public_key_bytes(&self) -> Vec<u8> {
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        self.secret_key.public_key().to_encoded_point(false).as_bytes().to_vec()
    }

    /// Returns the public key as URL-safe base64 (no padding) for use in URLs.
    pub fn public_key_b64(&self) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(self.public_key_bytes())
    }

    /// Returns the public key (base64url) for wallet Settings → Add Signer.
    pub fn pairing_token(&self) -> String {
        self.public_key_b64()
    }

    /// Returns the full pairing URL for the wallet settings page.
    pub fn pairing_url(&self, server_url: &str) -> String {
        format!(
            "{}/settings/pair-signer?pk={}",
            server_url.trim_end_matches('/'),
            self.public_key_b64()
        )
    }

    /// Decrypt a subkey delivery using ECIES (ECDH + AES-256-GCM).
    ///
    /// `ephemeral_pub_b64` — base64 ephemeral public key from the delivery
    /// `ciphertext_b64`    — base64 AES-GCM ciphertext (includes GCM tag)
    /// `iv_b64`            — base64 12-byte GCM nonce
    pub fn ecdh_decrypt(
        &self,
        ephemeral_pub_b64: &str,
        ciphertext_b64:    &str,
        iv_b64:            &str,
    ) -> Result<Vec<u8>> {
        use aes_gcm::{
            aead::{Aead, KeyInit},
            Aes256Gcm, Nonce,
        };
        use p256::{EncodedPoint, PublicKey};
        use p256::elliptic_curve::sec1::FromEncodedPoint;

        let ephemeral_pub_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(ephemeral_pub_b64)
            .context("Failed to decode ephemeral public key")?;
        let ciphertext = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(ciphertext_b64)
            .context("Failed to decode ciphertext")?;
        let iv_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(iv_b64)
            .context("Failed to decode IV")?;

        // Import the ephemeral public key
        let ephemeral_point = EncodedPoint::from_bytes(&ephemeral_pub_bytes)
            .map_err(|e| anyhow::anyhow!("Invalid ephemeral public key: {e}"))?;
        let ephemeral_pub = PublicKey::from_encoded_point(&ephemeral_point)
            .into_option()
            .context("Invalid ephemeral public key point")?;

        // ECDH shared secret
        let shared_secret = p256::ecdh::diffie_hellman(
            self.secret_key.to_nonzero_scalar(),
            ephemeral_pub.as_affine(),
        );

        // Derive AES key from shared secret using HKDF-SHA256
        let aes_key = hkdf_sha256(shared_secret.raw_secret_bytes().as_slice(), b"holder-signer-v1");

        // AES-256-GCM decrypt
        if iv_bytes.len() != 12 {
            anyhow::bail!("IV must be 12 bytes, got {}", iv_bytes.len());
        }
        let cipher = Aes256Gcm::new_from_slice(&aes_key)
            .map_err(|e| anyhow::anyhow!("AES key init failed: {e}"))?;
        let nonce = Nonce::from_slice(&iv_bytes);
        let plaintext = cipher.decrypt(nonce, ciphertext.as_ref())
            .map_err(|_| anyhow::anyhow!("AES-GCM decryption failed — wrong key or corrupted data"))?;

        Ok(plaintext)
    }

    /// Default path for the identity key file.
    pub fn default_path() -> PathBuf {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".holder-signer")
            .join("identity.pem")
    }
}

/// HKDF-SHA256: derive a 32-byte AES key from the ECDH shared secret.
pub fn hkdf_sha256(ikm: &[u8], info: &[u8]) -> [u8; 32] {
    // Simple HKDF-Extract + HKDF-Expand with a fixed salt
    let salt = b"safu-network-ecdh-v1";
    let prk = hmac_sha256(salt, ikm);
    let mut okm = [0u8; 32];
    let mut t = Vec::new();
    let mut t_i = Vec::new();
    t_i.extend_from_slice(info);
    t_i.push(1u8);
    t.extend_from_slice(&hmac_sha256(&prk, &t_i));
    okm.copy_from_slice(&t[..32]);
    okm
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    // HMAC-SHA256 from scratch (avoids pulling in the hmac crate separately)
    const BLOCK: usize = 64;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        let h = Sha256::digest(key);
        k[..32].copy_from_slice(&h);
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(data);
    let inner_hash = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(&inner_hash);
    outer.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::{
        aead::{Aead, KeyInit},
        Aes256Gcm, Nonce,
    };
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use proptest::prelude::*;

    /// Encrypt plaintext to `recipient` the same way the wallet API does
    /// (ECDH-P256 + HKDF holder-signer-v1 + AES-256-GCM).
    fn ecdh_encrypt_for(
        recipient: &SignerIdentity,
        plaintext: &[u8],
    ) -> (String, String, String) {
        let eph_sk = SecretKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let eph_pub_bytes = eph_sk.public_key().to_encoded_point(false).as_bytes().to_vec();
        let shared = p256::ecdh::diffie_hellman(
            eph_sk.to_nonzero_scalar(),
            recipient.secret_key.public_key().as_affine(),
        );
        let aes_key = hkdf_sha256(shared.raw_secret_bytes().as_slice(), b"holder-signer-v1");
        let cipher = Aes256Gcm::new_from_slice(&aes_key).expect("aes key");
        let mut iv = [0u8; 12];
        {
            use p256::elliptic_curve::rand_core::RngCore;
            p256::elliptic_curve::rand_core::OsRng.fill_bytes(&mut iv);
        }
        let nonce = Nonce::from_slice(&iv);
        let ciphertext = cipher.encrypt(nonce, plaintext).expect("encrypt");
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        (
            b64.encode(eph_pub_bytes),
            b64.encode(ciphertext),
            b64.encode(iv),
        )
    }

    #[test]
    fn pairing_token_is_public_key_b64() {
        let id = SignerIdentity::generate().unwrap();
        assert_eq!(id.pairing_token(), id.public_key_b64());
        assert!(id.public_key_bytes().len() == 65);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(24))]

        /// Correct recipient can always unwrap a fresh ECDH delivery.
        #[test]
        fn prop_ecdh_roundtrip(
            plaintext in prop::collection::vec(any::<u8>(), 1..64),
        ) {
            let id = SignerIdentity::generate().unwrap();
            let (eph, ct, iv) = ecdh_encrypt_for(&id, &plaintext);
            let got = id.ecdh_decrypt(&eph, &ct, &iv).unwrap();
            prop_assert_eq!(got, plaintext);
        }

        /// A different identity must not decrypt material wrapped for another signer.
        #[test]
        fn prop_wrong_identity_cannot_decrypt(
            plaintext in prop::collection::vec(any::<u8>(), 1..48),
        ) {
            let owner = SignerIdentity::generate().unwrap();
            let other = SignerIdentity::generate().unwrap();
            let (eph, ct, iv) = ecdh_encrypt_for(&owner, &plaintext);
            prop_assert!(other.ecdh_decrypt(&eph, &ct, &iv).is_err());
        }

        /// Bit-flip in ciphertext must fail closed (GCM auth).
        #[test]
        fn prop_tampered_ciphertext_rejected(
            plaintext in prop::collection::vec(any::<u8>(), 8..48),
            flip_idx in 0usize..64,
        ) {
            let id = SignerIdentity::generate().unwrap();
            let (eph, ct, iv) = ecdh_encrypt_for(&id, &plaintext);
            let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
            let mut raw = b64.decode(&ct).unwrap();
            let i = flip_idx % raw.len();
            raw[i] ^= 0x5a;
            let bad_ct = b64.encode(raw);
            prop_assert!(id.ecdh_decrypt(&eph, &bad_ct, &iv).is_err());
        }

        /// HKDF is deterministic for fixed IKM + info.
        #[test]
        fn prop_hkdf_deterministic(
            ikm in prop::collection::vec(any::<u8>(), 16..48),
            info in prop::collection::vec(any::<u8>(), 0..24),
        ) {
            let a = hkdf_sha256(&ikm, &info);
            let b = hkdf_sha256(&ikm, &info);
            prop_assert_eq!(a, b);
        }

        /// PEM save/load preserves ECDH capability (reliability of identity persistence).
        #[test]
        fn prop_pem_roundtrip_preserves_decrypt(
            plaintext in prop::collection::vec(any::<u8>(), 1..32),
        ) {
            let id = SignerIdentity::generate().unwrap();
            let dir = std::env::temp_dir().join(format!("holder-id-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join("identity.pem");
            id.save(&path).unwrap();
            let loaded = SignerIdentity::load(&path).unwrap();
            prop_assert_eq!(loaded.public_key_b64(), id.public_key_b64());
            let (eph, ct, iv) = ecdh_encrypt_for(&id, &plaintext);
            let got = loaded.ecdh_decrypt(&eph, &ct, &iv).unwrap();
            prop_assert_eq!(got, plaintext);
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}
