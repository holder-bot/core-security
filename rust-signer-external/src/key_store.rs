/// Local key store — stores decrypted ed25519 subkeys on disk, encrypted at rest.
///
/// Each API key's subkey is stored as an individual file under
/// `~/.holder-signer/keys/<api_key_id>`.
///
/// Files are encrypted with AES-256-GCM. The AES key is derived from the
/// daemon startup passphrase via PBKDF2-SHA256 (100k iterations, fixed salt).
///
/// This means a daemon restart requires re-entering the passphrase to unlock
/// the key store — the passphrase is never persisted on disk.
use anyhow::{Context, Result};
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use base64::Engine as _;
use std::path::PathBuf;

pub struct KeyStore {
    dir:            PathBuf,
    encryption_key: [u8; 32],
}

impl KeyStore {
    /// Open the key store, deriving the encryption key from `passphrase`.
    ///
    /// Creates the store directory if it does not exist.
    pub fn open(dir: PathBuf, passphrase: &str) -> Result<Self> {
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("Cannot create key store dir: {}", dir.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).ok();
        }

        let encryption_key = derive_key(passphrase);
        Ok(Self { dir, encryption_key })
    }

    /// Returns `true` if a subkey for `api_key_id` is stored.
    pub fn has(&self, api_key_id: &str) -> bool {
        self.key_path(api_key_id).exists()
    }

    /// Store an ed25519 subkey encrypted at rest.
    pub fn store(&self, api_key_id: &str, signing_key: &ed25519_dalek::SigningKey) -> Result<()> {
        use aes_gcm::aead::rand_core::RngCore;

        let plaintext = signing_key.to_bytes(); // 32-byte seed

        // Random 12-byte nonce
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let cipher = Aes256Gcm::new_from_slice(&self.encryption_key)
            .map_err(|e| anyhow::anyhow!("AES init failed: {e}"))?;
        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_ref())
            .map_err(|_| anyhow::anyhow!("Encryption failed for key {api_key_id}"))?;

        // Store as JSON: { nonce: base64, ct: base64 }
        let blob = serde_json::json!({
            "v":     1,
            "nonce": base64::engine::general_purpose::STANDARD.encode(nonce_bytes),
            "ct":    base64::engine::general_purpose::STANDARD.encode(&ciphertext),
        });

        let path = self.key_path(api_key_id);
        std::fs::write(&path, blob.to_string())
            .with_context(|| format!("Failed to write key file: {}", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).ok();
        }
        Ok(())
    }

    /// Load and decrypt an ed25519 subkey.
    pub fn load(&self, api_key_id: &str) -> Result<ed25519_dalek::SigningKey> {
        let path = self.key_path(api_key_id);
        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("Key not found in store: {api_key_id}"))?;

        let blob: serde_json::Value = serde_json::from_str(&content)
            .context("Failed to parse key store entry")?;

        let nonce_bytes = base64::engine::general_purpose::STANDARD
            .decode(blob["nonce"].as_str().context("Missing nonce")?)
            .context("Failed to decode nonce")?;
        let ciphertext = base64::engine::general_purpose::STANDARD
            .decode(blob["ct"].as_str().context("Missing ct")?)
            .context("Failed to decode ciphertext")?;

        if nonce_bytes.len() != 12 {
            anyhow::bail!("Invalid nonce length in key store for {api_key_id}");
        }
        let nonce = Nonce::from_slice(&nonce_bytes);
        let cipher = Aes256Gcm::new_from_slice(&self.encryption_key)
            .map_err(|e| anyhow::anyhow!("AES init failed: {e}"))?;
        let plaintext = cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|_| anyhow::anyhow!("Decryption failed for {api_key_id} — wrong passphrase?"))?;

        if plaintext.len() != 32 {
            anyhow::bail!("Unexpected key length {} for {api_key_id}", plaintext.len());
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&plaintext);
        Ok(ed25519_dalek::SigningKey::from_bytes(&seed))
    }

    /// List all API key IDs that have stored subkeys.
    pub fn list(&self) -> Vec<String> {
        std::fs::read_dir(&self.dir)
            .map(|entries| {
                entries
                    .filter_map(|e| e.ok())
                    .filter_map(|e| {
                        let name = e.file_name().to_string_lossy().to_string();
                        if name.ends_with(".key") {
                            Some(name.trim_end_matches(".key").to_string())
                        } else {
                            None
                        }
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Default key store directory.
    pub fn default_dir() -> PathBuf {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".holder-signer")
            .join("keys")
    }

    fn key_path(&self, api_key_id: &str) -> PathBuf {
        // Sanitise: keep only alphanumeric, dash, dot (matches our key ID format)
        let safe: String = api_key_id
            .chars()
            .map(|c| if c.is_alphanumeric() || c == '-' || c == '.' { c } else { '_' })
            .collect();
        self.dir.join(format!("{safe}.key"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn temp_store_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("holder-keystore-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("temp keystore dir");
        dir
    }

    #[test]
    fn list_empty_store() {
        let dir = temp_store_dir();
        let store = KeyStore::open(dir.clone(), "test-passphrase").unwrap();
        assert!(store.list().is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(8))]

        /// Encrypt/decrypt round-trip recovers the same ed25519 signing key.
        #[test]
        fn prop_store_load_roundtrip(
            seed in prop::array::uniform32(0u8..=255),
            passphrase in r"[a-zA-Z0-9_-]{8,24}",
            key_id in r"[a-zA-Z0-9._-]{4,24}",
        ) {
            let dir = temp_store_dir();
            let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
            let store = KeyStore::open(dir.clone(), &passphrase).unwrap();
            store.store(&key_id, &signing_key).unwrap();
            prop_assert!(store.has(&key_id));
            let loaded = store.load(&key_id).unwrap();
            prop_assert_eq!(loaded.to_bytes(), signing_key.to_bytes());
            prop_assert!(store.list().contains(&key_id));
            let _ = std::fs::remove_dir_all(dir);
        }

        /// Wrong passphrase must not decrypt stored subkeys.
        #[test]
        fn prop_wrong_passphrase_fails(
            seed in prop::array::uniform32(0u8..=255),
            passphrase in r"[a-zA-Z0-9_-]{8,24}",
            wrong in r"[a-zA-Z0-9_-]{8,24}",
            key_id in r"[a-zA-Z0-9._-]{4,24}",
        ) {
            prop_assume!(passphrase != wrong);
            let dir = temp_store_dir();
            let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
            let store = KeyStore::open(dir.clone(), &passphrase).unwrap();
            store.store(&key_id, &signing_key).unwrap();
            let bad = KeyStore::open(dir.clone(), &wrong).unwrap();
            prop_assert!(bad.load(&key_id).is_err());
            let _ = std::fs::remove_dir_all(dir);
        }

        /// Key IDs are sanitised consistently on store and load.
        #[test]
        fn prop_sanitised_key_id_roundtrip(
            seed in prop::array::uniform32(0u8..=255),
            passphrase in r"[a-zA-Z0-9_-]{8,24}",
        ) {
            let dir = temp_store_dir();
            let key_id = "0xabc.def-123";
            let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
            let store = KeyStore::open(dir.clone(), &passphrase).unwrap();
            store.store(key_id, &signing_key).unwrap();
            let loaded = store.load(key_id).unwrap();
            prop_assert_eq!(loaded.to_bytes(), signing_key.to_bytes());
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

/// Derive a 32-byte AES key from a passphrase using PBKDF2-SHA256.
fn derive_key(passphrase: &str) -> [u8; 32] {
    let salt = b"safu-signer-keystore-v1";
    let mut key = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(passphrase.as_bytes(), salt, 100_000, &mut key);
    key
}
