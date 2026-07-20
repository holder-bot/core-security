use bip39::{Mnemonic, Language, MnemonicType};
use tiny_hderive::bip44::DerivationPath;
use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature, Signer};
use zeroize::{Zeroize, ZeroizeOnDrop};
use secrecy::{Secret, ExposeSecret};
use wasm_bindgen::prelude::*;
use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};
use std::str::FromStr;

#[derive(Serialize, Deserialize, Debug, Clone, ZeroizeOnDrop)]
pub struct KeyPair {
    pub public_key: String,
    secret_key: Secret<Vec<u8>>,
}

#[derive(ZeroizeOnDrop)]
pub struct KeyManager {
    keypair: Option<Secret<Keypair>>,
    derivation_path: String,
}

#[wasm_bindgen]
impl KeyManager {
    #[wasm_bindgen(constructor)]
    pub fn new() -> KeyManager {
        KeyManager {
            keypair: None,
            derivation_path: "m/44'/501'/0'/0'".to_string(),
        }
    }

    /// Generate a new BIP39 mnemonic with enhanced entropy
    #[wasm_bindgen]
    pub fn generate_mnemonic() -> Result<String, JsValue> {
        // Generate 256 bits of entropy for 24-word mnemonic
        let mut entropy = [0u8; 32];
        getrandom::getrandom(&mut entropy)
            .map_err(|_| JsValue::from_str("Failed to generate secure entropy"))?;
        
        // Create BIP39 mnemonic
        let mnemonic = Mnemonic::from_entropy(&entropy, Language::English)
            .map_err(|_| JsValue::from_str("Failed to create mnemonic"))?;
        
        // Clear entropy from memory
        entropy.zeroize();
        
        Ok(mnemonic.to_string())
    }

    /// Derive keypair from mnemonic using BIP44 path
    #[wasm_bindgen]
    pub fn from_mnemonic(&mut self, mnemonic_phrase: &str, account_index: Option<u32>) -> Result<String, JsValue> {
        let account_idx = account_index.unwrap_or(0);
        
        web_sys::console::log_1(&format!("🦀 Processing mnemonic import via KeyManager (account: {})...", account_idx).into());
        log::info!("Starting KeyManager mnemonic import for account: {}", account_idx);
        
        if mnemonic_phrase.is_empty() {
            let error_msg = "Mnemonic phrase cannot be empty";
            web_sys::console::log_1(&format!("🦀 ❌ {}", error_msg).into());
            log::error!("{}", error_msg);
            return Err(JsValue::from_str(error_msg));
        }
        
        // Validate and parse mnemonic
        web_sys::console::log_1(&"🦀 Validating BIP39 mnemonic phrase...".into());
        log::info!("Validating BIP39 mnemonic phrase");
        
        let mnemonic = Mnemonic::from_phrase(mnemonic_phrase, Language::English)
            .map_err(|e| {
                let error_msg = format!("Invalid mnemonic: {}", e);
                web_sys::console::log_1(&format!("🦀 ❌ {}", error_msg).into());
                log::error!("{}", error_msg);
                JsValue::from_str(&error_msg)
            })?;
        
        // Validate mnemonic checksum
        web_sys::console::log_1(&"🦀 Verifying mnemonic checksum...".into());
        log::info!("Verifying mnemonic checksum");
        
        if !mnemonic.validate_checksum() {
            let error_msg = "Invalid mnemonic checksum";
            web_sys::console::log_1(&format!("🦀 ❌ {}", error_msg).into());
            log::error!("{}", error_msg);
            return Err(JsValue::from_str(error_msg));
        }
        
        // Generate seed from mnemonic
        web_sys::console::log_1(&"🦀 Generating BIP39 seed from mnemonic...".into());
        log::info!("Generating BIP39 seed from mnemonic");
        let seed = mnemonic.to_seed("");
        
        // Derive key using BIP44 path for Solana
        let derivation_path = format!("m/44'/501'/{}'/0'", account_idx);
        web_sys::console::log_1(&format!("🦀 Using BIP44 derivation path: {}", derivation_path).into());
        log::info!("Using BIP44 derivation path: {}", derivation_path);
        
        let path = DerivationPath::from_str(&derivation_path)
            .map_err(|e| {
                let error_msg = format!("Invalid derivation path: {}", e);
                web_sys::console::log_1(&format!("🦀 ❌ {}", error_msg).into());
                log::error!("{}", error_msg);
                JsValue::from_str(&error_msg)
            })?;
        
        // Derive the key
        web_sys::console::log_1(&"🦀 Performing hierarchical key derivation...".into());
        log::info!("Performing hierarchical key derivation");
        
        let derived_key = path.derive(&seed[..32])
            .map_err(|e| {
                let error_msg = format!("Key derivation failed: {}", e);
                web_sys::console::log_1(&format!("🦀 ❌ {}", error_msg).into());
                log::error!("{}", error_msg);
                JsValue::from_str(&error_msg)
            })?;
        
        // Create Ed25519 keypair
        web_sys::console::log_1(&"🦀 Creating Ed25519 keypair from derived key...".into());
        log::info!("Creating Ed25519 keypair from derived key");
        
        let secret_key = SecretKey::from_bytes(&derived_key)
            .map_err(|e| {
                let error_msg = format!("Invalid derived key: {}", e);
                web_sys::console::log_1(&format!("🦀 ❌ {}", error_msg).into());
                log::error!("{}", error_msg);
                JsValue::from_str(&error_msg)
            })?;
        let public_key = PublicKey::from(&secret_key);
        
        let keypair = Keypair { secret: secret_key, public: public_key };
        let public_key_str = bs58::encode(public_key.as_bytes()).into_string();
        
        // Store keypair securely
        web_sys::console::log_1(&"🦀 Storing keypair in secure memory...".into());
        log::info!("Storing keypair in secure memory");
        
        self.keypair = Some(Secret::new(keypair));
        self.derivation_path = derivation_path;
        
        web_sys::console::log_1(&format!("🦀 ✅ KeyManager mnemonic import successful! Public key: {}", &public_key_str[..8]).into());
        log::info!("KeyManager mnemonic import completed successfully");
        
        Ok(public_key_str)
    }

    /// Create keypair from private key
    #[wasm_bindgen]
    pub fn from_private_key(&mut self, private_key_base58: &str) -> Result<String, JsValue> {
        // Decode base58 private key
        let private_key_bytes = bs58::decode(private_key_base58)
            .into_vec()
            .map_err(|_| JsValue::from_str("Invalid private key format"))?;
        
        // Validate key length (64 bytes for ed25519)
        if private_key_bytes.len() != 64 {
            return Err(JsValue::from_str("Invalid private key length"));
        }
        
        // Create keypair from private key
        let secret_key = SecretKey::from_bytes(&private_key_bytes[..32])
            .map_err(|_| JsValue::from_str("Invalid secret key"))?;
        let public_key = PublicKey::from(&secret_key);
        let keypair = Keypair { secret: secret_key, public: public_key };
        
        // Validate keypair integrity
        let test_message = b"test_message";
        let signature = keypair.sign(test_message);
        if keypair.public.verify(test_message, &signature).is_err() {
            return Err(JsValue::from_str("Invalid keypair"));
        }
        
        let public_key_str = bs58::encode(public_key.as_bytes()).into_string();
        self.keypair = Some(Secret::new(keypair));
        
        Ok(public_key_str)
    }

    /// Get public key
    #[wasm_bindgen]
    pub fn get_public_key(&self) -> Result<String, JsValue> {
        match &self.keypair {
            Some(kp) => Ok(bs58::encode(kp.expose_secret().public.as_bytes()).into_string()),
            None => Err(JsValue::from_str("No keypair loaded")),
        }
    }

    /// Export private key (with security warning)
    #[wasm_bindgen]
    pub fn export_private_key(&self) -> Result<String, JsValue> {
        // SECURITY: Private key export disabled for security
        Err(JsValue::from_str("SECURITY: Private key export disabled. Use WASM signing methods instead."))
    }

    /// Sign message with the keypair
    #[wasm_bindgen]
    pub fn sign_message(&self, message: &[u8]) -> Result<Vec<u8>, JsValue> {
        match &self.keypair {
            Some(kp) => {
                let signature = kp.expose_secret().sign(message);
                Ok(signature.to_bytes().to_vec())
            },
            None => Err(JsValue::from_str("No keypair loaded")),
        }
    }

    /// Verify signature
    #[wasm_bindgen]
    pub fn verify_signature(&self, message: &[u8], signature: &[u8]) -> Result<bool, JsValue> {
        match &self.keypair {
            Some(kp) => {
                if signature.len() != 64 {
                    return Ok(false);
                }
                
                let sig = Signature::from_bytes(signature)
                    .map_err(|_| JsValue::from_str("Invalid signature format"))?;
                
                let is_valid = kp.expose_secret().public.verify(message, &sig).is_ok();
                Ok(is_valid)
            },
            None => Err(JsValue::from_str("No keypair loaded")),
        }
    }

    /// Generate deterministic keypair from seed
    #[wasm_bindgen]
    pub fn from_seed(&mut self, seed: &[u8]) -> Result<String, JsValue> {
        web_sys::console::log_1(&"🦀 Processing raw seed import via KeyManager...".into());
        log::info!("Starting KeyManager raw seed import");
        
        if seed.len() != 32 {
            let error_msg = format!("Seed must be 32 bytes, got {} bytes", seed.len());
            web_sys::console::log_1(&format!("🦀 ❌ {}", error_msg).into());
            log::error!("{}", error_msg);
            return Err(JsValue::from_str(&error_msg));
        }
        
        web_sys::console::log_1(&"🦀 Creating Ed25519 keypair from raw seed...".into());
        log::info!("Creating Ed25519 keypair from raw seed");
        
        let secret_key = SecretKey::from_bytes(seed)
            .map_err(|e| {
                let error_msg = format!("Invalid seed: {}", e);
                web_sys::console::log_1(&format!("🦀 ❌ {}", error_msg).into());
                log::error!("{}", error_msg);
                JsValue::from_str(&error_msg)
            })?;
        let public_key = PublicKey::from(&secret_key);
        
        let keypair = Keypair { secret: secret_key, public: public_key };
        let public_key_str = bs58::encode(public_key.as_bytes()).into_string();
        
        web_sys::console::log_1(&"🦀 Storing keypair from seed in secure memory...".into());
        log::info!("Storing keypair from seed in secure memory");
        
        self.keypair = Some(Secret::new(keypair));
        
        web_sys::console::log_1(&format!("🦀 ✅ KeyManager seed import successful! Public key: {}", &public_key_str[..8]).into());
        log::info!("KeyManager seed import completed successfully");
        
        Ok(public_key_str)
    }

    /// Derive child key from current key
    #[wasm_bindgen]
    pub fn derive_child_key(&self, index: u32) -> Result<String, JsValue> {
        match &self.keypair {
            Some(kp) => {
                let mut hasher = Sha256::new();
                hasher.update(kp.expose_secret().secret.as_bytes());
                hasher.update(index.to_be_bytes());
                let child_seed = hasher.finalize();
                
                let secret_key = SecretKey::from_bytes(child_seed.as_slice())
                    .map_err(|_| JsValue::from_str("Failed to derive child key"))?;
                let public_key = PublicKey::from(&secret_key);
                
                Ok(bs58::encode(public_key.as_bytes()).into_string())
            },
            None => Err(JsValue::from_str("No keypair loaded")),
        }
    }

    /// Generate secure random bytes
    #[wasm_bindgen]
    pub fn generate_random_bytes(length: usize) -> Result<Vec<u8>, JsValue> {
        let mut bytes = vec![0u8; length];
        getrandom::getrandom(&mut bytes)
            .map_err(|_| JsValue::from_str("Failed to generate random bytes"))?;
        Ok(bytes)
    }

    /// Clear the keypair from memory
    #[wasm_bindgen]
    pub fn clear_keypair(&mut self) {
        self.keypair = None;
    }

    /// Check if keypair is loaded
    #[wasm_bindgen]
    pub fn is_keypair_loaded(&self) -> bool {
        self.keypair.is_some()
    }

    /// Get derivation path
    #[wasm_bindgen]
    pub fn get_derivation_path(&self) -> String {
        self.derivation_path.clone()
    }

    /// Validate mnemonic phrase
    #[wasm_bindgen]
    pub fn validate_mnemonic(mnemonic_phrase: &str) -> Result<bool, JsValue> {
        match Mnemonic::from_phrase(mnemonic_phrase, Language::English) {
            Ok(mnemonic) => Ok(mnemonic.validate_checksum()),
            Err(_) => Ok(false),
        }
    }

    /// Generate entropy for mnemonic
    #[wasm_bindgen]
    pub fn generate_entropy(byte_count: usize) -> Result<Vec<u8>, JsValue> {
        if byte_count != 16 && byte_count != 20 && byte_count != 24 && byte_count != 28 && byte_count != 32 {
            return Err(JsValue::from_str("Invalid entropy size. Must be 16, 20, 24, 28, or 32 bytes"));
        }
        
        let mut entropy = vec![0u8; byte_count];
        getrandom::getrandom(&mut entropy)
            .map_err(|_| JsValue::from_str("Failed to generate entropy"))?;
        
        Ok(entropy)
    }
}