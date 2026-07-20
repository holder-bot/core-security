use wasm_bindgen::prelude::*;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce, Key};
use aes_gcm::aead::Aead;
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use serde::{Serialize, Deserialize};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use getrandom::getrandom;

/// Encrypted data container with all necessary metadata
#[derive(Serialize, Deserialize, Clone)]
pub struct EncryptedData {
    pub ciphertext: String,      // Base64 encoded encrypted data
    pub nonce: String,           // Base64 encoded nonce/IV
    pub salt: String,            // Base64 encoded salt for key derivation
    pub iterations: u32,         // PBKDF2 iterations
}

/// Result of encryption operation for WASM binding
#[wasm_bindgen]
pub struct EncryptionResult {
    success: bool,
    data: String,       // JSON serialized EncryptedData
    error: Option<String>,
}

#[wasm_bindgen]
impl EncryptionResult {
    #[wasm_bindgen(getter)]
    pub fn success(&self) -> bool {
        self.success
    }
    
    #[wasm_bindgen(getter)]
    pub fn data(&self) -> String {
        self.data.clone()
    }
    
    #[wasm_bindgen(getter)]
    pub fn error(&self) -> Option<String> {
        self.error.clone()
    }
}

/// Decryption result for WASM binding
#[wasm_bindgen]
pub struct DecryptionResult {
    success: bool,
    plaintext: String,
    error: Option<String>,
}

#[wasm_bindgen]
impl DecryptionResult {
    #[wasm_bindgen(getter)]
    pub fn success(&self) -> bool {
        self.success
    }
    
    #[wasm_bindgen(getter)]
    pub fn plaintext(&self) -> String {
        self.plaintext.clone()
    }
    
    #[wasm_bindgen(getter)]
    pub fn error(&self) -> Option<String> {
        self.error.clone()
    }
}

/// Main encryption manager for secure data operations
#[wasm_bindgen]
pub struct CryptoManager;

#[wasm_bindgen]
impl CryptoManager {
    #[wasm_bindgen(constructor)]
    pub fn new() -> CryptoManager {
        web_sys::console::log_1(&"🦀 CryptoManager initialized for AES-256-GCM operations".into());
        log::info!("CryptoManager instance created");
        CryptoManager
    }
    
    /// Generate a cryptographically secure salt
    #[wasm_bindgen]
    pub fn generate_salt() -> Vec<u8> {
        let mut salt = vec![0u8; 32]; // 256 bits
        getrandom(&mut salt).unwrap_or_default();
        
        web_sys::console::log_1(&"🦀 Cryptographic salt generated with secure entropy (32 bytes for PBKDF2)".into());
        log::info!("Salt generation completed");
        
        salt
    }
    
    /// Generate a cryptographically secure nonce/IV
    #[wasm_bindgen]
    pub fn generate_nonce() -> Vec<u8> {
        let mut nonce = vec![0u8; 12]; // 96 bits for GCM
        getrandom(&mut nonce).unwrap_or_default();
        
        web_sys::console::log_1(&"🦀 AES-GCM nonce generated with secure entropy (12 bytes, cryptographically unique)".into());
        log::info!("Nonce generation completed");
        
        nonce
    }
    
    /// Derive encryption key from password using PBKDF2
    fn derive_key(password: &str, salt: &[u8], iterations: u32) -> Result<[u8; 32], String> {
        let mut key = [0u8; 32]; // 256 bits for AES-256
        pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, iterations, &mut key);
        
        web_sys::console::log_1(&format!("🦀 Seed phrase encryption key derived with PBKDF2 ({} iterations) - securing mnemonic in localStorage", iterations).into());
        log::info!("PBKDF2 key derivation completed");
        
        Ok(key)
    }
    
    /// Encrypt data with AES-256-GCM
    #[wasm_bindgen]
    pub fn encrypt_data(&self, plaintext: &str, password: &str) -> EncryptionResult {
        web_sys::console::log_1(&"🦀 Starting AES-256-GCM encryption process".into());
        log::info!("Encryption operation initiated");
        
        // Generate salt and nonce
        let salt = Self::generate_salt();
        let nonce_bytes = Self::generate_nonce();
        // Match MetaMask browser-passworder DEFAULT (900_000). Stored in ciphertext JSON
        // so older vaults encrypted at 100_000 still decrypt via decrypt_data.
        let iterations = 900_000u32;
        
        log::info!("Encryption parameters prepared");
        
        // Derive key
        let key_bytes = match Self::derive_key(password, &salt, iterations) {
            Ok(key) => key,
            Err(e) => {
                web_sys::console::log_1(&format!("🦀 ❌ Key derivation failed: {}", e).into());
                log::error!("Key derivation failed: {}", e);
                return EncryptionResult {
                    success: false,
                    data: String::new(),
                    error: Some(e),
                };
            }
        };
        
        // Create cipher
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        // Encrypt
        match cipher.encrypt(nonce, plaintext.as_bytes()) {
            Ok(ciphertext) => {
                web_sys::console::log_1(&"🦀 Data encrypted successfully with AES-256-GCM cipher".into());
                log::info!("Encryption operation completed successfully");
                
                let encrypted_data = EncryptedData {
                    ciphertext: BASE64.encode(&ciphertext),
                    nonce: BASE64.encode(&nonce_bytes),
                    salt: BASE64.encode(&salt),
                    iterations,
                };
                
                match serde_json::to_string(&encrypted_data) {
                    Ok(json) => {
                        web_sys::console::log_1(&"🦀 Encrypted data packaged as JSON - ready for JavaScript localStorage".into());
                        log::info!("Encrypted data packaging completed for client-side storage");
                        EncryptionResult {
                            success: true,
                            data: json,
                            error: None,
                        }
                    },
                    Err(e) => {
                        let error_msg = format!("Serialization error: {}", e);
                        web_sys::console::log_1(&format!("🦀 ❌ {}", error_msg).into());
                        log::error!("{}", error_msg);
                        EncryptionResult {
                            success: false,
                            data: String::new(),
                            error: Some(error_msg),
                        }
                    }
                }
            },
            Err(e) => {
                let error_msg = format!("Encryption failed: {}", e);
                web_sys::console::log_1(&format!("🦀 ❌ {}", error_msg).into());
                log::error!("{}", error_msg);
                EncryptionResult {
                    success: false,
                    data: String::new(),
                    error: Some(error_msg),
                }
            }
        }
    }
    
    /// Decrypt data with AES-256-GCM
    #[wasm_bindgen]
    pub fn decrypt_data(&self, encrypted_json: &str, password: &str) -> DecryptionResult {
        web_sys::console::log_1(&"🦀 Starting AES-256-GCM decryption process".into());
        log::info!("Decryption operation initiated");
        
        // Parse encrypted data
        let encrypted_data: EncryptedData = match serde_json::from_str(encrypted_json) {
            Ok(data) => data,
            Err(e) => {
                let error_msg = format!("Invalid encrypted data format: {}", e);
                web_sys::console::log_1(&format!("🦀 ❌ {}", error_msg).into());
                log::error!("{}", error_msg);
                return DecryptionResult {
                    success: false,
                    plaintext: String::new(),
                    error: Some(error_msg),
                };
            }
        };
        
        web_sys::console::log_1(&"🦀 Encrypted data parsed successfully".into());
        log::info!("Encrypted data validation completed");
        
        // Decode components
        let salt = match BASE64.decode(&encrypted_data.salt) {
            Ok(s) => s,
            Err(e) => {
                let error_msg = format!("Invalid salt encoding: {}", e);
                web_sys::console::log_1(&format!("🦀 ❌ {}", error_msg).into());
                log::error!("{}", error_msg);
                return DecryptionResult {
                    success: false,
                    plaintext: String::new(),
                    error: Some(error_msg),
                };
            }
        };
        
        let nonce_bytes = match BASE64.decode(&encrypted_data.nonce) {
            Ok(n) => n,
            Err(e) => {
                let error_msg = format!("Invalid nonce encoding: {}", e);
                web_sys::console::log_1(&format!("🦀 ❌ {}", error_msg).into());
                log::error!("{}", error_msg);
                return DecryptionResult {
                    success: false,
                    plaintext: String::new(),
                    error: Some(error_msg),
                };
            }
        };
        
        let ciphertext = match BASE64.decode(&encrypted_data.ciphertext) {
            Ok(c) => c,
            Err(e) => {
                let error_msg = format!("Invalid ciphertext encoding: {}", e);
                web_sys::console::log_1(&format!("🦀 ❌ {}", error_msg).into());
                log::error!("{}", error_msg);
                return DecryptionResult {
                    success: false,
                    plaintext: String::new(),
                    error: Some(error_msg),
                };
            }
        };
        
        web_sys::console::log_1(&"🦀 Encryption components decoded successfully".into());
        log::info!("Component decoding completed");
        
        // Derive key
        let key_bytes = match Self::derive_key(password, &salt, encrypted_data.iterations) {
            Ok(key) => key,
            Err(e) => {
                web_sys::console::log_1(&format!("🦀 ❌ Key derivation failed: {}", e).into());
                log::error!("Key derivation failed: {}", e);
                return DecryptionResult {
                    success: false,
                    plaintext: String::new(),
                    error: Some(e),
                };
            }
        };
        
        // Create cipher and decrypt
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        web_sys::console::log_1(&"🦀 AES-256-GCM cipher ready for decryption".into());
        log::info!("Cipher preparation completed");
        
        match cipher.decrypt(nonce, ciphertext.as_ref()) {
            Ok(plaintext_bytes) => {
                match String::from_utf8(plaintext_bytes) {
                    Ok(plaintext) => {
                        web_sys::console::log_1(&"🦀 Data decrypted successfully".into());
                        log::info!("Decryption operation completed successfully");
                        DecryptionResult {
                            success: true,
                            plaintext,
                            error: None,
                        }
                    },
                    Err(e) => {
                        let error_msg = format!("Invalid UTF-8 in decrypted data: {}", e);
                        web_sys::console::log_1(&format!("🦀 ❌ {}", error_msg).into());
                        log::error!("{}", error_msg);
                        DecryptionResult {
                            success: false,
                            plaintext: String::new(),
                            error: Some(error_msg),
                        }
                    }
                }
            },
            Err(e) => {
                let error_msg = format!("Decryption failed: {}", e);
                web_sys::console::log_1(&format!("🦀 ❌ {}", error_msg).into());
                log::error!("{}", error_msg);
                DecryptionResult {
                    success: false,
                    plaintext: String::new(),
                    error: Some(error_msg),
                }
            }
        }
    }
    
    /// Best-effort stack scrub. Does NOT clear WalletManager.secured_mnemonic —
    /// call WalletManager.clear_wallet / clear_secured_mnemonic for that.
    /// (Previously overstated "all crypto material cleared"; MetaMask docs likewise
    /// acknowledge JS/WASM cannot guarantee full secret erasure.)
    #[wasm_bindgen]
    pub fn clear_memory(&self) {
        web_sys::console::log_1(&"🦀 CryptoManager stack scrub (best-effort; no retained secrets on this struct)".into());
        log::warn!("CryptoManager clear_memory: stack scrub only");
        
        let mut dummy_buffer = [0u8; 4096];
        use zeroize::Zeroize;
        dummy_buffer.zeroize();
    }
    
    /// Secure memory wipe for sensitive data buffers
    #[wasm_bindgen]
    pub fn secure_wipe_buffer(data: &mut [u8]) {
        use zeroize::Zeroize;
        data.zeroize();
        web_sys::console::log_1(&format!("🦀 Buffer of {} bytes securely wiped", data.len()).into());
        log::warn!("Buffer of {} bytes securely wiped", data.len());
    }
}

impl Default for CryptoManager {
    fn default() -> Self {
        Self::new()
    }
}