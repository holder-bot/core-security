use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::password_hash::{rand_core::OsRng, SaltString};
use aes_gcm::{Aes256Gcm, Key, Nonce, KeyInit, AeadCore, Aead};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};
use secrecy::{Secret, ExposeSecret};
use wasm_bindgen::prelude::*;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Password too weak: {0}")]
    WeakPassword(String),
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("Invalid password")]
    InvalidPassword,
    #[error("Key derivation failed")]
    KeyDerivationFailed,
}

#[derive(ZeroizeOnDrop)]
pub struct PasswordManager {
    cipher: Aes256Gcm,
    password_hash: Secret<String>,
}

#[wasm_bindgen]
impl PasswordManager {
    #[wasm_bindgen(constructor)]
    pub fn new(password: &str, salt: &[u8]) -> Result<PasswordManager, JsValue> {
        // Enhanced password validation
        Self::validate_password_strength(password)?;
        
        // Use Argon2 for password hashing (2023 winner of password hashing competition)
        let argon2 = Argon2::default();
        let salt_string = SaltString::encode_b64(salt)
            .map_err(|_| JsValue::from_str("Invalid salt"))?;
        
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt_string)
            .map_err(|_| JsValue::from_str("Password hashing failed"))?;
        
        // Derive encryption key using PBKDF2 (150,000 iterations for 2025)
        let mut key = [0u8; 32];
        pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, 150_000, &mut key);
        
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
        
        // Clear sensitive data from stack
        key.zeroize();
        
        Ok(PasswordManager {
            cipher,
            password_hash: Secret::new(password_hash.to_string()),
        })
    }

    #[wasm_bindgen]
    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, JsValue> {
        // Generate cryptographically secure nonce
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        
        // Add authentication tag for integrity
        match self.cipher.encrypt(&nonce, data) {
            Ok(ciphertext) => {
                let mut result = nonce.to_vec();
                result.extend_from_slice(&ciphertext);
                Ok(result)
            }
            Err(e) => Err(JsValue::from_str(&format!("Encryption failed: {}", e))),
        }
    }

    #[wasm_bindgen]
    pub fn decrypt(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, JsValue> {
        if encrypted_data.len() < 12 {
            return Err(JsValue::from_str("Invalid encrypted data length"));
        }
        
        let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);
        
        match self.cipher.decrypt(nonce, ciphertext) {
            Ok(plaintext) => Ok(plaintext),
            Err(e) => Err(JsValue::from_str(&format!("Decryption failed: {}", e))),
        }
    }

    #[wasm_bindgen]
    pub fn generate_secure_salt() -> Vec<u8> {
        let mut salt = [0u8; 32];
        getrandom::getrandom(&mut salt).expect("Failed to generate secure salt");
        salt.to_vec()
    }

    #[wasm_bindgen]
    pub fn validate_password_strength(password: &str) -> Result<(), JsValue> {
        let min_length = 16; // Increased from 12
        let mut score = 0;
        let mut feedback = Vec::new();

        // Length check
        if password.len() < min_length {
            feedback.push(format!("Password must be at least {} characters", min_length));
        } else {
            score += 1;
        }

        // Character variety checks
        if password.chars().any(|c| c.is_uppercase()) { score += 1; }
        else { feedback.push("Include uppercase letters".to_string()); }

        if password.chars().any(|c| c.is_lowercase()) { score += 1; }
        else { feedback.push("Include lowercase letters".to_string()); }

        if password.chars().any(|c| c.is_numeric()) { score += 1; }
        else { feedback.push("Include numbers".to_string()); }

        if password.chars().any(|c| !c.is_alphanumeric()) { score += 1; }
        else { feedback.push("Include special characters".to_string()); }

        // Entropy check
        let entropy = calculate_entropy(password);
        if entropy < 60.0 { // bits of entropy
            feedback.push("Password is too predictable".to_string());
        } else {
            score += 1;
        }

        // Common password check
        if is_common_password(password) {
            feedback.push("Password is too common".to_string());
        } else {
            score += 1;
        }

        if score < 6 {
            return Err(JsValue::from_str(&format!("Password too weak: {}", feedback.join(", "))));
        }

        Ok(())
    }

    #[wasm_bindgen]
    pub fn verify_password(&self, password: &str) -> bool {
        let parsed_hash = match PasswordHash::new(self.password_hash.expose_secret()) {
            Ok(hash) => hash,
            Err(_) => return false,
        };
        
        Argon2::default()
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok()
    }
}

fn calculate_entropy(password: &str) -> f64 {
    let mut charset_size = 0;
    if password.chars().any(|c| c.is_lowercase()) { charset_size += 26; }
    if password.chars().any(|c| c.is_uppercase()) { charset_size += 26; }
    if password.chars().any(|c| c.is_numeric()) { charset_size += 10; }
    if password.chars().any(|c| !c.is_alphanumeric()) { charset_size += 32; }
    
    (password.len() as f64) * (charset_size as f64).log2()
}

fn is_common_password(password: &str) -> bool {
    // Check against common passwords list
    const COMMON_PASSWORDS: &[&str] = &[
        "password", "123456", "password123", "admin", "qwerty",
        "letmein", "welcome", "monkey", "dragon", "master",
        "bitcoin", "solana", "crypto", "wallet", "seed",
        // Add more common passwords...
    ];
    
    COMMON_PASSWORDS.iter().any(|&common| 
        password.to_lowercase().contains(&common.to_lowercase())
    )
}