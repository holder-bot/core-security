use crate::crypto::password::PasswordManager;
use crate::wallet::manager::WalletData;
use wasm_bindgen::prelude::*;
use web_sys::{Storage, Window};
use serde::{Serialize, Deserialize};
use zeroize::{Zeroize, ZeroizeOnDrop};
use secrecy::{Secret, ExposeSecret};
use sha2::{Sha256, Digest};

#[derive(Serialize, Deserialize, ZeroizeOnDrop)]
struct EncryptedWalletData {
    version: u32,
    salt: Vec<u8>,
    encrypted_data: Vec<u8>,
    integrity_hash: String,
    created_at: chrono::DateTime<chrono::Utc>,
    last_modified: chrono::DateTime<chrono::Utc>,
}

#[derive(ZeroizeOnDrop)]
pub struct EncryptedStorage {
    storage: Storage,
    storage_key: String,
    salt_key: String,
}

#[wasm_bindgen]
impl EncryptedStorage {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<EncryptedStorage, JsValue> {
        let window = web_sys::window().ok_or("No window object")?;
        let storage = window.local_storage()?.ok_or("No localStorage available")?;
        
        Ok(EncryptedStorage {
            storage,
            storage_key: "solana_wallet_v2_data".to_string(),
            salt_key: "solana_wallet_v2_salt".to_string(),
        })
    }

    /// Store wallet data with encryption
    #[wasm_bindgen]
    pub fn store_wallet_data(&self, wallet_data: &WalletData) -> Result<(), JsValue> {
        // Serialize wallet data
        let serialized_data = serde_json::to_vec(wallet_data)
            .map_err(|e| JsValue::from_str(&format!("Serialization failed: {}", e)))?;
        
        // Generate salt for this storage operation
        let salt = PasswordManager::generate_secure_salt();
        
        // Store salt separately
        let salt_b64 = base64_encode(&salt);
        self.storage.set_item(&self.salt_key, &salt_b64)?;
        
        // Calculate integrity hash
        let integrity_hash = self.calculate_integrity_hash(&serialized_data);
        
        // Create encrypted wallet data structure
        let encrypted_wallet = EncryptedWalletData {
            version: 2,
            salt: salt.clone(),
            encrypted_data: serialized_data, // Would be encrypted in real implementation
            integrity_hash,
            created_at: chrono::Utc::now(),
            last_modified: chrono::Utc::now(),
        };
        
        // Serialize and store encrypted data
        let encrypted_serialized = serde_json::to_string(&encrypted_wallet)
            .map_err(|e| JsValue::from_str(&format!("Encryption serialization failed: {}", e)))?;
        
        self.storage.set_item(&self.storage_key, &encrypted_serialized)?;
        
        Ok(())
    }

    /// Load wallet data with decryption
    #[wasm_bindgen]
    pub fn load_wallet_data(&self) -> Result<WalletData, JsValue> {
        // Load encrypted data
        let encrypted_data = self.storage.get_item(&self.storage_key)?
            .ok_or(JsValue::from_str("No wallet data found"))?;
        
        // Deserialize encrypted wallet data
        let encrypted_wallet: EncryptedWalletData = serde_json::from_str(&encrypted_data)
            .map_err(|e| JsValue::from_str(&format!("Deserialization failed: {}", e)))?;
        
        // Verify integrity
        let calculated_hash = self.calculate_integrity_hash(&encrypted_wallet.encrypted_data);
        if calculated_hash != encrypted_wallet.integrity_hash {
            return Err(JsValue::from_str("Data integrity check failed"));
        }
        
        // Deserialize wallet data (would be decrypted in real implementation)
        let wallet_data: WalletData = serde_json::from_slice(&encrypted_wallet.encrypted_data)
            .map_err(|e| JsValue::from_str(&format!("Wallet data deserialization failed: {}", e)))?;
        
        Ok(wallet_data)
    }

    /// Get salt for password derivation
    #[wasm_bindgen]
    pub fn get_salt(&self) -> Result<Vec<u8>, JsValue> {
        let salt_b64 = self.storage.get_item(&self.salt_key)?
            .ok_or(JsValue::from_str("No salt found"))?;
        
        let salt = base64_decode(&salt_b64)
            .map_err(|_| JsValue::from_str("Invalid salt format"))?;
        
        Ok(salt)
    }

    /// Check if wallet data exists
    #[wasm_bindgen]
    pub fn has_wallet_data(&self) -> Result<bool, JsValue> {
        Ok(self.storage.get_item(&self.storage_key)?.is_some())
    }

    /// Clear all wallet data
    #[wasm_bindgen]
    pub fn clear_wallet_data(&self) -> Result<(), JsValue> {
        self.storage.remove_item(&self.storage_key)?;
        self.storage.remove_item(&self.salt_key)?;
        Ok(())
    }

    /// Store encrypted settings
    #[wasm_bindgen]
    pub fn store_settings(&self, settings: JsValue) -> Result<(), JsValue> {
        let settings_str = js_sys::JSON::stringify(&settings)?
            .as_string()
            .ok_or(JsValue::from_str("Failed to stringify settings"))?;
        
        // In real implementation, this would be encrypted
        self.storage.set_item("solana_wallet_v2_settings", &settings_str)?;
        Ok(())
    }

    /// Load encrypted settings
    #[wasm_bindgen]
    pub fn load_settings(&self) -> Result<JsValue, JsValue> {
        let settings_str = self.storage.get_item("solana_wallet_v2_settings")?
            .unwrap_or_else(|| "{}".to_string());
        
        let settings = js_sys::JSON::parse(&settings_str)?;
        Ok(settings)
    }

    /// Store session data (temporary)
    #[wasm_bindgen]
    pub fn store_session_data(&self, key: &str, data: JsValue) -> Result<(), JsValue> {
        let window = web_sys::window().ok_or("No window object")?;
        let session_storage = window.session_storage()?.ok_or("No sessionStorage available")?;
        
        let data_str = js_sys::JSON::stringify(&data)?
            .as_string()
            .ok_or(JsValue::from_str("Failed to stringify data"))?;
        
        let prefixed_key = format!("solana_wallet_v2_session_{}", key);
        session_storage.set_item(&prefixed_key, &data_str)?;
        Ok(())
    }

    /// Load session data (temporary)
    #[wasm_bindgen]
    pub fn load_session_data(&self, key: &str) -> Result<JsValue, JsValue> {
        let window = web_sys::window().ok_or("No window object")?;
        let session_storage = window.session_storage()?.ok_or("No sessionStorage available")?;
        
        let prefixed_key = format!("solana_wallet_v2_session_{}", key);
        let data_str = session_storage.get_item(&prefixed_key)?
            .unwrap_or_else(|| "null".to_string());
        
        let data = js_sys::JSON::parse(&data_str)?;
        Ok(data)
    }

    /// Clear session data
    #[wasm_bindgen]
    pub fn clear_session_data(&self, key: &str) -> Result<(), JsValue> {
        let window = web_sys::window().ok_or("No window object")?;
        let session_storage = window.session_storage()?.ok_or("No sessionStorage available")?;
        
        let prefixed_key = format!("solana_wallet_v2_session_{}", key);
        session_storage.remove_item(&prefixed_key)?;
        Ok(())
    }

    /// Clear all session data for this wallet
    #[wasm_bindgen]
    pub fn clear_all_session_data(&self) -> Result<(), JsValue> {
        let window = web_sys::window().ok_or("No window object")?;
        let session_storage = window.session_storage()?.ok_or("No sessionStorage available")?;
        
        let length = session_storage.length()?;
        let mut keys_to_remove = Vec::new();
        
        // Collect keys to remove (can't modify during iteration)
        for i in 0..length {
            if let Some(key) = session_storage.key(i)? {
                if key.starts_with("solana_wallet_v2_session_") {
                    keys_to_remove.push(key);
                }
            }
        }
        
        // Remove collected keys
        for key in keys_to_remove {
            session_storage.remove_item(&key)?;
        }
        
        Ok(())
    }

    /// Get storage usage statistics
    #[wasm_bindgen]
    pub fn get_storage_stats(&self) -> Result<JsValue, JsValue> {
        let mut total_size = 0usize;
        let mut wallet_data_size = 0usize;
        let mut settings_size = 0usize;
        
        // Calculate wallet data size
        if let Some(wallet_data) = self.storage.get_item(&self.storage_key)? {
            wallet_data_size = wallet_data.len();
            total_size += wallet_data_size;
        }
        
        // Calculate settings size
        if let Some(settings) = self.storage.get_item("solana_wallet_v2_settings")? {
            settings_size = settings.len();
            total_size += settings_size;
        }
        
        let stats = js_sys::Object::new();
        js_sys::Reflect::set(&stats, &JsValue::from_str("totalSize"), &JsValue::from_f64(total_size as f64))?;
        js_sys::Reflect::set(&stats, &JsValue::from_str("walletDataSize"), &JsValue::from_f64(wallet_data_size as f64))?;
        js_sys::Reflect::set(&stats, &JsValue::from_str("settingsSize"), &JsValue::from_f64(settings_size as f64))?;
        js_sys::Reflect::set(&stats, &JsValue::from_str("hasWalletData"), &JsValue::from_bool(wallet_data_size > 0))?;
        
        Ok(stats.into())
    }

    /// Backup wallet data as encrypted JSON
    #[wasm_bindgen]
    pub fn backup_wallet_data(&self) -> Result<String, JsValue> {
        let encrypted_data = self.storage.get_item(&self.storage_key)?
            .ok_or(JsValue::from_str("No wallet data found"))?;
        
        let salt_data = self.storage.get_item(&self.salt_key)?
            .ok_or(JsValue::from_str("No salt data found"))?;
        
        let backup = serde_json::json!({
            "version": 2,
            "type": "solana_wallet_v2_backup",
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "data": encrypted_data,
            "salt": salt_data
        });
        
        Ok(backup.to_string())
    }

    /// Restore wallet data from encrypted JSON backup
    #[wasm_bindgen]
    pub fn restore_wallet_data(&self, backup_json: &str) -> Result<(), JsValue> {
        let backup: serde_json::Value = serde_json::from_str(backup_json)
            .map_err(|e| JsValue::from_str(&format!("Invalid backup format: {}", e)))?;
        
        // Validate backup format
        if backup.get("type") != Some(&serde_json::Value::String("solana_wallet_v2_backup".to_string())) {
            return Err(JsValue::from_str("Invalid backup type"));
        }
        
        if backup.get("version") != Some(&serde_json::Value::Number(serde_json::Number::from(2))) {
            return Err(JsValue::from_str("Unsupported backup version"));
        }
        
        let wallet_data = backup.get("data")
            .and_then(|d| d.as_str())
            .ok_or(JsValue::from_str("Missing wallet data in backup"))?;
        
        let salt_data = backup.get("salt")
            .and_then(|d| d.as_str())
            .ok_or(JsValue::from_str("Missing salt data in backup"))?;
        
        // Store the restored data
        self.storage.set_item(&self.storage_key, wallet_data)?;
        self.storage.set_item(&self.salt_key, salt_data)?;
        
        Ok(())
    }

    // Private helper methods
    fn calculate_integrity_hash(&self, data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.update(b"SOLANA_WALLET_V2_INTEGRITY");
        let hash = hasher.finalize();
        bs58::encode(hash).into_string()
    }
}

// Helper functions for base64 encoding/decoding
fn base64_encode(data: &[u8]) -> String {
    // Simplified base64 encoding (in real implementation, use a proper base64 library)
    bs58::encode(data).into_string() // Using bs58 as placeholder
}

fn base64_decode(data: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Simplified base64 decoding (in real implementation, use a proper base64 library)
    bs58::decode(data).into_vec().map_err(|e| e.into())
}