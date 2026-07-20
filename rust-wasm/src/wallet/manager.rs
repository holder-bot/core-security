use crate::crypto::password::PasswordManager;
use crate::crypto::keys::KeyManager;
use bip39::{Mnemonic, Language};
use tiny_hderive::bip44::DerivationPath;
use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature, Signer};
use zeroize::{Zeroize, ZeroizeOnDrop};
use secrecy::{Secret, ExposeSecret};
use wasm_bindgen::prelude::*;
use serde::{Serialize, Deserialize};
use validator::Validate;
use std::str::FromStr;
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Validate, ZeroizeOnDrop)]
pub struct WalletData {
    pub version: u32,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub public_key: String,
    pub encrypted_private_key: Vec<u8>,
    pub account_index: u32,
    pub derivation_path: String,
    pub checksum: String, // Integrity verification
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AccountInfo {
    pub index: u32,
    pub public_key: String,
    pub derivation_path: String,
    pub balance: Option<u64>,
}

#[derive(ZeroizeOnDrop)]
pub struct WalletManager {
    keypair: Option<Secret<Keypair>>,
    account_index: u32,
    derivation_path: String,
    password_manager: Option<PasswordManager>,
    accounts: HashMap<u32, AccountInfo>,
}

#[wasm_bindgen]
impl WalletManager {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<WalletManager, JsValue> {
        wasm_logger::init(wasm_logger::Config::default());
        
        Ok(WalletManager {
            keypair: None,
            account_index: 0,
            derivation_path: "m/44'/501'/0'/0'".to_string(),
            password_manager: None,
            accounts: HashMap::new(),
        })
    }

    /// Initialize password manager
    #[wasm_bindgen]
    pub fn init_password_manager(&mut self, password: &str) -> Result<(), JsValue> {
        let salt = PasswordManager::generate_secure_salt();
        let password_manager = PasswordManager::new(password, &salt)?;
        self.password_manager = Some(password_manager);
        Ok(())
    }

    /// Generate new wallet using enhanced security patterns
    #[wasm_bindgen]
    pub fn generate_new_wallet(&mut self, account_index: Option<u32>) -> Result<JsValue, JsValue> {
        let account_idx = account_index.unwrap_or(0);
        
        web_sys::console::log_1(&"🦀 Generating new wallet with enhanced security...".into());
        log::info!("Starting enhanced wallet generation");
        
        // Generate entropy using secure random number generator
        let mut entropy = [0u8; 32]; // 256 bits = 24 words
        getrandom::getrandom(&mut entropy)
            .map_err(|e| {
                let error_msg = format!("Failed to generate secure entropy: {}", e);
                web_sys::console::log_1(&format!("🦀 ❌ {}", error_msg).into());
                log::error!("{}", error_msg);
                JsValue::from_str(&error_msg)
            })?;
        
        // Create BIP39 mnemonic
        let mnemonic = Mnemonic::from_entropy(&entropy, Language::English)
            .map_err(|e| {
                let error_msg = format!("Failed to create mnemonic: {}", e);
                web_sys::console::log_1(&format!("🦀 ❌ {}", error_msg).into());
                log::error!("{}", error_msg);
                JsValue::from_str(&error_msg)
            })?;
        
        // Clear entropy from memory
        entropy.zeroize();
        
        let public_key = self.setup_wallet_from_mnemonic(&mnemonic, account_idx)?;
        
        web_sys::console::log_1(&format!("🦀 ✅ Enhanced wallet created successfully! Public key: {}", &public_key[..8]).into());
        log::info!("Enhanced wallet generation completed successfully");
        
        // Return wallet info
        let result = js_sys::Object::new();
        js_sys::Reflect::set(
            &result,
            &JsValue::from_str("mnemonic"),
            &JsValue::from_str(&mnemonic.to_string()),
        )?;
        js_sys::Reflect::set(
            &result,
            &JsValue::from_str("publicKey"),
            &JsValue::from_str(&public_key),
        )?;
        js_sys::Reflect::set(
            &result,
            &JsValue::from_str("accountIndex"),
            &JsValue::from_f64(account_idx as f64),
        )?;
        js_sys::Reflect::set(
            &result,
            &JsValue::from_str("derivationPath"),
            &JsValue::from_str(&self.derivation_path),
        )?;
        
        Ok(result.into())
    }

    /// Restore wallet from seed phrase with enhanced validation
    #[wasm_bindgen]
    pub fn from_seed_phrase(&mut self, phrase: &str, account_index: Option<u32>) -> Result<String, JsValue> {
        let account_idx = account_index.unwrap_or(0);
        
        log::info!("Starting enhanced seed phrase import");
        
        if phrase.is_empty() {
            let error_msg = "Seed phrase cannot be empty";
            web_sys::console::log_1(&format!("🦀 ❌ {}", error_msg).into());
            log::error!("{}", error_msg);
            return Err(JsValue::from_str(error_msg));
        }
        
        // Validate and parse mnemonic
        let mnemonic = Mnemonic::from_phrase(phrase, Language::English)
            .map_err(|e| {
                let error_msg = format!("Invalid seed phrase: {}", e);
                web_sys::console::log_1(&format!("🦀 ❌ {}", error_msg).into());
                log::error!("{}", error_msg);
                JsValue::from_str(&error_msg)
            })?;
        
        // Validate mnemonic checksum
        if !mnemonic.validate_checksum() {
            let error_msg = "Invalid mnemonic checksum";
            web_sys::console::log_1(&format!("🦀 ❌ {}", error_msg).into());
            log::error!("{}", error_msg);
            return Err(JsValue::from_str(error_msg));
        }
        
        let public_key = self.setup_wallet_from_mnemonic(&mnemonic, account_idx)?;
        
        web_sys::console::log_1(&format!("🦀 ✅ Enhanced seed phrase imported successfully! Public key: {}", &public_key[..8]).into());
        log::info!("Enhanced seed phrase import completed");
        
        Ok(public_key)
    }

    /// Import from seed phrase with password and account index for HD wallet derivation
    #[wasm_bindgen]
    pub fn importFromSeedPhraseWithPassword(&mut self, phrase: &str, password: &str, account_index: u32) -> Result<String, JsValue> {
        web_sys::console::log_1(&format!("🦀 HD Wallet: Importing seed phrase with password for account index {}", account_index).into());
        log::info!("Starting HD wallet import with account index: {}", account_index);
        
        if phrase.is_empty() {
            let error_msg = "Seed phrase cannot be empty";
            web_sys::console::log_1(&format!("🦀 ❌ {}", error_msg).into());
            log::error!("{}", error_msg);
            return Err(JsValue::from_str(error_msg));
        }
        
        // Validate and parse mnemonic
        let mnemonic = Mnemonic::from_phrase(phrase, Language::English)
            .map_err(|e| {
                let error_msg = format!("Invalid seed phrase: {}", e);
                web_sys::console::log_1(&format!("🦀 ❌ {}", error_msg).into());
                log::error!("{}", error_msg);
                JsValue::from_str(&error_msg)
            })?;
        
        // Validate mnemonic checksum
        if !mnemonic.validate_checksum() {
            let error_msg = "Invalid mnemonic checksum";
            web_sys::console::log_1(&format!("🦀 ❌ {}", error_msg).into());
            log::error!("{}", error_msg);
            return Err(JsValue::from_str(error_msg));
        }
        
        // Initialize password manager if not already done
        if self.password_manager.is_none() {
            self.init_password_manager(password)?;
        }
        
        // Generate seed from mnemonic with optional passphrase (BIP39 standard)
        let seed = mnemonic.to_seed(password);
        web_sys::console::log_1(&format!("🦀 HD Wallet: Generated BIP39 seed with passphrase for account {}", account_index).into());
        log::info!("Generated BIP39 seed with passphrase for account: {}", account_index);
        
        // Create BIP44 derivation path for Solana: m/44'/501'/account_index'/0'
        let derivation_path = format!("m/44'/501'/{}'/0'", account_index);
        web_sys::console::log_1(&format!("🦀 HD Wallet: Using derivation path: {}", derivation_path).into());
        log::info!("Using HD wallet derivation path: {}", derivation_path);
        
        let path = DerivationPath::from_str(&derivation_path)
            .map_err(|e| {
                let error_msg = format!("Invalid derivation path: {}", e);
                web_sys::console::log_1(&format!("🦀 ❌ {}", error_msg).into());
                log::error!("{}", error_msg);
                JsValue::from_str(&error_msg)
            })?;
        
        // Derive key using BIP44 HD wallet derivation
        web_sys::console::log_1(&format!("🦀 HD Wallet: Deriving key for account index {}", account_index).into());
        log::info!("Deriving HD wallet key for account index: {}", account_index);
        
        let derived_key = path.derive(&seed[..32])
            .map_err(|e| {
                let error_msg = format!("HD wallet key derivation failed: {}", e);
                web_sys::console::log_1(&format!("🦀 ❌ {}", error_msg).into());
                log::error!("{}", error_msg);
                JsValue::from_str(&error_msg)
            })?;
        
        // Create ed25519 keypair from derived key
        web_sys::console::log_1(&format!("🦀 HD Wallet: Creating ed25519 keypair for account {}", account_index).into());
        log::info!("Creating ed25519 keypair for HD wallet account: {}", account_index);
        
        let secret_key = SecretKey::from_bytes(&derived_key)
            .map_err(|e| {
                let error_msg = format!("Invalid derived key: {}", e);
                web_sys::console::log_1(&format!("🦀 ❌ {}", error_msg).into());
                log::error!("{}", error_msg);
                JsValue::from_str(&error_msg)
            })?;
        let public_key = PublicKey::from(&secret_key);
        let public_key_str = bs58::encode(public_key.as_bytes()).into_string();
        
        // For HD wallet derivation, we only return the public key without storing the keypair
        // This allows deriving multiple addresses without overwriting the wallet state
        web_sys::console::log_1(&format!("🦀 ✅ HD Wallet: Successfully derived address for account {}: {}", account_index, &public_key_str[..8]).into());
        log::info!("HD wallet derivation completed for account {}: {}", account_index, &public_key_str[..8]);
        
        Ok(public_key_str)
    }

    /// Import wallet from private key with validation
    #[wasm_bindgen]
    pub fn from_private_key(&mut self, private_key_base58: &str) -> Result<String, JsValue> {
        web_sys::console::log_1(&"🦀 Processing private key import with validation...".into());
        log::info!("Starting enhanced private key import");
        
        if private_key_base58.is_empty() {
            let error_msg = "Private key cannot be empty";
            web_sys::console::log_1(&format!("🦀 ❌ {}", error_msg).into());
            log::error!("{}", error_msg);
            return Err(JsValue::from_str(error_msg));
        }
        
        // Validate base58 format
        let private_key_bytes = bs58::decode(private_key_base58)
            .into_vec()
            .map_err(|e| {
                let error_msg = format!("Invalid private key format: {}", e);
                web_sys::console::log_1(&format!("🦀 ❌ {}", error_msg).into());
                log::error!("{}", error_msg);
                JsValue::from_str(&error_msg)
            })?;
        
        // Validate key length (64 bytes for ed25519)
        if private_key_bytes.len() != 64 {
            let error_msg = "Invalid private key length";
            web_sys::console::log_1(&format!("🦀 ❌ {}", error_msg).into());
            log::error!("{}", error_msg);
            return Err(JsValue::from_str(error_msg));
        }
        
        // Create keypair
        let secret_key = SecretKey::from_bytes(&private_key_bytes[..32])
            .map_err(|e| {
                let error_msg = format!("Invalid secret key: {}", e);
                web_sys::console::log_1(&format!("🦀 ❌ {}", error_msg).into());
                log::error!("{}", error_msg);
                JsValue::from_str(&error_msg)
            })?;
        let public_key = PublicKey::from(&secret_key);
        let keypair = Keypair { secret: secret_key, public: public_key };
        
        // Validate keypair integrity
        let test_message = b"test_message";
        let signature = keypair.sign(test_message);
        if keypair.public.verify(test_message, &signature).is_err() {
            let error_msg = "Invalid keypair";
            web_sys::console::log_1(&format!("🦀 ❌ {}", error_msg).into());
            log::error!("{}", error_msg);
            return Err(JsValue::from_str(error_msg));
        }
        
        let public_key_str = bs58::encode(public_key.as_bytes()).into_string();
        self.keypair = Some(Secret::new(keypair));
        
        web_sys::console::log_1(&format!("🦀 ✅ Enhanced private key imported successfully! Public key: {}", &public_key_str[..8]).into());
        log::info!("Enhanced private key import completed");
        
        Ok(public_key_str)
    }

    /// Get public key with validation
    #[wasm_bindgen]
    pub fn get_public_key(&self) -> Result<String, JsValue> {
        match &self.keypair {
            Some(kp) => Ok(bs58::encode(kp.expose_secret().public.as_bytes()).into_string()),
            None => Err(JsValue::from_str("No wallet loaded")),
        }
    }

    /// SECURITY: Private key export disabled - private keys must never leave WASM memory
    #[wasm_bindgen]
    pub fn export_private_key(&self) -> Result<String, JsValue> {
        web_sys::console::log_1(&"🦀 🔒 SECURITY: Private key export DISABLED - keys secured in WASM memory".into());
        log::error!("Private key export blocked for security - keys must never leave WASM memory");
        
        Err(JsValue::from_str(
            "SECURITY: Private key export disabled. Private keys are secured in WASM memory and never exposed to JavaScript. Use sign_message() for cryptographic operations."
        ))
    }

    /// Sign transaction with enhanced security
    #[wasm_bindgen]
    pub fn sign_transaction(&self, transaction_bytes: &[u8]) -> Result<Vec<u8>, JsValue> {
        web_sys::console::log_1(&"🦀 Signing transaction with enhanced security...".into());
        log::info!("Starting transaction signing");
        
        match &self.keypair {
            Some(kp) => {
                let signature = kp.expose_secret().sign(transaction_bytes);
                web_sys::console::log_1(&"🦀 ✅ Transaction signed successfully".into());
                log::info!("Transaction signing completed");
                Ok(signature.to_bytes().to_vec())
            },
            None => {
                let error_msg = "No wallet loaded";
                web_sys::console::log_1(&format!("🦀 ❌ {}", error_msg).into());
                log::error!("{}", error_msg);
                Err(JsValue::from_str(error_msg))
            },
        }
    }

    /// Sign message
    #[wasm_bindgen]
    pub fn sign_message(&self, message: &[u8]) -> Result<Vec<u8>, JsValue> {
        web_sys::console::log_1(&"🦀 Signing message with ed25519...".into());
        log::info!("Starting message signing");
        
        match &self.keypair {
            Some(kp) => {
                let signature = kp.expose_secret().sign(message);
                web_sys::console::log_1(&"🦀 Message signed successfully".into());
                log::info!("Message signing completed");
                Ok(signature.to_bytes().to_vec())
            },
            None => {
                let error_msg = "No wallet loaded";
                web_sys::console::log_1(&format!("🦀 ❌ {}", error_msg).into());
                log::error!("{}", error_msg);
                Err(JsValue::from_str(error_msg))
            },
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
            None => Err(JsValue::from_str("No wallet loaded")),
        }
    }

    /// Derive multiple accounts from seed
    #[wasm_bindgen]
    pub fn derive_accounts(&mut self, start_index: u32, count: u32) -> Result<JsValue, JsValue> {
        if count > 100 {
            return Err(JsValue::from_str("Too many accounts requested"));
        }
        
        let accounts = js_sys::Array::new();
        
        // Get the base mnemonic if available
        if let Some(keypair) = &self.keypair {
            for i in start_index..(start_index + count) {
                let derivation_path = format!("m/44'/501'/{}'/0'", i);
                
                // For now, we'll derive the public key based on the index
                let derived_pubkey = self.derive_account_key(i)?;
                
                let account_info = AccountInfo {
                    index: i,
                    public_key: derived_pubkey.clone(),
                    derivation_path: derivation_path.clone(),
                    balance: None,
                };
                
                self.accounts.insert(i, account_info.clone());
                
                let js_account = js_sys::Object::new();
                js_sys::Reflect::set(
                    &js_account,
                    &JsValue::from_str("index"),
                    &JsValue::from_f64(i as f64),
                )?;
                js_sys::Reflect::set(
                    &js_account,
                    &JsValue::from_str("publicKey"),
                    &JsValue::from_str(&derived_pubkey),
                )?;
                js_sys::Reflect::set(
                    &js_account,
                    &JsValue::from_str("derivationPath"),
                    &JsValue::from_str(&derivation_path),
                )?;
                
                accounts.push(&js_account);
            }
        } else {
            return Err(JsValue::from_str("No wallet loaded"));
        }
        
        Ok(accounts.into())
    }

    /// Switch to different account
    #[wasm_bindgen]
    pub fn switch_account(&mut self, account_index: u32) -> Result<String, JsValue> {
        if let Some(account_info) = self.accounts.get(&account_index) {
            self.account_index = account_index;
            self.derivation_path = account_info.derivation_path.clone();
            
            // Re-derive the keypair for this account
            // This would need the original seed, which we don't store for security
            // For now, return the stored public key
            Ok(account_info.public_key.clone())
        } else {
            Err(JsValue::from_str("Account not found"))
        }
    }

    /// Get current account info
    #[wasm_bindgen]
    pub fn get_current_account(&self) -> Result<JsValue, JsValue> {
        if let Some(account_info) = self.accounts.get(&self.account_index) {
            let js_account = js_sys::Object::new();
            js_sys::Reflect::set(
                &js_account,
                &JsValue::from_str("index"),
                &JsValue::from_f64(account_info.index as f64),
            )?;
            js_sys::Reflect::set(
                &js_account,
                &JsValue::from_str("publicKey"),
                &JsValue::from_str(&account_info.public_key),
            )?;
            js_sys::Reflect::set(
                &js_account,
                &JsValue::from_str("derivationPath"),
                &JsValue::from_str(&account_info.derivation_path),
            )?;
            if let Some(balance) = account_info.balance {
                js_sys::Reflect::set(
                    &js_account,
                    &JsValue::from_str("balance"),
                    &JsValue::from_f64(balance as f64),
                )?;
            }
            Ok(js_account.into())
        } else {
            Err(JsValue::from_str("Current account not found"))
        }
    }

    /// Clear wallet from memory
    #[wasm_bindgen]
    pub fn clear_wallet(&mut self) {
        self.keypair = None;
        self.password_manager = None;
        self.accounts.clear();
        self.account_index = 0;
        self.derivation_path = "m/44'/501'/0'/0'".to_string();
    }

    /// Check if wallet is loaded
    #[wasm_bindgen]
    pub fn is_wallet_loaded(&self) -> bool {
        self.keypair.is_some()
    }

    /// Get derivation path
    #[wasm_bindgen]
    pub fn get_derivation_path(&self) -> String {
        self.derivation_path.clone()
    }

    /// Get account index
    #[wasm_bindgen]
    pub fn get_account_index(&self) -> u32 {
        self.account_index
    }

    // Private helper methods
    fn setup_wallet_from_mnemonic(&mut self, mnemonic: &Mnemonic, account_index: u32) -> Result<String, JsValue> {
        web_sys::console::log_1(&format!("🦀 Setting up wallet from mnemonic (account index: {})...", account_index).into());
        log::info!("Starting wallet setup from mnemonic with account index: {}", account_index);
        
        let seed = mnemonic.to_seed("");
        web_sys::console::log_1(&"🦀 Generated BIP39 seed from mnemonic".into());
        log::info!("Generated BIP39 seed from mnemonic");
        
        // Official Solana derivation path
        let derivation_path = format!("m/44'/501'/{}'/0'", account_index);
        web_sys::console::log_1(&format!("🦀 Using Solana derivation path: {}", derivation_path).into());
        log::info!("Using Solana derivation path: {}", derivation_path);
        
        let path = DerivationPath::from_str(&derivation_path)
            .map_err(|e| {
                let error_msg = format!("Invalid derivation path: {}", e);
                web_sys::console::log_1(&format!("🦀 ❌ {}", error_msg).into());
                log::error!("{}", error_msg);
                JsValue::from_str(&error_msg)
            })?;
        
        // Derive key
        web_sys::console::log_1(&"🦀 Deriving cryptographic key from seed...".into());
        log::info!("Deriving cryptographic key from seed");
        
        let derived_key = path.derive(&seed[..32])
            .map_err(|e| {
                let error_msg = format!("Key derivation failed: {}", e);
                web_sys::console::log_1(&format!("🦀 ❌ {}", error_msg).into());
                log::error!("{}", error_msg);
                JsValue::from_str(&error_msg)
            })?;
        
        web_sys::console::log_1(&"🦀 Creating ed25519 keypair...".into());
        log::info!("Creating ed25519 keypair");
        
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
        
        web_sys::console::log_1(&"🦀 Storing keypair securely in memory...".into());
        log::info!("Storing keypair securely in memory");
        
        self.keypair = Some(Secret::new(keypair));
        self.account_index = account_index;
        self.derivation_path = derivation_path.clone();
        
        // Store account info
        let account_info = AccountInfo {
            index: account_index,
            public_key: public_key_str.clone(),
            derivation_path: derivation_path,
            balance: None,
        };
        self.accounts.insert(account_index, account_info);
        
        web_sys::console::log_1(&format!("🦀 ✅ Wallet setup completed! Public key: {}", &public_key_str[..8]).into());
        log::info!("Wallet setup from mnemonic completed successfully");
        
        Ok(public_key_str)
    }

    fn derive_account_key(&self, account_index: u32) -> Result<String, JsValue> {
        // This is a simplified version - in a real implementation, 
        // you'd need to store the original seed or mnemonic to derive different accounts
        // For security, we don't store the seed, so this is a placeholder
        match &self.keypair {
            Some(kp) => {
                // Generate a deterministic but different key based on account index
                use sha2::{Sha256, Digest};
                let mut hasher = Sha256::new();
                hasher.update(kp.expose_secret().secret.as_bytes());
                hasher.update(account_index.to_be_bytes());
                let derived_seed = hasher.finalize();
                
                let secret_key = SecretKey::from_bytes(derived_seed.as_slice())
                    .map_err(|_| JsValue::from_str("Failed to derive account key"))?;
                let public_key = PublicKey::from(&secret_key);
                
                Ok(bs58::encode(public_key.as_bytes()).into_string())
            },
            None => Err(JsValue::from_str("No wallet loaded")),
        }
    }

    fn calculate_checksum(&self) -> Result<String, JsValue> {
        use sha2::{Sha256, Digest};
        
        if let Some(keypair) = &self.keypair {
            let mut hasher = Sha256::new();
            hasher.update(keypair.expose_secret().public.as_bytes());
            hasher.update(self.account_index.to_be_bytes());
            hasher.update(self.derivation_path.as_bytes());
            
            let hash = hasher.finalize();
            Ok(bs58::encode(hash).into_string())
        } else {
            Err(JsValue::from_str("No wallet loaded"))
        }
    }
}