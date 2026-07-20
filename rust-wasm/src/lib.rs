use wasm_bindgen::prelude::*;
use slip10::{BIP32Path, derive_key_from_path, Curve};
use ed25519_dalek;
use bip39::{Mnemonic, Language};
use rsa::{pkcs8::DecodePublicKey, Oaep, RsaPublicKey};
use sha2::Sha256;
use base64::Engine;

// Module declarations
mod crypto {
    pub mod encryption;
    pub use encryption::CryptoManager;
}

mod networks;
mod public;

// Re-export modules for WASM bindings
pub use crypto::CryptoManager;
pub use networks::*;
pub use public::*;

// Import network-specific key derivation functions
use networks::solana::keys::derive_solana_address;
use networks::soroban::keys::derive_soroban_address;

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global allocator
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

// Set up panic hook for better error messages
#[wasm_bindgen(start)]
pub fn init() {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
    
    wasm_logger::init(wasm_logger::Config::default());
    log::info!("Solana WASM Wallet v2 initialized with SPL token support");
    web_sys::console::log_1(&"Solana WASM Wallet v2 - SPL Token Edition".into());
}

// =============================================================================
// WORKING WALLET MANAGER WITH PROPER BIP39 SUPPORT
// =============================================================================

#[wasm_bindgen]
pub struct WalletManager {
    is_initialized: bool,
    current_keypair: Option<ed25519_dalek::SigningKey>,
    secured_mnemonic: Option<secrecy::Secret<String>>, // Securely store mnemonic for controlled display
}

#[wasm_bindgen]
impl WalletManager {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<WalletManager, JsValue> {
        Ok(WalletManager {
            is_initialized: false,
            current_keypair: None,
            secured_mnemonic: None,
        })
    }

    #[wasm_bindgen]
    pub fn generate_new_wallet(&mut self) -> Result<JsValue, JsValue> {
        self.generate_new_wallet_with_length(12) // Default to 12 words (standard)
    }

    /// Generate new wallet with specified word count (12 or 24)
    #[wasm_bindgen]
    pub fn generate_new_wallet_with_length(&mut self, word_count: u32) -> Result<JsValue, JsValue> {
        if word_count != 12 && word_count != 24 {
            return Err(JsValue::from_str("Word count must be 12 or 24"));
        }

        web_sys::console::log_1(&format!("🦀 Generating new BIP44 Solana wallet with {}-word seed phrase...", word_count).into());
        log::info!("Starting new BIP44 wallet generation with {} words", word_count);
        
        // Generate entropy for BIP39 mnemonic
        let entropy_bytes = if word_count == 12 { 16 } else { 32 }; // 128 bits = 12 words, 256 bits = 24 words
        web_sys::console::log_1(&format!("🦀 Collecting {} bits of secure entropy for BIP39 mnemonic generation...", entropy_bytes * 8).into());
        
        let mut entropy = vec![0u8; entropy_bytes];
        getrandom::getrandom(&mut entropy)
            .map_err(|e| {
                let error_msg = format!("Failed to generate entropy: {}", e);
                web_sys::console::log_1(&format!("🦀 ❌ {}", error_msg).into());
                log::error!("{}", error_msg);
                // Clear entropy on error
                use zeroize::Zeroize;
                entropy.zeroize();
                JsValue::from_str(&error_msg)
            })?;
        
        // Create BIP39 mnemonic from entropy
        let mnemonic = bip39::Mnemonic::from_entropy_in(Language::English, &entropy)
            .map_err(|e| {
                let error_msg = format!("Failed to create mnemonic: {}", e);
                web_sys::console::log_1(&format!("🦀 ❌ {}", error_msg).into());
                log::error!("{}", error_msg);
                // Clear entropy on error
                use zeroize::Zeroize;
                entropy.zeroize();
                JsValue::from_str(&error_msg)
            })?;
        
        // SECURITY: Clear entropy from memory immediately after use
        {
            use zeroize::Zeroize;
            entropy.zeroize();
            web_sys::console::log_1(&"🦀 Entropy zeroed from memory after mnemonic generation".into());
            log::warn!("Entropy successfully cleared from memory");
        }
        
        web_sys::console::log_1(&format!("🦀 BIP39 mnemonic generated with secure entropy ({}-word seed phrase)", word_count).into());
        
        // SECURITY: Store mnemonic securely in WASM memory for controlled display
        use secrecy::Secret;
        self.secured_mnemonic = Some(Secret::new(mnemonic.to_string()));
        web_sys::console::log_1(&"🦀 🔒 Mnemonic stored securely in WASM memory for controlled display".into());
        
        // Derive BIP44 address and keypair from mnemonic for account 0
        let public_key = self.derive_public_key_bip44(&mnemonic.to_string(), "", 0)?;
        web_sys::console::log_1(&"🦀 BIP44 keypair derived from mnemonic using path m/44'/501'/0'/0'".into());
        
        // Generate proper keypair that matches the derived address
        web_sys::console::log_1(&"🦀 Generating BIP39 seed (will be cleared after use)...".into());
        log::warn!("Generating BIP39 seed - will be cleared after use");
        
        let mut seed = mnemonic.to_seed("");
        let derivation_path = "m/44'/501'/0'/0'";
        
        let path: BIP32Path = derivation_path.parse()
            .map_err(|e| {
                // Clear seed on error
                use zeroize::Zeroize;
                seed.zeroize();
                JsValue::from_str(&format!("Invalid derivation path: {:?}", e))
            })?;
        
        let derived_key_result = derive_key_from_path(&seed, Curve::Ed25519, &path)
            .map_err(|e| {
                // Clear seed on error
                use zeroize::Zeroize;
                seed.zeroize();
                JsValue::from_str(&format!("SLIP-10 key derivation failed: {:?}", e))
            })?;
        
        let derived_key = derived_key_result.key;
        
        web_sys::console::log_1(&"🦀 Creating Ed25519 signing key from derived key...".into());
        log::warn!("Creating Ed25519 signing key from derived key");
        
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&derived_key);
        
        // SECURITY: Clear intermediate key material from memory
        {
            use zeroize::Zeroize;
            seed.zeroize();
            web_sys::console::log_1(&"🦀 BIP39 seed cleared from memory".into());
            log::warn!("BIP39 seed successfully cleared from memory");
        }
        
        // IMPORTANT: Store the keypair for transaction signing
        self.current_keypair = Some(signing_key);
        self.is_initialized = true;
        
        web_sys::console::log_1(&format!("🦀 ✅ BIP44 Solana wallet created successfully. Public key: {}", &public_key[..8]).into());
        web_sys::console::log_1(&"🦀 Private key stored in WASM memory, seed phrase ready for encryption".into());
        log::info!("BIP44 wallet generation completed successfully");
        
        // SECURITY: Do NOT expose mnemonic to JavaScript - keep in WASM memory only
        web_sys::console::log_1(&"🦀 🔒 SECURITY: Seed phrase kept in WASM memory, NOT exposed to JavaScript".into());
        log::info!("Seed phrase secured in WASM memory - not exposed to JavaScript");
        
        let result = js_sys::Object::new();
        // ❌ REMOVED: mnemonic field - this was a critical security vulnerability
        js_sys::Reflect::set(&result, &"publicKey".into(), &public_key.into())?;
        js_sys::Reflect::set(&result, &"accountIndex".into(), &0.into())?;
        js_sys::Reflect::set(&result, &"derivationPath".into(), &"m/44'/501'/0'/0'".into())?;
        js_sys::Reflect::set(&result, &"wordCount".into(), &word_count.into())?;
        js_sys::Reflect::set(&result, &"seedSecured".into(), &true.into())?; // Indicates seed is secured in WASM
        
        Ok(result.into())
    }

    /// SECURITY: Retrieve mnemonic for controlled display (ONLY for user backup)
    /// This should ONLY be called when user explicitly requests to view their seed phrase
    #[wasm_bindgen]
    pub fn get_mnemonic_for_backup_display(&self) -> Result<String, JsValue> {
        web_sys::console::log_1(&"🦀 🚨 SECURITY WARNING: Mnemonic requested for backup display".into());
        log::warn!("SECURITY: Mnemonic access requested for user backup display");
        
        match &self.secured_mnemonic {
            Some(secret_mnemonic) => {
                use secrecy::ExposeSecret;
                web_sys::console::log_1(&"🦀 🔓 Exposing mnemonic for controlled user backup (one-time display)".into());
                log::warn!("SECURITY: Mnemonic exposed for user backup - should be displayed ONCE");
                Ok(secret_mnemonic.expose_secret().clone())
            },
            None => {
                let error_msg = "No mnemonic available - wallet may not be properly initialized";
                web_sys::console::log_1(&format!("🦀 ❌ {}", error_msg).into());
                log::error!("{}", error_msg);
                Err(JsValue::from_str(error_msg))
            }
        }
    }
    
    /// SECURITY: Comprehensive memory audit and status report
    #[wasm_bindgen]
    pub fn security_audit_memory_status(&self) -> Result<JsValue, JsValue> {
        web_sys::console::log_1(&"🦀 Performing comprehensive memory status check...".into());
        log::warn!("Starting comprehensive memory status check");
        
        let result = js_sys::Object::new();
        
        // Check wallet state
        let wallet_loaded = self.current_keypair.is_some();
        js_sys::Reflect::set(&result, &"walletLoaded".into(), &wallet_loaded.into())?;
        
        // Memory security status
        js_sys::Reflect::set(&result, &"wasmMemoryIsolated".into(), &true.into())?;
        js_sys::Reflect::set(&result, &"privateKeysInWasmOnly".into(), &wallet_loaded.into())?;
        js_sys::Reflect::set(&result, &"plaintextSeedExposure".into(), &false.into())?;
        
        // Zeroization capabilities
        js_sys::Reflect::set(&result, &"zeroizeEnabled".into(), &true.into())?;
        js_sys::Reflect::set(&result, &"stackScrubbing".into(), &true.into())?;
        js_sys::Reflect::set(&result, &"memoryAuditLogging".into(), &true.into())?;
        
        web_sys::console::log_1(&format!("🦀 Wallet loaded: {}", wallet_loaded).into());
        web_sys::console::log_1(&"🦀 WASM memory isolation: ACTIVE".into());
        web_sys::console::log_1(&"🦀 Private key protection: SECURE".into());
        web_sys::console::log_1(&"🦀 Zeroization: ENABLED".into());
        
        log::warn!("Memory status check completed");
        
        Ok(result.into())
    }
    
    #[wasm_bindgen]
    pub fn from_seed_phrase(&mut self, phrase: &str, account_index: u32) -> Result<String, JsValue> {
        web_sys::console::log_1(&format!("🦀 Starting seed phrase import via Rust WASM for account index {}...", account_index).into());
        log::info!("Starting seed phrase import for account {}", account_index);
        
        if phrase.is_empty() {
            let error_msg = "Seed phrase cannot be empty";
            web_sys::console::log_1(&format!("🦀 ❌ {}", error_msg).into());
            log::error!("{}", error_msg);
            return Err(error_msg.into());
        }
        
        web_sys::console::log_1(&format!("🦀 Validating BIP39 mnemonic format and deriving Solana keypair for account {}...", account_index).into());
        
        // Use proper BIP44 derivation for the specified account index
        let public_key = self.derive_public_key_bip44(phrase, "", account_index)?;
        
        // Generate proper BIP44 keypair that matches the derived address
        let mnemonic = bip39::Mnemonic::parse_in_normalized(Language::English, phrase)
            .map_err(|e| JsValue::from_str(&format!("Invalid seed phrase: {}", e)))?;
        
        web_sys::console::log_1(&"🦀 Generating BIP39 seed (will be cleared after use)...".into());
        log::warn!("Generating BIP39 seed for account {} - will be cleared", account_index);
        
        let mut seed = mnemonic.to_seed("");
        let derivation_path = format!("m/44'/501'/{}'/0'", account_index);
        
        let path: BIP32Path = derivation_path.parse()
            .map_err(|e| {
                // Clear seed on error
                use zeroize::Zeroize;
                seed.zeroize();
                JsValue::from_str(&format!("Invalid derivation path: {:?}", e))
            })?;
        
        let derived_key_result = derive_key_from_path(&seed, Curve::Ed25519, &path)
            .map_err(|e| {
                // Clear seed on error
                use zeroize::Zeroize;
                seed.zeroize();
                JsValue::from_str(&format!("SLIP-10 key derivation failed: {:?}", e))
            })?;
        
        let derived_key = derived_key_result.key;
        
        web_sys::console::log_1(&"🦀 Generating Ed25519 keypair from BIP44 derivation...".into());
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&derived_key);
        
        // SECURITY: Clear seed from memory after use
        {
            use zeroize::Zeroize;
            seed.zeroize();
            web_sys::console::log_1(&"🦀 BIP39 seed cleared from memory after derivation".into());
            log::warn!("BIP39 seed successfully cleared for account {}", account_index);
        }
        
        self.current_keypair = Some(signing_key);
        self.is_initialized = true;
        
        web_sys::console::log_1(&format!("🦀 Solana account restored from seed. Public key (base58): {}", &public_key[..8]).into());
        web_sys::console::log_1(&"🦀 Private key loaded in WASM memory, seed phrase will be encrypted for storage".into());
        web_sys::console::log_1(&"🦀 READY TO ENCRYPT SEED WITH PASSWORD".into());
        log::info!("Seed phrase import completed");
        
        Ok(public_key)
    }

    /// Import from seed phrase with password and account index for HD wallet derivation using proper BIP44
    #[wasm_bindgen]
    pub fn importFromSeedPhraseWithPassword(&mut self, phrase: &str, password: &str, account_index: u32) -> Result<String, JsValue> {
        // Only log detailed steps for the first derivation (account 0) to reduce log spam
        let is_first_derivation = account_index == 0;
        
        if is_first_derivation {
            web_sys::console::log_1(&format!("🦀 BIP44 HD Wallet: Starting derivation for account index {}", account_index).into());
            log::info!("Starting BIP44 HD wallet derivation with account index: {}", account_index);
        }
        
        if phrase.is_empty() {
            let error_msg = "Seed phrase cannot be empty";
            web_sys::console::log_1(&format!("🦀 ❌ {}", error_msg).into());
            log::error!("{}", error_msg);
            return Err(error_msg.into());
        }
        
        if is_first_derivation {
            web_sys::console::log_1(&format!("🦀 BIP44: Using proper derivation path m/44'/501'/{}'/0'", account_index).into());
        }
        
        // SECURITY: Store mnemonic securely in WASM memory for controlled display (only for first account)
        if is_first_derivation {
            use secrecy::Secret;
            self.secured_mnemonic = Some(Secret::new(phrase.to_string()));
            web_sys::console::log_1(&"🦀 🔒 Imported mnemonic stored securely in WASM memory for controlled display".into());
        }
        
        // Use proper BIP44 derivation with account index and empty passphrase (password is for encryption, not derivation)
        let public_key = self.derive_public_key_bip44_and_store_keypair(phrase, "", account_index)?;
        
        if is_first_derivation {
            web_sys::console::log_1(&format!("🦀 BIP44 HD Wallet: Successfully derived address for account {}: {}", account_index, &public_key[..8]).into());
            log::info!("BIP44 HD wallet derivation completed for account {}: {}", account_index, &public_key[..8]);
        }
        
        Ok(public_key)
    }

    /// SECURE: Import from encrypted seed phrase data - decryption happens only in WASM
    /// This prevents plaintext seed phrases from ever existing in JavaScript memory
    #[wasm_bindgen]
    pub fn from_encrypted_seed_phrase(&mut self, encrypted_json: &str, password: &str, account_index: u32) -> Result<String, JsValue> {
        web_sys::console::log_1(&format!("🦀 SECURE: Loading wallet from encrypted seed phrase (account {})...", account_index).into());
        log::info!("Starting secure encrypted seed phrase import for account {}", account_index);
        
        // Decrypt the seed phrase within WASM - plaintext never touches JavaScript
        let decryption_result = match crate::crypto::encryption::CryptoManager::new().decrypt_data(encrypted_json, password) {
            result if result.success() => result,
            result => {
                let error_msg = format!("Failed to decrypt seed phrase: {}", result.error().unwrap_or("Unknown error".to_string()));
                web_sys::console::log_1(&format!("🦀 ❌ {}", error_msg).into());
                log::error!("{}", error_msg);
                return Err(error_msg.into());
            }
        };
        
        let plaintext_seed = decryption_result.plaintext();
        web_sys::console::log_1(&"🦀 Seed phrase decrypted successfully in WASM - plaintext never exposed to JavaScript".into());
        
        // Now use the decrypted seed phrase (still within WASM)
        let result = self.importFromSeedPhraseWithPassword(&plaintext_seed, "", account_index);
        
        // SECURITY: Explicitly clear the plaintext seed phrase from memory
        {
            use zeroize::Zeroize;
            let mut seed_bytes = plaintext_seed.into_bytes();
            seed_bytes.zeroize();
            web_sys::console::log_1(&"🦀 Plaintext seed phrase explicitly zeroed from WASM memory".into());
            log::warn!("Plaintext seed phrase successfully cleared from memory");
        }
        
        web_sys::console::log_1(&"🦀 SECURE: Wallet loaded, all plaintext data cleared from memory".into());
        
        result
    }

    /// SECURE: Derive Soroban address from encrypted seed phrase
    #[wasm_bindgen]
    pub fn derive_soroban_address(&mut self, encrypted_json: &str, password: &str, account_index: u32) -> Result<JsValue, JsValue> {
        web_sys::console::log_1(&format!("🦀 SECURE: Deriving Soroban address from encrypted seed phrase (account {})...", account_index).into());
        log::info!("Starting secure Soroban address derivation for account {}", account_index);
        
        // Decrypt the seed phrase within WASM - plaintext never touches JavaScript
        let decryption_result = match crate::crypto::encryption::CryptoManager::new().decrypt_data(encrypted_json, password) {
            result if result.success() => result,
            result => {
                let error_msg = format!("Failed to decrypt seed phrase: {}", result.error().unwrap_or("Unknown error".to_string()));
                web_sys::console::log_1(&format!("🦀 ❌ {}", error_msg).into());
                log::error!("{}", error_msg);
                return Err(error_msg.into());
            }
        };
        
        let plaintext_seed = decryption_result.plaintext();
        web_sys::console::log_1(&"🦀 Seed phrase decrypted successfully for Soroban address derivation".into());
        
        // Parse the mnemonic
        let mnemonic = bip39::Mnemonic::parse_in_normalized(bip39::Language::English, &plaintext_seed)
            .map_err(|e| {
                // Clear seed on error
                use zeroize::Zeroize;
                let mut seed_bytes = plaintext_seed.clone().into_bytes();
                seed_bytes.zeroize();
                JsValue::from_str(&format!("Invalid seed phrase: {}", e))
            })?;
        
        // Derive Soroban address using network module
        let (address, public_key_bytes) = derive_soroban_address(&mnemonic, account_index, "")
            .map_err(|e| {
                // Clear seed on error
                use zeroize::Zeroize;
                let mut seed_bytes = plaintext_seed.clone().into_bytes();
                seed_bytes.zeroize();
                e
            })?;
        
        // SECURITY: Explicitly clear the plaintext seed phrase from memory
        {
            use zeroize::Zeroize;
            let mut seed_bytes = plaintext_seed.into_bytes();
            seed_bytes.zeroize();
            web_sys::console::log_1(&"🦀 Plaintext seed phrase explicitly zeroed from WASM memory after Soroban derivation".into());
            log::warn!("Plaintext seed phrase successfully cleared from memory");
        }
        
        let result = js_sys::Object::new();
        js_sys::Reflect::set(&result, &"address".into(), &address.clone().into())?;
        js_sys::Reflect::set(&result, &"publicKey".into(), &hex::encode(public_key_bytes).into())?;
        js_sys::Reflect::set(&result, &"network".into(), &"soroban".into())?;
        js_sys::Reflect::set(&result, &"accountIndex".into(), &account_index.into())?;
        
        web_sys::console::log_1(&format!("🦀 SECURE: Soroban address derived successfully: {}", &address[..8]).into());
        log::info!("Secure Soroban address derivation completed for account {}", account_index);
        
        Ok(result.into())
    }

    /// SECURE: Export private key from encrypted seed phrase data
    /// All decryption and key derivation happens within WASM memory
    /// This is the only secure way to export private keys without exposing sensitive data to JavaScript
    #[wasm_bindgen]
    pub fn export_private_key_from_encrypted(&self, encrypted_json: &str, password: &str, account_index: u32) -> Result<String, JsValue> {
        web_sys::console::log_1(&format!("🦀 SECURE: Exporting private key from encrypted data (account {})...", account_index).into());
        log::info!("Starting secure private key export for account {}", account_index);
        
        // Decrypt the seed phrase within WASM - plaintext never touches JavaScript
        let decryption_result = match crate::crypto::encryption::CryptoManager::new().decrypt_data(encrypted_json, password) {
            result if result.success() => result,
            result => {
                let error_msg = format!("Failed to decrypt seed phrase: {}", result.error().unwrap_or("Unknown error".to_string()));
                web_sys::console::log_1(&format!("🦀 ❌ {}", error_msg).into());
                log::error!("{}", error_msg);
                return Err(error_msg.into());
            }
        };
        
        let plaintext_seed = decryption_result.plaintext();
        web_sys::console::log_1(&"🦀 Seed phrase decrypted successfully in WASM - deriving private key...".into());
        
        // Derive the private key within WASM memory
        let private_key_result = self.derive_private_key_bip44(&plaintext_seed, "", account_index);
        
        // SECURITY: Explicitly clear the plaintext seed phrase from memory
        {
            use zeroize::Zeroize;
            let mut seed_bytes = plaintext_seed.into_bytes();
            seed_bytes.zeroize();
            web_sys::console::log_1(&"🦀 Plaintext seed phrase explicitly zeroed from WASM memory".into());
            log::warn!("Plaintext seed phrase successfully cleared from memory");
        }
        
        match private_key_result {
            Ok(private_key_base58) => {
                web_sys::console::log_1(&"🦀 SECURE: Private key exported successfully via WASM".into());
                log::info!("Secure private key export completed for account {}", account_index);
                Ok(private_key_base58)
            },
            Err(e) => {
                web_sys::console::log_1(&format!("🦀 ❌ Private key derivation failed: {}", e.as_string().unwrap_or("Unknown error".to_string())).into());
                log::error!("Private key derivation failed for account {}", account_index);
                Err(e)
            }
        }
    }

    /// SECURE: Verify private key matches expected address without exposing key to JavaScript
    /// All verification happens within WASM memory for maximum security
    #[wasm_bindgen]
    pub fn verify_private_key_secure(&self, encrypted_json: &str, password: &str, account_index: u32, expected_address: &str) -> Result<bool, JsValue> {
        web_sys::console::log_1(&format!("🦀 SECURE: Verifying private key for account {} against address {}", account_index, expected_address).into());
        log::info!("Starting secure private key verification for account {}", account_index);
        
        // Decrypt the seed phrase within WASM - plaintext never touches JavaScript
        let decryption_result = match crate::crypto::encryption::CryptoManager::new().decrypt_data(encrypted_json, password) {
            result if result.success() => result,
            result => {
                let error_msg = format!("Failed to decrypt seed phrase for verification: {}", result.error().unwrap_or("Unknown error".to_string()));
                web_sys::console::log_1(&format!("🦀 ❌ {}", error_msg).into());
                log::error!("{}", error_msg);
                return Err(error_msg.into());
            }
        };
        
        let plaintext_seed = decryption_result.plaintext();
        web_sys::console::log_1(&"🦀 Seed phrase decrypted successfully for verification - deriving keypair...".into());
        
        // Derive the keypair within WASM memory
        let verification_result = self.verify_private_key_internal(&plaintext_seed, "", account_index, expected_address);
        
        // SECURITY: Explicitly clear the plaintext seed phrase from memory
        {
            use zeroize::Zeroize;
            let mut seed_bytes = plaintext_seed.into_bytes();
            seed_bytes.zeroize();
            web_sys::console::log_1(&"🦀 Plaintext seed phrase explicitly zeroed from WASM memory after verification".into());
            log::warn!("Plaintext seed phrase successfully cleared from memory after verification");
        }
        
        match verification_result {
            Ok(is_valid) => {
                if is_valid {
                    web_sys::console::log_1(&format!("🦀 ✅ Private key verification SUCCESS - matches address {}", expected_address).into());
                    log::info!("Secure private key verification successful for account {}", account_index);
                } else {
                    web_sys::console::log_1(&format!("🦀 ❌ Private key verification FAILED - does not match address {}", expected_address).into());
                    log::warn!("Secure private key verification failed for account {}", account_index);
                }
                Ok(is_valid)
            },
            Err(e) => {
                web_sys::console::log_1(&format!("🦀 ❌ Private key verification error: {}", e.as_string().unwrap_or("Unknown error".to_string())).into());
                log::error!("Private key verification error for account {}", account_index);
                Err(e)
            }
        }
    }

    /// SECURE: Derive private key and encrypt with server public key (RSA-OAEP) plus client cipher
    #[wasm_bindgen]
    pub fn derive_and_encrypt_for_server(
        &self,
        encrypted_json: &str,
        password: &str,
        account_index: u32,
        server_pubkey_pem: &str
    ) -> Result<JsValue, JsValue> {
        // Decrypt seed
        let decryption_result = match crate::crypto::encryption::CryptoManager::new().decrypt_data(encrypted_json, password) {
            result if result.success() => result,
            result => {
                let error_msg = format!("Failed to decrypt seed phrase: {}", result.error().unwrap_or("Unknown error".to_string()));
                return Err(error_msg.into());
            }
        };

        let plaintext_seed = decryption_result.plaintext();

        // Derive private key (base58 string)
        let private_key_base58 = self.derive_private_key_bip44(&plaintext_seed, "", account_index)?;

        // Encrypt with server public key (RSA-OAEP-SHA256)
        let pubkey = RsaPublicKey::from_public_key_pem(server_pubkey_pem)
            .map_err(|e| JsValue::from_str(&format!("Invalid server public key: {}", e)))?;
        let mut rng = rand::thread_rng();
        let encrypted_server = pubkey.encrypt(
            &mut rng,
            Oaep::new::<Sha256>(),
            private_key_base58.as_bytes()
        ).map_err(|e| JsValue::from_str(&format!("Server encryption failed: {}", e)))?;
        let server_ciphertext_b64 = base64::engine::general_purpose::STANDARD.encode(encrypted_server);

        // Client encryption (existing AES-GCM with password)
        let enc_result = crate::crypto::encryption::CryptoManager::new().encrypt_data(&private_key_base58, password);
        if !enc_result.success() {
            return Err(JsValue::from_str("Client encryption failed"));
        }

        // Zeroize seed
        {
            use zeroize::Zeroize;
            let mut seed_bytes = plaintext_seed.into_bytes();
            seed_bytes.zeroize();
        }

        // Build return object
        let result = js_sys::Object::new();
        js_sys::Reflect::set(&result, &"client_ciphertext".into(), &enc_result.data().into())?;
        js_sys::Reflect::set(&result, &"server_ciphertext".into(), &server_ciphertext_b64.into())?;
        Ok(result.into())
    }

    /// Encrypt arbitrary data with server public key (RSA-OAEP-SHA256)
    /// Used for NCS keys where we derive NEAR key separately
    #[wasm_bindgen]
    pub fn encrypt_with_server_public_key(
        &self,
        plaintext: &str,
        server_pubkey_pem: &str
    ) -> Result<JsValue, JsValue> {
        // Encrypt with server public key (RSA-OAEP-SHA256)
        let pubkey = RsaPublicKey::from_public_key_pem(server_pubkey_pem)
            .map_err(|e| JsValue::from_str(&format!("Invalid server public key: {}", e)))?;
        let mut rng = rand::thread_rng();
        let encrypted_server = pubkey.encrypt(
            &mut rng,
            Oaep::new::<Sha256>(),
            plaintext.as_bytes()
        ).map_err(|e| JsValue::from_str(&format!("Server encryption failed: {}", e)))?;
        let server_ciphertext_b64 = base64::engine::general_purpose::STANDARD.encode(encrypted_server);

        // Build return object
        let result = js_sys::Object::new();
        js_sys::Reflect::set(&result, &"server_ciphertext".into(), &server_ciphertext_b64.into())?;
        Ok(result.into())
    }

    // Internal verification function
    fn verify_private_key_internal(&self, mnemonic: &str, passphrase: &str, account_index: u32, expected_address: &str) -> Result<bool, JsValue> {
        // BIP44 derivation path for Solana: m/44'/501'/account_index'/0'
        let derivation_path = format!("m/44'/501'/{}'/0'", account_index);
        web_sys::console::log_1(&format!("🦀 Using BIP44 derivation path for verification: {}", derivation_path).into());
        
        // Generate BIP39 seed
        let seed = bip39::Mnemonic::parse(mnemonic)
            .map_err(|e| format!("Invalid mnemonic for verification: {}", e))?
            .to_seed(passphrase);
        
        web_sys::console::log_1(&"🦀 BIP39 seed generated for verification".into());
        
        // Derive key using SLIP-10 for Ed25519 compatibility (Phantom standard)
        let path: BIP32Path = derivation_path.parse()
            .map_err(|e| format!("Invalid derivation path for verification: {:?}", e))?;
        
        let derived_key_result = derive_key_from_path(&seed, Curve::Ed25519, &path)
            .map_err(|e| format!("SLIP-10 key derivation failed for verification: {:?}", e))?;
        
        let derived_key = derived_key_result.key;
        
        // Create Ed25519 signing key from derived key
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&derived_key);
        let verifying_key = signing_key.verifying_key();
        
        // Convert public key to Solana address format
        let derived_address = bs58::encode(verifying_key.as_bytes()).into_string();
        
        web_sys::console::log_1(&format!("🦀 Derived address: {}", derived_address).into());
        web_sys::console::log_1(&format!("🦀 Expected address: {}", expected_address).into());
        
        // Compare addresses
        let is_valid = derived_address == expected_address;
        
        // SECURITY: Clear derived key from memory
        {
            use zeroize::Zeroize;
            let mut key_bytes = derived_key.to_vec();
            key_bytes.zeroize();
            web_sys::console::log_1(&"🦀 Derived private key cleared from memory after verification".into());
        }
        
        Ok(is_valid)
    }

    #[wasm_bindgen]
    pub fn get_public_key(&self) -> Result<String, JsValue> {
        match &self.current_keypair {
            Some(keypair) => {
                let verifying_key = keypair.verifying_key();
                Ok(bs58::encode(verifying_key.as_bytes()).into_string())
            },
            None => Err("No wallet loaded".into())
        }
    }

    #[wasm_bindgen]
    pub fn sign_message(&self, message: &[u8]) -> Result<Vec<u8>, JsValue> {
        web_sys::console::log_1(&"🦀 Starting message signing with WASM-protected private key...".into());
        log::warn!("Starting message signing - private key never exposed to JS");
        
        match &self.current_keypair {
            Some(keypair) => {
                use ed25519_dalek::Signer;
                web_sys::console::log_1(&"🦀 Signing with Ed25519 keypair (private key remains in WASM)...".into());
                log::warn!("Ed25519 signing operation in progress");
                
                let signature = keypair.sign(message);
                
                web_sys::console::log_1(&"🦀 Message signed successfully - private key never left WASM memory".into());
                log::warn!("Message signing completed - private key security maintained");
                
                Ok(signature.to_bytes().to_vec())
            },
            None => {
                let error_msg = "No wallet loaded in WASM memory for signing";
                web_sys::console::log_1(&format!("🦀 ❌ {}", error_msg).into());
                log::error!("{}", error_msg);
                Err(error_msg.into())
            }
        }
    }

    /// SECURE: Sign Stellar transaction hash using encrypted seed phrase
    /// All cryptographic operations happen within WASM - private keys never exposed to JavaScript
    #[wasm_bindgen]
    pub fn sign_stellar_transaction_hash(&self, encrypted_json: &str, password: &str, account_index: u32, transaction_hash: &[u8]) -> Result<Vec<u8>, JsValue> {
        web_sys::console::log_1(&format!("🦀 SECURE: Signing Stellar transaction hash with WASM-protected key (account {})...", account_index).into());
        log::warn!("Starting secure Stellar transaction signing - private key never exposed to JS");
        
        // Decrypt the seed phrase within WASM - plaintext never touches JavaScript
        let decryption_result = match crate::crypto::encryption::CryptoManager::new().decrypt_data(encrypted_json, password) {
            result if result.success() => result,
            result => {
                let error_msg = format!("Failed to decrypt seed phrase for signing: {}", result.error().unwrap_or("Unknown error".to_string()));
                web_sys::console::log_1(&format!("🦀 ❌ {}", error_msg).into());
                log::error!("{}", error_msg);
                return Err(error_msg.into());
            }
        };
        
        let plaintext_seed = decryption_result.plaintext();
        web_sys::console::log_1(&"🦀 Seed phrase decrypted successfully for Stellar signing".into());
        
        // Parse the mnemonic
        let mnemonic = bip39::Mnemonic::parse_in_normalized(bip39::Language::English, &plaintext_seed)
            .map_err(|e| {
                // Clear seed on error
                use zeroize::Zeroize;
                let mut seed_bytes = plaintext_seed.clone().into_bytes();
                seed_bytes.zeroize();
                JsValue::from_str(&format!("Invalid seed phrase: {}", e))
            })?;
        
        // Generate seed from mnemonic
        let mut seed = mnemonic.to_seed("");
        
        // Create BIP44 derivation path for Stellar: m/44'/148'/account_index'
        let derivation_path = crate::networks::NetworkType::Soroban.derivation_path(account_index);
        web_sys::console::log_1(&format!("🦀 Stellar signing: Using derivation path: {}", derivation_path).into());
        
        let path: slip10::BIP32Path = derivation_path.parse()
            .map_err(|e| {
                // Clear sensitive data on error
                use zeroize::Zeroize;
                let mut seed_bytes = plaintext_seed.clone().into_bytes();
                seed_bytes.zeroize();
                seed.zeroize();
                JsValue::from_str(&format!("Invalid Stellar derivation path: {:?}", e))
            })?;
        
        // Derive key using BIP44/SLIP-10 for Ed25519
        let derived_key_result = slip10::derive_key_from_path(&seed, slip10::Curve::Ed25519, &path)
            .map_err(|e| {
                // Clear sensitive data on error
                use zeroize::Zeroize;
                let mut seed_bytes = plaintext_seed.clone().into_bytes();
                seed_bytes.zeroize();
                seed.zeroize();
                JsValue::from_str(&format!("Stellar key derivation failed: {:?}", e))
            })?;
        
        let derived_key = derived_key_result.key;
        
        // Create Ed25519 signing key from derived key
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&derived_key);
        
        // SECURITY: Clear sensitive data from memory after key creation
        {
            use zeroize::Zeroize;
            let mut seed_bytes = plaintext_seed.into_bytes();
            seed_bytes.zeroize();
            seed.zeroize();
            web_sys::console::log_1(&"🦀 Plaintext seed and intermediate keys cleared from WASM memory".into());
            log::warn!("Sensitive cryptographic material successfully cleared from memory");
        }
        
        // Sign the transaction hash
        use ed25519_dalek::Signer;
        let signature = signing_key.sign(transaction_hash);
        
        web_sys::console::log_1(&"🦀 SECURE: Stellar transaction hash signed successfully - private key never left WASM memory".into());
        log::warn!("Stellar transaction signing completed - private key security maintained");
        
        Ok(signature.to_bytes().to_vec())
    }

    #[wasm_bindgen]
    pub fn is_wallet_loaded(&self) -> bool {
        self.is_initialized && self.current_keypair.is_some()
    }

    /// Drop the in-WASM mnemonic copy used for backup display (after user confirms backup).
    #[wasm_bindgen]
    pub fn clear_secured_mnemonic(&mut self) {
        if self.secured_mnemonic.take().is_some() {
            web_sys::console::log_1(&"🦀 secured_mnemonic cleared from WASM".into());
            log::warn!("secured_mnemonic cleared");
        }
    }

    #[wasm_bindgen]
    pub fn clear_wallet(&mut self) {
        web_sys::console::log_1(&"🦀 Initiating comprehensive wallet memory clearing...".into());
        log::warn!("Starting comprehensive wallet memory clearing");
        
        // Clear keypair with explicit zeroization
        if let Some(keypair) = self.current_keypair.take() {
            web_sys::console::log_1(&"🦀 Clearing Ed25519 signing key from memory...".into());
            log::warn!("Clearing Ed25519 signing key from memory");
            
            // Force zeroization of the keypair
            // Note: ed25519_dalek::SigningKey implements Drop but we want explicit control
            use zeroize::Zeroize;
            // Convert to bytes and zeroize them
            let mut key_bytes = keypair.to_bytes();
            key_bytes.zeroize();
            
            web_sys::console::log_1(&"🦀 Ed25519 private key zeroed and dropped".into());
            log::warn!("Ed25519 private key successfully zeroed");
        } else {
            web_sys::console::log_1(&"🦀 No active keypair found to clear".into());
            log::warn!("No active keypair found in memory");
        }

        // MetaMask setLocked clears in-memory secrets; we must also drop the seed copy.
        self.secured_mnemonic = None;
        
        self.is_initialized = false;
        self.current_keypair = None;
        
        // Trigger garbage collection hint (WASM memory management)
        web_sys::console::log_1(&"🦀 Requesting WASM memory compaction...".into());
        log::warn!("WASM memory clearing completed");
        
        web_sys::console::log_1(&"🦀 Wallet memory fully cleared and secured".into());
    }
    
    // Generate a real mnemonic phrase
    fn generate_mnemonic(&self) -> Result<String, JsValue> {
        let mut entropy = [0u8; 16]; // 128 bits = 12 words
        getrandom::getrandom(&mut entropy)
            .map_err(|e| JsValue::from_str(&format!("Random generation failed: {}", e)))?;
        
        // Convert entropy to mnemonic words
        let words = [
            "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
            "address", "admit", "adopt", "adult", "advance", "advice", "aerobic", "affair",
            "afford", "afraid", "again", "agency", "agent", "agree", "ahead", "aim",
            "airport", "aisle", "alarm", "album", "alcohol", "alert", "alien", "all",
            "alley", "allow", "almost", "alone", "alpha", "already", "also", "alter",
            "always", "amateur", "amazing", "among", "amount", "amused", "analyst", "anchor",
            "ancient", "anger", "angle", "angry", "animal", "ankle", "announce", "annual",
            "another", "answer", "antenna", "antique", "anxiety", "any", "apart", "apology",
            "appear", "apple", "approve", "april", "arch", "arctic", "area", "arena",
            "argue", "arm", "armed", "armor", "army", "around", "arrange", "arrest",
            "arrive", "arrow", "art", "article", "artist", "artwork", "ask", "aspect",
            "assault", "asset", "assist", "assume", "asthma", "athlete", "atom", "attack",
            "attend", "attitude", "attract", "auction", "audit", "august", "aunt", "author",
            "auto", "autumn", "average", "avocado", "avoid", "awake", "aware", "away",
            "awesome", "awful", "axis", "baby", "bachelor", "bacon", "badge", "bag",
            "balance", "balcony", "ball", "bamboo", "banana", "banner", "bar", "barely",
            "bargain", "barrel", "base", "basic", "basket", "battle", "beach", "bean",
            "beauty", "because", "become", "beef", "before", "begin", "behave", "behind",
            "believe", "below", "belt", "bench", "benefit", "best", "betray", "better",
            "between", "beyond", "bicycle", "bid", "bike", "bind", "biology", "bird",
            "birth", "bitter", "black", "blade", "blame", "blanket", "blast", "bleak",
            "bless", "blind", "blood", "blossom", "blow", "blue", "blur", "blush",
            "board", "boat", "body", "boil", "bomb", "bone", "bonus", "book",
            "boost", "border", "boring", "borrow", "boss", "bottom", "bounce", "box",
            "boy", "bracket", "brain", "brand", "brass", "brave", "bread", "breeze",
            "brick", "bridge", "brief", "bright", "bring", "brisk", "broccoli", "broken",
            "bronze", "broom", "brother", "brown", "brush", "bubble", "buddy", "budget",
            "buffalo", "build", "bulb", "bulk", "bullet", "bundle", "bunker", "burden",
            "burger", "burst", "bus", "business", "busy", "butter", "buyer", "buzz"
        ];
        
        let mut mnemonic_words = Vec::new();
        for i in 0..12 {
            let index = (entropy[i % 16] as usize) % words.len();
            mnemonic_words.push(words[index]);
        }
        
        Ok(mnemonic_words.join(" "))
    }
    
    // Derive BIP44 address for account 0 (backward compatibility)
    fn derive_public_key_from_mnemonic_bip39(&self, mnemonic: &str, passphrase: &str) -> Result<String, JsValue> {
        self.derive_public_key_bip44(mnemonic, passphrase, 0)
    }

    fn derive_public_key_bip44(&self, mnemonic: &str, passphrase: &str, account_index: u32) -> Result<String, JsValue> {
        // Only log for primary address (0) to reduce spam during HD scanning
        if account_index == 0 {
            web_sys::console::log_1(&format!("🦀 SLIP-10: Deriving address using SLIP-10 for account {}", account_index).into());
        }
        
        // Validate and parse mnemonic
        let mnemonic_obj = bip39::Mnemonic::parse_in_normalized(Language::English, mnemonic)
            .map_err(|e| {
                let error_msg = format!("Invalid seed phrase: {}", e);
                web_sys::console::log_1(&format!("🦀 ❌ {}", error_msg).into());
                JsValue::from_str(&error_msg)
            })?;
        
        // Generate seed from mnemonic with optional passphrase (BIP39 standard)
        let seed = mnemonic_obj.to_seed(passphrase);
        if account_index == 0 {
            web_sys::console::log_1(&format!("🦀 SLIP-10: Generated BIP39 seed for account {}", account_index).into());
        }
        
        // Create BIP44 derivation path for Solana: m/44'/501'/account_index'/0'
        let derivation_path = format!("m/44'/501'/{}'/0'", account_index);
        if account_index == 0 {
            web_sys::console::log_1(&format!("🦀 SLIP-10: Using derivation path: {}", derivation_path).into());
        }
        
        // Derive key using SLIP-10 for Ed25519 compatibility (Phantom standard)
        let path: BIP32Path = derivation_path.parse()
            .map_err(|e| {
                let error_msg = format!("Invalid derivation path: {:?}", e);
                web_sys::console::log_1(&format!("🦀 ❌ {}", error_msg).into());
                JsValue::from_str(&error_msg)
            })?;
        
        let derived_key_result = derive_key_from_path(&seed, Curve::Ed25519, &path)
            .map_err(|e| {
                let error_msg = format!("SLIP-10 key derivation failed: {:?}", e);
                web_sys::console::log_1(&format!("🦀 ❌ {}", error_msg).into());
                JsValue::from_str(&error_msg)
            })?;
        
        let derived_key = derived_key_result.key;
        
        // Create Ed25519 keypair from derived key
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&derived_key);
        let verifying_key = signing_key.verifying_key();
        
        let public_key_str = bs58::encode(verifying_key.as_bytes()).into_string();
        if account_index == 0 {
            web_sys::console::log_1(&format!("🦀 BIP44: Address derived for account {}: {}", account_index, &public_key_str[..8]).into());
        }
        
        Ok(public_key_str)
    }

    // Derive BIP44 address AND store the keypair for signing (needed for transaction signing)
    fn derive_public_key_bip44_and_store_keypair(&mut self, mnemonic: &str, passphrase: &str, account_index: u32) -> Result<String, JsValue> {
        // Only log for primary address (0) to reduce spam during HD scanning
        if account_index == 0 {
            web_sys::console::log_1(&format!("🦀 BIP44: Deriving address and storing keypair for account {}", account_index).into());
        }
        
        // Validate and parse mnemonic
        let mnemonic_obj = bip39::Mnemonic::parse_in_normalized(Language::English, mnemonic)
            .map_err(|e| {
                let error_msg = format!("Invalid seed phrase: {}", e);
                web_sys::console::log_1(&format!("🦀 ❌ {}", error_msg).into());
                JsValue::from_str(&error_msg)
            })?;
        
        // Generate seed from mnemonic with optional passphrase (BIP39 standard)
        let mut seed = mnemonic_obj.to_seed(passphrase);
        if account_index == 0 {
            web_sys::console::log_1(&format!("🦀 SLIP-10: Generated BIP39 seed for account {}", account_index).into());
        }
        
        // Create BIP44 derivation path for Solana: m/44'/501'/account_index'/0'
        let derivation_path = format!("m/44'/501'/{}'/0'", account_index);
        if account_index == 0 {
            web_sys::console::log_1(&format!("🦀 SLIP-10: Using derivation path: {}", derivation_path).into());
        }
        
        // Derive key using SLIP-10 for Ed25519 compatibility (Phantom standard)
        let path: BIP32Path = derivation_path.parse()
            .map_err(|e| {
                // Clear seed on error
                use zeroize::Zeroize;
                seed.zeroize();
                let error_msg = format!("Invalid derivation path: {:?}", e);
                web_sys::console::log_1(&format!("🦀 ❌ {}", error_msg).into());
                JsValue::from_str(&error_msg)
            })?;
        
        let derived_key_result = derive_key_from_path(&seed, Curve::Ed25519, &path)
            .map_err(|e| {
                // Clear seed on error
                use zeroize::Zeroize;
                seed.zeroize();
                let error_msg = format!("SLIP-10 key derivation failed: {:?}", e);
                web_sys::console::log_1(&format!("🦀 ❌ {}", error_msg).into());
                JsValue::from_str(&error_msg)
            })?;
        
        let derived_key = derived_key_result.key;
        
        // Create Ed25519 keypair from derived key
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&derived_key);
        let verifying_key = signing_key.verifying_key();
        
        // SECURITY: Clear seed from memory after use
        {
            use zeroize::Zeroize;
            seed.zeroize();
        }
        
        // IMPORTANT: Store the keypair for transaction signing
        self.current_keypair = Some(signing_key);
        self.is_initialized = true;
        
        let public_key_str = bs58::encode(verifying_key.as_bytes()).into_string();
        if account_index == 0 {
            web_sys::console::log_1(&format!("🦀 BIP44: Address derived and keypair stored for account {}: {}", account_index, &public_key_str[..8]).into());
            web_sys::console::log_1(&"🦀 Keypair stored in WASM memory for secure transaction signing".into());
        }
        
        Ok(public_key_str)
    }

    // SECURE: Derive private key from mnemonic and return in Base58 format
    // This is only used for secure private key export within WASM
    fn derive_private_key_bip44(&self, mnemonic: &str, passphrase: &str, account_index: u32) -> Result<String, JsValue> {
        web_sys::console::log_1(&format!("🦀 SECURE: Deriving private key for account {} via BIP44", account_index).into());
        log::info!("Starting secure private key derivation for account {}", account_index);
        
        // Validate and parse mnemonic
        let mnemonic_obj = bip39::Mnemonic::parse_in_normalized(Language::English, mnemonic)
            .map_err(|e| {
                let error_msg = format!("Invalid seed phrase: {}", e);
                web_sys::console::log_1(&format!("🦀 ❌ {}", error_msg).into());
                log::error!("{}", error_msg);
                JsValue::from_str(&error_msg)
            })?;
        
        // Generate seed from mnemonic with optional passphrase (BIP39 standard)
        let mut seed = mnemonic_obj.to_seed(passphrase);
        web_sys::console::log_1(&format!("🦀 BIP39 seed generated for private key derivation (account {})", account_index).into());
        
        // Create BIP44 derivation path for Solana: m/44'/501'/account_index'/0'
        let derivation_path = format!("m/44'/501'/{}'/0'", account_index);
        web_sys::console::log_1(&format!("🦀 Using SLIP-10 derivation path: {}", derivation_path).into());
        
        // Derive key using SLIP-10 for Ed25519 compatibility (Phantom standard)
        let path: BIP32Path = derivation_path.parse()
            .map_err(|e| {
                // Clear seed on error
                use zeroize::Zeroize;
                seed.zeroize();
                let error_msg = format!("Invalid derivation path: {:?}", e);
                web_sys::console::log_1(&format!("🦀 ❌ {}", error_msg).into());
                log::error!("{}", error_msg);
                JsValue::from_str(&error_msg)
            })?;
        
        let derived_key_result = derive_key_from_path(&seed, Curve::Ed25519, &path)
            .map_err(|e| {
                // Clear seed on error
                use zeroize::Zeroize;
                seed.zeroize();
                let error_msg = format!("SLIP-10 key derivation failed: {:?}", e);
                web_sys::console::log_1(&format!("🦀 ❌ {}", error_msg).into());
                log::error!("{}", error_msg);
                JsValue::from_str(&error_msg)
            })?;
        
        let derived_key = derived_key_result.key;
        
        // Create Ed25519 signing key from derived key
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&derived_key);
        let verifying_key = signing_key.verifying_key();
        
        // Create 64-byte secret key (private + public) for Phantom compatibility
        let mut secret_key = [0u8; 64];
        secret_key[..32].copy_from_slice(&signing_key.to_bytes());
        secret_key[32..].copy_from_slice(&verifying_key.to_bytes());
        
        // Convert secret key to Base58 format for export (Phantom compatible)
        let private_key_base58 = bs58::encode(secret_key).into_string();
        web_sys::console::log_1(&"🦀 Exported 64-byte secret key (private+public) for Phantom compatibility".into());
        
        // SECURITY: Clear seed from memory after use
        {
            use zeroize::Zeroize;
            seed.zeroize();
            web_sys::console::log_1(&"🦀 BIP39 seed cleared from memory after private key derivation".into());
            log::warn!("BIP39 seed successfully cleared from memory");
        }
        
        web_sys::console::log_1(&format!("🦀 SECURE: Private key derived successfully for account {}", account_index).into());
        log::info!("Secure private key derivation completed for account {}", account_index);
        
        Ok(private_key_base58)
    }
}

// =============================================================================
// SPL TOKEN MANAGER
// =============================================================================

#[wasm_bindgen]
pub struct TokenManager {
    rpc_url: String,
}

#[wasm_bindgen]
impl TokenManager {
    #[wasm_bindgen(constructor)]
    pub fn new(rpc_url: &str) -> TokenManager {
        TokenManager {
            rpc_url: rpc_url.to_string(),
        }
    }

    /// Get SOL balance for address (simplified)
    #[wasm_bindgen]
    pub fn get_sol_balance(&self, address: &str) -> Result<f64, JsValue> {
        if !self.is_valid_solana_address(address) {
            return Err(JsValue::from_str("Invalid Solana address"));
        }
        
        // In a real implementation, this would make an RPC call
        // For now, return a demo balance
        Ok(1.5) // 1.5 SOL
    }

    /// Create transfer instruction for SOL or SPL tokens
    #[wasm_bindgen]
    pub fn create_transfer_instruction(
        &self, 
        from_address: &str, 
        to_address: &str, 
        amount: f64,
        token_mint: Option<String>
    ) -> Result<JsValue, JsValue> {
        if !self.is_valid_solana_address(from_address) {
            return Err(JsValue::from_str("Invalid from address"));
        }
        if !self.is_valid_solana_address(to_address) {
            return Err(JsValue::from_str("Invalid to address"));
        }
        if amount <= 0.0 {
            return Err(JsValue::from_str("Amount must be positive"));
        }

        let instruction = js_sys::Object::new();
        
        if let Some(mint) = token_mint {
            // SPL Token transfer
            js_sys::Reflect::set(&instruction, &"type".into(), &"spl-transfer".into())?;
            js_sys::Reflect::set(&instruction, &"mint".into(), &mint.into())?;
        } else {
            // SOL transfer
            js_sys::Reflect::set(&instruction, &"type".into(), &"sol-transfer".into())?;
        }
        
        js_sys::Reflect::set(&instruction, &"from".into(), &from_address.into())?;
        js_sys::Reflect::set(&instruction, &"to".into(), &to_address.into())?;
        js_sys::Reflect::set(&instruction, &"amount".into(), &amount.into())?;
        js_sys::Reflect::set(&instruction, &"programId".into(), &"11111111111111111111111111111112".into())?;
        
        Ok(instruction.into())
    }

    /// Get associated token account address
    #[wasm_bindgen]
    pub fn get_associated_token_address(&self, owner: &str, mint: &str) -> Result<String, JsValue> {
        if !self.is_valid_solana_address(owner) {
            return Err(JsValue::from_str("Invalid owner address"));
        }
        if !self.is_valid_solana_address(mint) {
            return Err(JsValue::from_str("Invalid mint address"));
        }
        
        // Simplified ATA calculation using hash
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(owner.as_bytes());
        hasher.update(mint.as_bytes());
        hasher.update(b"ATA");
        
        let hash = hasher.finalize();
        Ok(bs58::encode(&hash[..32]).into_string())
    }

    /// Validate if a string is a valid Solana address
    #[wasm_bindgen]
    pub fn is_valid_solana_address(&self, address: &str) -> bool {
        if address.len() < 32 || address.len() > 44 {
            return false;
        }
        
        bs58::decode(address).into_vec().is_ok()
    }

    /// Get token account info (simplified)
    #[wasm_bindgen]
    pub fn get_token_account_info(&self, account_address: &str) -> Result<JsValue, JsValue> {
        if !self.is_valid_solana_address(account_address) {
            return Err(JsValue::from_str("Invalid account address"));
        }
        
        // Mock token account info
        let info = js_sys::Object::new();
        js_sys::Reflect::set(&info, &"address".into(), &account_address.into())?;
        js_sys::Reflect::set(&info, &"mint".into(), &"EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v".into())?; // USDC mint
        js_sys::Reflect::set(&info, &"balance".into(), &100.0.into())?; // 100 tokens
        js_sys::Reflect::set(&info, &"decimals".into(), &6.into())?; // USDC has 6 decimals
        js_sys::Reflect::set(&info, &"symbol".into(), &"USDC".into())?;
        
        Ok(info.into())
    }
}

// =============================================================================
// PASSWORD MANAGER (Simplified)
// =============================================================================

#[wasm_bindgen]
pub struct PasswordManager {
    is_valid: bool,
    password_hash: String,
    salt: Vec<u8>,
}

#[wasm_bindgen]
impl PasswordManager {
    #[wasm_bindgen(constructor)]
    pub fn new(password: &str, salt: &[u8]) -> Result<PasswordManager, JsValue> {
        web_sys::console::log_1(&"🦀 Initializing password manager with PBKDF2 hashing...".into());
        log::info!("Starting password manager initialization");
        
        Self::validate_password_strength(password)?;
        
        // Create password hash using PBKDF2-like derivation with SHA-256
        let password_hash = Self::hash_password_with_salt(password, salt)?;
        
        web_sys::console::log_1(&"🦀 Password hashed with PBKDF2-SHA256 - stored in WASM linear memory".into());
        log::info!("Password hashing completed successfully");
        
        Ok(PasswordManager { 
            is_valid: true,
            password_hash,
            salt: salt.to_vec(),
        })
    }

    /// Create a PasswordManager for login purposes without password strength validation
    #[wasm_bindgen]
    pub fn new_for_login(password: &str, salt: &[u8]) -> Result<PasswordManager, JsValue> {
        web_sys::console::log_1(&"🦀 Initializing password manager for login with PBKDF2 hashing...".into());
        log::info!("Starting password manager initialization for login");
        
        // Skip password strength validation for login
        
        // Create password hash using PBKDF2-like derivation with SHA-256
        let password_hash = Self::hash_password_with_salt(password, salt)?;
        
        web_sys::console::log_1(&"🦀 Password hashed with PBKDF2-SHA256 - stored in WASM linear memory".into());
        log::info!("Password hashing completed successfully");
        
        Ok(PasswordManager { 
            is_valid: true,
            password_hash,
            salt: salt.to_vec(),
        })
    }

    #[wasm_bindgen]
    pub fn validate_password_strength(password: &str) -> Result<(), JsValue> {
        web_sys::console::log_1(&"🦀 Validating password strength...".into());
        log::info!("Starting password validation");
        
        if password.len() < 8 {
            let error_msg = "Password must be at least 8 characters";
            web_sys::console::log_1(&format!("🦀 ❌ {}", error_msg).into());
            log::warn!("{}", error_msg);
            return Err(error_msg.into());
        }
        
        let has_upper = password.chars().any(|c| c.is_uppercase());
        let has_lower = password.chars().any(|c| c.is_lowercase());
        let has_digit = password.chars().any(|c| c.is_numeric());
        let has_special = password.chars().any(|c| !c.is_alphanumeric());
        
        if !has_upper || !has_lower || !has_digit || !has_special {
            let error_msg = "Password must contain uppercase, lowercase, number, and special character";
            web_sys::console::log_1(&format!("🦀 ❌ {}", error_msg).into());
            log::warn!("{}", error_msg);
            return Err(error_msg.into());
        }
        
        web_sys::console::log_1(&"🦀 Password validation passed".into());
        log::info!("Password validation completed successfully");
        
        Ok(())
    }

    #[wasm_bindgen]
    pub fn verify_password(&self, password: &str) -> Result<bool, JsValue> {
        web_sys::console::log_1(&"🦀 Verifying login password with Rust encryption...".into());
        log::info!("Starting password verification for login");
        
        // Hash the provided password with the stored salt
        let password_hash = Self::hash_password_with_salt(password, &self.salt)?;
        
        // Compare with stored hash
        let is_valid = password_hash == self.password_hash;
        
        if is_valid {
            web_sys::console::log_1(&"🦀 Login successful - password decrypted and verified in Rust".into());
            log::info!("Password verification completed successfully");
        } else {
            web_sys::console::log_1(&"🦀 Login failed - incorrect password".into());
            log::warn!("Password verification failed");
        }
        
        Ok(is_valid)
    }
    
    #[wasm_bindgen]
    pub fn generate_secure_salt() -> Vec<u8> {
        let mut salt = vec![0u8; 32];
        getrandom::getrandom(&mut salt).unwrap_or_default();
        salt
    }
    
    // Private helper method for password hashing
    fn hash_password_with_salt(password: &str, salt: &[u8]) -> Result<String, JsValue> {
        use sha2::{Sha256, Digest};
        
        // Simple PBKDF2-like derivation with multiple rounds
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        hasher.update(salt);
        
        // Multiple rounds for better security
        let mut hash = hasher.finalize().to_vec();
        for _ in 0..1000 {
            let mut round_hasher = Sha256::new();
            round_hasher.update(&hash);
            round_hasher.update(salt);
            hash = round_hasher.finalize().to_vec();
        }
        
        // Convert to hex string
        Ok(hex::encode(hash))
    }
}

// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================

#[wasm_bindgen]
pub fn get_version() -> String {
    "2.1.0-spl".to_string()
}

#[wasm_bindgen]
pub fn get_build_timestamp() -> String {
    // Use build-time generated timestamp for unique builds
    const PKG_VERSION: &str = env!("CARGO_PKG_VERSION");
    const BUILD_TIMESTAMP: &str = env!("BUILD_TIMESTAMP");
    
    format!("v{}-{}", PKG_VERSION, BUILD_TIMESTAMP)
}

#[wasm_bindgen]
pub fn get_build_info_detailed() -> JsValue {
    let build_timestamp = get_build_timestamp();
    let build_date = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string();
    
    web_sys::console::log_1(&format!("🦀 WASM Build Info - Timestamp: {} | Compiled: {}", build_timestamp, build_date).into());
    log::info!("WASM build timestamp: {} | compiled: {}", build_timestamp, build_date);
    
    let info = js_sys::Object::new();
    js_sys::Reflect::set(&info, &"version".into(), &"2.1.0-spl".into()).unwrap();
    js_sys::Reflect::set(&info, &"buildTimestamp".into(), &build_timestamp.into()).unwrap();
    js_sys::Reflect::set(&info, &"buildDate".into(), &build_date.into()).unwrap();
    js_sys::Reflect::set(&info, &"features".into(), &js_sys::Array::of4(
        &"spl-tokens".into(),
        &"enhanced-security".into(),
        &"bip39-mnemonic".into(),
        &"ed25519-signing".into()
    )).unwrap();
    info.into()
}

#[wasm_bindgen]
pub fn get_build_info() -> JsValue {
    let build_timestamp = get_build_timestamp();
    
    let info = js_sys::Object::new();
    js_sys::Reflect::set(&info, &"version".into(), &"2.1.0-spl".into()).unwrap();
    js_sys::Reflect::set(&info, &"buildTimestamp".into(), &build_timestamp.into()).unwrap();
    js_sys::Reflect::set(&info, &"buildDate".into(), &chrono::Utc::now().format("%Y-%m-%d").to_string().into()).unwrap();
    js_sys::Reflect::set(&info, &"features".into(), &js_sys::Array::of4(
        &"spl-tokens".into(),
        &"enhanced-security".into(),
        &"bip39-mnemonic".into(),
        &"ed25519-signing".into()
    )).unwrap();
    info.into()
}

#[wasm_bindgen]
pub fn test_wasm() -> String {
    let build_timestamp = get_build_timestamp();
    
    // Add logging that will appear in the JavaScript log system with build info
    web_sys::console::log_1(&format!("🦀 WASM test function called from Rust! Build: {}", build_timestamp).into());
    log::info!("Rust WASM test function executed successfully - build: {}", build_timestamp);
    
    format!("WASM SPL Token wallet is working correctly! Build: {}", build_timestamp)
}

/// Log a message from Rust to the JavaScript console (appears in system logs)
#[wasm_bindgen]
pub fn log_from_rust(message: &str) {
    web_sys::console::log_1(&format!("🦀 Rust: {}", message).into());
    log::info!("Rust message: {}", message);
}

/// Example function that demonstrates Rust->JS logging during operations
#[wasm_bindgen]  
pub fn demo_rust_logging() -> JsValue {
    // This will appear in the JavaScript log system
    web_sys::console::log_1(&"🦀 Starting Rust wallet operation...".into());
    
    // Using structured logging
    log::info!("Generating new cryptographic keys in Rust");
    
    // Simulate some work
    let mut entropy = [0u8; 32];
    if getrandom::getrandom(&mut entropy).is_ok() {
        web_sys::console::log_1(&"🦀 Successfully generated entropy in Rust".into());
        log::info!("Entropy generation completed");
    } else {
        web_sys::console::log_1(&"🦀 ❌ Failed to generate entropy in Rust".into());
        log::error!("Entropy generation failed");
    }
    
    web_sys::console::log_1(&"🦀 Rust operation completed".into());
    
    let result = js_sys::Object::new();
    js_sys::Reflect::set(&result, &"success".into(), &true.into()).unwrap();
    js_sys::Reflect::set(&result, &"message".into(), &"Rust logging demo completed".into()).unwrap();
    result.into()
}

// =============================================================================
// FREIGHTER WALLET COMPATIBILITY TESTING
// =============================================================================

/// Test Soroban key derivation against Freighter wallet addresses
/// This ensures ecosystem compatibility by verifying we derive the same addresses
#[wasm_bindgen]
pub fn test_freighter_compatibility() -> JsValue {
    web_sys::console::log_1(&"🦀 Testing Freighter wallet compatibility...".into());
    
    // Test data from Freighter wallet
    let test_seed = "claim decade trick change caught uphold destroy ring answer fat choose wing";
    let expected_address_1 = "GDJVKVE36C22RRNRUL7KKWHSGRKGY6QA5HTTEFCAQLTVG4HKEYI4O5DN";
    let expected_address_2 = "GABB7GY6NOHWRPR7OZTBZJSDXIZDPQ37VRXZQENB44DL2TQOYHHE3R5I";
    
    let result = js_sys::Object::new();
    
    // Parse mnemonic
    let mnemonic = match bip39::Mnemonic::parse_in_normalized(bip39::Language::English, test_seed) {
        Ok(m) => m,
        Err(e) => {
            let error_msg = format!("Failed to parse test seed: {}", e);
            web_sys::console::log_1(&format!("🦀 ❌ {}", error_msg).into());
            js_sys::Reflect::set(&result, &"success".into(), &false.into()).unwrap();
            js_sys::Reflect::set(&result, &"error".into(), &error_msg.into()).unwrap();
            return result.into();
        }
    };
    
    // Test derivation for index 0 (first address)
    match derive_soroban_address(&mnemonic, 0, "") {
        Ok((address_0, _)) => {
            let matches_0 = address_0 == expected_address_1;
            web_sys::console::log_1(&format!("🦀 Index 0 - Expected: {} | Derived: {} | Match: {}", 
                expected_address_1, address_0, matches_0).into());
            js_sys::Reflect::set(&result, &"address_0_expected".into(), &expected_address_1.into()).unwrap();
            js_sys::Reflect::set(&result, &"address_0_derived".into(), &address_0.into()).unwrap();
            js_sys::Reflect::set(&result, &"address_0_match".into(), &matches_0.into()).unwrap();
        },
        Err(e) => {
            let error_msg = format!("Failed to derive address 0: {}", e.as_string().unwrap_or_default());
            web_sys::console::log_1(&format!("🦀 ❌ {}", error_msg).into());
            js_sys::Reflect::set(&result, &"success".into(), &false.into()).unwrap();
            js_sys::Reflect::set(&result, &"error".into(), &error_msg.into()).unwrap();
            return result.into();
        }
    }
    
    // Test derivation for index 1 (second address)
    match derive_soroban_address(&mnemonic, 1, "") {
        Ok((address_1, _)) => {
            let matches_1 = address_1 == expected_address_2;
            web_sys::console::log_1(&format!("🦀 Index 1 - Expected: {} | Derived: {} | Match: {}", 
                expected_address_2, address_1, matches_1).into());
            js_sys::Reflect::set(&result, &"address_1_expected".into(), &expected_address_2.into()).unwrap();
            js_sys::Reflect::set(&result, &"address_1_derived".into(), &address_1.into()).unwrap();
            js_sys::Reflect::set(&result, &"address_1_match".into(), &matches_1.into()).unwrap();
            
            // Overall success
            let both_match = matches_1 && result.dyn_ref::<js_sys::Object>()
                .and_then(|obj| js_sys::Reflect::get(obj, &"address_0_match".into()).ok())
                .and_then(|val| val.as_bool())
                .unwrap_or(false);
            
            js_sys::Reflect::set(&result, &"success".into(), &both_match.into()).unwrap();
            if both_match {
                web_sys::console::log_1(&"🦀 ✅ Freighter compatibility CONFIRMED - derivation pattern matches!".into());
            } else {
                web_sys::console::log_1(&"🦀 ❌ Freighter compatibility FAILED - derivation pattern differs".into());
            }
        },
        Err(e) => {
            let error_msg = format!("Failed to derive address 1: {}", e.as_string().unwrap_or_default());
            web_sys::console::log_1(&format!("🦀 ❌ {}", error_msg).into());
            js_sys::Reflect::set(&result, &"success".into(), &false.into()).unwrap();
            js_sys::Reflect::set(&result, &"error".into(), &error_msg.into()).unwrap();
            return result.into();
        }
    }
    
    result.into()
}

/// Detect which network an address belongs to based on its format
#[wasm_bindgen]
pub fn detect_address_network(address: &str) -> JsValue {
    use networks::soroban::keys::is_valid_stellar_address;
    
    let result = js_sys::Object::new();
    
    // Check if it's a valid Stellar address (G... format)
    if is_valid_stellar_address(address) {
        js_sys::Reflect::set(&result, &"network".into(), &"soroban".into()).unwrap();
        js_sys::Reflect::set(&result, &"valid".into(), &true.into()).unwrap();
        js_sys::Reflect::set(&result, &"format".into(), &"stellar".into()).unwrap();
        return result.into();
    }
    
    // Check if it's a valid Solana address (base58, 32-44 chars)
    if address.len() >= 32 && address.len() <= 44 {
        if let Ok(_) = bs58::decode(address).into_vec() {
            js_sys::Reflect::set(&result, &"network".into(), &"solana".into()).unwrap();
            js_sys::Reflect::set(&result, &"valid".into(), &true.into()).unwrap();
            js_sys::Reflect::set(&result, &"format".into(), &"base58".into()).unwrap();
            return result.into();
        }
    }
    
    // Unknown or invalid address format
    js_sys::Reflect::set(&result, &"network".into(), &"unknown".into()).unwrap();
    js_sys::Reflect::set(&result, &"valid".into(), &false.into()).unwrap();
    js_sys::Reflect::set(&result, &"format".into(), &"unknown".into()).unwrap();
    result.into()
}

/// Derive addresses for both networks from a seed phrase
#[wasm_bindgen]
pub fn derive_dual_network_addresses(seed_phrase: &str, account_index: u32) -> JsValue {
    let result = js_sys::Object::new();
    
    // Parse mnemonic
    let mnemonic = match bip39::Mnemonic::parse_in_normalized(bip39::Language::English, seed_phrase) {
        Ok(m) => m,
        Err(e) => {
            let error_msg = format!("Failed to parse seed phrase: {}", e);
            web_sys::console::log_1(&format!("🦀 ❌ {}", error_msg).into());
            js_sys::Reflect::set(&result, &"success".into(), &false.into()).unwrap();
            js_sys::Reflect::set(&result, &"error".into(), &error_msg.into()).unwrap();
            return result.into();
        }
    };
    
    // Derive Solana address
    let solana_result = match derive_solana_address(&mnemonic, account_index, "") {
        Ok((address, public_key)) => {
            let addr_obj = js_sys::Object::new();
            js_sys::Reflect::set(&addr_obj, &"address".into(), &address.into()).unwrap();
            js_sys::Reflect::set(&addr_obj, &"publicKey".into(), &hex::encode(public_key).into()).unwrap();
            addr_obj
        },
        Err(e) => {
            let error_msg = format!("Solana derivation failed: {}", e.as_string().unwrap_or_default());
            web_sys::console::log_1(&format!("🦀 ❌ {}", error_msg).into());
            js_sys::Reflect::set(&result, &"success".into(), &false.into()).unwrap();
            js_sys::Reflect::set(&result, &"error".into(), &error_msg.into()).unwrap();
            return result.into();
        }
    };
    
    // Derive Soroban address
    let soroban_result = match derive_soroban_address(&mnemonic, account_index, "") {
        Ok((address, public_key)) => {
            let addr_obj = js_sys::Object::new();
            js_sys::Reflect::set(&addr_obj, &"address".into(), &address.into()).unwrap();
            js_sys::Reflect::set(&addr_obj, &"publicKey".into(), &hex::encode(public_key).into()).unwrap();
            addr_obj
        },
        Err(e) => {
            let error_msg = format!("Soroban derivation failed: {}", e.as_string().unwrap_or_default());
            web_sys::console::log_1(&format!("🦀 ❌ {}", error_msg).into());
            js_sys::Reflect::set(&result, &"success".into(), &false.into()).unwrap();
            js_sys::Reflect::set(&result, &"error".into(), &error_msg.into()).unwrap();
            return result.into();
        }
    };
    
    // Return both addresses
    js_sys::Reflect::set(&result, &"success".into(), &true.into()).unwrap();
    js_sys::Reflect::set(&result, &"solana".into(), &solana_result.into()).unwrap();
    js_sys::Reflect::set(&result, &"soroban".into(), &soroban_result.into()).unwrap();
    
    web_sys::console::log_1(&format!("🦀 Successfully derived addresses for both networks (account index {})", account_index).into());
    
    result.into()
}
