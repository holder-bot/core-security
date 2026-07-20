use crate::networks::NetworkType;
use bip39::Mnemonic;
use slip10::{BIP32Path, derive_key_from_path, Curve};
use ed25519_dalek::{VerifyingKey, SigningKey};
use std::str::FromStr;
use wasm_bindgen::prelude::*;

pub fn derive_solana_address(mnemonic: &Mnemonic, account_index: u32, passphrase: &str) -> Result<(String, Vec<u8>), JsValue> {
    web_sys::console::log_1(&format!("🦀 Solana: Deriving address for account index {}", account_index).into());
    
    // Generate seed from mnemonic with passphrase
    let seed = mnemonic.to_seed(passphrase);
    
    // Create BIP44 derivation path for Solana: m/44'/501'/account_index'/0'
    let derivation_path = NetworkType::Solana.derivation_path(account_index);
    web_sys::console::log_1(&format!("🦀 Solana: Using derivation path: {}", derivation_path).into());
    
    let path = BIP32Path::from_str(&derivation_path)
        .map_err(|e| JsValue::from_str(&format!("Invalid Solana derivation path: {:?}", e)))?;
    
    // Derive key using BIP44 - need to use slip10 for actual derivation
    let derived_key = derive_key_from_path(&seed, Curve::Ed25519, &path)
        .map_err(|e| JsValue::from_str(&format!("Solana key derivation failed: {:?}", e)))?;
    
    // Create ed25519 keypair
    let secret_key = SigningKey::from_bytes(&derived_key.key);
    let public_key = VerifyingKey::from(&secret_key);
    
    // Encode as base58 for Solana
    let address = bs58::encode(public_key.as_bytes()).into_string();
    
    web_sys::console::log_1(&format!("🦀 Solana: Successfully derived address: {}", &address[..8]).into());
    
    Ok((address, public_key.as_bytes().to_vec()))
}