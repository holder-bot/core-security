use crate::networks::NetworkType;
use bip39::Mnemonic;
use slip10::{BIP32Path, derive_key_from_path, Curve};
use ed25519_dalek::{VerifyingKey, SigningKey};
use stellar_strkey::{ed25519, Strkey};
use std::str::FromStr;
use wasm_bindgen::prelude::*;

pub fn derive_soroban_address(mnemonic: &Mnemonic, account_index: u32, passphrase: &str) -> Result<(String, Vec<u8>), JsValue> {
    web_sys::console::log_1(&format!("🦀 Soroban: Deriving address for account index {}", account_index).into());
    
    // Generate seed from mnemonic with passphrase
    let seed = mnemonic.to_seed(passphrase);
    
    // Create BIP44 derivation path for Stellar: m/44'/148'/0'/0/account_index
    let derivation_path = NetworkType::Soroban.derivation_path(account_index);
    web_sys::console::log_1(&format!("🦀 Soroban: Using derivation path: {}", derivation_path).into());
    
    let path = BIP32Path::from_str(&derivation_path)
        .map_err(|e| JsValue::from_str(&format!("Invalid Soroban derivation path: {:?}", e)))?;
    
    // Derive key using BIP44
    let derived_key = derive_key_from_path(&seed, Curve::Ed25519, &path)
        .map_err(|e| JsValue::from_str(&format!("Soroban key derivation failed: {:?}", e)))?;
    
    // Create ed25519 keypair
    let secret_key = SigningKey::from_bytes(&derived_key.key);
    let public_key = VerifyingKey::from(&secret_key);
    
    // Encode as Stellar account address (G...)
    let stellar_public_key = ed25519::PublicKey(*public_key.as_bytes());
    let address = stellar_public_key.to_string();
    
    web_sys::console::log_1(&format!("🦀 Soroban: Successfully derived address: {}", &address[..8]).into());
    
    Ok((address, public_key.as_bytes().to_vec()))
}

/// Validate Stellar address format
pub fn is_valid_stellar_address(address: &str) -> bool {
    if let Ok(strkey) = Strkey::from_string(address) {
        matches!(strkey, Strkey::PublicKeyEd25519(_))
    } else {
        false
    }
}