pub mod solana;
pub mod soroban;

use wasm_bindgen::prelude::*;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum NetworkType {
    Solana,
    Soroban,
}

impl NetworkType {
    pub fn coin_type(&self) -> u32 {
        match self {
            NetworkType::Solana => 501,  // Solana coin type
            NetworkType::Soroban => 148, // Stellar coin type
        }
    }

    pub fn derivation_path(&self, account_index: u32) -> String {
        match self {
            NetworkType::Solana => format!("m/44'/501'/{}'/0'", account_index),
            NetworkType::Soroban => format!("m/44'/148'/{}'", account_index), // Standard Stellar path: 3 components
        }
    }
}

#[derive(Debug, Clone)]
pub struct NetworkAddress {
    pub network: NetworkType,
    pub address: String,
    pub public_key_bytes: Vec<u8>,
}

impl NetworkAddress {
    pub fn new(network: NetworkType, address: String, public_key_bytes: Vec<u8>) -> NetworkAddress {
        NetworkAddress {
            network,
            address,
            public_key_bytes,
        }
    }

    pub fn address(&self) -> String {
        self.address.clone()
    }

    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key_bytes.clone()
    }
}