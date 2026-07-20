use wasm_bindgen::prelude::*;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AssociatedTokenAccount {
    pub address: String,
    pub owner: String,
    pub mint: String,
    pub exists: bool,
}

#[wasm_bindgen]
pub struct AssociatedAccountManager {
    associated_token_program_id: String,
    token_program_id: String,
    system_program_id: String,
    rent_sysvar_id: String,
}

#[wasm_bindgen]
impl AssociatedAccountManager {
    #[wasm_bindgen(constructor)]
    pub fn new() -> AssociatedAccountManager {
        AssociatedAccountManager {
            associated_token_program_id: "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL".to_string(),
            token_program_id: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".to_string(),
            system_program_id: "11111111111111111111111111111112".to_string(),
            rent_sysvar_id: "SysvarRent111111111111111111111111111111111".to_string(),
        }
    }

    /// Get associated token address for owner and mint
    #[wasm_bindgen]
    pub fn get_associated_token_address(&self, owner: &str, mint: &str) -> Result<String, JsValue> {
        if !self.is_valid_address(owner) {
            return Err(JsValue::from_str("Invalid owner address"));
        }
        if !self.is_valid_address(mint) {
            return Err(JsValue::from_str("Invalid mint address"));
        }
        
        // Calculate associated token address using PDA derivation
        let address = self.find_associated_token_address(owner, mint)?;
        Ok(address)
    }

    /// Create associated token account instruction
    #[wasm_bindgen]
    pub fn create_associated_token_account_instruction(
        &self,
        payer: &str,
        owner: &str,
        mint: &str,
    ) -> Result<JsValue, JsValue> {
        if !self.is_valid_address(payer) {
            return Err(JsValue::from_str("Invalid payer address"));
        }
        if !self.is_valid_address(owner) {
            return Err(JsValue::from_str("Invalid owner address"));
        }
        if !self.is_valid_address(mint) {
            return Err(JsValue::from_str("Invalid mint address"));
        }
        
        let associated_token_address = self.get_associated_token_address(owner, mint)?;
        
        let instruction = serde_json::json!({
            "programId": self.associated_token_program_id,
            "keys": [
                {"pubkey": payer, "isSigner": true, "isWritable": true},
                {"pubkey": associated_token_address, "isSigner": false, "isWritable": true},
                {"pubkey": owner, "isSigner": false, "isWritable": false},
                {"pubkey": mint, "isSigner": false, "isWritable": false},
                {"pubkey": self.system_program_id, "isSigner": false, "isWritable": false},
                {"pubkey": self.token_program_id, "isSigner": false, "isWritable": false},
                {"pubkey": self.rent_sysvar_id, "isSigner": false, "isWritable": false}
            ],
            "data": {
                "instruction": "create_associated_token_account"
            }
        });
        
        Ok(serde_wasm_bindgen::to_value(&instruction)?)
    }

    /// Create associated token account instruction (idempotent)
    #[wasm_bindgen]
    pub fn create_associated_token_account_idempotent_instruction(
        &self,
        payer: &str,
        owner: &str,
        mint: &str,
    ) -> Result<JsValue, JsValue> {
        // Same as regular create but with idempotent flag
        let mut instruction_value = self.create_associated_token_account_instruction(payer, owner, mint)?;
        
        if let Ok(mut instruction) = serde_wasm_bindgen::from_value::<serde_json::Value>(instruction_value.clone()) {
            if let Some(data) = instruction.get_mut("data") {
                data["idempotent"] = serde_json::Value::Bool(true);
            }
            return Ok(serde_wasm_bindgen::to_value(&instruction)?);
        }
        
        Ok(instruction_value)
    }

    /// Check if associated token account exists
    #[wasm_bindgen]
    pub async fn account_exists(&self, owner: &str, mint: &str) -> Result<bool, JsValue> {
        let ata_address = self.get_associated_token_address(owner, mint)?;
        
        // In real implementation, this would make an RPC call to check if account exists
        let account_data = self.fetch_account_info(&ata_address).await;
        
        match account_data {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Get associated token account info
    #[wasm_bindgen]
    pub async fn get_account_info(&self, owner: &str, mint: &str) -> Result<JsValue, JsValue> {
        let ata_address = self.get_associated_token_address(owner, mint)?;
        let exists = self.account_exists(owner, mint).await?;
        
        let account_info = AssociatedTokenAccount {
            address: ata_address,
            owner: owner.to_string(),
            mint: mint.to_string(),
            exists,
        };
        
        Ok(serde_wasm_bindgen::to_value(&account_info)?)
    }

    /// Get multiple associated token addresses
    #[wasm_bindgen]
    pub fn get_multiple_associated_token_addresses(
        &self,
        owner: &str,
        mints: Vec<String>,
    ) -> Result<JsValue, JsValue> {
        if !self.is_valid_address(owner) {
            return Err(JsValue::from_str("Invalid owner address"));
        }
        
        let mut addresses = Vec::new();
        
        for mint in mints {
            if !self.is_valid_address(&mint) {
                return Err(JsValue::from_str(&format!("Invalid mint address: {}", mint)));
            }
            
            let ata_address = self.get_associated_token_address(owner, &mint)?;
            let account_info = AssociatedTokenAccount {
                address: ata_address,
                owner: owner.to_string(),
                mint,
                exists: false, // Would need to check individually
            };
            addresses.push(account_info);
        }
        
        Ok(serde_wasm_bindgen::to_value(&addresses)?)
    }

    /// Validate associated token account ownership
    #[wasm_bindgen]
    pub fn validate_account_ownership(&self, account: &str, expected_owner: &str, mint: &str) -> Result<bool, JsValue> {
        let expected_ata = self.get_associated_token_address(expected_owner, mint)?;
        Ok(expected_ata == account)
    }

    // Private helper methods
    fn find_associated_token_address(&self, owner: &str, mint: &str) -> Result<String, JsValue> {
        // Simplified PDA calculation for associated token address
        // Real implementation would use proper Solana PDA derivation
        use sha2::{Sha256, Digest};
        
        let mut hasher = Sha256::new();
        hasher.update(owner.as_bytes());
        hasher.update(self.associated_token_program_id.as_bytes());
        hasher.update(mint.as_bytes());
        
        // Add the seed for ATA derivation
        hasher.update(b"ATA_SEED");
        
        let hash = hasher.finalize();
        
        // Ensure the result is a valid ed25519 point (simplified check)
        let mut address_bytes = [0u8; 32];
        address_bytes.copy_from_slice(&hash[..32]);
        
        // Ensure it's not on the ed25519 curve (simplified)
        if address_bytes[31] & 128 != 0 {
            address_bytes[31] &= 127;
        }
        
        Ok(bs58::encode(address_bytes).into_string())
    }

    async fn fetch_account_info(&self, address: &str) -> Result<Vec<u8>, JsValue> {
        // Placeholder for RPC call to fetch account info
        // In real implementation, this would call getAccountInfo
        Err(JsValue::from_str("Account not found")) // Default to not found
    }

    fn is_valid_address(&self, address: &str) -> bool {
        // Basic validation for base58 address format
        if address.len() < 32 || address.len() > 44 {
            return false;
        }
        
        bs58::decode(address).into_vec().is_ok()
    }
}