use wasm_bindgen::prelude::*;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SplTokenAccount {
    pub mint: String,
    pub address: String,
    pub balance: u64,
    pub decimals: u8,
    pub frozen: bool,
    pub delegate: Option<String>,
    pub delegated_amount: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SplMintInfo {
    pub address: String,
    pub decimals: u8,
    pub supply: u64,
    pub mint_authority: Option<String>,
    pub freeze_authority: Option<String>,
}

#[wasm_bindgen]
pub struct SplTokenManager {
    rpc_url: String,
    token_program_id: String,
    accounts_cache: HashMap<String, Vec<SplTokenAccount>>,
    mints_cache: HashMap<String, SplMintInfo>,
}

#[wasm_bindgen]
impl SplTokenManager {
    #[wasm_bindgen(constructor)]
    pub fn new(rpc_url: &str) -> SplTokenManager {
        SplTokenManager {
            rpc_url: rpc_url.to_string(),
            token_program_id: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".to_string(),
            accounts_cache: HashMap::new(),
            mints_cache: HashMap::new(),
        }
    }

    /// Get SPL token accounts for owner
    #[wasm_bindgen]
    pub async fn get_token_accounts(&mut self, owner: &str) -> Result<JsValue, JsValue> {
        if !self.is_valid_address(owner) {
            return Err(JsValue::from_str("Invalid owner address"));
        }
        
        // Check cache first
        if let Some(cached_accounts) = self.accounts_cache.get(owner) {
            return Ok(serde_wasm_bindgen::to_value(cached_accounts)?);
        }
        
        // Fetch accounts from RPC (placeholder implementation)
        let accounts = self.fetch_token_accounts(owner).await?;
        
        // Cache results
        self.accounts_cache.insert(owner.to_string(), accounts.clone());
        
        Ok(serde_wasm_bindgen::to_value(&accounts)?)
    }

    /// Get token balance for specific account
    #[wasm_bindgen]
    pub async fn get_token_balance(&self, token_account: &str) -> Result<JsValue, JsValue> {
        if !self.is_valid_address(token_account) {
            return Err(JsValue::from_str("Invalid token account address"));
        }
        
        let account_data = self.fetch_account_data(token_account).await?;
        let account_info = self.parse_token_account(&account_data)?;
        
        Ok(serde_wasm_bindgen::to_value(&account_info)?)
    }

    /// Get mint information
    #[wasm_bindgen]
    pub async fn get_mint_info(&mut self, mint_address: &str) -> Result<JsValue, JsValue> {
        if !self.is_valid_address(mint_address) {
            return Err(JsValue::from_str("Invalid mint address"));
        }
        
        // Check cache first
        if let Some(cached_mint) = self.mints_cache.get(mint_address) {
            return Ok(serde_wasm_bindgen::to_value(cached_mint)?);
        }
        
        let mint_data = self.fetch_account_data(mint_address).await?;
        let mint_info = self.parse_mint_account(&mint_data, mint_address)?;
        
        // Cache result
        self.mints_cache.insert(mint_address.to_string(), mint_info.clone());
        
        Ok(serde_wasm_bindgen::to_value(&mint_info)?)
    }

    /// Create transfer instruction
    #[wasm_bindgen]
    pub fn create_transfer_instruction(
        &self,
        source: &str,
        destination: &str,
        authority: &str,
        amount: u64,
    ) -> Result<JsValue, JsValue> {
        if !self.is_valid_address(source) {
            return Err(JsValue::from_str("Invalid source address"));
        }
        if !self.is_valid_address(destination) {
            return Err(JsValue::from_str("Invalid destination address"));
        }
        if !self.is_valid_address(authority) {
            return Err(JsValue::from_str("Invalid authority address"));
        }
        if amount == 0 {
            return Err(JsValue::from_str("Amount must be greater than 0"));
        }
        
        let instruction = serde_json::json!({
            "programId": self.token_program_id,
            "keys": [
                {"pubkey": source, "isSigner": false, "isWritable": true},
                {"pubkey": destination, "isSigner": false, "isWritable": true},
                {"pubkey": authority, "isSigner": true, "isWritable": false}
            ],
            "data": {
                "instruction": "transfer",
                "amount": amount
            }
        });
        
        Ok(serde_wasm_bindgen::to_value(&instruction)?)
    }

    /// Create approve instruction
    #[wasm_bindgen]
    pub fn create_approve_instruction(
        &self,
        source: &str,
        delegate: &str,
        authority: &str,
        amount: u64,
    ) -> Result<JsValue, JsValue> {
        if !self.is_valid_address(source) {
            return Err(JsValue::from_str("Invalid source address"));
        }
        if !self.is_valid_address(delegate) {
            return Err(JsValue::from_str("Invalid delegate address"));
        }
        if !self.is_valid_address(authority) {
            return Err(JsValue::from_str("Invalid authority address"));
        }
        
        let instruction = serde_json::json!({
            "programId": self.token_program_id,
            "keys": [
                {"pubkey": source, "isSigner": false, "isWritable": true},
                {"pubkey": delegate, "isSigner": false, "isWritable": false},
                {"pubkey": authority, "isSigner": true, "isWritable": false}
            ],
            "data": {
                "instruction": "approve",
                "amount": amount
            }
        });
        
        Ok(serde_wasm_bindgen::to_value(&instruction)?)
    }

    /// Create revoke instruction
    #[wasm_bindgen]
    pub fn create_revoke_instruction(&self, source: &str, authority: &str) -> Result<JsValue, JsValue> {
        if !self.is_valid_address(source) {
            return Err(JsValue::from_str("Invalid source address"));
        }
        if !self.is_valid_address(authority) {
            return Err(JsValue::from_str("Invalid authority address"));
        }
        
        let instruction = serde_json::json!({
            "programId": self.token_program_id,
            "keys": [
                {"pubkey": source, "isSigner": false, "isWritable": true},
                {"pubkey": authority, "isSigner": true, "isWritable": false}
            ],
            "data": {
                "instruction": "revoke"
            }
        });
        
        Ok(serde_wasm_bindgen::to_value(&instruction)?)
    }

    /// Clear cache
    #[wasm_bindgen]
    pub fn clear_cache(&mut self) {
        self.accounts_cache.clear();
        self.mints_cache.clear();
    }

    // Private helper methods
    async fn fetch_token_accounts(&self, owner: &str) -> Result<Vec<SplTokenAccount>, JsValue> {
        // Placeholder for RPC call to fetch token accounts
        // In real implementation, this would call getProgramAccounts or getTokenAccountsByOwner
        Ok(vec![])
    }

    async fn fetch_account_data(&self, address: &str) -> Result<Vec<u8>, JsValue> {
        // Placeholder for RPC call to fetch account data
        // In real implementation, this would call getAccountInfo
        Ok(vec![0u8; 165]) // SPL Token account size
    }

    fn parse_token_account(&self, data: &[u8]) -> Result<SplTokenAccount, JsValue> {
        if data.len() < 165 {
            return Err(JsValue::from_str("Invalid token account data length"));
        }
        
        // Parse SPL Token account structure
        let mint = bs58::encode(&data[0..32]).into_string();
        let owner = bs58::encode(&data[32..64]).into_string();
        let amount = u64::from_le_bytes(data[64..72].try_into().unwrap_or([0u8; 8]));
        let delegate_option = data[72];
        let state = data[108];
        let is_native_option = data[109];
        let delegated_amount = u64::from_le_bytes(data[73..81].try_into().unwrap_or([0u8; 8]));
        let close_authority_option = data[81];
        
        let delegate = if delegate_option != 0 {
            Some(bs58::encode(&data[113..145]).into_string())
        } else {
            None
        };
        
        // Generate placeholder address (in real implementation, this would be the actual account address)
        let address = self.generate_account_address(&mint, &owner);
        
        Ok(SplTokenAccount {
            mint,
            address,
            balance: amount,
            decimals: 9, // Would need to fetch from mint
            frozen: state == 2,
            delegate,
            delegated_amount,
        })
    }

    fn parse_mint_account(&self, data: &[u8], mint_address: &str) -> Result<SplMintInfo, JsValue> {
        if data.len() < 82 {
            return Err(JsValue::from_str("Invalid mint account data length"));
        }
        
        // Parse SPL Token mint structure
        let mint_authority_option = data[0];
        let supply = u64::from_le_bytes(data[1..9].try_into().unwrap_or([0u8; 8]));
        let decimals = data[9];
        let is_initialized = data[10] != 0;
        let freeze_authority_option = data[11];
        
        let mint_authority = if mint_authority_option != 0 {
            Some(bs58::encode(&data[4..36]).into_string())
        } else {
            None
        };
        
        let freeze_authority = if freeze_authority_option != 0 {
            Some(bs58::encode(&data[45..77]).into_string())
        } else {
            None
        };
        
        Ok(SplMintInfo {
            address: mint_address.to_string(),
            decimals,
            supply,
            mint_authority,
            freeze_authority,
        })
    }

    fn generate_account_address(&self, mint: &str, owner: &str) -> String {
        // Simplified account address generation
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(mint.as_bytes());
        hasher.update(owner.as_bytes());
        let hash = hasher.finalize();
        bs58::encode(&hash[..32]).into_string()
    }

    fn is_valid_address(&self, address: &str) -> bool {
        // Basic validation for base58 address format
        if address.len() < 32 || address.len() > 44 {
            return false;
        }
        
        bs58::decode(address).into_vec().is_ok()
    }
}