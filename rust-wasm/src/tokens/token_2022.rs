use wasm_bindgen::prelude::*;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

// Note: Some imports are simplified as full SPL Token-2022 isn't available in stable versions
// This is a foundational implementation that can be expanded

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TokenAccount {
    pub mint: String,
    pub address: String,
    pub balance: u64,
    pub decimals: u8,
    pub symbol: String,
    pub name: String,
    pub is_frozen: bool,
    pub close_authority: Option<String>,
    pub delegate: Option<String>,
    pub extensions: Vec<ExtensionInfo>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ExtensionInfo {
    pub extension_type: String,
    pub data: serde_json::Value,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TransferParams {
    pub from_token_account: String,
    pub to_token_account: String,
    pub amount: u64,
    pub decimals: u8,
    pub memo: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MintInfo {
    pub address: String,
    pub decimals: u8,
    pub supply: u64,
    pub mint_authority: Option<String>,
    pub freeze_authority: Option<String>,
    pub extensions: Vec<ExtensionInfo>,
}

#[wasm_bindgen]
pub struct TokenManager {
    rpc_url: String,
    token_program_id: String,
    token_2022_program_id: String,
    known_mints: HashMap<String, MintInfo>,
    accounts_cache: HashMap<String, Vec<TokenAccount>>,
}

#[wasm_bindgen]
impl TokenManager {
    #[wasm_bindgen(constructor)]
    pub fn new(rpc_url: &str) -> TokenManager {
        TokenManager {
            rpc_url: rpc_url.to_string(),
            token_program_id: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".to_string(),
            token_2022_program_id: "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb".to_string(),
            known_mints: HashMap::new(),
            accounts_cache: HashMap::new(),
        }
    }

    /// Get all SPL and Token-2022 accounts for owner
    #[wasm_bindgen]
    pub async fn get_token_accounts(&mut self, owner: &str) -> Result<JsValue, JsValue> {
        // Validate owner address format
        if !self.is_valid_address(owner) {
            return Err(JsValue::from_str("Invalid owner address"));
        }
        
        let mut all_accounts = Vec::new();
        
        // Get SPL Token accounts
        let spl_accounts = self.get_spl_token_accounts(owner).await?;
        all_accounts.extend(spl_accounts);
        
        // Get Token-2022 accounts
        let token_2022_accounts = self.get_token_2022_accounts(owner).await?;
        all_accounts.extend(token_2022_accounts);
        
        // Cache the results
        self.accounts_cache.insert(owner.to_string(), all_accounts.clone());
        
        // Convert to JS
        Ok(serde_wasm_bindgen::to_value(&all_accounts)?)
    }

    /// Get specific token balance with enhanced validation
    #[wasm_bindgen]
    pub async fn get_token_balance(&self, token_account: &str, validate_mint: bool) -> Result<JsValue, JsValue> {
        if !self.is_valid_address(token_account) {
            return Err(JsValue::from_str("Invalid token account address"));
        }
        
        // Simulate fetching account data (in real implementation, this would make RPC calls)
        let account_data = self.fetch_account_data(token_account).await?;
        
        // Determine if this is SPL Token or Token-2022
        let is_token_2022 = account_data.owner == self.token_2022_program_id;
        
        let (balance, decimals, mint) = if is_token_2022 {
            self.parse_token_2022_account(&account_data.data)?
        } else {
            self.parse_spl_token_account(&account_data.data)?
        };
        
        // Validate mint if requested
        if validate_mint {
            self.validate_mint_authority(&mint, is_token_2022).await?;
        }
        
        let result = js_sys::Object::new();
        js_sys::Reflect::set(&result, &JsValue::from_str("balance"), &JsValue::from_f64(balance as f64))?;
        js_sys::Reflect::set(&result, &JsValue::from_str("decimals"), &JsValue::from_f64(decimals as f64))?;
        js_sys::Reflect::set(&result, &JsValue::from_str("mint"), &JsValue::from_str(&mint))?;
        js_sys::Reflect::set(&result, &JsValue::from_str("isToken2022"), &JsValue::from_bool(is_token_2022))?;
        
        Ok(result.into())
    }

    /// Create secure token transfer instruction
    #[wasm_bindgen]
    pub fn create_transfer_instruction(&self, params: JsValue) -> Result<JsValue, JsValue> {
        let transfer_params: TransferParams = serde_wasm_bindgen::from_value(params)?;
        
        // Validate addresses
        if !self.is_valid_address(&transfer_params.from_token_account) {
            return Err(JsValue::from_str("Invalid from token account"));
        }
        if !self.is_valid_address(&transfer_params.to_token_account) {
            return Err(JsValue::from_str("Invalid to token account"));
        }
        
        // Validate amount
        if transfer_params.amount == 0 {
            return Err(JsValue::from_str("Transfer amount must be greater than 0"));
        }
        
        // Create instruction based on token type
        let instruction = self.build_transfer_instruction(
            &transfer_params.from_token_account,
            &transfer_params.to_token_account,
            transfer_params.amount,
            transfer_params.memo.as_deref(),
        )?;
        
        Ok(serde_wasm_bindgen::to_value(&instruction)?)
    }

    /// Get SOL balance for address
    #[wasm_bindgen]
    pub async fn get_sol_balance(&self, address: &str) -> Result<f64, JsValue> {
        if !self.is_valid_address(address) {
            return Err(JsValue::from_str("Invalid address"));
        }
        
        let balance = self.fetch_sol_balance(address).await?;
        Ok(balance as f64 / 1_000_000_000.0) // Convert lamports to SOL
    }

    /// Validate mint authority (security check)
    #[wasm_bindgen]
    pub async fn validate_mint_authority(&self, mint: &str, is_token_2022: bool) -> Result<bool, JsValue> {
        if !self.is_valid_address(mint) {
            return Err(JsValue::from_str("Invalid mint address"));
        }
        
        let mint_data = self.fetch_account_data(mint).await?;
        
        let (mint_authority, freeze_authority) = if is_token_2022 {
            self.parse_token_2022_mint(&mint_data.data)?
        } else {
            self.parse_spl_mint(&mint_data.data)?
        };
        
        // Check for known malicious authorities
        if let Some(authority) = mint_authority {
            if self.is_known_malicious_authority(&authority) {
                return Ok(false);
            }
        }
        
        if let Some(authority) = freeze_authority {
            if self.is_known_malicious_authority(&authority) {
                return Ok(false);
            }
        }
        
        Ok(true)
    }

    /// Get mint info with extensions
    #[wasm_bindgen]
    pub async fn get_mint_info(&mut self, mint_address: &str) -> Result<JsValue, JsValue> {
        if !self.is_valid_address(mint_address) {
            return Err(JsValue::from_str("Invalid mint address"));
        }
        
        // Check cache first
        if let Some(mint_info) = self.known_mints.get(mint_address) {
            return Ok(serde_wasm_bindgen::to_value(mint_info)?);
        }
        
        // Fetch mint data
        let mint_data = self.fetch_account_data(mint_address).await?;
        let is_token_2022 = mint_data.owner == self.token_2022_program_id;
        
        let mint_info = if is_token_2022 {
            self.parse_token_2022_mint_full(&mint_data.data, mint_address)?
        } else {
            self.parse_spl_mint_full(&mint_data.data, mint_address)?
        };
        
        // Cache the result
        self.known_mints.insert(mint_address.to_string(), mint_info.clone());
        
        Ok(serde_wasm_bindgen::to_value(&mint_info)?)
    }

    /// Check if address is associated token account
    #[wasm_bindgen]
    pub fn is_associated_token_account(&self, account: &str, owner: &str, mint: &str) -> Result<bool, JsValue> {
        // Calculate expected ATA address
        let expected_ata = self.get_associated_token_address(owner, mint)?;
        Ok(expected_ata == account)
    }

    /// Get associated token address
    #[wasm_bindgen]
    pub fn get_associated_token_address(&self, owner: &str, mint: &str) -> Result<String, JsValue> {
        // This is a simplified calculation - real implementation would use proper derivation
        use sha2::{Sha256, Digest};
        
        let mut hasher = Sha256::new();
        hasher.update(owner.as_bytes());
        hasher.update(mint.as_bytes());
        hasher.update(b"ATA"); // Associated Token Account seed
        
        let hash = hasher.finalize();
        Ok(bs58::encode(&hash[..32]).into_string())
    }

    /// Clear cache
    #[wasm_bindgen]
    pub fn clear_cache(&mut self) {
        self.accounts_cache.clear();
        self.known_mints.clear();
    }

    // Private helper methods
    async fn get_spl_token_accounts(&self, owner: &str) -> Result<Vec<TokenAccount>, JsValue> {
        // Placeholder implementation for SPL Token account fetching
        // In real implementation, this would make RPC calls
        Ok(vec![])
    }

    async fn get_token_2022_accounts(&self, owner: &str) -> Result<Vec<TokenAccount>, JsValue> {
        // Placeholder implementation for Token-2022 account fetching
        // In real implementation, this would make RPC calls and parse extensions
        Ok(vec![])
    }

    fn parse_token_2022_account(&self, data: &[u8]) -> Result<(u64, u8, String), JsValue> {
        // Simplified parsing - real implementation would use SPL Token-2022 library
        if data.len() < 165 {
            return Err(JsValue::from_str("Invalid account data length"));
        }
        
        // Extract basic account info (simplified)
        let mint_bytes = &data[0..32];
        let owner_bytes = &data[32..64];
        let amount_bytes = &data[64..72];
        
        let mint = bs58::encode(mint_bytes).into_string();
        let balance = u64::from_le_bytes(amount_bytes.try_into().unwrap_or([0u8; 8]));
        
        // Get decimals from mint (would need separate RPC call)
        let decimals = 9; // Placeholder
        
        Ok((balance, decimals, mint))
    }

    fn parse_spl_token_account(&self, data: &[u8]) -> Result<(u64, u8, String), JsValue> {
        // Simplified parsing for SPL Token account
        if data.len() < 165 {
            return Err(JsValue::from_str("Invalid account data length"));
        }
        
        let mint_bytes = &data[0..32];
        let amount_bytes = &data[64..72];
        
        let mint = bs58::encode(mint_bytes).into_string();
        let balance = u64::from_le_bytes(amount_bytes.try_into().unwrap_or([0u8; 8]));
        
        let decimals = 9; // Placeholder
        
        Ok((balance, decimals, mint))
    }

    fn build_transfer_instruction(
        &self,
        from: &str,
        to: &str,
        amount: u64,
        memo: Option<&str>,
    ) -> Result<serde_json::Value, JsValue> {
        // Build transfer instruction JSON (simplified)
        let mut instruction = serde_json::json!({
            "programId": self.token_program_id,
            "keys": [
                {"pubkey": from, "isSigner": false, "isWritable": true},
                {"pubkey": to, "isSigner": false, "isWritable": true}
            ],
            "data": {
                "instruction": "transfer",
                "amount": amount
            }
        });
        
        if let Some(memo_text) = memo {
            instruction["memo"] = serde_json::Value::String(memo_text.to_string());
        }
        
        Ok(instruction)
    }

    fn is_known_malicious_authority(&self, authority: &str) -> bool {
        // Check against known malicious mint authorities
        const KNOWN_MALICIOUS: &[&str] = &[
            // Add known malicious addresses here
        ];
        
        KNOWN_MALICIOUS.contains(&authority)
    }

    async fn fetch_account_data(&self, address: &str) -> Result<AccountData, JsValue> {
        // Placeholder for RPC call to fetch account data
        // In real implementation, this would make HTTP requests to Solana RPC
        Ok(AccountData {
            owner: self.token_program_id.clone(),
            data: vec![0u8; 165], // Placeholder data
        })
    }

    async fn fetch_sol_balance(&self, address: &str) -> Result<u64, JsValue> {
        // Placeholder for RPC call to fetch SOL balance
        Ok(0)
    }

    fn parse_token_2022_mint(&self, data: &[u8]) -> Result<(Option<String>, Option<String>), JsValue> {
        // Simplified mint parsing
        if data.len() < 82 {
            return Err(JsValue::from_str("Invalid mint data length"));
        }
        
        // Extract mint and freeze authority (simplified)
        let mint_auth_present = data[4] != 0;
        let freeze_auth_present = data[36] != 0;
        
        let mint_authority = if mint_auth_present {
            Some(bs58::encode(&data[5..37]).into_string())
        } else {
            None
        };
        
        let freeze_authority = if freeze_auth_present {
            Some(bs58::encode(&data[37..69]).into_string())
        } else {
            None
        };
        
        Ok((mint_authority, freeze_authority))
    }

    fn parse_spl_mint(&self, data: &[u8]) -> Result<(Option<String>, Option<String>), JsValue> {
        // Similar to Token-2022 but without extensions
        self.parse_token_2022_mint(data)
    }

    fn parse_token_2022_mint_full(&self, data: &[u8], mint_address: &str) -> Result<MintInfo, JsValue> {
        let (mint_authority, freeze_authority) = self.parse_token_2022_mint(data)?;
        
        // Extract additional info (simplified)
        let decimals = if data.len() > 44 { data[44] } else { 9 };
        let supply = if data.len() >= 52 {
            u64::from_le_bytes(data[36..44].try_into().unwrap_or([0u8; 8]))
        } else {
            0
        };
        
        // Parse extensions (simplified)
        let extensions = self.parse_extensions(&data[82..])?;
        
        Ok(MintInfo {
            address: mint_address.to_string(),
            decimals,
            supply,
            mint_authority,
            freeze_authority,
            extensions,
        })
    }

    fn parse_spl_mint_full(&self, data: &[u8], mint_address: &str) -> Result<MintInfo, JsValue> {
        let (mint_authority, freeze_authority) = self.parse_spl_mint(data)?;
        
        let decimals = if data.len() > 44 { data[44] } else { 9 };
        let supply = if data.len() >= 52 {
            u64::from_le_bytes(data[36..44].try_into().unwrap_or([0u8; 8]))
        } else {
            0
        };
        
        Ok(MintInfo {
            address: mint_address.to_string(),
            decimals,
            supply,
            mint_authority,
            freeze_authority,
            extensions: vec![], // SPL Token has no extensions
        })
    }

    fn parse_extensions(&self, extension_data: &[u8]) -> Result<Vec<ExtensionInfo>, JsValue> {
        // Simplified extension parsing
        // Real implementation would parse each extension type
        let mut extensions = Vec::new();
        
        if !extension_data.is_empty() {
            // Placeholder for extension parsing
            extensions.push(ExtensionInfo {
                extension_type: "placeholder".to_string(),
                data: serde_json::json!({"length": extension_data.len()}),
            });
        }
        
        Ok(extensions)
    }

    fn is_valid_address(&self, address: &str) -> bool {
        // Basic validation for base58 address format
        if address.len() < 32 || address.len() > 44 {
            return false;
        }
        
        // Check if it's valid base58
        bs58::decode(address).into_vec().is_ok()
    }
}

#[derive(Debug)]
struct AccountData {
    owner: String,
    data: Vec<u8>,
}