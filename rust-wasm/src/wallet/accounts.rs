use wasm_bindgen::prelude::*;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use crate::wallet::manager::AccountInfo;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TokenAccount {
    pub mint: String,
    pub address: String,
    pub balance: u64,
    pub decimals: u8,
    pub frozen: bool,
}

#[wasm_bindgen]
pub struct AccountManager {
    accounts: HashMap<String, AccountInfo>,
    token_accounts: HashMap<String, Vec<TokenAccount>>,
}

#[wasm_bindgen]
impl AccountManager {
    #[wasm_bindgen(constructor)]
    pub fn new() -> AccountManager {
        AccountManager {
            accounts: HashMap::new(),
            token_accounts: HashMap::new(),
        }
    }

    /// Add account to manager
    #[wasm_bindgen]
    pub fn add_account(&mut self, account_info: JsValue) -> Result<(), JsValue> {
        let account: AccountInfo = serde_wasm_bindgen::from_value(account_info)?;
        self.accounts.insert(account.public_key.clone(), account);
        Ok(())
    }

    /// Get account by public key
    #[wasm_bindgen]
    pub fn get_account(&self, public_key: &str) -> Result<JsValue, JsValue> {
        match self.accounts.get(public_key) {
            Some(account) => Ok(serde_wasm_bindgen::to_value(account)?),
            None => Err(JsValue::from_str("Account not found")),
        }
    }

    /// Get all accounts
    #[wasm_bindgen]
    pub fn get_all_accounts(&self) -> Result<JsValue, JsValue> {
        let accounts: Vec<&AccountInfo> = self.accounts.values().collect();
        Ok(serde_wasm_bindgen::to_value(&accounts)?)
    }

    /// Add token account
    #[wasm_bindgen]
    pub fn add_token_account(&mut self, owner: &str, token_account: JsValue) -> Result<(), JsValue> {
        let token_acc: TokenAccount = serde_wasm_bindgen::from_value(token_account)?;
        
        self.token_accounts
            .entry(owner.to_string())
            .or_insert_with(Vec::new)
            .push(token_acc);
        
        Ok(())
    }

    /// Get token accounts for owner
    #[wasm_bindgen]
    pub fn get_token_accounts(&self, owner: &str) -> Result<JsValue, JsValue> {
        match self.token_accounts.get(owner) {
            Some(accounts) => Ok(serde_wasm_bindgen::to_value(accounts)?),
            None => Ok(serde_wasm_bindgen::to_value(&Vec::<TokenAccount>::new())?),
        }
    }

    /// Update account balance
    #[wasm_bindgen]
    pub fn update_account_balance(&mut self, public_key: &str, balance: u64) -> Result<(), JsValue> {
        match self.accounts.get_mut(public_key) {
            Some(account) => {
                account.balance = Some(balance);
                Ok(())
            },
            None => Err(JsValue::from_str("Account not found")),
        }
    }

    /// Remove account
    #[wasm_bindgen]
    pub fn remove_account(&mut self, public_key: &str) -> Result<(), JsValue> {
        self.accounts.remove(public_key);
        self.token_accounts.remove(public_key);
        Ok(())
    }

    /// Clear all accounts
    #[wasm_bindgen]
    pub fn clear_accounts(&mut self) {
        self.accounts.clear();
        self.token_accounts.clear();
    }

    /// Get account count
    #[wasm_bindgen]
    pub fn get_account_count(&self) -> u32 {
        self.accounts.len() as u32
    }

    /// Check if account exists
    #[wasm_bindgen]
    pub fn has_account(&self, public_key: &str) -> bool {
        self.accounts.contains_key(public_key)
    }
}