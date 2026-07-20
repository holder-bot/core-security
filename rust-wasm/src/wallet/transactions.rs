use wasm_bindgen::prelude::*;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TransactionInfo {
    pub signature: String,
    pub block_time: Option<i64>,
    pub slot: u64,
    pub status: String,
    pub fee: u64,
    pub from: String,
    pub to: String,
    pub amount: u64,
    pub transaction_type: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UnsignedTransaction {
    pub to: String,
    pub amount: u64,
    pub memo: Option<String>,
    pub recent_blockhash: String,
    pub fee_payer: String,
}

#[wasm_bindgen]
pub struct TransactionManager {
    transactions: HashMap<String, TransactionInfo>,
    pending_transactions: HashMap<String, UnsignedTransaction>,
}

#[wasm_bindgen]
impl TransactionManager {
    #[wasm_bindgen(constructor)]
    pub fn new() -> TransactionManager {
        TransactionManager {
            transactions: HashMap::new(),
            pending_transactions: HashMap::new(),
        }
    }

    /// Create unsigned transaction
    #[wasm_bindgen]
    pub fn create_transaction(&mut self, params: JsValue) -> Result<String, JsValue> {
        let tx: UnsignedTransaction = serde_wasm_bindgen::from_value(params)?;
        
        // Generate transaction ID
        let tx_id = self.generate_transaction_id(&tx);
        
        // Validate transaction
        self.validate_transaction(&tx)?;
        
        // Store pending transaction
        self.pending_transactions.insert(tx_id.clone(), tx);
        
        Ok(tx_id)
    }

    /// Get pending transaction
    #[wasm_bindgen]
    pub fn get_pending_transaction(&self, tx_id: &str) -> Result<JsValue, JsValue> {
        match self.pending_transactions.get(tx_id) {
            Some(tx) => Ok(serde_wasm_bindgen::to_value(tx)?),
            None => Err(JsValue::from_str("Transaction not found")),
        }
    }

    /// Mark transaction as signed
    #[wasm_bindgen]
    pub fn mark_transaction_signed(&mut self, tx_id: &str, signature: &str) -> Result<(), JsValue> {
        if let Some(tx) = self.pending_transactions.remove(tx_id) {
            let tx_info = TransactionInfo {
                signature: signature.to_string(),
                block_time: None,
                slot: 0,
                status: "pending".to_string(),
                fee: 5000, // Default fee
                from: tx.fee_payer.clone(),
                to: tx.to.clone(),
                amount: tx.amount,
                transaction_type: "transfer".to_string(),
            };
            
            self.transactions.insert(signature.to_string(), tx_info);
            Ok(())
        } else {
            Err(JsValue::from_str("Transaction not found"))
        }
    }

    /// Update transaction status
    #[wasm_bindgen]
    pub fn update_transaction_status(&mut self, signature: &str, status: &str, slot: Option<u64>, block_time: Option<i64>) -> Result<(), JsValue> {
        if let Some(tx) = self.transactions.get_mut(signature) {
            tx.status = status.to_string();
            if let Some(s) = slot {
                tx.slot = s;
            }
            if let Some(t) = block_time {
                tx.block_time = Some(t);
            }
            Ok(())
        } else {
            Err(JsValue::from_str("Transaction not found"))
        }
    }

    /// Get transaction by signature
    #[wasm_bindgen]
    pub fn get_transaction(&self, signature: &str) -> Result<JsValue, JsValue> {
        match self.transactions.get(signature) {
            Some(tx) => Ok(serde_wasm_bindgen::to_value(tx)?),
            None => Err(JsValue::from_str("Transaction not found")),
        }
    }

    /// Get all transactions
    #[wasm_bindgen]
    pub fn get_all_transactions(&self) -> Result<JsValue, JsValue> {
        let txs: Vec<&TransactionInfo> = self.transactions.values().collect();
        Ok(serde_wasm_bindgen::to_value(&txs)?)
    }

    /// Get transactions by status
    #[wasm_bindgen]
    pub fn get_transactions_by_status(&self, status: &str) -> Result<JsValue, JsValue> {
        let txs: Vec<&TransactionInfo> = self.transactions
            .values()
            .filter(|tx| tx.status == status)
            .collect();
        Ok(serde_wasm_bindgen::to_value(&txs)?)
    }

    /// Clear all transactions
    #[wasm_bindgen]
    pub fn clear_transactions(&mut self) {
        self.transactions.clear();
        self.pending_transactions.clear();
    }

    /// Get transaction count
    #[wasm_bindgen]
    pub fn get_transaction_count(&self) -> u32 {
        self.transactions.len() as u32
    }

    /// Get pending transaction count
    #[wasm_bindgen]
    pub fn get_pending_transaction_count(&self) -> u32 {
        self.pending_transactions.len() as u32
    }

    // Private helper methods
    fn generate_transaction_id(&self, tx: &UnsignedTransaction) -> String {
        use sha2::{Sha256, Digest};
        
        let mut hasher = Sha256::new();
        hasher.update(tx.to.as_bytes());
        hasher.update(tx.amount.to_be_bytes());
        hasher.update(tx.recent_blockhash.as_bytes());
        hasher.update(tx.fee_payer.as_bytes());
        if let Some(memo) = &tx.memo {
            hasher.update(memo.as_bytes());
        }
        
        let hash = hasher.finalize();
        bs58::encode(hash).into_string()
    }

    fn validate_transaction(&self, tx: &UnsignedTransaction) -> Result<(), JsValue> {
        // Validate recipient address
        if tx.to.is_empty() {
            return Err(JsValue::from_str("Recipient address cannot be empty"));
        }
        
        // Validate amount
        if tx.amount == 0 {
            return Err(JsValue::from_str("Amount must be greater than 0"));
        }
        
        // Validate fee payer
        if tx.fee_payer.is_empty() {
            return Err(JsValue::from_str("Fee payer cannot be empty"));
        }
        
        // Validate recent blockhash
        if tx.recent_blockhash.is_empty() {
            return Err(JsValue::from_str("Recent blockhash cannot be empty"));
        }
        
        // Validate memo length if present
        if let Some(memo) = &tx.memo {
            if memo.len() > 566 {
                return Err(JsValue::from_str("Memo too long (max 566 characters)"));
            }
        }
        
        Ok(())
    }
}