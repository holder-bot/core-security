use wasm_bindgen::prelude::*;
use zeroize::Zeroize;

#[wasm_bindgen]
pub struct SecureRandom;

#[wasm_bindgen]
impl SecureRandom {
    /// Generate cryptographically secure random bytes
    #[wasm_bindgen]
    pub fn generate_bytes(length: usize) -> Result<Vec<u8>, JsValue> {
        let mut bytes = vec![0u8; length];
        getrandom::getrandom(&mut bytes)
            .map_err(|_| JsValue::from_str("Failed to generate secure random bytes"))?;
        Ok(bytes)
    }

    /// Generate secure random number in range
    #[wasm_bindgen]
    pub fn generate_u32() -> Result<u32, JsValue> {
        let mut bytes = [0u8; 4];
        getrandom::getrandom(&mut bytes)
            .map_err(|_| JsValue::from_str("Failed to generate secure random u32"))?;
        Ok(u32::from_be_bytes(bytes))
    }

    /// Generate secure random number in range
    #[wasm_bindgen]
    pub fn generate_u64() -> Result<u64, JsValue> {
        let mut bytes = [0u8; 8];
        getrandom::getrandom(&mut bytes)
            .map_err(|_| JsValue::from_str("Failed to generate secure random u64"))?;
        Ok(u64::from_be_bytes(bytes))
    }

    /// Generate secure random number in range [0, max)
    #[wasm_bindgen]
    pub fn generate_range(max: u32) -> Result<u32, JsValue> {
        if max == 0 {
            return Err(JsValue::from_str("Maximum value must be greater than 0"));
        }
        
        let mut bytes = [0u8; 4];
        getrandom::getrandom(&mut bytes)
            .map_err(|_| JsValue::from_str("Failed to generate secure random bytes"))?;
        
        let value = u32::from_be_bytes(bytes);
        Ok(value % max)
    }

    /// Generate secure random salt
    #[wasm_bindgen]
    pub fn generate_salt() -> Result<Vec<u8>, JsValue> {
        Self::generate_bytes(32)
    }

    /// Generate secure random IV/nonce
    #[wasm_bindgen]
    pub fn generate_iv() -> Result<Vec<u8>, JsValue> {
        Self::generate_bytes(12) // 96 bits for AES-GCM
    }

    /// Generate secure random token
    #[wasm_bindgen]
    pub fn generate_token() -> Result<String, JsValue> {
        let bytes = Self::generate_bytes(32)?;
        Ok(bs58::encode(bytes).into_string())
    }

    /// Fill buffer with secure random data
    #[wasm_bindgen]
    pub fn fill_buffer(buffer: &mut [u8]) -> Result<(), JsValue> {
        getrandom::getrandom(buffer)
            .map_err(|_| JsValue::from_str("Failed to fill buffer with secure random data"))?;
        Ok(())
    }

    /// Securely clear memory
    #[wasm_bindgen]
    pub fn secure_clear(data: &mut [u8]) {
        data.zeroize();
    }
}