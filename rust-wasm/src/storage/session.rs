use wasm_bindgen::prelude::*;
use web_sys::{Storage, Window};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SessionData {
    pub user_id: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_activity: chrono::DateTime<chrono::Utc>,
    pub session_timeout: u32, // in minutes
    pub permissions: Vec<String>,
    pub settings: HashMap<String, serde_json::Value>,
}

#[wasm_bindgen]
pub struct SessionManager {
    storage: Storage,
    session_key: String,
    activity_key: String,
    timeout_minutes: u32,
}

#[wasm_bindgen]
impl SessionManager {
    #[wasm_bindgen(constructor)]
    pub fn new(timeout_minutes: Option<u32>) -> Result<SessionManager, JsValue> {
        let window = web_sys::window().ok_or("No window object")?;
        let storage = window.session_storage()?.ok_or("No sessionStorage available")?;
        
        Ok(SessionManager {
            storage,
            session_key: "solana_wallet_v2_session".to_string(),
            activity_key: "solana_wallet_v2_activity".to_string(),
            timeout_minutes: timeout_minutes.unwrap_or(30),
        })
    }

    /// Start a new session
    #[wasm_bindgen]
    pub fn start_session(&self, user_id: &str) -> Result<(), JsValue> {
        let session_data = SessionData {
            user_id: user_id.to_string(),
            created_at: chrono::Utc::now(),
            last_activity: chrono::Utc::now(),
            session_timeout: self.timeout_minutes,
            permissions: vec!["wallet:read".to_string(), "wallet:write".to_string()],
            settings: HashMap::new(),
        };
        
        let serialized = serde_json::to_string(&session_data)
            .map_err(|e| JsValue::from_str(&format!("Session serialization failed: {}", e)))?;
        
        self.storage.set_item(&self.session_key, &serialized)?;
        self.update_activity()?;
        
        Ok(())
    }

    /// Check if session is valid and not expired
    #[wasm_bindgen]
    pub fn is_session_valid(&self) -> Result<bool, JsValue> {
        let session_data = match self.get_session_data()? {
            Some(data) => data,
            None => return Ok(false),
        };
        
        let now = chrono::Utc::now();
        let timeout_duration = chrono::Duration::minutes(session_data.session_timeout as i64);
        let expires_at = session_data.last_activity + timeout_duration;
        
        Ok(now < expires_at)
    }

    /// Update session activity timestamp
    #[wasm_bindgen]
    pub fn update_activity(&self) -> Result<(), JsValue> {
        if let Some(mut session_data) = self.get_session_data()? {
            session_data.last_activity = chrono::Utc::now();
            
            let serialized = serde_json::to_string(&session_data)
                .map_err(|e| JsValue::from_str(&format!("Session serialization failed: {}", e)))?;
            
            self.storage.set_item(&self.session_key, &serialized)?;
        }
        
        // Store simple activity timestamp for quick checks
        let activity_timestamp = chrono::Utc::now().timestamp().to_string();
        self.storage.set_item(&self.activity_key, &activity_timestamp)?;
        
        Ok(())
    }

    /// Get current session data
    #[wasm_bindgen]
    pub fn get_session_info(&self) -> Result<JsValue, JsValue> {
        match self.get_session_data()? {
            Some(session_data) => {
                let is_valid = self.is_session_valid()?;
                let now = chrono::Utc::now();
                let timeout_duration = chrono::Duration::minutes(session_data.session_timeout as i64);
                let expires_at = session_data.last_activity + timeout_duration;
                let time_remaining = (expires_at - now).num_seconds().max(0);
                
                let info = js_sys::Object::new();
                js_sys::Reflect::set(&info, &JsValue::from_str("userId"), &JsValue::from_str(&session_data.user_id))?;
                js_sys::Reflect::set(&info, &JsValue::from_str("isValid"), &JsValue::from_bool(is_valid))?;
                js_sys::Reflect::set(&info, &JsValue::from_str("createdAt"), &JsValue::from_str(&session_data.created_at.to_rfc3339()))?;
                js_sys::Reflect::set(&info, &JsValue::from_str("lastActivity"), &JsValue::from_str(&session_data.last_activity.to_rfc3339()))?;
                js_sys::Reflect::set(&info, &JsValue::from_str("timeoutMinutes"), &JsValue::from_f64(session_data.session_timeout as f64))?;
                js_sys::Reflect::set(&info, &JsValue::from_str("timeRemainingSeconds"), &JsValue::from_f64(time_remaining as f64))?;
                js_sys::Reflect::set(&info, &JsValue::from_str("permissions"), &serde_wasm_bindgen::to_value(&session_data.permissions)?)?;
                
                Ok(info.into())
            },
            None => Err(JsValue::from_str("No active session")),
        }
    }

    /// End current session
    #[wasm_bindgen]
    pub fn end_session(&self) -> Result<(), JsValue> {
        self.storage.remove_item(&self.session_key)?;
        self.storage.remove_item(&self.activity_key)?;
        
        // Clear all session-related data
        let length = self.storage.length()?;
        let mut keys_to_remove = Vec::new();
        
        for i in 0..length {
            if let Some(key) = self.storage.key(i)? {
                if key.starts_with("solana_wallet_v2_session_") {
                    keys_to_remove.push(key);
                }
            }
        }
        
        for key in keys_to_remove {
            self.storage.remove_item(&key)?;
        }
        
        Ok(())
    }

    /// Check if user has specific permission
    #[wasm_bindgen]
    pub fn has_permission(&self, permission: &str) -> Result<bool, JsValue> {
        if let Some(session_data) = self.get_session_data()? {
            if !self.is_session_valid()? {
                return Ok(false);
            }
            
            Ok(session_data.permissions.contains(&permission.to_string()))
        } else {
            Ok(false)
        }
    }

    /// Add permission to current session
    #[wasm_bindgen]
    pub fn add_permission(&self, permission: &str) -> Result<(), JsValue> {
        if let Some(mut session_data) = self.get_session_data()? {
            if !session_data.permissions.contains(&permission.to_string()) {
                session_data.permissions.push(permission.to_string());
                
                let serialized = serde_json::to_string(&session_data)
                    .map_err(|e| JsValue::from_str(&format!("Session serialization failed: {}", e)))?;
                
                self.storage.set_item(&self.session_key, &serialized)?;
            }
            Ok(())
        } else {
            Err(JsValue::from_str("No active session"))
        }
    }

    /// Remove permission from current session
    #[wasm_bindgen]
    pub fn remove_permission(&self, permission: &str) -> Result<(), JsValue> {
        if let Some(mut session_data) = self.get_session_data()? {
            session_data.permissions.retain(|p| p != permission);
            
            let serialized = serde_json::to_string(&session_data)
                .map_err(|e| JsValue::from_str(&format!("Session serialization failed: {}", e)))?;
            
            self.storage.set_item(&self.session_key, &serialized)?;
            Ok(())
        } else {
            Err(JsValue::from_str("No active session"))
        }
    }

    /// Set session setting
    #[wasm_bindgen]
    pub fn set_session_setting(&self, key: &str, value: JsValue) -> Result<(), JsValue> {
        if let Some(mut session_data) = self.get_session_data()? {
            let json_value: serde_json::Value = serde_wasm_bindgen::from_value(value)?;
            session_data.settings.insert(key.to_string(), json_value);
            
            let serialized = serde_json::to_string(&session_data)
                .map_err(|e| JsValue::from_str(&format!("Session serialization failed: {}", e)))?;
            
            self.storage.set_item(&self.session_key, &serialized)?;
            Ok(())
        } else {
            Err(JsValue::from_str("No active session"))
        }
    }

    /// Get session setting
    #[wasm_bindgen]
    pub fn get_session_setting(&self, key: &str) -> Result<JsValue, JsValue> {
        if let Some(session_data) = self.get_session_data()? {
            if let Some(value) = session_data.settings.get(key) {
                Ok(serde_wasm_bindgen::to_value(value)?)
            } else {
                Ok(JsValue::NULL)
            }
        } else {
            Err(JsValue::from_str("No active session"))
        }
    }

    /// Extend session timeout
    #[wasm_bindgen]
    pub fn extend_session(&self, additional_minutes: u32) -> Result<(), JsValue> {
        if let Some(mut session_data) = self.get_session_data()? {
            session_data.session_timeout += additional_minutes;
            session_data.last_activity = chrono::Utc::now();
            
            let serialized = serde_json::to_string(&session_data)
                .map_err(|e| JsValue::from_str(&format!("Session serialization failed: {}", e)))?;
            
            self.storage.set_item(&self.session_key, &serialized)?;
            Ok(())
        } else {
            Err(JsValue::from_str("No active session"))
        }
    }

    /// Get time until session expires
    #[wasm_bindgen]
    pub fn get_time_until_expiry(&self) -> Result<i64, JsValue> {
        if let Some(session_data) = self.get_session_data()? {
            let now = chrono::Utc::now();
            let timeout_duration = chrono::Duration::minutes(session_data.session_timeout as i64);
            let expires_at = session_data.last_activity + timeout_duration;
            
            Ok((expires_at - now).num_seconds().max(0))
        } else {
            Err(JsValue::from_str("No active session"))
        }
    }

    /// Check if session will expire soon (within 5 minutes)
    #[wasm_bindgen]
    pub fn is_session_expiring_soon(&self) -> Result<bool, JsValue> {
        let time_remaining = self.get_time_until_expiry()?;
        Ok(time_remaining > 0 && time_remaining <= 300) // 5 minutes
    }

    // Private helper methods
    fn get_session_data(&self) -> Result<Option<SessionData>, JsValue> {
        if let Some(session_str) = self.storage.get_item(&self.session_key)? {
            let session_data: SessionData = serde_json::from_str(&session_str)
                .map_err(|e| JsValue::from_str(&format!("Session deserialization failed: {}", e)))?;
            Ok(Some(session_data))
        } else {
            Ok(None)
        }
    }
}