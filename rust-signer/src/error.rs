use wasm_bindgen::JsValue;

#[derive(Debug)]
pub enum SignerError {
    /// JSON parsing failed (e.g. wrap_params)
    JsonParse(String),
    /// Base64 decoding failed
    Base64Decode(String),
    /// AES-256-GCM authentication / decryption failed.
    /// Always means either wrong passphrase or corrupted ciphertext.
    AesDecrypt,
    /// RSA-OAEP decryption failed.
    /// Means wrong server key or corrupted inner ciphertext.
    RsaDecrypt(String),
    /// Ed25519 key string could not be decoded.
    KeyParse(String),
    /// Key bytes are the wrong length.
    InvalidKeyLength { got: usize, expected: usize },
}

impl std::fmt::Display for SignerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::JsonParse(msg)       => write!(f, "wrap_params parse error: {msg}"),
            Self::Base64Decode(msg)    => write!(f, "base64 decode error: {msg}"),
            Self::AesDecrypt           => write!(f, "AES-256-GCM decryption failed (wrong passphrase or corrupted ciphertext)"),
            Self::RsaDecrypt(msg)      => write!(f, "RSA-OAEP decryption failed: {msg}"),
            Self::KeyParse(msg)        => write!(f, "ed25519 key parse error: {msg}"),
            Self::InvalidKeyLength { got, expected } =>
                write!(f, "key length error: got {got} bytes, expected {expected}"),
        }
    }
}

impl From<SignerError> for JsValue {
    fn from(e: SignerError) -> JsValue {
        JsValue::from_str(&e.to_string())
    }
}
