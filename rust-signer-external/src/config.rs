/// Persistent config for the external-signer daemon.
///
/// Stored at `~/.holder-signer/config.toml`.
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// One API key the daemon authenticates with and polls.
/// Jobs for every key sharing that key's `signer_key_pair_id` are returned
/// (server-side filter-by-signer).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PollKey {
    pub key_public_id: String,
    pub key_secret: String,
    /// Optional label for logs (e.g. "yubikey", "regular").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    /// Base URL of the safu server (e.g. "https://safu-wallet-dev1-....run.app").
    pub server_url: String,

    /// API key public ID for authentication (legacy single-key; also used when
    /// `poll_keys` is empty).
    pub key_public_id: String,

    /// API key secret (stored in plain text — treat this file as a secret).
    pub key_secret: String,

    /// Additional API keys to poll. When set, the daemon polls each entry
    /// (plus the legacy `key_public_id` if not duplicated). Use this so one
    /// process can serve a YubiKey-bound key and a Regular Mode key.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub poll_keys: Vec<PollKey>,

    /// Server RSA private key PEM (allows local subkey decryption in convenience mode).
    /// Only required for the legacy `connect` / `sign` commands.
    /// Not needed when using the `daemon` command with E2EE key delivery.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub server_rsa_pem: String,

    /// Port for the local HTTP proxy (connect mode, default: 9090).
    #[serde(default = "default_port")]
    pub local_port: u16,

    /// Path to the EC P-256 identity key PEM (default: ~/.holder-signer/identity.pem).
    /// Overrides the default only when set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_ec_key_path: Option<String>,

    /// Identity backend: "software" (Regular Mode), "yubikey" (HSM),
    /// or "dual" (load both when available — decrypt with whichever works).
    #[serde(default = "default_backend")]
    pub backend: String,

    /// Path to libykcs11 (optional — auto-detected if unset).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pkcs11_library: Option<String>,

    /// PIV user PIN for PKCS#11 login (default YubiKey factory PIN: 123456).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pkcs11_pin: Option<String>,

    /// PIV slot for identity key (default: 9a authentication).
    #[serde(default = "default_yubikey_piv_slot")]
    pub yubikey_piv_slot: String,
}

fn default_port() -> u16 { 9090 }
fn default_backend() -> String { "software".to_string() }
fn default_yubikey_piv_slot() -> String { "9a".to_string() }

impl Config {
    pub fn path() -> PathBuf {
        let base = dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."));
        base.join(".holder-signer").join("config.toml")
    }

    pub fn load() -> Result<Self> {
        let path = Self::path();
        let content = std::fs::read_to_string(&path)
            .with_context(|| format!(
                "Cannot read config at {}. Run `safu-signer setup` or `safu-signer init` first.",
                path.display()
            ))?;
        toml::from_str(&content)
            .with_context(|| format!("Failed to parse config at {}", path.display()))
    }

    pub fn save(&self) -> Result<()> {
        let path = Self::path();
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)
                .with_context(|| format!("Failed to create config dir: {}", dir.display()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).ok();
            }
        }
        let content = toml::to_string_pretty(self)
            .context("Failed to serialize config")?;
        std::fs::write(&path, &content)
            .with_context(|| format!("Failed to write config to {}", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).ok();
        }
        Ok(())
    }

    /// All API keys to poll this cycle (legacy fields + `poll_keys`, deduped by id).
    pub fn all_poll_keys(&self) -> Vec<PollKey> {
        let mut out: Vec<PollKey> = Vec::new();
        if !self.key_public_id.is_empty() && !self.key_secret.is_empty() {
            out.push(PollKey {
                key_public_id: self.key_public_id.clone(),
                key_secret: self.key_secret.clone(),
                label: Some("primary".into()),
            });
        }
        for k in &self.poll_keys {
            if k.key_public_id.is_empty() || k.key_secret.is_empty() {
                continue;
            }
            if out.iter().any(|e| e.key_public_id == k.key_public_id) {
                continue;
            }
            out.push(k.clone());
        }
        out
    }
}
