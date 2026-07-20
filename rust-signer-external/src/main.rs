/// holder-signer — self-custodial signing daemon for safu.
///
/// Commands:
///   init     Generate EC P-256 identity keypair and print the pairing token.
///   token    Print the signer public key (base64url) for wallet registration.
///   setup    Save server credentials to ~/.holder-signer/config.toml.
///   status   Show current config and stored subkeys.
///   connect  [--port 9090]  Run local signing proxy (agent calls this).
///   sign     <request.json> One-shot signing from file / stdin.
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;
use zeroize::Zeroizing;

mod backend;
mod config;
mod install_paths;
mod labels;
mod service_install;
mod grpc_daemon;
mod hmac_auth;
mod identity;
mod key_store;
mod sign_pipeline;
mod server;

use config::Config;
use identity::SignerIdentity;
use key_store::KeyStore;

// ── CLI ───────────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name    = "holder-signer",
    about   = "Holder agent signer — signs transactions locally, keys never leave this machine",
    version,
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a new EC P-256 identity keypair and print the public key for registration.
    ///
    /// Default is Regular Mode (key file at ~/.holder-signer/identity.pem).
    /// Use --backend yubikey for HSM Mode (YubiKey, non-interactive server/daemon use).
    Init {
        /// Force overwrite an existing identity key.
        #[arg(long)]
        force: bool,

        /// Identity backend: "software" (default, Regular Mode) or "yubikey" (HSM Mode).
        /// Future/experimental: "secure-enclave" (macOS only, not production-ready).
        #[arg(long, default_value = "software")]
        backend: String,
    },

    /// Print the signer public key without regenerating the keypair.
    Token {
        /// Identity backend override (reads from config if not set).
        #[arg(long)]
        backend: Option<String>,
    },

    /// Save server credentials to ~/.holder-signer/config.toml.
    ///
    /// --rsa-pem-file is only required for the legacy passphrase-based
    /// connect / sign commands. E2EE mode does not need it.
    Setup {
        /// Base URL of the safu server.
        #[arg(long)]
        server: String,

        /// API key public ID.
        #[arg(long)]
        key_id: String,

        /// API key secret.
        #[arg(long)]
        key_secret: String,

        /// Path to the server RSA private key PEM (legacy mode only).
        #[arg(long)]
        rsa_pem_file: Option<String>,

        /// Local port for the signing proxy (default: 9090).
        #[arg(long, default_value_t = 9090)]
        port: u16,

        /// Skip installing a persistent daemon service (systemd on Linux, launchd on macOS).
        #[arg(long)]
        no_install_service: bool,

        /// Install persistent daemon service without prompting (non-interactive).
        #[arg(long)]
        install_service: bool,
    },

    /// Install holder-signer daemon as a persistent OS service and start it.
    InstallService,

    /// Remove the holder-signer OS service.
    UninstallService,

    /// Show current config, identity key, and stored subkeys.
    Status,

    /// Start the local signing proxy on localhost:<port>.
    ///
    /// Run this alongside your agent. The agent should point its safu
    /// base URL to http://localhost:<port> and include its API key
    /// credentials in each request. The signer handles signing locally.
    Connect {
        /// Override port from config.
        #[arg(long)]
        port: Option<u16>,
    },

    /// Export the identity keypair as an AES-256-GCM encrypted file.
    ///
    /// The output file can be transferred to another machine and imported with
    /// `holder-signer import-key`. The one-time password must be shared securely
    /// (e.g., via a password manager) and is not stored anywhere.
    ExportKey {
        /// Output path for the encrypted bundle (default: ~/holder-signer-export.bin).
        #[arg(long)]
        out: Option<String>,

        /// One-time password to encrypt the export (prompted if omitted).
        #[arg(long, env = "SAFU_EXPORT_PASSWORD")]
        password: Option<String>,
    },

    /// Import an identity keypair from an export bundle created by `export-key`.
    ImportKey {
        /// Path to the encrypted bundle.
        bundle: String,

        /// One-time password used during export (prompted if omitted).
        #[arg(long, env = "SAFU_EXPORT_PASSWORD")]
        password: Option<String>,

        /// Force overwrite an existing identity key.
        #[arg(long)]
        force: bool,
    },

    /// Start the E2EE signing daemon.
    ///
    /// Polls the server's RemoteSignerService.PollJob gRPC endpoint, decrypts
    /// signing jobs with the local identity key, runs NEAR MPC signing, and
    /// reports results back via CompleteJob.
    ///
    /// Requires `holder-signer init` (for the identity key) and `holder-signer setup`
    /// (for server URL + API key credentials).
    Daemon {
        /// gRPC endpoint URL (default: uses server_url from config).
        #[arg(long)]
        grpc_url: Option<String>,

        /// Poll interval in seconds between empty batches (default: 5).
        #[arg(long, default_value_t = 5)]
        poll_interval: u64,
    },

    /// One-shot sign: read a submit request from file (or stdin if "-"),
    /// execute the full pipeline, print the result as JSON.
    Sign {
        /// Path to a JSON file containing the submit request body.
        /// Use "-" to read from stdin.
        #[arg(default_value = "-")]
        request_file: String,

        /// Passphrase. Prefer the SAFU_PASSPHRASE env var to avoid shell history.
        #[arg(long, env = "SAFU_PASSPHRASE")]
        passphrase: Option<String>,
    },
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    match cli.command {
        Command::Init { force, backend }                     => cmd_init(force, &backend).await,
        Command::Token { backend }                           => cmd_token(backend.as_deref()).await,
        Command::Setup { server, key_id, key_secret, rsa_pem_file, port, no_install_service, install_service }
                                                             => cmd_setup(server, key_id, key_secret, rsa_pem_file, port, no_install_service, install_service).await,
        Command::InstallService                              => cmd_install_service().await,
        Command::UninstallService                            => cmd_uninstall_service().await,
        Command::Status                                      => cmd_status().await,
        Command::Daemon { grpc_url, poll_interval }          => cmd_daemon(grpc_url, poll_interval).await,
        Command::Connect { port }                            => cmd_connect(port).await,
        Command::ExportKey { out, password }                 => cmd_export_key(out, password).await,
        Command::ImportKey { bundle, password, force }       => cmd_import_key(bundle, password, force).await,
        Command::Sign { request_file, passphrase }           => cmd_sign(request_file, passphrase).await,
    }
}

// ── init ──────────────────────────────────────────────────────────────────────

async fn cmd_init(force: bool, backend_type: &str) {
    let path = SignerIdentity::default_path();

    // Warn if switching backends
    if force {
        let existing_backend = Config::load().ok().map(|c| c.backend).unwrap_or_default();
        if !existing_backend.is_empty() && existing_backend != backend_type && existing_backend != "software" || backend_type != "software" {
            eprintln!();
            eprintln!("  WARNING: Switching backend from '{}' to '{}'.", existing_backend, backend_type);
            eprintln!("  You will need to re-register the signer and create new API keys.");
            eprintln!("  Existing API keys bound to the old identity will stop working.");
            eprintln!();
        }
    }

    let identity = backend::generate_identity(backend_type, &path, force)
        .unwrap_or_else(|e| { eprintln!("Failed to generate identity: {e}"); std::process::exit(1); });

    let token = identity.pairing_token()
        .unwrap_or_else(|e| { eprintln!("Failed to get pairing token: {e}"); std::process::exit(1); });
    let backend_name = identity.backend_name();

    // Save backend choice to config (create/update)
    let mut config = Config::load().unwrap_or_default();
    config.backend = backend_type.to_string();
    if backend_type == "yubikey" {
        config.yubikey_piv_slot = std::env::var("HOLDER_SIGNER_PIV_SLOT")
            .unwrap_or_else(|_| config.yubikey_piv_slot.clone());
        if config.pkcs11_pin.is_none() {
            config.pkcs11_pin = std::env::var("HOLDER_SIGNER_PKCS11_PIN").ok();
        }
        if config.pkcs11_library.is_none() {
            config.pkcs11_library = std::env::var("HOLDER_SIGNER_PKCS11_LIBRARY").ok();
        }
    }
    config.save().ok();

    println!();
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  Signer initialised — {}.", labels::display_backend_name(backend_name));
    println!();
    println!("  Public key (paste into Settings → Signers):");
    println!("  {token}");
    println!();
    println!("  To pair with your wallet:");
    println!("    1. Open Settings → Signers & Hardware Keys");
    println!("    2. Click \"Add Signer\"");
    println!("    3. Paste this public key");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    if backend_name == "software" {
        println!();
        println!("  Identity key stored at: {}", path.display());
    } else if backend_name == "regular" || backend_name == "yubikey-mock" {
        println!();
        println!("  Identity key stored locally (Regular Mode — dev build without PKCS#11).");
    } else if backend_name == "yubikey" {
        println!();
        println!("  Identity key stored on YubiKey PIV slot (HSM mode).");
        println!("  Requires: libykcs11 + ykman (see docs/rust-signer-external-hardware-impl.md)");
    } else if backend_name == "secure-enclave" {
        println!();
        println!("  Identity key stored in macOS Secure Enclave (future / experimental — not production-ready).");
    }
    println!("  Run `holder-signer token` to display this token again.");
    println!();
}

// ── token ─────────────────────────────────────────────────────────────────────

async fn cmd_token(backend_override: Option<&str>) {
    let config = Config::load().unwrap_or_default();
    let backend_type = backend_override.unwrap_or(&config.backend);
    let path = config.signer_ec_key_path.as_ref()
        .map(std::path::PathBuf::from)
        .unwrap_or_else(SignerIdentity::default_path);

    let identity = backend::create_backend(backend_type, &path)
        .unwrap_or_else(|e| { eprintln!("Failed to load identity: {e}"); std::process::exit(1); });

    let token = identity.pairing_token()
        .unwrap_or_else(|e| { eprintln!("Failed to get pairing token: {e}"); std::process::exit(1); });

    println!();
    println!("  Public key ({}, safe to share):", labels::display_backend_name(identity.backend_name()));
    println!("  {token}");
    println!();
    println!("  Paste into Settings → Signers & Hardware Keys → Add Signer");
    println!();
}

fn backend_label(backend_name: &str) -> &str {
    labels::display_backend_name(backend_name)
}

fn backend_config_label(backend: &str) -> &str {
    labels::display_config_backend(backend)
}

// ── setup ─────────────────────────────────────────────────────────────────────

/// Ask on a TTY whether to install the persistent OS service. Defaults to no when non-interactive.
fn prompt_install_persistent_service() -> bool {
    use std::io::{self, IsTerminal, Write};

    if !io::stdin().is_terminal() {
        return false;
    }

    print!("  Install persistent service? [y/N] ");
    let _ = io::stdout().flush();
    let mut line = String::new();
    if io::stdin().read_line(&mut line).is_err() {
        return false;
    }
    matches!(line.trim().to_lowercase().as_str(), "y" | "yes")
}

async fn cmd_setup(
    server:       String,
    key_id:       String,
    key_secret:   String,
    rsa_pem_file: Option<String>,
    port:         u16,
    no_install_service: bool,
    install_service: bool,
) {
    let server_rsa_pem = match rsa_pem_file {
        Some(ref path) => {
            let pem = match std::fs::read_to_string(path) {
                Ok(s) => s,
                Err(e) => { eprintln!("Error reading RSA PEM file '{path}': {e}"); std::process::exit(1); }
            };
            if !pem.contains("PRIVATE KEY") {
                eprintln!("Error: '{path}' does not look like a PEM private key");
                std::process::exit(1);
            }
            pem
        }
        None => String::new(),
    };

    // Verify server connectivity
    let client = reqwest::Client::new();
    print!("  Checking server at {server}...");
    match client.get(format!("{server}/healthz")).send().await {
        Ok(resp) if resp.status().is_success() => println!(" ok"),
        Ok(resp) => println!(" HTTP {}", resp.status()),
        Err(e) => {
            println!(" failed");
            eprintln!("  Warning: Could not reach server: {e}");
            eprintln!("  Saving config anyway — check server URL later.");
        }
    }

    // Preserve existing backend / pkcs11 settings if config already exists
    let mut config = Config::load().unwrap_or_default();
    config.server_url = server.trim_end_matches('/').to_string();
    config.key_public_id = key_id;
    config.key_secret = key_secret;
    config.server_rsa_pem = server_rsa_pem;
    config.local_port = port;
    if config.backend.is_empty() {
        config.backend = "software".into();
    }
    service_install::autofill_yubikey_paths(&mut config);

    match config.save() {
        Ok(()) => {
            println!();
            println!("  Config saved to: {}", Config::path().display());
            println!("  Mode: {}", backend_config_label(&config.backend));
            let should_install = if no_install_service {
                false
            } else if install_service {
                true
            } else {
                prompt_install_persistent_service()
            };
            if should_install {
                println!();
                print!("  Installing persistent daemon service...");
                match service_install::install_daemon_service() {
                    Ok(()) => println!(" done"),
                    Err(e) => {
                        println!(" skipped");
                        eprintln!("  Warning: Could not install OS service: {e:#}");
                        eprintln!("  Run manually: holder-signer daemon");
                        eprintln!("  Or retry: holder-signer install-service");
                    }
                }
            } else {
                println!("  Run: holder-signer daemon");
                println!("  Or install service later: holder-signer install-service");
            }
        }
        Err(e) => { eprintln!("Error saving config: {e}"); std::process::exit(1); }
    }
}

async fn cmd_install_service() {
    println!();
    print!("  Installing persistent daemon service...");
    match service_install::install_daemon_service() {
        Ok(()) => println!(" done"),
        Err(e) => {
            eprintln!(" failed: {e:#}");
            std::process::exit(1);
        }
    }
    println!();
}

async fn cmd_uninstall_service() {
    println!();
    match service_install::uninstall_daemon_service() {
        Ok(()) => {}
        Err(e) => {
            eprintln!(" failed: {e:#}");
            std::process::exit(1);
        }
    }
    println!();
}

// ── status ────────────────────────────────────────────────────────────────────

async fn cmd_status() {
    let config = load_config_or_exit();

    let identity_path = config
        .signer_ec_key_path
        .as_ref()
        .map(std::path::PathBuf::from)
        .unwrap_or_else(SignerIdentity::default_path);

    println!();
    println!("  holder-signer status");
    println!("  config   : {}", Config::path().display());
    println!("  server   : {}", config.server_url);
    println!("  key id   : {}", config.key_public_id);
    println!("  port     : {}", config.local_port);
    println!("  backend  : {}", backend_config_label(if config.backend.is_empty() { "software" } else { &config.backend }));
    if config.backend == "yubikey" {
        println!("  piv slot : {}", config.yubikey_piv_slot);
        if let Some(ref lib) = config.pkcs11_library {
            println!("  pkcs11   : {lib}");
        } else {
            println!("  pkcs11   : (auto-detect libykcs11)");
        }
    }
    println!();

    match backend::create_backend(&config.backend, &identity_path) {
        Ok(id) => {
            let pub_b64 = id.public_key_b64().unwrap_or_else(|_| "?".into());
            println!("  identity : {} (public: {})", backend_label(id.backend_name()), pub_b64);
        }
        Err(_) if config.backend == "software" || config.backend.is_empty() => {
            if identity_path.exists() {
                println!("  identity : {} (ERROR loading)", identity_path.display());
            } else {
                println!("  identity : NOT FOUND — run `holder-signer init`");
            }
        }
        Err(e) => println!("  identity : {} (ERROR: {e})", config.backend),
    }

    let store_dir = KeyStore::default_dir();
    if store_dir.exists() {
        let count = std::fs::read_dir(&store_dir)
            .map(|e| e.filter_map(|f| f.ok())
                      .filter(|f| f.file_name().to_string_lossy().ends_with(".key"))
                      .count())
            .unwrap_or(0);
        println!("  key store: {} ({count} subkeys)", store_dir.display());
    } else {
        println!("  key store: not yet created");
    }
    println!();
}

// ── daemon ────────────────────────────────────────────────────────────────────

async fn cmd_daemon(grpc_url_arg: Option<String>, poll_interval: u64) {
    let config = load_config_or_exit();

    let grpc_url = grpc_url_arg.unwrap_or_else(|| config.server_url.clone());

    if let Err(e) = grpc_daemon::run_daemon(&config, &grpc_url, poll_interval).await {
        eprintln!("Daemon error: {e:#}");
        std::process::exit(1);
    }
}

// ── connect ───────────────────────────────────────────────────────────────────

async fn cmd_connect(port_override: Option<u16>) {
    let mut config = load_config_or_exit();

    if let Some(p) = port_override {
        config.local_port = p;
    }

    println!();
    println!("  holder-signer connect");
    println!("  server  : {}", config.server_url);
    println!("  port    : {}", config.local_port);
    println!("  Waiting for requests from agent…");
    println!();

    if let Err(e) = server::run(config).await {
        eprintln!("Server error: {e}");
        std::process::exit(1);
    }
}

// ── sign ──────────────────────────────────────────────────────────────────────

async fn cmd_sign(request_file: String, passphrase_arg: Option<String>) {
    let config = load_config_or_exit();

    if config.server_rsa_pem.is_empty() {
        eprintln!(
            "RSA PEM not configured. Re-run setup with --rsa-pem-file, \
             or use the E2EE connect mode (no RSA PEM needed)."
        );
        std::process::exit(1);
    }

    let request_str = if request_file == "-" {
        let mut s = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut s)
            .expect("Failed to read stdin");
        s
    } else {
        std::fs::read_to_string(&request_file)
            .unwrap_or_else(|e| { eprintln!("Cannot read {request_file}: {e}"); std::process::exit(1); })
    };

    let mut request: serde_json::Value = serde_json::from_str(&request_str)
        .unwrap_or_else(|e| { eprintln!("Invalid JSON: {e}"); std::process::exit(1); });

    let passphrase = Zeroizing::new(
        passphrase_arg
            .or_else(|| request.get("passphrase").and_then(|v| v.as_str()).map(|s| s.to_string()))
            .unwrap_or_default()
    );
    if passphrase.is_empty() {
        eprintln!("Passphrase required. Use --passphrase, SAFU_PASSPHRASE env var, or include in request JSON.");
        std::process::exit(1);
    }

    if let Some(obj) = request.as_object_mut() {
        obj.remove("passphrase");
        obj.insert("signingMode".into(), serde_json::json!("external"));
    }

    let network = request.get("network")
        .and_then(|v| v.as_str())
        .unwrap_or("solana-devnet")
        .to_string();

    let client = reqwest::Client::new();
    let kid = request.get("keyPublicId").and_then(|v| v.as_str())
        .or_else(|| if !config.key_public_id.is_empty() { Some(&config.key_public_id) } else { None });
    let secret = request.get("keySecret").and_then(|v| v.as_str())
        .or_else(|| if !config.key_secret.is_empty() { Some(&config.key_secret) } else { None });

    let (kid, secret) = match (kid, secret) {
        (Some(k), Some(s)) => (k.to_string(), s.to_string()),
        _ => { eprintln!("API key credentials required in request or config."); std::process::exit(1); }
    };

    let session_path = "/api/agent/session/from-key";
    let session_body = serde_json::json!({ "keyPublicId": kid });
    let session_body_bytes = serde_json::to_vec(&session_body).unwrap();
    let auth_header = hmac_auth::build_hmac_auth_header(&kid, &secret, "POST", session_path, &session_body_bytes);

    let session_resp = client
        .post(format!("{}{session_path}", config.server_url))
        .header("Authorization", auth_header)
        .header("Content-Type", "application/json")
        .body(session_body_bytes)
        .send().await
        .unwrap_or_else(|e| { eprintln!("Session request failed: {e}"); std::process::exit(1); });

    let session_data: serde_json::Value = session_resp.json().await
        .unwrap_or_else(|e| { eprintln!("Session parse failed: {e}"); std::process::exit(1); });

    let token = session_data["sessionToken"].as_str()
        .or_else(|| session_data["token"].as_str())
        .unwrap_or_else(|| { eprintln!("No session token in response: {session_data}"); std::process::exit(1); })
        .to_string();

    let server_resp = client
        .post(format!("{}/api/agent/transaction/submit", config.server_url))
        .bearer_auth(&token)
        .json(&request)
        .send().await
        .unwrap_or_else(|e| { eprintln!("Submit failed: {e}"); std::process::exit(1); });

    if !server_resp.status().is_success() {
        let status = server_resp.status();
        let body = server_resp.text().await.unwrap_or_default();
        eprintln!("Server error {status}: {body}");
        std::process::exit(1);
    }

    let server_data: sign_pipeline::SubmitServerResponse = server_resp.json().await
        .unwrap_or_else(|e| { eprintln!("Server response parse failed: {e}"); std::process::exit(1); });

    match sign_pipeline::run(
        &config.server_url,
        &token,
        server_data,
        passphrase,
        &config.server_rsa_pem,
        &network,
    ).await {
        Ok(result) => println!("{}", serde_json::to_string_pretty(&result).unwrap()),
        Err(e) => { eprintln!("Signing pipeline failed: {e}"); std::process::exit(1); }
    }
}

// ── export-key ────────────────────────────────────────────────────────────────

async fn cmd_export_key(out: Option<String>, password_arg: Option<String>) {
    let path = SignerIdentity::default_path();
    if !path.exists() {
        eprintln!("No identity key found at {}. Run `holder-signer init` first.", path.display());
        std::process::exit(1);
    }
    let pem = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| { eprintln!("Cannot read identity key: {e}"); std::process::exit(1); });

    let password = match password_arg {
        Some(p) => p,
        None => rpassword_prompt("Export password: "),
    };
    if password.is_empty() {
        eprintln!("Password must not be empty.");
        std::process::exit(1);
    }

    let encrypted = encrypt_export(pem.as_bytes(), password.as_bytes())
        .unwrap_or_else(|e| { eprintln!("Encryption failed: {e}"); std::process::exit(1); });

    let out_path = out.unwrap_or_else(|| {
        dirs::home_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("holder-signer-export.bin")
            .to_string_lossy()
            .into_owned()
    });
    std::fs::write(&out_path, &encrypted)
        .unwrap_or_else(|e| { eprintln!("Cannot write export file: {e}"); std::process::exit(1); });

    println!();
    println!("  Identity key exported to: {out_path}");
    println!("  Transfer this file to the target machine and run:");
    println!("  holder-signer import-key {out_path}");
    println!("  Keep the password secure — it's not stored anywhere.");
    println!();
}

// ── import-key ────────────────────────────────────────────────────────────────

async fn cmd_import_key(bundle: String, password_arg: Option<String>, force: bool) {
    let dest = SignerIdentity::default_path();
    if dest.exists() && !force {
        eprintln!(
            "Identity key already exists at {}.\n\
             Use --force to overwrite (this invalidates any existing key deliveries).",
            dest.display()
        );
        std::process::exit(1);
    }

    let encrypted = std::fs::read(&bundle)
        .unwrap_or_else(|e| { eprintln!("Cannot read bundle file '{bundle}': {e}"); std::process::exit(1); });

    let password = match password_arg {
        Some(p) => p,
        None => rpassword_prompt("Export password: "),
    };

    let pem_bytes = decrypt_export(&encrypted, password.as_bytes())
        .unwrap_or_else(|e| { eprintln!("Decryption failed (wrong password?): {e}"); std::process::exit(1); });

    let pem_str = String::from_utf8(pem_bytes)
        .unwrap_or_else(|_| { eprintln!("Decrypted data is not valid UTF-8 — bundle may be corrupt."); std::process::exit(1); });

    let identity = SignerIdentity::load_from_pem(&pem_str)
        .unwrap_or_else(|e| { eprintln!("Failed to load identity from bundle: {e}"); std::process::exit(1); });
    identity.save(&dest)
        .unwrap_or_else(|e| { eprintln!("Failed to save identity key: {e}"); std::process::exit(1); });

    println!();
    println!("  Identity key imported to: {}", dest.display());
    println!("  Public key: {}", identity.public_key_b64());
    println!();
}

// ── Export/import crypto helpers ──────────────────────────────────────────────

/// Encrypt plaintext with AES-256-GCM using a PBKDF2-derived key.
/// Output format: [16-byte salt][12-byte nonce][ciphertext+tag]
fn encrypt_export(plaintext: &[u8], password: &[u8]) -> anyhow::Result<Vec<u8>> {
    use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Nonce};
    use pbkdf2::pbkdf2_hmac;
    use sha2::Sha256;

    let salt: [u8; 16] = {
        use p256::elliptic_curve::rand_core::RngCore;
        let mut s = [0u8; 16];
        p256::elliptic_curve::rand_core::OsRng.fill_bytes(&mut s);
        s
    };
    let nonce_bytes: [u8; 12] = {
        use p256::elliptic_curve::rand_core::RngCore;
        let mut n = [0u8; 12];
        p256::elliptic_curve::rand_core::OsRng.fill_bytes(&mut n);
        n
    };

    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password, &salt, 200_000, &mut key);

    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| anyhow::anyhow!("AES key init: {e}"))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, plaintext)
        .map_err(|_| anyhow::anyhow!("Encryption failed"))?;

    let mut out = Vec::with_capacity(28 + ciphertext.len());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt an export bundle produced by `encrypt_export`.
fn decrypt_export(data: &[u8], password: &[u8]) -> anyhow::Result<Vec<u8>> {
    use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Nonce};
    use pbkdf2::pbkdf2_hmac;
    use sha2::Sha256;

    if data.len() < 28 {
        anyhow::bail!("Bundle too short to be valid");
    }
    let (salt, rest) = data.split_at(16);
    let (nonce_bytes, ciphertext) = rest.split_at(12);

    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password, salt, 200_000, &mut key);

    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| anyhow::anyhow!("AES key init: {e}"))?;
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher.decrypt(nonce, ciphertext)
        .map_err(|_| anyhow::anyhow!("Decryption failed — wrong password or corrupted bundle"))
}

/// Prompt for a password without echo (falls back to stdin if not a tty).
fn rpassword_prompt(prompt: &str) -> String {
    eprint!("{prompt}");
    let mut line = String::new();
    std::io::BufRead::read_line(&mut std::io::stdin().lock(), &mut line).ok();
    line.trim_end_matches(['\n', '\r']).to_string()
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn load_config_or_exit() -> Config {
    Config::load().unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(1);
    })
}
