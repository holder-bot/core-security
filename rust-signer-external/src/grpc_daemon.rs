/// gRPC daemon — polls RemoteSignerService.PollJob, decrypts subkeys via ECDH,
/// signs transactions via NEAR MPC, and reports results with CompleteJob.
///
/// Also supports HTTP REST polling via /api/signer/poll when the server URL
/// starts with http:// or https:// (Cloud Run / production deployments where
/// the gRPC port is not directly accessible).
use anyhow::{bail, Context, Result};
use futures::FutureExt;
use serde::Deserialize;
use std::str::FromStr;
use zeroize::Zeroize;

use crate::{backend::{self, IdentityBackend}, config::Config, identity::SignerIdentity, sign_pipeline};

// Include tonic-generated client code for the `signer` proto package.
mod proto {
    tonic::include_proto!("signer");
}

use proto::remote_signer_service_client::RemoteSignerServiceClient;
use proto::{CompleteJobRequest, PollJobRequest};

/// Start the signing daemon.  Blocks indefinitely (Ctrl-C to stop).
///
/// If `grpc_url` starts with "http://" or "https://", uses HTTP REST polling
/// via /api/signer/poll (works with Cloud Run where gRPC port is internal).
/// Otherwise connects to the gRPC endpoint directly.
pub async fn run_daemon(config: &Config, grpc_url: &str, poll_interval_secs: u64) -> Result<()> {
    if grpc_url.starts_with("http://") || grpc_url.starts_with("https://") {
        return run_http_daemon(config, grpc_url, poll_interval_secs).await;
    }
    let identity_path = config
        .signer_ec_key_path
        .as_ref()
        .map(std::path::PathBuf::from)
        .unwrap_or_else(SignerIdentity::default_path);

    let identity = backend::create_backend(&config.backend, &identity_path)
        .context("Failed to load identity key — run `holder-signer init` first")?;

    tracing::info!("Daemon identity public key ({}): {}", crate::labels::display_backend_name(identity.backend_name()),
        identity.public_key_b64().unwrap_or_else(|_| "?".into()));

    // ── Connect to gRPC ───────────────────────────────────────────────────────
    let endpoint = tonic::transport::Endpoint::from_str(grpc_url)
        .with_context(|| format!("Invalid gRPC URL: {grpc_url}"))?;

    let endpoint = if grpc_url.starts_with("https://") {
        // Use the Mozilla CA bundle (webpki-roots) to verify Cloud Run / public TLS certs.
        let tls = tonic::transport::ClientTlsConfig::new().with_webpki_roots();
        endpoint
            .tls_config(tls)
            .context("TLS config failed")?
    } else {
        endpoint
    };

    let channel = endpoint.connect().await
        .with_context(|| format!("Failed to connect to gRPC at {grpc_url}"))?;

    let mut client = RemoteSignerServiceClient::new(channel);

    println!();
    println!("  holder-signer daemon");
    println!("  gRPC     : {grpc_url}");
    println!("  key id   : {} (auth; polls all keys bound to this signer)", config.key_public_id);
    println!("  Polling for signing jobs… (Ctrl-C to stop)");
    println!();

    // ── Poll loop ─────────────────────────────────────────────────────────────
    loop {
        match client
            .poll_job(PollJobRequest {
                key_public_id: config.key_public_id.clone(),
                max_jobs:      10,
                timeout_secs:  0,
            })
            .await
        {
            Ok(resp) => {
                let jobs = resp.into_inner().jobs;
                if jobs.is_empty() {
                    tokio::time::sleep(std::time::Duration::from_secs(poll_interval_secs)).await;
                    continue;
                }
                tracing::info!("Received {} job(s)", jobs.len());
                for job in jobs {
                    let tx_id = job.transaction_id.clone();
                    match handle_job(&mut client, identity.as_ref(), &job).await {
                        Ok(()) => tracing::info!("[{tx_id}] Completed successfully"),
                        Err(e) => {
                            tracing::error!("[{tx_id}] Failed: {e:#}");
                            let _ = client
                                .complete_job(CompleteJobRequest {
                                    transaction_id: tx_id,
                                    status:         "failed".into(),
                                    error_message:  e.to_string(),
                                    ..Default::default()
                                })
                                .await;
                        }
                    }
                }
            }
            Err(e) => {
                tracing::warn!("PollJob error: {e:#} — retrying in {poll_interval_secs}s");
                tokio::time::sleep(std::time::Duration::from_secs(poll_interval_secs)).await;
            }
        }
    }
}

async fn handle_job(
    client:   &mut RemoteSignerServiceClient<tonic::transport::Channel>,
    identity: &dyn IdentityBackend,
    job:      &proto::SigningJob,
) -> Result<()> {
    let tx_id = &job.transaction_id;

    // Check expiry
    if !job.expires_at.is_empty() {
        if let Ok(expires) = chrono::DateTime::parse_from_rfc3339(&job.expires_at) {
            if expires < chrono::Utc::now() {
                bail!("Job expired at {}", job.expires_at);
            }
        }
    }

    // Parse signing material
    let mat: sign_pipeline::SigningMaterial = serde_json::from_str(&job.signing_material)
        .context("Failed to parse signing_material JSON")?;

    // Decrypt subkey using identity EC key
    let signing_key = decrypt_subkey(identity, &mat)
        .context("Subkey decryption failed")?;

    // Run signing pipeline (steps 2–5: build → NEAR MPC → broadcast)
    let (network_tx_hash, near_tx_hash) =
        sign_pipeline::run_signing_only(tx_id, &mat, signing_key, &job.network).await?;

    // Report completion via gRPC
    client
        .complete_job(CompleteJobRequest {
            transaction_id: tx_id.clone(),
            status:         "transmitted".into(),
            network_tx_hash,
            near_tx_hash,
            ..Default::default()
        })
        .await
        .context("CompleteJob gRPC call failed")?;

    Ok(())
}

// ── Subkey decryption ─────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct EcdhWrapParams {
    alg:                        Option<String>,
    #[serde(rename = "ephemeralPubKey")]
    ephemeral_pub_key:          Option<String>,
    iv:                         Option<String>,
}

fn decrypt_subkey(
    identity: &dyn IdentityBackend,
    mat:      &sign_pipeline::SigningMaterial,
) -> Result<ed25519_dalek::SigningKey> {
    let params: EcdhWrapParams = serde_json::from_str(&mat.subkey_wrap_params)
        .context("Failed to parse subkeyWrapParams JSON")?;

    match params.alg.as_deref() {
        Some("ecdh-p256-aes256gcm") => {
            let ephemeral_pub = params
                .ephemeral_pub_key
                .as_deref()
                .context("Missing ephemeralPubKey in wrap params")?;
            let iv = params.iv.as_deref().context("Missing iv in wrap params")?;

            let plaintext = identity
                .ecdh_decrypt(ephemeral_pub, &mat.subkey_server_wrapped_private_key, iv)
                .context("ECDH decryption failed")?;

            let key_str = std::str::from_utf8(&plaintext)
                .context("Decrypted key bytes are not valid UTF-8")?;

            parse_ed25519_key(key_str.trim())
        }
        Some(other) => bail!("Unsupported subkey wrap alg: {other}"),
        None => bail!("subkeyWrapParams missing 'alg' field"),
    }
}

/// Try each loaded identity until ECDH unwrap succeeds.
fn decrypt_subkey_any(
    identities: &[Box<dyn IdentityBackend>],
    mat: &sign_pipeline::SigningMaterial,
) -> Result<(ed25519_dalek::SigningKey, String)> {
    let mut last_err: Option<anyhow::Error> = None;
    for id in identities {
        match decrypt_subkey(id.as_ref(), mat) {
            Ok(sk) => {
                return Ok((sk, id.backend_name().to_string()));
            }
            Err(e) => {
                last_err = Some(e);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("No identity backends available")))
        .context("Subkey decryption failed for all loaded identities")
}

/// Parse a base58-encoded ed25519 signing key (Solana / NEAR format).
/// Accepts an optional `ed25519:` prefix.
fn parse_ed25519_key(key_str: &str) -> Result<ed25519_dalek::SigningKey> {
    let b58 = key_str.strip_prefix("ed25519:").unwrap_or(key_str).trim();

    let mut raw = bs58::decode(b58)
        .into_vec()
        .context("Base58 decode failed for private key")?;

    if raw.len() < 32 {
        let got = raw.len();
        raw.zeroize();
        bail!("Private key too short: {got} bytes (expected ≥ 32)");
    }

    let seed: [u8; 32] = raw[..32]
        .try_into()
        .map_err(|_| anyhow::anyhow!("Seed slice error"))?;
    raw.zeroize();

    Ok(ed25519_dalek::SigningKey::from_bytes(&seed))
}

// ── HTTP REST polling mode ────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HttpSigningJob {
    transaction_id:  String,
    #[allow(dead_code)]
    api_key_id:      String,
    network:         String,
    signing_material: String,
    expires_at:      String,
}

#[derive(Debug, Deserialize)]
struct PollResponse {
    jobs: Vec<HttpSigningJob>,
}

async fn get_session_token_for_key(
    client: &reqwest::Client,
    server_url: &str,
    key_public_id: &str,
    key_secret: &str,
) -> Result<String> {
    let path = "/api/agent/session/from-key";
    let url = format!("{server_url}{path}");
    let body = serde_json::json!({ "keyPublicId": key_public_id });
    let body_bytes = serde_json::to_vec(&body)?;

    let auth_header = crate::hmac_auth::build_hmac_auth_header(
        key_public_id,
        key_secret,
        "POST",
        path,
        &body_bytes,
    );

    let resp = client
        .post(&url)
        .header("Authorization", auth_header)
        .header("Content-Type", "application/json")
        .body(body_bytes)
        .send()
        .await
        .context("Session request failed")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        bail!("Session endpoint returned {status}: {body}");
    }

    let data: serde_json::Value = resp.json().await.context("Session response parse failed")?;
    let token = data["sessionToken"].as_str()
        .or_else(|| data["session_token"].as_str())
        .or_else(|| data["token"].as_str())
        .map(|s| s.to_string())
        .context("No session token in response")?;

    Ok(token)
}

/// HTTP REST polling daemon — used when the server URL is a Cloud Run HTTPS endpoint.
async fn run_http_daemon(config: &Config, server_url: &str, poll_interval_secs: u64) -> Result<()> {
    let identity_path = config
        .signer_ec_key_path
        .as_ref()
        .map(std::path::PathBuf::from)
        .unwrap_or_else(SignerIdentity::default_path);

    let identities = backend::create_backends_for_daemon(&config.backend, &identity_path)
        .context("Failed to load identity key(s) — run `holder-signer init` first")?;

    for id in &identities {
        tracing::info!(
            "Daemon identity ({}): {}",
            crate::labels::display_backend_name(id.backend_name()),
            id.public_key_b64().unwrap_or_else(|_| "?".into())
        );
    }

    let poll_keys = config.all_poll_keys();
    if poll_keys.is_empty() {
        bail!("No API keys configured — run `holder-signer setup` or add [[poll_keys]]");
    }

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .context("Failed to build HTTP client")?;

    println!();
    println!("  holder-signer daemon (HTTP mode)");
    println!("  server   : {server_url}");
    println!("  backend  : {}", config.backend);
    println!("  identities: {}", identities.len());
    for k in &poll_keys {
        let label = k.label.as_deref().unwrap_or("-");
        println!("  poll key : {} ({label})", k.key_public_id);
    }
    println!("  Polling for signing jobs… (Ctrl-C to stop)");
    println!();

    // Per-key session tokens
    let mut sessions: Vec<(crate::config::PollKey, String)> = Vec::new();
    for k in &poll_keys {
        tracing::info!("Authenticating poll key {} ({})", k.key_public_id, k.label.as_deref().unwrap_or("-"));
        let token = get_session_token_for_key(&client, server_url, &k.key_public_id, &k.key_secret).await?;
        sessions.push((k.clone(), token));
    }

    let lease_owner = format!(
        "holder-signer:{}:{}",
        std::env::var("HOSTNAME").unwrap_or_else(|_| "local".to_string()),
        std::process::id(),
    );

    let mut failed_tx_ids: std::collections::HashSet<String> = std::collections::HashSet::new();

    let shutdown = tokio::signal::ctrl_c();
    tokio::pin!(shutdown);

    loop {
        if (&mut shutdown).now_or_never().is_some() {
            tracing::info!("Shutdown signal received — exiting gracefully");
            return Ok(());
        }

        let mut any_jobs = false;
        for (key, session_token) in sessions.iter_mut() {
            let poll_url = format!("{server_url}/api/signer/poll");
            let resp = client
                .post(&poll_url)
                .bearer_auth(session_token.as_str())
                .json(&serde_json::json!({
                    "maxJobs": 10,
                    "leaseOwner": format!("{lease_owner}:{}", key.key_public_id),
                    "leaseMs": std::cmp::max(poll_interval_secs * 1000, 120_000),
                }))
                .send()
                .await;

            match resp {
                Err(e) => {
                    tracing::warn!("[{}] Poll request failed: {e:#}", key.key_public_id);
                    continue;
                }
                Ok(r) if r.status() == 401 => {
                    tracing::info!("[{}] Session expired — refreshing", key.key_public_id);
                    match get_session_token_for_key(
                        &client,
                        server_url,
                        &key.key_public_id,
                        &key.key_secret,
                    )
                    .await
                    {
                        Ok(t) => *session_token = t,
                        Err(e) => tracing::warn!("[{}] Token refresh failed: {e:#}", key.key_public_id),
                    }
                    continue;
                }
                Ok(r) if !r.status().is_success() => {
                    let status = r.status();
                    let body = r.text().await.unwrap_or_default();
                    tracing::warn!("[{}] Poll returned {status}: {body}", key.key_public_id);
                    continue;
                }
                Ok(r) => {
                    let poll_resp: PollResponse = match r.json().await {
                        Ok(p) => p,
                        Err(e) => {
                            tracing::warn!("[{}] Poll parse failed: {e:#}", key.key_public_id);
                            continue;
                        }
                    };
                    if poll_resp.jobs.is_empty() {
                        continue;
                    }
                    any_jobs = true;
                    tracing::info!(
                        "[{}] Received {} job(s)",
                        key.key_public_id,
                        poll_resp.jobs.len()
                    );

                    for job in poll_resp.jobs {
                        let tx_id = job.transaction_id.clone();
                        if failed_tx_ids.contains(&tx_id) {
                            continue;
                        }

                        match handle_http_job_multi(
                            server_url,
                            session_token.as_str(),
                            &identities,
                            &job,
                        )
                        .await
                        {
                            Ok(backend_used) => {
                                tracing::info!(
                                    "[{tx_id}] Completed successfully (unwrap={backend_used})"
                                );
                            }
                            Err(e) => {
                                let err_str = format!("{e:#}");
                                let is_ecdh_error = err_str.contains("ECDH")
                                    || err_str.contains("AES-GCM decryption failed")
                                    || err_str.contains("all loaded identities");
                                let is_transient = {
                                    let lower = err_str.to_lowercase();
                                    lower.contains("rate limit")
                                        || lower.contains("timeout")
                                        || lower.contains("temporar")
                                        || err_str.contains("RateLimited")
                                        || err_str.contains("429")
                                        || err_str.contains("503")
                                };

                                if is_ecdh_error {
                                    tracing::error!("[{tx_id}] ECDH failed for all identities: {err_str}");
                                    continue;
                                }
                                if is_transient {
                                    tracing::warn!("[{tx_id}] Transient failure — will retry: {err_str}");
                                    continue;
                                }

                                tracing::error!("[{tx_id}] Failed: {err_str}");
                                failed_tx_ids.insert(tx_id.clone());
                                let _ = client
                                    .post(format!(
                                        "{server_url}/api/agent/transaction/{tx_id}/complete"
                                    ))
                                    .bearer_auth(session_token.as_str())
                                    .json(&serde_json::json!({
                                        "status": "failed",
                                        "errorMessage": err_str.chars().take(500).collect::<String>(),
                                    }))
                                    .send()
                                    .await;
                            }
                        }
                    }
                }
            }
        }

        if !any_jobs {
            tokio::time::sleep(std::time::Duration::from_secs(poll_interval_secs)).await;
        }
    }
}

async fn handle_http_job_multi(
    server_url: &str,
    session_token: &str,
    identities: &[Box<dyn IdentityBackend>],
    job: &HttpSigningJob,
) -> Result<String> {
    let tx_id = &job.transaction_id;

    if !job.expires_at.is_empty() {
        if let Ok(expires) = chrono::DateTime::parse_from_rfc3339(&job.expires_at) {
            if expires < chrono::Utc::now() {
                bail!("Job expired at {}", job.expires_at);
            }
        }
    }

    let mat: sign_pipeline::SigningMaterial = serde_json::from_str(&job.signing_material)
        .context("Failed to parse signing_material JSON")?;

    let (signing_key, backend_used) = decrypt_subkey_any(identities, &mat)?;

    sign_pipeline::run_from_signing_key(
        server_url,
        session_token,
        tx_id,
        &mat,
        signing_key,
        &job.network,
    )
    .await?;

    Ok(backend_used)
}

async fn handle_http_job(
    server_url:   &str,
    session_token: &str,
    identity:     &dyn IdentityBackend,
    job:          &HttpSigningJob,
) -> Result<()> {
    let tx_id = &job.transaction_id;

    if !job.expires_at.is_empty() {
        if let Ok(expires) = chrono::DateTime::parse_from_rfc3339(&job.expires_at) {
            if expires < chrono::Utc::now() {
                bail!("Job expired at {}", job.expires_at);
            }
        }
    }

    let mat: sign_pipeline::SigningMaterial = serde_json::from_str(&job.signing_material)
        .context("Failed to parse signing_material JSON")?;

    let signing_key = decrypt_subkey(identity, &mat)
        .context("Subkey decryption failed")?;

    sign_pipeline::run_from_signing_key(
        server_url,
        session_token,
        tx_id,
        &mat,
        signing_key,
        &job.network,
    ).await?;

    Ok(())
}
