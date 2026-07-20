/// Full local signing pipeline for the external signer.
///
/// Given the signingMaterial from the server + a passphrase + RSA PEM:
///   1. Unwrap the subkey (AES + RSA)
///   2. Build chain tx bytes (Solana / EVM) via safu-network
///   3. Sign NEAR request_sign_v2 → broadcast → poll MPC signature
///   4. Attach signature to chain tx → broadcast to chain RPC
///   5. POST /api/agent/transaction/{id}/complete to server
///   6. Return the network tx hash
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;
use zeroize::Zeroizing;

use base64::Engine as _;
use safu_network::{solana, evm, near_client};

/// Signing material returned by the server's signingMode: "external" path.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SigningMaterial {
    pub subkey_server_wrapped_private_key: String,
    pub subkey_wrap_params:                String,
    pub near_account_id:                   String,
    pub near_contract_id:                  String,
    pub chain:                             String,
    pub template_id:                       String,
    pub tx_details:                        serde_json::Value,
    pub public_key:                        String,
    #[serde(default)]
    pub derivation_path:                   String,
}

/// The full server submit response (external signing path).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubmitServerResponse {
    pub transaction_id:   String,
    pub status:           String,
    pub signing_material: Option<SigningMaterial>,
    pub near_rpc_urls:    Option<Vec<String>>,
    pub expires_at:       Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PipelineResult {
    pub transaction_id:  String,
    pub status:          String,
    pub network_tx_hash: String,
}

/// Run the complete signing pipeline locally.
///
/// `server_url`      — base URL of the safu server
/// `session_token`   — JWT from the server session
/// `server_response` — parsed response from the server submit call
/// `passphrase`      — user's passphrase (never sent to server)
/// `rsa_pem`         — server RSA private key PEM (stored locally after setup)
/// `network`         — e.g. "solana-mainnet", "solana-devnet", "base-mainnet"
pub async fn run(
    server_url:      &str,
    session_token:   &str,
    server_response: SubmitServerResponse,
    passphrase:      Zeroizing<String>,
    rsa_pem:         &str,
    network:         &str,
) -> Result<PipelineResult> {
    let tx_id = server_response.transaction_id.clone();

    if server_response.status != "ready_for_external_signing" {
        bail!(
            "Server returned unexpected status: {} — expected ready_for_external_signing",
            server_response.status
        );
    }

    let mat = server_response.signing_material
        .context("Server response missing signingMaterial")?;

    // ── Step 1: unwrap the subkey ─────────────────────────────────────────────
    tracing::info!("[{}] Unwrapping subkey…", tx_id);
    let signing_key = safu_signer::crypto::unwrap::unwrap_subkey(
        &mat.subkey_server_wrapped_private_key,
        &mat.subkey_wrap_params,
        passphrase.as_str(),
        rsa_pem,
    )
    .map_err(|e| anyhow::anyhow!("Key unwrap failed: {e}"))?;
    drop(passphrase); // zeroed here

    run_from_signing_key(server_url, session_token, &tx_id, &mat, signing_key, network).await
}

/// Inner pipeline used by both the passphrase path (above) and the daemon
/// path (where the signing key is loaded from the key store).
///
/// Calls `notify_complete` via REST at the end. The gRPC daemon should use
/// `run_signing_only` instead and report completion via `CompleteJob`.
pub async fn run_from_signing_key(
    server_url:    &str,
    session_token: &str,
    tx_id:         &str,
    mat:           &SigningMaterial,
    signing_key:   ed25519_dalek::SigningKey,
    network:       &str,
) -> Result<PipelineResult> {
    let (network_tx_hash, near_tx_hash) = run_signing_only(tx_id, mat, signing_key, network).await?;

    if let Err(e) = notify_complete(server_url, session_token, tx_id, &network_tx_hash, &near_tx_hash).await {
        // Non-fatal — server will reconcile via chain polling
        tracing::warn!("[{}] Failed to notify server of completion: {e:#}", tx_id);
    }

    Ok(PipelineResult {
        transaction_id:  tx_id.to_string(),
        status:          "transmitted".into(),
        network_tx_hash,
    })
}

/// Run signing steps 2–5 (build → NEAR MPC → broadcast) without REST notification.
/// Returns `(network_tx_hash, near_tx_hash)`.
/// The gRPC daemon calls this and reports completion via `CompleteJob`.
pub async fn run_signing_only(
    tx_id:       &str,
    mat:         &SigningMaterial,
    signing_key: ed25519_dalek::SigningKey,
    network:     &str,
) -> Result<(String, String)> {
    let chain = mat.chain.to_lowercase();

    // ── Step 2+3+4: Chain-specific signing and broadcast ──────────────────────
    let network_id = near_client::network_id_for_contract(&mat.near_contract_id);
    let derivation_path = if mat.derivation_path.is_empty() {
        "0".to_string()
    } else {
        mat.derivation_path.clone()
    };

    let (network_tx_hash, near_tx_hash) = match chain_kind(&chain) {
        ChainKind::Solana => {
            sign_and_broadcast_solana(
                tx_id, mat, signing_key, network, network_id, &derivation_path,
            ).await?
        }

        ChainKind::Evm => {
            let request_id = uuid::Uuid::new_v4().to_string();
            // EVM: template signing — NEAR contract builds EIP-1559 + signs + returns signed tx
            // The daemon does NOT build tx bytes — the contract does it from template params.
            tracing::info!("[{}] Requesting NEAR MPC template signature (request_template_sign_v2)…", tx_id);
            let near_template_id = normalize_evm_template_id(&mat.template_id);

            // Convert ETH amount to wei string (contract expects wei)
            let amount_str = mat.tx_details.get("amount").and_then(|v| v.as_str()).unwrap_or("0");
            let amount_wei = parse_eth_to_wei(amount_str).to_string();

            // Resolve EVM chain ID
            let evm_chain_id = mat.tx_details.get("evmChainId")
                .or(mat.tx_details.get("chainId"))
                .and_then(|v| v.as_str().map(|s| s.to_string()).or(v.as_u64().map(|n| n.to_string())))
                .unwrap_or_else(|| evm_chain_id_from_network(network).to_string());

            // Build evm_tx_params — fetch nonce + gas from RPC if not provided
            let evm_tx_params = match mat.tx_details.get("evmTxParams") {
                Some(p) if !p.is_null() && p.as_object().map(|o| !o.is_empty()).unwrap_or(false) => p.clone(),
                _ => {
                    let to_addr = mat.tx_details.get("toPublicKey").or(mat.tx_details.get("to"))
                        .and_then(|v| v.as_str()).unwrap_or("");
                    evm::fetch_evm_tx_params(&mat.public_key, to_addr, &amount_wei, network).await
                        .unwrap_or_else(|e| {
                            tracing::warn!("[{}] Failed to fetch EVM tx params: {e:#}, using defaults", tx_id);
                            json!({
                                "nonce": 0,
                                "gas_limit": 21000,
                                "max_fee_per_gas": "2000000000",
                                "max_priority_fee_per_gas": "1000000"
                            })
                        })
                }
            };

            let to_addr = mat.tx_details.get("toPublicKey").or(mat.tx_details.get("to"))
                .and_then(|v| v.as_str()).unwrap_or("");

            tracing::info!("[{}] EVM template params: to={}, amount_wei={}, chainId={}, nonce={}",
                tx_id, to_addr, amount_wei, evm_chain_id,
                evm_tx_params.get("nonce").and_then(|v| v.as_u64()).unwrap_or(0));

            let near_payload = json!({
                "request_id": request_id,
                "request": {
                    "template_id":     near_template_id,
                    "chain":           chain_label(&mat.chain),
                    "derivation_path": derivation_path,
                    "to":              to_addr,
                    "amount":          amount_wei,
                    "evm_chain_id":    evm_chain_id,
                    "evm_tx_params":   evm_tx_params,
                },
            });
            let signed_near_tx = near_client::build_and_sign_request_template_sign_v2(
                signing_key, &mat.near_account_id, &mat.near_contract_id,
                near_payload, network_id,
            ).await.context("Failed to build NEAR template signing tx")?;

            let outcome = near_client::broadcast_signed_tx(&signed_near_tx, network_id)
                .await.context("Failed to broadcast NEAR template signing request")?;
            let actual_rid = near_client::extract_request_id(&outcome).unwrap_or(request_id);
            let near_hash = outcome.transaction.hash.to_string();
            tracing::info!("[{}] NEAR template sign submitted: {} (request_id={})", tx_id, near_hash, actual_rid);

            tracing::info!("[{}] Polling NEAR MPC for EVM signature…", tx_id);
            let mpc_sig_payload = near_client::poll_sign_result(
                &actual_rid, &mat.near_contract_id, network_id, 60, 5000,
            ).await.context("EVM template MPC polling failed")?;

            tracing::info!("[{}] Assembling signed EVM transaction…", tx_id);
            let evm_params = evm_tx_params;
            let chain_id: u64 = mat.tx_details.get("evmChainId")
                .or(mat.tx_details.get("chainId"))
                .and_then(|v| v.as_str().or(v.as_u64().map(|_| "")).and_then(|s| if s.is_empty() { v.as_u64() } else { s.parse().ok() }))
                .unwrap_or(84532); // default: Base Sepolia
            let nonce: u64 = evm_params.get("nonce").and_then(|v| v.as_u64()).unwrap_or(0);
            let gas_limit: u64 = evm_params.get("gasLimit").or(evm_params.get("gas_limit"))
                .and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
                .unwrap_or(21000);
            let max_fee: u128 = evm_params.get("maxFeePerGas").or(evm_params.get("max_fee_per_gas"))
                .and_then(|v| v.as_str().and_then(|s| s.parse().ok()).or(v.as_u64().map(|n| n as u128)))
                .unwrap_or(1_000_000_000); // 1 gwei default
            let max_priority_fee: u128 = evm_params.get("maxPriorityFeePerGas").or(evm_params.get("max_priority_fee_per_gas"))
                .and_then(|v| v.as_str().and_then(|s| s.parse().ok()).or(v.as_u64().map(|n| n as u128)))
                .unwrap_or(1_000_000);
            let to_addr = mat.tx_details.get("toPublicKey").or(mat.tx_details.get("to"))
                .and_then(|v| v.as_str()).unwrap_or("");
            let amount_str = mat.tx_details.get("amount").and_then(|v| v.as_str()).unwrap_or("0");
            // Convert ETH amount to wei
            let value_wei: u128 = parse_eth_to_wei(amount_str);
            let data = evm_params.get("data")
                .and_then(|v| v.as_str())
                .map(|s| hex::decode(s.trim_start_matches("0x")).unwrap_or_default())
                .unwrap_or_default();

            let signed_tx = evm::assemble_signed_evm_tx(
                &mpc_sig_payload, chain_id, nonce, max_priority_fee, max_fee,
                gas_limit, to_addr, value_wei, &data,
            ).context("Failed to assemble signed EVM tx")?;

            tracing::info!("[{}] Broadcasting EVM tx ({} bytes)…", tx_id, signed_tx.len());
            let tx_hash = evm::broadcast_raw_tx(&signed_tx, network).await
                .context("EVM broadcast failed")?;
            (tx_hash, near_hash)
        }

        ChainKind::Unknown => bail!("Unsupported chain: {}", mat.chain),
    };
    tracing::info!("[{}] Transmitted: {}", tx_id, network_tx_hash);

    Ok((network_tx_hash, near_tx_hash))
}

// ── Helpers ───────────────────────────────────────────────────────────────────

pub async fn notify_complete(
    server_url:      &str,
    session_token:   &str,
    tx_id:           &str,
    network_tx_hash: &str,
    near_tx_hash:    &str,
) -> Result<()> {
    let client = reqwest::Client::new();
    let url = format!("{server_url}/api/agent/transaction/{tx_id}/complete");
    let resp = client
        .post(&url)
        .bearer_auth(session_token)
        .json(&json!({
            "networkTxHash": network_tx_hash,
            "nearTxHash":    near_tx_hash,
            "status":        "transmitted",
        }))
        .send()
        .await
        .context("Failed to send complete request to server")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        bail!("Server complete endpoint returned {status}: {body}");
    }
    Ok(())
}

/// Solana MPC sign + broadcast with retries (fresh blockhash, derivation-path fallback).
async fn sign_and_broadcast_solana(
    tx_id:           &str,
    mat:             &SigningMaterial,
    signing_key:     ed25519_dalek::SigningKey,
    network:         &str,
    network_id:      &str,
    derivation_path: &str,
) -> Result<(String, String)> {
    let mut path = derivation_path.to_string();
    let mut path_fallback_pending = path != "0";
    let max_blockhash_retries = 2;

    for blockhash_attempt in 0..=max_blockhash_retries {
        tracing::info!(
            "[{}] Building SOL tx bytes (attempt {}, path={})…",
            tx_id, blockhash_attempt + 1, path
        );
        let tx_bytes = solana::build_transaction_bytes(
            &mat.template_id, &mat.tx_details, &mat.public_key, network,
        ).await.context("Failed to build Solana tx bytes")?;

        let request_id = uuid::Uuid::new_v4().to_string();
        tracing::info!("[{}] Requesting NEAR MPC signature (request_sign_v2)…", tx_id);
        let payload_b64 = base64::engine::general_purpose::STANDARD.encode(&tx_bytes);
        let memo = mat.tx_details.get("memo").and_then(|v| v.as_str());
        let near_payload = json!({
            "request_id": request_id,
            "request": {
                "chain":           chain_label(&mat.chain),
                "derivation_path": path,
                "payload":         payload_b64,
                "memo":            memo,
            },
        });
        let signed_near_tx = near_client::build_and_sign_request_sign_v2(
            signing_key.clone(), &mat.near_account_id, &mat.near_contract_id,
            near_payload, network_id,
        ).await.context("Failed to build NEAR MPC signing tx")?;

        let outcome = near_client::broadcast_signed_tx(&signed_near_tx, network_id)
            .await.context("Failed to broadcast NEAR MPC signing request")?;
        let actual_rid = near_client::extract_request_id(&outcome).unwrap_or(request_id);
        let near_hash = outcome.transaction.hash.to_string();
        tracing::info!(
            "[{}] NEAR MPC request submitted: {} (request_id={})",
            tx_id, near_hash, actual_rid
        );

        tracing::info!("[{}] Polling NEAR MPC for signature…", tx_id);
        let sig_bytes = near_client::poll_sign_result(
            &actual_rid, &mat.near_contract_id, network_id, 60, 3000,
        ).await.context("MPC signature polling failed")?;
        let sig: [u8; 64] = sig_bytes.as_slice().try_into().map_err(|_| {
            anyhow::anyhow!(
                "MPC returned signature of unexpected length {} (expected 64)",
                sig_bytes.len()
            )
        })?;

        tracing::info!("[{}] Broadcasting SOL tx…", tx_id);
        match solana::broadcast(&tx_bytes, &sig, network).await {
            Ok(tx_hash) => return Ok((tx_hash, near_hash)),
            Err(e) => {
                let msg = format!("{e:#}");
                if solana::is_blockhash_expired_error(&msg)
                    && blockhash_attempt < max_blockhash_retries
                {
                    tracing::warn!(
                        "[{}] Solana blockhash expired before broadcast; rebuilding (retry {})",
                        tx_id, blockhash_attempt + 2
                    );
                    continue;
                }
                if solana::is_signature_verification_error(&msg)
                    && path_fallback_pending
                {
                    tracing::warn!(
                        "[{}] Signature verification failed on path {}; retrying with path 0",
                        tx_id, path
                    );
                    path = "0".into();
                    path_fallback_pending = false;
                    continue;
                }
                return Err(e).context("Solana broadcast failed");
            }
        }
    }

    bail!("Solana sign+broadcast failed after retries")
}

enum ChainKind { Solana, Evm, Unknown }

fn chain_kind(chain_lower: &str) -> ChainKind {
    if chain_lower.contains("sol") {
        ChainKind::Solana
    } else if chain_lower.contains("evm") || chain_lower.contains("eth")
           || chain_lower.contains("base") || chain_lower.contains("hedera")
    {
        ChainKind::Evm
    } else {
        ChainKind::Unknown
    }
}

fn chain_label(chain: &str) -> &'static str {
    match chain.to_lowercase().as_str() {
        s if s.contains("eth") || s.contains("evm") || s.contains("base") => "Evm",
        s if s.contains("btc") || s.contains("bitcoin") => "Bitcoin",
        _ => "Solana",
    }
}

fn evm_chain_id_from_network(network: &str) -> u64 {
    let net = network.to_lowercase();
    if net == "base-mpc" || (net.contains("base") && net.contains("sepolia")) { 84532 }
    else if net.contains("base") { 8453 }
    else if net.contains("sepolia") { 11155111 }
    else if net.contains("ethereum") || net.contains("eth") { 1 }
    else { 84532 } // default: Base Sepolia
}

fn normalize_evm_template_id(template_id: &str) -> &str {
    match template_id {
        "evm_native_transfer_v1" | "evm_erc20_transfer_v1" | "evm_x402_usdc_v1" => template_id,
        _ => "evm_native_transfer_v1",
    }
}

/// Parse an ETH amount string (e.g. "0.0001") to wei (u128).
fn parse_eth_to_wei(amount: &str) -> u128 {
    let amount = amount.trim();
    if amount.is_empty() || amount == "0" { return 0; }
    // Split on decimal point
    let parts: Vec<&str> = amount.split('.').collect();
    let whole: u128 = parts[0].parse().unwrap_or(0);
    let frac_str = if parts.len() > 1 { parts[1] } else { "" };
    // Pad or truncate to 18 decimal places
    let padded = format!("{:0<18}", frac_str);
    let frac: u128 = padded[..18].parse().unwrap_or(0);
    whole * 1_000_000_000_000_000_000 + frac
}
