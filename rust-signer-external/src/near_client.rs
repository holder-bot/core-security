/// NEAR RPC client — adapted from rust-api/src/signing/near_client.rs.
use anyhow::{bail, Context, Result};
use base64::Engine as _;
use near_jsonrpc_client::{methods, JsonRpcClient};
use near_jsonrpc_primitives::types::query::QueryResponseKind;
use near_primitives::{
    transaction::{Action, FunctionCallAction, Transaction},
    types::{AccountId, BlockReference},
    views::FinalExecutionOutcomeView,
};
use serde_json::json;
use std::{
    collections::HashMap,
    str::FromStr,
    sync::{LazyLock, Mutex},
    time::{Duration as StdDuration, SystemTime},
};
use tokio::time::{sleep, Duration};

const TESTNET_RPCS: &[&str] = &[
    "https://rpc.testnet.near.org",
    "https://near-testnet.drpc.org",
    "https://test.rpc.fastnear.com",
    "https://testnet-rpc.intea.rs",
];
const MAINNET_RPCS: &[&str] = &[
    "https://rpc.mainnet.near.org",
    "https://near-mainnet.drpc.org",
    "https://rpc.mainnet.pagoda.co",
    "https://free.rpc.fastnear.com",
];

const BASE_COOLDOWN_MS: u64 = 5_000;
const MAX_COOLDOWN_MS: u64 = 120_000;
const REQUEST_ID_REUSED_COOLDOWN_MS: u64 = 2_000;
const RATE_LIMIT_COOLDOWN_MIN_MS: u64 = 60_000;
const RATE_LIMIT_COOLDOWN_MAX_MS: u64 = 180_000;
const MEDIUM_COOLDOWN_MIN_MS: u64 = 15_000;
const MEDIUM_COOLDOWN_MAX_MS: u64 = 60_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RpcErrorClass {
    RateLimited,
    Timeout,
    Transport,
    Other,
}

fn classify_rpc_error(error: &str) -> RpcErrorClass {
    let text = error.to_ascii_lowercase();
    if text.contains("429")
        || text.contains("too many requests")
        || text.contains("rate limit")
        || text.contains("quota")
        || text.contains("throttl")
    {
        return RpcErrorClass::RateLimited;
    }
    if text.contains("timed out")
        || text.contains("timeout")
        || text.contains("504")
        || text.contains("408")
    {
        return RpcErrorClass::Timeout;
    }
    if text.contains("econnrefused")
        || text.contains("enotfound")
        || text.contains("econnreset")
        || text.contains("network")
        || text.contains("fetch failed")
        || text.contains("failed to fetch")
        || text.contains("tls")
        || text.contains("dns")
    {
        return RpcErrorClass::Transport;
    }
    RpcErrorClass::Other
}

#[derive(Clone, Debug, Default)]
struct RpcHealth {
    failures: u32,
    cooldown_until_ms: u64,
    last_failure_at_ms: u64,
}

static RPC_HEALTH: LazyLock<Mutex<HashMap<&'static str, RpcHealth>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub fn rpc_urls(network_id: &str) -> &'static [&'static str] {
    if network_id.contains("mainnet") { MAINNET_RPCS } else { TESTNET_RPCS }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_else(|_| StdDuration::from_millis(0))
        .as_millis() as u64
}

fn rpc_candidates(network_id: &str) -> Vec<&'static str> {
    let now = now_ms();
    let health = RPC_HEALTH.lock().expect("rpc health lock poisoned");
    let mut ranked: Vec<(&'static str, RpcHealth, bool)> = rpc_urls(network_id)
        .iter()
        .copied()
        .map(|url| {
            let state = health.get(url).cloned().unwrap_or_default();
            let cooling = state.cooldown_until_ms > now;
            (url, state, cooling)
        })
        .collect();

    ranked.sort_by(|a, b| {
        a.2.cmp(&b.2)
            .then_with(|| a.1.failures.cmp(&b.1.failures))
            .then_with(|| a.1.last_failure_at_ms.cmp(&b.1.last_failure_at_ms))
    });

    ranked.into_iter().map(|(url, _, _)| url).collect()
}

fn mark_rpc_success(url: &'static str) {
    let mut health = RPC_HEALTH.lock().expect("rpc health lock poisoned");
    let current = health.get(url).cloned().unwrap_or_default();
    health.insert(url, RpcHealth {
        failures: current.failures.saturating_sub(1),
        cooldown_until_ms: 0,
        last_failure_at_ms: current.last_failure_at_ms,
    });
}

fn mark_rpc_failure(url: &'static str, error: &str) {
    let now = now_ms();
    let mut health = RPC_HEALTH.lock().expect("rpc health lock poisoned");
    let current = health.get(url).cloned().unwrap_or_default();
    let is_request_id_reused = error.to_ascii_lowercase().contains("request_id already used");
    let error_class = classify_rpc_error(error);
    let next_failures = if is_request_id_reused {
        current.failures
    } else {
        (current.failures + 1).min(8)
    };
    let next_cooldown_ms = if is_request_id_reused {
        REQUEST_ID_REUSED_COOLDOWN_MS
    } else if error_class == RpcErrorClass::RateLimited {
        let span = RATE_LIMIT_COOLDOWN_MAX_MS.saturating_sub(RATE_LIMIT_COOLDOWN_MIN_MS).saturating_add(1);
        RATE_LIMIT_COOLDOWN_MIN_MS + (now % span)
    } else if error_class == RpcErrorClass::Timeout || error_class == RpcErrorClass::Transport {
        let exp = (BASE_COOLDOWN_MS * 2u64.saturating_pow(next_failures.saturating_sub(1))).min(MAX_COOLDOWN_MS);
        exp.clamp(MEDIUM_COOLDOWN_MIN_MS, MEDIUM_COOLDOWN_MAX_MS)
    } else {
        (BASE_COOLDOWN_MS * 2u64.saturating_pow(next_failures.saturating_sub(1))).min(MAX_COOLDOWN_MS)
    };

    health.insert(url, RpcHealth {
        failures: next_failures,
        cooldown_until_ms: now + next_cooldown_ms,
        last_failure_at_ms: now,
    });
}

pub fn network_id_for_contract(contract_id: &str) -> &'static str {
    if contract_id.ends_with(".near") && !contract_id.ends_with(".testnet") {
        "mainnet"
    } else {
        "testnet"
    }
}

pub async fn broadcast_signed_tx(
    signed_tx_bytes: &[u8],
    network_id: &str,
) -> Result<FinalExecutionOutcomeView> {
    use borsh::BorshDeserialize;
    let urls = rpc_candidates(network_id);
    let mut last_err = anyhow::anyhow!("No RPC URLs available");

    for url in urls {
        let client = JsonRpcClient::connect(url);
        let signed_tx = near_primitives::transaction::SignedTransaction::try_from_slice(signed_tx_bytes)
            .context("Failed to deserialize signed NEAR tx")?;
        match client
            .call(methods::broadcast_tx_commit::RpcBroadcastTxCommitRequest {
                signed_transaction: signed_tx,
            })
            .await
        {
            Ok(outcome) => {
                mark_rpc_success(url);
                ensure_execution_success(&outcome)?;
                return Ok(outcome);
            }
            Err(e) => {
                mark_rpc_failure(url, &e.to_string());
                tracing::warn!("NEAR RPC {url} failed: {e}");
                last_err = anyhow::anyhow!("{e}");
            }
        }
    }
    Err(last_err)
}

fn ensure_execution_success(outcome: &FinalExecutionOutcomeView) -> Result<()> {
    let value = serde_json::to_value(outcome).context("Failed to serialize NEAR execution outcome")?;

    if let Some(failure) = value.get("status").and_then(|status| status.get("Failure")) {
        bail!("NEAR transaction execution failed: {}", failure);
    }

    for receipt in value.get("receipts_outcome").and_then(|v| v.as_array()).into_iter().flatten() {
        if let Some(failure) = receipt
            .get("outcome")
            .and_then(|outcome| outcome.get("status"))
            .and_then(|status| status.get("Failure"))
        {
            bail!("NEAR receipt execution failed: {}", failure);
        }
    }

    Ok(())
}

pub async fn get_access_key_info(
    account_id: &str,
    public_key: &near_crypto::PublicKey,
    network_id: &str,
) -> Result<(near_primitives::hash::CryptoHash, u64)> {
    let urls = rpc_candidates(network_id);
    let mut last_err = anyhow::anyhow!("No RPC URLs available");

    for url in urls {
        let client = JsonRpcClient::connect(url);
        let account: AccountId = AccountId::from_str(account_id)
            .context("Invalid NEAR account ID")?;
        match client
            .call(methods::query::RpcQueryRequest {
                block_reference: BlockReference::latest(),
                request: near_primitives::views::QueryRequest::ViewAccessKey {
                    account_id: account.clone(),
                    public_key: public_key.clone(),
                },
            })
            .await
        {
            Ok(resp) => {
                if let QueryResponseKind::AccessKey(info) = resp.kind {
                    mark_rpc_success(url);
                    return Ok((resp.block_hash, info.nonce));
                }
                mark_rpc_failure(url, "unexpected query response kind");
                last_err = anyhow::anyhow!("Unexpected query response kind");
            }
            Err(e) => {
                mark_rpc_failure(url, &e.to_string());
                tracing::warn!("NEAR RPC {url} failed: {e}");
                last_err = anyhow::anyhow!("{e}");
            }
        }
    }
    Err(last_err)
}

/// Build + sign a NEAR `request_sign_v2` tx, return borsh-serialized bytes.
pub async fn build_and_sign_request_sign_v2(
    signing_key:     ed25519_dalek::SigningKey,
    near_account_id: &str,
    contract_id:     &str,
    payload:         serde_json::Value,
    network_id:      &str,
) -> Result<Vec<u8>> {
    let account_id: AccountId = AccountId::from_str(near_account_id)
        .context("Invalid NEAR account ID")?;
    let receiver_id: AccountId = AccountId::from_str(contract_id)
        .context("Invalid NEAR contract ID")?;

    let secret_key = near_crypto::SecretKey::ED25519(
        near_crypto::ED25519SecretKey(signing_key.to_keypair_bytes())
    );
    let public_key = secret_key.public_key();

    let (block_hash, nonce) =
        get_access_key_info(near_account_id, &public_key, network_id).await?;

    let tx = Transaction {
        signer_id:   account_id,
        public_key:  public_key.clone(),
        nonce:       nonce + 1,
        receiver_id,
        block_hash,
        actions: vec![Action::FunctionCall(Box::new(FunctionCallAction {
            method_name: "request_sign_v2".to_string(),
            args:        serde_json::to_vec(&payload).context("Failed to serialize payload")?,
            gas:         300_000_000_000_000,
            deposit:     0,
        }))],
    };

    let signature = secret_key.sign(tx.get_hash_and_size().0.as_ref());
    let signed_tx = near_primitives::transaction::SignedTransaction::new(signature, tx);

    borsh::to_vec(&signed_tx).context("Failed to borsh-encode signed tx")
}

/// Poll `get_sign_result` until MPC result is ready.
pub async fn poll_sign_result(
    request_id:   &str,
    contract_id:  &str,
    network_id:   &str,
    max_attempts: u32,
    interval_ms:  u64,
) -> Result<Vec<u8>> {
    let urls = rpc_candidates(network_id);
    if urls.is_empty() {
        bail!("No RPC URLs available for poll_sign_result");
    }

    // Sticky primary for a short burst; rotate on rate-limit/timeout/transport.
    let mut rpc_index: usize = 0;
    let mut sticky_remaining: u32 = max_attempts.min(3);
    let mut last_err: Option<anyhow::Error> = None;

    for attempt in 0..max_attempts {
        if attempt > 0 {
            sleep(Duration::from_millis(interval_ms)).await;
        }

        let url = urls.get(rpc_index).copied().unwrap_or(urls[0]);
        let client = JsonRpcClient::connect(url);
        let account: AccountId = AccountId::from_str(contract_id)
            .context("Invalid contract ID")?;

        let result = client
            .call(methods::query::RpcQueryRequest {
                block_reference: BlockReference::latest(),
                request: near_primitives::views::QueryRequest::CallFunction {
                    account_id:   account,
                    method_name:  "get_sign_result".into(),
                    args:         serde_json::to_vec(&json!({ "request_id": request_id }))
                                      .unwrap().into(),
                },
            })
            .await;

        match result {
            Ok(resp) => {
                if let QueryResponseKind::CallResult(call_result) = resp.kind {
                    mark_rpc_success(url);
                    let value: serde_json::Value =
                        serde_json::from_slice(&call_result.result)
                            .context("Failed to parse get_sign_result response")?;

                    if let Some(sig) = extract_signature(&value) {
                        return Ok(sig);
                    }
                    if value.get("ok").and_then(|v| v.as_bool()) == Some(false) {
                        let error = value.get("error")
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown MPC signing error");
                        bail!("MPC signing failed: {error}");
                    }

                    // null / pending — keep sticky briefly then rotate
                    if sticky_remaining > 0 {
                        sticky_remaining = sticky_remaining.saturating_sub(1);
                    } else {
                        rpc_index = (rpc_index + 1) % urls.len();
                        sticky_remaining = (max_attempts - attempt - 1).min(2);
                    }
                }
            }
            Err(e) => {
                let msg = e.to_string();
                mark_rpc_failure(url, &msg);
                last_err = Some(anyhow::anyhow!("{msg}"));

                let cls = classify_rpc_error(&msg);
                tracing::warn!("NEAR RPC {url} poll attempt {attempt} failed (class={:?}): {msg}", cls);
                if cls == RpcErrorClass::RateLimited || cls == RpcErrorClass::Timeout || cls == RpcErrorClass::Transport {
                    rpc_index = (rpc_index + 1) % urls.len();
                    sticky_remaining = (max_attempts - attempt - 1).min(2);
                }
            }
        }

        if attempt > 0 && attempt % 10 == 0 {
            tracing::warn!(
                "poll_sign_result still no visible result after {attempt} attempts (request_id={request_id}, rpc_index={rpc_index})"
            );
        }
    }

    if let Some(e) = last_err {
        bail!("MPC signing timed out after {max_attempts} attempts (last_error={})", e);
    }
    bail!("MPC signing timed out after {max_attempts} attempts")
}

fn is_valid_sig_len(len: usize) -> bool {
    len == 64 || len == 65
}

/// Extract raw 64-byte/65-byte signature or payload from a get_sign_result response.
/// Handles `{ ok: true, payload: base64 }`, arrays, `{ signature: [...] }`, hex/base64 strings.
fn extract_signature(val: &serde_json::Value) -> Option<Vec<u8>> {
    if val.is_null() {
        return None;
    }

    // { ok: true, payload: "<base64>" } — primary TypeScript SignResult format
    if val.get("ok").and_then(|v| v.as_bool()) == Some(true) {
        if let Some(payload_b64) = val.get("payload").and_then(|v| v.as_str()) {
            if let Ok(payload_bytes) = base64::engine::general_purpose::STANDARD.decode(payload_b64) {
                if let Ok(inner) = serde_json::from_slice::<serde_json::Value>(&payload_bytes) {
                    if let Some(sig) = extract_signature(&inner) {
                        return Some(sig);
                    }
                }
                if is_valid_sig_len(payload_bytes.len()) {
                    return Some(payload_bytes);
                }
            }
        }
    }

    // Array of u8
    if let Some(arr) = val.as_array() {
        let bytes: Option<Vec<u8>> = arr.iter()
            .map(|v| v.as_u64().map(|n| n as u8))
            .collect();
        if let Some(b) = bytes { if is_valid_sig_len(b.len()) { return Some(b); } }
    }

    // { signature: [...] }
    if let Some(sig) = val.get("signature") {
        return extract_signature(sig);
    }

    // { signature_hex: "..." }
    if let Some(hex_str) = val.get("signature_hex").and_then(|v| v.as_str()) {
        if let Ok(b) = hex::decode(hex_str.strip_prefix("0x").unwrap_or(hex_str)) {
            if is_valid_sig_len(b.len()) { return Some(b); }
        }
    }

    // hex or base64 string
    if let Some(s) = val.as_str() {
        let s = s.strip_prefix("0x").unwrap_or(s);
        if let Ok(b) = hex::decode(s) { if is_valid_sig_len(b.len()) { return Some(b); } }
        if let Ok(b) = base64::engine::general_purpose::STANDARD.decode(s) {
            if is_valid_sig_len(b.len()) { return Some(b); }
        }
    }

    None
}

/// Extract request_id from the execution outcome logs.
pub fn extract_request_id(outcome: &FinalExecutionOutcomeView) -> Option<String> {
    for receipt in &outcome.receipts_outcome {
        for log in &receipt.outcome.logs {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(log) {
                if let Some(id) = v.get("request_id").and_then(|v| v.as_str()) {
                    return Some(id.to_string());
                }
            }
            if let Some(id) = log.strip_prefix("request_id: ") {
                return Some(id.trim().to_string());
            }
        }
    }
    for log in &outcome.transaction_outcome.outcome.logs {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(log) {
            if let Some(id) = v.get("request_id").and_then(|v| v.as_str()) {
                return Some(id.to_string());
            }
        }
    }
    None
}
