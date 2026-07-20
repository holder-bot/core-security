/// Local Axum server on localhost:9090.
///
/// Exposes the same API as the safu server so agents don't need code changes —
/// just point the base URL to http://localhost:9090.
use anyhow::Result;
use axum::{extract::State, http::HeaderMap, routing::{get, post}, Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{net::SocketAddr, sync::Arc};
use tower_http::cors::{Any, CorsLayer};
use zeroize::Zeroizing;

use crate::{config::Config, identity::SignerIdentity, sign_pipeline};

// ── Shared state ──────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct ServerState {
    pub config: Arc<Config>,
    pub client: reqwest::Client,
}

// ── Request / Response ────────────────────────────────────────────────────────

/// Same fields as the server's SubmitBody — agent sends this to localhost:9090.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SubmitBody {
    // Auth
    key_public_id: Option<String>,
    key_secret:    Option<String>,

    // Transaction
    transaction_type: Option<String>,
    details:          Option<Value>,
    description:      Option<String>,
    context:          Option<Value>,
    network:          Option<String>,
    /// Passphrase is accepted here (local only), never forwarded to server.
    passphrase:       Option<String>,
    idempotency_key:  Option<String>,
    template_id:      Option<String>,
    template_params:  Option<Value>,

    // Flattened convenience fields
    from_public_key: Option<String>,
    to_public_key:   Option<String>,
    amount:          Option<Value>,
    token:           Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SubmitResponse {
    transaction_id:  String,
    status:          String,
    message:         String,
    network_tx_hash: Option<String>,
}

// ── Info handler (for browser-initiated pairing) ──────────────────────────────

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SignerInfo {
    initialized: bool,
    public_key:  Option<String>,
}

async fn info_handler() -> Json<SignerInfo> {
    let path = SignerIdentity::default_path();
    match SignerIdentity::load(&path) {
        Ok(id) => Json(SignerInfo {
            initialized: true,
            public_key:  Some(id.public_key_b64()),
        }),
        Err(_) => Json(SignerInfo {
            initialized: false,
            public_key:  None,
        }),
    }
}

// ── Handler ───────────────────────────────────────────────────────────────────

async fn submit_handler(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Json(mut body): Json<SubmitBody>,
) -> Result<Json<SubmitResponse>, (axum::http::StatusCode, Json<Value>)> {
    macro_rules! err {
        ($code:expr, $msg:expr) => {
            return Err(($code, Json(serde_json::json!({ "error": $msg }))))
        };
    }

    // Extract passphrase before forwarding — it must not leave this machine
    let passphrase = Zeroizing::new(body.passphrase.take().unwrap_or_default());

    // Determine session token: forward from Authorization header if present,
    // otherwise obtain from the server using the key credentials.
    let token = match get_session_token(&state, &headers, &body.key_public_id, &body.key_secret).await {
        Ok(t) => t,
        Err(e) => err!(axum::http::StatusCode::UNAUTHORIZED, e.to_string()),
    };

    // Build the forwarding body (same JSON, add signingMode, strip passphrase)
    let mut forward = serde_json::json!({
        "transactionType": body.transaction_type,
        "details":         body.details,
        "description":     body.description,
        "context":         body.context,
        "network":         body.network,
        "idempotencyKey":  body.idempotency_key,
        "templateId":      body.template_id,
        "templateParams":  body.template_params,
        "fromPublicKey":   body.from_public_key,
        "toPublicKey":     body.to_public_key,
        "amount":          body.amount,
        "token":           body.token,
        "signingMode":     "external",
    });
    // Remove null fields to keep the request clean
    if let Some(obj) = forward.as_object_mut() {
        obj.retain(|_, v| !v.is_null());
    }

    let network = body.network.clone()
        .unwrap_or_else(|| "solana-devnet".into());

    // Forward to server
    let server_resp = state.client
        .post(format!("{}/api/agent/transaction/submit", state.config.server_url))
        .bearer_auth(&token)
        .json(&forward)
        .send()
        .await
        .map_err(|e| (
            axum::http::StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({ "error": format!("Server request failed: {e}") }))
        ))?;

    if !server_resp.status().is_success() {
        let status = server_resp.status();
        let body_text = server_resp.text().await.unwrap_or_default();
        let code = axum::http::StatusCode::from_u16(status.as_u16())
            .unwrap_or(axum::http::StatusCode::BAD_GATEWAY);
        return Err((code, Json(serde_json::from_str(&body_text)
            .unwrap_or_else(|_| serde_json::json!({ "error": body_text })))));
    }

    let server_data: sign_pipeline::SubmitServerResponse = server_resp
        .json()
        .await
        .map_err(|e| (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": format!("Failed to parse server response: {e}") }))
        ))?;

    let tx_id = server_data.transaction_id.clone();

    // Run the local signing pipeline
    let result = sign_pipeline::run(
        &state.config.server_url,
        &token,
        server_data,
        passphrase,
        &state.config.server_rsa_pem,
        &network,
    ).await
    .map_err(|e| (
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({ "error": format!("Signing failed: {e}"), "transactionId": tx_id }))
    ))?;

    Ok(Json(SubmitResponse {
        transaction_id:  result.transaction_id,
        status:          result.status,
        message:         "Transaction signed and broadcast locally".into(),
        network_tx_hash: Some(result.network_tx_hash),
    }))
}

// ── Session helper ────────────────────────────────────────────────────────────

async fn get_session_token(
    state:          &ServerState,
    headers:        &HeaderMap,
    key_public_id:  &Option<String>,
    key_secret:     &Option<String>,
) -> anyhow::Result<String> {
    // Prefer Authorization header forwarded from agent
    if let Some(v) = headers.get(axum::http::header::AUTHORIZATION) {
        if let Ok(s) = v.to_str() {
            if let Some(tok) = s.strip_prefix("Bearer ") {
                return Ok(tok.to_string());
            }
        }
    }

    // Fall back to body credentials or config credentials
    let kid = key_public_id.as_deref()
        .or_else(|| if !state.config.key_public_id.is_empty() { Some(&state.config.key_public_id) } else { None })
        .ok_or_else(|| anyhow::anyhow!("No API key ID — set in config or pass in request"))?;
    let secret = key_secret.as_deref()
        .or_else(|| if !state.config.key_secret.is_empty() { Some(&state.config.key_secret) } else { None })
        .ok_or_else(|| anyhow::anyhow!("No API key secret — set in config or pass in request"))?;

    let path = "/api/agent/session/from-key";
    let url = format!("{}{path}", state.config.server_url);
    let body = serde_json::json!({ "keyPublicId": kid });
    let body_bytes = serde_json::to_vec(&body)
        .map_err(|e| anyhow::anyhow!("JSON serialize failed: {e}"))?;

    let auth_header = crate::hmac_auth::build_hmac_auth_header(kid, secret, "POST", path, &body_bytes);

    let resp = state.client
        .post(&url)
        .header("Authorization", auth_header)
        .header("Content-Type", "application/json")
        .body(body_bytes)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("Session request failed: {e}"))?;

    let data: serde_json::Value = resp.json().await
        .map_err(|e| anyhow::anyhow!("Session response parse failed: {e}"))?;

    data["sessionToken"].as_str()
        .or_else(|| data["token"].as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow::anyhow!("Server did not return a session token"))
}

// ── Server start ──────────────────────────────────────────────────────────────

pub async fn run(config: Config) -> Result<()> {
    let port = config.local_port;
    let state = ServerState {
        config: Arc::new(config),
        client: reqwest::Client::new(),
    };

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/api/signer/info", get(info_handler))
        .route("/api/agent/transaction/submit", post(submit_handler))
        .layer(cors)
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    tracing::info!("external-signer listening on http://{addr}");
    println!("  external-signer ready on http://localhost:{port}");
    println!("  Point your agent's base URL here. Ctrl+C to stop.");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
