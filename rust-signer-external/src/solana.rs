/// Solana transaction building and broadcast for the external signer.
/// Adapted from rust-api/src/network/solana.rs.
use anyhow::{bail, Context, Result};
use solana_rpc_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    pubkey::Pubkey,
    signature::Signature,
    transaction::Transaction,
};
use std::str::FromStr;

fn rpc_url(network: &str) -> &'static str {
    if network.to_lowercase().contains("mainnet") {
        "https://solana.publicnode.com"
    } else {
        "https://api.devnet.solana.com"
    }
}

/// Build the serialized Solana message bytes from templateId + txDetails.
pub async fn build_transaction_bytes(
    template_id: &str,
    tx_details:  &serde_json::Value,
    public_key:  &str,
    network:     &str,
) -> Result<Vec<u8>> {
    match template_id {
        "native_transfer_v1" | "sol_native_transfer_v1" => {
            build_sol_transfer_message(tx_details, public_key, network).await
        }
        "spl_transfer_v1" | "solana_usdc_transfer_v1" => {
            build_spl_transfer_message(tx_details, public_key, network).await
        }
        other => bail!("Unsupported Solana template: {other}"),
    }
}

/// Attach MPC signature to message bytes and broadcast. Returns tx hash.
pub async fn broadcast(
    tx_bytes:  &[u8],
    sig_bytes: &[u8; 64],
    network:   &str,
) -> Result<String> {
    let client = RpcClient::new_with_commitment(
        rpc_url(network).to_string(),
        CommitmentConfig::confirmed(),
    );

    let message = bincode::deserialize::<solana_sdk::message::Message>(tx_bytes)
        .context("Failed to deserialize Solana message")?;

    let signature = Signature::from(*sig_bytes);
    let signed_tx = Transaction {
        signatures: vec![signature],
        message,
    };

    let sig = client
        .send_transaction(&signed_tx)
        .await
        .context("Solana broadcast failed")?;

    Ok(sig.to_string())
}

// ── Transaction builders ─────────────────────���────────────────────────────────

async fn build_sol_transfer_message(
    details:  &serde_json::Value,
    from_str: &str,
    network:  &str,
) -> Result<Vec<u8>> {
    use solana_sdk::{message::Message, system_instruction};

    let from = Pubkey::from_str(from_str).context("Invalid from pubkey")?;
    let to_str = details.get("toPublicKey")
        .or_else(|| details.get("to"))
        .and_then(|v| v.as_str())
        .context("Missing toPublicKey")?;
    let to = Pubkey::from_str(to_str).context("Invalid to pubkey")?;

    let lamports = extract_lamports(details).context("Missing or invalid amount")?;

    let client = RpcClient::new(rpc_url(network).to_string());
    let recent_blockhash = client
        .get_latest_blockhash()
        .await
        .context("Failed to get Solana blockhash")?;

    let ix  = system_instruction::transfer(&from, &to, lamports);
    let msg = Message::new_with_blockhash(&[ix], Some(&from), &recent_blockhash);

    Ok(msg.serialize())
}

async fn build_spl_transfer_message(
    details:  &serde_json::Value,
    from_str: &str,
    network:  &str,
) -> Result<Vec<u8>> {
    use solana_sdk::message::Message;
    use spl_token::instruction::transfer_checked;
    use spl_associated_token_account::get_associated_token_address;

    let from_owner = Pubkey::from_str(from_str).context("Invalid from pubkey")?;
    let to_str = details.get("toPublicKey")
        .or_else(|| details.get("to"))
        .and_then(|v| v.as_str())
        .context("Missing toPublicKey")?;
    let to_owner = Pubkey::from_str(to_str).context("Invalid to pubkey")?;

    let mint_str = details.get("mint")
        .or_else(|| details.get("tokenMint"))
        .and_then(|v| v.as_str())
        .context("Missing mint address")?;
    let mint = Pubkey::from_str(mint_str).context("Invalid mint pubkey")?;

    let decimals = details.get("decimals")
        .and_then(|v| v.as_u64())
        .unwrap_or(6) as u8;

    let amount = details.get("atomicAmount")
        .and_then(|v| v.as_u64())
        .or_else(|| {
            let human = details.get("amount").and_then(|v| v.as_f64())?;
            Some((human * 10f64.powi(decimals as i32)) as u64)
        })
        .context("Missing amount")?;

    let source_ata = get_associated_token_address(&from_owner, &mint);
    let dest_ata   = get_associated_token_address(&to_owner,   &mint);

    let client = RpcClient::new(rpc_url(network).to_string());
    let recent_blockhash = client.get_latest_blockhash().await
        .context("Failed to get Solana blockhash")?;

    let ix = transfer_checked(
        &spl_token::id(),
        &source_ata,
        &mint,
        &dest_ata,
        &from_owner,
        &[],
        amount,
        decimals,
    )?;

    let msg = Message::new_with_blockhash(&[ix], Some(&from_owner), &recent_blockhash);
    Ok(msg.serialize())
}

fn extract_lamports(details: &serde_json::Value) -> Option<u64> {
    if let Some(l) = details.get("lamports").and_then(|v| v.as_u64()) {
        return Some(l);
    }
    let sol = details.get("amount").and_then(|v| {
        v.as_f64().or_else(|| v.as_str().and_then(|s| s.parse().ok()))
    })?;
    Some((sol * 1_000_000_000.0) as u64)
}
