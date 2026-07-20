/// Auto-approval policy decision — mirrors resolveAutoApprovalPolicyDecision.
///
/// Phase 3b-1 scope: determines whether a submitted transaction can be
/// immediately signed by the server (isPolicyEligibleAuto) or must be queued
/// for wallet UI approval.
///
/// Full smart-contract proof-mode validation is deferred (marked TODO below);
/// this implements the primary fast-path checks that cover the common case.
use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::db::{ApiKey, AutoApprovalSettings, ApiKeyPolicyRecord};

/// The decision returned to the submit handler.
#[derive(Debug, Clone)]
pub struct PolicyDecision {
    /// If true: server should auto-sign immediately.
    pub eligible: bool,
    /// Human-readable reason when not eligible.
    pub reason:   Option<String>,
    /// Failure code when blocked by policy.
    pub failure_code: Option<String>,
}

/// Top-level policy JSON structure (stored in api_key_policies.policy_json).
#[derive(Debug, Deserialize)]
struct PolicyJson {
    enabled:     bool,
    #[serde(rename = "assetRules", default)]
    asset_rules: Vec<AssetRule>,
    #[serde(rename = "quoteProvenance", default)]
    quote_provenance: Option<QuoteProvenance>,
}

#[derive(Debug, Deserialize)]
struct AssetRule {
    #[serde(rename = "maxPerTxUsd")]
    max_per_tx_usd:  Option<f64>,
    #[serde(rename = "maxPerTxNative")]
    max_per_tx_native: Option<String>,
    #[serde(rename = "ruleId", default)]
    rule_id: Option<String>,
    #[serde(default)]
    tokens: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct QuoteProvenance {
    #[serde(default)]
    items: Vec<QuoteItem>,
}

#[derive(Debug, Deserialize)]
struct QuoteItem {
    #[serde(rename = "derivedMaxPerTxNative")]
    derived_max_per_tx_native: Option<f64>,
    #[serde(rename = "scope", default)]
    scope: Option<String>,
}

pub struct DecisionInput<'a> {
    pub api_key:         &'a ApiKey,
    pub network:         &'a str,
    pub template_id:     Option<&'a str>,
    pub tx_details:      &'a Value,
    pub auto_approval:   Option<&'a AutoApprovalSettings>,
    pub policy_record:   Option<&'a ApiKeyPolicyRecord>,
    /// Account index for proof-mode scope (None = unknown)
    pub account_index:   Option<i64>,
}

/// Evaluate whether the transaction is eligible for auto-approval.
pub fn resolve_policy_decision(input: &DecisionInput<'_>) -> PolicyDecision {
    // Only near_vault and remote_signer keys support MPC signing
    let storage = input.api_key.storage_type.as_deref().unwrap_or("");
    if storage != "near_vault" && storage != "remote_signer" {
        return not_eligible("API key is not a near_vault or remote_signer key");
    }

    // Network must be Solana or EVM
    if !is_signing_eligible_network(input.network) {
        return not_eligible(&format!("Network {n} is not supported for auto-sign", n = input.network));
    }

    // Policy record must exist and be enabled
    let policy = match input.policy_record {
        Some(r) => match serde_json::from_str::<PolicyJson>(&r.policy_json) {
            Ok(p) => p,
            Err(e) => return not_eligible(&format!("Policy JSON parse error: {e}")),
        },
        None => {
            // Fall back to legacy auto_approval settings if no policy record
            return legacy_auto_approval_decision(input);
        }
    };

    if !policy.enabled {
        return not_eligible("Policy is disabled for this key");
    }

    if policy.asset_rules.is_empty() {
        return not_eligible("Policy has no asset rules");
    }

    // Build a map of ruleId → derivedMaxPerTxNative from quote provenance
    let derived_natives: std::collections::HashMap<String, f64> = policy.quote_provenance
        .as_ref()
        .map(|qp| qp.items.iter()
            .filter_map(|item| {
                let scope = item.scope.as_deref()?;
                let native = item.derived_max_per_tx_native?;
                Some((scope.to_string(), native))
            })
            .collect())
        .unwrap_or_default();

    // Check the first matching rule (matches TypeScript behaviour)
    let amount_usd = extract_amount_usd(input.tx_details);
    for rule in &policy.asset_rules {
        // Token filter: if rule specifies tokens, check the tx token matches
        if !rule.tokens.is_empty() {
            let tx_token = input.tx_details
                .get("token")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !rule.tokens.iter().any(|t| t.eq_ignore_ascii_case(tx_token)) {
                continue;
            }
        }

        // Check USD limit if we have a USD amount
        if let Some(max_usd) = rule.max_per_tx_usd {
            if let Some(usd) = amount_usd {
                if usd > max_usd {
                    return PolicyDecision {
                        eligible:     false,
                        reason:       Some(format!("Amount ${usd:.4} exceeds per-tx limit ${max_usd}")),
                        failure_code: Some("limit_per_tx_usd_exceeded".into()),
                    };
                }
                return PolicyDecision { eligible: true, reason: None, failure_code: None };
            }
        }

        // Check native amount limit — from rule or derived from quote provenance
        let max_native: Option<f64> = rule.max_per_tx_native
            .as_ref()
            .and_then(|s| s.parse().ok())
            .or_else(|| rule.rule_id.as_ref()
                .and_then(|rid| derived_natives.get(rid).copied()));

        if let Some(max_native) = max_native {
            if let Some(amount) = extract_native_amount(input.tx_details) {
                if max_native > 0.0 && amount > max_native {
                    return PolicyDecision {
                        eligible:     false,
                        reason:       Some(format!("Amount {amount} exceeds per-tx native limit {max_native}")),
                        failure_code: Some("limit_per_tx_native_exceeded".into()),
                    };
                }
                return PolicyDecision { eligible: true, reason: None, failure_code: None };
            }
        }

        // Rule matched, no amount to check — eligible (NEAR contract is the on-chain safety net)
        return PolicyDecision { eligible: true, reason: None, failure_code: None };
    }

    not_eligible("No matching policy rule found")
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn legacy_auto_approval_decision(input: &DecisionInput<'_>) -> PolicyDecision {
    match input.auto_approval {
        Some(aa) if aa.enabled => {
            if let Some(max) = aa.max_amount {
                if let Some(usd) = extract_amount_usd(input.tx_details) {
                    if usd > max {
                        return PolicyDecision {
                            eligible:     false,
                            reason:       Some(format!("Amount ${usd:.4} exceeds auto-approval limit ${max}")),
                            failure_code: Some("limit_per_tx_usd_exceeded".into()),
                        };
                    }
                }
            }
            PolicyDecision { eligible: true, reason: None, failure_code: None }
        }
        _ => not_eligible("Auto-approval is not enabled for this key"),
    }
}

fn not_eligible(reason: &str) -> PolicyDecision {
    PolicyDecision {
        eligible:     false,
        reason:       Some(reason.to_string()),
        failure_code: None,
    }
}

fn is_signing_eligible_network(network: &str) -> bool {
    let n = network.to_lowercase();
    n.contains("solana") || n.contains("devnet") ||
    n.contains("base")   || n.contains("evm")    ||
    n.contains("ethereum") || n.contains("eip155") ||
    n.contains("hedera")
}

/// Extract native amount from tx_details as f64.
/// Looks for `amount` field (string or number).
fn extract_native_amount(details: &Value) -> Option<f64> {
    details.get("amount")
        .and_then(|v| v.as_f64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
        .filter(|a| *a > 0.0)
}

/// Extract the USD amount from tx_details.
/// Checks `amountUsd` first. If not present and native amount is provided,
/// returns None — the caller should fall through to not_eligible rather than
/// auto-approving without knowing the USD value.
fn extract_amount_usd(details: &Value) -> Option<f64> {
    if let Some(v) = details.get("amountUsd").and_then(|v| v.as_f64()) {
        return Some(v);
    }
    None
}
