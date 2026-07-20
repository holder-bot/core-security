use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hex;
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::collections::LookupMap;
use near_sdk::json_types::{Base64VecU8, U128};
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::{
    bs58, env, near_bindgen, require, serde_json, AccountId, Gas, PanicOnDefault, Promise,
    PromiseResult, PublicKey,
};

const MAX_PAYLOAD_BYTES: usize = 16 * 1024;
const GAS_FOR_SIGN: Gas = Gas(100_000_000_000_000); // 100 Tgas — Secp256k1 signing needs more than Eddsa
const GAS_FOR_CALLBACK: Gas = Gas(10_000_000_000_000); // 10 Tgas for on_sign_complete
const NATIVE_TOKEN: &str = "native";
const MPC_METHOD_SIGN_RAW: &str = "sign";
const MPC_METHOD_SIGN_TEMPLATE: &str = "sign_template";
const POLICY_MEMO_PREFIX: &str = "policy:";
const POLICY_MEMO_SEPARATOR: char = '|';
const SOLANA_SYSTEM_PROGRAM_ID: &str = "11111111111111111111111111111111";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde", rename_all = "camelCase")]
struct ContractPolicyInputMemo {
    pub template_id: String,
    pub template_params: serde_json::Value,
    pub policy_snapshot: Option<ContractPolicySnapshotMemo>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde", rename_all = "camelCase")]
struct ContractPolicySnapshotMemo {
    pub template_allowlist: Vec<String>,
    pub destination_allowlist: Vec<String>,
    pub rule: Option<ContractPolicyRuleMemo>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde", rename_all = "camelCase")]
struct ContractPolicyRuleMemo {
    pub rule_id: String,
    pub asset_type: String,
    pub asset_id: String,
    pub max_per_tx_native: Option<serde_json::Value>,
    pub max_per_period_native: Option<serde_json::Value>,
    pub period_seconds: Option<u64>,
    pub max_tx_count_per_period: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ParsedSolanaNativeTransfer {
    pub from_public_key: String,
    pub destination: String,
    pub lamports: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ParsedNearNativeTransfer {
    pub from_implicit: String,
    pub destination: String,
    pub yocto: u128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ParsedNearFtTransfer {
    pub from_implicit: String,
    pub ft_contract: String,
    pub destination: String,
    /// Raw NEP-141 amount (smallest units).
    pub amount: u128,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize, Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub enum Chain {
    Solana,
    Evm,
    Bitcoin,
    /// NEAR implicit account MPC (Eddsa). Same curve/domain as Solana for v1.
    Near,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize, Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub struct ChainPaths {
    pub chain: Chain,
    pub paths: Vec<String>,
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(crate = "near_sdk::serde")]
pub struct SignRequest {
    pub chain: Chain,
    pub derivation_path: String,
    pub payload: Base64VecU8,
    pub memo: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize, Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub enum TxKind {
    SolanaNative,
    SolanaSpl,
    SolanaToken2022,
    EvmNative,
    EvmErc20,
    BitcoinSend,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize, Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub struct TxTemplate {
    pub template_id: String,
    pub chain: Chain,
    pub kind: TxKind,
    pub allowed_tokens: Option<Vec<String>>,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize, Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub struct TemplateSignRequest {
    pub template_id: String,
    pub chain: Chain,
    pub derivation_path: String,
    pub to: String,
    pub amount: U128,
    pub token_contract: Option<String>,
    pub symbol: Option<String>,
    pub evm_chain_id: Option<String>,
    pub memo: Option<String>,
    /// EVM transaction parameters (required for EVM chains).
    /// The contract builds the full EIP-1559 tx RLP from these + template params.
    pub evm_tx_params: Option<EvmTxParams>,
}

/// Mechanical EVM transaction fields provided by the server.
/// These cannot redirect funds — they only affect gas/nonce.
#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize, Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub struct EvmTxParams {
    pub nonce: u64,
    pub gas_limit: u64,
    pub max_fee_per_gas: U128,
    pub max_priority_fee_per_gas: U128,
    /// ABI-encoded calldata hex. For native transfers, omit or set empty.
    pub data: Option<String>,
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(crate = "near_sdk::serde")]
pub struct SignResult {
    pub request_id: String,
    pub ok: bool,
    pub payload: Option<Base64VecU8>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize, Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde", rename_all = "camelCase")]
pub struct ApiKeyPolicyV1 {
    pub version: String,
    pub template_id: String,
    pub asset_type: String,
    pub asset_id: Option<String>,
    pub max_per_tx_native: Option<String>,
    pub max_per_period_native: Option<String>,
    pub period_seconds: Option<u64>,
    pub max_tx_count_per_period: Option<u64>,
    pub allow_destinations: Vec<String>,
    pub period_start_unix_seconds: Option<u64>,
    pub spent_this_period_native: Option<String>,
    pub tx_count_this_period: Option<u64>,
}

#[derive(
    Clone, Debug, Default, PartialEq, Eq, BorshDeserialize, BorshSerialize, Serialize, Deserialize,
)]
#[serde(crate = "near_sdk::serde", rename_all = "camelCase")]
pub struct PolicyManagerGrant {
    pub can_manage_policies: bool,
    pub can_manage_self_policy: bool,
}

#[derive(BorshDeserialize, BorshSerialize)]
struct AllowedPaths {
    entries: Vec<ChainPaths>,
}

impl AllowedPaths {
    fn new(paths: Vec<ChainPaths>) -> Self {
        Self { entries: paths }
    }

    fn is_allowed(&self, chain: &Chain, derivation_path: &str) -> bool {
        if self.entries.iter().any(|entry| {
            &entry.chain == chain && entry.paths.iter().any(|p| p == derivation_path)
        }) {
            return true;
        }
        // Migration: Near MPC shares Ed25519 paths with Solana until Near paths are registered.
        if chain == &Chain::Near {
            return self.entries.iter().any(|entry| {
                entry.chain == Chain::Solana && entry.paths.iter().any(|p| p == derivation_path)
            });
        }
        false
    }
}

fn key_type_for_chain(chain: &Chain) -> &'static str {
    match chain {
        Chain::Solana | Chain::Near => "Eddsa",
        Chain::Evm => "Ecdsa",
        Chain::Bitcoin => "Ecdsa",
    }
}

fn domain_id_for_chain(chain: &Chain) -> u8 {
    match chain {
        // Near MPC uses Eddsa domain 1 — same as Solana until a Near-specific domain exists.
        Chain::Solana | Chain::Near => 1,
        Chain::Evm => 0,
        Chain::Bitcoin => 0,
    }
}

fn mpc_sign_payload_bytes(chain: &Chain, payload: &[u8]) -> Vec<u8> {
    if chain == &Chain::Near {
        use sha2::{Digest, Sha256};
        Sha256::digest(payload).to_vec()
    } else {
        payload.to_vec()
    }
}

/// Parsed `x402-eip3009:{json}` memo for EIP-712 TransferWithAuthorization signing.
struct Eip3009MemoParts {
    from: String,
    token: String,
    valid_after: u64,
    valid_before: u64,
    nonce: [u8; 32],
    domain_name: String,
    domain_version: String,
}

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize, PanicOnDefault)]
pub struct Contract {
    owner_id: AccountId,
    mpc_contract_id: AccountId,
    /// Keyed by "{account_id}|{public_key}"
    subkeys: LookupMap<String, AllowedPaths>,
    /// Index of subkeys per account for listing
    subkey_index: LookupMap<AccountId, Vec<String>>,
    /// Keyed by "{chain}|{template_id}"
    templates: LookupMap<String, TxTemplate>,
    /// Keyed by "{chain}|{token_contract_or_native}"
    token_caps: LookupMap<String, u128>,
    /// Keyed by request_id
    sign_results: LookupMap<String, SignResult>,
    /// Keyed by "{account_id}|{public_key}"
    policy_managers: LookupMap<String, PolicyManagerGrant>,
    /// Keyed by "{account_id}|{public_key}"
    api_key_policies: LookupMap<String, ApiKeyPolicyV1>,
}

#[derive(BorshDeserialize, BorshSerialize)]
struct ContractV0 {
    owner_id: AccountId,
    mpc_contract_id: AccountId,
    subkeys: LookupMap<String, AllowedPaths>,
    subkey_index: LookupMap<AccountId, Vec<String>>,
    templates: LookupMap<String, TxTemplate>,
    token_caps: LookupMap<String, u128>,
    sign_results: LookupMap<String, SignResult>,
}

#[derive(BorshDeserialize, BorshSerialize)]
struct ContractV1 {
    owner_id: AccountId,
    mpc_contract_id: AccountId,
    subkeys: LookupMap<String, AllowedPaths>,
    subkey_index: LookupMap<AccountId, Vec<String>>,
    templates: LookupMap<String, TxTemplate>,
    token_caps: LookupMap<String, u128>,
    sign_results: LookupMap<String, SignResult>,
    api_key_policies: LookupMap<String, ApiKeyPolicyV1>,
}

#[near_bindgen]
impl Contract {
    #[init]
    pub fn new(owner_id: AccountId, mpc_contract_id: AccountId) -> Self {
        require!(!env::state_exists(), "already initialized");
        Self {
            owner_id,
            mpc_contract_id,
            subkeys: LookupMap::new(b"s"),
            subkey_index: LookupMap::new(b"i"),
            templates: LookupMap::new(b"t"),
            token_caps: LookupMap::new(b"c"),
            sign_results: LookupMap::new(b"r"),
            policy_managers: LookupMap::new(b"g"),
            api_key_policies: LookupMap::new(b"p"),
        }
    }

    /// Migration helper for upgrades from the minimal stub (reinitializes collections).
    #[init(ignore_state)]
    pub fn migrate(owner_id: AccountId, mpc_contract_id: AccountId) -> Self {
        if let Some(old_state) = env::state_read::<ContractV1>() {
            return Self {
                owner_id: old_state.owner_id,
                mpc_contract_id: old_state.mpc_contract_id,
                subkeys: old_state.subkeys,
                subkey_index: old_state.subkey_index,
                templates: old_state.templates,
                token_caps: old_state.token_caps,
                sign_results: old_state.sign_results,
                policy_managers: LookupMap::new(b"g"),
                api_key_policies: old_state.api_key_policies,
            };
        }

        if let Some(old_state) = env::state_read::<ContractV0>() {
            return Self {
                owner_id: old_state.owner_id,
                mpc_contract_id: old_state.mpc_contract_id,
                subkeys: old_state.subkeys,
                subkey_index: old_state.subkey_index,
                templates: old_state.templates,
                token_caps: old_state.token_caps,
                sign_results: old_state.sign_results,
                policy_managers: LookupMap::new(b"g"),
                api_key_policies: LookupMap::new(b"p"),
            };
        }

        Self {
            owner_id,
            mpc_contract_id,
            subkeys: LookupMap::new(b"s"),
            subkey_index: LookupMap::new(b"i"),
            templates: LookupMap::new(b"t"),
            token_caps: LookupMap::new(b"c"),
            sign_results: LookupMap::new(b"r"),
            policy_managers: LookupMap::new(b"g"),
            api_key_policies: LookupMap::new(b"p"),
        }
    }

    /// Add a subkey for the caller with allowed derivation paths per chain.
    pub fn add_subkey(&mut self, public_key: PublicKey, derivation_paths: Vec<ChainPaths>) {
        self.assert_direct_call();
        // assert_direct_call() rejects cross-contract invocations and prevents relay/proxy attacks.
        // we already have the identity of the caller from the runtime environment via `#[near_bindgen]` macro
        let caller = env::predecessor_account_id();
        // NEAR runtime guarantees that `predecessor_account_id()` reflects the true transaction signer
        Self::validate_paths(&derivation_paths);
        let pk = Self::pk_to_string(&public_key);
        let storage_key = Self::compose_key(&caller, &pk);
        self.subkeys
            .insert(&storage_key, &AllowedPaths::new(derivation_paths.clone()));
        self.push_index(&caller, pk.clone());
        Self::log_event(
            "subkey_added",
            serde_json::json!({ "account_id": caller, "public_key": pk, "paths": derivation_paths }),
        );
    }

    /// Update derivation paths for an existing subkey (caller-scoped).
    pub fn set_subkey_paths(&mut self, public_key: PublicKey, derivation_paths: Vec<ChainPaths>) {
        self.assert_direct_call();
        let caller = env::predecessor_account_id();
        Self::validate_paths(&derivation_paths);
        let pk = Self::pk_to_string(&public_key);
        let storage_key = Self::compose_key(&caller, &pk);
        require!(self.subkeys.get(&storage_key).is_some(), "subkey not found");
        self.subkeys
            .insert(&storage_key, &AllowedPaths::new(derivation_paths.clone()));
        Self::log_event(
            "subkey_paths_set",
            serde_json::json!({ "account_id": caller, "public_key": pk, "paths": derivation_paths }),
        );
    }

    /// Remove a subkey for the caller.
    pub fn remove_subkey(&mut self, public_key: PublicKey) {
        self.assert_direct_call();
        let caller = env::predecessor_account_id();
        let pk = Self::pk_to_string(&public_key);
        let storage_key = Self::compose_key(&caller, &pk);
        require!(
            self.subkeys.remove(&storage_key).is_some(),
            "subkey not found"
        );
        self.drop_from_index(&caller, &pk);
        Self::log_event(
            "subkey_removed",
            serde_json::json!({ "account_id": caller, "public_key": pk }),
        );
    }

    /// List subkeys owned by the given account (view).
    pub fn list_subkeys(&self, account_id: AccountId) -> Vec<String> {
        self.subkey_index.get(&account_id).unwrap_or_default()
    }

    /// Get allowed derivation paths for a specific subkey owned by the caller.
    pub fn get_subkey_paths(&self, public_key: PublicKey) -> Option<Vec<ChainPaths>> {
        let caller = env::predecessor_account_id();
        let pk = Self::pk_to_string(&public_key);
        self.subkeys
            .get(&Self::compose_key(&caller, &pk))
            .map(|p| p.entries)
    }

    /// Main entry: request an MPC signature. Must be signed by a registered subkey of the caller.
    #[payable]
    pub fn request_sign(&mut self, request: SignRequest) -> Promise {
        self.assert_direct_call();
        require!(!request.payload.0.is_empty(), "invalid payload size");
        require!(
            request.payload.0.len() <= MAX_PAYLOAD_BYTES,
            "payload too large"
        );
        Self::validate_path(&request.derivation_path);
        let caller = env::predecessor_account_id();
        let signer_pk = Self::pk_to_string(&env::signer_account_pk());
        let storage_key = Self::compose_key(&caller, &signer_pk);
        let allowed = self
            .subkeys
            .get(&storage_key)
            .unwrap_or_else(|| env::panic_str("unauthorized subkey"));
        require!(
            allowed.is_allowed(&request.chain, &request.derivation_path),
            "derivation path not allowed"
        );

        let SignRequest {
            chain,
            derivation_path,
            payload,
            memo,
        } = request;
        self.enforce_contract_policy_for_raw_request(
            &chain,
            &payload.0,
            memo.as_deref(),
            &caller,
            &signer_pk,
        );

        Self::log_event(
            "sign_request",
            serde_json::json!({
                "account_id": caller,
                "public_key": signer_pk,
                "chain": chain,
                "derivation_path": derivation_path,
                "memo": memo,
                "payload_len": payload.0.len()
            }),
        );

        let payload_hex = hex::encode(mpc_sign_payload_bytes(&chain, &payload.0));
        let key_type = key_type_for_chain(&chain);
        let signer_path = format!("{}:{}", caller, derivation_path);
        let args = serde_json::json!({
            "request": {
                "payload_v2": { key_type: payload_hex },
                "path": signer_path,
                "domain_id": domain_id_for_chain(&chain),
            }
        });

        Promise::new(self.mpc_contract_id.clone()).function_call(
            MPC_METHOD_SIGN_RAW.to_string(),
            args.to_string().into_bytes(),
            1,
            GAS_FOR_SIGN,
        )
    }

    /// Request an MPC signature with a request_id (stores result for polling).
    #[payable]
    pub fn request_sign_v2(&mut self, request_id: String, request: SignRequest) -> Promise {
        self.assert_direct_call();
        self.assert_new_request_id(&request_id);
        require!(!request.payload.0.is_empty(), "invalid payload size");
        require!(
            request.payload.0.len() <= MAX_PAYLOAD_BYTES,
            "payload too large"
        );
        Self::validate_path(&request.derivation_path);
        let caller = env::predecessor_account_id();
        let signer_pk = Self::pk_to_string(&env::signer_account_pk());
        let storage_key = Self::compose_key(&caller, &signer_pk);
        let allowed = self
            .subkeys
            .get(&storage_key)
            .unwrap_or_else(|| env::panic_str("unauthorized subkey"));
        require!(
            allowed.is_allowed(&request.chain, &request.derivation_path),
            "derivation path not allowed"
        );

        let SignRequest {
            chain,
            derivation_path,
            payload,
            memo,
        } = request;
        self.enforce_contract_policy_for_raw_request(
            &chain,
            &payload.0,
            memo.as_deref(),
            &caller,
            &signer_pk,
        );

        let payload_hex = hex::encode(mpc_sign_payload_bytes(&chain, &payload.0));
        let key_type = key_type_for_chain(&chain);
        let signer_path = format!("{}:{}", caller, derivation_path);
        let args = serde_json::json!({
            "request": {
                "payload_v2": { key_type: payload_hex },
                "path": signer_path,
                "domain_id": domain_id_for_chain(&chain),
            }
        });

        Promise::new(self.mpc_contract_id.clone())
            .function_call(
                MPC_METHOD_SIGN_RAW.to_string(),
                args.to_string().into_bytes(),
                1,
                GAS_FOR_SIGN,
            )
            .then(
                Promise::new(env::current_account_id()).function_call(
                    "on_sign_complete".to_string(),
                    serde_json::json!({ "request_id": request_id })
                        .to_string()
                        .into_bytes(),
                    0,
                    GAS_FOR_CALLBACK,
                ),
            )
    }

    /// Owner-only: set or update a template definition.
    pub fn set_template(&mut self, template: TxTemplate) {
        self.assert_owner();
        require!(!template.template_id.is_empty(), "template_id required");
        if let Some(tokens) = &template.allowed_tokens {
            for token in tokens {
                require!(!token.is_empty(), "empty token in allowlist");
            }
        }
        let key = Self::template_key(&template.chain, &template.template_id);
        self.templates.insert(&key, &template);
        Self::log_event("template_set", serde_json::json!({ "template": template }));
    }

    /// Owner-only: remove a template.
    pub fn remove_template(&mut self, chain: Chain, template_id: String) {
        self.assert_owner();
        let key = Self::template_key(&chain, &template_id);
        require!(self.templates.remove(&key).is_some(), "template not found");
        Self::log_event(
            "template_removed",
            serde_json::json!({ "chain": chain, "template_id": template_id }),
        );
    }

    /// Owner-only: set max amount cap for a token (or native).
    pub fn set_token_cap(
        &mut self,
        chain: Chain,
        token_contract: Option<String>,
        max_amount: U128,
    ) {
        self.assert_owner();
        let token = token_contract.unwrap_or_else(|| NATIVE_TOKEN.to_string());
        require!(!token.is_empty(), "token required");
        let key = Self::cap_key(&chain, &token);
        self.token_caps.insert(&key, &max_amount.0);
        Self::log_event(
            "token_cap_set",
            serde_json::json!({ "chain": chain, "token_contract": token, "max_amount": max_amount }),
        );
    }

    /// Owner-only: remove max amount cap.
    pub fn remove_token_cap(&mut self, chain: Chain, token_contract: Option<String>) {
        self.assert_owner();
        let token = token_contract.unwrap_or_else(|| NATIVE_TOKEN.to_string());
        let key = Self::cap_key(&chain, &token);
        require!(self.token_caps.remove(&key).is_some(), "cap not found");
        Self::log_event(
            "token_cap_removed",
            serde_json::json!({ "chain": chain, "token_contract": token }),
        );
    }

    pub fn get_template(&self, chain: Chain, template_id: String) -> Option<TxTemplate> {
        self.templates
            .get(&Self::template_key(&chain, &template_id))
    }

    pub fn get_token_cap(&self, chain: Chain, token_contract: Option<String>) -> Option<U128> {
        let token = token_contract.unwrap_or_else(|| NATIVE_TOKEN.to_string());
        self.token_caps
            .get(&Self::cap_key(&chain, &token))
            .map(U128)
    }

    /// Request a templated sign; enforces template + token caps before forwarding.
    pub fn request_template_sign(&self, request: TemplateSignRequest) -> Promise {
        self.assert_direct_call();
        require!(!request.template_id.is_empty(), "template_id required");
        require!(
            !request.derivation_path.is_empty(),
            "derivation_path required"
        );
        Self::validate_path(&request.derivation_path);
        require!(!request.to.is_empty(), "to required");

        let caller = env::predecessor_account_id();
        let signer_pk = Self::pk_to_string(&env::signer_account_pk());
        let storage_key = Self::compose_key(&caller, &signer_pk);
        let allowed = self
            .subkeys
            .get(&storage_key)
            .unwrap_or_else(|| env::panic_str("unauthorized subkey"));
        require!(
            allowed.is_allowed(&request.chain, &request.derivation_path),
            "derivation path not allowed"
        );

        let template = self
            .templates
            .get(&Self::template_key(&request.chain, &request.template_id))
            .unwrap_or_else(|| env::panic_str("template not found"));
        require!(template.chain == request.chain, "template chain mismatch");

        Self::validate_template_request(&template, &request);
        self.enforce_persisted_policy_for_template_request(
            &request.chain,
            &template,
            &request,
            &caller,
            &signer_pk,
        );

        let token_contract = request
            .token_contract
            .clone()
            .unwrap_or_else(|| NATIVE_TOKEN.to_string());
        let cap_key = Self::cap_key(&request.chain, &token_contract);
        if let Some(max_amount) = self.token_caps.get(&cap_key) {
            require!(request.amount.0 <= max_amount, "amount exceeds cap");
        }

        Self::log_event(
            "template_sign_request",
            serde_json::json!({
                "account_id": caller,
                "public_key": signer_pk,
                "template_id": request.template_id,
                "chain": request.chain,
                "kind": template.kind,
                "to": request.to,
                "amount": request.amount,
                "token_contract": request.token_contract,
                "symbol": request.symbol,
                "evm_chain_id": request.evm_chain_id,
                "memo": request.memo
            }),
        );

        let signer_path = format!("{}:{}", caller, request.derivation_path);
        let args = serde_json::json!({
            "request": {
                "caller": caller,
                "template_id": request.template_id,
                "chain": request.chain,
                "kind": template.kind,
                "derivation_path": signer_path,
                "to": request.to,
                "amount": request.amount,
                "token_contract": request.token_contract,
                "symbol": request.symbol,
                "evm_chain_id": request.evm_chain_id,
                "memo": request.memo,
            }
        });

        Promise::new(self.mpc_contract_id.clone()).function_call(
            MPC_METHOD_SIGN_TEMPLATE.to_string(),
            args.to_string().into_bytes(),
            1,
            GAS_FOR_SIGN,
        )
    }

    /// Request a templated sign with a request_id (stores result for polling).
    pub fn request_template_sign_v2(
        &mut self,
        request_id: String,
        request: TemplateSignRequest,
    ) -> Promise {
        self.assert_direct_call();
        self.assert_new_request_id(&request_id);
        require!(!request.template_id.is_empty(), "template_id required");
        require!(
            !request.derivation_path.is_empty(),
            "derivation_path required"
        );
        Self::validate_path(&request.derivation_path);
        require!(!request.to.is_empty(), "to required");

        let caller = env::predecessor_account_id();
        let signer_pk = Self::pk_to_string(&env::signer_account_pk());
        let storage_key = Self::compose_key(&caller, &signer_pk);
        let allowed = self
            .subkeys
            .get(&storage_key)
            .unwrap_or_else(|| env::panic_str("unauthorized subkey"));
        require!(
            allowed.is_allowed(&request.chain, &request.derivation_path),
            "derivation path not allowed"
        );

        let template = self
            .templates
            .get(&Self::template_key(&request.chain, &request.template_id))
            .unwrap_or_else(|| env::panic_str("template not found"));
        require!(template.chain == request.chain, "template chain mismatch");

        Self::validate_template_request(&template, &request);
        self.enforce_persisted_policy_for_template_request(
            &request.chain,
            &template,
            &request,
            &caller,
            &signer_pk,
        );

        let token_contract = request
            .token_contract
            .clone()
            .unwrap_or_else(|| NATIVE_TOKEN.to_string());
        let cap_key = Self::cap_key(&request.chain, &token_contract);
        if let Some(max_amount) = self.token_caps.get(&cap_key) {
            require!(request.amount.0 <= max_amount, "amount exceeds cap");
        }

        let signer_path = format!("{}:{}", caller, request.derivation_path);

        // For EVM chains: build the tx RLP locally, hash it, call standard MPC `sign`.
        // This avoids calling `sign_template` (which doesn't exist on the MPC contract).
        // Special case: x402 EIP-3009 — sign EIP-712 TransferWithAuthorization digest
        // (memo prefix `x402-eip3009:`) instead of an EIP-1559 tx hash.
        if request.chain == Chain::Evm {
            let chain_id: u64 = request.evm_chain_id
                .as_ref()
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(|| env::panic_str("evm_chain_id required and must be numeric"));

            let is_eip3009 = request
                .memo
                .as_deref()
                .map(|m| m.starts_with("x402-eip3009:"))
                .unwrap_or(false);
            let is_eip712_digest = request
                .memo
                .as_deref()
                .map(|m| m.starts_with("eip712-digest:"))
                .unwrap_or(false);
            let tx_hash = if is_eip712_digest {
                // Precomputed EIP-712 / EIP-191 digest (32 bytes) — Hyperliquid AcceptTerms, Permit2, personal_sign, …
                Self::parse_eip712_digest_memo(request.memo.as_deref())
                    .unwrap_or_else(|| env::panic_str("eip712_digest_memo_invalid"))
            } else if is_eip3009 {
                let eip3009 = Self::parse_eip3009_memo(request.memo.as_deref())
                    .unwrap_or_else(|| env::panic_str("eip3009_memo_invalid"));
                let pay_to = Self::parse_evm_address(&request.to);
                let token = Self::parse_evm_address(&eip3009.token);
                let from = Self::parse_evm_address(&eip3009.from);
                Self::build_eip3009_transfer_auth_hash(
                    &eip3009.domain_name,
                    &eip3009.domain_version,
                    chain_id,
                    &token,
                    &from,
                    &pay_to,
                    request.amount.0,
                    eip3009.valid_after,
                    eip3009.valid_before,
                    &eip3009.nonce,
                )
            } else {
                let evm_params = request.evm_tx_params
                    .unwrap_or_else(|| env::panic_str("evm_tx_params required for EVM template signing"));
                let to_addr = Self::parse_evm_address(&request.to);
                let value = request.amount.0;
                let data_bytes: Vec<u8> = match &evm_params.data {
                    Some(d) if !d.is_empty() => {
                        let hex_str = d.strip_prefix("0x").unwrap_or(d);
                        hex::decode(hex_str).unwrap_or_else(|_| env::panic_str("invalid evm_tx_params.data hex"))
                    }
                    _ => vec![],
                };
                Self::build_evm_tx_hash(
                    chain_id, evm_params.nonce,
                    evm_params.max_priority_fee_per_gas.0, evm_params.max_fee_per_gas.0,
                    evm_params.gas_limit, &to_addr, value, &data_bytes,
                )
            };
            let payload_hex = hex::encode(&tx_hash);

            Self::log_event("template_sign_evm_built", serde_json::json!({
                "request_id": request_id,
                "template_id": request.template_id,
                "chain_id": chain_id,
                "to": request.to,
                "value": request.amount,
                "tx_hash_hex": payload_hex,
                "eip3009": request.memo.as_deref().map(|m| m.starts_with("x402-eip3009:")).unwrap_or(false),
                "eip712_digest": request.memo.as_deref().map(|m| m.starts_with("eip712-digest:")).unwrap_or(false),
            }));

            let key_type = key_type_for_chain(&request.chain);
            let domain_id = domain_id_for_chain(&request.chain);
            let args = serde_json::json!({
                "request": {
                    "payload_v2": { (key_type): payload_hex },
                    "path": signer_path,
                    "domain_id": domain_id
                }
            });

            return Promise::new(self.mpc_contract_id.clone())
                .function_call(
                    MPC_METHOD_SIGN_RAW.to_string(),
                    args.to_string().into_bytes(),
                    1,
                    GAS_FOR_SIGN,
                )
                .then(
                    Promise::new(env::current_account_id()).function_call(
                        "on_sign_complete".to_string(),
                        serde_json::json!({ "request_id": request_id })
                            .to_string()
                            .into_bytes(),
                        0,
                        GAS_FOR_CALLBACK,
                    ),
                );
        }

        // Non-EVM: forward to MPC sign_template (original path)
        let args = serde_json::json!({
            "request": {
                "caller": caller,
                "template_id": request.template_id,
                "chain": request.chain,
                "kind": template.kind,
                "derivation_path": signer_path,
                "to": request.to,
                "amount": request.amount,
                "token_contract": request.token_contract,
                "symbol": request.symbol,
                "evm_chain_id": request.evm_chain_id,
                "memo": request.memo,
            }
        });

        Promise::new(self.mpc_contract_id.clone())
            .function_call(
                MPC_METHOD_SIGN_TEMPLATE.to_string(),
                args.to_string().into_bytes(),
                1,
                GAS_FOR_SIGN,
            )
            .then(
                Promise::new(env::current_account_id()).function_call(
                    "on_sign_complete".to_string(),
                    serde_json::json!({ "request_id": request_id })
                        .to_string()
                        .into_bytes(),
                    0,
                    GAS_FOR_CALLBACK,
                ),
            )
    }

    /// View: get stored sign result for a request_id.
    pub fn get_sign_result(&self, request_id: String) -> Option<SignResult> {
        self.sign_results.get(&request_id)
    }

    /// Root-wallet-only: grant policy-manager authority to a registered subkey.
    pub fn grant_policy_manager(
        &mut self,
        public_key: PublicKey,
        can_manage_self_policy: Option<bool>,
    ) {
        self.assert_direct_call();
        let caller = env::predecessor_account_id();
        let target_pk = Self::pk_to_string(&public_key);
        let storage_key = Self::compose_key(&caller, &target_pk);
        require!(self.subkeys.get(&storage_key).is_some(), "subkey not found");

        let grant = PolicyManagerGrant {
            can_manage_policies: true,
            can_manage_self_policy: can_manage_self_policy.unwrap_or(false),
        };
        self.policy_managers.insert(&storage_key, &grant);
        Self::log_event(
            "policy_manager_granted",
            serde_json::json!({
                "account_id": caller,
                "public_key": target_pk,
                "grant": grant
            }),
        );
    }

    /// Root-wallet-only: revoke policy-manager authority from a registered subkey.
    pub fn revoke_policy_manager(&mut self, public_key: PublicKey) {
        self.assert_direct_call();
        let caller = env::predecessor_account_id();
        let target_pk = Self::pk_to_string(&public_key);
        let storage_key = Self::compose_key(&caller, &target_pk);
        require!(
            self.policy_managers.remove(&storage_key).is_some(),
            "policy manager not found"
        );
        Self::log_event(
            "policy_manager_revoked",
            serde_json::json!({ "account_id": caller, "public_key": target_pk }),
        );
    }

    pub fn get_policy_manager(
        &self,
        account_id: AccountId,
        public_key: PublicKey,
    ) -> Option<PolicyManagerGrant> {
        let target_pk = Self::pk_to_string(&public_key);
        self.policy_managers
            .get(&Self::compose_key(&account_id, &target_pk))
    }

    /// Role-gated: set or update persisted policy for a signer subkey.
    pub fn set_signer_policy(&mut self, public_key: PublicKey, policy: ApiKeyPolicyV1) {
        self.assert_direct_call();
        let caller = env::predecessor_account_id();
        let target_pk = Self::pk_to_string(&public_key);
        self.assert_can_manage_policy(&caller, &target_pk);
        self.upsert_signer_policy(&caller, &target_pk, policy, "signer_policy_set");
    }

    /// Root/browser path: direct policy write for a signer subkey.
    pub fn owner_set_signer_policy(&mut self, public_key: PublicKey, policy: ApiKeyPolicyV1) {
        self.assert_direct_call();
        let caller = env::predecessor_account_id();
        let target_pk = Self::pk_to_string(&public_key);
        self.upsert_signer_policy(&caller, &target_pk, policy, "owner_signer_policy_set");
    }

    /// Role-gated: remove persisted policy for a signer subkey.
    pub fn remove_signer_policy(&mut self, public_key: PublicKey) {
        self.assert_direct_call();
        let caller = env::predecessor_account_id();
        let target_pk = Self::pk_to_string(&public_key);
        self.assert_can_manage_policy(&caller, &target_pk);
        self.drop_signer_policy(&caller, &target_pk, "signer_policy_removed");
    }

    /// Root/browser path: direct policy removal for a signer subkey.
    pub fn owner_remove_signer_policy(&mut self, public_key: PublicKey) {
        self.assert_direct_call();
        let caller = env::predecessor_account_id();
        let target_pk = Self::pk_to_string(&public_key);
        self.drop_signer_policy(&caller, &target_pk, "owner_signer_policy_removed");
    }

    pub fn get_signer_policy(
        &self,
        account_id: AccountId,
        public_key: PublicKey,
    ) -> Option<ApiKeyPolicyV1> {
        let target_pk = Self::pk_to_string(&public_key);
        self.api_key_policies
            .get(&Self::compose_key(&account_id, &target_pk))
    }

    /// Owner-only: remove stored sign results by request_id.
    pub fn cleanup_results(&mut self, request_ids: Vec<String>) -> u32 {
        self.assert_owner();
        let total = request_ids.len() as u32;
        let mut removed = 0u32;
        for request_id in request_ids {
            if self.sign_results.remove(&request_id).is_some() {
                removed += 1;
            }
        }
        Self::log_event(
            "cleanup_results",
            serde_json::json!({
                "removed": removed,
                "total": total
            }),
        );
        removed
    }

    #[private]
    pub fn on_sign_complete(&mut self, request_id: String) -> SignResult {
        let result = match env::promise_result(0) {
            PromiseResult::Successful(bytes) => SignResult {
                request_id: request_id.clone(),
                ok: true,
                payload: if bytes.is_empty() {
                    None
                } else {
                    Some(Base64VecU8(bytes))
                },
                error: None,
            },
            PromiseResult::Failed => SignResult {
                request_id: request_id.clone(),
                ok: false,
                payload: None,
                error: Some("mpc sign failed".to_string()),
            },
            PromiseResult::NotReady => env::panic_str("promise not ready"),
        };
        self.sign_results.insert(&request_id, &result);
        Self::log_event(
            "sign_result",
            serde_json::json!({
                "request_id": request_id,
                "ok": result.ok,
                "has_payload": result.payload.is_some(),
                "error": result.error
            }),
        );
        result
    }

    pub fn get_owner(&self) -> AccountId {
        self.owner_id.clone()
    }

    pub fn get_mpc(&self) -> AccountId {
        self.mpc_contract_id.clone()
    }

    /// Owner-only: update MPC endpoint without resetting contract state.
    pub fn set_mpc(&mut self, mpc_contract_id: AccountId) {
        self.assert_owner();
        self.mpc_contract_id = mpc_contract_id.clone();
        Self::log_event(
            "mpc_updated",
            serde_json::json!({
                "mpc_contract_id": mpc_contract_id
            }),
        );
    }

    fn assert_owner(&self) {
        require!(env::predecessor_account_id() == self.owner_id, "owner only");
    }

    fn assert_new_request_id(&self, request_id: &str) {
        require!(!request_id.is_empty(), "request_id required");
        // NEAR cross-contract calls complete in a later block. Without this check,
        // a caller could submit the same `request_id` a second time before the first
        // callback has written its result.
        require!(
            self.sign_results.get(&request_id.to_string()).is_none(),
            "request_id already used"
        );
    }

    fn assert_direct_call(&self) {
        require!(
            env::predecessor_account_id() == env::signer_account_id(),
            "cross-contract calls not allowed"
        );
    }

    fn assert_can_manage_policy(&self, caller: &AccountId, target_pk: &str) {
        let signer_pk = Self::pk_to_string(&env::signer_account_pk());
        let signer_storage_key = Self::compose_key(caller, &signer_pk);
        if self.subkeys.get(&signer_storage_key).is_none() {
            return;
        }

        let Some(grant) = self.policy_managers.get(&signer_storage_key) else {
            env::panic_str("policy write not allowed");
        };

        if grant.can_manage_policies {
            return;
        }
        if grant.can_manage_self_policy && signer_pk == target_pk {
            return;
        }

        env::panic_str("policy write not allowed");
    }

    fn upsert_signer_policy(
        &mut self,
        caller: &AccountId,
        target_pk: &str,
        policy: ApiKeyPolicyV1,
        event: &str,
    ) {
        let storage_key = Self::compose_key(caller, target_pk);
        require!(self.subkeys.get(&storage_key).is_some(), "subkey not found");
        let normalized = Self::normalize_api_key_policy(policy);
        self.api_key_policies.insert(&storage_key, &normalized);
        Self::log_event(
            event,
            serde_json::json!({
                "account_id": caller,
                "public_key": target_pk,
                "template_id": normalized.template_id,
                "asset_type": normalized.asset_type,
                "asset_id": normalized.asset_id,
                "period_seconds": normalized.period_seconds,
                "max_tx_count_per_period": normalized.max_tx_count_per_period,
                "allow_destinations": normalized.allow_destinations
            }),
        );
    }

    fn drop_signer_policy(&mut self, caller: &AccountId, target_pk: &str, event: &str) {
        let storage_key = Self::compose_key(caller, target_pk);
        require!(
            self.api_key_policies.remove(&storage_key).is_some(),
            "policy not found"
        );
        Self::log_event(
            event,
            serde_json::json!({ "account_id": caller, "public_key": target_pk }),
        );
    }

    // ─── EVM RLP encoding ───────────────────────────────────────────────

    fn rlp_encode_bytes(data: &[u8]) -> Vec<u8> {
        if data.len() == 1 && data[0] < 0x80 {
            return data.to_vec();
        }
        let mut out = Self::rlp_length_prefix(data.len(), 0x80);
        out.extend_from_slice(data);
        out
    }

    fn rlp_encode_list(items: &[Vec<u8>]) -> Vec<u8> {
        let mut payload = Vec::new();
        for item in items { payload.extend_from_slice(item); }
        let mut out = Self::rlp_length_prefix(payload.len(), 0xc0);
        out.extend_from_slice(&payload);
        out
    }

    fn rlp_length_prefix(len: usize, offset: u8) -> Vec<u8> {
        if len < 56 {
            vec![offset + len as u8]
        } else {
            let len_bytes = Self::minimal_be_bytes_usize(len);
            let mut out = vec![offset + 55 + len_bytes.len() as u8];
            out.extend_from_slice(&len_bytes);
            out
        }
    }

    fn rlp_encode_u64(val: u64) -> Vec<u8> {
        if val == 0 { return Self::rlp_encode_bytes(&[]); }
        let be = val.to_be_bytes();
        let start = be.iter().position(|&b| b != 0).unwrap_or(7);
        Self::rlp_encode_bytes(&be[start..])
    }

    fn rlp_encode_u128(val: u128) -> Vec<u8> {
        if val == 0 { return Self::rlp_encode_bytes(&[]); }
        let be = val.to_be_bytes();
        let start = be.iter().position(|&b| b != 0).unwrap_or(15);
        Self::rlp_encode_bytes(&be[start..])
    }

    fn minimal_be_bytes_usize(val: usize) -> Vec<u8> {
        let be = (val as u64).to_be_bytes();
        let start = be.iter().position(|&b| b != 0).unwrap_or(7);
        be[start..].to_vec()
    }

    /// Build unsigned EIP-1559 (type 2) tx and return keccak256 hash.
    fn build_evm_tx_hash(
        chain_id: u64, nonce: u64, max_priority_fee: u128, max_fee: u128,
        gas_limit: u64, to: &[u8; 20], value: u128, data: &[u8],
    ) -> Vec<u8> {
        let items: Vec<Vec<u8>> = vec![
            Self::rlp_encode_u64(chain_id),
            Self::rlp_encode_u64(nonce),
            Self::rlp_encode_u128(max_priority_fee),
            Self::rlp_encode_u128(max_fee),
            Self::rlp_encode_u64(gas_limit),
            Self::rlp_encode_bytes(to),
            Self::rlp_encode_u128(value),
            Self::rlp_encode_bytes(data),
            Self::rlp_encode_list(&[]), // empty accessList
        ];
        let rlp_list = Self::rlp_encode_list(&items);
        let mut envelope = vec![0x02u8];
        envelope.extend_from_slice(&rlp_list);
        env::keccak256(&envelope).to_vec()
    }

    fn parse_evm_address(addr: &str) -> [u8; 20] {
        let hex_str = addr.strip_prefix("0x").unwrap_or(addr);
        require!(hex_str.len() == 40, "invalid EVM address length");
        let bytes = hex::decode(hex_str).unwrap_or_else(|_| env::panic_str("invalid EVM address hex"));
        let mut out = [0u8; 20];
        out.copy_from_slice(&bytes);
        out
    }

    fn parse_eip3009_memo(memo: Option<&str>) -> Option<Eip3009MemoParts> {
        let memo = memo?;
        let raw = memo.strip_prefix("x402-eip3009:")?;
        let v: serde_json::Value = serde_json::from_str(raw).ok()?;
        let from = v.get("from")?.as_str()?.to_string();
        let token = v.get("token")?.as_str()?.to_string();
        let domain_name = v
            .get("domainName")
            .and_then(|x| x.as_str())
            .unwrap_or("USD Coin")
            .to_string();
        let domain_version = v
            .get("domainVersion")
            .and_then(|x| x.as_str())
            .unwrap_or("2")
            .to_string();
        let valid_after = Self::json_u64(v.get("validAfter")?)?;
        let valid_before = Self::json_u64(v.get("validBefore")?)?;
        let nonce_hex = v.get("nonce")?.as_str()?;
        let nonce_bytes = hex::decode(nonce_hex.strip_prefix("0x").unwrap_or(nonce_hex)).ok()?;
        if nonce_bytes.len() != 32 {
            return None;
        }
        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(&nonce_bytes);
        Some(Eip3009MemoParts {
            from,
            token,
            valid_after,
            valid_before,
            nonce,
            domain_name,
            domain_version,
        })
    }

    /// Parse `eip712-digest:0x` + 64 hex chars (32-byte keccak digest to MPC-sign).
    fn parse_eip712_digest_memo(memo: Option<&str>) -> Option<Vec<u8>> {
        let memo = memo?;
        let hex_str = memo.strip_prefix("eip712-digest:")?;
        let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        if hex_str.len() != 64 {
            return None;
        }
        hex::decode(hex_str).ok()
    }

    fn json_u64(v: &serde_json::Value) -> Option<u64> {
        if let Some(n) = v.as_u64() {
            return Some(n);
        }
        v.as_str()?.parse().ok()
    }

    fn abi_encode_address(addr: &[u8; 20]) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[12..].copy_from_slice(addr);
        out
    }

    fn abi_encode_u256(n: u128) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[16..].copy_from_slice(&n.to_be_bytes());
        out
    }

    fn abi_encode_bytes32(b: &[u8; 32]) -> [u8; 32] {
        *b
    }

    /// EIP-712 digest for EIP-3009 `TransferWithAuthorization`.
    fn build_eip3009_transfer_auth_hash(
        domain_name: &str,
        domain_version: &str,
        chain_id: u64,
        verifying_contract: &[u8; 20],
        from: &[u8; 20],
        to: &[u8; 20],
        value: u128,
        valid_after: u64,
        valid_before: u64,
        nonce: &[u8; 32],
    ) -> Vec<u8> {
        let domain_typehash = env::keccak256(
            b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
        );
        let transfer_typehash = env::keccak256(
            b"TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)",
        );
        let name_hash = env::keccak256(domain_name.as_bytes());
        let version_hash = env::keccak256(domain_version.as_bytes());

        let mut domain_encoded = Vec::with_capacity(32 * 5);
        domain_encoded.extend_from_slice(&domain_typehash);
        domain_encoded.extend_from_slice(&name_hash);
        domain_encoded.extend_from_slice(&version_hash);
        domain_encoded.extend_from_slice(&Self::abi_encode_u256(chain_id as u128));
        domain_encoded.extend_from_slice(&Self::abi_encode_address(verifying_contract));
        let domain_separator = env::keccak256(&domain_encoded);

        let mut struct_encoded = Vec::with_capacity(32 * 7);
        struct_encoded.extend_from_slice(&transfer_typehash);
        struct_encoded.extend_from_slice(&Self::abi_encode_address(from));
        struct_encoded.extend_from_slice(&Self::abi_encode_address(to));
        struct_encoded.extend_from_slice(&Self::abi_encode_u256(value));
        struct_encoded.extend_from_slice(&Self::abi_encode_u256(valid_after as u128));
        struct_encoded.extend_from_slice(&Self::abi_encode_u256(valid_before as u128));
        struct_encoded.extend_from_slice(&Self::abi_encode_bytes32(nonce));
        let struct_hash = env::keccak256(&struct_encoded);

        let mut digest_input = Vec::with_capacity(2 + 32 + 32);
        digest_input.extend_from_slice(&[0x19, 0x01]);
        digest_input.extend_from_slice(&domain_separator);
        digest_input.extend_from_slice(&struct_hash);
        env::keccak256(&digest_input).to_vec()
    }

    // ─── End EVM RLP ──────────────────────────────────────────────────

    fn compose_key(account_id: &AccountId, pk: &str) -> String {
        format!("{}|{}", account_id, pk)
    }

    fn template_key(chain: &Chain, template_id: &str) -> String {
        format!("{}|{}", Self::chain_key(chain), template_id)
    }

    fn cap_key(chain: &Chain, token_contract: &str) -> String {
        format!("{}|{}", Self::chain_key(chain), token_contract)
    }

    fn chain_key(chain: &Chain) -> &'static str {
        match chain {
            Chain::Solana => "solana",
            Chain::Evm => "evm",
            Chain::Bitcoin => "bitcoin",
            Chain::Near => "near",
        }
    }

    fn pk_to_string(pk: &PublicKey) -> String {
        bs58::encode(pk.as_bytes()).into_string()
    }

    fn validate_paths(paths: &[ChainPaths]) {
        require!(!paths.is_empty(), "paths required");
        for entry in paths {
            require!(!entry.paths.is_empty(), "path list cannot be empty");
            for p in &entry.paths {
                Self::validate_path(p);
            }
        }
        // ensure unique chain per entry
        let mut seen = std::collections::HashSet::new();
        for entry in paths {
            require!(
                seen.insert(format!("{:?}", entry.chain)),
                "duplicate chain entry"
            );
        }
    }

    fn validate_path(path: &str) {
        require!(!path.is_empty(), "empty derivation path");
        require!(
            !path.contains(':'),
            "derivation path contains invalid separator"
        );
    }

    fn validate_template_request(template: &TxTemplate, request: &TemplateSignRequest) {
        match template.kind {
            TxKind::SolanaNative | TxKind::EvmNative | TxKind::BitcoinSend => {
                require!(request.token_contract.is_none(), "token not allowed");
            }
            TxKind::SolanaSpl | TxKind::SolanaToken2022 | TxKind::EvmErc20 => {
                require!(request.token_contract.is_some(), "token contract required");
            }
        }
        if let Some(allowed) = &template.allowed_tokens {
            if let Some(token) = &request.token_contract {
                require!(allowed.contains(token), "token not allowed");
            } else {
                require!(false, "token contract required");
            }
        }
    }

    fn chain_requires_policy(chain: &Chain) -> bool {
        matches!(chain, Chain::Solana | Chain::Evm | Chain::Near)
    }

    fn template_kind_asset_type(kind: &TxKind) -> &'static str {
        match kind {
            TxKind::SolanaNative | TxKind::EvmNative | TxKind::BitcoinSend => "native",
            TxKind::SolanaSpl | TxKind::SolanaToken2022 | TxKind::EvmErc20 => "token",
        }
    }

    fn parse_policy_native_limit_units(chain: &Chain, raw: &str) -> Option<u128> {
        match chain {
            Chain::Solana => Self::parse_decimal_amount_to_units(raw, 9),
            Chain::Evm => Self::parse_decimal_amount_to_units(raw, 18),
            Chain::Bitcoin => Self::parse_decimal_amount_to_units(raw, 8),
            Chain::Near => Self::parse_decimal_amount_to_units(raw, 24),
        }
    }

    fn enforce_persisted_policy_for_template_request(
        &self,
        chain: &Chain,
        template: &TxTemplate,
        request: &TemplateSignRequest,
        account_id: &AccountId,
        signer_public_key: &str,
    ) {
        if !Self::chain_requires_policy(chain) {
            return;
        }

        let storage_key = Self::compose_key(account_id, signer_public_key);
        let policy = self
            .api_key_policies
            .get(&storage_key)
            .unwrap_or_else(|| env::panic_str("policy_not_enabled"));

        require!(
            policy.template_id == request.template_id,
            "template_not_allowed"
        );

        if !policy.allow_destinations.is_empty() {
            require!(
                policy
                    .allow_destinations
                    .iter()
                    .any(|item| item.eq_ignore_ascii_case(&request.to)),
                "destination_not_allowed"
            );
        }

        let expected_asset_type = Self::template_kind_asset_type(&template.kind);
        require!(
            policy
                .asset_type
                .trim()
                .eq_ignore_ascii_case(expected_asset_type),
            "asset_type_not_allowed"
        );

        if expected_asset_type == "token" {
            let Some(request_token) = request.token_contract.as_ref() else {
                env::panic_str("token contract required");
            };
            if let Some(policy_asset_id) = policy.asset_id.as_ref() {
                require!(
                    policy_asset_id.trim().eq_ignore_ascii_case(request_token),
                    "asset_not_allowed"
                );
            }
            return;
        }

        if let Some(raw_limit) = policy.max_per_tx_native.as_ref() {
            let max_units = Self::parse_policy_native_limit_units(chain, raw_limit)
                .unwrap_or_else(|| env::panic_str("invalid max_per_tx_native"));
            require!(
                request.amount.0 <= max_units,
                "limit_per_tx_native_exceeded"
            );
        }
    }

    fn enforce_contract_policy_for_raw_request(
        &mut self,
        chain: &Chain,
        payload: &[u8],
        memo: Option<&str>,
        caller: &AccountId,
        signer_pk: &str,
    ) {
        if chain == &Chain::Evm {
            env::panic_str("evm_raw_signing_not_allowed_use_template");
        }

        let mut parsed_solana_native: Option<ParsedSolanaNativeTransfer> = None;
        let mut parsed_near_native: Option<ParsedNearNativeTransfer> = None;
        let mut parsed_near_ft: Option<ParsedNearFtTransfer> = None;

        if let Some(memo_text) = memo {
            if let Some(encoded_payload) = Self::extract_policy_memo_payload(memo_text) {
                let policy = Self::decode_contract_policy_memo(encoded_payload);
                match (chain, policy.template_id.as_str()) {
                    (Chain::Solana, "sol_native_transfer_v1") => {
                        parsed_solana_native =
                            Some(self.enforce_solana_native_policy(payload, &policy));
                    }
                    (Chain::Near, "near_native_transfer_v1" | "sol_native_transfer_v1") => {
                        parsed_near_native =
                            Some(self.enforce_near_native_policy(payload, &policy));
                    }
                    (Chain::Near, "near_ft_transfer_v1") => {
                        parsed_near_ft = Some(self.enforce_near_ft_policy(payload, &policy));
                    }
                    _ => {
                        // Raw-path policy enforcement is intentionally limited to verifiable payload
                        // types until more chain/template parsers land.
                    }
                }
            }
        }

        self.enforce_persisted_policy_for_raw_request(
            chain,
            payload,
            caller,
            signer_pk,
            parsed_solana_native.as_ref(),
            parsed_near_native.as_ref(),
            parsed_near_ft.as_ref(),
        );
    }

    fn extract_policy_memo_payload(memo: &str) -> Option<&str> {
        if !memo.starts_with(POLICY_MEMO_PREFIX) {
            return None;
        }
        let raw = &memo[POLICY_MEMO_PREFIX.len()..];
        Some(raw.split(POLICY_MEMO_SEPARATOR).next().unwrap_or(raw))
    }

    fn decode_contract_policy_memo(encoded: &str) -> ContractPolicyInputMemo {
        let bytes = URL_SAFE_NO_PAD
            .decode(encoded)
            .unwrap_or_else(|_| env::panic_str("invalid_policy_memo"));
        serde_json::from_slice::<ContractPolicyInputMemo>(&bytes)
            .unwrap_or_else(|_| env::panic_str("invalid_policy_memo"))
    }

    fn enforce_solana_native_policy(
        &mut self,
        payload: &[u8],
        policy: &ContractPolicyInputMemo,
    ) -> ParsedSolanaNativeTransfer {
        let parsed = Self::parse_solana_native_transfer(payload)
            .unwrap_or_else(|_| env::panic_str("policy_payload_mismatch"));
        let expected_from = Self::json_string_field(&policy.template_params, "fromPublicKey")
            .unwrap_or_else(|| env::panic_str("policy_payload_mismatch"));
        let expected_destination = Self::json_string_field(&policy.template_params, "destination")
            .unwrap_or_else(|| env::panic_str("policy_payload_mismatch"));
        let expected_amount = Self::json_string_field(&policy.template_params, "amount")
            .unwrap_or_else(|| env::panic_str("policy_payload_mismatch"));
        let expected_lamports = Self::parse_sol_amount_to_lamports(&expected_amount)
            .unwrap_or_else(|| env::panic_str("policy_payload_mismatch"));

        require!(
            parsed.from_public_key == expected_from,
            "policy_payload_mismatch"
        );
        require!(
            parsed.destination == expected_destination,
            "policy_payload_mismatch"
        );
        require!(
            parsed.lamports == expected_lamports,
            "policy_payload_mismatch"
        );

        if let Some(snapshot) = &policy.policy_snapshot {
            if !snapshot.template_allowlist.is_empty() {
                require!(
                    snapshot
                        .template_allowlist
                        .iter()
                        .any(|item| item == &policy.template_id),
                    "template_not_allowed"
                );
            }

            if !snapshot.destination_allowlist.is_empty() {
                require!(
                    snapshot
                        .destination_allowlist
                        .iter()
                        .any(|item| item == &parsed.destination),
                    "destination_not_allowed"
                );
            }

            if let Some(rule) = &snapshot.rule {
                let asset_type = rule.asset_type.trim().to_lowercase();
                if asset_type == "native" {
                    if let Some(max_lamports) =
                        Self::policy_native_cap_to_lamports(rule.max_per_tx_native.as_ref())
                    {
                        require!(
                            parsed.lamports <= max_lamports,
                            "limit_per_tx_native_exceeded"
                        );
                    }
                }
            }
        }
        parsed
    }

    fn enforce_near_native_policy(
        &mut self,
        payload: &[u8],
        policy: &ContractPolicyInputMemo,
    ) -> ParsedNearNativeTransfer {
        let parsed = Self::parse_near_native_transfer(payload)
            .unwrap_or_else(|_| env::panic_str("policy_payload_mismatch"));
        let expected_from = Self::json_string_field(&policy.template_params, "fromPublicKey")
            .or_else(|| Self::json_string_field(&policy.template_params, "fromAddress"))
            .unwrap_or_else(|| env::panic_str("policy_payload_mismatch"));
        let expected_destination = Self::json_string_field(&policy.template_params, "destination")
            .unwrap_or_else(|| env::panic_str("policy_payload_mismatch"));
        let expected_amount = Self::json_string_field(&policy.template_params, "amount")
            .unwrap_or_else(|| env::panic_str("policy_payload_mismatch"));
        let expected_yocto = Self::parse_near_amount_to_yocto(&expected_amount)
            .unwrap_or_else(|| env::panic_str("policy_payload_mismatch"));

        require!(
            parsed.from_implicit == expected_from.to_lowercase(),
            "policy_payload_mismatch"
        );
        require!(parsed.destination == expected_destination, "policy_payload_mismatch");
        require!(parsed.yocto == expected_yocto, "policy_payload_mismatch");

        if let Some(snapshot) = &policy.policy_snapshot {
            if !snapshot.template_allowlist.is_empty() {
                require!(
                    snapshot
                        .template_allowlist
                        .iter()
                        .any(|item| item == &policy.template_id),
                    "template_not_allowed"
                );
            }

            if !snapshot.destination_allowlist.is_empty() {
                require!(
                    snapshot
                        .destination_allowlist
                        .iter()
                        .any(|item| item == &parsed.destination),
                    "destination_not_allowed"
                );
            }

            if let Some(rule) = &snapshot.rule {
                let asset_type = rule.asset_type.trim().to_lowercase();
                if asset_type == "native" {
                    if let Some(max_yocto) =
                        Self::policy_native_cap_to_yocto(rule.max_per_tx_native.as_ref())
                    {
                        require!(
                            parsed.yocto <= max_yocto,
                            "limit_per_tx_native_exceeded"
                        );
                    }
                }
            }
        }
        parsed
    }

    fn enforce_near_ft_policy(
        &mut self,
        payload: &[u8],
        policy: &ContractPolicyInputMemo,
    ) -> ParsedNearFtTransfer {
        let parsed = Self::parse_near_ft_transfer(payload)
            .unwrap_or_else(|_| env::panic_str("policy_payload_mismatch"));
        let expected_from = Self::json_string_field(&policy.template_params, "fromPublicKey")
            .or_else(|| Self::json_string_field(&policy.template_params, "fromAddress"))
            .unwrap_or_else(|| env::panic_str("policy_payload_mismatch"));
        let expected_destination = Self::json_string_field(&policy.template_params, "destination")
            .unwrap_or_else(|| env::panic_str("policy_payload_mismatch"));
        let expected_token = Self::json_string_field(&policy.template_params, "tokenContract")
            .or_else(|| Self::json_string_field(&policy.template_params, "tokenAddress"))
            .unwrap_or_else(|| env::panic_str("policy_payload_mismatch"));
        let expected_amount = Self::json_string_field(&policy.template_params, "amount")
            .unwrap_or_else(|| env::panic_str("policy_payload_mismatch"));
        let expected_units = Self::parse_token_amount_units(&expected_amount)
            .unwrap_or_else(|| env::panic_str("policy_payload_mismatch"));

        require!(
            parsed.from_implicit == expected_from.to_lowercase(),
            "policy_payload_mismatch"
        );
        require!(
            parsed.destination == expected_destination,
            "policy_payload_mismatch"
        );
        require!(
            parsed
                .ft_contract
                .eq_ignore_ascii_case(expected_token.trim()),
            "policy_payload_mismatch"
        );
        require!(parsed.amount == expected_units, "policy_payload_mismatch");

        if let Some(snapshot) = &policy.policy_snapshot {
            if !snapshot.template_allowlist.is_empty() {
                require!(
                    snapshot
                        .template_allowlist
                        .iter()
                        .any(|item| item == &policy.template_id),
                    "template_not_allowed"
                );
            }

            if !snapshot.destination_allowlist.is_empty() {
                require!(
                    snapshot
                        .destination_allowlist
                        .iter()
                        .any(|item| item == &parsed.destination),
                    "destination_not_allowed"
                );
            }

            if let Some(rule) = &snapshot.rule {
                let asset_type = rule.asset_type.trim().to_lowercase();
                require!(asset_type == "token", "asset_type_not_allowed");
                let policy_asset_id = rule.asset_id.trim();
                require!(!policy_asset_id.is_empty(), "asset_id required");
                require!(
                    policy_asset_id.eq_ignore_ascii_case(&parsed.ft_contract),
                    "token_not_allowed"
                );
                if let Some(max_units) =
                    Self::policy_token_cap_to_units(rule.max_per_tx_native.as_ref())
                {
                    require!(parsed.amount <= max_units, "limit_per_tx_native_exceeded");
                }
            }
        }
        parsed
    }

    fn enforce_persisted_policy_for_raw_request(
        &mut self,
        chain: &Chain,
        payload: &[u8],
        account_id: &AccountId,
        signer_public_key: &str,
        parsed_solana_native: Option<&ParsedSolanaNativeTransfer>,
        parsed_near_native: Option<&ParsedNearNativeTransfer>,
        parsed_near_ft: Option<&ParsedNearFtTransfer>,
    ) {
        if !Self::chain_requires_policy(chain) {
            return;
        }

        let storage_key = Self::compose_key(account_id, signer_public_key);
        let Some(policy) = self.api_key_policies.get(&storage_key) else {
            env::panic_str("policy_not_enabled");
        };

        if chain == &Chain::Solana {
            let asset_type = policy.asset_type.trim().to_lowercase();
            if asset_type != "native" {
                return;
            }
            if policy.template_id != "sol_native_transfer_v1" {
                return;
            }

            let parsed = match parsed_solana_native {
                Some(parsed) => parsed.clone(),
                None => Self::parse_solana_native_transfer(payload)
                    .unwrap_or_else(|_| env::panic_str("policy_payload_mismatch")),
            };
            self.enforce_persisted_api_key_policy(
                account_id,
                signer_public_key,
                &policy.template_id,
                &parsed,
            );
            return;
        }

        if chain == &Chain::Near {
            let asset_type = policy.asset_type.trim().to_lowercase();
            if asset_type == "token" || policy.template_id == "near_ft_transfer_v1" {
                require!(
                    policy.template_id == "near_ft_transfer_v1",
                    "template_not_allowed"
                );
                require!(asset_type == "token", "asset_type_not_allowed");
                let parsed = match parsed_near_ft {
                    Some(parsed) => parsed.clone(),
                    None => Self::parse_near_ft_transfer(payload)
                        .unwrap_or_else(|_| env::panic_str("policy_payload_mismatch")),
                };
                self.enforce_persisted_api_key_policy_near_ft(
                    account_id,
                    signer_public_key,
                    &policy.template_id,
                    &parsed,
                );
                return;
            }
            if asset_type != "native" {
                return;
            }
            if policy.template_id != "near_native_transfer_v1"
                && policy.template_id != "sol_native_transfer_v1"
            {
                return;
            }

            // Native Transfer → enforce native caps.
            // Bootstrap policies (empty dest allowlist) also unlock NEP-141 Path C
            // (optional storage_deposit + ft_transfer) — off-chain policy already gated.
            if let Some(parsed) = parsed_near_native.cloned().or_else(|| {
                Self::parse_near_native_transfer(payload).ok()
            }) {
                self.enforce_persisted_api_key_policy_near(
                    account_id,
                    signer_public_key,
                    &policy.template_id,
                    &parsed,
                );
                return;
            }

            let ft_ok = parsed_near_ft.is_some()
                || Self::parse_near_ft_transfer(payload).is_ok();
            if ft_ok {
                require!(
                    policy.allow_destinations.is_empty(),
                    "token_transfer_not_allowed"
                );
                return;
            }

            env::panic_str("policy_payload_mismatch");
        }

        if chain == &Chain::Evm {
            return;
        }

        env::panic_str("policy_check_failed");
    }

    fn enforce_persisted_api_key_policy(
        &mut self,
        account_id: &AccountId,
        signer_public_key: &str,
        template_id: &str,
        parsed: &ParsedSolanaNativeTransfer,
    ) {
        let storage_key = Self::compose_key(account_id, signer_public_key);
        let mut policy = match self.api_key_policies.get(&storage_key) {
            Some(policy) => policy,
            None => return,
        };

        require!(policy.template_id == template_id, "template_not_allowed");

        if !policy.allow_destinations.is_empty() {
            require!(
                policy
                    .allow_destinations
                    .iter()
                    .any(|item| item == &parsed.destination),
                "destination_not_allowed"
            );
        }

        if let Some(max_lamports) =
            Self::optional_string_amount_to_lamports(policy.max_per_tx_native.as_ref())
        {
            require!(
                parsed.lamports <= max_lamports,
                "limit_per_tx_native_exceeded"
            );
        }

        let max_per_period_lamports =
            Self::optional_string_amount_to_lamports(policy.max_per_period_native.as_ref());
        let max_tx_count_per_period = policy.max_tx_count_per_period;
        if max_per_period_lamports.is_none() && max_tx_count_per_period.is_none() {
            return;
        }

        let period_seconds = policy.period_seconds.unwrap_or(0);
        require!(period_seconds > 0, "policy_check_failed");

        let now_seconds = env::block_timestamp() / 1_000_000_000;
        let window_start = now_seconds - (now_seconds % period_seconds);
        if policy.period_start_unix_seconds != Some(window_start) {
            policy.period_start_unix_seconds = Some(window_start);
            policy.spent_this_period_native = Some("0".to_string());
            policy.tx_count_this_period = Some(0);
        }

        let current_spent =
            Self::optional_string_amount_to_lamports(policy.spent_this_period_native.as_ref())
                .unwrap_or(0);
        let next_spent = current_spent
            .checked_add(parsed.lamports)
            .unwrap_or_else(|| env::panic_str("policy_check_failed"));

        if let Some(max_lamports) = max_per_period_lamports {
            require!(
                next_spent <= max_lamports,
                "limit_per_period_native_exceeded"
            );
        }

        let current_tx_count = policy.tx_count_this_period.unwrap_or(0);
        let next_tx_count = current_tx_count
            .checked_add(1)
            .unwrap_or_else(|| env::panic_str("policy_check_failed"));
        if let Some(max_tx_count) = max_tx_count_per_period {
            require!(next_tx_count <= max_tx_count, "limit_tx_count_exceeded");
        }

        policy.period_start_unix_seconds = Some(window_start);
        policy.spent_this_period_native = Some(Self::lamports_to_sol_amount_string(next_spent));
        policy.tx_count_this_period = Some(next_tx_count);
        self.api_key_policies.insert(&storage_key, &policy);
    }

    fn enforce_persisted_api_key_policy_near(
        &mut self,
        account_id: &AccountId,
        signer_public_key: &str,
        template_id: &str,
        parsed: &ParsedNearNativeTransfer,
    ) {
        let storage_key = Self::compose_key(account_id, signer_public_key);
        let mut policy = match self.api_key_policies.get(&storage_key) {
            Some(policy) => policy,
            None => return,
        };

        require!(policy.template_id == template_id, "template_not_allowed");

        if !policy.allow_destinations.is_empty() {
            require!(
                policy
                    .allow_destinations
                    .iter()
                    .any(|item| item == &parsed.destination),
                "destination_not_allowed"
            );
        }

        if let Some(max_yocto) =
            Self::optional_string_amount_to_yocto(policy.max_per_tx_native.as_ref())
        {
            require!(parsed.yocto <= max_yocto, "limit_per_tx_native_exceeded");
        }

        let max_per_period_yocto =
            Self::optional_string_amount_to_yocto(policy.max_per_period_native.as_ref());
        let max_tx_count_per_period = policy.max_tx_count_per_period;
        if max_per_period_yocto.is_none() && max_tx_count_per_period.is_none() {
            return;
        }

        let period_seconds = policy.period_seconds.unwrap_or(0);
        require!(period_seconds > 0, "policy_check_failed");

        let now_seconds = env::block_timestamp() / 1_000_000_000;
        let window_start = now_seconds - (now_seconds % period_seconds);
        if policy.period_start_unix_seconds != Some(window_start) {
            policy.period_start_unix_seconds = Some(window_start);
            policy.spent_this_period_native = Some("0".to_string());
            policy.tx_count_this_period = Some(0);
        }

        let current_spent =
            Self::optional_string_amount_to_yocto(policy.spent_this_period_native.as_ref())
                .unwrap_or(0);
        let next_spent = current_spent
            .checked_add(parsed.yocto)
            .unwrap_or_else(|| env::panic_str("policy_check_failed"));

        if let Some(max_yocto) = max_per_period_yocto {
            require!(next_spent <= max_yocto, "limit_per_period_native_exceeded");
        }

        let current_tx_count = policy.tx_count_this_period.unwrap_or(0);
        let next_tx_count = current_tx_count
            .checked_add(1)
            .unwrap_or_else(|| env::panic_str("policy_check_failed"));
        if let Some(max_tx_count) = max_tx_count_per_period {
            require!(next_tx_count <= max_tx_count, "limit_tx_count_exceeded");
        }

        policy.period_start_unix_seconds = Some(window_start);
        policy.spent_this_period_native = Some(Self::yocto_to_near_amount_string(next_spent));
        policy.tx_count_this_period = Some(next_tx_count);
        self.api_key_policies.insert(&storage_key, &policy);
    }

    fn enforce_persisted_api_key_policy_near_ft(
        &mut self,
        account_id: &AccountId,
        signer_public_key: &str,
        template_id: &str,
        parsed: &ParsedNearFtTransfer,
    ) {
        let storage_key = Self::compose_key(account_id, signer_public_key);
        let mut policy = match self.api_key_policies.get(&storage_key) {
            Some(policy) => policy,
            None => return,
        };

        require!(policy.template_id == template_id, "template_not_allowed");
        require!(
            policy.asset_type.trim().eq_ignore_ascii_case("token"),
            "asset_type_not_allowed"
        );
        let Some(policy_asset_id) = policy.asset_id.as_ref() else {
            env::panic_str("asset_id required");
        };
        require!(
            policy_asset_id
                .trim()
                .eq_ignore_ascii_case(&parsed.ft_contract),
            "token_not_allowed"
        );

        if !policy.allow_destinations.is_empty() {
            require!(
                policy
                    .allow_destinations
                    .iter()
                    .any(|item| item == &parsed.destination),
                "destination_not_allowed"
            );
        }

        if let Some(max_units) =
            Self::optional_string_amount_to_token_units(policy.max_per_tx_native.as_ref())
        {
            require!(parsed.amount <= max_units, "limit_per_tx_native_exceeded");
        }

        let max_per_period_units =
            Self::optional_string_amount_to_token_units(policy.max_per_period_native.as_ref());
        let max_tx_count_per_period = policy.max_tx_count_per_period;
        if max_per_period_units.is_none() && max_tx_count_per_period.is_none() {
            return;
        }

        let period_seconds = policy.period_seconds.unwrap_or(0);
        require!(period_seconds > 0, "policy_check_failed");

        let now_seconds = env::block_timestamp() / 1_000_000_000;
        let window_start = now_seconds - (now_seconds % period_seconds);
        if policy.period_start_unix_seconds != Some(window_start) {
            policy.period_start_unix_seconds = Some(window_start);
            policy.spent_this_period_native = Some("0".to_string());
            policy.tx_count_this_period = Some(0);
        }

        let current_spent =
            Self::optional_string_amount_to_token_units(policy.spent_this_period_native.as_ref())
                .unwrap_or(0);
        let next_spent = current_spent
            .checked_add(parsed.amount)
            .unwrap_or_else(|| env::panic_str("policy_check_failed"));

        if let Some(max_units) = max_per_period_units {
            require!(next_spent <= max_units, "limit_per_period_native_exceeded");
        }

        let current_tx_count = policy.tx_count_this_period.unwrap_or(0);
        let next_tx_count = current_tx_count
            .checked_add(1)
            .unwrap_or_else(|| env::panic_str("policy_check_failed"));
        if let Some(max_tx_count) = max_tx_count_per_period {
            require!(next_tx_count <= max_tx_count, "limit_tx_count_exceeded");
        }

        policy.period_start_unix_seconds = Some(window_start);
        policy.spent_this_period_native = Some(next_spent.to_string());
        policy.tx_count_this_period = Some(next_tx_count);
        self.api_key_policies.insert(&storage_key, &policy);
    }

    fn json_string_field(value: &serde_json::Value, key: &str) -> Option<String> {
        value.get(key)?.as_str().map(|item| item.to_string())
    }

    fn policy_native_cap_to_lamports(value: Option<&serde_json::Value>) -> Option<u64> {
        let raw = value?;
        match raw {
            serde_json::Value::String(inner) => Self::parse_sol_amount_to_lamports(inner),
            serde_json::Value::Number(inner) => {
                Self::parse_sol_amount_to_lamports(&inner.to_string())
            }
            _ => None,
        }
    }

    fn optional_string_amount_to_lamports(value: Option<&String>) -> Option<u64> {
        value
            .map(|item| item.trim())
            .filter(|item| !item.is_empty())
            .and_then(Self::parse_sol_amount_to_lamports)
    }

    fn parse_decimal_amount_to_units(value: &str, decimals: usize) -> Option<u128> {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return None;
        }
        let mut parts = trimmed.split('.');
        let whole = parts.next()?;
        let frac = parts.next();
        if parts.next().is_some() {
            return None;
        }
        if !whole.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
        let scale = 10u128.checked_pow(u32::try_from(decimals).ok()?)?;
        let mut units = whole.parse::<u128>().ok()?.checked_mul(scale)?;
        if let Some(frac_part) = frac {
            if frac_part.len() > decimals || !frac_part.chars().all(|c| c.is_ascii_digit()) {
                return None;
            }
            if decimals > 0 {
                let mut padded = frac_part.to_string();
                while padded.len() < decimals {
                    padded.push('0');
                }
                if !padded.is_empty() {
                    units = units.checked_add(padded.parse::<u128>().ok()?)?;
                }
            } else if !frac_part.is_empty() {
                return None;
            }
        }
        Some(units)
    }

    fn parse_sol_amount_to_lamports(value: &str) -> Option<u64> {
        let units = Self::parse_decimal_amount_to_units(value, 9)?;
        u64::try_from(units).ok()
    }

    fn parse_near_amount_to_yocto(value: &str) -> Option<u128> {
        Self::parse_decimal_amount_to_units(value, 24)
    }

    /// NEP-141 amounts are integer strings in smallest units. Also accept plain decimals
    /// with no fractional part via the 0-decimal parser.
    fn parse_token_amount_units(value: &str) -> Option<u128> {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return None;
        }
        if trimmed.contains('.') {
            // Allow "1.5" only when synced with known decimals elsewhere; raw path expects integers.
            return None;
        }
        if !trimmed.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
        if trimmed.len() > 1 && trimmed.starts_with('0') {
            return None;
        }
        trimmed.parse::<u128>().ok()
    }

    fn optional_string_amount_to_token_units(value: Option<&String>) -> Option<u128> {
        value
            .map(|item| item.trim())
            .filter(|item| !item.is_empty())
            .and_then(Self::parse_token_amount_units)
    }

    fn policy_token_cap_to_units(value: Option<&serde_json::Value>) -> Option<u128> {
        let raw = value?;
        match raw {
            serde_json::Value::String(inner) => Self::parse_token_amount_units(inner),
            serde_json::Value::Number(inner) => {
                if let Some(u) = inner.as_u64() {
                    Some(u128::from(u))
                } else {
                    Self::parse_token_amount_units(&inner.to_string())
                }
            }
            _ => None,
        }
    }

    fn optional_string_amount_to_yocto(value: Option<&String>) -> Option<u128> {
        value
            .map(|item| item.trim())
            .filter(|item| !item.is_empty())
            .and_then(Self::parse_near_amount_to_yocto)
    }

    fn policy_native_cap_to_yocto(value: Option<&serde_json::Value>) -> Option<u128> {
        let raw = value?;
        match raw {
            serde_json::Value::String(inner) => Self::parse_near_amount_to_yocto(inner),
            serde_json::Value::Number(inner) => {
                Self::parse_near_amount_to_yocto(&inner.to_string())
            }
            _ => None,
        }
    }

    fn yocto_to_near_amount_string(yocto: u128) -> String {
        let scale = 1_000_000_000_000_000_000_000_000u128;
        let whole = yocto / scale;
        let frac = yocto % scale;
        if frac == 0 {
            return whole.to_string();
        }
        let mut frac_string = format!("{:024}", frac);
        while frac_string.ends_with('0') {
            frac_string.pop();
        }
        format!("{}.{}", whole, frac_string)
    }

    fn read_u32_le(data: &[u8], pos: &mut usize) -> Result<u32, &'static str> {
        if *pos + 4 > data.len() {
            return Err("unexpected eof");
        }
        let bytes = [
            data[*pos],
            data[*pos + 1],
            data[*pos + 2],
            data[*pos + 3],
        ];
        *pos += 4;
        Ok(u32::from_le_bytes(bytes))
    }

    fn read_u64_le(data: &[u8], pos: &mut usize) -> Result<u64, &'static str> {
        if *pos + 8 > data.len() {
            return Err("unexpected eof");
        }
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&data[*pos..*pos + 8]);
        *pos += 8;
        Ok(u64::from_le_bytes(bytes))
    }

    fn read_u128_le(data: &[u8], pos: &mut usize) -> Result<u128, &'static str> {
        let lo = Self::read_u64_le(data, pos)? as u128;
        let hi = Self::read_u64_le(data, pos)? as u128;
        Ok(lo | (hi << 64))
    }

    fn read_borsh_string(data: &[u8], pos: &mut usize) -> Result<String, &'static str> {
        let len = Self::read_u32_le(data, pos)? as usize;
        let bytes = Self::read_bytes(data, pos, len)?;
        String::from_utf8(bytes.to_vec()).map_err(|_| "invalid utf8")
    }

    fn parse_near_native_transfer(payload: &[u8]) -> Result<ParsedNearNativeTransfer, &'static str> {
        let mut pos = 0usize;
        let from_implicit = Self::read_borsh_string(payload, &mut pos)?.to_lowercase();
        let key_type = Self::read_u8(payload, &mut pos)?;
        if key_type != 0 {
            return Err("unsupported public key type");
        }
        Self::read_bytes(payload, &mut pos, 32)?;
        let _nonce = Self::read_u64_le(payload, &mut pos)?;
        let destination = Self::read_borsh_string(payload, &mut pos)?;
        Self::read_bytes(payload, &mut pos, 32)?;
        let action_count = Self::read_u32_le(payload, &mut pos)? as usize;
        if action_count != 1 {
            return Err("expected exactly one action");
        }
        let action_variant = Self::read_u8(payload, &mut pos)?;
        if action_variant != 3 {
            return Err("not a transfer action");
        }
        let yocto = Self::read_u128_le(payload, &mut pos)?;
        if pos != payload.len() {
            return Err("unexpected trailing bytes");
        }
        Ok(ParsedNearNativeTransfer {
            from_implicit,
            destination,
            yocto,
        })
    }

    /// Parse a NEAR FT Path C payload: optional `storage_deposit` then `ft_transfer`.
    /// Receiver account is the FT contract; destination is `ft_transfer.args.receiver_id`.
    fn parse_near_ft_transfer(payload: &[u8]) -> Result<ParsedNearFtTransfer, &'static str> {
        let mut pos = 0usize;
        let from_implicit = Self::read_borsh_string(payload, &mut pos)?.to_lowercase();
        let key_type = Self::read_u8(payload, &mut pos)?;
        if key_type != 0 {
            return Err("unsupported public key type");
        }
        Self::read_bytes(payload, &mut pos, 32)?;
        let _nonce = Self::read_u64_le(payload, &mut pos)?;
        let ft_contract = Self::read_borsh_string(payload, &mut pos)?;
        if ft_contract.is_empty() {
            return Err("ft contract required");
        }
        Self::read_bytes(payload, &mut pos, 32)?;
        let action_count = Self::read_u32_le(payload, &mut pos)? as usize;
        if action_count != 1 && action_count != 2 {
            return Err("expected one or two actions");
        }

        let mut storage_account_id: Option<String> = None;
        if action_count == 2 {
            let action_variant = Self::read_u8(payload, &mut pos)?;
            if action_variant != 2 {
                return Err("storage_deposit must be a function call");
            }
            let method_name = Self::read_borsh_string(payload, &mut pos)?;
            if method_name != "storage_deposit" {
                return Err("first action must be storage_deposit");
            }
            let args_len = Self::read_u32_le(payload, &mut pos)? as usize;
            let args_bytes = Self::read_bytes(payload, &mut pos, args_len)?;
            let _gas = Self::read_u64_le(payload, &mut pos)?;
            let deposit = Self::read_u128_le(payload, &mut pos)?;
            if deposit == 0 {
                return Err("storage_deposit requires attached deposit");
            }
            let args: serde_json::Value =
                serde_json::from_slice(args_bytes).map_err(|_| "invalid storage_deposit args")?;
            // registration_only must be true when present (Path C Intents deposits).
            if let Some(reg) = args.get("registration_only") {
                if reg.as_bool() != Some(true) {
                    return Err("storage_deposit registration_only must be true");
                }
            }
            let account_id = args
                .get("account_id")
                .and_then(|v| v.as_str())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .ok_or("storage_deposit account_id required")?;
            storage_account_id = Some(account_id);
        }

        let action_variant = Self::read_u8(payload, &mut pos)?;
        if action_variant != 2 {
            return Err("not a function call action");
        }
        let method_name = Self::read_borsh_string(payload, &mut pos)?;
        if method_name != "ft_transfer" {
            return Err("not an ft_transfer call");
        }
        let args_len = Self::read_u32_le(payload, &mut pos)? as usize;
        let args_bytes = Self::read_bytes(payload, &mut pos, args_len)?;
        let _gas = Self::read_u64_le(payload, &mut pos)?;
        let deposit = Self::read_u128_le(payload, &mut pos)?;
        if deposit != 1 {
            return Err("ft_transfer requires 1 yocto deposit");
        }
        if pos != payload.len() {
            return Err("unexpected trailing bytes");
        }

        let args: serde_json::Value =
            serde_json::from_slice(args_bytes).map_err(|_| "invalid ft_transfer args")?;
        let destination = args
            .get("receiver_id")
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .ok_or("ft_transfer receiver_id required")?;
        if let Some(storage_acct) = storage_account_id.as_ref() {
            if storage_acct != &destination {
                return Err("storage_deposit account_id must match ft_transfer receiver_id");
            }
        }
        let amount_str = args
            .get("amount")
            .and_then(|v| {
                if let Some(s) = v.as_str() {
                    Some(s.to_string())
                } else if let Some(n) = v.as_u64() {
                    Some(n.to_string())
                } else {
                    None
                }
            })
            .ok_or("ft_transfer amount required")?;
        let amount =
            Self::parse_token_amount_units(&amount_str).ok_or("invalid ft_transfer amount")?;
        if amount == 0 {
            return Err("ft_transfer amount must be positive");
        }

        Ok(ParsedNearFtTransfer {
            from_implicit,
            ft_contract,
            destination,
            amount,
        })
    }

    fn lamports_to_sol_amount_string(lamports: u64) -> String {
        let whole = lamports / 1_000_000_000;
        let frac = lamports % 1_000_000_000;
        if frac == 0 {
            return whole.to_string();
        }
        let mut frac_string = format!("{:09}", frac);
        while frac_string.ends_with('0') {
            frac_string.pop();
        }
        format!("{}.{}", whole, frac_string)
    }

    fn parse_solana_native_transfer(
        payload: &[u8],
    ) -> Result<ParsedSolanaNativeTransfer, &'static str> {
        let mut pos = 0usize;
        Self::read_u8(payload, &mut pos)?;
        Self::read_u8(payload, &mut pos)?;
        Self::read_u8(payload, &mut pos)?;

        let account_count = Self::read_shortvec(payload, &mut pos)?;
        let mut accounts: Vec<String> = Vec::with_capacity(account_count);
        for _ in 0..account_count {
            let bytes = Self::read_bytes(payload, &mut pos, 32)?;
            accounts.push(bs58::encode(bytes).into_string());
        }

        Self::read_bytes(payload, &mut pos, 32)?; // recent blockhash

        let instruction_count = Self::read_shortvec(payload, &mut pos)?;
        if instruction_count != 1 {
            return Err("expected exactly one instruction");
        }

        let program_id_index = Self::read_u8(payload, &mut pos)? as usize;
        let account_index_count = Self::read_shortvec(payload, &mut pos)?;
        if account_index_count != 2 {
            return Err("expected transfer account list");
        }
        let from_index = Self::read_u8(payload, &mut pos)? as usize;
        let destination_index = Self::read_u8(payload, &mut pos)? as usize;
        let data_len = Self::read_shortvec(payload, &mut pos)?;
        let data = Self::read_bytes(payload, &mut pos, data_len)?;

        if pos != payload.len() {
            return Err("unexpected trailing bytes");
        }
        if program_id_index >= accounts.len()
            || from_index >= accounts.len()
            || destination_index >= accounts.len()
        {
            return Err("account index out of range");
        }
        if accounts[program_id_index] != SOLANA_SYSTEM_PROGRAM_ID {
            return Err("not a system transfer");
        }
        if data.len() != 12 {
            return Err("unexpected instruction data len");
        }

        let instruction = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        if instruction != 2 {
            return Err("not a transfer opcode");
        }
        let lamports = u64::from_le_bytes([
            data[4], data[5], data[6], data[7], data[8], data[9], data[10], data[11],
        ]);

        Ok(ParsedSolanaNativeTransfer {
            from_public_key: accounts[from_index].clone(),
            destination: accounts[destination_index].clone(),
            lamports,
        })
    }

    fn read_u8(data: &[u8], pos: &mut usize) -> Result<u8, &'static str> {
        if *pos >= data.len() {
            return Err("unexpected eof");
        }
        let value = data[*pos];
        *pos += 1;
        Ok(value)
    }

    fn read_bytes<'a>(
        data: &'a [u8],
        pos: &mut usize,
        len: usize,
    ) -> Result<&'a [u8], &'static str> {
        if data.len().saturating_sub(*pos) < len {
            return Err("unexpected eof");
        }
        let start = *pos;
        *pos += len;
        Ok(&data[start..start + len])
    }

    fn read_shortvec(data: &[u8], pos: &mut usize) -> Result<usize, &'static str> {
        let mut result = 0usize;
        let mut shift = 0usize;
        loop {
            let byte = Self::read_u8(data, pos)? as usize;
            result |= (byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(result);
            }
            shift += 7;
            if shift > 28 {
                return Err("shortvec overflow");
            }
        }
    }

    fn push_index(&mut self, account: &AccountId, pk: String) {
        let mut current = self.subkey_index.get(account).unwrap_or_default();
        if !current.contains(&pk) {
            current.push(pk);
            self.subkey_index.insert(account, &current);
        }
    }

    fn drop_from_index(&mut self, account: &AccountId, pk: &str) {
        if let Some(mut current) = self.subkey_index.get(account) {
            current.retain(|k| k != pk);
            self.subkey_index.insert(account, &current);
        }
    }

    fn log_event(event: &str, data: serde_json::Value) {
        let payload = serde_json::json!({
            "standard": "safu-subkey",
            "version": "0.1.0",
            "event": event,
            "data": data
        });
        env::log_str(&payload.to_string());
    }

    fn normalize_api_key_policy(policy: ApiKeyPolicyV1) -> ApiKeyPolicyV1 {
        let version = policy.version.trim().to_string();
        let template_id = policy.template_id.trim().to_string();
        let asset_type = policy.asset_type.trim().to_lowercase();
        let asset_id = policy
            .asset_id
            .map(|item| item.trim().to_string())
            .filter(|item| !item.is_empty());
        let allow_destinations: Vec<String> = policy
            .allow_destinations
            .into_iter()
            .map(|item| item.trim().to_string())
            .filter(|item| !item.is_empty())
            .collect();

        require!(!version.is_empty(), "version required");
        require!(!template_id.is_empty(), "template_id required");
        require!(!asset_type.is_empty(), "asset_type required");
        require!(
            policy.max_per_tx_native.is_some(),
            "max_per_tx_native required"
        );
        if policy.max_per_period_native.is_some() || policy.max_tx_count_per_period.is_some() {
            require!(
                policy.period_seconds.unwrap_or(0) > 0,
                "period_seconds required"
            );
        }
        if let Some(max_per_tx_native) = policy.max_per_tx_native.as_ref() {
            require!(
                Self::parse_decimal_amount_to_units(max_per_tx_native.trim(), 18).is_some(),
                "invalid max_per_tx_native"
            );
        }
        if let Some(max_per_period_native) = policy.max_per_period_native.as_ref() {
            require!(
                Self::parse_decimal_amount_to_units(max_per_period_native.trim(), 18).is_some(),
                "invalid max_per_period_native"
            );
        }
        if let Some(spent) = policy.spent_this_period_native.as_ref() {
            require!(
                Self::parse_decimal_amount_to_units(spent.trim(), 18).is_some(),
                "invalid spent_this_period_native"
            );
        }

        ApiKeyPolicyV1 {
            version,
            template_id,
            asset_type,
            asset_id,
            max_per_tx_native: policy
                .max_per_tx_native
                .map(|item| item.trim().to_string())
                .filter(|item| !item.is_empty()),
            max_per_period_native: policy
                .max_per_period_native
                .map(|item| item.trim().to_string())
                .filter(|item| !item.is_empty()),
            period_seconds: policy.period_seconds.filter(|value| *value > 0),
            max_tx_count_per_period: policy.max_tx_count_per_period.filter(|value| *value > 0),
            allow_destinations,
            period_start_unix_seconds: policy.period_start_unix_seconds,
            spent_this_period_native: policy
                .spent_this_period_native
                .map(|item| item.trim().to_string())
                .filter(|item| !item.is_empty()),
            tx_count_this_period: policy.tx_count_this_period,
        }
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::{testing_env, AccountId};
    use std::any::Any;

    fn context(predecessor: AccountId, signer_pk: PublicKey) -> VMContextBuilder {
        let mut ctx = VMContextBuilder::new();
        ctx.predecessor_account_id(predecessor.clone());
        ctx.signer_account_id(predecessor);
        ctx.signer_account_pk(signer_pk);
        ctx
    }

    fn sample_paths() -> Vec<ChainPaths> {
        vec![ChainPaths {
            chain: Chain::Solana,
            paths: vec!["0".to_string(), "1".to_string()],
        }]
    }

    fn sample_paths_evm() -> Vec<ChainPaths> {
        vec![ChainPaths {
            chain: Chain::Evm,
            paths: vec!["0".to_string()],
        }]
    }

    fn make_solana_native_transfer_payload(
        from: &str,
        destination: &str,
        lamports: u64,
    ) -> Vec<u8> {
        let from_bytes = bs58::decode(from).into_vec().unwrap();
        let destination_bytes = bs58::decode(destination).into_vec().unwrap();
        let system_program_bytes = bs58::decode(SOLANA_SYSTEM_PROGRAM_ID).into_vec().unwrap();
        assert_eq!(from_bytes.len(), 32);
        assert_eq!(destination_bytes.len(), 32);
        assert_eq!(system_program_bytes.len(), 32);

        let mut payload = Vec::new();
        payload.extend_from_slice(&[1, 0, 1]); // legacy message header
        payload.extend_from_slice(&encode_shortvec(3)); // account key count
        payload.extend_from_slice(&from_bytes); // signer/from
        payload.extend_from_slice(&destination_bytes); // destination
        payload.extend_from_slice(&system_program_bytes); // program id
        payload.extend_from_slice(&[0u8; 32]); // recent blockhash
        payload.extend_from_slice(&encode_shortvec(1)); // instruction count
        payload.push(2); // program_id_index => system program
        payload.extend_from_slice(&encode_shortvec(2)); // account index count
        payload.push(0); // from index
        payload.push(1); // destination index
        payload.extend_from_slice(&encode_shortvec(12)); // transfer ix data len
        payload.extend_from_slice(&2u32.to_le_bytes()); // system transfer opcode
        payload.extend_from_slice(&lamports.to_le_bytes());
        payload
    }

    fn encode_shortvec(mut value: usize) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if value == 0 {
                break;
            }
        }
        out
    }

    fn write_borsh_string(out: &mut Vec<u8>, value: &str) {
        let bytes = value.as_bytes();
        out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(bytes);
    }

    fn implicit_hex_from_seed(seed: &[u8; 32]) -> String {
        hex::encode(seed).to_lowercase()
    }

    /// Build a minimal near-api-js `encodeTransaction` native Transfer payload for tests.
    fn make_near_native_transfer_payload(
        from_implicit: &str,
        destination: &str,
        yocto: u128,
        pubkey_seed: &[u8; 32],
        block_hash: &[u8; 32],
        nonce: u64,
    ) -> Vec<u8> {
        let mut payload = Vec::new();
        write_borsh_string(&mut payload, from_implicit);
        payload.push(0); // ED25519
        payload.extend_from_slice(pubkey_seed);
        payload.extend_from_slice(&nonce.to_le_bytes());
        write_borsh_string(&mut payload, destination);
        payload.extend_from_slice(block_hash);
        payload.extend_from_slice(&1u32.to_le_bytes()); // one action
        payload.push(3); // Transfer
        payload.extend_from_slice(&yocto.to_le_bytes());
        payload
    }

    /// Build a minimal NEAR `ft_transfer` FunctionCall payload for tests.
    fn make_near_ft_transfer_payload(
        from_implicit: &str,
        ft_contract: &str,
        destination: &str,
        amount: u128,
        pubkey_seed: &[u8; 32],
        block_hash: &[u8; 32],
        nonce: u64,
        gas: u64,
    ) -> Vec<u8> {
        make_near_ft_transfer_payload_with_storage(
            from_implicit,
            ft_contract,
            destination,
            amount,
            pubkey_seed,
            block_hash,
            nonce,
            gas,
            None,
        )
    }

    /// Optional `storage_deposit` (registration_only) + `ft_transfer`.
    fn make_near_ft_transfer_payload_with_storage(
        from_implicit: &str,
        ft_contract: &str,
        destination: &str,
        amount: u128,
        pubkey_seed: &[u8; 32],
        block_hash: &[u8; 32],
        nonce: u64,
        gas: u64,
        storage_deposit_yocto: Option<u128>,
    ) -> Vec<u8> {
        let ft_args = serde_json::json!({
            "receiver_id": destination,
            "amount": amount.to_string(),
        })
        .to_string();
        let ft_args_bytes = ft_args.as_bytes();

        let mut payload = Vec::new();
        write_borsh_string(&mut payload, from_implicit);
        payload.push(0); // ED25519
        payload.extend_from_slice(pubkey_seed);
        payload.extend_from_slice(&nonce.to_le_bytes());
        write_borsh_string(&mut payload, ft_contract);
        payload.extend_from_slice(block_hash);
        let action_count: u32 = if storage_deposit_yocto.is_some() { 2 } else { 1 };
        payload.extend_from_slice(&action_count.to_le_bytes());
        if let Some(storage_yocto) = storage_deposit_yocto {
            let storage_args = serde_json::json!({
                "account_id": destination,
                "registration_only": true,
            })
            .to_string();
            let storage_args_bytes = storage_args.as_bytes();
            payload.push(2); // FunctionCall
            write_borsh_string(&mut payload, "storage_deposit");
            payload.extend_from_slice(&(storage_args_bytes.len() as u32).to_le_bytes());
            payload.extend_from_slice(storage_args_bytes);
            payload.extend_from_slice(&gas.to_le_bytes());
            payload.extend_from_slice(&storage_yocto.to_le_bytes());
        }
        payload.push(2); // FunctionCall
        write_borsh_string(&mut payload, "ft_transfer");
        payload.extend_from_slice(&(ft_args_bytes.len() as u32).to_le_bytes());
        payload.extend_from_slice(ft_args_bytes);
        payload.extend_from_slice(&gas.to_le_bytes());
        payload.extend_from_slice(&1u128.to_le_bytes()); // 1 yocto deposit
        payload
    }

    fn sample_paths_near() -> Vec<ChainPaths> {
        vec![ChainPaths {
            chain: Chain::Near,
            paths: vec!["0".to_string()],
        }]
    }

    fn panic_to_string(err: Box<dyn Any + Send>) -> String {
        if let Some(msg) = err.downcast_ref::<&str>() {
            return (*msg).to_string();
        }
        if let Some(msg) = err.downcast_ref::<String>() {
            return msg.clone();
        }
        "unknown panic".to_string()
    }

    #[test]
    fn add_and_request_sign() {
        let signer_pk: PublicKey = "ed25519:7a4Jhtp5mf7f5ez7sJ57zoCbsrSq8JhuWYeAMJtURHTh"
            .parse()
            .unwrap();
        let ctx = context("alice.testnet".parse().unwrap(), signer_pk.clone());
        testing_env!(ctx.build());
        let mut contract = Contract::new(
            "owner.testnet".parse().unwrap(),
            "v1.signer-prod.testnet".parse().unwrap(),
        );

        contract.add_subkey(
            signer_pk.clone(),
            vec![ChainPaths {
                chain: Chain::Bitcoin,
                paths: vec!["0".to_string()],
            }],
        );

        let req = SignRequest {
            chain: Chain::Bitcoin,
            derivation_path: "0".to_string(),
            payload: Base64VecU8(vec![1, 2, 3]),
            memo: None,
        };

        // Should not panic (promise returned)
        let _ = contract.request_sign(req);
    }

    #[test]
    fn template_flow_happy_path() {
        let signer_pk: PublicKey = "ed25519:7a4Jhtp5mf7f5ez7sJ57zoCbsrSq8JhuWYeAMJtURHTh"
            .parse()
            .unwrap();
        let ctx = context("owner.testnet".parse().unwrap(), signer_pk.clone());
        testing_env!(ctx.build());
        let mut contract = Contract::new(
            "owner.testnet".parse().unwrap(),
            "v1.signer-prod.testnet".parse().unwrap(),
        );

        contract.set_template(TxTemplate {
            template_id: "solana-send".to_string(),
            chain: Chain::Solana,
            kind: TxKind::SolanaNative,
            allowed_tokens: None,
        });
        contract.set_token_cap(Chain::Solana, None, U128(1_000_000));

        contract.add_subkey(signer_pk.clone(), sample_paths());
        contract.owner_set_signer_policy(
            signer_pk.clone(),
            ApiKeyPolicyV1 {
                version: "v1".to_string(),
                template_id: "solana-send".to_string(),
                asset_type: "native".to_string(),
                asset_id: Some("solana-devnet".to_string()),
                max_per_tx_native: Some("0.000000010".to_string()),
                max_per_period_native: None,
                period_seconds: None,
                max_tx_count_per_period: None,
                allow_destinations: vec!["SomeSolanaAddress".to_string()],
                period_start_unix_seconds: None,
                spent_this_period_native: None,
                tx_count_this_period: None,
            },
        );

        let request = TemplateSignRequest {
            template_id: "solana-send".to_string(),
            chain: Chain::Solana,
            derivation_path: "0".to_string(),
            to: "SomeSolanaAddress".to_string(),
            amount: U128(5),
            token_contract: None,
            symbol: None,
            evm_chain_id: None,
            memo: None,
            evm_tx_params: None,
        };

        let _ = contract.request_template_sign(request);
    }

    #[test]
    fn parse_sol_amount_to_lamports_works() {
        assert_eq!(
            Contract::parse_sol_amount_to_lamports("0.02"),
            Some(20_000_000)
        );
        assert_eq!(
            Contract::parse_sol_amount_to_lamports("1"),
            Some(1_000_000_000)
        );
        assert_eq!(
            Contract::parse_sol_amount_to_lamports("0.000000001"),
            Some(1)
        );
        assert_eq!(Contract::parse_sol_amount_to_lamports(""), None);
        assert_eq!(Contract::parse_sol_amount_to_lamports("1.0000000001"), None);
    }

    #[test]
    fn parse_near_native_transfer_works() {
        let hex = "400000006438343764646535376336313561343637323732623865323465613562636438313938303064323064343732356630303963623761636332306233373133656100d847dde57c615a467272b8e24ea5bcd819800d20d4725f009cb7acc20b3713ea2a000000000000004000000031626237393434383066616364633861343566366235376538303532343433653662613437323439643861623536323530356264626566333661366536313639010101010101010101010101010101010101010101010101010101010101010101000000030000a0dec5adc9353600000000000000";
        let payload = hex::decode(hex).expect("hex decode");
        let parsed = Contract::parse_near_native_transfer(&payload).expect("parse near tx");
        assert_eq!(
            parsed.from_implicit,
            "d847dde57c615a467272b8e24ea5bcd819800d20d4725f009cb7acc20b3713ea"
        );
        assert_eq!(
            parsed.destination,
            "1bb794480facdc8a45f6b57e8052443e6ba47249d8ab562505bdbef36a6e6169"
        );
        assert_eq!(parsed.yocto, 1_000_000_000_000_000_000_000);
    }

    #[test]
    fn near_persisted_policy_enforced_without_policy_memo() {
        let signer_pk: PublicKey = "ed25519:7a4Jhtp5mf7f5ez7sJ57zoCbsrSq8JhuWYeAMJtURHTh"
            .parse()
            .unwrap();
        let ctx = context("alice.testnet".parse().unwrap(), signer_pk.clone());
        testing_env!(ctx.build());
        let mut contract = Contract::new(
            "owner.testnet".parse().unwrap(),
            "v1.signer-prod.testnet".parse().unwrap(),
        );

        contract.add_subkey(
            signer_pk.clone(),
            vec![ChainPaths {
                chain: Chain::Near,
                paths: vec!["0".to_string()],
            }],
        );

        let _from = "d847dde57c615a467272b8e24ea5bcd819800d20d4725f009cb7acc20b3713ea".to_string();
        let destination =
            "1bb794480facdc8a45f6b57e8052443e6ba47249d8ab562505bdbef36a6e6169".to_string();
        contract.owner_set_signer_policy(
            signer_pk.clone(),
            ApiKeyPolicyV1 {
                version: "v1".to_string(),
                template_id: "near_native_transfer_v1".to_string(),
                asset_type: "native".to_string(),
                asset_id: Some("NEAR".to_string()),
                max_per_tx_native: Some("0.002".to_string()),
                max_per_period_native: None,
                period_seconds: None,
                max_tx_count_per_period: None,
                allow_destinations: vec![destination.clone()],
                period_start_unix_seconds: None,
                spent_this_period_native: None,
                tx_count_this_period: None,
            },
        );

        let hex = "400000006438343764646535376336313561343637323732623865323465613562636438313938303064323064343732356630303963623761636332306233373133656100d847dde57c615a467272b8e24ea5bcd819800d20d4725f009cb7acc20b3713ea2a000000000000004000000031626237393434383066616364633861343566366235376538303532343433653662613437323439643861623536323530356264626566333661366536313639010101010101010101010101010101010101010101010101010101010101010101000000030000a0dec5adc9353600000000000000";
        let payload = hex::decode(hex).expect("hex decode");
        Contract::parse_near_native_transfer(&payload).expect("preflight parse");

        let in_limit_req = SignRequest {
            chain: Chain::Near,
            derivation_path: "0".to_string(),
            payload: Base64VecU8(payload.clone()),
            memo: None,
        };
        let _ = contract.request_sign_v2("req-near-in-limit".to_string(), in_limit_req);

        let mut over_payload = payload.clone();
        let deposit_offset = over_payload.len() - 16;
        over_payload[deposit_offset..deposit_offset + 16]
            .copy_from_slice(&3_000_000_000_000_000_000_000u128.to_le_bytes());

        let over_limit_req = SignRequest {
            chain: Chain::Near,
            derivation_path: "0".to_string(),
            payload: Base64VecU8(over_payload),
            memo: None,
        };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = contract.request_sign_v2("req-near-over-limit".to_string(), over_limit_req);
        }));

        assert!(result.is_err());
        let panic_text = panic_to_string(result.unwrap_err());
        assert!(panic_text.contains("limit_per_tx_native_exceeded"));
    }

    #[test]
    fn near_policy_rejects_wrong_destination() {
        let signer_pk: PublicKey = "ed25519:7a4Jhtp5mf7f5ez7sJ57zoCbsrSq8JhuWYeAMJtURHTh"
            .parse()
            .unwrap();
        let ctx = context("alice.testnet".parse().unwrap(), signer_pk.clone());
        testing_env!(ctx.build());
        let mut contract = Contract::new(
            "owner.testnet".parse().unwrap(),
            "v1.signer-prod.testnet".parse().unwrap(),
        );

        contract.add_subkey(signer_pk.clone(), sample_paths_near());

        let from = "d847dde57c615a467272b8e24ea5bcd819800d20d4725f009cb7acc20b3713ea";
        let allowed = "1bb794480facdc8a45f6b57e8052443e6ba47249d8ab562505bdbef36a6e6169";
        let blocked = "9ca3d0f7befc77e4d38eb810ca02675bfc4897482ed329232ca1eaf18c6e9f9b";

        contract.owner_set_signer_policy(
            signer_pk.clone(),
            ApiKeyPolicyV1 {
                version: "v1".to_string(),
                template_id: "near_native_transfer_v1".to_string(),
                asset_type: "native".to_string(),
                asset_id: Some("NEAR".to_string()),
                max_per_tx_native: Some("1".to_string()),
                max_per_period_native: None,
                period_seconds: None,
                max_tx_count_per_period: None,
                allow_destinations: vec![allowed.to_string()],
                period_start_unix_seconds: None,
                spent_this_period_native: None,
                tx_count_this_period: None,
            },
        );

        let payload = make_near_native_transfer_payload(
            from,
            blocked,
            1_000_000_000_000_000_000_000,
            &[7u8; 32],
            &[9u8; 32],
            1,
        );

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = contract.request_sign_v2(
                "req-near-bad-dest".to_string(),
                SignRequest {
                    chain: Chain::Near,
                    derivation_path: "0".to_string(),
                    payload: Base64VecU8(payload),
                    memo: None,
                },
            );
        }));

        assert!(result.is_err());
        let panic_text = panic_to_string(result.unwrap_err());
        assert!(panic_text.contains("destination_not_allowed"));
    }

    #[test]
    fn near_policy_rejects_malformed_payload() {
        let parsed = Contract::parse_near_native_transfer(&[0x01, 0x02, 0x03]);
        assert!(parsed.is_err());
    }

    #[test]
    fn parse_near_ft_transfer_works() {
        let from = "d847dde57c615a467272b8e24ea5bcd819800d20d4725f009cb7acc20b3713ea";
        let destination = "1bb794480facdc8a45f6b57e8052443e6ba47249d8ab562505bdbef36a6e6169";
        let ft_contract = "usdc.near";
        let payload = make_near_ft_transfer_payload(
            from,
            ft_contract,
            destination,
            1_500_000,
            &[3u8; 32],
            &[4u8; 32],
            7,
            30_000_000_000_000,
        );
        let parsed = Contract::parse_near_ft_transfer(&payload).expect("parse ft transfer");
        assert_eq!(parsed.from_implicit, from);
        assert_eq!(parsed.ft_contract, ft_contract);
        assert_eq!(parsed.destination, destination);
        assert_eq!(parsed.amount, 1_500_000);
    }

    #[test]
    fn parse_near_ft_transfer_with_storage_deposit_works() {
        let from = "d847dde57c615a467272b8e24ea5bcd819800d20d4725f009cb7acc20b3713ea";
        let destination = "c1200a0efaec775672b46ef1a6fc64f53498e83bf396dbddf8bab96b58823708";
        let ft_contract = "17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1";
        let payload = make_near_ft_transfer_payload_with_storage(
            from,
            ft_contract,
            destination,
            5_000_000,
            &[3u8; 32],
            &[4u8; 32],
            7,
            30_000_000_000_000,
            Some(1_250_000_000_000_000_000_000),
        );
        let parsed = Contract::parse_near_ft_transfer(&payload).expect("parse ft+storage");
        assert_eq!(parsed.from_implicit, from);
        assert_eq!(parsed.ft_contract, ft_contract);
        assert_eq!(parsed.destination, destination);
        assert_eq!(parsed.amount, 5_000_000);
    }

    #[test]
    fn near_ft_policy_rejects_wrong_token_and_over_cap() {
        let signer_pk: PublicKey = "ed25519:7a4Jhtp5mf7f5ez7sJ57zoCbsrSq8JhuWYeAMJtURHTh"
            .parse()
            .unwrap();
        let ctx = context("alice.testnet".parse().unwrap(), signer_pk.clone());
        testing_env!(ctx.build());
        let mut contract = Contract::new(
            "owner.testnet".parse().unwrap(),
            "v1.signer-prod.testnet".parse().unwrap(),
        );

        contract.add_subkey(
            signer_pk.clone(),
            vec![ChainPaths {
                chain: Chain::Near,
                paths: vec!["0".to_string()],
            }],
        );

        let from = "d847dde57c615a467272b8e24ea5bcd819800d20d4725f009cb7acc20b3713ea";
        let destination = "1bb794480facdc8a45f6b57e8052443e6ba47249d8ab562505bdbef36a6e6169";
        let ft_contract = "usdc.near";
        contract.owner_set_signer_policy(
            signer_pk.clone(),
            ApiKeyPolicyV1 {
                version: "v1".to_string(),
                template_id: "near_ft_transfer_v1".to_string(),
                asset_type: "token".to_string(),
                asset_id: Some(ft_contract.to_string()),
                max_per_tx_native: Some("2000000".to_string()),
                max_per_period_native: None,
                period_seconds: None,
                max_tx_count_per_period: None,
                allow_destinations: vec![destination.to_string()],
                period_start_unix_seconds: None,
                spent_this_period_native: None,
                tx_count_this_period: None,
            },
        );

        let in_limit = make_near_ft_transfer_payload(
            from,
            ft_contract,
            destination,
            1_000_000,
            &[3u8; 32],
            &[4u8; 32],
            1,
            30_000_000_000_000,
        );
        let _ = contract.request_sign_v2(
            "req-near-ft-ok".to_string(),
            SignRequest {
                chain: Chain::Near,
                derivation_path: "0".to_string(),
                payload: Base64VecU8(in_limit),
                memo: None,
            },
        );

        let wrong_token = make_near_ft_transfer_payload(
            from,
            "weth.near",
            destination,
            1_000_000,
            &[3u8; 32],
            &[4u8; 32],
            2,
            30_000_000_000_000,
        );
        let wrong = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = contract.request_sign_v2(
                "req-near-ft-wrong-token".to_string(),
                SignRequest {
                    chain: Chain::Near,
                    derivation_path: "0".to_string(),
                    payload: Base64VecU8(wrong_token),
                    memo: None,
                },
            );
        }));
        assert!(wrong.is_err());
        assert!(panic_to_string(wrong.unwrap_err()).contains("token_not_allowed"));

        let over = make_near_ft_transfer_payload(
            from,
            ft_contract,
            destination,
            3_000_000,
            &[3u8; 32],
            &[4u8; 32],
            3,
            30_000_000_000_000,
        );
        let over_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = contract.request_sign_v2(
                "req-near-ft-over".to_string(),
                SignRequest {
                    chain: Chain::Near,
                    derivation_path: "0".to_string(),
                    payload: Base64VecU8(over),
                    memo: None,
                },
            );
        }));
        assert!(over_result.is_err());
        assert!(panic_to_string(over_result.unwrap_err()).contains("limit_per_tx_native_exceeded"));
    }

    #[test]
    fn near_ft_parser_rejects_wrong_method_and_deposit() {
        let from = "d847dde57c615a467272b8e24ea5bcd819800d20d4725f009cb7acc20b3713ea";
        let destination = "1bb794480facdc8a45f6b57e8052443e6ba47249d8ab562505bdbef36a6e6169";
        let mut payload = make_near_ft_transfer_payload(
            from,
            "usdc.near",
            destination,
            100,
            &[1u8; 32],
            &[2u8; 32],
            1,
            1,
        );
        // Corrupt deposit (last 16 bytes) to 0
        let len = payload.len();
        payload[len - 16..].copy_from_slice(&0u128.to_le_bytes());
        assert!(Contract::parse_near_ft_transfer(&payload).is_err());

        // Native transfer must not parse as FT
        let native = make_near_native_transfer_payload(from, destination, 1, &[1u8; 32], &[2u8; 32], 1);
        assert!(Contract::parse_near_ft_transfer(&native).is_err());
    }

    #[test]
    fn bootstrap_native_policy_allows_near_ft_when_dest_allowlist_empty() {
        let signer_pk: PublicKey = "ed25519:7a4Jhtp5mf7f5ez7sJ57zoCbsrSq8JhuWYeAMJtURHTh"
            .parse()
            .unwrap();
        let ctx = context("alice.testnet".parse().unwrap(), signer_pk.clone());
        testing_env!(ctx.build());
        let mut contract = Contract::new(
            "owner.testnet".parse().unwrap(),
            "v1.signer-prod.testnet".parse().unwrap(),
        );

        contract.add_subkey(
            signer_pk.clone(),
            vec![ChainPaths {
                chain: Chain::Near,
                paths: vec!["0".to_string()],
            }],
        );

        // Mirrors frontend bootstrap policy (sol_native + empty destinations).
        contract.owner_set_signer_policy(
            signer_pk.clone(),
            ApiKeyPolicyV1 {
                version: "v1".to_string(),
                template_id: "sol_native_transfer_v1".to_string(),
                asset_type: "native".to_string(),
                asset_id: None,
                max_per_tx_native: Some("100000000000".to_string()),
                max_per_period_native: None,
                period_seconds: None,
                max_tx_count_per_period: None,
                allow_destinations: vec![],
                period_start_unix_seconds: None,
                spent_this_period_native: None,
                tx_count_this_period: None,
            },
        );

        let from = "d847dde57c615a467272b8e24ea5bcd819800d20d4725f009cb7acc20b3713ea";
        let destination = "392f24d8c93470946c2d8773d642879aecbeb4cd5fefc97628e0cd8e42684901";
        let ft_contract = "17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1";
        let payload = make_near_ft_transfer_payload_with_storage(
            from,
            ft_contract,
            destination,
            5_000_000,
            &[3u8; 32],
            &[4u8; 32],
            7,
            30_000_000_000_000,
            Some(1_250_000_000_000_000_000_000),
        );
        let _ = contract.request_sign_v2(
            "req-bootstrap-ft".to_string(),
            SignRequest {
                chain: Chain::Near,
                derivation_path: "0".to_string(),
                payload: Base64VecU8(payload),
                memo: None,
            },
        );
    }

    #[test]
    fn persisted_policy_enforced_without_policy_memo() {
        let signer_pk: PublicKey = "ed25519:7a4Jhtp5mf7f5ez7sJ57zoCbsrSq8JhuWYeAMJtURHTh"
            .parse()
            .unwrap();
        let ctx = context("alice.testnet".parse().unwrap(), signer_pk.clone());
        testing_env!(ctx.build());
        let mut contract = Contract::new(
            "owner.testnet".parse().unwrap(),
            "v1.signer-prod.testnet".parse().unwrap(),
        );

        contract.add_subkey(
            signer_pk.clone(),
            vec![ChainPaths {
                chain: Chain::Solana,
                paths: vec!["0".to_string()],
            }],
        );

        let destination = bs58::encode([7u8; 32]).into_string();
        let from = bs58::encode([9u8; 32]).into_string();
        contract.owner_set_signer_policy(
            signer_pk.clone(),
            ApiKeyPolicyV1 {
                version: "v1".to_string(),
                template_id: "sol_native_transfer_v1".to_string(),
                asset_type: "native".to_string(),
                asset_id: Some("solana-devnet".to_string()),
                max_per_tx_native: Some("0.0117".to_string()),
                max_per_period_native: None,
                period_seconds: None,
                max_tx_count_per_period: None,
                allow_destinations: vec![destination.clone()],
                period_start_unix_seconds: None,
                spent_this_period_native: None,
                tx_count_this_period: None,
            },
        );

        let in_limit_req = SignRequest {
            chain: Chain::Solana,
            derivation_path: "0".to_string(),
            payload: Base64VecU8(make_solana_native_transfer_payload(
                &from,
                &destination,
                11_600_000,
            )),
            memo: None,
        };
        let _ = contract.request_sign_v2("req-in-limit".to_string(), in_limit_req);

        let over_limit_req = SignRequest {
            chain: Chain::Solana,
            derivation_path: "0".to_string(),
            payload: Base64VecU8(make_solana_native_transfer_payload(
                &from,
                &destination,
                11_800_000,
            )),
            memo: None,
        };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = contract.request_sign_v2("req-over-limit".to_string(), over_limit_req);
        }));

        assert!(result.is_err());
        let panic_text = panic_to_string(result.unwrap_err());
        assert!(panic_text.contains("limit_per_tx_native_exceeded"));
    }

    #[test]
    fn evm_template_policy_enforced() {
        let signer_pk: PublicKey = "ed25519:7a4Jhtp5mf7f5ez7sJ57zoCbsrSq8JhuWYeAMJtURHTh"
            .parse()
            .unwrap();
        let ctx = context("owner.testnet".parse().unwrap(), signer_pk.clone());
        testing_env!(ctx.build());
        let mut contract = Contract::new(
            "owner.testnet".parse().unwrap(),
            "v1.signer-prod.testnet".parse().unwrap(),
        );

        contract.set_template(TxTemplate {
            template_id: "evm-native-send".to_string(),
            chain: Chain::Evm,
            kind: TxKind::EvmNative,
            allowed_tokens: None,
        });
        contract.add_subkey(signer_pk.clone(), sample_paths_evm());
        contract.owner_set_signer_policy(
            signer_pk.clone(),
            ApiKeyPolicyV1 {
                version: "v1".to_string(),
                template_id: "evm-native-send".to_string(),
                asset_type: "native".to_string(),
                asset_id: Some("eth".to_string()),
                max_per_tx_native: Some("0.500000000000000000".to_string()),
                max_per_period_native: None,
                period_seconds: None,
                max_tx_count_per_period: None,
                allow_destinations: vec!["0xabc".to_string()],
                period_start_unix_seconds: None,
                spent_this_period_native: None,
                tx_count_this_period: None,
            },
        );

        let in_limit = TemplateSignRequest {
            template_id: "evm-native-send".to_string(),
            chain: Chain::Evm,
            derivation_path: "0".to_string(),
            to: "0xabc".to_string(),
            amount: U128(500_000_000_000_000_000),
            token_contract: None,
            symbol: Some("ETH".to_string()),
            evm_chain_id: Some("11155111".to_string()),
            memo: None,
            evm_tx_params: Some(EvmTxParams {
                nonce: 0,
                gas_limit: 21_000,
                max_fee_per_gas: U128(1_000_000_000),
                max_priority_fee_per_gas: U128(1_000_000_000),
                data: None,
            }),
        };
        let _ = contract.request_template_sign(in_limit);

        let over_limit = TemplateSignRequest {
            template_id: "evm-native-send".to_string(),
            chain: Chain::Evm,
            derivation_path: "0".to_string(),
            to: "0xabc".to_string(),
            amount: U128(600_000_000_000_000_000),
            token_contract: None,
            symbol: Some("ETH".to_string()),
            evm_chain_id: Some("11155111".to_string()),
            memo: None,
            evm_tx_params: Some(EvmTxParams {
                nonce: 0,
                gas_limit: 21_000,
                max_fee_per_gas: U128(1_000_000_000),
                max_priority_fee_per_gas: U128(1_000_000_000),
                data: None,
            }),
        };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = contract.request_template_sign(over_limit);
        }));

        assert!(result.is_err());
        let panic_text = panic_to_string(result.unwrap_err());
        assert!(panic_text.contains("limit_per_tx_native_exceeded"));
    }

    // ── Property-based tests ─────────────────────────────────────────────────

    #[test]
    fn eip3009_transfer_auth_hash_matches_viem() {
        let signer_pk: PublicKey = "ed25519:7a4Jhtp5mf7f5ez7sJ57zoCbsrSq8JhuWYeAMJtURHTh"
            .parse()
            .unwrap();
        let ctx = context("alice.testnet".parse().unwrap(), signer_pk);
        testing_env!(ctx.build());

        let token = Contract::parse_evm_address("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913");
        let from = Contract::parse_evm_address("0x857b06519E91e3A54538791bDbb0E22373e36b66");
        let to = Contract::parse_evm_address("0xD593832Ce9C2B13B192ba50B55dd9AF44e96700d");
        let nonce = hex::decode("f3746613c2d920b5fdabc0856f2aeb2d4f88ee6037b8cc5d04a71a4462f13480")
            .unwrap();
        let mut nonce32 = [0u8; 32];
        nonce32.copy_from_slice(&nonce);

        let digest = Contract::build_eip3009_transfer_auth_hash(
            "USD Coin",
            "2",
            8453,
            &token,
            &from,
            &to,
            10_000,
            0,
            1_740_672_154,
            &nonce32,
        );
        assert_eq!(
            hex::encode(digest),
            "c9d71a9c1d0a61c278af1f204c10bf1884605cf0cd2c957074c98ad1c91dad64"
        );
    }

    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(12))]

        /// lamports → SOL string → lamports round-trip for representable values.
        #[test]
        fn prop_lamports_sol_roundtrip(lamports in 0u64..=10_000_000_000u64) {
            let sol = Contract::lamports_to_sol_amount_string(lamports);
            let parsed = Contract::parse_sol_amount_to_lamports(&sol)
                .expect("parsed formatted SOL amount");
            prop_assert_eq!(parsed, lamports);
        }

        /// Valid decimal strings within precision parse to Some and fit chain decimals.
        #[test]
        fn prop_decimal_whole_part_parses(
            whole in 0u32..1_000_000,
            frac_digits in 0usize..=9,
            frac in 0u32..1_000_000_000,
        ) {
            let frac_str = format!("{:0width$}", frac, width = frac_digits.min(9));
            let trimmed_frac = frac_str.chars().take(frac_digits).collect::<String>();
            let amount = if frac_digits == 0 {
                whole.to_string()
            } else {
                format!("{}.{trimmed_frac}", whole)
            };

            if let Some(units) = Contract::parse_decimal_amount_to_units(&amount, 9) {
                prop_assert!(units <= u128::from(u64::MAX));
                if frac_digits <= 9 {
                    let lamports = Contract::parse_sol_amount_to_lamports(&amount);
                    if units <= u128::from(u64::MAX) {
                        prop_assert_eq!(lamports, Some(u64::try_from(units).unwrap()));
                    }
                }
            }
        }

        /// Extra fractional digits beyond chain precision must be rejected.
        #[test]
        fn prop_decimal_rejects_excess_fractional_digits(
            whole in 1u32..10_000,
            extra in prop::collection::vec(any::<u8>(), 10..=16),
        ) {
            let frac: String = extra.into_iter().map(|b| char::from(b'0' + (b % 10))).collect();
            let amount = format!("{}.{frac}", whole);
            prop_assert!(Contract::parse_decimal_amount_to_units(&amount, 9).is_none());
            prop_assert!(Contract::parse_sol_amount_to_lamports(&amount).is_none());
        }

        /// Policy limit parsing is consistent with generic decimal parsing for SOL.
        #[test]
        fn prop_policy_limit_matches_decimal_parser(
            lamports in 1u64..=5_000_000_000u64,
        ) {
            let sol = Contract::lamports_to_sol_amount_string(lamports);
            let from_policy = Contract::parse_policy_native_limit_units(&Chain::Solana, &sol);
            let from_decimal = Contract::parse_decimal_amount_to_units(&sol, 9);
            prop_assert_eq!(from_policy, from_decimal);
        }

        /// Built Solana native transfer payloads round-trip through the parser.
        #[test]
        fn prop_solana_native_transfer_roundtrip(
            from_seed in prop::array::uniform32(1u8..=255),
            dest_seed in prop::array::uniform32(1u8..=255),
            lamports in 1u64..=1_000_000u64,
        ) {
            let from = bs58::encode(from_seed).into_string();
            let destination = bs58::encode(dest_seed).into_string();
            let payload = make_solana_native_transfer_payload(&from, &destination, lamports);
            let parsed = Contract::parse_solana_native_transfer(&payload)
                .expect("parse solana native transfer");
            prop_assert_eq!(parsed.from_public_key, from);
            prop_assert_eq!(parsed.destination, destination);
            prop_assert_eq!(parsed.lamports, lamports);
        }

        /// Built NEAR native transfer payloads round-trip through the parser.
        #[test]
        fn prop_near_native_transfer_roundtrip(
            from_seed in prop::array::uniform32(1u8..=255),
            dest_seed in prop::array::uniform32(1u8..=255),
            pubkey_seed in prop::array::uniform32(1u8..=255),
            block_seed in prop::array::uniform32(0u8..=255),
            yocto in 1u128..=1_000_000_000_000_000_000_000u128,
            nonce in 1u64..=1_000_000u64,
        ) {
            let from = implicit_hex_from_seed(&from_seed);
            let destination = implicit_hex_from_seed(&dest_seed);
            let payload = make_near_native_transfer_payload(
                &from,
                &destination,
                yocto,
                &pubkey_seed,
                &block_seed,
                nonce,
            );
            let parsed = Contract::parse_near_native_transfer(&payload)
                .expect("parse near native transfer");
            prop_assert_eq!(parsed.from_implicit, from);
            prop_assert_eq!(parsed.destination, destination);
            prop_assert_eq!(parsed.yocto, yocto);
        }

        /// NEAR policy limit parsing uses 24 decimal places (yoctoNEAR).
        #[test]
        fn prop_near_policy_limit_matches_decimal_parser(
            whole in 0u32..10_000,
            frac_digits in 0usize..=24,
            frac in 0u128..1_000_000_000_000_000_000_000_000u128,
        ) {
            let frac_str = format!("{:0width$}", frac, width = frac_digits.min(24));
            let trimmed_frac = frac_str.chars().take(frac_digits).collect::<String>();
            let amount = if frac_digits == 0 {
                whole.to_string()
            } else {
                format!("{}.{trimmed_frac}", whole)
            };

            if let Some(units) = Contract::parse_decimal_amount_to_units(&amount, 24) {
                let from_policy =
                    Contract::parse_policy_native_limit_units(&Chain::Near, &amount);
                prop_assert_eq!(from_policy, Some(units));
            }
        }

        /// Trailing bytes after a valid NEAR transfer must be rejected.
        #[test]
        fn prop_near_parser_rejects_trailing_bytes(
            from_seed in prop::array::uniform32(1u8..=255),
            dest_seed in prop::array::uniform32(1u8..=255),
            extra in prop::collection::vec(any::<u8>(), 1..=8),
        ) {
            let from = implicit_hex_from_seed(&from_seed);
            let destination = implicit_hex_from_seed(&dest_seed);
            let mut payload = make_near_native_transfer_payload(
                &from,
                &destination,
                1,
                &[1u8; 32],
                &[2u8; 32],
                1,
            );
            payload.extend_from_slice(&extra);
            prop_assert!(Contract::parse_near_native_transfer(&payload).is_err());
        }

        /// Built NEAR ft_transfer payloads round-trip through the parser.
        #[test]
        fn prop_near_ft_transfer_roundtrip(
            from_seed in prop::array::uniform32(1u8..=255),
            dest_seed in prop::array::uniform32(1u8..=255),
            token_seed in prop::array::uniform32(1u8..=255),
            pubkey_seed in prop::array::uniform32(1u8..=255),
            block_seed in prop::array::uniform32(0u8..=255),
            amount in 1u128..=1_000_000_000_000u128,
            nonce in 1u64..=1_000_000u64,
        ) {
            let from = implicit_hex_from_seed(&from_seed);
            let destination = implicit_hex_from_seed(&dest_seed);
            let ft_contract = format!("{}.near", &hex::encode(token_seed)[..16]);
            let payload = make_near_ft_transfer_payload(
                &from,
                &ft_contract,
                &destination,
                amount,
                &pubkey_seed,
                &block_seed,
                nonce,
                30_000_000_000_000,
            );
            let parsed =
                Contract::parse_near_ft_transfer(&payload).expect("parse near ft transfer");
            prop_assert_eq!(parsed.from_implicit, from);
            prop_assert_eq!(parsed.ft_contract, ft_contract);
            prop_assert_eq!(parsed.destination, destination);
            prop_assert_eq!(parsed.amount, amount);
        }
    }
}
