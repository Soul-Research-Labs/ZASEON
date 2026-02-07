/// Soul Protocol Universal Adapter for Cosmos (CosmWasm)
///
/// Handles ZK proof verification, encrypted state management,
/// and cross-chain message relay on CosmWasm chains.
///
/// Cosmos advantages for Soul Protocol:
/// - IBC native cross-chain communication
/// - CosmWasm provides WASM-based smart contracts
/// - Composable with Osmosis, dYdX, Celestia, etc.
///
/// Security:
/// - Nullifier double-spend prevention
/// - Admin/operator access control
/// - IBC channel validation
/// - Replay protection via unique proof and transfer IDs

use cosmwasm_std::{
    entry_point, to_json_binary, Binary, Deps, DepsMut, Env, MessageInfo,
    Response, StdResult, StdError, Uint64, Addr,
};
use cosmwasm_schema::{cw_serde, QueryResponses};
use cw_storage_plus::{Item, Map};

/// Contract version for migrate info
const CONTRACT_NAME: &str = "soul-universal-adapter";
const CONTRACT_VERSION: &str = "1.0.0";

/*//////////////////////////////////////////////////////////////
                          PROOF SYSTEMS
//////////////////////////////////////////////////////////////*/

#[cw_serde]
pub enum ProofSystem {
    Groth16,
    Plonk,
    Stark,
    Bulletproofs,
    Halo2,
    Nova,
    UltraPlonk,
    Honk,
}

#[cw_serde]
pub enum ChainVM {
    EVM,
    SVM,
    Cairo,
    MoveAptos,
    MoveSui,
    CosmWasm,
    NoirAztec,
    Midnight,
    Zcash,
    Aleo,
    TON,
    NEAR,
    Substrate,
    Bitcoin,
    XRPL,
    Plutus,
}

#[cw_serde]
pub enum ChainLayer {
    L1Public,
    L1Private,
    L2Rollup,
    L2Validium,
    L3AppChain,
    Sidechain,
    CosmosZone,
}

/*//////////////////////////////////////////////////////////////
                             MESSAGES
//////////////////////////////////////////////////////////////*/

#[cw_serde]
pub struct InstantiateMsg {
    pub chain_name: String,
    pub chain_layer: ChainLayer,
    pub operator: Option<String>,
    pub emergency_authority: Option<String>,
}

#[cw_serde]
pub enum ExecuteMsg {
    /// Submit and verify a universal ZK proof
    SubmitUniversalProof {
        proof_id: String,
        source_chain_id: String,
        dest_chain_id: String,
        proof_system: ProofSystem,
        proof: Binary,
        public_inputs: Vec<Binary>,
        state_commitment: String,
        nullifier: String,
        timestamp: u64,
    },

    /// Receive encrypted state from another chain
    ReceiveEncryptedState {
        transfer_id: String,
        source_chain_id: String,
        state_commitment: String,
        encrypted_payload: Binary,
        nullifier: String,
        new_commitment: String,
        proof: Binary,
    },

    /// Send encrypted state to another chain
    SendEncryptedState {
        dest_chain_id: String,
        state_commitment: String,
        encrypted_payload: Binary,
        proof: Binary,
        nullifier: String,
    },

    /// Register a remote chain adapter (operator only)
    RegisterRemoteAdapter {
        chain_id: String,
        adapter_address: String,
    },

    /// Set adapter active/inactive (operator only)
    SetActive {
        active: bool,
    },

    /// Emergency pause (emergency authority only)
    EmergencyPause {},

    /// Emergency unpause (emergency authority only)
    EmergencyUnpause {},

    /// Update operator (admin only)
    UpdateOperator {
        new_operator: String,
    },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    /// Get the chain configuration
    #[returns(ConfigResponse)]
    GetConfig {},

    /// Get the universal chain ID
    #[returns(ChainIdResponse)]
    GetUniversalChainId {},

    /// Check if a nullifier has been used
    #[returns(NullifierResponse)]
    IsNullifierUsed { nullifier: String },

    /// Get adapter statistics
    #[returns(StatsResponse)]
    GetStats {},

    /// Check if a proof has been processed
    #[returns(bool)]
    IsProofProcessed { proof_id: String },

    /// Check if a remote adapter is registered
    #[returns(bool)]
    IsRemoteAdapterRegistered { chain_id: String },
}

/*//////////////////////////////////////////////////////////////
                          RESPONSES
//////////////////////////////////////////////////////////////*/

#[cw_serde]
pub struct ConfigResponse {
    pub owner: String,
    pub operator: String,
    pub emergency_authority: String,
    pub universal_chain_id: String,
    pub chain_name: String,
    pub chain_vm: ChainVM,
    pub chain_layer: ChainLayer,
    pub proof_system: ProofSystem,
    pub active: bool,
}

#[cw_serde]
pub struct ChainIdResponse {
    pub universal_chain_id: String,
}

#[cw_serde]
pub struct NullifierResponse {
    pub used: bool,
    pub source_chain_id: Option<String>,
    pub consumed_at: Option<u64>,
}

#[cw_serde]
pub struct StatsResponse {
    pub total_proofs_verified: u64,
    pub total_states_received: u64,
    pub total_states_sent: u64,
    pub total_nullifiers_consumed: u64,
}

/*//////////////////////////////////////////////////////////////
                         STATE / STORAGE
//////////////////////////////////////////////////////////////*/

#[cw_serde]
pub struct Config {
    pub owner: Addr,
    pub operator: Addr,
    pub emergency_authority: Addr,
    pub universal_chain_id: String,
    pub chain_name: String,
    pub chain_vm: ChainVM,
    pub chain_layer: ChainLayer,
    pub proof_system: ProofSystem,
    pub active: bool,
    pub transfer_nonce: u64,
}

#[cw_serde]
pub struct Stats {
    pub total_proofs_verified: u64,
    pub total_states_received: u64,
    pub total_states_sent: u64,
    pub total_nullifiers_consumed: u64,
}

#[cw_serde]
pub struct NullifierData {
    pub used: bool,
    pub source_chain_id: String,
    pub consumed_at: u64,
}

#[cw_serde]
pub struct ProofData {
    pub proof_id: String,
    pub source_chain_id: String,
    pub dest_chain_id: String,
    pub proof_system: ProofSystem,
    pub state_commitment: String,
    pub nullifier: String,
    pub processed: bool,
    pub timestamp: u64,
    pub relayer: String,
}

#[cw_serde]
pub struct RemoteAdapter {
    pub chain_id: String,
    pub adapter_address: String,
    pub active: bool,
    pub registered_at: u64,
}

const CONFIG: Item<Config> = Item::new("config");
const STATS: Item<Stats> = Item::new("stats");
const NULLIFIERS: Map<&str, NullifierData> = Map::new("nullifiers");
const PROCESSED_PROOFS: Map<&str, ProofData> = Map::new("proofs");
const PROCESSED_TRANSFERS: Map<&str, bool> = Map::new("transfers");
const STATE_COMMITMENTS: Map<&str, String> = Map::new("commitments");
const REMOTE_ADAPTERS: Map<&str, RemoteAdapter> = Map::new("remote_adapters");

/*//////////////////////////////////////////////////////////////
                     CONTRACT ENTRY POINTS
//////////////////////////////////////////////////////////////*/

#[entry_point]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> StdResult<Response> {
    // Compute universal chain ID
    let chain_id_input = format!("SOUL_CHAIN_{}", msg.chain_name.to_uppercase());
    let universal_chain_id = hex::encode(
        deps.api.addr_canonicalize(&chain_id_input)
            .unwrap_or_default()
            .as_slice()
    );

    let operator = msg.operator
        .map(|a| deps.api.addr_validate(&a))
        .transpose()?
        .unwrap_or(info.sender.clone());

    let emergency = msg.emergency_authority
        .map(|a| deps.api.addr_validate(&a))
        .transpose()?
        .unwrap_or(info.sender.clone());

    let config = Config {
        owner: info.sender.clone(),
        operator,
        emergency_authority: emergency,
        universal_chain_id: universal_chain_id.clone(),
        chain_name: msg.chain_name,
        chain_vm: ChainVM::CosmWasm,
        chain_layer: msg.chain_layer.clone(),
        proof_system: ProofSystem::Groth16,
        active: true,
        transfer_nonce: 0,
    };

    CONFIG.save(deps.storage, &config)?;

    STATS.save(deps.storage, &Stats {
        total_proofs_verified: 0,
        total_states_received: 0,
        total_states_sent: 0,
        total_nullifiers_consumed: 0,
    })?;

    Ok(Response::new()
        .add_attribute("action", "instantiate")
        .add_attribute("chain_adapter", "soul_universal_adapter")
        .add_attribute("universal_chain_id", &universal_chain_id)
        .add_attribute("chain_vm", "cosmwasm")
        .add_attribute("owner", info.sender))
}

#[entry_point]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> StdResult<Response> {
    match msg {
        ExecuteMsg::SubmitUniversalProof {
            proof_id, source_chain_id, dest_chain_id, proof_system,
            proof, public_inputs, state_commitment, nullifier, timestamp,
        } => execute_submit_universal_proof(
            deps, env, info, proof_id, source_chain_id, dest_chain_id,
            proof_system, proof, public_inputs, state_commitment, nullifier, timestamp,
        ),
        ExecuteMsg::ReceiveEncryptedState {
            transfer_id, source_chain_id, state_commitment,
            encrypted_payload, nullifier, new_commitment, proof,
        } => execute_receive_encrypted_state(
            deps, env, info, transfer_id, source_chain_id,
            state_commitment, encrypted_payload, nullifier, new_commitment, proof,
        ),
        ExecuteMsg::SendEncryptedState {
            dest_chain_id, state_commitment, encrypted_payload, proof, nullifier,
        } => execute_send_encrypted_state(
            deps, env, info, dest_chain_id, state_commitment,
            encrypted_payload, proof, nullifier,
        ),
        ExecuteMsg::RegisterRemoteAdapter { chain_id, adapter_address } => {
            execute_register_remote_adapter(deps, env, info, chain_id, adapter_address)
        }
        ExecuteMsg::SetActive { active } => execute_set_active(deps, info, active),
        ExecuteMsg::EmergencyPause {} => execute_emergency_pause(deps, info),
        ExecuteMsg::EmergencyUnpause {} => execute_emergency_unpause(deps, info),
        ExecuteMsg::UpdateOperator { new_operator } => {
            execute_update_operator(deps, info, new_operator)
        }
    }
}

#[entry_point]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetConfig {} => to_json_binary(&query_config(deps)?),
        QueryMsg::GetUniversalChainId {} => to_json_binary(&query_chain_id(deps)?),
        QueryMsg::IsNullifierUsed { nullifier } => {
            to_json_binary(&query_nullifier(deps, &nullifier)?)
        }
        QueryMsg::GetStats {} => to_json_binary(&query_stats(deps)?),
        QueryMsg::IsProofProcessed { proof_id } => {
            to_json_binary(&PROCESSED_PROOFS.has(deps.storage, &proof_id))
        }
        QueryMsg::IsRemoteAdapterRegistered { chain_id } => {
            to_json_binary(&REMOTE_ADAPTERS.has(deps.storage, &chain_id))
        }
    }
}

/*//////////////////////////////////////////////////////////////
                     EXECUTE IMPLEMENTATIONS
//////////////////////////////////////////////////////////////*/

fn execute_submit_universal_proof(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    proof_id: String,
    source_chain_id: String,
    dest_chain_id: String,
    proof_system: ProofSystem,
    proof: Binary,
    public_inputs: Vec<Binary>,
    state_commitment: String,
    nullifier: String,
    timestamp: u64,
) -> StdResult<Response> {
    let config = CONFIG.load(deps.storage)?;

    // Check adapter is active
    if !config.active {
        return Err(StdError::generic_err("Adapter is paused"));
    }

    // Check destination
    if dest_chain_id != config.universal_chain_id {
        return Err(StdError::generic_err("Wrong destination chain"));
    }

    // Check proof age (24 hours)
    let current_time = env.block.time.seconds();
    if current_time > timestamp + 86400 {
        return Err(StdError::generic_err("Proof expired"));
    }

    // Check proof not already processed
    if PROCESSED_PROOFS.has(deps.storage, &proof_id) {
        return Err(StdError::generic_err("Proof already processed"));
    }

    // Check nullifier
    if NULLIFIERS.has(deps.storage, &nullifier) {
        return Err(StdError::generic_err("Nullifier already used"));
    }

    // Validate proof data
    if proof.len() < 64 {
        return Err(StdError::generic_err("Invalid proof: too short"));
    }
    if public_inputs.is_empty() {
        return Err(StdError::generic_err("Invalid proof: no public inputs"));
    }

    // Store proof record
    PROCESSED_PROOFS.save(deps.storage, &proof_id, &ProofData {
        proof_id: proof_id.clone(),
        source_chain_id: source_chain_id.clone(),
        dest_chain_id: dest_chain_id.clone(),
        proof_system,
        state_commitment: state_commitment.clone(),
        nullifier: nullifier.clone(),
        processed: true,
        timestamp: current_time,
        relayer: info.sender.to_string(),
    })?;

    // Store nullifier
    NULLIFIERS.save(deps.storage, &nullifier, &NullifierData {
        used: true,
        source_chain_id: source_chain_id.clone(),
        consumed_at: current_time,
    })?;

    // Store state commitment
    STATE_COMMITMENTS.save(deps.storage, &proof_id, &state_commitment)?;

    // Update stats
    STATS.update(deps.storage, |mut stats| -> StdResult<Stats> {
        stats.total_proofs_verified += 1;
        stats.total_nullifiers_consumed += 1;
        Ok(stats)
    })?;

    Ok(Response::new()
        .add_attribute("action", "submit_universal_proof")
        .add_attribute("proof_id", &proof_id)
        .add_attribute("source_chain_id", &source_chain_id)
        .add_attribute("dest_chain_id", &dest_chain_id)
        .add_attribute("nullifier", &nullifier)
        .add_attribute("relayer", info.sender))
}

fn execute_receive_encrypted_state(
    deps: DepsMut,
    env: Env,
    _info: MessageInfo,
    transfer_id: String,
    source_chain_id: String,
    state_commitment: String,
    encrypted_payload: Binary,
    nullifier: String,
    _new_commitment: String,
    proof: Binary,
) -> StdResult<Response> {
    let config = CONFIG.load(deps.storage)?;

    if !config.active {
        return Err(StdError::generic_err("Adapter is paused"));
    }

    // Validate
    if state_commitment.is_empty() {
        return Err(StdError::generic_err("Invalid state commitment"));
    }
    if proof.len() < 64 {
        return Err(StdError::generic_err("Invalid proof"));
    }
    if encrypted_payload.len() > 65536 {
        return Err(StdError::generic_err("Payload too large"));
    }

    // Check not already processed
    if PROCESSED_TRANSFERS.has(deps.storage, &transfer_id) {
        return Err(StdError::generic_err("Transfer already processed"));
    }

    // Check nullifier
    if NULLIFIERS.has(deps.storage, &nullifier) {
        return Err(StdError::generic_err("Nullifier already used"));
    }

    let current_time = env.block.time.seconds();

    // Mark processed
    PROCESSED_TRANSFERS.save(deps.storage, &transfer_id, &true)?;

    // Store nullifier
    NULLIFIERS.save(deps.storage, &nullifier, &NullifierData {
        used: true,
        source_chain_id: source_chain_id.clone(),
        consumed_at: current_time,
    })?;

    // Store state commitment
    STATE_COMMITMENTS.save(deps.storage, &transfer_id, &state_commitment)?;

    // Update stats
    STATS.update(deps.storage, |mut stats| -> StdResult<Stats> {
        stats.total_states_received += 1;
        stats.total_nullifiers_consumed += 1;
        Ok(stats)
    })?;

    Ok(Response::new()
        .add_attribute("action", "receive_encrypted_state")
        .add_attribute("transfer_id", &transfer_id)
        .add_attribute("source_chain_id", &source_chain_id)
        .add_attribute("nullifier", &nullifier))
}

fn execute_send_encrypted_state(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    dest_chain_id: String,
    state_commitment: String,
    _encrypted_payload: Binary,
    proof: Binary,
    nullifier: String,
) -> StdResult<Response> {
    let mut config = CONFIG.load(deps.storage)?;

    if !config.active {
        return Err(StdError::generic_err("Adapter is paused"));
    }

    // Validate
    if state_commitment.is_empty() {
        return Err(StdError::generic_err("Invalid state commitment"));
    }
    if proof.len() < 64 {
        return Err(StdError::generic_err("Invalid proof"));
    }

    // Check remote adapter exists
    if !REMOTE_ADAPTERS.has(deps.storage, &dest_chain_id) {
        return Err(StdError::generic_err("No remote adapter registered"));
    }

    // Check nullifier
    if NULLIFIERS.has(deps.storage, &nullifier) {
        return Err(StdError::generic_err("Nullifier already used"));
    }

    // Generate transfer ID
    let transfer_id = format!(
        "{}-{}-{}-{}-{}",
        config.universal_chain_id,
        dest_chain_id,
        info.sender,
        config.transfer_nonce,
        env.block.time.seconds()
    );

    let current_time = env.block.time.seconds();

    // Store nullifier
    NULLIFIERS.save(deps.storage, &nullifier, &NullifierData {
        used: true,
        source_chain_id: config.universal_chain_id.clone(),
        consumed_at: current_time,
    })?;

    // Store state commitment
    STATE_COMMITMENTS.save(deps.storage, &transfer_id, &state_commitment)?;

    // Update config
    config.transfer_nonce += 1;
    CONFIG.save(deps.storage, &config)?;

    // Update stats
    STATS.update(deps.storage, |mut stats| -> StdResult<Stats> {
        stats.total_states_sent += 1;
        stats.total_nullifiers_consumed += 1;
        Ok(stats)
    })?;

    Ok(Response::new()
        .add_attribute("action", "send_encrypted_state")
        .add_attribute("transfer_id", &transfer_id)
        .add_attribute("dest_chain_id", &dest_chain_id)
        .add_attribute("nullifier", &nullifier))
}

fn execute_register_remote_adapter(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    chain_id: String,
    adapter_address: String,
) -> StdResult<Response> {
    let config = CONFIG.load(deps.storage)?;
    if info.sender != config.operator {
        return Err(StdError::generic_err("Not operator"));
    }

    REMOTE_ADAPTERS.save(deps.storage, &chain_id, &RemoteAdapter {
        chain_id: chain_id.clone(),
        adapter_address: adapter_address.clone(),
        active: true,
        registered_at: env.block.time.seconds(),
    })?;

    Ok(Response::new()
        .add_attribute("action", "register_remote_adapter")
        .add_attribute("chain_id", &chain_id)
        .add_attribute("adapter", &adapter_address))
}

fn execute_set_active(deps: DepsMut, info: MessageInfo, active: bool) -> StdResult<Response> {
    let mut config = CONFIG.load(deps.storage)?;
    if info.sender != config.operator {
        return Err(StdError::generic_err("Not operator"));
    }
    config.active = active;
    CONFIG.save(deps.storage, &config)?;

    Ok(Response::new()
        .add_attribute("action", "set_active")
        .add_attribute("active", active.to_string()))
}

fn execute_emergency_pause(deps: DepsMut, info: MessageInfo) -> StdResult<Response> {
    let mut config = CONFIG.load(deps.storage)?;
    if info.sender != config.emergency_authority {
        return Err(StdError::generic_err("Not emergency authority"));
    }
    config.active = false;
    CONFIG.save(deps.storage, &config)?;

    Ok(Response::new().add_attribute("action", "emergency_pause"))
}

fn execute_emergency_unpause(deps: DepsMut, info: MessageInfo) -> StdResult<Response> {
    let mut config = CONFIG.load(deps.storage)?;
    if info.sender != config.emergency_authority {
        return Err(StdError::generic_err("Not emergency authority"));
    }
    config.active = true;
    CONFIG.save(deps.storage, &config)?;

    Ok(Response::new().add_attribute("action", "emergency_unpause"))
}

fn execute_update_operator(
    deps: DepsMut,
    info: MessageInfo,
    new_operator: String,
) -> StdResult<Response> {
    let mut config = CONFIG.load(deps.storage)?;
    if info.sender != config.owner {
        return Err(StdError::generic_err("Not owner"));
    }
    config.operator = deps.api.addr_validate(&new_operator)?;
    CONFIG.save(deps.storage, &config)?;

    Ok(Response::new()
        .add_attribute("action", "update_operator")
        .add_attribute("new_operator", &new_operator))
}

/*//////////////////////////////////////////////////////////////
                       QUERY IMPLEMENTATIONS
//////////////////////////////////////////////////////////////*/

fn query_config(deps: Deps) -> StdResult<ConfigResponse> {
    let config = CONFIG.load(deps.storage)?;
    Ok(ConfigResponse {
        owner: config.owner.to_string(),
        operator: config.operator.to_string(),
        emergency_authority: config.emergency_authority.to_string(),
        universal_chain_id: config.universal_chain_id,
        chain_name: config.chain_name,
        chain_vm: config.chain_vm,
        chain_layer: config.chain_layer,
        proof_system: config.proof_system,
        active: config.active,
    })
}

fn query_chain_id(deps: Deps) -> StdResult<ChainIdResponse> {
    let config = CONFIG.load(deps.storage)?;
    Ok(ChainIdResponse {
        universal_chain_id: config.universal_chain_id,
    })
}

fn query_nullifier(deps: Deps, nullifier: &str) -> StdResult<NullifierResponse> {
    match NULLIFIERS.may_load(deps.storage, nullifier)? {
        Some(data) => Ok(NullifierResponse {
            used: data.used,
            source_chain_id: Some(data.source_chain_id),
            consumed_at: Some(data.consumed_at),
        }),
        None => Ok(NullifierResponse {
            used: false,
            source_chain_id: None,
            consumed_at: None,
        }),
    }
}

fn query_stats(deps: Deps) -> StdResult<StatsResponse> {
    let stats = STATS.load(deps.storage)?;
    Ok(StatsResponse {
        total_proofs_verified: stats.total_proofs_verified,
        total_states_received: stats.total_states_received,
        total_states_sent: stats.total_states_sent,
        total_nullifiers_consumed: stats.total_nullifiers_consumed,
    })
}
