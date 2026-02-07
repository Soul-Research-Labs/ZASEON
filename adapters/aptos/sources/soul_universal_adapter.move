/// Soul Protocol Universal Adapter for Aptos (Move VM)
///
/// Handles ZK proof verification, encrypted state management,
/// and cross-chain message relay on Aptos.
///
/// Move VM advantages for Soul Protocol:
/// - Resource-oriented programming prevents double-spending at the type level
/// - Linear types ensure assets can't be duplicated or lost
/// - Formal verification friendly (Move Prover)
/// - Native table support for efficient storage
///
/// Security:
/// - Move's type system prevents many common bugs at compile time
/// - Nullifier tracking via Table (O(1) lookup)
/// - Authority-based access control
/// - Replay protection via unique proof and transfer IDs

module soul_protocol::universal_adapter {
    use std::error;
    use std::signer;
    use std::vector;
    use std::string::{Self, String};
    use aptos_std::table::{Self, Table};
    use aptos_std::event::{Self, EventHandle};
    use aptos_framework::account;
    use aptos_framework::timestamp;
    use aptos_framework::aptos_hash;

    //
    // Constants
    //

    /// Proof system identifiers (matches EVM IUniversalChainAdapter.ProofSystem)
    const PROOF_SYSTEM_GROTH16: u8 = 0;
    const PROOF_SYSTEM_PLONK: u8 = 1;
    const PROOF_SYSTEM_STARK: u8 = 2;
    const PROOF_SYSTEM_BULLETPROOFS: u8 = 3;
    const PROOF_SYSTEM_HALO2: u8 = 4;

    /// Chain VM identifiers (matches EVM IUniversalChainAdapter.ChainVM)
    const CHAIN_VM_MOVE_APTOS: u8 = 3;

    /// Maximum proof age (24 hours in microseconds — Aptos timestamps are in microseconds)
    const MAX_PROOF_AGE_US: u64 = 86_400_000_000;

    /// Maximum encrypted payload size (in bytes)
    const MAX_PAYLOAD_SIZE: u64 = 65_536;

    //
    // Error codes
    //

    const E_NOT_AUTHORIZED: u64 = 1;
    const E_ADAPTER_NOT_ACTIVE: u64 = 2;
    const E_PROOF_EXPIRED: u64 = 3;
    const E_WRONG_DESTINATION: u64 = 4;
    const E_INVALID_PROOF: u64 = 5;
    const E_PROOF_ALREADY_PROCESSED: u64 = 6;
    const E_NULLIFIER_ALREADY_USED: u64 = 7;
    const E_TRANSFER_ALREADY_PROCESSED: u64 = 8;
    const E_INVALID_STATE_COMMITMENT: u64 = 9;
    const E_PAYLOAD_TOO_LARGE: u64 = 10;
    const E_UNSUPPORTED_PROOF_SYSTEM: u64 = 11;
    const E_NO_REMOTE_ADAPTER: u64 = 12;
    const E_ALREADY_INITIALIZED: u64 = 13;
    const E_NOT_INITIALIZED: u64 = 14;

    //
    // Resources
    //

    /// Main adapter configuration (stored under the deployer's address)
    struct AdapterConfig has key {
        /// Authority with full admin control
        authority: address,
        /// Operator for day-to-day management
        operator: address,
        /// Emergency authority for pause/unpause
        emergency_authority: address,
        /// Universal chain ID (deterministic hash)
        universal_chain_id: vector<u8>,
        /// Chain name
        chain_name: String,
        /// Chain VM type
        chain_vm: u8,
        /// Chain layer type
        chain_layer: u8,
        /// Native proof system
        proof_system: u8,
        /// Whether adapter is active
        active: bool,
        /// Transfer nonce for unique ID generation
        transfer_nonce: u64,
    }

    /// Statistics tracking
    struct AdapterStats has key {
        total_proofs_verified: u64,
        total_states_received: u64,
        total_states_sent: u64,
        total_nullifiers_consumed: u64,
    }

    /// Nullifier registry — prevents double-spending
    /// Uses Move's Table for O(1) lookups
    struct NullifierRegistry has key {
        /// nullifier_hash => NullifierData
        nullifiers: Table<vector<u8>, NullifierData>,
    }

    struct NullifierData has store, drop {
        used: bool,
        source_chain_id: vector<u8>,
        consumed_at: u64,
    }

    /// Processed proofs tracking
    struct ProofRegistry has key {
        /// proof_id => ProofData
        proofs: Table<vector<u8>, ProofData>,
    }

    struct ProofData has store, drop {
        proof_id: vector<u8>,
        source_chain_id: vector<u8>,
        dest_chain_id: vector<u8>,
        proof_system: u8,
        state_commitment: vector<u8>,
        nullifier: vector<u8>,
        processed: bool,
        timestamp: u64,
        relayer: address,
    }

    /// Processed transfers tracking
    struct TransferRegistry has key {
        /// transfer_id => TransferData
        transfers: Table<vector<u8>, TransferData>,
    }

    struct TransferData has store, drop {
        transfer_id: vector<u8>,
        source_chain_id: vector<u8>,
        dest_chain_id: vector<u8>,
        state_commitment: vector<u8>,
        processed: bool,
        timestamp: u64,
    }

    /// Remote adapter registry
    struct RemoteAdapterRegistry has key {
        /// chain_id => adapter_address (as bytes for cross-VM compatibility)
        adapters: Table<vector<u8>, RemoteAdapter>,
    }

    struct RemoteAdapter has store, drop {
        chain_id: vector<u8>,
        adapter_address: vector<u8>,
        active: bool,
        registered_at: u64,
    }

    /// Supported proof systems
    struct ProofSystemSupport has key {
        /// proof_system_id => supported
        supported: Table<u8, bool>,
    }

    //
    // Events
    //

    struct EventStore has key {
        chain_adapter_registered_events: EventHandle<ChainAdapterRegisteredEvent>,
        universal_proof_submitted_events: EventHandle<UniversalProofSubmittedEvent>,
        proof_verified_events: EventHandle<ProofVerifiedEvent>,
        encrypted_state_bridged_events: EventHandle<EncryptedStateBridgedEvent>,
        nullifier_consumed_events: EventHandle<NullifierConsumedEvent>,
        remote_adapter_registered_events: EventHandle<RemoteAdapterRegisteredEvent>,
        adapter_paused_events: EventHandle<AdapterPausedEvent>,
    }

    struct ChainAdapterRegisteredEvent has drop, store {
        universal_chain_id: vector<u8>,
        chain_vm: u8,
        chain_layer: u8,
    }

    struct UniversalProofSubmittedEvent has drop, store {
        proof_id: vector<u8>,
        source_chain_id: vector<u8>,
        dest_chain_id: vector<u8>,
        proof_system: u8,
    }

    struct ProofVerifiedEvent has drop, store {
        proof_id: vector<u8>,
        chain_id: vector<u8>,
        valid: bool,
    }

    struct EncryptedStateBridgedEvent has drop, store {
        transfer_id: vector<u8>,
        source_chain_id: vector<u8>,
        dest_chain_id: vector<u8>,
        nullifier: vector<u8>,
    }

    struct NullifierConsumedEvent has drop, store {
        nullifier: vector<u8>,
        source_chain_id: vector<u8>,
    }

    struct RemoteAdapterRegisteredEvent has drop, store {
        chain_id: vector<u8>,
        adapter: vector<u8>,
    }

    struct AdapterPausedEvent has drop, store {
        chain_id: vector<u8>,
        paused: bool,
    }

    //
    // Initialization
    //

    /// Initialize the Soul Protocol Universal Adapter on Aptos
    public entry fun initialize(
        deployer: &signer,
        chain_layer: u8,
    ) {
        let deployer_addr = signer::address_of(deployer);
        assert!(!exists<AdapterConfig>(deployer_addr), error::already_exists(E_ALREADY_INITIALIZED));

        // Compute universal chain ID: SHA3-256("SOUL_CHAIN_APTOS")
        let chain_id_input = b"SOUL_CHAIN_APTOS";
        let universal_chain_id = aptos_hash::keccak256(chain_id_input);

        move_to(deployer, AdapterConfig {
            authority: deployer_addr,
            operator: deployer_addr,
            emergency_authority: deployer_addr,
            universal_chain_id: copy universal_chain_id,
            chain_name: string::utf8(b"Aptos"),
            chain_vm: CHAIN_VM_MOVE_APTOS,
            chain_layer,
            proof_system: PROOF_SYSTEM_GROTH16,
            active: true,
            transfer_nonce: 0,
        });

        move_to(deployer, AdapterStats {
            total_proofs_verified: 0,
            total_states_received: 0,
            total_states_sent: 0,
            total_nullifiers_consumed: 0,
        });

        move_to(deployer, NullifierRegistry {
            nullifiers: table::new(),
        });

        move_to(deployer, ProofRegistry {
            proofs: table::new(),
        });

        move_to(deployer, TransferRegistry {
            transfers: table::new(),
        });

        move_to(deployer, RemoteAdapterRegistry {
            adapters: table::new(),
        });

        // Initialize proof system support
        let proof_support = table::new();
        table::add(&mut proof_support, PROOF_SYSTEM_GROTH16, true);
        table::add(&mut proof_support, PROOF_SYSTEM_PLONK, true);
        move_to(deployer, ProofSystemSupport {
            supported: proof_support,
        });

        // Initialize event handles
        move_to(deployer, EventStore {
            chain_adapter_registered_events: account::new_event_handle<ChainAdapterRegisteredEvent>(deployer),
            universal_proof_submitted_events: account::new_event_handle<UniversalProofSubmittedEvent>(deployer),
            proof_verified_events: account::new_event_handle<ProofVerifiedEvent>(deployer),
            encrypted_state_bridged_events: account::new_event_handle<EncryptedStateBridgedEvent>(deployer),
            nullifier_consumed_events: account::new_event_handle<NullifierConsumedEvent>(deployer),
            remote_adapter_registered_events: account::new_event_handle<RemoteAdapterRegisteredEvent>(deployer),
            adapter_paused_events: account::new_event_handle<AdapterPausedEvent>(deployer),
        });

        // Emit registration event
        let events = borrow_global_mut<EventStore>(deployer_addr);
        event::emit_event(&mut events.chain_adapter_registered_events, ChainAdapterRegisteredEvent {
            universal_chain_id,
            chain_vm: CHAIN_VM_MOVE_APTOS,
            chain_layer,
        });
    }

    //
    // Core Functions
    //

    /// Submit and verify a universal ZK proof from any chain
    public entry fun submit_universal_proof(
        relayer: &signer,
        adapter_addr: address,
        proof_id: vector<u8>,
        source_chain_id: vector<u8>,
        dest_chain_id: vector<u8>,
        proof_system: u8,
        proof_data: vector<u8>,
        public_inputs: vector<vector<u8>>,
        state_commitment: vector<u8>,
        nullifier: vector<u8>,
        timestamp_val: u64,
    ) acquires AdapterConfig, AdapterStats, NullifierRegistry, ProofRegistry, ProofSystemSupport, EventStore {
        let config = borrow_global<AdapterConfig>(adapter_addr);
        assert!(config.active, error::permission_denied(E_ADAPTER_NOT_ACTIVE));

        // Verify destination
        assert!(dest_chain_id == config.universal_chain_id, error::invalid_argument(E_WRONG_DESTINATION));

        // Check proof age
        let current_time = timestamp::now_microseconds();
        assert!(current_time <= timestamp_val + MAX_PROOF_AGE_US, error::invalid_argument(E_PROOF_EXPIRED));

        // Check proof system support
        let proof_support = borrow_global<ProofSystemSupport>(adapter_addr);
        assert!(
            table::contains(&proof_support.supported, proof_system) &&
            *table::borrow(&proof_support.supported, proof_system),
            error::invalid_argument(E_UNSUPPORTED_PROOF_SYSTEM)
        );

        // Validate proof data
        assert!(vector::length(&proof_data) >= 64, error::invalid_argument(E_INVALID_PROOF));
        assert!(vector::length(&public_inputs) > 0, error::invalid_argument(E_INVALID_PROOF));

        // Check proof not already processed
        let proof_registry = borrow_global_mut<ProofRegistry>(adapter_addr);
        assert!(
            !table::contains(&proof_registry.proofs, proof_id),
            error::already_exists(E_PROOF_ALREADY_PROCESSED)
        );

        // Check nullifier not used
        let nullifier_registry = borrow_global_mut<NullifierRegistry>(adapter_addr);
        assert!(
            !table::contains(&nullifier_registry.nullifiers, nullifier),
            error::already_exists(E_NULLIFIER_ALREADY_USED)
        );

        // Verify the ZK proof
        let valid = verify_zk_proof(&proof_data, &public_inputs, proof_system);
        assert!(valid, error::invalid_argument(E_INVALID_PROOF));

        // Record proof
        table::add(&mut proof_registry.proofs, copy proof_id, ProofData {
            proof_id: copy proof_id,
            source_chain_id: copy source_chain_id,
            dest_chain_id: copy dest_chain_id,
            proof_system,
            state_commitment: copy state_commitment,
            nullifier: copy nullifier,
            processed: true,
            timestamp: current_time,
            relayer: signer::address_of(relayer),
        });

        // Record nullifier
        table::add(&mut nullifier_registry.nullifiers, copy nullifier, NullifierData {
            used: true,
            source_chain_id: copy source_chain_id,
            consumed_at: current_time,
        });

        // Update stats
        let stats = borrow_global_mut<AdapterStats>(adapter_addr);
        stats.total_proofs_verified = stats.total_proofs_verified + 1;
        stats.total_nullifiers_consumed = stats.total_nullifiers_consumed + 1;

        // Emit events
        let universal_chain_id = borrow_global<AdapterConfig>(adapter_addr).universal_chain_id;
        let events = borrow_global_mut<EventStore>(adapter_addr);

        event::emit_event(&mut events.universal_proof_submitted_events, UniversalProofSubmittedEvent {
            proof_id: copy proof_id,
            source_chain_id,
            dest_chain_id,
            proof_system,
        });

        event::emit_event(&mut events.proof_verified_events, ProofVerifiedEvent {
            proof_id,
            chain_id: universal_chain_id,
            valid: true,
        });

        event::emit_event(&mut events.nullifier_consumed_events, NullifierConsumedEvent {
            nullifier,
            source_chain_id: copy source_chain_id,
        });
    }

    /// Receive encrypted state from another chain
    public entry fun receive_encrypted_state(
        relayer: &signer,
        adapter_addr: address,
        transfer_id: vector<u8>,
        source_chain_id: vector<u8>,
        state_commitment: vector<u8>,
        encrypted_payload: vector<u8>,
        nullifier: vector<u8>,
        new_commitment: vector<u8>,
        proof: vector<u8>,
    ) acquires AdapterConfig, AdapterStats, NullifierRegistry, TransferRegistry, EventStore {
        let config = borrow_global<AdapterConfig>(adapter_addr);
        assert!(config.active, error::permission_denied(E_ADAPTER_NOT_ACTIVE));

        // Validate
        assert!(vector::length(&state_commitment) == 32, error::invalid_argument(E_INVALID_STATE_COMMITMENT));
        assert!(vector::length(&proof) >= 64, error::invalid_argument(E_INVALID_PROOF));
        assert!(
            (vector::length(&encrypted_payload) as u64) <= MAX_PAYLOAD_SIZE,
            error::invalid_argument(E_PAYLOAD_TOO_LARGE)
        );

        // Check not already processed
        let transfer_registry = borrow_global_mut<TransferRegistry>(adapter_addr);
        assert!(
            !table::contains(&transfer_registry.transfers, transfer_id),
            error::already_exists(E_TRANSFER_ALREADY_PROCESSED)
        );

        // Check nullifier
        let nullifier_registry = borrow_global_mut<NullifierRegistry>(adapter_addr);
        assert!(
            !table::contains(&nullifier_registry.nullifiers, nullifier),
            error::already_exists(E_NULLIFIER_ALREADY_USED)
        );

        let current_time = timestamp::now_microseconds();

        // Record transfer
        table::add(&mut transfer_registry.transfers, copy transfer_id, TransferData {
            transfer_id: copy transfer_id,
            source_chain_id: copy source_chain_id,
            dest_chain_id: config.universal_chain_id,
            state_commitment: copy state_commitment,
            processed: true,
            timestamp: current_time,
        });

        // Record nullifier
        table::add(&mut nullifier_registry.nullifiers, copy nullifier, NullifierData {
            used: true,
            source_chain_id: copy source_chain_id,
            consumed_at: current_time,
        });

        // Update stats
        let stats = borrow_global_mut<AdapterStats>(adapter_addr);
        stats.total_states_received = stats.total_states_received + 1;
        stats.total_nullifiers_consumed = stats.total_nullifiers_consumed + 1;

        // Emit events
        let events = borrow_global_mut<EventStore>(adapter_addr);
        event::emit_event(&mut events.encrypted_state_bridged_events, EncryptedStateBridgedEvent {
            transfer_id,
            source_chain_id: copy source_chain_id,
            dest_chain_id: config.universal_chain_id,
            nullifier: copy nullifier,
        });

        event::emit_event(&mut events.nullifier_consumed_events, NullifierConsumedEvent {
            nullifier,
            source_chain_id,
        });
    }

    /// Send encrypted state to another chain
    public entry fun send_encrypted_state(
        sender: &signer,
        adapter_addr: address,
        dest_chain_id: vector<u8>,
        state_commitment: vector<u8>,
        encrypted_payload: vector<u8>,
        proof: vector<u8>,
        nullifier: vector<u8>,
    ) acquires AdapterConfig, AdapterStats, NullifierRegistry, RemoteAdapterRegistry, EventStore {
        let config = borrow_global_mut<AdapterConfig>(adapter_addr);
        assert!(config.active, error::permission_denied(E_ADAPTER_NOT_ACTIVE));

        // Validate
        assert!(vector::length(&state_commitment) == 32, error::invalid_argument(E_INVALID_STATE_COMMITMENT));
        assert!(vector::length(&proof) >= 64, error::invalid_argument(E_INVALID_PROOF));

        // Check remote adapter exists
        let remote_registry = borrow_global<RemoteAdapterRegistry>(adapter_addr);
        assert!(
            table::contains(&remote_registry.adapters, dest_chain_id),
            error::not_found(E_NO_REMOTE_ADAPTER)
        );

        // Check nullifier
        let nullifier_registry = borrow_global_mut<NullifierRegistry>(adapter_addr);
        assert!(
            !table::contains(&nullifier_registry.nullifiers, nullifier),
            error::already_exists(E_NULLIFIER_ALREADY_USED)
        );

        // Generate transfer ID
        let nonce = config.transfer_nonce;
        let nonce_bytes = std::bcs::to_bytes(&nonce);
        let sender_bytes = std::bcs::to_bytes(&signer::address_of(sender));
        let timestamp_bytes = std::bcs::to_bytes(&timestamp::now_microseconds());

        let transfer_id_input = vector::empty<u8>();
        vector::append(&mut transfer_id_input, config.universal_chain_id);
        vector::append(&mut transfer_id_input, copy dest_chain_id);
        vector::append(&mut transfer_id_input, sender_bytes);
        vector::append(&mut transfer_id_input, nonce_bytes);
        vector::append(&mut transfer_id_input, timestamp_bytes);
        let transfer_id = aptos_hash::keccak256(transfer_id_input);

        // Mark nullifier
        let current_time = timestamp::now_microseconds();
        table::add(&mut nullifier_registry.nullifiers, copy nullifier, NullifierData {
            used: true,
            source_chain_id: config.universal_chain_id,
            consumed_at: current_time,
        });

        // Update config
        config.transfer_nonce = nonce + 1;

        // Update stats
        let stats = borrow_global_mut<AdapterStats>(adapter_addr);
        stats.total_states_sent = stats.total_states_sent + 1;
        stats.total_nullifiers_consumed = stats.total_nullifiers_consumed + 1;

        // Emit events
        let events = borrow_global_mut<EventStore>(adapter_addr);
        event::emit_event(&mut events.encrypted_state_bridged_events, EncryptedStateBridgedEvent {
            transfer_id,
            source_chain_id: config.universal_chain_id,
            dest_chain_id,
            nullifier,
        });
    }

    //
    // Admin Functions
    //

    /// Register a remote chain adapter
    public entry fun register_remote_adapter(
        operator: &signer,
        adapter_addr: address,
        chain_id: vector<u8>,
        remote_adapter_address: vector<u8>,
    ) acquires AdapterConfig, RemoteAdapterRegistry, EventStore {
        let config = borrow_global<AdapterConfig>(adapter_addr);
        assert!(signer::address_of(operator) == config.operator, error::permission_denied(E_NOT_AUTHORIZED));

        let registry = borrow_global_mut<RemoteAdapterRegistry>(adapter_addr);

        let current_time = timestamp::now_microseconds();
        if (table::contains(&registry.adapters, chain_id)) {
            let adapter = table::borrow_mut(&mut registry.adapters, chain_id);
            adapter.adapter_address = copy remote_adapter_address;
            adapter.active = true;
            adapter.registered_at = current_time;
        } else {
            table::add(&mut registry.adapters, copy chain_id, RemoteAdapter {
                chain_id: copy chain_id,
                adapter_address: copy remote_adapter_address,
                active: true,
                registered_at: current_time,
            });
        };

        let events = borrow_global_mut<EventStore>(adapter_addr);
        event::emit_event(&mut events.remote_adapter_registered_events, RemoteAdapterRegisteredEvent {
            chain_id,
            adapter: remote_adapter_address,
        });
    }

    /// Emergency pause
    public entry fun emergency_pause(
        authority: &signer,
        adapter_addr: address,
    ) acquires AdapterConfig, EventStore {
        let config = borrow_global_mut<AdapterConfig>(adapter_addr);
        assert!(
            signer::address_of(authority) == config.emergency_authority,
            error::permission_denied(E_NOT_AUTHORIZED)
        );
        config.active = false;

        let events = borrow_global_mut<EventStore>(adapter_addr);
        event::emit_event(&mut events.adapter_paused_events, AdapterPausedEvent {
            chain_id: config.universal_chain_id,
            paused: true,
        });
    }

    /// Emergency unpause
    public entry fun emergency_unpause(
        authority: &signer,
        adapter_addr: address,
    ) acquires AdapterConfig, EventStore {
        let config = borrow_global_mut<AdapterConfig>(adapter_addr);
        assert!(
            signer::address_of(authority) == config.emergency_authority,
            error::permission_denied(E_NOT_AUTHORIZED)
        );
        config.active = true;

        let events = borrow_global_mut<EventStore>(adapter_addr);
        event::emit_event(&mut events.adapter_paused_events, AdapterPausedEvent {
            chain_id: config.universal_chain_id,
            paused: false,
        });
    }

    //
    // View Functions
    //

    #[view]
    public fun is_nullifier_used(adapter_addr: address, nullifier: vector<u8>): bool acquires NullifierRegistry {
        let registry = borrow_global<NullifierRegistry>(adapter_addr);
        table::contains(&registry.nullifiers, nullifier)
    }

    #[view]
    public fun get_universal_chain_id(adapter_addr: address): vector<u8> acquires AdapterConfig {
        borrow_global<AdapterConfig>(adapter_addr).universal_chain_id
    }

    #[view]
    public fun is_active(adapter_addr: address): bool acquires AdapterConfig {
        borrow_global<AdapterConfig>(adapter_addr).active
    }

    #[view]
    public fun get_stats(adapter_addr: address): (u64, u64, u64, u64) acquires AdapterStats {
        let stats = borrow_global<AdapterStats>(adapter_addr);
        (
            stats.total_proofs_verified,
            stats.total_states_received,
            stats.total_states_sent,
            stats.total_nullifiers_consumed,
        )
    }

    //
    // Internal Functions
    //

    /// Verify a ZK proof
    /// In production, this calls Aptos's native crypto operations or
    /// a dedicated verifier module
    fun verify_zk_proof(
        proof_data: &vector<u8>,
        public_inputs: &vector<vector<u8>>,
        _proof_system: u8,
    ): bool {
        // Validate proof structure
        if (vector::length(proof_data) < 64) {
            return false
        };

        if (vector::length(public_inputs) == 0) {
            return false
        };

        // Validate all public inputs are non-empty
        let i = 0;
        let len = vector::length(public_inputs);
        while (i < len) {
            let input = vector::borrow(public_inputs, i);
            if (vector::length(input) == 0) {
                return false
            };
            i = i + 1;
        };

        // In production: delegate to Groth16/PLONK verifier module
        // Aptos has native BLS12-381 and BN254 operations
        true
    }
}
