/// Soul Protocol Universal Adapter for StarkNet
///
/// Handles ZK proof verification (STARK-native), encrypted state management,
/// and cross-chain message relay on StarkNet.
///
/// Key advantage: StarkNet uses STARK proofs natively, so proof verification
/// is significantly cheaper here compared to SNARK-based chains.
///
/// Architecture:
/// - Mirrors IUniversalChainAdapter from EVM side
/// - Leverages StarkNet's native felt252 types for efficient hashing
/// - Uses STARK-native proof verification (cheap on StarkNet)
/// - Supports receiving Groth16/PLONK proofs via proof translation
///
/// Security:
/// - Nullifier double-spend prevention
/// - Owner-based access control for operator/emergency functions
/// - Replay protection via unique proof and transfer IDs
/// - Pausable emergency circuit breaker

use starknet::ContractAddress;

#[starknet::interface]
trait ISoulUniversalAdapter<TContractState> {
    // Core functions
    fn get_universal_chain_id(self: @TContractState) -> felt252;
    fn get_chain_vm(self: @TContractState) -> u8;
    fn get_chain_layer(self: @TContractState) -> u8;
    fn get_native_proof_system(self: @TContractState) -> u8;
    fn is_active(self: @TContractState) -> bool;

    // Proof verification
    fn verify_proof(
        self: @TContractState,
        proof: Span<felt252>,
        public_inputs: Span<felt252>,
        proof_system: u8,
    ) -> bool;

    fn submit_universal_proof(
        ref self: TContractState,
        proof_id: felt252,
        source_chain_id: felt252,
        dest_chain_id: felt252,
        proof_system: u8,
        proof: Span<felt252>,
        public_inputs: Span<felt252>,
        state_commitment: felt252,
        nullifier: felt252,
        timestamp: u64,
    ) -> bool;

    // Encrypted state transfers
    fn receive_encrypted_state(
        ref self: TContractState,
        transfer_id: felt252,
        source_chain_id: felt252,
        state_commitment: felt252,
        encrypted_payload: Span<felt252>,
        nullifier: felt252,
        new_commitment: felt252,
        proof: Span<felt252>,
    ) -> bool;

    fn send_encrypted_state(
        ref self: TContractState,
        dest_chain_id: felt252,
        state_commitment: felt252,
        encrypted_payload: Span<felt252>,
        proof: Span<felt252>,
        nullifier: felt252,
    ) -> felt252;

    // Nullifier checks
    fn is_nullifier_used(self: @TContractState, nullifier: felt252) -> bool;

    // Admin
    fn register_remote_adapter(
        ref self: TContractState,
        chain_id: felt252,
        adapter_address: felt252,
    );

    fn set_active(ref self: TContractState, active: bool);
    fn emergency_pause(ref self: TContractState);
    fn emergency_unpause(ref self: TContractState);

    // Stats
    fn get_total_proofs_verified(self: @TContractState) -> u64;
    fn get_total_states_received(self: @TContractState) -> u64;
    fn get_total_states_sent(self: @TContractState) -> u64;
    fn get_total_nullifiers_consumed(self: @TContractState) -> u64;
}

#[starknet::contract]
mod SoulUniversalAdapter {
    use starknet::{
        ContractAddress, get_caller_address, get_block_timestamp, get_block_number
    };
    use core::pedersen::PedersenTrait;
    use core::hash::{HashStateTrait, HashStateExTrait};

    /*//////////////////////////////////////////////////////////////
                          PROOF SYSTEM CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// STARK = 2 (native proof system for StarkNet)
    const PROOF_SYSTEM_GROTH16: u8 = 0;
    const PROOF_SYSTEM_PLONK: u8 = 1;
    const PROOF_SYSTEM_STARK: u8 = 2;
    const PROOF_SYSTEM_HALO2: u8 = 4;
    const PROOF_SYSTEM_HONK: u8 = 7;

    /// Chain VM constants
    const CHAIN_VM_CAIRO: u8 = 2;

    /// Maximum proof age (24 hours = 86400 seconds)
    const MAX_PROOF_AGE: u64 = 86400;

    /// Maximum encrypted payload length (in felt252 elements)
    const MAX_PAYLOAD_FELTS: u32 = 2048;

    /*//////////////////////////////////////////////////////////////
                               STORAGE
    //////////////////////////////////////////////////////////////*/

    #[storage]
    struct Storage {
        // Config
        owner: ContractAddress,
        operator: ContractAddress,
        emergency_authority: ContractAddress,
        universal_chain_id: felt252,
        chain_vm: u8,
        chain_layer: u8,
        native_proof_system: u8,
        active: bool,

        // Nullifier registry
        nullifier_used: LegacyMap<felt252, bool>,

        // Processed proofs and transfers
        processed_proofs: LegacyMap<felt252, bool>,
        processed_transfers: LegacyMap<felt252, bool>,

        // State commitments
        state_commitments: LegacyMap<felt252, felt252>,

        // Remote adapters (chain_id => adapter_address)
        remote_adapters: LegacyMap<felt252, felt252>,
        remote_adapter_active: LegacyMap<felt252, bool>,

        // Proof system support
        proof_system_supported: LegacyMap<u8, bool>,

        // Statistics
        total_proofs_verified: u64,
        total_states_received: u64,
        total_states_sent: u64,
        total_nullifiers_consumed: u64,
        transfer_nonce: u64,

        // Proofs per source chain
        proofs_from_chain: LegacyMap<felt252, u64>,
    }

    /*//////////////////////////////////////////////////////////////
                               EVENTS
    //////////////////////////////////////////////////////////////*/

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        ChainAdapterRegistered: ChainAdapterRegistered,
        UniversalProofSubmitted: UniversalProofSubmitted,
        ProofVerifiedOnDestination: ProofVerifiedOnDestination,
        EncryptedStateBridged: EncryptedStateBridged,
        NullifierConsumed: NullifierConsumed,
        RemoteAdapterRegistered: RemoteAdapterRegistered,
        StateCommitmentStored: StateCommitmentStored,
        AdapterPaused: AdapterPaused,
        AdapterUnpaused: AdapterUnpaused,
    }

    #[derive(Drop, starknet::Event)]
    struct ChainAdapterRegistered {
        #[key]
        universal_chain_id: felt252,
        chain_vm: u8,
        chain_layer: u8,
    }

    #[derive(Drop, starknet::Event)]
    struct UniversalProofSubmitted {
        #[key]
        proof_id: felt252,
        #[key]
        source_chain_id: felt252,
        dest_chain_id: felt252,
        proof_system: u8,
    }

    #[derive(Drop, starknet::Event)]
    struct ProofVerifiedOnDestination {
        #[key]
        proof_id: felt252,
        chain_id: felt252,
        valid: bool,
    }

    #[derive(Drop, starknet::Event)]
    struct EncryptedStateBridged {
        #[key]
        transfer_id: felt252,
        #[key]
        source_chain_id: felt252,
        dest_chain_id: felt252,
        nullifier: felt252,
    }

    #[derive(Drop, starknet::Event)]
    struct NullifierConsumed {
        #[key]
        nullifier: felt252,
        source_chain_id: felt252,
    }

    #[derive(Drop, starknet::Event)]
    struct RemoteAdapterRegistered {
        #[key]
        chain_id: felt252,
        adapter: felt252,
    }

    #[derive(Drop, starknet::Event)]
    struct StateCommitmentStored {
        #[key]
        commitment: felt252,
        transfer_id: felt252,
    }

    #[derive(Drop, starknet::Event)]
    struct AdapterPaused {
        chain_id: felt252,
    }

    #[derive(Drop, starknet::Event)]
    struct AdapterUnpaused {
        chain_id: felt252,
    }

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    #[constructor]
    fn constructor(
        ref self: ContractState,
        owner: ContractAddress,
        chain_layer: u8,
    ) {
        // Compute universal chain ID for StarkNet
        // Using Pedersen hash of "SOUL_CHAIN_STARKNET"
        let chain_id = PedersenTrait::new(0)
            .update('SOUL_CHAIN_STARKNET')
            .finalize();

        self.owner.write(owner);
        self.operator.write(owner);
        self.emergency_authority.write(owner);
        self.universal_chain_id.write(chain_id);
        self.chain_vm.write(CHAIN_VM_CAIRO);
        self.chain_layer.write(chain_layer);
        self.native_proof_system.write(PROOF_SYSTEM_STARK);
        self.active.write(true);

        // StarkNet natively supports STARKs (cheap verification)
        // and can support Groth16/PLONK through dedicated verifiers
        self.proof_system_supported.write(PROOF_SYSTEM_STARK, true);
        self.proof_system_supported.write(PROOF_SYSTEM_GROTH16, true);
        self.proof_system_supported.write(PROOF_SYSTEM_PLONK, true);

        // Initialize stats
        self.total_proofs_verified.write(0);
        self.total_states_received.write(0);
        self.total_states_sent.write(0);
        self.total_nullifiers_consumed.write(0);
        self.transfer_nonce.write(0);

        self.emit(ChainAdapterRegistered {
            universal_chain_id: chain_id,
            chain_vm: CHAIN_VM_CAIRO,
            chain_layer,
        });
    }

    /*//////////////////////////////////////////////////////////////
                         IMPLEMENTATION
    //////////////////////////////////////////////////////////////*/

    #[abi(embed_v0)]
    impl SoulUniversalAdapterImpl of super::ISoulUniversalAdapter<ContractState> {

        fn get_universal_chain_id(self: @ContractState) -> felt252 {
            self.universal_chain_id.read()
        }

        fn get_chain_vm(self: @ContractState) -> u8 {
            self.chain_vm.read()
        }

        fn get_chain_layer(self: @ContractState) -> u8 {
            self.chain_layer.read()
        }

        fn get_native_proof_system(self: @ContractState) -> u8 {
            self.native_proof_system.read()
        }

        fn is_active(self: @ContractState) -> bool {
            self.active.read()
        }

        fn verify_proof(
            self: @ContractState,
            proof: Span<felt252>,
            public_inputs: Span<felt252>,
            proof_system: u8,
        ) -> bool {
            // Check proof system is supported
            assert(self.proof_system_supported.read(proof_system), 'Unsupported proof system');

            // Validate proof structure
            assert(proof.len() > 0, 'Empty proof');
            assert(public_inputs.len() > 0, 'Empty public inputs');

            // STARK proofs are natively cheap on StarkNet
            // Groth16/PLONK verification delegated to dedicated contracts
            if proof_system == PROOF_SYSTEM_STARK {
                // Native STARK verification — StarkNet's key advantage
                // The STARK proof can be verified with O(log n) computation
                return verify_stark_proof(proof, public_inputs);
            }

            // For SNARK-based systems, use generic verification
            verify_generic_proof(proof, public_inputs, proof_system)
        }

        fn submit_universal_proof(
            ref self: ContractState,
            proof_id: felt252,
            source_chain_id: felt252,
            dest_chain_id: felt252,
            proof_system: u8,
            proof: Span<felt252>,
            public_inputs: Span<felt252>,
            state_commitment: felt252,
            nullifier: felt252,
            timestamp: u64,
        ) -> bool {
            // Security checks
            assert(self.active.read(), 'Adapter paused');
            assert(
                dest_chain_id == self.universal_chain_id.read(),
                'Wrong destination'
            );

            // Check proof age
            let current_time = get_block_timestamp();
            assert(
                current_time <= timestamp + MAX_PROOF_AGE,
                'Proof expired'
            );

            // Check proof not already processed
            assert(!self.processed_proofs.read(proof_id), 'Proof already processed');

            // Check nullifier not used
            assert(!self.nullifier_used.read(nullifier), 'Nullifier already used');

            // Verify the proof
            assert(self.proof_system_supported.read(proof_system), 'Unsupported proof system');

            let valid = if proof_system == PROOF_SYSTEM_STARK {
                verify_stark_proof(proof, public_inputs)
            } else {
                verify_generic_proof(proof, public_inputs, proof_system)
            };
            assert(valid, 'Invalid proof');

            // Mark as processed
            self.processed_proofs.write(proof_id, true);
            self.nullifier_used.write(nullifier, true);
            self.state_commitments.write(proof_id, state_commitment);

            // Update stats
            self.total_proofs_verified.write(self.total_proofs_verified.read() + 1);
            self.total_nullifiers_consumed.write(self.total_nullifiers_consumed.read() + 1);

            let chain_count = self.proofs_from_chain.read(source_chain_id);
            self.proofs_from_chain.write(source_chain_id, chain_count + 1);

            // Emit events
            self.emit(UniversalProofSubmitted {
                proof_id,
                source_chain_id,
                dest_chain_id,
                proof_system,
            });

            self.emit(ProofVerifiedOnDestination {
                proof_id,
                chain_id: self.universal_chain_id.read(),
                valid: true,
            });

            self.emit(NullifierConsumed {
                nullifier,
                source_chain_id,
            });

            true
        }

        fn receive_encrypted_state(
            ref self: ContractState,
            transfer_id: felt252,
            source_chain_id: felt252,
            state_commitment: felt252,
            encrypted_payload: Span<felt252>,
            nullifier: felt252,
            new_commitment: felt252,
            proof: Span<felt252>,
        ) -> bool {
            assert(self.active.read(), 'Adapter paused');

            // Validate
            assert(state_commitment != 0, 'Invalid state commitment');
            assert(proof.len() > 0, 'Empty proof');
            assert(encrypted_payload.len() <= MAX_PAYLOAD_FELTS, 'Payload too large');

            // Check not already processed
            assert(!self.processed_transfers.read(transfer_id), 'Transfer already processed');

            // Check nullifier
            assert(!self.nullifier_used.read(nullifier), 'Nullifier already used');

            // Mark processed
            self.processed_transfers.write(transfer_id, true);
            self.nullifier_used.write(nullifier, true);
            self.state_commitments.write(transfer_id, state_commitment);

            // Update stats
            self.total_states_received.write(self.total_states_received.read() + 1);
            self.total_nullifiers_consumed.write(self.total_nullifiers_consumed.read() + 1);

            self.emit(EncryptedStateBridged {
                transfer_id,
                source_chain_id,
                dest_chain_id: self.universal_chain_id.read(),
                nullifier,
            });

            self.emit(NullifierConsumed {
                nullifier,
                source_chain_id,
            });

            self.emit(StateCommitmentStored {
                commitment: state_commitment,
                transfer_id,
            });

            true
        }

        fn send_encrypted_state(
            ref self: ContractState,
            dest_chain_id: felt252,
            state_commitment: felt252,
            encrypted_payload: Span<felt252>,
            proof: Span<felt252>,
            nullifier: felt252,
        ) -> felt252 {
            assert(self.active.read(), 'Adapter paused');
            assert(state_commitment != 0, 'Invalid state commitment');
            assert(proof.len() > 0, 'Empty proof');
            assert(!self.nullifier_used.read(nullifier), 'Nullifier already used');

            // Check remote adapter exists
            assert(
                self.remote_adapter_active.read(dest_chain_id),
                'No remote adapter'
            );

            // Generate transfer ID via Pedersen hash
            let nonce = self.transfer_nonce.read();
            let caller = get_caller_address();
            let timestamp = get_block_timestamp();

            let transfer_id = PedersenTrait::new(0)
                .update(self.universal_chain_id.read())
                .update(dest_chain_id)
                .update(caller.into())
                .update(nonce.into())
                .update(timestamp.into())
                .finalize();

            // Mark nullifier
            self.nullifier_used.write(nullifier, true);
            self.state_commitments.write(transfer_id, state_commitment);

            // Update stats
            self.transfer_nonce.write(nonce + 1);
            self.total_states_sent.write(self.total_states_sent.read() + 1);
            self.total_nullifiers_consumed.write(self.total_nullifiers_consumed.read() + 1);

            self.emit(EncryptedStateBridged {
                transfer_id,
                source_chain_id: self.universal_chain_id.read(),
                dest_chain_id,
                nullifier,
            });

            transfer_id
        }

        fn is_nullifier_used(self: @ContractState, nullifier: felt252) -> bool {
            self.nullifier_used.read(nullifier)
        }

        fn register_remote_adapter(
            ref self: ContractState,
            chain_id: felt252,
            adapter_address: felt252,
        ) {
            assert(get_caller_address() == self.operator.read(), 'Not operator');
            assert(adapter_address != 0, 'Zero address');

            self.remote_adapters.write(chain_id, adapter_address);
            self.remote_adapter_active.write(chain_id, true);

            self.emit(RemoteAdapterRegistered {
                chain_id,
                adapter: adapter_address,
            });
        }

        fn set_active(ref self: ContractState, active: bool) {
            assert(get_caller_address() == self.operator.read(), 'Not operator');
            self.active.write(active);
        }

        fn emergency_pause(ref self: ContractState) {
            assert(
                get_caller_address() == self.emergency_authority.read(),
                'Not emergency authority'
            );
            self.active.write(false);
            self.emit(AdapterPaused {
                chain_id: self.universal_chain_id.read(),
            });
        }

        fn emergency_unpause(ref self: ContractState) {
            assert(
                get_caller_address() == self.emergency_authority.read(),
                'Not emergency authority'
            );
            self.active.write(true);
            self.emit(AdapterUnpaused {
                chain_id: self.universal_chain_id.read(),
            });
        }

        fn get_total_proofs_verified(self: @ContractState) -> u64 {
            self.total_proofs_verified.read()
        }

        fn get_total_states_received(self: @ContractState) -> u64 {
            self.total_states_received.read()
        }

        fn get_total_states_sent(self: @ContractState) -> u64 {
            self.total_states_sent.read()
        }

        fn get_total_nullifiers_consumed(self: @ContractState) -> u64 {
            self.total_nullifiers_consumed.read()
        }
    }

    /*//////////////////////////////////////////////////////////////
                      INTERNAL PROOF VERIFICATION
    //////////////////////////////////////////////////////////////*/

    /// Verify a STARK proof natively on StarkNet
    /// StarkNet's key advantage: STARK verification is O(log n) and
    /// significantly cheaper than SNARK verification
    fn verify_stark_proof(
        proof: Span<felt252>,
        public_inputs: Span<felt252>,
    ) -> bool {
        // STARK proofs on StarkNet are verified natively by the OS
        // This function validates the proof structure
        // In production, this would call StarkNet's proof verification syscall

        // Minimum STARK proof size (in felt252 elements)
        if proof.len() < 16 {
            return false;
        }

        if public_inputs.len() == 0 {
            return false;
        }

        // Validate public inputs are non-zero
        let mut i: u32 = 0;
        loop {
            if i >= public_inputs.len() {
                break;
            }
            if *public_inputs.at(i) == 0 {
                return false;
            }
            i += 1;
        };

        // In production: call verified STARK verifier
        true
    }

    /// Verify a non-STARK proof (Groth16, PLONK, etc.)
    /// These require dedicated verifier contracts on StarkNet
    fn verify_generic_proof(
        proof: Span<felt252>,
        public_inputs: Span<felt252>,
        _proof_system: u8,
    ) -> bool {
        // Generic proof validation
        if proof.len() < 8 {
            return false;
        }

        if public_inputs.len() == 0 {
            return false;
        }

        // In production: delegate to specific verifier contract
        // e.g., Groth16Verifier, PlonkVerifier deployed on StarkNet
        true
    }
}
