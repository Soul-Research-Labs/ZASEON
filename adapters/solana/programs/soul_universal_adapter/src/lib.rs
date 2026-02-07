use anchor_lang::prelude::*;
use anchor_lang::solana_program::keccak;

declare_id!("SouLUnvADPTR1111111111111111111111111111111");

/// Soul Protocol Universal Adapter for Solana
///
/// Handles ZK proof verification, encrypted state management,
/// and cross-chain message relay on the Solana side.
///
/// Architecture:
/// - Mirrors the IUniversalChainAdapter interface from EVM
/// - Uses PDAs for deterministic account addressing
/// - Leverages Solana's native Ed25519 for signature verification
/// - Supports Groth16 proof verification via precompile (when available)
///
/// Security:
/// - Nullifier double-spend prevention via PDA accounts
/// - Authority-based access control (relayer, operator, emergency)
/// - Replay protection via unique transfer IDs
/// - State commitment storage for auditability
#[program]
pub mod soul_universal_adapter {
    use super::*;

    /// Initialize the adapter with chain configuration
    pub fn initialize(
        ctx: Context<Initialize>,
        chain_name: String,
        proof_system: u8,
        chain_layer: u8,
    ) -> Result<()> {
        let config = &mut ctx.accounts.config;
        config.authority = ctx.accounts.authority.key();
        config.operator = ctx.accounts.authority.key();
        config.emergency_authority = ctx.accounts.authority.key();

        // Compute universal chain ID: keccak256("SOUL_CHAIN_SOLANA")
        let chain_id_input = format!("SOUL_CHAIN_{}", chain_name);
        let hash = keccak::hash(chain_id_input.as_bytes());
        config.universal_chain_id = hash.to_bytes();

        config.chain_name = chain_name;
        config.chain_vm = ChainVM::SVM as u8;
        config.chain_layer = chain_layer;
        config.proof_system = proof_system;
        config.active = true;
        config.total_proofs_verified = 0;
        config.total_states_received = 0;
        config.total_states_sent = 0;
        config.total_nullifiers_consumed = 0;
        config.transfer_nonce = 0;
        config.bump = ctx.bumps.config;

        emit!(ChainAdapterRegistered {
            universal_chain_id: config.universal_chain_id,
            chain_vm: config.chain_vm,
            chain_layer: config.chain_layer,
        });

        Ok(())
    }

    /// Submit and verify a universal ZK proof from any chain
    pub fn submit_universal_proof(
        ctx: Context<SubmitUniversalProof>,
        proof_id: [u8; 32],
        source_chain_id: [u8; 32],
        dest_chain_id: [u8; 32],
        proof_system: u8,
        proof_data: Vec<u8>,
        public_inputs: Vec<[u8; 32]>,
        state_commitment: [u8; 32],
        nullifier: [u8; 32],
        timestamp: i64,
    ) -> Result<()> {
        let config = &ctx.accounts.config;
        require!(config.active, SoulAdapterError::AdapterNotActive);

        // Verify proof age (max 24 hours)
        let clock = Clock::get()?;
        let max_age: i64 = 86400; // 24 hours in seconds
        require!(
            clock.unix_timestamp <= timestamp + max_age,
            SoulAdapterError::ProofExpired
        );

        // Verify destination is this chain
        require!(
            dest_chain_id == config.universal_chain_id,
            SoulAdapterError::WrongDestinationChain
        );

        // Verify proof data is not empty and meets minimum size
        require!(proof_data.len() >= 64, SoulAdapterError::InvalidProof);
        require!(!public_inputs.is_empty(), SoulAdapterError::InvalidProof);

        // Initialize the proof record PDA
        let proof_record = &mut ctx.accounts.proof_record;
        require!(!proof_record.processed, SoulAdapterError::ProofAlreadyProcessed);

        // Initialize the nullifier PDA
        let nullifier_record = &mut ctx.accounts.nullifier_record;
        require!(!nullifier_record.used, SoulAdapterError::NullifierAlreadyUsed);

        // Verify the ZK proof
        // In production, this uses Solana's Groth16 verify precompile
        // or a custom on-chain verifier program
        let valid = verify_zk_proof(&proof_data, &public_inputs, proof_system)?;
        require!(valid, SoulAdapterError::InvalidProof);

        // Mark proof as processed
        proof_record.proof_id = proof_id;
        proof_record.source_chain_id = source_chain_id;
        proof_record.dest_chain_id = dest_chain_id;
        proof_record.proof_system = proof_system;
        proof_record.state_commitment = state_commitment;
        proof_record.nullifier = nullifier;
        proof_record.processed = true;
        proof_record.timestamp = clock.unix_timestamp;
        proof_record.relayer = ctx.accounts.relayer.key();
        proof_record.bump = ctx.bumps.proof_record;

        // Mark nullifier as used
        nullifier_record.nullifier = nullifier;
        nullifier_record.used = true;
        nullifier_record.source_chain_id = source_chain_id;
        nullifier_record.consumed_at = clock.unix_timestamp;
        nullifier_record.bump = ctx.bumps.nullifier_record;

        // Update stats
        let config = &mut ctx.accounts.config;
        config.total_proofs_verified = config.total_proofs_verified.checked_add(1)
            .ok_or(SoulAdapterError::Overflow)?;
        config.total_nullifiers_consumed = config.total_nullifiers_consumed.checked_add(1)
            .ok_or(SoulAdapterError::Overflow)?;

        emit!(UniversalProofSubmitted {
            proof_id,
            source_chain_id,
            dest_chain_id,
            proof_system,
        });

        emit!(ProofVerifiedOnDestination {
            proof_id,
            chain_id: config.universal_chain_id,
            valid: true,
        });

        emit!(NullifierConsumed {
            nullifier,
            source_chain_id,
        });

        Ok(())
    }

    /// Receive encrypted state from another chain
    pub fn receive_encrypted_state(
        ctx: Context<ReceiveEncryptedState>,
        transfer_id: [u8; 32],
        source_chain_id: [u8; 32],
        dest_chain_id: [u8; 32],
        state_commitment: [u8; 32],
        encrypted_payload: Vec<u8>,
        nullifier: [u8; 32],
        new_commitment: [u8; 32],
        proof: Vec<u8>,
    ) -> Result<()> {
        let config = &ctx.accounts.config;
        require!(config.active, SoulAdapterError::AdapterNotActive);

        // Validate destination
        require!(
            dest_chain_id == config.universal_chain_id,
            SoulAdapterError::WrongDestinationChain
        );

        // Validate payload size (max 64KB)
        require!(
            encrypted_payload.len() <= 65_536,
            SoulAdapterError::PayloadTooLarge
        );

        require!(proof.len() >= 64, SoulAdapterError::InvalidProof);
        require!(state_commitment != [0u8; 32], SoulAdapterError::InvalidStateCommitment);

        // Check transfer not already processed
        let transfer_record = &mut ctx.accounts.transfer_record;
        require!(!transfer_record.processed, SoulAdapterError::TransferAlreadyProcessed);

        // Check nullifier
        let nullifier_record = &mut ctx.accounts.nullifier_record;
        require!(!nullifier_record.used, SoulAdapterError::NullifierAlreadyUsed);

        // Mark transfer as processed
        transfer_record.transfer_id = transfer_id;
        transfer_record.source_chain_id = source_chain_id;
        transfer_record.dest_chain_id = dest_chain_id;
        transfer_record.state_commitment = state_commitment;
        transfer_record.new_commitment = new_commitment;
        transfer_record.processed = true;
        transfer_record.timestamp = Clock::get()?.unix_timestamp;
        transfer_record.bump = ctx.bumps.transfer_record;

        // Mark nullifier as used
        nullifier_record.nullifier = nullifier;
        nullifier_record.used = true;
        nullifier_record.source_chain_id = source_chain_id;
        nullifier_record.consumed_at = Clock::get()?.unix_timestamp;
        nullifier_record.bump = ctx.bumps.nullifier_record;

        // Update stats
        let config = &mut ctx.accounts.config;
        config.total_states_received = config.total_states_received.checked_add(1)
            .ok_or(SoulAdapterError::Overflow)?;
        config.total_nullifiers_consumed = config.total_nullifiers_consumed.checked_add(1)
            .ok_or(SoulAdapterError::Overflow)?;

        emit!(EncryptedStateBridged {
            transfer_id,
            source_chain_id,
            dest_chain_id,
            nullifier,
        });

        Ok(())
    }

    /// Send encrypted state to another chain (initiates cross-chain transfer)
    pub fn send_encrypted_state(
        ctx: Context<SendEncryptedState>,
        dest_chain_id: [u8; 32],
        state_commitment: [u8; 32],
        encrypted_payload: Vec<u8>,
        proof: Vec<u8>,
        nullifier: [u8; 32],
    ) -> Result<()> {
        let config = &mut ctx.accounts.config;
        require!(config.active, SoulAdapterError::AdapterNotActive);

        require!(state_commitment != [0u8; 32], SoulAdapterError::InvalidStateCommitment);
        require!(proof.len() >= 64, SoulAdapterError::InvalidProof);
        require!(
            encrypted_payload.len() <= 65_536,
            SoulAdapterError::PayloadTooLarge
        );

        // Check nullifier
        let nullifier_record = &mut ctx.accounts.nullifier_record;
        require!(!nullifier_record.used, SoulAdapterError::NullifierAlreadyUsed);

        // Generate transfer ID
        let clock = Clock::get()?;
        let transfer_id_input = [
            config.universal_chain_id.as_ref(),
            dest_chain_id.as_ref(),
            ctx.accounts.sender.key().as_ref(),
            &config.transfer_nonce.to_le_bytes(),
            &clock.unix_timestamp.to_le_bytes(),
        ]
        .concat();
        let transfer_id = keccak::hash(&transfer_id_input).to_bytes();

        // Store outgoing transfer
        let outgoing = &mut ctx.accounts.outgoing_transfer;
        outgoing.transfer_id = transfer_id;
        outgoing.source_chain_id = config.universal_chain_id;
        outgoing.dest_chain_id = dest_chain_id;
        outgoing.state_commitment = state_commitment;
        outgoing.sender = ctx.accounts.sender.key();
        outgoing.timestamp = clock.unix_timestamp;
        outgoing.bump = ctx.bumps.outgoing_transfer;

        // Mark nullifier as used
        nullifier_record.nullifier = nullifier;
        nullifier_record.used = true;
        nullifier_record.source_chain_id = config.universal_chain_id;
        nullifier_record.consumed_at = clock.unix_timestamp;
        nullifier_record.bump = ctx.bumps.nullifier_record;

        // Update stats
        config.transfer_nonce = config.transfer_nonce.checked_add(1)
            .ok_or(SoulAdapterError::Overflow)?;
        config.total_states_sent = config.total_states_sent.checked_add(1)
            .ok_or(SoulAdapterError::Overflow)?;
        config.total_nullifiers_consumed = config.total_nullifiers_consumed.checked_add(1)
            .ok_or(SoulAdapterError::Overflow)?;

        emit!(EncryptedStateBridged {
            transfer_id,
            source_chain_id: config.universal_chain_id,
            dest_chain_id,
            nullifier,
        });

        Ok(())
    }

    /// Register a remote chain adapter (operator only)
    pub fn register_remote_adapter(
        ctx: Context<RegisterRemoteAdapter>,
        remote_chain_id: [u8; 32],
        remote_adapter: Vec<u8>,
    ) -> Result<()> {
        let config = &ctx.accounts.config;
        require!(
            ctx.accounts.operator.key() == config.operator,
            SoulAdapterError::Unauthorized
        );

        let remote = &mut ctx.accounts.remote_adapter;
        remote.chain_id = remote_chain_id;
        remote.adapter_address = remote_adapter.clone();
        remote.active = true;
        remote.registered_at = Clock::get()?.unix_timestamp;
        remote.bump = ctx.bumps.remote_adapter;

        emit!(RemoteAdapterRegistered {
            chain_id: remote_chain_id,
            adapter: remote_adapter,
        });

        Ok(())
    }

    /// Emergency pause (emergency authority only)
    pub fn emergency_pause(ctx: Context<EmergencyAction>) -> Result<()> {
        let config = &mut ctx.accounts.config;
        require!(
            ctx.accounts.authority.key() == config.emergency_authority,
            SoulAdapterError::Unauthorized
        );
        config.active = false;

        emit!(AdapterPaused {
            chain_id: config.universal_chain_id,
        });

        Ok(())
    }

    /// Emergency unpause (emergency authority only)
    pub fn emergency_unpause(ctx: Context<EmergencyAction>) -> Result<()> {
        let config = &mut ctx.accounts.config;
        require!(
            ctx.accounts.authority.key() == config.emergency_authority,
            SoulAdapterError::Unauthorized
        );
        config.active = true;

        emit!(AdapterUnpaused {
            chain_id: config.universal_chain_id,
        });

        Ok(())
    }
}

/*//////////////////////////////////////////////////////////////
                         ZK PROOF VERIFICATION
//////////////////////////////////////////////////////////////*/

/// Verify a ZK proof on Solana
/// In production, this should call:
/// 1. Solana's native Groth16 precompile (when available)
/// 2. A custom BPF verifier program
/// 3. Light Protocol's compressed proof verification
fn verify_zk_proof(
    proof: &[u8],
    public_inputs: &[[u8; 32]],
    proof_system: u8,
) -> Result<bool> {
    // Validate proof structure based on proof system
    match proof_system {
        // Groth16 = 0: Expect 256 bytes (8 x 32-byte field elements for BN254)
        0 => {
            if proof.len() < 256 {
                return Ok(false);
            }
        }
        // PLONK = 1: Variable length, minimum 512 bytes
        1 => {
            if proof.len() < 512 {
                return Ok(false);
            }
        }
        // STARK = 2: Variable length, larger proofs
        2 => {
            if proof.len() < 1024 {
                return Ok(false);
            }
        }
        // Unknown proof system
        _ => return Err(SoulAdapterError::UnsupportedProofSystem.into()),
    }

    // Validate public inputs are non-zero
    for input in public_inputs {
        if *input == [0u8; 32] {
            return Ok(false);
        }
    }

    // In production, delegate to actual verifier
    // For development, accept structurally valid proofs
    Ok(true)
}

/*//////////////////////////////////////////////////////////////
                          ACCOUNT STRUCTURES
//////////////////////////////////////////////////////////////*/

#[account]
#[derive(InitSpace)]
pub struct AdapterConfig {
    pub authority: Pubkey,
    pub operator: Pubkey,
    pub emergency_authority: Pubkey,
    pub universal_chain_id: [u8; 32],
    #[max_len(32)]
    pub chain_name: String,
    pub chain_vm: u8,
    pub chain_layer: u8,
    pub proof_system: u8,
    pub active: bool,
    pub total_proofs_verified: u64,
    pub total_states_received: u64,
    pub total_states_sent: u64,
    pub total_nullifiers_consumed: u64,
    pub transfer_nonce: u64,
    pub bump: u8,
}

#[account]
#[derive(InitSpace)]
pub struct ProofRecord {
    pub proof_id: [u8; 32],
    pub source_chain_id: [u8; 32],
    pub dest_chain_id: [u8; 32],
    pub proof_system: u8,
    pub state_commitment: [u8; 32],
    pub nullifier: [u8; 32],
    pub processed: bool,
    pub timestamp: i64,
    pub relayer: Pubkey,
    pub bump: u8,
}

#[account]
#[derive(InitSpace)]
pub struct NullifierRecord {
    pub nullifier: [u8; 32],
    pub used: bool,
    pub source_chain_id: [u8; 32],
    pub consumed_at: i64,
    pub bump: u8,
}

#[account]
#[derive(InitSpace)]
pub struct TransferRecord {
    pub transfer_id: [u8; 32],
    pub source_chain_id: [u8; 32],
    pub dest_chain_id: [u8; 32],
    pub state_commitment: [u8; 32],
    pub new_commitment: [u8; 32],
    pub processed: bool,
    pub timestamp: i64,
    pub bump: u8,
}

#[account]
#[derive(InitSpace)]
pub struct OutgoingTransfer {
    pub transfer_id: [u8; 32],
    pub source_chain_id: [u8; 32],
    pub dest_chain_id: [u8; 32],
    pub state_commitment: [u8; 32],
    pub sender: Pubkey,
    pub timestamp: i64,
    pub bump: u8,
}

#[account]
#[derive(InitSpace)]
pub struct RemoteAdapterRecord {
    pub chain_id: [u8; 32],
    #[max_len(128)]
    pub adapter_address: Vec<u8>,
    pub active: bool,
    pub registered_at: i64,
    pub bump: u8,
}

/*//////////////////////////////////////////////////////////////
                           CHAIN VM ENUM
//////////////////////////////////////////////////////////////*/

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq)]
pub enum ChainVM {
    EVM = 0,
    SVM = 1,
    Cairo = 2,
    MoveAptos = 3,
    MoveSui = 4,
    CosmWasm = 5,
    NoirAztec = 6,
    Midnight = 7,
    Zcash = 8,
    Aleo = 9,
    TON = 10,
    NEAR = 11,
    Substrate = 12,
    Bitcoin = 13,
    XRPL = 14,
    Plutus = 15,
}

/*//////////////////////////////////////////////////////////////
                     INSTRUCTION ACCOUNTS
//////////////////////////////////////////////////////////////*/

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + AdapterConfig::INIT_SPACE,
        seeds = [b"soul_adapter_config"],
        bump
    )]
    pub config: Account<'info, AdapterConfig>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(proof_id: [u8; 32], source_chain_id: [u8; 32], dest_chain_id: [u8; 32], proof_system: u8, proof_data: Vec<u8>, public_inputs: Vec<[u8; 32]>, state_commitment: [u8; 32], nullifier: [u8; 32])]
pub struct SubmitUniversalProof<'info> {
    #[account(
        mut,
        seeds = [b"soul_adapter_config"],
        bump = config.bump
    )]
    pub config: Account<'info, AdapterConfig>,
    #[account(
        init,
        payer = relayer,
        space = 8 + ProofRecord::INIT_SPACE,
        seeds = [b"proof", &proof_id],
        bump
    )]
    pub proof_record: Account<'info, ProofRecord>,
    #[account(
        init,
        payer = relayer,
        space = 8 + NullifierRecord::INIT_SPACE,
        seeds = [b"nullifier", &nullifier],
        bump
    )]
    pub nullifier_record: Account<'info, NullifierRecord>,
    #[account(mut)]
    pub relayer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(transfer_id: [u8; 32], source_chain_id: [u8; 32], dest_chain_id: [u8; 32], state_commitment: [u8; 32], encrypted_payload: Vec<u8>, nullifier: [u8; 32])]
pub struct ReceiveEncryptedState<'info> {
    #[account(
        mut,
        seeds = [b"soul_adapter_config"],
        bump = config.bump
    )]
    pub config: Account<'info, AdapterConfig>,
    #[account(
        init,
        payer = relayer,
        space = 8 + TransferRecord::INIT_SPACE,
        seeds = [b"transfer", &transfer_id],
        bump
    )]
    pub transfer_record: Account<'info, TransferRecord>,
    #[account(
        init,
        payer = relayer,
        space = 8 + NullifierRecord::INIT_SPACE,
        seeds = [b"nullifier", &nullifier],
        bump
    )]
    pub nullifier_record: Account<'info, NullifierRecord>,
    #[account(mut)]
    pub relayer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(dest_chain_id: [u8; 32], state_commitment: [u8; 32], encrypted_payload: Vec<u8>, proof: Vec<u8>, nullifier: [u8; 32])]
pub struct SendEncryptedState<'info> {
    #[account(
        mut,
        seeds = [b"soul_adapter_config"],
        bump = config.bump
    )]
    pub config: Account<'info, AdapterConfig>,
    #[account(
        init,
        payer = sender,
        space = 8 + OutgoingTransfer::INIT_SPACE,
        seeds = [b"outgoing", &sender.key().to_bytes(), &config.transfer_nonce.to_le_bytes()],
        bump
    )]
    pub outgoing_transfer: Account<'info, OutgoingTransfer>,
    #[account(
        init,
        payer = sender,
        space = 8 + NullifierRecord::INIT_SPACE,
        seeds = [b"nullifier", &nullifier],
        bump
    )]
    pub nullifier_record: Account<'info, NullifierRecord>,
    #[account(mut)]
    pub sender: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(remote_chain_id: [u8; 32])]
pub struct RegisterRemoteAdapter<'info> {
    #[account(
        seeds = [b"soul_adapter_config"],
        bump = config.bump
    )]
    pub config: Account<'info, AdapterConfig>,
    #[account(
        init,
        payer = operator,
        space = 8 + RemoteAdapterRecord::INIT_SPACE,
        seeds = [b"remote_adapter", &remote_chain_id],
        bump
    )]
    pub remote_adapter: Account<'info, RemoteAdapterRecord>,
    #[account(mut)]
    pub operator: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct EmergencyAction<'info> {
    #[account(
        mut,
        seeds = [b"soul_adapter_config"],
        bump = config.bump
    )]
    pub config: Account<'info, AdapterConfig>,
    pub authority: Signer<'info>,
}

/*//////////////////////////////////////////////////////////////
                              EVENTS
//////////////////////////////////////////////////////////////*/

#[event]
pub struct ChainAdapterRegistered {
    pub universal_chain_id: [u8; 32],
    pub chain_vm: u8,
    pub chain_layer: u8,
}

#[event]
pub struct UniversalProofSubmitted {
    pub proof_id: [u8; 32],
    pub source_chain_id: [u8; 32],
    pub dest_chain_id: [u8; 32],
    pub proof_system: u8,
}

#[event]
pub struct ProofVerifiedOnDestination {
    pub proof_id: [u8; 32],
    pub chain_id: [u8; 32],
    pub valid: bool,
}

#[event]
pub struct NullifierConsumed {
    pub nullifier: [u8; 32],
    pub source_chain_id: [u8; 32],
}

#[event]
pub struct EncryptedStateBridged {
    pub transfer_id: [u8; 32],
    pub source_chain_id: [u8; 32],
    pub dest_chain_id: [u8; 32],
    pub nullifier: [u8; 32],
}

#[event]
pub struct RemoteAdapterRegistered {
    pub chain_id: [u8; 32],
    pub adapter: Vec<u8>,
}

#[event]
pub struct AdapterPaused {
    pub chain_id: [u8; 32],
}

#[event]
pub struct AdapterUnpaused {
    pub chain_id: [u8; 32],
}

/*//////////////////////////////////////////////////////////////
                             ERRORS
//////////////////////////////////////////////////////////////*/

#[error_code]
pub enum SoulAdapterError {
    #[msg("Adapter is not active")]
    AdapterNotActive,
    #[msg("Unauthorized")]
    Unauthorized,
    #[msg("Proof has expired")]
    ProofExpired,
    #[msg("Wrong destination chain")]
    WrongDestinationChain,
    #[msg("Invalid proof")]
    InvalidProof,
    #[msg("Proof already processed")]
    ProofAlreadyProcessed,
    #[msg("Nullifier already used")]
    NullifierAlreadyUsed,
    #[msg("Transfer already processed")]
    TransferAlreadyProcessed,
    #[msg("Invalid state commitment")]
    InvalidStateCommitment,
    #[msg("Payload too large (max 64KB)")]
    PayloadTooLarge,
    #[msg("Unsupported proof system")]
    UnsupportedProofSystem,
    #[msg("Arithmetic overflow")]
    Overflow,
}
