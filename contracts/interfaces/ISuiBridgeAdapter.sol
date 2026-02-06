// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title ISuiBridgeAdapter
 * @author Soul Protocol
 * @notice Interface for the Sui bridge adapter
 * @dev Enables cross-chain interoperability between Soul Protocol and the Sui Network
 *
 * SUI INTEGRATION MODEL:
 *
 *   ┌───────────────────────────┐         ┌───────────────────────────┐
 *   │      Soul Protocol        │         │        Sui Network        │
 *   │  ┌─────────────────────┐  │         │  ┌─────────────────────┐  │
 *   │  │ SuiBridge           │◄─┼────────►│  │  Sui Bridge Object  │  │
 *   │  │ Adapter (EVM side)  │  │         │  │  (Move module)      │  │
 *   │  └─────────────────────┘  │         │  └─────────────────────┘  │
 *   │        │                  │         │        │                  │
 *   │  ┌─────▼───────────────┐  │         │  ┌─────▼───────────────┐  │
 *   │  │  Privacy Layer      │  │         │  │  Checkpoint          │  │
 *   │  │  (ZK Commitments)   │  │         │  │  (Consensus Commit) │  │
 *   │  └─────────────────────┘  │         │  └─────────────────────┘  │
 *   └───────────────────────────┘         └───────────────────────────┘
 *
 * BRIDGE MECHANISMS:
 * 1. Lock & Mint: Lock SUI on Sui → Mint wSUI on Soul Protocol
 * 2. Burn & Release: Burn wSUI on Soul → Release SUI on Sui Network
 * 3. Checkpoint Verification: Validator committee attests to checkpoint digests
 * 4. HTLC Escrow: Atomic swaps with hashlock/timelock conditions
 *
 * PROOF VERIFICATION:
 * - Sui uses Mysticeti BFT consensus with sub-second finality (~400ms)
 * - Validators sign checkpoint summaries containing transaction effects
 * - Committee-based threshold signature verification (2/3+1 stake weight)
 * - Object inclusion proofs verify object state against checkpoint roots
 * - Epoch-based validator reconfiguration with stake delegation
 *
 * SUI CONCEPTS:
 * - MIST: Smallest unit of SUI (1 SUI = 1e9 MIST, 9 decimals)
 * - Object Model: Unique owned/shared objects with versioning
 * - Checkpoint: Certified output of consensus containing transaction effects
 * - Epoch: Period between validator committee reconfigurations (~24h)
 * - Transaction Digest: 32-byte Blake2b hash uniquely identifying a transaction
 * - Object ID: 32-byte unique identifier for on-chain objects
 * - Mysticeti: DAG-based BFT consensus protocol with low latency
 * - Chain ID: sui-mainnet → numeric 784 for EVM mapping
 * - Finality: 10 checkpoint confirmations for cross-chain safety
 * - Block time: ~400ms (Mysticeti consensus rounds)
 */
interface ISuiBridgeAdapter {
    /*//////////////////////////////////////////////////////////////
                                ENUMS
    //////////////////////////////////////////////////////////////*/

    /// @notice Status of a SUI deposit (Sui → Soul)
    enum DepositStatus {
        PENDING,
        VERIFIED,
        COMPLETED,
        FAILED
    }

    /// @notice Status of a SUI withdrawal (Soul → Sui)
    enum WithdrawalStatus {
        PENDING,
        PROCESSING,
        COMPLETED,
        REFUNDED,
        FAILED
    }

    /// @notice Status of a token swap escrow
    enum EscrowStatus {
        ACTIVE,
        FINISHED,
        CANCELLED
    }

    /// @notice Types of Sui bridge operations
    enum SuiBridgeOpType {
        TOKEN_TRANSFER, // Standard token transfer
        OBJECT_TRANSFER, // Object-based transfer
        COMMITTEE_UPDATE, // Validator committee rotation
        EMERGENCY_OP // Emergency bridge operation
    }

    /*//////////////////////////////////////////////////////////////
                               STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Bridge configuration for Sui integration
    struct BridgeConfig {
        address suiBridgeContract;
        address wrappedSUI;
        address validatorCommitteeOracle;
        uint256 minCommitteeSignatures;
        uint256 requiredCheckpointConfirmations;
        bool active;
    }

    /// @notice SUI deposit record
    /// @dev Tracks MIST-denominated deposits from Sui to Soul
    struct SUIDeposit {
        bytes32 depositId;
        bytes32 suiTxDigest;
        bytes32 suiSender; // 32-byte Sui address
        address evmRecipient;
        uint256 amountMist;
        uint256 netAmountMist;
        uint256 fee;
        DepositStatus status;
        uint256 checkpointSequence;
        uint256 initiatedAt;
        uint256 completedAt;
    }

    /// @notice SUI withdrawal record
    /// @dev Tracks MIST-denominated withdrawals from Soul to Sui
    struct SUIWithdrawal {
        bytes32 withdrawalId;
        address evmSender;
        bytes32 suiRecipient; // 32-byte Sui address
        uint256 amountMist;
        bytes32 suiTxDigest;
        WithdrawalStatus status;
        uint256 initiatedAt;
        uint256 completedAt;
    }

    /// @notice HTLC escrow for atomic swaps
    struct SUIEscrow {
        bytes32 escrowId;
        address evmParty;
        bytes32 suiParty; // 32-byte Sui address
        uint256 amountMist;
        bytes32 hashlock;
        bytes32 preimage;
        uint256 finishAfter;
        uint256 cancelAfter;
        EscrowStatus status;
        uint256 createdAt;
    }

    /// @notice Sui checkpoint record
    /// @dev Represents a certified checkpoint from the Sui network
    struct SuiCheckpoint {
        uint256 sequenceNumber;
        bytes32 digest; // Checkpoint digest (Blake2b hash)
        bytes32 previousDigest;
        bytes32 transactionDigestRoot;
        bytes32 effectsRoot;
        uint256 epoch;
        bytes32 validatorSetHash; // Hash of active validator committee
        uint256 timestampMs;
        bool verified;
    }

    /// @notice Validator committee attestation
    /// @dev Sui validators sign checkpoint summaries; requires 2/3+1 stake weight
    struct ValidatorAttestation {
        bytes32 validatorPublicKey; // BLS12-381 compressed public key hash
        bytes signature;
    }

    /// @notice Object inclusion proof for Sui's object model
    /// @dev Proves an object's state is included in a checkpoint
    struct SuiObjectProof {
        bytes32 objectId;
        uint256 version;
        bytes32 objectDigest;
        bytes32[] proof; // Merkle proof path
        uint256 proofIndex;
    }

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event BridgeConfigured(
        address indexed suiBridgeContract,
        address wrappedSUI,
        address validatorCommitteeOracle
    );
    event SUIDepositInitiated(
        bytes32 indexed depositId,
        bytes32 indexed suiTxDigest,
        bytes32 suiSender,
        address indexed evmRecipient,
        uint256 amountMist
    );
    event SUIDepositCompleted(
        bytes32 indexed depositId,
        address indexed evmRecipient,
        uint256 amountMist
    );
    event SUIWithdrawalInitiated(
        bytes32 indexed withdrawalId,
        address indexed evmSender,
        bytes32 suiRecipient,
        uint256 amountMist
    );
    event SUIWithdrawalCompleted(
        bytes32 indexed withdrawalId,
        bytes32 suiTxDigest
    );
    event SUIWithdrawalRefunded(
        bytes32 indexed withdrawalId,
        address indexed evmSender,
        uint256 amountMist
    );
    event EscrowCreated(
        bytes32 indexed escrowId,
        address indexed evmParty,
        bytes32 suiParty,
        uint256 amountMist,
        bytes32 hashlock
    );
    event EscrowFinished(bytes32 indexed escrowId, bytes32 preimage);
    event EscrowCancelled(bytes32 indexed escrowId);
    event CheckpointVerified(
        uint256 indexed sequenceNumber,
        bytes32 digest,
        uint256 epoch
    );
    event PrivateDepositRegistered(
        bytes32 indexed depositId,
        bytes32 commitment,
        bytes32 nullifier
    );
    event FeesWithdrawn(address indexed recipient, uint256 amount);

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    error InvalidSuiAddress();
    error InvalidAmount();
    error AmountBelowMinimum(uint256 amount, uint256 minimum);
    error AmountAboveMaximum(uint256 amount, uint256 maximum);
    error DepositNotFound(bytes32 depositId);
    error DepositAlreadyCompleted(bytes32 depositId);
    error DepositNotVerified(bytes32 depositId);
    error WithdrawalNotFound(bytes32 withdrawalId);
    error WithdrawalNotPending(bytes32 withdrawalId);
    error WithdrawalAlreadyCompleted(bytes32 withdrawalId);
    error RefundTooEarly(uint256 currentTime, uint256 refundTime);
    error EscrowNotFound(bytes32 escrowId);
    error EscrowNotActive(bytes32 escrowId);
    error EscrowTimelockNotMet();
    error InvalidHashlock();
    error InvalidPreimage();
    error InvalidTimelockRange();
    error SuiTxAlreadyUsed(bytes32 suiTxDigest);
    error CheckpointNotVerified(uint256 sequenceNumber);
    error InvalidCheckpointProof();
    error InsufficientCommitteeSignatures(uint256 provided, uint256 required);
    error BridgeNotConfigured();
    error NullifierAlreadyUsed(bytes32 nullifier);
    error ZeroAddress();

    /*//////////////////////////////////////////////////////////////
                              FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    // --- Configuration ---

    function configure(
        address suiBridgeContract,
        address wrappedSUI,
        address validatorCommitteeOracle,
        uint256 minCommitteeSignatures,
        uint256 requiredCheckpointConfirmations
    ) external;

    // --- Deposits (Sui → Soul) ---

    function initiateSUIDeposit(
        bytes32 suiTxDigest,
        bytes32 suiSender,
        address evmRecipient,
        uint256 amountMist,
        uint256 checkpointSequence,
        SuiObjectProof calldata txProof,
        ValidatorAttestation[] calldata attestations
    ) external returns (bytes32);

    function completeSUIDeposit(bytes32 depositId) external;

    // --- Withdrawals (Soul → Sui) ---

    function initiateWithdrawal(
        bytes32 suiRecipient,
        uint256 amountMist
    ) external returns (bytes32);

    function completeWithdrawal(
        bytes32 withdrawalId,
        bytes32 suiTxDigest,
        SuiObjectProof calldata txProof,
        ValidatorAttestation[] calldata attestations
    ) external;

    function refundWithdrawal(bytes32 withdrawalId) external;

    // --- Escrow (Atomic Swaps) ---

    function createEscrow(
        bytes32 suiParty,
        bytes32 hashlock,
        uint256 finishAfter,
        uint256 cancelAfter
    ) external payable returns (bytes32);

    function finishEscrow(bytes32 escrowId, bytes32 preimage) external;

    function cancelEscrow(bytes32 escrowId) external;

    // --- Privacy ---

    function registerPrivateDeposit(
        bytes32 depositId,
        bytes32 commitment,
        bytes32 nullifier,
        bytes calldata zkProof
    ) external;

    // --- Checkpoint Verification ---

    function submitCheckpoint(
        uint256 sequenceNumber,
        bytes32 digest,
        bytes32 previousDigest,
        bytes32 transactionDigestRoot,
        bytes32 effectsRoot,
        uint256 epoch,
        bytes32 validatorSetHash,
        uint256 timestampMs,
        ValidatorAttestation[] calldata attestations
    ) external;

    // --- Views ---

    function getDeposit(
        bytes32 depositId
    ) external view returns (SUIDeposit memory);

    function getWithdrawal(
        bytes32 withdrawalId
    ) external view returns (SUIWithdrawal memory);

    function getEscrow(
        bytes32 escrowId
    ) external view returns (SUIEscrow memory);

    function getCheckpoint(
        uint256 sequenceNumber
    ) external view returns (SuiCheckpoint memory);
}
