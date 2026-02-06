// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title ISeiBridgeAdapter
 * @author Soul Protocol
 * @notice Interface for the Sei bridge adapter
 * @dev Enables cross-chain interoperability between Soul Protocol and the Sei Network
 *
 * SEI INTEGRATION MODEL:
 *
 *   ┌───────────────────────────┐         ┌───────────────────────────┐
 *   │      Soul Protocol        │         │        Sei Network        │
 *   │  ┌─────────────────────┐  │         │  ┌─────────────────────┐  │
 *   │  │ SeiBridge            │◄─┼────────►│  │  Sei EVM Module     │  │
 *   │  │ Adapter (EVM side)  │  │         │  │  (Parallel EVM)     │  │
 *   │  └─────────────────────┘  │         │  └─────────────────────┘  │
 *   │        │                  │         │        │                  │
 *   │  ┌─────▼───────────────┐  │         │  ┌─────▼───────────────┐  │
 *   │  │  Privacy Layer      │  │         │  │  Twin-Turbo         │  │
 *   │  │  (ZK Commitments)   │  │         │  │  Consensus (~400ms) │  │
 *   │  └─────────────────────┘  │         │  └─────────────────────┘  │
 *   └───────────────────────────┘         └───────────────────────────┘
 *
 * BRIDGE MECHANISMS:
 * 1. Lock & Mint: Lock SEI on Sei → Mint wSEI on Soul Protocol
 * 2. Burn & Release: Burn wSEI on Soul → Release SEI on Sei Network
 * 3. Validator Attestation: Tendermint BFT validators attest to block finality
 * 4. HTLC Escrow: Atomic swaps with hashlock/timelock conditions
 *
 * PROOF VERIFICATION:
 * - Sei uses Twin-Turbo consensus (optimistic block processing + intelligent propagation)
 * - Tendermint BFT validators sign block headers; 2/3+1 voting power required
 * - Merkle proofs verify state/transaction inclusion against block headers
 * - Parallel EVM execution with optimistic concurrency control
 * - Single-slot finality: blocks are final once committed
 *
 * SEI CONCEPTS:
 * - usei: Smallest unit of SEI (1 SEI = 1e6 usei, 6 decimals)
 * - Twin-Turbo: Optimistic block processing + intelligent block propagation
 * - Parallel EVM: Optimistic parallel transaction execution
 * - Built-in Order Book: Native DEX module for on-chain matching
 * - SeiDB: Optimized storage layer for high-throughput DeFi
 * - Chain ID: sei-mainnet (EVM chain ID 1329)
 * - Finality: 8 block confirmations for cross-chain safety
 * - Block time: ~400ms (Twin-Turbo consensus)
 */
interface ISeiBridgeAdapter {
    /*//////////////////////////////////////////////////////////////
                                ENUMS
    //////////////////////////////////////////////////////////////*/

    /// @notice Status of a SEI deposit (Sei → Soul)
    enum DepositStatus {
        PENDING,
        VERIFIED,
        COMPLETED,
        FAILED
    }

    /// @notice Status of a SEI withdrawal (Soul → Sei)
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

    /// @notice Types of Sei bridge operations
    enum SeiBridgeOpType {
        TOKEN_TRANSFER, // Standard token transfer
        EVM_INTEROP, // EVM ↔ Cosmos interop transfer
        ORDER_BOOK_SETTLE, // DEX settlement relay
        EMERGENCY_OP // Emergency bridge operation
    }

    /*//////////////////////////////////////////////////////////////
                               STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Bridge configuration for Sei integration
    struct BridgeConfig {
        address seiBridgeContract;
        address wrappedSEI;
        address validatorOracle;
        uint256 minValidatorSignatures;
        uint256 requiredBlockConfirmations;
        bool active;
    }

    /// @notice SEI deposit record
    /// @dev Tracks usei-denominated deposits from Sei to Soul
    struct SEIDeposit {
        bytes32 depositId;
        bytes32 seiTxHash;
        bytes32 seiSender; // sei1... bech32 address as bytes32
        address evmRecipient;
        uint256 amountUsei;
        uint256 netAmountUsei;
        uint256 fee;
        DepositStatus status;
        uint256 blockHeight;
        uint256 initiatedAt;
        uint256 completedAt;
    }

    /// @notice SEI withdrawal record
    /// @dev Tracks usei-denominated withdrawals from Soul to Sei
    struct SEIWithdrawal {
        bytes32 withdrawalId;
        address evmSender;
        bytes32 seiRecipient; // sei1... bech32 address as bytes32
        uint256 amountUsei;
        bytes32 seiTxHash;
        WithdrawalStatus status;
        uint256 initiatedAt;
        uint256 completedAt;
    }

    /// @notice HTLC escrow for atomic swaps
    struct SEIEscrow {
        bytes32 escrowId;
        address evmParty;
        bytes32 seiParty; // sei1... bech32 address as bytes32
        uint256 amountUsei;
        bytes32 hashlock;
        bytes32 preimage;
        uint256 finishAfter;
        uint256 cancelAfter;
        EscrowStatus status;
        uint256 createdAt;
    }

    /// @notice Sei block header record
    /// @dev Represents a committed block from the Sei network
    struct SeiBlockHeader {
        uint256 height;
        bytes32 blockHash;
        bytes32 parentHash;
        bytes32 stateRoot;
        bytes32 txRoot;
        bytes32 validatorSetHash;
        uint256 timestamp;
        uint256 numTxs;
        bool verified;
    }

    /// @notice Validator attestation for Tendermint BFT
    /// @dev Sei validators sign block headers; 2/3+1 voting power required
    struct ValidatorAttestation {
        address validator;
        bytes signature;
    }

    /// @notice Merkle inclusion proof for Sei state/tx verification
    struct SeiMerkleProof {
        bytes32 leafHash;
        bytes32[] proof;
        uint256 index;
    }

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event BridgeConfigured(
        address indexed seiBridgeContract,
        address wrappedSEI,
        address validatorOracle
    );
    event SEIDepositInitiated(
        bytes32 indexed depositId,
        bytes32 indexed seiTxHash,
        bytes32 seiSender,
        address indexed evmRecipient,
        uint256 amountUsei
    );
    event SEIDepositCompleted(
        bytes32 indexed depositId,
        address indexed evmRecipient,
        uint256 amountUsei
    );
    event SEIWithdrawalInitiated(
        bytes32 indexed withdrawalId,
        address indexed evmSender,
        bytes32 seiRecipient,
        uint256 amountUsei
    );
    event SEIWithdrawalCompleted(
        bytes32 indexed withdrawalId,
        bytes32 seiTxHash
    );
    event SEIWithdrawalRefunded(
        bytes32 indexed withdrawalId,
        address indexed evmSender,
        uint256 amountUsei
    );
    event EscrowCreated(
        bytes32 indexed escrowId,
        address indexed evmParty,
        bytes32 seiParty,
        uint256 amountUsei,
        bytes32 hashlock
    );
    event EscrowFinished(bytes32 indexed escrowId, bytes32 preimage);
    event EscrowCancelled(bytes32 indexed escrowId);
    event BlockHeaderVerified(
        uint256 indexed height,
        bytes32 blockHash,
        uint256 numTxs
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

    error InvalidSeiAddress();
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
    error SeiTxAlreadyUsed(bytes32 seiTxHash);
    error BlockNotVerified(uint256 height);
    error InvalidBlockProof();
    error InsufficientValidatorSignatures(uint256 provided, uint256 required);
    error BridgeNotConfigured();
    error NullifierAlreadyUsed(bytes32 nullifier);
    error ZeroAddress();

    /*//////////////////////////////////////////////////////////////
                              FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    // --- Configuration ---

    function configure(
        address seiBridgeContract,
        address wrappedSEI,
        address validatorOracle,
        uint256 minValidatorSignatures,
        uint256 requiredBlockConfirmations
    ) external;

    // --- Deposits (Sei → Soul) ---

    function initiateSEIDeposit(
        bytes32 seiTxHash,
        bytes32 seiSender,
        address evmRecipient,
        uint256 amountUsei,
        uint256 blockHeight,
        SeiMerkleProof calldata txProof,
        ValidatorAttestation[] calldata attestations
    ) external returns (bytes32);

    function completeSEIDeposit(bytes32 depositId) external;

    // --- Withdrawals (Soul → Sei) ---

    function initiateWithdrawal(
        bytes32 seiRecipient,
        uint256 amountUsei
    ) external returns (bytes32);

    function completeWithdrawal(
        bytes32 withdrawalId,
        bytes32 seiTxHash,
        SeiMerkleProof calldata txProof,
        ValidatorAttestation[] calldata attestations
    ) external;

    function refundWithdrawal(bytes32 withdrawalId) external;

    // --- Escrow (Atomic Swaps) ---

    function createEscrow(
        bytes32 seiParty,
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

    // --- Block Header Verification ---

    function submitBlockHeader(
        uint256 height,
        bytes32 blockHash,
        bytes32 parentHash,
        bytes32 stateRoot,
        bytes32 txRoot,
        bytes32 validatorSetHash,
        uint256 timestamp,
        uint256 numTxs,
        ValidatorAttestation[] calldata attestations
    ) external;

    // --- Views ---

    function getDeposit(
        bytes32 depositId
    ) external view returns (SEIDeposit memory);

    function getWithdrawal(
        bytes32 withdrawalId
    ) external view returns (SEIWithdrawal memory);

    function getEscrow(
        bytes32 escrowId
    ) external view returns (SEIEscrow memory);

    function getBlockHeader(
        uint256 height
    ) external view returns (SeiBlockHeader memory);
}
