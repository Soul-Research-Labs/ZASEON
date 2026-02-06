// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IAptosBridgeAdapter
 * @author Soul Protocol
 * @notice Interface for the Aptos bridge adapter
 * @dev Enables cross-chain interoperability between Soul Protocol and the Aptos Network
 *
 * APTOS INTEGRATION MODEL:
 *
 *   ┌───────────────────────────┐         ┌───────────────────────────┐
 *   │      Soul Protocol        │         │       Aptos Network       │
 *   │  ┌─────────────────────┐  │         │  ┌─────────────────────┐  │
 *   │  │ AptosBridge          │◄─┼────────►│  │  Move VM            │  │
 *   │  │ Adapter (EVM side)  │  │         │  │  (Resource Model)   │  │
 *   │  └─────────────────────┘  │         │  └─────────────────────┘  │
 *   │        │                  │         │        │                  │
 *   │  ┌─────▼───────────────┐  │         │  ┌─────▼───────────────┐  │
 *   │  │  Privacy Layer      │  │         │  │  AptosBFT           │  │
 *   │  │  (ZK Commitments)   │  │         │  │  Consensus (<1s)    │  │
 *   │  └─────────────────────┘  │         │  └─────────────────────┘  │
 *   └───────────────────────────┘         └───────────────────────────┘
 *
 * BRIDGE MECHANISMS:
 * 1. Lock & Mint: Lock APT on Aptos → Mint wAPT on Soul Protocol
 * 2. Burn & Release: Burn wAPT on Soul → Release APT on Aptos Network
 * 3. Validator Attestation: AptosBFT validators attest to ledger state
 * 4. HTLC Escrow: Atomic swaps with hashlock/timelock conditions
 *
 * PROOF VERIFICATION:
 * - Aptos uses AptosBFT (DiemBFT v4) consensus with sub-second finality
 * - Validators sign LedgerInfo; 2/3+1 voting power required for commitment
 * - State proofs use Jellyfish Merkle Trees for efficient verification
 * - Block-STM: parallel transaction execution with optimistic concurrency
 * - Epochs rotate validator sets; epoch changes require 2/3+1 agreement
 *
 * APTOS CONCEPTS:
 * - Octas: Smallest unit of APT (1 APT = 1e8 Octas, 8 decimals)
 * - Move VM: Resource-oriented smart contract language
 * - Block-STM: Parallel execution engine with MVCC
 * - Jellyfish Merkle Tree: Sparse Merkle tree for state proofs
 * - LedgerInfo: Signed summary of committed blockchain state
 * - Chain ID: aptos-mainnet → 1
 * - Finality: 6 ledger version confirmations for cross-chain safety
 * - Block time: ~160ms per block (AptosBFT consensus)
 */
interface IAptosBridgeAdapter {
    /*//////////////////////////////////////////////////////////////
                                ENUMS
    //////////////////////////////////////////////////////////////*/

    /// @notice Status of a deposit from Aptos → Soul
    enum DepositStatus {
        PENDING,
        VERIFIED,
        COMPLETED,
        FAILED
    }

    /// @notice Status of a withdrawal from Soul → Aptos
    enum WithdrawalStatus {
        PENDING,
        PROCESSING,
        COMPLETED,
        REFUNDED,
        FAILED
    }

    /// @notice Status of an HTLC escrow
    enum EscrowStatus {
        ACTIVE,
        FINISHED,
        CANCELLED
    }

    /// @notice Operation types for the Aptos bridge
    enum AptosBridgeOpType {
        COIN_TRANSFER,     // Standard AptosCoin transfer
        RESOURCE_TRANSFER, // Move resource transfer
        VALIDATOR_UPDATE,  // Epoch validator set rotation
        EMERGENCY_OP       // Emergency governance action
    }

    /*//////////////////////////////////////////////////////////////
                               STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Bridge configuration
    /// @param aptosBridgeContract Address of the Aptos-side bridge module
    /// @param wrappedAPT ERC-20 wrapper for APT
    /// @param validatorOracle Oracle for AptosBFT validator verification
    /// @param minValidatorSignatures Minimum validator signatures required
    /// @param requiredLedgerConfirmations Ledger version confirmations needed
    /// @param active Whether the bridge is accepting transfers
    struct BridgeConfig {
        address aptosBridgeContract;
        address wrappedAPT;
        address validatorOracle;
        uint256 minValidatorSignatures;
        uint256 requiredLedgerConfirmations;
        bool active;
    }

    /// @notice Deposit record (Aptos → Soul)
    /// @param depositId Unique deposit identifier
    /// @param aptosTxHash Aptos transaction hash (32 bytes)
    /// @param aptosSender Aptos account address (32 bytes)
    /// @param evmRecipient EVM recipient address
    /// @param amountOctas Amount in Octas (1e8 per APT)
    /// @param netAmountOctas Amount after fee deduction
    /// @param fee Bridge fee deducted
    /// @param status Current deposit status
    /// @param ledgerVersion Aptos ledger version for this deposit
    /// @param initiatedAt Block timestamp when initiated
    /// @param completedAt Block timestamp when completed
    struct APTDeposit {
        bytes32 depositId;
        bytes32 aptosTxHash;
        bytes32 aptosSender;
        address evmRecipient;
        uint256 amountOctas;
        uint256 netAmountOctas;
        uint256 fee;
        DepositStatus status;
        uint256 ledgerVersion;
        uint256 initiatedAt;
        uint256 completedAt;
    }

    /// @notice Withdrawal record (Soul → Aptos)
    /// @param withdrawalId Unique withdrawal identifier
    /// @param evmSender EVM sender address
    /// @param aptosRecipient Aptos account address (32 bytes)
    /// @param amountOctas Amount in Octas
    /// @param aptosTxHash Confirmed Aptos transaction hash
    /// @param status Current withdrawal status
    /// @param initiatedAt Block timestamp when initiated
    /// @param completedAt Block timestamp when completed
    struct APTWithdrawal {
        bytes32 withdrawalId;
        address evmSender;
        bytes32 aptosRecipient;
        uint256 amountOctas;
        bytes32 aptosTxHash;
        WithdrawalStatus status;
        uint256 initiatedAt;
        uint256 completedAt;
    }

    /// @notice HTLC Escrow record for atomic swaps
    /// @param escrowId Unique escrow identifier
    /// @param evmParty EVM-side participant
    /// @param aptosParty Aptos-side participant (32-byte address)
    /// @param amountOctas Amount locked in Octas
    /// @param hashlock SHA-256 hashlock
    /// @param preimage Revealed preimage (zero until finished)
    /// @param finishAfter Earliest time the escrow can be finished
    /// @param cancelAfter Earliest time the escrow can be cancelled
    /// @param status Current escrow status
    /// @param createdAt Block timestamp when created
    struct APTEscrow {
        bytes32 escrowId;
        address evmParty;
        bytes32 aptosParty;
        uint256 amountOctas;
        bytes32 hashlock;
        bytes32 preimage;
        uint256 finishAfter;
        uint256 cancelAfter;
        EscrowStatus status;
        uint256 createdAt;
    }

    /// @notice Aptos LedgerInfo header for cross-chain verification
    /// @param ledgerVersion Ledger version (monotonically increasing)
    /// @param transactionHash Hash of the transaction at this version
    /// @param stateRootHash Root hash of the Jellyfish Merkle state tree
    /// @param eventRootHash Root hash of the event accumulator
    /// @param epoch Current epoch number
    /// @param round Consensus round within epoch
    /// @param timestamp Block timestamp (microseconds)
    /// @param numTransactions Number of transactions in the block
    /// @param verified Whether this header has been verified
    struct AptosLedgerInfo {
        uint256 ledgerVersion;
        bytes32 transactionHash;
        bytes32 stateRootHash;
        bytes32 eventRootHash;
        uint256 epoch;
        uint256 round;
        uint256 timestamp;
        uint256 numTransactions;
        bool verified;
    }

    /// @notice Validator attestation for AptosBFT consensus
    /// @param validator Validator address (EVM-mapped)
    /// @param signature Validator's BLS signature over ledger info
    struct ValidatorAttestation {
        address validator;
        bytes signature;
    }

    /// @notice Jellyfish Merkle proof for state/transaction inclusion
    /// @param leafHash Hash of the leaf node
    /// @param proof Array of sibling hashes
    /// @param index Position in the tree
    struct AptosStateProof {
        bytes32 leafHash;
        bytes32[] proof;
        uint256 index;
    }

    /*//////////////////////////////////////////////////////////////
                               EVENTS
    //////////////////////////////////////////////////////////////*/

    event BridgeConfigured(
        address indexed aptosBridgeContract,
        address wrappedAPT,
        address validatorOracle
    );

    event APTDepositInitiated(
        bytes32 indexed depositId,
        bytes32 indexed aptosTxHash,
        bytes32 aptosSender,
        address indexed evmRecipient,
        uint256 amountOctas
    );

    event APTDepositCompleted(
        bytes32 indexed depositId,
        address indexed evmRecipient,
        uint256 amountOctas
    );

    event APTWithdrawalInitiated(
        bytes32 indexed withdrawalId,
        address indexed evmSender,
        bytes32 aptosRecipient,
        uint256 amountOctas
    );

    event APTWithdrawalCompleted(
        bytes32 indexed withdrawalId,
        bytes32 aptosTxHash
    );

    event APTWithdrawalRefunded(
        bytes32 indexed withdrawalId,
        address indexed evmSender,
        uint256 amountOctas
    );

    event EscrowCreated(
        bytes32 indexed escrowId,
        address indexed evmParty,
        bytes32 aptosParty,
        uint256 amountOctas,
        bytes32 hashlock
    );

    event EscrowFinished(bytes32 indexed escrowId, bytes32 preimage);

    event EscrowCancelled(bytes32 indexed escrowId);

    event LedgerInfoVerified(
        uint256 indexed ledgerVersion,
        bytes32 transactionHash,
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

    error ZeroAddress();
    error BridgeNotConfigured();
    error BridgeAlreadyConfigured();
    error InvalidAmount();
    error AmountBelowMinimum(uint256 amount, uint256 minimum);
    error AmountAboveMaximum(uint256 amount, uint256 maximum);
    error AptosTxAlreadyUsed(bytes32 txHash);
    error DepositNotFound(bytes32 depositId);
    error DepositAlreadyCompleted(bytes32 depositId);
    error DepositNotVerified(bytes32 depositId);
    error WithdrawalNotFound(bytes32 withdrawalId);
    error WithdrawalAlreadyCompleted(bytes32 withdrawalId);
    error WithdrawalNotPending(bytes32 withdrawalId);
    error RefundTooEarly(uint256 currentTime, uint256 refundAfter);
    error EscrowNotFound(bytes32 escrowId);
    error EscrowNotActive(bytes32 escrowId);
    error EscrowTimelockNotMet();
    error InvalidPreimage(bytes32 expected, bytes32 actual);
    error InvalidTimelockRange();
    error LedgerVersionNotVerified(uint256 version);
    error InvalidStateProof();
    error InsufficientValidatorSignatures(uint256 got, uint256 required);
    error NullifierAlreadyUsed(bytes32 nullifier);

    /*//////////////////////////////////////////////////////////////
                             FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function configure(
        address aptosBridgeContract,
        address wrappedAPT,
        address validatorOracle,
        uint256 minValidatorSignatures,
        uint256 requiredLedgerConfirmations
    ) external;

    function setTreasury(address treasury) external;

    function initiateAPTDeposit(
        bytes32 aptosTxHash,
        bytes32 aptosSender,
        address evmRecipient,
        uint256 amountOctas,
        uint256 ledgerVersion,
        AptosStateProof calldata txProof,
        ValidatorAttestation[] calldata attestations
    ) external returns (bytes32 depositId);

    function completeAPTDeposit(bytes32 depositId) external;

    function initiateWithdrawal(
        bytes32 aptosRecipient,
        uint256 amountOctas
    ) external returns (bytes32 withdrawalId);

    function completeWithdrawal(
        bytes32 withdrawalId,
        bytes32 aptosTxHash,
        AptosStateProof calldata txProof,
        ValidatorAttestation[] calldata attestations
    ) external;

    function refundWithdrawal(bytes32 withdrawalId) external;

    function createEscrow(
        bytes32 aptosParty,
        bytes32 hashlock,
        uint256 finishAfter,
        uint256 cancelAfter
    ) external payable returns (bytes32 escrowId);

    function finishEscrow(bytes32 escrowId, bytes32 preimage) external;

    function cancelEscrow(bytes32 escrowId) external;

    function registerPrivateDeposit(
        bytes32 depositId,
        bytes32 commitment,
        bytes32 nullifier,
        bytes calldata zkProof
    ) external;

    function submitLedgerInfo(
        uint256 ledgerVersion,
        bytes32 transactionHash,
        bytes32 stateRootHash,
        bytes32 eventRootHash,
        uint256 epoch,
        uint256 round,
        uint256 timestamp,
        uint256 numTransactions,
        ValidatorAttestation[] calldata attestations
    ) external;

    function getDeposit(bytes32 depositId) external view returns (APTDeposit memory);
    function getWithdrawal(bytes32 withdrawalId) external view returns (APTWithdrawal memory);
    function getEscrow(bytes32 escrowId) external view returns (APTEscrow memory);
    function getLedgerInfo(uint256 version) external view returns (AptosLedgerInfo memory);
    function getUserDeposits(address user) external view returns (bytes32[] memory);
    function getUserWithdrawals(address user) external view returns (bytes32[] memory);
    function getUserEscrows(address user) external view returns (bytes32[] memory);
}
