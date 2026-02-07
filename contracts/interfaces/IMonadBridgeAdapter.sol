// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IMonadBridgeAdapter
 * @author Soul Protocol
 * @notice Interface for the Monad bridge adapter
 * @dev Enables cross-chain interoperability between Soul Protocol and Monad
 *
 * MONAD CONCEPTS:
 * - Wei: Standard EVM 18-decimal (MON native token)
 * - MonadBFT: Pipeline-optimized HotStuff2-based BFT consensus
 * - Parallel Execution: Optimistic parallel execution with conflict detection
 * - MonadDb: Custom LSM-tree state database for SSD optimization
 * - Deferred Execution: Consensus decoupled from execution
 * - Superscalar Pipelining: Overlapped consensus stages
 * - Chain ID: monad-mainnet (TBD, using 41454 as placeholder)
 * - Finality: Single-slot (~1s)
 * - Block time: ~1 second (target 10k TPS)
 */
interface IMonadBridgeAdapter {
    enum DepositStatus {
        PENDING,
        VERIFIED,
        COMPLETED,
        FAILED
    }
    enum WithdrawalStatus {
        PENDING,
        PROCESSING,
        COMPLETED,
        REFUNDED,
        FAILED
    }
    enum EscrowStatus {
        ACTIVE,
        FINISHED,
        CANCELLED
    }
    enum MonadBridgeOpType {
        MON_TRANSFER,
        ERC20_TRANSFER,
        MONADBFT_RELAY,
        EMERGENCY_OP
    }

    struct BridgeConfig {
        address monadBridgeContract;
        address wrappedMON;
        address monadBFTVerifier;
        uint256 minValidatorSignatures;
        uint256 requiredBlockConfirmations;
        bool active;
    }

    struct MONDeposit {
        bytes32 depositId;
        bytes32 monadTxHash;
        address monadSender;
        address evmRecipient;
        uint256 amountWei;
        uint256 netAmountWei;
        uint256 fee;
        DepositStatus status;
        uint256 monadBlockNumber;
        uint256 initiatedAt;
        uint256 completedAt;
    }

    struct MONWithdrawal {
        bytes32 withdrawalId;
        address evmSender;
        address monadRecipient;
        uint256 amountWei;
        bytes32 monadTxHash;
        WithdrawalStatus status;
        uint256 initiatedAt;
        uint256 completedAt;
    }

    struct MONEscrow {
        bytes32 escrowId;
        address evmParty;
        address monadParty;
        uint256 amountWei;
        bytes32 hashlock;
        bytes32 preimage;
        uint256 finishAfter;
        uint256 cancelAfter;
        EscrowStatus status;
        uint256 createdAt;
    }

    struct MonadBFTBlock {
        uint256 blockNumber;
        bytes32 blockHash;
        bytes32 parentHash;
        bytes32 stateRoot;
        bytes32 executionRoot;
        uint256 round;
        uint256 timestamp;
        bool verified;
    }

    struct ValidatorAttestation {
        address validator;
        bytes signature;
    }

    struct MonadStateProof {
        bytes32[] merkleProof;
        bytes32 stateRoot;
        bytes value;
    }

    error ZeroAddress();
    error AmountBelowMinimum(uint256 amount, uint256 minimum);
    error AmountAboveMaximum(uint256 amount, uint256 maximum);
    error DepositNotFound(bytes32 depositId);
    error DepositAlreadyCompleted(bytes32 depositId);
    error DepositNotVerified(bytes32 depositId);
    error WithdrawalNotFound(bytes32 withdrawalId);
    error WithdrawalNotPending(bytes32 withdrawalId);
    error RefundTooEarly(uint256 current, uint256 earliest);
    error EscrowNotFound(bytes32 escrowId);
    error EscrowNotActive(bytes32 escrowId);
    error EscrowTimelockNotMet();
    error InvalidPreimage(bytes32 expected, bytes32 actual);
    error InvalidTimelockRange();
    error InvalidAmount();
    error MonadTxAlreadyUsed(bytes32 txHash);
    error MonadBlockNotVerified(uint256 blockNumber);
    error InsufficientValidatorSignatures(uint256 got, uint256 required);
    error NullifierAlreadyUsed(bytes32 nullifier);

    event BridgeConfigured(
        address monadBridgeContract,
        address wrappedMON,
        address monadBFTVerifier
    );
    event MonadBFTBlockVerified(
        uint256 blockNumber,
        bytes32 blockHash,
        bytes32 stateRoot
    );
    event MONDepositInitiated(
        bytes32 indexed depositId,
        bytes32 monadTxHash,
        address monadSender,
        address indexed evmRecipient,
        uint256 amountWei
    );
    event MONDepositCompleted(
        bytes32 indexed depositId,
        address indexed evmRecipient,
        uint256 netAmountWei
    );
    event MONWithdrawalInitiated(
        bytes32 indexed withdrawalId,
        address indexed evmSender,
        address monadRecipient,
        uint256 amountWei
    );
    event MONWithdrawalCompleted(
        bytes32 indexed withdrawalId,
        bytes32 monadTxHash
    );
    event MONWithdrawalRefunded(
        bytes32 indexed withdrawalId,
        address indexed evmSender,
        uint256 amountWei
    );
    event EscrowCreated(
        bytes32 indexed escrowId,
        address indexed evmParty,
        address monadParty,
        uint256 amountWei,
        bytes32 hashlock
    );
    event EscrowFinished(bytes32 indexed escrowId, bytes32 preimage);
    event EscrowCancelled(bytes32 indexed escrowId);
    event PrivateDepositRegistered(
        bytes32 indexed depositId,
        bytes32 commitment,
        bytes32 nullifier
    );
    event FeesWithdrawn(address indexed treasury, uint256 amount);

    function configure(
        address monadBridgeContract,
        address wrappedMON,
        address monadBFTVerifier,
        uint256 minValidatorSignatures,
        uint256 requiredBlockConfirmations
    ) external;

    function setTreasury(address _treasury) external;

    function submitMonadBFTBlock(
        uint256 blockNumber,
        bytes32 blockHash,
        bytes32 parentHash,
        bytes32 stateRoot,
        bytes32 executionRoot,
        uint256 round,
        uint256 timestamp,
        ValidatorAttestation[] calldata attestations
    ) external;

    function initiateMONDeposit(
        bytes32 monadTxHash,
        address monadSender,
        address evmRecipient,
        uint256 amountWei,
        uint256 monadBlockNumber,
        MonadStateProof calldata txProof,
        ValidatorAttestation[] calldata attestations
    ) external returns (bytes32 depositId);

    function completeMONDeposit(bytes32 depositId) external;

    function initiateWithdrawal(
        address monadRecipient,
        uint256 amountWei
    ) external returns (bytes32 withdrawalId);

    function completeWithdrawal(
        bytes32 withdrawalId,
        bytes32 monadTxHash,
        MonadStateProof calldata txProof,
        ValidatorAttestation[] calldata attestations
    ) external;

    function refundWithdrawal(bytes32 withdrawalId) external;

    function createEscrow(
        address monadParty,
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

    function getDeposit(
        bytes32 depositId
    ) external view returns (MONDeposit memory);

    function getWithdrawal(
        bytes32 withdrawalId
    ) external view returns (MONWithdrawal memory);

    function getEscrow(
        bytes32 escrowId
    ) external view returns (MONEscrow memory);

    function getMonadBFTBlock(
        uint256 blockNumber
    ) external view returns (MonadBFTBlock memory);

    function getUserDeposits(
        address user
    ) external view returns (bytes32[] memory);

    function getUserWithdrawals(
        address user
    ) external view returns (bytes32[] memory);

    function getUserEscrows(
        address user
    ) external view returns (bytes32[] memory);
}
