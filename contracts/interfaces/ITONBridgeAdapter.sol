// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title ITONBridgeAdapter
 * @author Soul Protocol
 * @notice Interface for The Open Network (TON) bridge adapter
 * @dev Enables cross-chain interoperability between Soul Protocol and TON
 *
 * TON CONCEPTS:
 * - Nanoton: Smallest unit (1 TON = 1e9 Nanoton, 9 decimals)
 * - Catchain: BFT consensus protocol
 * - Infinite Sharding Paradigm: Dynamic splitting/merging of workchains
 * - Masterchain: Coordinates all workchains (workchain -1)
 * - Basechain: Default workchain for user accounts (workchain 0)
 * - TVM: TON Virtual Machine (stack-based, continuations)
 * - FunC / Tact: Smart contract languages
 * - Jettons: TON fungible token standard (TEP-74)
 * - Chain ID: ton-mainnet → -239
 * - Finality: ~5 seconds
 * - Block time: ~5 seconds
 */
interface ITONBridgeAdapter {
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
    enum TONBridgeOpType {
        TON_TRANSFER,
        JETTON_TRANSFER,
        WORKCHAIN_RELAY,
        EMERGENCY_OP
    }

    struct BridgeConfig {
        address tonBridgeContract;
        address wrappedTON;
        address tonLightClient;
        uint256 minValidatorSignatures;
        uint256 requiredBlockConfirmations;
        bool active;
    }

    struct TONDeposit {
        bytes32 depositId;
        bytes32 tonTxHash;
        bytes32 tonSender;
        address evmRecipient;
        uint256 amountNanoton;
        uint256 netAmountNanoton;
        uint256 fee;
        DepositStatus status;
        uint256 tonSeqno;
        uint256 initiatedAt;
        uint256 completedAt;
    }

    struct TONWithdrawal {
        bytes32 withdrawalId;
        address evmSender;
        bytes32 tonRecipient;
        uint256 amountNanoton;
        bytes32 tonTxHash;
        WithdrawalStatus status;
        uint256 initiatedAt;
        uint256 completedAt;
    }

    struct TONEscrow {
        bytes32 escrowId;
        address evmParty;
        bytes32 tonParty;
        uint256 amountNanoton;
        bytes32 hashlock;
        bytes32 preimage;
        uint256 finishAfter;
        uint256 cancelAfter;
        EscrowStatus status;
        uint256 createdAt;
    }

    struct MasterchainBlock {
        uint256 seqno;
        bytes32 rootHash;
        bytes32 fileHash;
        int256 workchain;
        uint256 shardId;
        uint256 timestamp;
        bool verified;
    }

    struct ValidatorAttestation {
        address validator;
        bytes signature;
    }

    struct TONStateProof {
        bytes32[] merkleProof;
        bytes32 rootHash;
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
    error TONTxAlreadyUsed(bytes32 txHash);
    error TONBlockNotVerified(uint256 seqno);
    error InsufficientValidatorSignatures(uint256 got, uint256 required);
    error NullifierAlreadyUsed(bytes32 nullifier);

    event BridgeConfigured(
        address tonBridgeContract,
        address wrappedTON,
        address tonLightClient
    );
    event MasterchainBlockVerified(
        uint256 seqno,
        bytes32 rootHash,
        bytes32 fileHash
    );
    event TONDepositInitiated(
        bytes32 indexed depositId,
        bytes32 tonTxHash,
        bytes32 tonSender,
        address indexed evmRecipient,
        uint256 amountNanoton
    );
    event TONDepositCompleted(
        bytes32 indexed depositId,
        address indexed evmRecipient,
        uint256 netAmountNanoton
    );
    event TONWithdrawalInitiated(
        bytes32 indexed withdrawalId,
        address indexed evmSender,
        bytes32 tonRecipient,
        uint256 amountNanoton
    );
    event TONWithdrawalCompleted(
        bytes32 indexed withdrawalId,
        bytes32 tonTxHash
    );
    event TONWithdrawalRefunded(
        bytes32 indexed withdrawalId,
        address indexed evmSender,
        uint256 amountNanoton
    );
    event EscrowCreated(
        bytes32 indexed escrowId,
        address indexed evmParty,
        bytes32 tonParty,
        uint256 amountNanoton,
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
        address tonBridgeContract,
        address wrappedTON,
        address tonLightClient,
        uint256 minValidatorSignatures,
        uint256 requiredBlockConfirmations
    ) external;

    function setTreasury(address _treasury) external;

    function submitMasterchainBlock(
        uint256 seqno,
        bytes32 rootHash,
        bytes32 fileHash,
        int256 workchain,
        uint256 shardId,
        uint256 timestamp,
        ValidatorAttestation[] calldata attestations
    ) external;

    function initiateTONDeposit(
        bytes32 tonTxHash,
        bytes32 tonSender,
        address evmRecipient,
        uint256 amountNanoton,
        uint256 tonSeqno,
        TONStateProof calldata txProof,
        ValidatorAttestation[] calldata attestations
    ) external returns (bytes32 depositId);

    function completeTONDeposit(bytes32 depositId) external;

    function initiateWithdrawal(
        bytes32 tonRecipient,
        uint256 amountNanoton
    ) external returns (bytes32 withdrawalId);

    function completeWithdrawal(
        bytes32 withdrawalId,
        bytes32 tonTxHash,
        TONStateProof calldata txProof,
        ValidatorAttestation[] calldata attestations
    ) external;

    function refundWithdrawal(bytes32 withdrawalId) external;

    function createEscrow(
        bytes32 tonParty,
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
    ) external view returns (TONDeposit memory);

    function getWithdrawal(
        bytes32 withdrawalId
    ) external view returns (TONWithdrawal memory);

    function getEscrow(
        bytes32 escrowId
    ) external view returns (TONEscrow memory);

    function getMasterchainBlock(
        uint256 seqno
    ) external view returns (MasterchainBlock memory);

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
