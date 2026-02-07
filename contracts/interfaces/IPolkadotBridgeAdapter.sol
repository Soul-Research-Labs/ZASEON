// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IPolkadotBridgeAdapter
 * @author Soul Protocol
 * @notice Interface for the Polkadot bridge adapter
 * @dev Enables cross-chain interoperability between Soul Protocol and Polkadot/Substrate chains
 *
 * POLKADOT INTEGRATION MODEL:
 *
 *   ┌───────────────────────────┐         ┌───────────────────────────┐
 *   │      Soul Protocol        │         │    Polkadot Relay Chain   │
 *   │  ┌─────────────────────┐  │         │  ┌─────────────────────┐  │
 *   │  │ PolkadotBridge      │◄─┼────────►│  │  XCM / XCMP          │  │
 *   │  │ Adapter (EVM side)  │  │         │  │  (Cross-Consensus)   │  │
 *   │  └─────────────────────┘  │         │  └─────────────────────┘  │
 *   │        │                  │         │        │                  │
 *   │  ┌─────▼───────────────┐  │         │  ┌─────▼───────────────┐  │
 *   │  │  Privacy Layer      │  │         │  │  GRANDPA + BABE      │  │
 *   │  │  (ZK Commitments)   │  │         │  │  Hybrid Consensus    │  │
 *   │  └─────────────────────┘  │         │  └─────────────────────┘  │
 *   └───────────────────────────┘         └───────────────────────────┘
 *
 * POLKADOT CONCEPTS:
 * - Planck: Smallest unit of DOT (1 DOT = 1e10 Planck, 10 decimals)
 * - GRANDPA: GHOST-based Recursive ANcestor Deriving Prefix Agreement (finality)
 * - BABE: Blind Assignment for Blockchain Extension (block production)
 * - XCM: Cross-Consensus Messaging format
 * - XCMP: Cross-Chain Message Passing between parachains
 * - Relay Chain: Central chain coordinating consensus and security
 * - Parachain: Application-specific chains connected to relay chain
 * - Finality: GRANDPA provides deterministic finality (~12-60s)
 * - Block time: ~6 seconds
 * - Chain ID: polkadot relay → 0 (custom)
 */
interface IPolkadotBridgeAdapter {
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
    enum PolkadotBridgeOpType {
        DOT_TRANSFER,
        ASSET_HUB_TRANSFER,
        XCM_RELAY,
        EMERGENCY_OP
    }

    struct BridgeConfig {
        address polkadotBridgeContract;
        address wrappedDOT;
        address grandpaVerifier;
        uint256 minValidatorSignatures;
        uint256 requiredFinalityConfirmations;
        bool active;
    }

    struct DOTDeposit {
        bytes32 depositId;
        bytes32 substrateTxHash;
        bytes32 substrateSender;
        address evmRecipient;
        uint256 amountPlanck;
        uint256 netAmountPlanck;
        uint256 fee;
        DepositStatus status;
        uint256 relayBlockNumber;
        uint256 initiatedAt;
        uint256 completedAt;
    }

    struct DOTWithdrawal {
        bytes32 withdrawalId;
        address evmSender;
        bytes32 substrateRecipient;
        uint256 amountPlanck;
        bytes32 substrateTxHash;
        WithdrawalStatus status;
        uint256 initiatedAt;
        uint256 completedAt;
    }

    struct DOTEscrow {
        bytes32 escrowId;
        address evmParty;
        bytes32 substrateParty;
        uint256 amountPlanck;
        bytes32 hashlock;
        bytes32 preimage;
        uint256 finishAfter;
        uint256 cancelAfter;
        EscrowStatus status;
        uint256 createdAt;
    }

    struct GrandpaHeader {
        uint256 blockNumber;
        bytes32 blockHash;
        bytes32 parentHash;
        bytes32 stateRoot;
        bytes32 extrinsicsRoot;
        uint256 setId;
        uint256 timestamp;
        bool verified;
    }

    struct ValidatorAttestation {
        address validator;
        bytes signature;
    }

    struct SubstrateStateProof {
        bytes32[] merkleProof;
        bytes32 storageKey;
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
    error SubstrateTxAlreadyUsed(bytes32 txHash);
    error RelayBlockNotVerified(uint256 blockNumber);
    error InsufficientValidatorSignatures(uint256 got, uint256 required);
    error NullifierAlreadyUsed(bytes32 nullifier);

    event BridgeConfigured(
        address polkadotBridgeContract,
        address wrappedDOT,
        address grandpaVerifier
    );
    event GrandpaHeaderVerified(
        uint256 blockNumber,
        bytes32 blockHash,
        uint256 setId
    );
    event DOTDepositInitiated(
        bytes32 indexed depositId,
        bytes32 substrateTxHash,
        bytes32 substrateSender,
        address indexed evmRecipient,
        uint256 amountPlanck
    );
    event DOTDepositCompleted(
        bytes32 indexed depositId,
        address indexed evmRecipient,
        uint256 netAmountPlanck
    );
    event DOTWithdrawalInitiated(
        bytes32 indexed withdrawalId,
        address indexed evmSender,
        bytes32 substrateRecipient,
        uint256 amountPlanck
    );
    event DOTWithdrawalCompleted(
        bytes32 indexed withdrawalId,
        bytes32 substrateTxHash
    );
    event DOTWithdrawalRefunded(
        bytes32 indexed withdrawalId,
        address indexed evmSender,
        uint256 amountPlanck
    );
    event EscrowCreated(
        bytes32 indexed escrowId,
        address indexed evmParty,
        bytes32 substrateParty,
        uint256 amountPlanck,
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
        address polkadotBridgeContract,
        address wrappedDOT,
        address grandpaVerifier,
        uint256 minValidatorSignatures,
        uint256 requiredFinalityConfirmations
    ) external;

    function setTreasury(address _treasury) external;

    function submitGrandpaHeader(
        uint256 blockNumber,
        bytes32 blockHash,
        bytes32 parentHash,
        bytes32 stateRoot,
        bytes32 extrinsicsRoot,
        uint256 setId,
        uint256 timestamp,
        ValidatorAttestation[] calldata attestations
    ) external;

    function initiateDOTDeposit(
        bytes32 substrateTxHash,
        bytes32 substrateSender,
        address evmRecipient,
        uint256 amountPlanck,
        uint256 relayBlockNumber,
        SubstrateStateProof calldata txProof,
        ValidatorAttestation[] calldata attestations
    ) external returns (bytes32 depositId);

    function completeDOTDeposit(bytes32 depositId) external;

    function initiateWithdrawal(
        bytes32 substrateRecipient,
        uint256 amountPlanck
    ) external returns (bytes32 withdrawalId);

    function completeWithdrawal(
        bytes32 withdrawalId,
        bytes32 substrateTxHash,
        SubstrateStateProof calldata txProof,
        ValidatorAttestation[] calldata attestations
    ) external;

    function refundWithdrawal(bytes32 withdrawalId) external;

    function createEscrow(
        bytes32 substrateParty,
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
    ) external view returns (DOTDeposit memory);

    function getWithdrawal(
        bytes32 withdrawalId
    ) external view returns (DOTWithdrawal memory);

    function getEscrow(
        bytes32 escrowId
    ) external view returns (DOTEscrow memory);

    function getGrandpaHeader(
        uint256 blockNumber
    ) external view returns (GrandpaHeader memory);

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
