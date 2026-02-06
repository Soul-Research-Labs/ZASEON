// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IHyperliquidBridgeAdapter
 * @author Soul Protocol
 * @notice Interface for the Hyperliquid bridge adapter
 * @dev Enables cross-chain interoperability between Soul Protocol and Hyperliquid L1
 *
 * HYPERLIQUID INTEGRATION MODEL:
 *
 *   ┌───────────────────────────┐         ┌───────────────────────────┐
 *   │      Soul Protocol        │         │       Hyperliquid L1      │
 *   │  ┌─────────────────────┐  │         │  ┌─────────────────────┐  │
 *   │  │ HyperliquidBridge   │◄─┼────────►│  │  Bridge Contract    │  │
 *   │  │ Adapter (EVM side)  │  │         │  │  (HyperEVM side)    │  │
 *   │  └─────────────────────┘  │         │  └─────────────────────┘  │
 *   │        │                  │         │        │                  │
 *   │  ┌─────▼───────────────┐  │         │  ┌─────▼───────────────┐  │
 *   │  │  Privacy Layer      │  │         │  │  HyperBFT Consensus │  │
 *   │  │  (ZK Commitments)   │  │         │  │  + Order Book       │  │
 *   │  └─────────────────────┘  │         │  └─────────────────────┘  │
 *   └───────────────────────────┘         └───────────────────────────┘
 *
 * BRIDGE MECHANISMS:
 * 1. Lock & Mint: Lock HYPE on Hyperliquid → Mint wHYPE on Soul Protocol
 * 2. Burn & Release: Burn wHYPE on Soul → Release HYPE on Hyperliquid
 * 3. Validator Attestation: Cross-chain verification via HyperBFT validator signatures
 * 4. HTLC Escrow: Atomic swaps with hashlock/timelock conditions
 *
 * PROOF VERIFICATION:
 * - Hyperliquid uses HyperBFT consensus (based on HotStuff protocol)
 * - Near-instant BFT finality (~3 blocks, ~0.6 seconds)
 * - 4 active validators in the BFT committee
 * - 2/3+1 supermajority required for block finality (3/4 validators)
 * - State proofs via Merkle inclusion in block headers
 * - ECDSA validator signatures for block attestation
 *
 * HYPERLIQUID CONCEPTS:
 * - Drips: Smallest unit of HYPE (1 HYPE = 1e8 drips)
 * - Block: ~200ms block latency (sub-second)
 * - HyperBFT: Modified HotStuff BFT consensus
 * - HyperEVM: EVM-compatible execution environment
 * - Chain ID: 999 (HyperEVM mainnet)
 * - Finality: ~3 blocks (~0.6 seconds) for BFT finality
 */
interface IHyperliquidBridgeAdapter {
    /*//////////////////////////////////////////////////////////////
                                ENUMS
    //////////////////////////////////////////////////////////////*/

    /// @notice Status of a HYPE deposit (Hyperliquid → Soul)
    enum DepositStatus {
        PENDING,
        VERIFIED,
        COMPLETED,
        FAILED
    }

    /// @notice Status of a HYPE withdrawal (Soul → Hyperliquid)
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

    /// @notice Hyperliquid transaction types relevant to the bridge
    enum HyperliquidTxType {
        TRANSFER,
        SPOT_TRANSFER,
        CONTRACT_CALL,
        CROSS_CHAIN
    }

    /*//////////////////////////////////////////////////////////////
                               STRUCTS
    //////////////////////////////////////////////////////////////*/

    struct BridgeConfig {
        address hyperliquidBridgeContract;
        address wrappedHYPE;
        address validatorOracle;
        uint256 minValidatorSignatures;
        uint256 requiredBlockConfirmations;
        bool active;
    }

    struct HYPEDeposit {
        bytes32 depositId;
        bytes32 hlTxHash;
        address hlSender;
        address evmRecipient;
        uint256 amountDrips;
        uint256 netAmountDrips;
        uint256 fee;
        DepositStatus status;
        uint256 blockNumber;
        uint256 initiatedAt;
        uint256 completedAt;
    }

    struct HYPEWithdrawal {
        bytes32 withdrawalId;
        address evmSender;
        address hlRecipient;
        uint256 amountDrips;
        bytes32 hlTxHash;
        WithdrawalStatus status;
        uint256 initiatedAt;
        uint256 completedAt;
    }

    struct HYPEEscrow {
        bytes32 escrowId;
        address evmParty;
        address hlParty;
        uint256 amountDrips;
        bytes32 hashlock;
        bytes32 preimage;
        uint256 finishAfter;
        uint256 cancelAfter;
        EscrowStatus status;
        uint256 createdAt;
    }

    struct HyperBFTBlockHeader {
        uint256 blockNumber;
        bytes32 blockHash;
        bytes32 parentHash;
        bytes32 transactionsRoot;
        bytes32 stateRoot;
        uint256 blockTime;
        bool finalized;
    }

    struct ValidatorAttestation {
        address validator;
        bytes signature;
    }

    struct HyperliquidMerkleProof {
        bytes32 leafHash;
        bytes32[] proof;
        uint256 index;
    }

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event BridgeConfigured(
        address indexed hyperliquidBridgeContract,
        address wrappedHYPE,
        address validatorOracle
    );
    event HYPEDepositInitiated(
        bytes32 indexed depositId,
        bytes32 indexed hlTxHash,
        address hlSender,
        address indexed evmRecipient,
        uint256 amountDrips
    );
    event HYPEDepositCompleted(
        bytes32 indexed depositId,
        address indexed evmRecipient,
        uint256 amountDrips
    );
    event HYPEWithdrawalInitiated(
        bytes32 indexed withdrawalId,
        address indexed evmSender,
        address hlRecipient,
        uint256 amountDrips
    );
    event HYPEWithdrawalCompleted(
        bytes32 indexed withdrawalId,
        bytes32 hlTxHash
    );
    event HYPEWithdrawalRefunded(
        bytes32 indexed withdrawalId,
        address indexed evmSender,
        uint256 amountDrips
    );
    event EscrowCreated(
        bytes32 indexed escrowId,
        address indexed evmParty,
        address hlParty,
        uint256 amountDrips,
        bytes32 hashlock
    );
    event EscrowFinished(bytes32 indexed escrowId, bytes32 preimage);
    event EscrowCancelled(bytes32 indexed escrowId);
    event BlockHeaderSubmitted(uint256 indexed blockNumber, bytes32 blockHash);
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
    error InvalidAmount();
    error AmountTooSmall(uint256 amountDrips);
    error AmountTooLarge(uint256 amountDrips);
    error DepositNotFound(bytes32 depositId);
    error InvalidDepositStatus(bytes32 depositId, DepositStatus current);
    error WithdrawalNotFound(bytes32 withdrawalId);
    error InvalidWithdrawalStatus(
        bytes32 withdrawalId,
        WithdrawalStatus current
    );
    error EscrowNotFound(bytes32 escrowId);
    error EscrowNotActive(bytes32 escrowId);
    error FinishAfterNotReached(bytes32 escrowId, uint256 finishAfter);
    error CancelAfterNotReached(bytes32 escrowId, uint256 cancelAfter);
    error InvalidHashlock();
    error InvalidPreimage(bytes32 expected, bytes32 got);
    error InvalidBlockProof();
    error BlockNotFinalized(uint256 blockNumber);
    error InsufficientValidatorSignatures(uint256 got, uint256 required);
    error HLTxAlreadyUsed(bytes32 txHash);
    error NullifierAlreadyUsed(bytes32 nullifier);
    error InvalidProof();
    error InsufficientFee(uint256 provided, uint256 required);
    error TimelockTooShort(uint256 provided, uint256 minimum);
    error TimelockTooLong(uint256 provided, uint256 maximum);
    error WithdrawalTimelockNotExpired(bytes32 withdrawalId);

    /*//////////////////////////////////////////////////////////////
                             FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function configure(
        address hyperliquidBridgeContract,
        address wrappedHYPE,
        address validatorOracle,
        uint256 minValidatorSignatures,
        uint256 requiredBlockConfirmations
    ) external;

    function initiateHYPEDeposit(
        bytes32 hlTxHash,
        address hlSender,
        address evmRecipient,
        uint256 amountDrips,
        uint256 blockNumber,
        HyperliquidMerkleProof calldata txProof,
        ValidatorAttestation[] calldata attestations
    ) external returns (bytes32 depositId);

    function completeHYPEDeposit(bytes32 depositId) external;

    function initiateWithdrawal(
        address hlRecipient,
        uint256 amountDrips
    ) external returns (bytes32 withdrawalId);

    function completeWithdrawal(
        bytes32 withdrawalId,
        bytes32 hlTxHash,
        HyperliquidMerkleProof calldata txProof,
        ValidatorAttestation[] calldata attestations
    ) external;

    function refundWithdrawal(bytes32 withdrawalId) external;

    function createEscrow(
        address hlParty,
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

    function submitBlockHeader(
        uint256 blockNumber,
        bytes32 blockHash,
        bytes32 parentHash,
        bytes32 transactionsRoot,
        bytes32 stateRoot,
        uint256 blockTime,
        ValidatorAttestation[] calldata attestations
    ) external;

    function getDeposit(
        bytes32 depositId
    ) external view returns (HYPEDeposit memory);

    function getWithdrawal(
        bytes32 withdrawalId
    ) external view returns (HYPEWithdrawal memory);

    function getEscrow(
        bytes32 escrowId
    ) external view returns (HYPEEscrow memory);

    function getBlockHeader(
        uint256 blockNumber
    ) external view returns (HyperBFTBlockHeader memory);
}
