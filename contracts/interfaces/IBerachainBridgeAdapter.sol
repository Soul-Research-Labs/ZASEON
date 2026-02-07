// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IBerachainBridgeAdapter
 * @author Soul Protocol
 * @notice Interface for the Berachain bridge adapter
 * @dev Enables cross-chain interoperability between Soul Protocol and Berachain
 *
 * BERACHAIN CONCEPTS:
 * - Wei: Standard EVM 18-decimal (BERA native token)
 * - Proof of Liquidity (PoL): Novel consensus aligning validators with liquidity
 * - BeaconKit: CometBFT-based consensus engine (EVM-compatible)
 * - BGT: Governance token (non-transferable, earned via PoL)
 * - HONEY: Native stablecoin
 * - Reward Vaults: PoL incentive distribution vaults
 * - Chain ID: 80094 (Berachain mainnet)
 * - Finality: Single-slot CometBFT (~5s)
 * - Block time: ~5 seconds
 */
interface IBerachainBridgeAdapter {
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
    enum BerachainBridgeOpType {
        BERA_TRANSFER,
        ERC20_TRANSFER,
        POL_RELAY,
        EMERGENCY_OP
    }

    struct BridgeConfig {
        address berachainBridgeContract;
        address wrappedBERA;
        address cometBFTVerifier;
        uint256 minValidatorSignatures;
        uint256 requiredBlockConfirmations;
        bool active;
    }

    struct BERADeposit {
        bytes32 depositId;
        bytes32 beraTxHash;
        address beraSender;
        address evmRecipient;
        uint256 amountWei;
        uint256 netAmountWei;
        uint256 fee;
        DepositStatus status;
        uint256 beraBlockNumber;
        uint256 initiatedAt;
        uint256 completedAt;
    }

    struct BERAWithdrawal {
        bytes32 withdrawalId;
        address evmSender;
        address beraRecipient;
        uint256 amountWei;
        bytes32 beraTxHash;
        WithdrawalStatus status;
        uint256 initiatedAt;
        uint256 completedAt;
    }

    struct BERAEscrow {
        bytes32 escrowId;
        address evmParty;
        address beraParty;
        uint256 amountWei;
        bytes32 hashlock;
        bytes32 preimage;
        uint256 finishAfter;
        uint256 cancelAfter;
        EscrowStatus status;
        uint256 createdAt;
    }

    struct CometBFTBlock {
        uint256 blockNumber;
        bytes32 blockHash;
        bytes32 appHash;
        bytes32 validatorsHash;
        uint256 round;
        uint256 timestamp;
        bool verified;
    }

    struct ValidatorAttestation {
        address validator;
        bytes signature;
    }

    struct CometBFTProof {
        bytes32[] merkleProof;
        bytes32 appHash;
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
    error BeraTxAlreadyUsed(bytes32 txHash);
    error BeraBlockNotVerified(uint256 blockNumber);
    error InsufficientValidatorSignatures(uint256 got, uint256 required);
    error NullifierAlreadyUsed(bytes32 nullifier);

    event BridgeConfigured(
        address berachainBridgeContract,
        address wrappedBERA,
        address cometBFTVerifier
    );
    event CometBFTBlockVerified(
        uint256 blockNumber,
        bytes32 blockHash,
        bytes32 appHash
    );
    event BERADepositInitiated(
        bytes32 indexed depositId,
        bytes32 beraTxHash,
        address beraSender,
        address indexed evmRecipient,
        uint256 amountWei
    );
    event BERADepositCompleted(
        bytes32 indexed depositId,
        address indexed evmRecipient,
        uint256 netAmountWei
    );
    event BERAWithdrawalInitiated(
        bytes32 indexed withdrawalId,
        address indexed evmSender,
        address beraRecipient,
        uint256 amountWei
    );
    event BERAWithdrawalCompleted(
        bytes32 indexed withdrawalId,
        bytes32 beraTxHash
    );
    event BERAWithdrawalRefunded(
        bytes32 indexed withdrawalId,
        address indexed evmSender,
        uint256 amountWei
    );
    event EscrowCreated(
        bytes32 indexed escrowId,
        address indexed evmParty,
        address beraParty,
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
        address berachainBridgeContract,
        address wrappedBERA,
        address cometBFTVerifier,
        uint256 minValidatorSignatures,
        uint256 requiredBlockConfirmations
    ) external;

    function setTreasury(address _treasury) external;

    function submitCometBFTBlock(
        uint256 blockNumber,
        bytes32 blockHash,
        bytes32 appHash,
        bytes32 validatorsHash,
        uint256 round,
        uint256 timestamp,
        ValidatorAttestation[] calldata attestations
    ) external;

    function initiateBERADeposit(
        bytes32 beraTxHash,
        address beraSender,
        address evmRecipient,
        uint256 amountWei,
        uint256 beraBlockNumber,
        CometBFTProof calldata txProof,
        ValidatorAttestation[] calldata attestations
    ) external returns (bytes32 depositId);

    function completeBERADeposit(bytes32 depositId) external;

    function initiateWithdrawal(
        address beraRecipient,
        uint256 amountWei
    ) external returns (bytes32 withdrawalId);

    function completeWithdrawal(
        bytes32 withdrawalId,
        bytes32 beraTxHash,
        CometBFTProof calldata txProof,
        ValidatorAttestation[] calldata attestations
    ) external;

    function refundWithdrawal(bytes32 withdrawalId) external;

    function createEscrow(
        address beraParty,
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
    ) external view returns (BERADeposit memory);

    function getWithdrawal(
        bytes32 withdrawalId
    ) external view returns (BERAWithdrawal memory);

    function getEscrow(
        bytes32 escrowId
    ) external view returns (BERAEscrow memory);

    function getCometBFTBlock(
        uint256 blockNumber
    ) external view returns (CometBFTBlock memory);

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
