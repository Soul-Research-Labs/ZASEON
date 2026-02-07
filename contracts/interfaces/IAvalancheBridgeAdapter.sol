// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IAvalancheBridgeAdapter
 * @author Soul Protocol
 * @notice Interface for the Avalanche bridge adapter
 * @dev Enables cross-chain interoperability between Soul Protocol and Avalanche C-Chain
 *
 * AVALANCHE CONCEPTS:
 * - nAVAX: Smallest unit (1 AVAX = 1e18 nAVAX / wei, 18 decimals, EVM native)
 * - Snowman: Linear chain consensus for C-Chain (optimistic, sub-second finality)
 * - Avalanche Consensus: Snow family (Snowball, Snowflake) for DAG-based P-Chain/X-Chain
 * - C-Chain: Contract Chain (EVM compatible)
 * - P-Chain: Platform Chain (staking & subnets)
 * - X-Chain: Exchange Chain (asset creation)
 * - Subnets: Application-specific networks with custom VMs
 * - Warp Messaging: Native cross-subnet messaging (AWM)
 * - Chain ID: 43114 (C-Chain mainnet)
 * - Finality: Sub-second (~1-2s) via Snowman consensus
 * - Block time: ~2 seconds
 */
interface IAvalancheBridgeAdapter {
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
    enum AvalancheBridgeOpType {
        AVAX_TRANSFER,
        ERC20_TRANSFER,
        WARP_MESSAGE,
        EMERGENCY_OP
    }

    struct BridgeConfig {
        address avalancheBridgeContract;
        address wrappedAVAX;
        address warpVerifier;
        uint256 minValidatorSignatures;
        uint256 requiredBlockConfirmations;
        bool active;
    }

    struct AVAXDeposit {
        bytes32 depositId;
        bytes32 cChainTxHash;
        address cChainSender;
        address evmRecipient;
        uint256 amountWei;
        uint256 netAmountWei;
        uint256 fee;
        DepositStatus status;
        uint256 cChainBlockNumber;
        uint256 initiatedAt;
        uint256 completedAt;
    }

    struct AVAXWithdrawal {
        bytes32 withdrawalId;
        address evmSender;
        address cChainRecipient;
        uint256 amountWei;
        bytes32 cChainTxHash;
        WithdrawalStatus status;
        uint256 initiatedAt;
        uint256 completedAt;
    }

    struct AVAXEscrow {
        bytes32 escrowId;
        address evmParty;
        address cChainParty;
        uint256 amountWei;
        bytes32 hashlock;
        bytes32 preimage;
        uint256 finishAfter;
        uint256 cancelAfter;
        EscrowStatus status;
        uint256 createdAt;
    }

    struct SnowmanBlock {
        uint256 blockNumber;
        bytes32 blockHash;
        bytes32 parentHash;
        bytes32 stateRoot;
        uint256 timestamp;
        bool verified;
    }

    struct ValidatorAttestation {
        address validator;
        bytes signature;
    }

    struct WarpStateProof {
        bytes32[] merkleProof;
        bytes32 storageRoot;
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
    error CChainTxAlreadyUsed(bytes32 txHash);
    error CChainBlockNotVerified(uint256 blockNumber);
    error InsufficientValidatorSignatures(uint256 got, uint256 required);
    error NullifierAlreadyUsed(bytes32 nullifier);

    event BridgeConfigured(
        address avalancheBridgeContract,
        address wrappedAVAX,
        address warpVerifier
    );
    event SnowmanBlockVerified(
        uint256 blockNumber,
        bytes32 blockHash,
        bytes32 stateRoot
    );
    event AVAXDepositInitiated(
        bytes32 indexed depositId,
        bytes32 cChainTxHash,
        address cChainSender,
        address indexed evmRecipient,
        uint256 amountWei
    );
    event AVAXDepositCompleted(
        bytes32 indexed depositId,
        address indexed evmRecipient,
        uint256 netAmountWei
    );
    event AVAXWithdrawalInitiated(
        bytes32 indexed withdrawalId,
        address indexed evmSender,
        address cChainRecipient,
        uint256 amountWei
    );
    event AVAXWithdrawalCompleted(
        bytes32 indexed withdrawalId,
        bytes32 cChainTxHash
    );
    event AVAXWithdrawalRefunded(
        bytes32 indexed withdrawalId,
        address indexed evmSender,
        uint256 amountWei
    );
    event EscrowCreated(
        bytes32 indexed escrowId,
        address indexed evmParty,
        address cChainParty,
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
        address avalancheBridgeContract,
        address wrappedAVAX,
        address warpVerifier,
        uint256 minValidatorSignatures,
        uint256 requiredBlockConfirmations
    ) external;

    function setTreasury(address _treasury) external;

    function submitSnowmanBlock(
        uint256 blockNumber,
        bytes32 blockHash,
        bytes32 parentHash,
        bytes32 stateRoot,
        uint256 timestamp,
        ValidatorAttestation[] calldata attestations
    ) external;

    function initiateAVAXDeposit(
        bytes32 cChainTxHash,
        address cChainSender,
        address evmRecipient,
        uint256 amountWei,
        uint256 cChainBlockNumber,
        WarpStateProof calldata txProof,
        ValidatorAttestation[] calldata attestations
    ) external returns (bytes32 depositId);

    function completeAVAXDeposit(bytes32 depositId) external;

    function initiateWithdrawal(
        address cChainRecipient,
        uint256 amountWei
    ) external returns (bytes32 withdrawalId);

    function completeWithdrawal(
        bytes32 withdrawalId,
        bytes32 cChainTxHash,
        WarpStateProof calldata txProof,
        ValidatorAttestation[] calldata attestations
    ) external;

    function refundWithdrawal(bytes32 withdrawalId) external;

    function createEscrow(
        address cChainParty,
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
    ) external view returns (AVAXDeposit memory);

    function getWithdrawal(
        bytes32 withdrawalId
    ) external view returns (AVAXWithdrawal memory);

    function getEscrow(
        bytes32 escrowId
    ) external view returns (AVAXEscrow memory);

    function getSnowmanBlock(
        uint256 blockNumber
    ) external view returns (SnowmanBlock memory);

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
