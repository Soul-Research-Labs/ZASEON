// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title ICosmosBridgeAdapter
 * @author Soul Protocol
 * @notice Interface for the Cosmos/IBC bridge adapter
 * @dev Enables cross-chain interoperability via IBC protocol
 *
 * COSMOS CONCEPTS:
 * - uatom: Smallest unit of ATOM (1 ATOM = 1e6 uatom, 6 decimals)
 * - IBC: Inter-Blockchain Communication protocol
 * - Tendermint BFT: Byzantine Fault Tolerant consensus (~6s blocks)
 * - Light Client: IBC relies on on-chain light client verification
 * - ICS-20: Fungible token transfer standard over IBC
 * - Channel/Port: IBC communication endpoints
 * - Chain ID: cosmoshub-4
 * - Finality: Instant (single-slot Tendermint finality)
 */
interface ICosmosBridgeAdapter {
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
    enum CosmosBridgeOpType {
        ATOM_TRANSFER,
        ICS20_TRANSFER,
        IBC_RELAY,
        EMERGENCY_OP
    }

    struct BridgeConfig {
        address cosmosBridgeContract;
        address wrappedATOM;
        address ibcLightClient;
        uint256 minValidatorSignatures;
        uint256 requiredBlockConfirmations;
        bool active;
    }

    struct ATOMDeposit {
        bytes32 depositId;
        bytes32 cosmosTxHash;
        bytes32 cosmosSender;
        address evmRecipient;
        uint256 amountUatom;
        uint256 netAmountUatom;
        uint256 fee;
        DepositStatus status;
        uint256 cosmosHeight;
        uint256 initiatedAt;
        uint256 completedAt;
    }

    struct ATOMWithdrawal {
        bytes32 withdrawalId;
        address evmSender;
        bytes32 cosmosRecipient;
        uint256 amountUatom;
        bytes32 cosmosTxHash;
        WithdrawalStatus status;
        uint256 initiatedAt;
        uint256 completedAt;
    }

    struct ATOMEscrow {
        bytes32 escrowId;
        address evmParty;
        bytes32 cosmosParty;
        uint256 amountUatom;
        bytes32 hashlock;
        bytes32 preimage;
        uint256 finishAfter;
        uint256 cancelAfter;
        EscrowStatus status;
        uint256 createdAt;
    }

    struct TendermintHeader {
        uint256 height;
        bytes32 blockHash;
        bytes32 appHash;
        bytes32 validatorsHash;
        uint256 timestamp;
        bool verified;
    }

    struct ValidatorAttestation {
        address validator;
        bytes signature;
    }

    struct IBCProof {
        bytes32[] merklePath;
        bytes32 commitmentRoot;
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
    error CosmosTxAlreadyUsed(bytes32 txHash);
    error CosmosHeightNotVerified(uint256 height);
    error InsufficientValidatorSignatures(uint256 got, uint256 required);
    error NullifierAlreadyUsed(bytes32 nullifier);

    event BridgeConfigured(
        address cosmosBridgeContract,
        address wrappedATOM,
        address ibcLightClient
    );
    event TendermintHeaderVerified(
        uint256 height,
        bytes32 blockHash,
        bytes32 appHash
    );
    event ATOMDepositInitiated(
        bytes32 indexed depositId,
        bytes32 cosmosTxHash,
        bytes32 cosmosSender,
        address indexed evmRecipient,
        uint256 amountUatom
    );
    event ATOMDepositCompleted(
        bytes32 indexed depositId,
        address indexed evmRecipient,
        uint256 netAmountUatom
    );
    event ATOMWithdrawalInitiated(
        bytes32 indexed withdrawalId,
        address indexed evmSender,
        bytes32 cosmosRecipient,
        uint256 amountUatom
    );
    event ATOMWithdrawalCompleted(
        bytes32 indexed withdrawalId,
        bytes32 cosmosTxHash
    );
    event ATOMWithdrawalRefunded(
        bytes32 indexed withdrawalId,
        address indexed evmSender,
        uint256 amountUatom
    );
    event EscrowCreated(
        bytes32 indexed escrowId,
        address indexed evmParty,
        bytes32 cosmosParty,
        uint256 amountUatom,
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
        address cosmosBridgeContract,
        address wrappedATOM,
        address ibcLightClient,
        uint256 minValidatorSignatures,
        uint256 requiredBlockConfirmations
    ) external;

    function setTreasury(address _treasury) external;

    function submitTendermintHeader(
        uint256 height,
        bytes32 blockHash,
        bytes32 appHash,
        bytes32 validatorsHash,
        uint256 timestamp,
        ValidatorAttestation[] calldata attestations
    ) external;

    function initiateATOMDeposit(
        bytes32 cosmosTxHash,
        bytes32 cosmosSender,
        address evmRecipient,
        uint256 amountUatom,
        uint256 cosmosHeight,
        IBCProof calldata txProof,
        ValidatorAttestation[] calldata attestations
    ) external returns (bytes32 depositId);

    function completeATOMDeposit(bytes32 depositId) external;

    function initiateWithdrawal(
        bytes32 cosmosRecipient,
        uint256 amountUatom
    ) external returns (bytes32 withdrawalId);

    function completeWithdrawal(
        bytes32 withdrawalId,
        bytes32 cosmosTxHash,
        IBCProof calldata txProof,
        ValidatorAttestation[] calldata attestations
    ) external;

    function refundWithdrawal(bytes32 withdrawalId) external;

    function createEscrow(
        bytes32 cosmosParty,
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
    ) external view returns (ATOMDeposit memory);

    function getWithdrawal(
        bytes32 withdrawalId
    ) external view returns (ATOMWithdrawal memory);

    function getEscrow(
        bytes32 escrowId
    ) external view returns (ATOMEscrow memory);

    function getTendermintHeader(
        uint256 height
    ) external view returns (TendermintHeader memory);

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
