// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title ICardanoBridgeAdapter
 * @author Soul Protocol
 * @notice Interface for the Cardano bridge adapter
 * @dev Enables cross-chain interoperability between Soul Protocol and Cardano
 *
 * CARDANO CONCEPTS:
 * - Lovelace: Smallest unit (1 ADA = 1e6 Lovelace, 6 decimals)
 * - Ouroboros: Proof-of-Stake consensus family (Praos variant)
 * - eUTXO: Extended UTXO model (vs account model)
 * - Plutus: Smart contract language (Haskell-based)
 * - Native Tokens: First-class assets on ledger (no smart contract needed)
 * - Epochs: 5-day periods, divided into slots (~1 block/20s)
 * - Chain ID: cardano-mainnet (764824073)
 * - Finality: ~20 minutes (k=2160 parameter, ~36 blocks)
 * - Block time: ~20 seconds
 */
interface ICardanoBridgeAdapter {
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
    enum CardanoBridgeOpType {
        ADA_TRANSFER,
        NATIVE_TOKEN_TRANSFER,
        PLUTUS_SCRIPT,
        EMERGENCY_OP
    }

    struct BridgeConfig {
        address cardanoBridgeContract;
        address wrappedADA;
        address cardanoLightClient;
        uint256 minValidatorSignatures;
        uint256 requiredBlockConfirmations;
        bool active;
    }

    struct ADADeposit {
        bytes32 depositId;
        bytes32 cardanoTxHash;
        bytes32 cardanoSender;
        address evmRecipient;
        uint256 amountLovelace;
        uint256 netAmountLovelace;
        uint256 fee;
        DepositStatus status;
        uint256 cardanoSlot;
        uint256 initiatedAt;
        uint256 completedAt;
    }

    struct ADAWithdrawal {
        bytes32 withdrawalId;
        address evmSender;
        bytes32 cardanoRecipient;
        uint256 amountLovelace;
        bytes32 cardanoTxHash;
        WithdrawalStatus status;
        uint256 initiatedAt;
        uint256 completedAt;
    }

    struct ADAEscrow {
        bytes32 escrowId;
        address evmParty;
        bytes32 cardanoParty;
        uint256 amountLovelace;
        bytes32 hashlock;
        bytes32 preimage;
        uint256 finishAfter;
        uint256 cancelAfter;
        EscrowStatus status;
        uint256 createdAt;
    }

    struct OuroborosHeader {
        uint256 slot;
        uint256 epoch;
        bytes32 blockHash;
        bytes32 prevBlockHash;
        bytes32 vrfOutput;
        bytes32 blockBodyHash;
        uint256 timestamp;
        bool verified;
    }

    struct ValidatorAttestation {
        address validator;
        bytes signature;
    }

    struct CardanoStateProof {
        bytes32[] merklePath;
        bytes32 blockBodyHash;
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
    error CardanoTxAlreadyUsed(bytes32 txHash);
    error CardanoSlotNotVerified(uint256 slot);
    error InsufficientValidatorSignatures(uint256 got, uint256 required);
    error NullifierAlreadyUsed(bytes32 nullifier);

    event BridgeConfigured(
        address cardanoBridgeContract,
        address wrappedADA,
        address cardanoLightClient
    );
    event OuroborosHeaderVerified(
        uint256 slot,
        uint256 epoch,
        bytes32 blockHash
    );
    event ADADepositInitiated(
        bytes32 indexed depositId,
        bytes32 cardanoTxHash,
        bytes32 cardanoSender,
        address indexed evmRecipient,
        uint256 amountLovelace
    );
    event ADADepositCompleted(
        bytes32 indexed depositId,
        address indexed evmRecipient,
        uint256 netAmountLovelace
    );
    event ADAWithdrawalInitiated(
        bytes32 indexed withdrawalId,
        address indexed evmSender,
        bytes32 cardanoRecipient,
        uint256 amountLovelace
    );
    event ADAWithdrawalCompleted(
        bytes32 indexed withdrawalId,
        bytes32 cardanoTxHash
    );
    event ADAWithdrawalRefunded(
        bytes32 indexed withdrawalId,
        address indexed evmSender,
        uint256 amountLovelace
    );
    event EscrowCreated(
        bytes32 indexed escrowId,
        address indexed evmParty,
        bytes32 cardanoParty,
        uint256 amountLovelace,
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
        address cardanoBridgeContract,
        address wrappedADA,
        address cardanoLightClient,
        uint256 minValidatorSignatures,
        uint256 requiredBlockConfirmations
    ) external;

    function setTreasury(address _treasury) external;

    function submitOuroborosHeader(
        uint256 slot,
        uint256 epoch,
        bytes32 blockHash,
        bytes32 prevBlockHash,
        bytes32 vrfOutput,
        bytes32 blockBodyHash,
        uint256 timestamp,
        ValidatorAttestation[] calldata attestations
    ) external;

    function initiateADADeposit(
        bytes32 cardanoTxHash,
        bytes32 cardanoSender,
        address evmRecipient,
        uint256 amountLovelace,
        uint256 cardanoSlot,
        CardanoStateProof calldata txProof,
        ValidatorAttestation[] calldata attestations
    ) external returns (bytes32 depositId);

    function completeADADeposit(bytes32 depositId) external;

    function initiateWithdrawal(
        bytes32 cardanoRecipient,
        uint256 amountLovelace
    ) external returns (bytes32 withdrawalId);

    function completeWithdrawal(
        bytes32 withdrawalId,
        bytes32 cardanoTxHash,
        CardanoStateProof calldata txProof,
        ValidatorAttestation[] calldata attestations
    ) external;

    function refundWithdrawal(bytes32 withdrawalId) external;

    function createEscrow(
        bytes32 cardanoParty,
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
    ) external view returns (ADADeposit memory);

    function getWithdrawal(
        bytes32 withdrawalId
    ) external view returns (ADAWithdrawal memory);

    function getEscrow(
        bytes32 escrowId
    ) external view returns (ADAEscrow memory);

    function getOuroborosHeader(
        uint256 slot
    ) external view returns (OuroborosHeader memory);

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
