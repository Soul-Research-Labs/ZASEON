// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IBNBBridgeAdapter
 * @author Soul Protocol
 * @notice Interface for the BNB Chain (BSC) bridge adapter
 * @dev Enables cross-chain interoperability between Soul Protocol and BNB Chain
 *
 * BNB CHAIN INTEGRATION MODEL:
 *
 *   ┌───────────────────────────┐         ┌───────────────────────────┐
 *   │      Soul Protocol        │         │       BNB Chain (BSC)     │
 *   │  ┌─────────────────────┐  │         │  ┌─────────────────────┐  │
 *   │  │ BNBBridgeAdapter    │◄─┼────────►│  │  Bridge Contract    │  │
 *   │  │ (EVM side)          │  │         │  │  (BSC side)         │  │
 *   │  └─────────────────────┘  │         │  └─────────────────────┘  │
 *   │        │                  │         │        │                  │
 *   │  ┌─────▼───────────────┐  │         │  ┌─────▼───────────────┐  │
 *   │  │  Privacy Layer      │  │         │  │  BEP-20 Tokens      │  │
 *   │  │  (ZK Commitments)   │  │         │  │  + Native BNB       │  │
 *   │  └─────────────────────┘  │         │  └─────────────────────┘  │
 *   └───────────────────────────┘         └───────────────────────────┘
 *
 * BRIDGE MECHANISMS:
 * 1. Lock & Mint: Lock BNB on BSC → Mint wBNB on Soul Protocol
 * 2. Burn & Release: Burn wBNB on Soul → Release BNB on BSC
 * 3. BEP-20 Bridge: Bridge BEP-20 tokens to/from ERC-20 equivalents
 * 4. Validator Attestation: Cross-chain verification via BSC validator signatures
 *
 * PROOF VERIFICATION:
 * - BSC uses Proof of Staked Authority (PoSA) consensus
 * - Combines Delegated Proof of Stake (DPoS) with Proof of Authority (PoA)
 * - 21 active validators produce blocks in rotation
 * - State proofs via Merkle-Patricia Trie inclusion in block headers
 * - Transaction proofs via RLP-encoded Merkle proof
 * - ECDSA validator signatures for block attestation
 *
 * BNB CHAIN CONCEPTS:
 * - Wei: Smallest unit of BNB (1 BNB = 1e18 wei)
 * - Block: ~3 second block time
 * - Epoch: 200 blocks, validator set changes at epoch boundaries
 * - PoSA: Proof of Staked Authority (DPoS + PoA hybrid)
 * - BEP-20: BSC token standard (equivalent to ERC-20)
 * - Finality: ~15 blocks (~45 seconds) for practical finality
 */
interface IBNBBridgeAdapter {
    /*//////////////////////////////////////////////////////////////
                                ENUMS
    //////////////////////////////////////////////////////////////*/

    /// @notice Status of a BNB deposit (BSC → Soul)
    enum DepositStatus {
        PENDING, // Awaiting proof submission
        VERIFIED, // Proof verified, awaiting minting
        COMPLETED, // wBNB minted to recipient
        FAILED // Verification failed
    }

    /// @notice Status of a BNB withdrawal (Soul → BSC)
    enum WithdrawalStatus {
        PENDING, // wBNB burned, awaiting BSC release
        PROCESSING, // Validator signing in progress
        COMPLETED, // BNB released on BSC
        REFUNDED, // Refunded on Soul side
        FAILED // Release failed
    }

    /// @notice Status of a token swap escrow
    enum EscrowStatus {
        ACTIVE, // Escrow created, awaiting finish/cancel
        FINISHED, // Escrow successfully finished
        CANCELLED // Escrow cancelled after timeout
    }

    /// @notice BSC transaction types relevant to the bridge
    enum BSCTxType {
        TRANSFER, // Native BNB transfer
        BEP20_TRANSFER, // BEP-20 token transfer
        CONTRACT_CALL, // Arbitrary contract call
        CROSS_CHAIN // Cross-chain message
    }

    /*//////////////////////////////////////////////////////////////
                               STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Bridge configuration
    struct BridgeConfig {
        address bscBridgeContract; // BSC-side bridge contract address
        address wrappedBNB; // ERC-20 wrapped BNB token on Soul
        address validatorOracle; // Oracle for BSC validator signatures
        uint256 minValidatorSignatures; // Min validator signatures required
        uint256 requiredBlockConfirmations; // Block confirmations before acceptance
        bool active;
    }

    /// @notice BNB deposit record (BSC → Soul)
    struct BNBDeposit {
        bytes32 depositId;
        bytes32 bscTxHash; // BSC transaction hash
        address bscSender; // BSC sender address (EVM-compatible)
        address evmRecipient; // Soul Protocol recipient address
        uint256 amountWei; // Amount in wei (1 BNB = 1e18 wei)
        uint256 netAmountWei; // After bridge fee
        uint256 fee; // Bridge fee in wei
        DepositStatus status;
        uint256 blockNumber; // BSC block number
        uint256 initiatedAt;
        uint256 completedAt;
    }

    /// @notice BNB withdrawal record (Soul → BSC)
    struct BNBWithdrawal {
        bytes32 withdrawalId;
        address evmSender; // Soul Protocol sender
        address bscRecipient; // BSC recipient address
        uint256 amountWei; // Amount in wei
        bytes32 bscTxHash; // BSC release tx hash (set on completion)
        WithdrawalStatus status;
        uint256 initiatedAt;
        uint256 completedAt;
    }

    /// @notice Token swap escrow (for atomic cross-chain swaps)
    struct BNBEscrow {
        bytes32 escrowId;
        address evmParty; // Soul-side party
        address bscParty; // BSC-side party address
        uint256 amountWei; // Amount in wei
        bytes32 hashlock; // SHA-256 hashlock for HTLC
        bytes32 preimage; // Preimage (set on finish)
        uint256 finishAfter; // Earliest finish time (UNIX)
        uint256 cancelAfter; // Earliest cancel time (UNIX)
        EscrowStatus status;
        uint256 createdAt;
    }

    /// @notice BSC block header (for proof verification)
    struct BSCBlockHeader {
        uint256 blockNumber;
        bytes32 blockHash;
        bytes32 parentHash;
        bytes32 transactionsRoot; // Merkle root of transactions
        bytes32 stateRoot; // Root of state trie
        bytes32 receiptsRoot; // Root of receipts trie
        uint256 blockTime; // Block time in UNIX seconds
        bool finalized;
    }

    /// @notice BSC validator attestation
    struct ValidatorAttestation {
        address validator; // Validator address (EVM)
        bytes signature; // ECDSA signature over block hash
    }

    /// @notice BSC Merkle-Patricia proof
    struct BSCMerkleProof {
        bytes32 leafHash; // Transaction hash
        bytes32[] proof; // Merkle proof nodes
        uint256 index; // Leaf index in the tree
    }

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Emitted when the bridge is configured
    event BridgeConfigured(
        address indexed bscBridgeContract,
        address wrappedBNB,
        address validatorOracle
    );

    /// @notice Emitted when a BNB deposit is initiated
    event BNBDepositInitiated(
        bytes32 indexed depositId,
        bytes32 indexed bscTxHash,
        address bscSender,
        address indexed evmRecipient,
        uint256 amountWei
    );

    /// @notice Emitted when a BNB deposit is completed (wBNB minted)
    event BNBDepositCompleted(
        bytes32 indexed depositId,
        address indexed evmRecipient,
        uint256 amountWei
    );

    /// @notice Emitted when a BNB withdrawal is initiated (wBNB burned)
    event BNBWithdrawalInitiated(
        bytes32 indexed withdrawalId,
        address indexed evmSender,
        address bscRecipient,
        uint256 amountWei
    );

    /// @notice Emitted when a BNB withdrawal is completed on BSC
    event BNBWithdrawalCompleted(
        bytes32 indexed withdrawalId,
        bytes32 bscTxHash
    );

    /// @notice Emitted when a BNB withdrawal is refunded on Soul
    event BNBWithdrawalRefunded(
        bytes32 indexed withdrawalId,
        address indexed evmSender,
        uint256 amountWei
    );

    /// @notice Emitted when a cross-chain escrow is created
    event EscrowCreated(
        bytes32 indexed escrowId,
        address indexed evmParty,
        address bscParty,
        uint256 amountWei,
        bytes32 hashlock
    );

    /// @notice Emitted when an escrow is finished with valid preimage
    event EscrowFinished(bytes32 indexed escrowId, bytes32 preimage);

    /// @notice Emitted when an escrow is cancelled after timeout
    event EscrowCancelled(bytes32 indexed escrowId);

    /// @notice Emitted when a BSC block header is submitted
    event BlockHeaderSubmitted(uint256 indexed blockNumber, bytes32 blockHash);

    /// @notice Emitted when a private deposit is registered with ZK proof
    event PrivateDepositRegistered(
        bytes32 indexed depositId,
        bytes32 commitment,
        bytes32 nullifier
    );

    /// @notice Emitted when accumulated fees are withdrawn
    event FeesWithdrawn(address indexed recipient, uint256 amount);

    /*//////////////////////////////////////////////////////////////
                               ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Thrown when a zero address is provided
    error ZeroAddress();
    /// @notice Thrown when the bridge is not configured
    error BridgeNotConfigured();
    /// @notice Thrown when an invalid amount is provided
    error InvalidAmount();
    /// @notice Thrown when deposit amount is below minimum
    error AmountTooSmall(uint256 amountWei);
    /// @notice Thrown when deposit amount exceeds maximum
    error AmountTooLarge(uint256 amountWei);
    /// @notice Thrown when a deposit ID is not found
    error DepositNotFound(bytes32 depositId);
    /// @notice Thrown when a deposit is in an unexpected status
    error InvalidDepositStatus(bytes32 depositId, DepositStatus current);
    /// @notice Thrown when a withdrawal ID is not found
    error WithdrawalNotFound(bytes32 withdrawalId);
    /// @notice Thrown when a withdrawal is in an unexpected status
    error InvalidWithdrawalStatus(
        bytes32 withdrawalId,
        WithdrawalStatus current
    );
    /// @notice Thrown when an escrow ID is not found
    error EscrowNotFound(bytes32 escrowId);
    /// @notice Thrown when an escrow is not in ACTIVE status
    error EscrowNotActive(bytes32 escrowId);
    /// @notice Thrown when finish time has not been reached
    error FinishAfterNotReached(bytes32 escrowId, uint256 finishAfter);
    /// @notice Thrown when cancel time has not been reached
    error CancelAfterNotReached(bytes32 escrowId, uint256 cancelAfter);
    /// @notice Thrown when an invalid hashlock is provided
    error InvalidHashlock();
    /// @notice Thrown when a preimage does not match the hashlock
    error InvalidPreimage(bytes32 expected, bytes32 got);
    /// @notice Thrown when a Merkle proof is invalid
    error InvalidBlockProof();
    /// @notice Thrown when a block is not finalized
    error BlockNotFinalized(uint256 blockNumber);
    /// @notice Thrown when validator signatures are insufficient
    error InsufficientValidatorSignatures(uint256 got, uint256 required);
    /// @notice Thrown when a BSC tx hash has already been used
    error BSCTxAlreadyUsed(bytes32 txHash);
    /// @notice Thrown when a nullifier has already been consumed
    error NullifierAlreadyUsed(bytes32 nullifier);
    /// @notice Thrown when a ZK proof is invalid
    error InvalidProof();
    /// @notice Thrown when an insufficient fee is provided
    error InsufficientFee(uint256 provided, uint256 required);
    /// @notice Thrown when an escrow timelock duration is too short
    error TimelockTooShort(uint256 provided, uint256 minimum);
    /// @notice Thrown when an escrow timelock duration is too long
    error TimelockTooLong(uint256 provided, uint256 maximum);
    /// @notice Thrown when a withdrawal refund delay has not expired
    error WithdrawalTimelockNotExpired(bytes32 withdrawalId);

    /*//////////////////////////////////////////////////////////////
                             FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Configure the bridge parameters
    function configure(
        address bscBridgeContract,
        address wrappedBNB,
        address validatorOracle,
        uint256 minValidatorSignatures,
        uint256 requiredBlockConfirmations
    ) external;

    /// @notice Initiate a BNB deposit (BSC → Soul)
    /// @dev Called by relayer with BSC transaction proof
    function initiateBNBDeposit(
        bytes32 bscTxHash,
        address bscSender,
        address evmRecipient,
        uint256 amountWei,
        uint256 blockNumber,
        BSCMerkleProof calldata txProof,
        ValidatorAttestation[] calldata attestations
    ) external returns (bytes32 depositId);

    /// @notice Complete a BNB deposit after verification
    function completeBNBDeposit(bytes32 depositId) external;

    /// @notice Initiate a BNB withdrawal (Soul → BSC)
    /// @dev Burns wBNB and queues BSC release
    function initiateWithdrawal(
        address bscRecipient,
        uint256 amountWei
    ) external returns (bytes32 withdrawalId);

    /// @notice Complete a withdrawal after BSC release
    function completeWithdrawal(
        bytes32 withdrawalId,
        bytes32 bscTxHash,
        BSCMerkleProof calldata txProof,
        ValidatorAttestation[] calldata attestations
    ) external;

    /// @notice Refund a pending withdrawal after grace period
    function refundWithdrawal(bytes32 withdrawalId) external;

    /// @notice Create a cross-chain escrow (HTLC) for atomic swaps
    function createEscrow(
        address bscParty,
        bytes32 hashlock,
        uint256 finishAfter,
        uint256 cancelAfter
    ) external payable returns (bytes32 escrowId);

    /// @notice Finish an escrow by providing the valid preimage
    function finishEscrow(bytes32 escrowId, bytes32 preimage) external;

    /// @notice Cancel an escrow after the cancel-after time
    function cancelEscrow(bytes32 escrowId) external;

    /// @notice Register a private deposit with ZK proof
    function registerPrivateDeposit(
        bytes32 depositId,
        bytes32 commitment,
        bytes32 nullifier,
        bytes calldata zkProof
    ) external;

    /// @notice Submit a finalized BSC block header
    function submitBlockHeader(
        uint256 blockNumber,
        bytes32 blockHash,
        bytes32 parentHash,
        bytes32 transactionsRoot,
        bytes32 stateRoot,
        bytes32 receiptsRoot,
        uint256 blockTime,
        ValidatorAttestation[] calldata attestations
    ) external;

    /// @notice Get deposit details
    function getDeposit(
        bytes32 depositId
    ) external view returns (BNBDeposit memory);

    /// @notice Get withdrawal details
    function getWithdrawal(
        bytes32 withdrawalId
    ) external view returns (BNBWithdrawal memory);

    /// @notice Get escrow details
    function getEscrow(
        bytes32 escrowId
    ) external view returns (BNBEscrow memory);

    /// @notice Get block header details
    function getBlockHeader(
        uint256 blockNumber
    ) external view returns (BSCBlockHeader memory);
}
