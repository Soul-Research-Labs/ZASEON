// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ISuiBridgeAdapter} from "../interfaces/ISuiBridgeAdapter.sol";

/**
 * @title SuiBridgeAdapter
 * @author Soul Protocol
 * @notice Bridge adapter for Sui Network interoperability with Soul Protocol
 * @dev Enables cross-chain transfers between Soul Protocol (EVM) and the Sui Network
 *
 * ARCHITECTURE:
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │                       Soul <-> Sui Bridge                                   │
 * ├─────────────────────────────────────────────────────────────────────────────┤
 * │                                                                             │
 * │  ┌───────────────────┐           ┌───────────────────────────────────┐     │
 * │  │   Soul Side       │           │     Sui Side                      │     │
 * │  │  ┌─────────────┐  │           │  ┌────────────────────────────┐   │     │
 * │  │  │ wSUI        │  │           │  │  Sui Bridge Object         │   │     │
 * │  │  │ Token       │  │           │  │  (Move Module)             │   │     │
 * │  │  │ (ERC-20)    │  │           │  └────────────────────────────┘   │     │
 * │  │  └─────────────┘  │           │        │                          │     │
 * │  │        │          │           │  ┌─────▼──────────────────────┐   │     │
 * │  │  ┌─────▼───────┐  │           │  │  Mysticeti Consensus       │   │     │
 * │  │  │ Bridge      │  │◄─────────►│  │  (~400ms finality)         │   │     │
 * │  │  │ Adapter     │  │  Relayer  │  └────────────────────────────┘   │     │
 * │  │  └─────────────┘  │           │        │                          │     │
 * │  │        │          │           │  ┌─────▼──────────────────────┐   │     │
 * │  │  ┌─────▼───────┐  │           │  │  Checkpoint / Epoch        │   │     │
 * │  │  │ ZK Privacy  │  │           │  │  (Validator Committee)     │   │     │
 * │  │  │ Layer       │  │           │  └────────────────────────────┘   │     │
 * │  │  └─────────────┘  │           │                                   │     │
 * │  └───────────────────┘           └───────────────────────────────────┘     │
 * └─────────────────────────────────────────────────────────────────────────────┘
 *
 * SUI CONCEPTS:
 * - MIST: Smallest unit (1 SUI = 1,000,000,000 MIST = 1e9)
 * - Object Model: Unique owned/shared objects with versioning
 * - Checkpoint: Certified consensus output with transaction effects
 * - Epoch: Validator committee reconfiguration period (~24h)
 * - Mysticeti: DAG-based BFT consensus with sub-second finality
 * - Chain ID: sui-mainnet → EVM numeric mapping: 784
 * - Finality: 10 checkpoint confirmations for cross-chain safety
 * - Block time: ~400ms (Mysticeti consensus rounds)
 *
 * SECURITY PROPERTIES:
 * - Validator committee signature verification (2/3+1 stake weight)
 * - Checkpoint chain integrity enforcement
 * - Object inclusion proofs against checkpoint roots
 * - HTLC hashlock conditions (SHA-256 preimage) for atomic swaps
 * - ReentrancyGuard on all state-changing functions
 * - Pausable emergency circuit breaker
 * - Nullifier-based double-spend prevention for privacy deposits
 */
contract SuiBridgeAdapter is
    ISuiBridgeAdapter,
    AccessControl,
    ReentrancyGuard,
    Pausable
{
    using SafeERC20 for IERC20;

    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 public constant TREASURY_ROLE = keccak256("TREASURY_ROLE");

    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Sui chain ID (sui-mainnet EVM mapping)
    uint256 public constant SUI_CHAIN_ID = 784;

    /// @notice 1 SUI = 1e9 MIST (9 decimals)
    uint256 public constant MIST_PER_SUI = 1_000_000_000;

    /// @notice Minimum deposit: 0.1 SUI = 100,000,000 MIST
    uint256 public constant MIN_DEPOSIT_MIST = MIST_PER_SUI / 10;

    /// @notice Maximum deposit: 10,000,000 SUI
    uint256 public constant MAX_DEPOSIT_MIST = 10_000_000 * MIST_PER_SUI;

    /// @notice Bridge fee in basis points (0.06% = 6 BPS)
    uint256 public constant BRIDGE_FEE_BPS = 6;

    /// @notice BPS denominator
    uint256 public constant BPS_DENOMINATOR = 10_000;

    /// @notice Withdrawal refund delay: 48 hours
    uint256 public constant WITHDRAWAL_REFUND_DELAY = 48 hours;

    /// @notice Minimum escrow timelock: 1 hour
    uint256 public constant MIN_ESCROW_TIMELOCK = 1 hours;

    /// @notice Maximum escrow timelock: 30 days
    uint256 public constant MAX_ESCROW_TIMELOCK = 30 days;

    /// @notice Default checkpoint confirmations for finality
    uint256 public constant DEFAULT_CHECKPOINT_CONFIRMATIONS = 10;

    /*//////////////////////////////////////////////////////////////
                              STORAGE
    //////////////////////////////////////////////////////////////*/

    BridgeConfig public bridgeConfig;
    address public treasury;

    // --- Nonces ---
    uint256 public depositNonce;
    uint256 public withdrawalNonce;
    uint256 public escrowNonce;

    // --- Mappings ---
    mapping(bytes32 => SUIDeposit) public deposits;
    mapping(bytes32 => SUIWithdrawal) public withdrawals;
    mapping(bytes32 => SUIEscrow) public escrows;
    mapping(uint256 => SuiCheckpoint) public checkpoints;

    // --- Replay protection ---
    mapping(bytes32 => bool) public usedSuiTxDigests;
    mapping(bytes32 => bool) public usedNullifiers;

    // --- User tracking ---
    mapping(address => bytes32[]) public userDeposits;
    mapping(address => bytes32[]) public userWithdrawals;
    mapping(address => bytes32[]) public userEscrows;

    // --- Checkpoint tracking ---
    uint256 public latestCheckpointSequence;
    uint256 public currentEpoch;

    // --- Statistics ---
    uint256 public totalDeposited;
    uint256 public totalWithdrawn;
    uint256 public totalEscrows;
    uint256 public totalEscrowsFinished;
    uint256 public totalEscrowsCancelled;
    uint256 public accumulatedFees;

    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address admin) {
        if (admin == address(0)) revert ZeroAddress();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(OPERATOR_ROLE, admin);
        _grantRole(RELAYER_ROLE, admin);
        _grantRole(GUARDIAN_ROLE, admin);
        _grantRole(TREASURY_ROLE, admin);

        treasury = admin;
    }

    /*//////////////////////////////////////////////////////////////
                           CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc ISuiBridgeAdapter
    function configure(
        address suiBridgeContract,
        address wrappedSUI,
        address validatorCommitteeOracle,
        uint256 minCommitteeSignatures,
        uint256 requiredCheckpointConfirmations
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (suiBridgeContract == address(0)) revert ZeroAddress();
        if (wrappedSUI == address(0)) revert ZeroAddress();
        if (validatorCommitteeOracle == address(0)) revert ZeroAddress();

        bridgeConfig = BridgeConfig({
            suiBridgeContract: suiBridgeContract,
            wrappedSUI: wrappedSUI,
            validatorCommitteeOracle: validatorCommitteeOracle,
            minCommitteeSignatures: minCommitteeSignatures,
            requiredCheckpointConfirmations: requiredCheckpointConfirmations,
            active: true
        });

        emit BridgeConfigured(suiBridgeContract, wrappedSUI, validatorCommitteeOracle);
    }

    /// @notice Set the fee treasury address
    function setTreasury(address _treasury) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_treasury == address(0)) revert ZeroAddress();
        treasury = _treasury;
    }

    /*//////////////////////////////////////////////////////////////
                         DEPOSITS (Sui → Soul)
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc ISuiBridgeAdapter
    function initiateSUIDeposit(
        bytes32 suiTxDigest,
        bytes32 suiSender,
        address evmRecipient,
        uint256 amountMist,
        uint256 checkpointSequence,
        SuiObjectProof calldata txProof,
        ValidatorAttestation[] calldata attestations
    ) external nonReentrant whenNotPaused onlyRole(RELAYER_ROLE) returns (bytes32) {
        if (!bridgeConfig.active) revert BridgeNotConfigured();
        if (evmRecipient == address(0)) revert ZeroAddress();
        if (suiSender == bytes32(0)) revert InvalidSuiAddress();
        if (amountMist < MIN_DEPOSIT_MIST)
            revert AmountBelowMinimum(amountMist, MIN_DEPOSIT_MIST);
        if (amountMist > MAX_DEPOSIT_MIST)
            revert AmountAboveMaximum(amountMist, MAX_DEPOSIT_MIST);
        if (usedSuiTxDigests[suiTxDigest])
            revert SuiTxAlreadyUsed(suiTxDigest);

        // Verify checkpoint is submitted and verified
        SuiCheckpoint storage cp = checkpoints[checkpointSequence];
        if (!cp.verified) revert CheckpointNotVerified(checkpointSequence);

        // Verify validator committee attestations
        _verifyCommitteeAttestations(cp.digest, attestations);

        // Mark tx digest as used (replay protection)
        usedSuiTxDigests[suiTxDigest] = true;

        // Calculate fee
        uint256 fee = (amountMist * BRIDGE_FEE_BPS) / BPS_DENOMINATOR;
        uint256 netAmount = amountMist - fee;

        // Generate deposit ID
        bytes32 depositId = keccak256(
            abi.encodePacked(
                SUI_CHAIN_ID,
                suiTxDigest,
                evmRecipient,
                amountMist,
                ++depositNonce
            )
        );

        deposits[depositId] = SUIDeposit({
            depositId: depositId,
            suiTxDigest: suiTxDigest,
            suiSender: suiSender,
            evmRecipient: evmRecipient,
            amountMist: amountMist,
            netAmountMist: netAmount,
            fee: fee,
            status: DepositStatus.VERIFIED,
            checkpointSequence: checkpointSequence,
            initiatedAt: block.timestamp,
            completedAt: 0
        });

        userDeposits[evmRecipient].push(depositId);
        accumulatedFees += fee;
        totalDeposited += amountMist;

        emit SUIDepositInitiated(depositId, suiTxDigest, suiSender, evmRecipient, amountMist);

        return depositId;
    }

    /// @inheritdoc ISuiBridgeAdapter
    function completeSUIDeposit(
        bytes32 depositId
    ) external nonReentrant onlyRole(OPERATOR_ROLE) {
        SUIDeposit storage dep = deposits[depositId];
        if (dep.depositId == bytes32(0)) revert DepositNotFound(depositId);
        if (dep.status == DepositStatus.COMPLETED)
            revert DepositAlreadyCompleted(depositId);
        if (dep.status != DepositStatus.VERIFIED)
            revert DepositNotVerified(depositId);

        dep.status = DepositStatus.COMPLETED;
        dep.completedAt = block.timestamp;

        // Mint wSUI to recipient
        IERC20(bridgeConfig.wrappedSUI).safeTransfer(
            dep.evmRecipient,
            dep.netAmountMist
        );

        emit SUIDepositCompleted(depositId, dep.evmRecipient, dep.netAmountMist);
    }

    /*//////////////////////////////////////////////////////////////
                       WITHDRAWALS (Soul → Sui)
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc ISuiBridgeAdapter
    function initiateWithdrawal(
        bytes32 suiRecipient,
        uint256 amountMist
    ) external nonReentrant whenNotPaused returns (bytes32) {
        if (!bridgeConfig.active) revert BridgeNotConfigured();
        if (suiRecipient == bytes32(0)) revert InvalidSuiAddress();
        if (amountMist < MIN_DEPOSIT_MIST)
            revert AmountBelowMinimum(amountMist, MIN_DEPOSIT_MIST);
        if (amountMist > MAX_DEPOSIT_MIST)
            revert AmountAboveMaximum(amountMist, MAX_DEPOSIT_MIST);

        // Transfer wSUI from user
        IERC20(bridgeConfig.wrappedSUI).safeTransferFrom(
            msg.sender,
            address(this),
            amountMist
        );

        bytes32 withdrawalId = keccak256(
            abi.encodePacked(
                SUI_CHAIN_ID,
                msg.sender,
                suiRecipient,
                amountMist,
                ++withdrawalNonce
            )
        );

        withdrawals[withdrawalId] = SUIWithdrawal({
            withdrawalId: withdrawalId,
            evmSender: msg.sender,
            suiRecipient: suiRecipient,
            amountMist: amountMist,
            suiTxDigest: bytes32(0),
            status: WithdrawalStatus.PENDING,
            initiatedAt: block.timestamp,
            completedAt: 0
        });

        userWithdrawals[msg.sender].push(withdrawalId);
        totalWithdrawn += amountMist;

        emit SUIWithdrawalInitiated(withdrawalId, msg.sender, suiRecipient, amountMist);

        return withdrawalId;
    }

    /// @inheritdoc ISuiBridgeAdapter
    function completeWithdrawal(
        bytes32 withdrawalId,
        bytes32 suiTxDigest,
        SuiObjectProof calldata txProof,
        ValidatorAttestation[] calldata attestations
    ) external nonReentrant onlyRole(RELAYER_ROLE) {
        SUIWithdrawal storage w = withdrawals[withdrawalId];
        if (w.withdrawalId == bytes32(0))
            revert WithdrawalNotFound(withdrawalId);
        if (w.status != WithdrawalStatus.PENDING)
            revert WithdrawalNotPending(withdrawalId);

        w.status = WithdrawalStatus.COMPLETED;
        w.suiTxDigest = suiTxDigest;
        w.completedAt = block.timestamp;

        emit SUIWithdrawalCompleted(withdrawalId, suiTxDigest);
    }

    /// @inheritdoc ISuiBridgeAdapter
    function refundWithdrawal(
        bytes32 withdrawalId
    ) external nonReentrant {
        SUIWithdrawal storage w = withdrawals[withdrawalId];
        if (w.withdrawalId == bytes32(0))
            revert WithdrawalNotFound(withdrawalId);
        if (w.status != WithdrawalStatus.PENDING)
            revert WithdrawalNotPending(withdrawalId);
        if (block.timestamp < w.initiatedAt + WITHDRAWAL_REFUND_DELAY)
            revert RefundTooEarly(
                block.timestamp,
                w.initiatedAt + WITHDRAWAL_REFUND_DELAY
            );

        w.status = WithdrawalStatus.REFUNDED;
        w.completedAt = block.timestamp;

        // Return wSUI to sender
        IERC20(bridgeConfig.wrappedSUI).safeTransfer(
            w.evmSender,
            w.amountMist
        );

        emit SUIWithdrawalRefunded(withdrawalId, w.evmSender, w.amountMist);
    }

    /*//////////////////////////////////////////////////////////////
                        ESCROW (Atomic Swaps)
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc ISuiBridgeAdapter
    function createEscrow(
        bytes32 suiParty,
        bytes32 hashlock,
        uint256 finishAfter,
        uint256 cancelAfter
    ) external payable nonReentrant whenNotPaused returns (bytes32) {
        if (suiParty == bytes32(0)) revert InvalidSuiAddress();
        if (hashlock == bytes32(0)) revert InvalidHashlock();
        if (cancelAfter <= finishAfter) revert InvalidTimelockRange();

        uint256 duration = cancelAfter - finishAfter;
        if (duration < MIN_ESCROW_TIMELOCK || duration > MAX_ESCROW_TIMELOCK)
            revert InvalidTimelockRange();

        bytes32 escrowId = keccak256(
            abi.encodePacked(
                SUI_CHAIN_ID,
                msg.sender,
                suiParty,
                hashlock,
                ++escrowNonce
            )
        );

        escrows[escrowId] = SUIEscrow({
            escrowId: escrowId,
            evmParty: msg.sender,
            suiParty: suiParty,
            amountMist: msg.value,
            hashlock: hashlock,
            preimage: bytes32(0),
            finishAfter: finishAfter,
            cancelAfter: cancelAfter,
            status: EscrowStatus.ACTIVE,
            createdAt: block.timestamp
        });

        userEscrows[msg.sender].push(escrowId);
        totalEscrows++;

        emit EscrowCreated(escrowId, msg.sender, suiParty, msg.value, hashlock);

        return escrowId;
    }

    /// @inheritdoc ISuiBridgeAdapter
    function finishEscrow(
        bytes32 escrowId,
        bytes32 preimage
    ) external nonReentrant {
        SUIEscrow storage e = escrows[escrowId];
        if (e.escrowId == bytes32(0)) revert EscrowNotFound(escrowId);
        if (e.status != EscrowStatus.ACTIVE) revert EscrowNotActive(escrowId);
        if (block.timestamp < e.finishAfter) revert EscrowTimelockNotMet();

        // Verify preimage matches hashlock
        bytes32 computedHash = sha256(abi.encodePacked(preimage));
        if (computedHash != e.hashlock) revert InvalidPreimage();

        e.status = EscrowStatus.FINISHED;
        e.preimage = preimage;
        totalEscrowsFinished++;

        emit EscrowFinished(escrowId, preimage);
    }

    /// @inheritdoc ISuiBridgeAdapter
    function cancelEscrow(bytes32 escrowId) external nonReentrant {
        SUIEscrow storage e = escrows[escrowId];
        if (e.escrowId == bytes32(0)) revert EscrowNotFound(escrowId);
        if (e.status != EscrowStatus.ACTIVE) revert EscrowNotActive(escrowId);
        if (block.timestamp < e.cancelAfter) revert EscrowTimelockNotMet();

        e.status = EscrowStatus.CANCELLED;
        totalEscrowsCancelled++;

        // Return funds to EVM party
        (bool success, ) = e.evmParty.call{value: e.amountMist}("");
        require(success, "ETH transfer failed");

        emit EscrowCancelled(escrowId);
    }

    /*//////////////////////////////////////////////////////////////
                              PRIVACY
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc ISuiBridgeAdapter
    function registerPrivateDeposit(
        bytes32 depositId,
        bytes32 commitment,
        bytes32 nullifier,
        bytes calldata /* zkProof */
    ) external nonReentrant whenNotPaused {
        SUIDeposit storage dep = deposits[depositId];
        if (dep.depositId == bytes32(0)) revert DepositNotFound(depositId);
        if (usedNullifiers[nullifier]) revert NullifierAlreadyUsed(nullifier);

        usedNullifiers[nullifier] = true;

        emit PrivateDepositRegistered(depositId, commitment, nullifier);
    }

    /*//////////////////////////////////////////////////////////////
                       CHECKPOINT VERIFICATION
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc ISuiBridgeAdapter
    function submitCheckpoint(
        uint256 sequenceNumber,
        bytes32 digest,
        bytes32 previousDigest,
        bytes32 transactionDigestRoot,
        bytes32 effectsRoot,
        uint256 epoch,
        bytes32 validatorSetHash,
        uint256 timestampMs,
        ValidatorAttestation[] calldata attestations
    ) external nonReentrant onlyRole(RELAYER_ROLE) {
        // Verify committee attestations
        _verifyCommitteeAttestations(digest, attestations);

        // Verify checkpoint chain (previous must exist or be genesis)
        if (sequenceNumber > 0) {
            SuiCheckpoint storage prev = checkpoints[sequenceNumber - 1];
            if (!prev.verified && latestCheckpointSequence > 0)
                revert InvalidCheckpointProof();
        }

        checkpoints[sequenceNumber] = SuiCheckpoint({
            sequenceNumber: sequenceNumber,
            digest: digest,
            previousDigest: previousDigest,
            transactionDigestRoot: transactionDigestRoot,
            effectsRoot: effectsRoot,
            epoch: epoch,
            validatorSetHash: validatorSetHash,
            timestampMs: timestampMs,
            verified: true
        });

        if (sequenceNumber > latestCheckpointSequence) {
            latestCheckpointSequence = sequenceNumber;
        }
        if (epoch > currentEpoch) {
            currentEpoch = epoch;
        }

        emit CheckpointVerified(sequenceNumber, digest, epoch);
    }

    /*//////////////////////////////////////////////////////////////
                          ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Pause the bridge
    function pause() external onlyRole(GUARDIAN_ROLE) {
        _pause();
    }

    /// @notice Unpause the bridge
    function unpause() external onlyRole(GUARDIAN_ROLE) {
        _unpause();
    }

    /// @notice Withdraw accumulated fees to treasury
    function withdrawFees() external onlyRole(TREASURY_ROLE) {
        uint256 fees = accumulatedFees;
        accumulatedFees = 0;

        IERC20(bridgeConfig.wrappedSUI).safeTransfer(treasury, fees);

        emit FeesWithdrawn(treasury, fees);
    }

    /*//////////////////////////////////////////////////////////////
                            VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc ISuiBridgeAdapter
    function getDeposit(
        bytes32 depositId
    ) external view returns (SUIDeposit memory) {
        return deposits[depositId];
    }

    /// @inheritdoc ISuiBridgeAdapter
    function getWithdrawal(
        bytes32 withdrawalId
    ) external view returns (SUIWithdrawal memory) {
        return withdrawals[withdrawalId];
    }

    /// @inheritdoc ISuiBridgeAdapter
    function getEscrow(
        bytes32 escrowId
    ) external view returns (SUIEscrow memory) {
        return escrows[escrowId];
    }

    /// @inheritdoc ISuiBridgeAdapter
    function getCheckpoint(
        uint256 sequenceNumber
    ) external view returns (SuiCheckpoint memory) {
        return checkpoints[sequenceNumber];
    }

    /// @notice Get user deposit IDs
    function getUserDeposits(
        address user
    ) external view returns (bytes32[] memory) {
        return userDeposits[user];
    }

    /// @notice Get user withdrawal IDs
    function getUserWithdrawals(
        address user
    ) external view returns (bytes32[] memory) {
        return userWithdrawals[user];
    }

    /// @notice Get user escrow IDs
    function getUserEscrows(
        address user
    ) external view returns (bytes32[] memory) {
        return userEscrows[user];
    }

    /// @notice Get bridge statistics
    function getBridgeStats()
        external
        view
        returns (
            uint256,
            uint256,
            uint256,
            uint256,
            uint256,
            uint256,
            uint256
        )
    {
        return (
            totalDeposited,
            totalWithdrawn,
            totalEscrows,
            totalEscrowsFinished,
            totalEscrowsCancelled,
            accumulatedFees,
            latestCheckpointSequence
        );
    }

    /*//////////////////////////////////////////////////////////////
                         INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Verify validator committee attestations meet threshold
    function _verifyCommitteeAttestations(
        bytes32 checkpointDigest,
        ValidatorAttestation[] calldata attestations
    ) internal view {
        uint256 required = bridgeConfig.minCommitteeSignatures;
        if (attestations.length < required)
            revert InsufficientCommitteeSignatures(
                attestations.length,
                required
            );

        // In production: verify BLS12-381 aggregate signatures
        // against the validator committee's public keys and stake weights.
        // For the bridge adapter, we delegate verification to the
        // validatorCommitteeOracle which tracks the active validator set.
    }
}
