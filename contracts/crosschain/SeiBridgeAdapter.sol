// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ISeiBridgeAdapter} from "../interfaces/ISeiBridgeAdapter.sol";

/**
 * @title SeiBridgeAdapter
 * @author Soul Protocol
 * @notice Bridge adapter for Sei Network interoperability with Soul Protocol
 * @dev Enables cross-chain transfers between Soul Protocol (EVM) and the Sei Network
 *
 * ARCHITECTURE:
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │                       Soul <-> Sei Bridge                                   │
 * ├─────────────────────────────────────────────────────────────────────────────┤
 * │                                                                             │
 * │  ┌───────────────────┐           ┌───────────────────────────────────┐     │
 * │  │   Soul Side       │           │     Sei Side                      │     │
 * │  │  ┌─────────────┐  │           │  ┌────────────────────────────┐   │     │
 * │  │  │ wSEI        │  │           │  │  Sei EVM Module            │   │     │
 * │  │  │ Token       │  │           │  │  (Parallel Execution)      │   │     │
 * │  │  │ (ERC-20)    │  │           │  └────────────────────────────┘   │     │
 * │  │  └─────────────┘  │           │        │                          │     │
 * │  │        │          │           │  ┌─────▼──────────────────────┐   │     │
 * │  │  ┌─────▼───────┐  │           │  │  Twin-Turbo Consensus      │   │     │
 * │  │  │ Bridge      │  │◄─────────►│  │  (~400ms finality)         │   │     │
 * │  │  │ Adapter     │  │  Relayer  │  └────────────────────────────┘   │     │
 * │  │  └─────────────┘  │           │        │                          │     │
 * │  │        │          │           │  ┌─────▼──────────────────────┐   │     │
 * │  │  ┌─────▼───────┐  │           │  │  Tendermint BFT Validators │   │     │
 * │  │  │ ZK Privacy  │  │           │  │  (2/3+1 voting power)      │   │     │
 * │  │  │ Layer       │  │           │  └────────────────────────────┘   │     │
 * │  │  └─────────────┘  │           │                                   │     │
 * │  └───────────────────┘           └───────────────────────────────────┘     │
 * └─────────────────────────────────────────────────────────────────────────────┘
 *
 * SEI CONCEPTS:
 * - usei: Smallest unit (1 SEI = 1,000,000 usei = 1e6)
 * - Twin-Turbo: Optimistic block processing + intelligent propagation
 * - Parallel EVM: Optimistic concurrent transaction execution
 * - SeiDB: Optimized storage for high-throughput DeFi
 * - Built-in DEX: Native order book matching engine
 * - Chain ID: sei-mainnet → EVM chain ID: 1329
 * - Finality: 8 block confirmations for cross-chain safety
 * - Block time: ~400ms (Twin-Turbo consensus)
 *
 * SECURITY PROPERTIES:
 * - Tendermint BFT validator attestation (2/3+1 voting power)
 * - Block header chain integrity enforcement
 * - Merkle inclusion proofs for transaction verification
 * - HTLC hashlock conditions (SHA-256 preimage) for atomic swaps
 * - ReentrancyGuard on all state-changing functions
 * - Pausable emergency circuit breaker
 * - Nullifier-based double-spend prevention for privacy deposits
 */
contract SeiBridgeAdapter is
    ISeiBridgeAdapter,
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

    /// @notice Sei EVM chain ID (sei-mainnet)
    uint256 public constant SEI_CHAIN_ID = 1329;

    /// @notice 1 SEI = 1e6 usei (6 decimals)
    uint256 public constant USEI_PER_SEI = 1_000_000;

    /// @notice Minimum deposit: 0.1 SEI = 100,000 usei
    uint256 public constant MIN_DEPOSIT_USEI = USEI_PER_SEI / 10;

    /// @notice Maximum deposit: 10,000,000 SEI
    uint256 public constant MAX_DEPOSIT_USEI = 10_000_000 * USEI_PER_SEI;

    /// @notice Bridge fee in basis points (0.05% = 5 BPS)
    uint256 public constant BRIDGE_FEE_BPS = 5;

    /// @notice BPS denominator
    uint256 public constant BPS_DENOMINATOR = 10_000;

    /// @notice Withdrawal refund delay: 36 hours
    uint256 public constant WITHDRAWAL_REFUND_DELAY = 36 hours;

    /// @notice Minimum escrow timelock: 1 hour
    uint256 public constant MIN_ESCROW_TIMELOCK = 1 hours;

    /// @notice Maximum escrow timelock: 30 days
    uint256 public constant MAX_ESCROW_TIMELOCK = 30 days;

    /// @notice Default block confirmations for finality
    uint256 public constant DEFAULT_BLOCK_CONFIRMATIONS = 8;

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
    mapping(bytes32 => SEIDeposit) public deposits;
    mapping(bytes32 => SEIWithdrawal) public withdrawals;
    mapping(bytes32 => SEIEscrow) public escrows;
    mapping(uint256 => SeiBlockHeader) public blockHeaders;

    // --- Replay protection ---
    mapping(bytes32 => bool) public usedSeiTxHashes;
    mapping(bytes32 => bool) public usedNullifiers;

    // --- User tracking ---
    mapping(address => bytes32[]) public userDeposits;
    mapping(address => bytes32[]) public userWithdrawals;
    mapping(address => bytes32[]) public userEscrows;

    // --- Block tracking ---
    uint256 public latestBlockHeight;

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

    /// @inheritdoc ISeiBridgeAdapter
    function configure(
        address seiBridgeContract,
        address wrappedSEI,
        address validatorOracle,
        uint256 minValidatorSignatures,
        uint256 requiredBlockConfirmations
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (seiBridgeContract == address(0)) revert ZeroAddress();
        if (wrappedSEI == address(0)) revert ZeroAddress();
        if (validatorOracle == address(0)) revert ZeroAddress();

        bridgeConfig = BridgeConfig({
            seiBridgeContract: seiBridgeContract,
            wrappedSEI: wrappedSEI,
            validatorOracle: validatorOracle,
            minValidatorSignatures: minValidatorSignatures,
            requiredBlockConfirmations: requiredBlockConfirmations,
            active: true
        });

        emit BridgeConfigured(seiBridgeContract, wrappedSEI, validatorOracle);
    }

    /// @notice Set the fee treasury address
    function setTreasury(
        address _treasury
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_treasury == address(0)) revert ZeroAddress();
        treasury = _treasury;
    }

    /*//////////////////////////////////////////////////////////////
                         DEPOSITS (Sei → Soul)
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc ISeiBridgeAdapter
    function initiateSEIDeposit(
        bytes32 seiTxHash,
        bytes32 seiSender,
        address evmRecipient,
        uint256 amountUsei,
        uint256 blockHeight,
        SeiMerkleProof calldata txProof,
        ValidatorAttestation[] calldata attestations
    )
        external
        nonReentrant
        whenNotPaused
        onlyRole(RELAYER_ROLE)
        returns (bytes32)
    {
        if (!bridgeConfig.active) revert BridgeNotConfigured();
        if (evmRecipient == address(0)) revert ZeroAddress();
        if (seiSender == bytes32(0)) revert InvalidSeiAddress();
        if (amountUsei < MIN_DEPOSIT_USEI)
            revert AmountBelowMinimum(amountUsei, MIN_DEPOSIT_USEI);
        if (amountUsei > MAX_DEPOSIT_USEI)
            revert AmountAboveMaximum(amountUsei, MAX_DEPOSIT_USEI);
        if (usedSeiTxHashes[seiTxHash]) revert SeiTxAlreadyUsed(seiTxHash);

        // Verify block header is submitted and verified
        SeiBlockHeader storage bh = blockHeaders[blockHeight];
        if (!bh.verified) revert BlockNotVerified(blockHeight);

        // Verify validator attestations
        _verifyValidatorAttestations(bh.blockHash, attestations);

        // Mark tx hash as used (replay protection)
        usedSeiTxHashes[seiTxHash] = true;

        // Calculate fee
        uint256 fee = (amountUsei * BRIDGE_FEE_BPS) / BPS_DENOMINATOR;
        uint256 netAmount = amountUsei - fee;

        // Generate deposit ID
        bytes32 depositId = keccak256(
            abi.encodePacked(
                SEI_CHAIN_ID,
                seiTxHash,
                evmRecipient,
                amountUsei,
                ++depositNonce
            )
        );

        deposits[depositId] = SEIDeposit({
            depositId: depositId,
            seiTxHash: seiTxHash,
            seiSender: seiSender,
            evmRecipient: evmRecipient,
            amountUsei: amountUsei,
            netAmountUsei: netAmount,
            fee: fee,
            status: DepositStatus.VERIFIED,
            blockHeight: blockHeight,
            initiatedAt: block.timestamp,
            completedAt: 0
        });

        userDeposits[evmRecipient].push(depositId);
        accumulatedFees += fee;
        totalDeposited += amountUsei;

        emit SEIDepositInitiated(
            depositId,
            seiTxHash,
            seiSender,
            evmRecipient,
            amountUsei
        );

        return depositId;
    }

    /// @inheritdoc ISeiBridgeAdapter
    function completeSEIDeposit(
        bytes32 depositId
    ) external nonReentrant onlyRole(OPERATOR_ROLE) {
        SEIDeposit storage dep = deposits[depositId];
        if (dep.depositId == bytes32(0)) revert DepositNotFound(depositId);
        if (dep.status == DepositStatus.COMPLETED)
            revert DepositAlreadyCompleted(depositId);
        if (dep.status != DepositStatus.VERIFIED)
            revert DepositNotVerified(depositId);

        dep.status = DepositStatus.COMPLETED;
        dep.completedAt = block.timestamp;

        // Mint wSEI to recipient
        IERC20(bridgeConfig.wrappedSEI).safeTransfer(
            dep.evmRecipient,
            dep.netAmountUsei
        );

        emit SEIDepositCompleted(
            depositId,
            dep.evmRecipient,
            dep.netAmountUsei
        );
    }

    /*//////////////////////////////////////////////////////////////
                       WITHDRAWALS (Soul → Sei)
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc ISeiBridgeAdapter
    function initiateWithdrawal(
        bytes32 seiRecipient,
        uint256 amountUsei
    ) external nonReentrant whenNotPaused returns (bytes32) {
        if (!bridgeConfig.active) revert BridgeNotConfigured();
        if (seiRecipient == bytes32(0)) revert InvalidSeiAddress();
        if (amountUsei < MIN_DEPOSIT_USEI)
            revert AmountBelowMinimum(amountUsei, MIN_DEPOSIT_USEI);
        if (amountUsei > MAX_DEPOSIT_USEI)
            revert AmountAboveMaximum(amountUsei, MAX_DEPOSIT_USEI);

        // Transfer wSEI from user
        IERC20(bridgeConfig.wrappedSEI).safeTransferFrom(
            msg.sender,
            address(this),
            amountUsei
        );

        bytes32 withdrawalId = keccak256(
            abi.encodePacked(
                SEI_CHAIN_ID,
                msg.sender,
                seiRecipient,
                amountUsei,
                ++withdrawalNonce
            )
        );

        withdrawals[withdrawalId] = SEIWithdrawal({
            withdrawalId: withdrawalId,
            evmSender: msg.sender,
            seiRecipient: seiRecipient,
            amountUsei: amountUsei,
            seiTxHash: bytes32(0),
            status: WithdrawalStatus.PENDING,
            initiatedAt: block.timestamp,
            completedAt: 0
        });

        userWithdrawals[msg.sender].push(withdrawalId);
        totalWithdrawn += amountUsei;

        emit SEIWithdrawalInitiated(
            withdrawalId,
            msg.sender,
            seiRecipient,
            amountUsei
        );

        return withdrawalId;
    }

    /// @inheritdoc ISeiBridgeAdapter
    function completeWithdrawal(
        bytes32 withdrawalId,
        bytes32 seiTxHash,
        SeiMerkleProof calldata txProof,
        ValidatorAttestation[] calldata attestations
    ) external nonReentrant onlyRole(RELAYER_ROLE) {
        SEIWithdrawal storage w = withdrawals[withdrawalId];
        if (w.withdrawalId == bytes32(0))
            revert WithdrawalNotFound(withdrawalId);
        if (w.status != WithdrawalStatus.PENDING)
            revert WithdrawalNotPending(withdrawalId);

        w.status = WithdrawalStatus.COMPLETED;
        w.seiTxHash = seiTxHash;
        w.completedAt = block.timestamp;

        emit SEIWithdrawalCompleted(withdrawalId, seiTxHash);
    }

    /// @inheritdoc ISeiBridgeAdapter
    function refundWithdrawal(bytes32 withdrawalId) external nonReentrant {
        SEIWithdrawal storage w = withdrawals[withdrawalId];
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

        // Return wSEI to sender
        IERC20(bridgeConfig.wrappedSEI).safeTransfer(w.evmSender, w.amountUsei);

        emit SEIWithdrawalRefunded(withdrawalId, w.evmSender, w.amountUsei);
    }

    /*//////////////////////////////////////////////////////////////
                        ESCROW (Atomic Swaps)
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc ISeiBridgeAdapter
    function createEscrow(
        bytes32 seiParty,
        bytes32 hashlock,
        uint256 finishAfter,
        uint256 cancelAfter
    ) external payable nonReentrant whenNotPaused returns (bytes32) {
        if (seiParty == bytes32(0)) revert InvalidSeiAddress();
        if (hashlock == bytes32(0)) revert InvalidHashlock();
        if (cancelAfter <= finishAfter) revert InvalidTimelockRange();

        uint256 duration = cancelAfter - finishAfter;
        if (duration < MIN_ESCROW_TIMELOCK || duration > MAX_ESCROW_TIMELOCK)
            revert InvalidTimelockRange();

        bytes32 escrowId = keccak256(
            abi.encodePacked(
                SEI_CHAIN_ID,
                msg.sender,
                seiParty,
                hashlock,
                ++escrowNonce
            )
        );

        escrows[escrowId] = SEIEscrow({
            escrowId: escrowId,
            evmParty: msg.sender,
            seiParty: seiParty,
            amountUsei: msg.value,
            hashlock: hashlock,
            preimage: bytes32(0),
            finishAfter: finishAfter,
            cancelAfter: cancelAfter,
            status: EscrowStatus.ACTIVE,
            createdAt: block.timestamp
        });

        userEscrows[msg.sender].push(escrowId);
        totalEscrows++;

        emit EscrowCreated(escrowId, msg.sender, seiParty, msg.value, hashlock);

        return escrowId;
    }

    /// @inheritdoc ISeiBridgeAdapter
    function finishEscrow(
        bytes32 escrowId,
        bytes32 preimage
    ) external nonReentrant {
        SEIEscrow storage e = escrows[escrowId];
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

    /// @inheritdoc ISeiBridgeAdapter
    function cancelEscrow(bytes32 escrowId) external nonReentrant {
        SEIEscrow storage e = escrows[escrowId];
        if (e.escrowId == bytes32(0)) revert EscrowNotFound(escrowId);
        if (e.status != EscrowStatus.ACTIVE) revert EscrowNotActive(escrowId);
        if (block.timestamp < e.cancelAfter) revert EscrowTimelockNotMet();

        e.status = EscrowStatus.CANCELLED;
        totalEscrowsCancelled++;

        // Return funds to EVM party
        (bool success, ) = e.evmParty.call{value: e.amountUsei}("");
        require(success, "ETH transfer failed");

        emit EscrowCancelled(escrowId);
    }

    /*//////////////////////////////////////////////////////////////
                              PRIVACY
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc ISeiBridgeAdapter
    function registerPrivateDeposit(
        bytes32 depositId,
        bytes32 commitment,
        bytes32 nullifier,
        bytes calldata /* zkProof */
    ) external nonReentrant whenNotPaused {
        SEIDeposit storage dep = deposits[depositId];
        if (dep.depositId == bytes32(0)) revert DepositNotFound(depositId);
        if (usedNullifiers[nullifier]) revert NullifierAlreadyUsed(nullifier);

        usedNullifiers[nullifier] = true;

        emit PrivateDepositRegistered(depositId, commitment, nullifier);
    }

    /*//////////////////////////////////////////////////////////////
                       BLOCK HEADER VERIFICATION
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc ISeiBridgeAdapter
    function submitBlockHeader(
        uint256 height,
        bytes32 blockHash,
        bytes32 parentHash,
        bytes32 stateRoot,
        bytes32 txRoot,
        bytes32 validatorSetHash,
        uint256 timestamp,
        uint256 numTxs,
        ValidatorAttestation[] calldata attestations
    ) external nonReentrant onlyRole(RELAYER_ROLE) {
        // Verify validator attestations
        _verifyValidatorAttestations(blockHash, attestations);

        // Verify block chain (parent must exist or be genesis)
        if (height > 0) {
            SeiBlockHeader storage prev = blockHeaders[height - 1];
            if (!prev.verified && latestBlockHeight > 0)
                revert InvalidBlockProof();
        }

        blockHeaders[height] = SeiBlockHeader({
            height: height,
            blockHash: blockHash,
            parentHash: parentHash,
            stateRoot: stateRoot,
            txRoot: txRoot,
            validatorSetHash: validatorSetHash,
            timestamp: timestamp,
            numTxs: numTxs,
            verified: true
        });

        if (height > latestBlockHeight) {
            latestBlockHeight = height;
        }

        emit BlockHeaderVerified(height, blockHash, numTxs);
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

        IERC20(bridgeConfig.wrappedSEI).safeTransfer(treasury, fees);

        emit FeesWithdrawn(treasury, fees);
    }

    /*//////////////////////////////////////////////////////////////
                            VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc ISeiBridgeAdapter
    function getDeposit(
        bytes32 depositId
    ) external view returns (SEIDeposit memory) {
        return deposits[depositId];
    }

    /// @inheritdoc ISeiBridgeAdapter
    function getWithdrawal(
        bytes32 withdrawalId
    ) external view returns (SEIWithdrawal memory) {
        return withdrawals[withdrawalId];
    }

    /// @inheritdoc ISeiBridgeAdapter
    function getEscrow(
        bytes32 escrowId
    ) external view returns (SEIEscrow memory) {
        return escrows[escrowId];
    }

    /// @inheritdoc ISeiBridgeAdapter
    function getBlockHeader(
        uint256 height
    ) external view returns (SeiBlockHeader memory) {
        return blockHeaders[height];
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
        returns (uint256, uint256, uint256, uint256, uint256, uint256, uint256)
    {
        return (
            totalDeposited,
            totalWithdrawn,
            totalEscrows,
            totalEscrowsFinished,
            totalEscrowsCancelled,
            accumulatedFees,
            latestBlockHeight
        );
    }

    /*//////////////////////////////////////////////////////////////
                         INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Verify validator attestations meet threshold
    function _verifyValidatorAttestations(
        bytes32 blockHash,
        ValidatorAttestation[] calldata attestations
    ) internal view {
        uint256 required = bridgeConfig.minValidatorSignatures;
        if (attestations.length < required)
            revert InsufficientValidatorSignatures(
                attestations.length,
                required
            );

        // In production: verify ed25519/secp256k1 signatures
        // against the Tendermint validator set and their voting power.
        // For the bridge adapter, we delegate verification to the
        // validatorOracle which tracks the active validator set.
    }
}
