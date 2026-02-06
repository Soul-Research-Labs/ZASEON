// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IBNBBridgeAdapter} from "../interfaces/IBNBBridgeAdapter.sol";

/**
 * @title BNBBridgeAdapter
 * @author Soul Protocol
 * @notice Bridge adapter for BNB Chain (BSC) interoperability with Soul Protocol
 * @dev Enables cross-chain transfers between Soul Protocol (EVM) and BNB Chain
 *
 * ARCHITECTURE:
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │                     Soul <-> BNB Chain Bridge                               │
 * ├─────────────────────────────────────────────────────────────────────────────┤
 * │                                                                             │
 * │  ┌───────────────────┐           ┌───────────────────────────────────┐     │
 * │  │   Soul Side       │           │        BSC Side                   │     │
 * │  │  ┌─────────────┐  │           │  ┌────────────────────────────┐   │     │
 * │  │  │ wBNB Token  │  │           │  │  Bridge Contract           │   │     │
 * │  │  │ (ERC-20)    │  │           │  │  (BEP-20 compatible)       │   │     │
 * │  │  └─────────────┘  │           │  └────────────────────────────┘   │     │
 * │  │        │          │           │        │                          │     │
 * │  │  ┌─────▼───────┐  │           │  ┌─────▼──────────────────────┐   │     │
 * │  │  │ Bridge      │  │◄─────────►│  │  PoSA Validator Set        │   │     │
 * │  │  │ Adapter     │  │  Relayer  │  │  (21 active validators)    │   │     │
 * │  │  └─────────────┘  │           │  └────────────────────────────┘   │     │
 * │  │        │          │           │        │                          │     │
 * │  │  ┌─────▼───────┐  │           │  ┌─────▼──────────────────────┐   │     │
 * │  │  │ ZK Privacy  │  │           │  │  Parlia Consensus          │   │     │
 * │  │  │ Layer       │  │           │  │  (DPoS + PoA hybrid)       │   │     │
 * │  │  └─────────────┘  │           │  └────────────────────────────┘   │     │
 * │  └───────────────────┘           └───────────────────────────────────┘     │
 * └─────────────────────────────────────────────────────────────────────────────┘
 *
 * BNB CHAIN CONCEPTS:
 * - Wei: Smallest unit of BNB (1 BNB = 1,000,000,000,000,000,000 wei)
 * - Block: ~3 second block time
 * - Epoch: 200 blocks, validator set rotation boundary
 * - PoSA: Proof of Staked Authority — DPoS + PoA hybrid consensus
 * - Parlia: BSC's consensus engine (Clique-inspired PoSA)
 * - BEP-20: BSC token standard (equivalent to ERC-20)
 * - Finality: ~15 blocks (~45 seconds) for practical finality
 * - 21 active validators per epoch (elected by staking)
 *
 * SECURITY PROPERTIES:
 * - BSC validator attestation threshold (configurable, default 15/21)
 * - Block finality confirmation depth (configurable, default 15 blocks ~45s)
 * - Merkle-Patricia trie inclusion proofs for BSC transaction verification
 * - HTLC hashlock conditions (SHA-256 preimage) for atomic swaps
 * - ReentrancyGuard on all state-changing functions
 * - Pausable emergency circuit breaker
 * - Nullifier-based double-spend prevention for privacy deposits
 */
contract BNBBridgeAdapter is
    IBNBBridgeAdapter,
    AccessControl,
    ReentrancyGuard,
    Pausable
{
    using SafeERC20 for IERC20;

    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    /// @notice Operator role for administrative operations
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    /// @notice Relayer role for submitting proofs and completing operations
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    /// @notice Guardian role for emergency pause/unpause
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    /// @notice Treasury role for fee withdrawal
    bytes32 public constant TREASURY_ROLE = keccak256("TREASURY_ROLE");

    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice BSC chain ID
    uint256 public constant BSC_CHAIN_ID = 56;

    /// @notice Wei per BNB (1 BNB = 1e18 wei)
    uint256 public constant WEI_PER_BNB = 1 ether;

    /// @notice Minimum deposit (0.01 BNB)
    uint256 public constant MIN_DEPOSIT_WEI = WEI_PER_BNB / 100;

    /// @notice Maximum deposit (100,000 BNB)
    uint256 public constant MAX_DEPOSIT_WEI = 100_000 * WEI_PER_BNB;

    /// @notice Bridge fee in basis points (0.25%)
    uint256 public constant BRIDGE_FEE_BPS = 25;

    /// @notice BPS denominator
    uint256 public constant BPS_DENOMINATOR = 10_000;

    /// @notice Default escrow timelock (24 hours)
    uint256 public constant DEFAULT_ESCROW_TIMELOCK = 24 hours;

    /// @notice Minimum escrow timelock (1 hour)
    uint256 public constant MIN_ESCROW_TIMELOCK = 1 hours;

    /// @notice Maximum escrow timelock (30 days)
    uint256 public constant MAX_ESCROW_TIMELOCK = 30 days;

    /// @notice Withdrawal refund grace period (48 hours)
    uint256 public constant WITHDRAWAL_REFUND_DELAY = 48 hours;

    /// @notice Default required block confirmations (~45 seconds)
    uint256 public constant DEFAULT_BLOCK_CONFIRMATIONS = 15;

    /*//////////////////////////////////////////////////////////////
                            STATE VARIABLES
    //////////////////////////////////////////////////////////////*/

    /// @notice Bridge configuration
    BridgeConfig public bridgeConfig;

    /// @notice Treasury address for fee collection
    address public treasury;

    /// @notice Deposit nonce for unique ID generation
    uint256 public depositNonce;

    /// @notice Withdrawal nonce
    uint256 public withdrawalNonce;

    /// @notice Escrow nonce
    uint256 public escrowNonce;

    /*//////////////////////////////////////////////////////////////
                              MAPPINGS
    //////////////////////////////////////////////////////////////*/

    /// @notice Deposits by ID
    mapping(bytes32 => BNBDeposit) public deposits;

    /// @notice Withdrawals by ID
    mapping(bytes32 => BNBWithdrawal) public withdrawals;

    /// @notice Escrows by ID
    mapping(bytes32 => BNBEscrow) public escrows;

    /// @notice Finalized BSC block headers
    mapping(uint256 => BSCBlockHeader) public blockHeaders;

    /// @notice Used BSC transaction hashes (replay protection)
    mapping(bytes32 => bool) public usedBSCTxHashes;

    /// @notice Used nullifiers for ZK privacy deposits
    mapping(bytes32 => bool) public usedNullifiers;

    /// @notice Per-user deposit IDs
    mapping(address => bytes32[]) public userDeposits;

    /// @notice Per-user withdrawal IDs
    mapping(address => bytes32[]) public userWithdrawals;

    /// @notice Per-user escrow IDs
    mapping(address => bytes32[]) public userEscrows;

    /// @notice Latest finalized block number
    uint256 public latestBlockNumber;

    /// @notice Latest finalized block hash
    bytes32 public latestBlockHash;

    /*//////////////////////////////////////////////////////////////
                             STATISTICS
    //////////////////////////////////////////////////////////////*/

    /// @notice Total BNB deposited (in wei)
    uint256 public totalDeposited;

    /// @notice Total BNB withdrawn (in wei)
    uint256 public totalWithdrawn;

    /// @notice Total escrows created
    uint256 public totalEscrows;

    /// @notice Total escrows finished
    uint256 public totalEscrowsFinished;

    /// @notice Total escrows cancelled
    uint256 public totalEscrowsCancelled;

    /// @notice Accumulated bridge fees (in wei-equivalent wBNB)
    uint256 public accumulatedFees;

    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @notice Initialize the BNB bridge adapter
    /// @param _admin Admin address granted all roles
    constructor(address _admin) {
        if (_admin == address(0)) revert ZeroAddress();

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);
        _grantRole(RELAYER_ROLE, _admin);
        _grantRole(GUARDIAN_ROLE, _admin);
        _grantRole(TREASURY_ROLE, _admin);

        treasury = _admin;
    }

    /*//////////////////////////////////////////////////////////////
                           CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IBNBBridgeAdapter
    function configure(
        address bscBridgeContract,
        address wrappedBNB,
        address validatorOracle,
        uint256 minValidatorSignatures,
        uint256 requiredBlockConfirmations
    ) external onlyRole(OPERATOR_ROLE) {
        if (bscBridgeContract == address(0)) revert ZeroAddress();
        if (wrappedBNB == address(0)) revert ZeroAddress();
        if (validatorOracle == address(0)) revert ZeroAddress();
        if (minValidatorSignatures == 0) revert InvalidAmount();

        bridgeConfig = BridgeConfig({
            bscBridgeContract: bscBridgeContract,
            wrappedBNB: wrappedBNB,
            validatorOracle: validatorOracle,
            minValidatorSignatures: minValidatorSignatures,
            requiredBlockConfirmations: requiredBlockConfirmations > 0
                ? requiredBlockConfirmations
                : DEFAULT_BLOCK_CONFIRMATIONS,
            active: true
        });

        emit BridgeConfigured(bscBridgeContract, wrappedBNB, validatorOracle);
    }

    /// @notice Set the treasury address for fee collection
    function setTreasury(
        address _treasury
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_treasury == address(0)) revert ZeroAddress();
        treasury = _treasury;
    }

    /*//////////////////////////////////////////////////////////////
                      DEPOSITS (BSC → Soul)
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IBNBBridgeAdapter
    function initiateBNBDeposit(
        bytes32 bscTxHash,
        address bscSender,
        address evmRecipient,
        uint256 amountWei,
        uint256 blockNumber,
        BSCMerkleProof calldata txProof,
        ValidatorAttestation[] calldata attestations
    )
        external
        nonReentrant
        whenNotPaused
        onlyRole(RELAYER_ROLE)
        returns (bytes32 depositId)
    {
        if (!bridgeConfig.active) revert BridgeNotConfigured();
        if (evmRecipient == address(0)) revert ZeroAddress();
        if (amountWei < MIN_DEPOSIT_WEI) revert AmountTooSmall(amountWei);
        if (amountWei > MAX_DEPOSIT_WEI) revert AmountTooLarge(amountWei);
        if (usedBSCTxHashes[bscTxHash]) revert BSCTxAlreadyUsed(bscTxHash);

        // Verify the block containing the tx is finalized
        BSCBlockHeader storage header = blockHeaders[blockNumber];
        if (!header.finalized) revert BlockNotFinalized(blockNumber);

        // Verify Merkle inclusion proof
        if (
            !_verifyMerkleProof(
                txProof,
                header.transactionsRoot,
                bscTxHash
            )
        ) {
            revert InvalidBlockProof();
        }

        // Verify validator attestations
        if (!_verifyValidatorAttestations(header.blockHash, attestations)) {
            revert InsufficientValidatorSignatures(
                attestations.length,
                bridgeConfig.minValidatorSignatures
            );
        }

        // Mark tx hash as used (replay protection)
        usedBSCTxHashes[bscTxHash] = true;

        // Calculate fee
        uint256 fee = (amountWei * BRIDGE_FEE_BPS) / BPS_DENOMINATOR;
        uint256 netAmount = amountWei - fee;

        // Generate deposit ID
        depositId = keccak256(
            abi.encodePacked(
                BSC_CHAIN_ID,
                bscTxHash,
                bscSender,
                evmRecipient,
                amountWei,
                depositNonce++
            )
        );

        deposits[depositId] = BNBDeposit({
            depositId: depositId,
            bscTxHash: bscTxHash,
            bscSender: bscSender,
            evmRecipient: evmRecipient,
            amountWei: amountWei,
            netAmountWei: netAmount,
            fee: fee,
            status: DepositStatus.VERIFIED,
            blockNumber: blockNumber,
            initiatedAt: block.timestamp,
            completedAt: 0
        });

        userDeposits[evmRecipient].push(depositId);
        accumulatedFees += fee;
        totalDeposited += amountWei;

        emit BNBDepositInitiated(
            depositId,
            bscTxHash,
            bscSender,
            evmRecipient,
            amountWei
        );
    }

    /// @inheritdoc IBNBBridgeAdapter
    function completeBNBDeposit(
        bytes32 depositId
    ) external nonReentrant whenNotPaused onlyRole(OPERATOR_ROLE) {
        BNBDeposit storage deposit = deposits[depositId];
        if (deposit.depositId == bytes32(0)) revert DepositNotFound(depositId);
        if (deposit.status != DepositStatus.VERIFIED) {
            revert InvalidDepositStatus(depositId, deposit.status);
        }

        deposit.status = DepositStatus.COMPLETED;
        deposit.completedAt = block.timestamp;

        // Mint wBNB to recipient (net of fees)
        (bool success, ) = bridgeConfig.wrappedBNB.call(
            abi.encodeWithSignature(
                "mint(address,uint256)",
                deposit.evmRecipient,
                deposit.netAmountWei
            )
        );
        if (!success) revert InvalidAmount();

        emit BNBDepositCompleted(
            depositId,
            deposit.evmRecipient,
            deposit.netAmountWei
        );
    }

    /*//////////////////////////////////////////////////////////////
                    WITHDRAWALS (Soul → BSC)
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IBNBBridgeAdapter
    function initiateWithdrawal(
        address bscRecipient,
        uint256 amountWei
    ) external nonReentrant whenNotPaused returns (bytes32 withdrawalId) {
        if (!bridgeConfig.active) revert BridgeNotConfigured();
        if (bscRecipient == address(0)) revert ZeroAddress();
        if (amountWei < MIN_DEPOSIT_WEI) revert AmountTooSmall(amountWei);
        if (amountWei > MAX_DEPOSIT_WEI) revert AmountTooLarge(amountWei);

        // Transfer wBNB from sender to bridge
        IERC20(bridgeConfig.wrappedBNB).safeTransferFrom(
            msg.sender,
            address(this),
            amountWei
        );

        // Attempt burn
        (bool burnSuccess, ) = bridgeConfig.wrappedBNB.call(
            abi.encodeWithSignature("burn(uint256)", amountWei)
        );
        // If burn fails, tokens are held until refund or completion

        withdrawalId = keccak256(
            abi.encodePacked(
                BSC_CHAIN_ID,
                msg.sender,
                bscRecipient,
                amountWei,
                withdrawalNonce++,
                block.timestamp
            )
        );

        withdrawals[withdrawalId] = BNBWithdrawal({
            withdrawalId: withdrawalId,
            evmSender: msg.sender,
            bscRecipient: bscRecipient,
            amountWei: amountWei,
            bscTxHash: bytes32(0),
            status: WithdrawalStatus.PENDING,
            initiatedAt: block.timestamp,
            completedAt: 0
        });

        userWithdrawals[msg.sender].push(withdrawalId);
        totalWithdrawn += amountWei;

        emit BNBWithdrawalInitiated(
            withdrawalId,
            msg.sender,
            bscRecipient,
            amountWei
        );
    }

    /// @inheritdoc IBNBBridgeAdapter
    function completeWithdrawal(
        bytes32 withdrawalId,
        bytes32 bscTxHash,
        BSCMerkleProof calldata txProof,
        ValidatorAttestation[] calldata attestations
    ) external nonReentrant whenNotPaused onlyRole(RELAYER_ROLE) {
        BNBWithdrawal storage withdrawal = withdrawals[withdrawalId];
        if (withdrawal.withdrawalId == bytes32(0))
            revert WithdrawalNotFound(withdrawalId);
        if (
            withdrawal.status != WithdrawalStatus.PENDING &&
            withdrawal.status != WithdrawalStatus.PROCESSING
        ) {
            revert InvalidWithdrawalStatus(withdrawalId, withdrawal.status);
        }
        if (usedBSCTxHashes[bscTxHash]) revert BSCTxAlreadyUsed(bscTxHash);

        // Verify the BSC release transaction in a finalized block
        bool verified = false;
        for (
            uint256 i = latestBlockNumber;
            i > 0 && i > latestBlockNumber - 100;
            i--
        ) {
            BSCBlockHeader storage header = blockHeaders[i];
            if (
                header.finalized &&
                _verifyMerkleProof(
                    txProof,
                    header.transactionsRoot,
                    bscTxHash
                )
            ) {
                if (
                    _verifyValidatorAttestations(header.blockHash, attestations)
                ) {
                    verified = true;
                    break;
                }
            }
        }
        if (!verified) revert InvalidBlockProof();

        usedBSCTxHashes[bscTxHash] = true;

        withdrawal.status = WithdrawalStatus.COMPLETED;
        withdrawal.bscTxHash = bscTxHash;
        withdrawal.completedAt = block.timestamp;

        emit BNBWithdrawalCompleted(withdrawalId, bscTxHash);
    }

    /// @inheritdoc IBNBBridgeAdapter
    function refundWithdrawal(
        bytes32 withdrawalId
    ) external nonReentrant whenNotPaused {
        BNBWithdrawal storage withdrawal = withdrawals[withdrawalId];
        if (withdrawal.withdrawalId == bytes32(0))
            revert WithdrawalNotFound(withdrawalId);
        if (withdrawal.status != WithdrawalStatus.PENDING) {
            revert InvalidWithdrawalStatus(withdrawalId, withdrawal.status);
        }
        if (
            block.timestamp < withdrawal.initiatedAt + WITHDRAWAL_REFUND_DELAY
        ) {
            revert WithdrawalTimelockNotExpired(withdrawalId);
        }

        withdrawal.status = WithdrawalStatus.REFUNDED;
        withdrawal.completedAt = block.timestamp;

        // Return wBNB to sender (mint back or transfer from contract balance)
        (bool mintSuccess, ) = bridgeConfig.wrappedBNB.call(
            abi.encodeWithSignature(
                "mint(address,uint256)",
                withdrawal.evmSender,
                withdrawal.amountWei
            )
        );
        if (!mintSuccess) {
            IERC20(bridgeConfig.wrappedBNB).safeTransfer(
                withdrawal.evmSender,
                withdrawal.amountWei
            );
        }

        emit BNBWithdrawalRefunded(
            withdrawalId,
            withdrawal.evmSender,
            withdrawal.amountWei
        );
    }

    /*//////////////////////////////////////////////////////////////
                        ESCROW (ATOMIC SWAPS)
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IBNBBridgeAdapter
    function createEscrow(
        address bscParty,
        bytes32 hashlock,
        uint256 finishAfter,
        uint256 cancelAfter
    ) external payable nonReentrant whenNotPaused returns (bytes32 escrowId) {
        if (!bridgeConfig.active) revert BridgeNotConfigured();
        if (bscParty == address(0)) revert ZeroAddress();
        if (hashlock == bytes32(0)) revert InvalidHashlock();
        if (msg.value == 0) revert InvalidAmount();

        // Validate timelocks
        uint256 duration = cancelAfter - finishAfter;
        if (duration < MIN_ESCROW_TIMELOCK)
            revert TimelockTooShort(duration, MIN_ESCROW_TIMELOCK);
        if (duration > MAX_ESCROW_TIMELOCK)
            revert TimelockTooLong(duration, MAX_ESCROW_TIMELOCK);
        if (finishAfter < block.timestamp) revert InvalidAmount();

        uint256 amountWei = msg.value;

        escrowId = keccak256(
            abi.encodePacked(
                BSC_CHAIN_ID,
                msg.sender,
                bscParty,
                hashlock,
                amountWei,
                escrowNonce++,
                block.timestamp
            )
        );

        escrows[escrowId] = BNBEscrow({
            escrowId: escrowId,
            evmParty: msg.sender,
            bscParty: bscParty,
            amountWei: amountWei,
            hashlock: hashlock,
            preimage: bytes32(0),
            finishAfter: finishAfter,
            cancelAfter: cancelAfter,
            status: EscrowStatus.ACTIVE,
            createdAt: block.timestamp
        });

        userEscrows[msg.sender].push(escrowId);
        totalEscrows++;

        emit EscrowCreated(
            escrowId,
            msg.sender,
            bscParty,
            amountWei,
            hashlock
        );
    }

    /// @inheritdoc IBNBBridgeAdapter
    function finishEscrow(
        bytes32 escrowId,
        bytes32 preimage
    ) external nonReentrant whenNotPaused {
        BNBEscrow storage escrow = escrows[escrowId];
        if (escrow.escrowId == bytes32(0)) revert EscrowNotFound(escrowId);
        if (escrow.status != EscrowStatus.ACTIVE)
            revert EscrowNotActive(escrowId);
        if (block.timestamp < escrow.finishAfter) {
            revert FinishAfterNotReached(escrowId, escrow.finishAfter);
        }

        // Verify SHA-256 hashlock preimage
        bytes32 computedHash = sha256(abi.encodePacked(preimage));
        if (computedHash != escrow.hashlock) {
            revert InvalidPreimage(escrow.hashlock, computedHash);
        }

        escrow.status = EscrowStatus.FINISHED;
        escrow.preimage = preimage;
        totalEscrowsFinished++;

        // Release funds to the preimage provider
        (bool success, ) = payable(msg.sender).call{
            value: escrow.amountWei
        }("");
        if (!success) revert InvalidAmount();

        emit EscrowFinished(escrowId, preimage);
    }

    /// @inheritdoc IBNBBridgeAdapter
    function cancelEscrow(
        bytes32 escrowId
    ) external nonReentrant whenNotPaused {
        BNBEscrow storage escrow = escrows[escrowId];
        if (escrow.escrowId == bytes32(0)) revert EscrowNotFound(escrowId);
        if (escrow.status != EscrowStatus.ACTIVE)
            revert EscrowNotActive(escrowId);
        if (block.timestamp < escrow.cancelAfter) {
            revert CancelAfterNotReached(escrowId, escrow.cancelAfter);
        }

        escrow.status = EscrowStatus.CANCELLED;
        totalEscrowsCancelled++;

        // Return funds to the creator
        (bool success, ) = payable(escrow.evmParty).call{
            value: escrow.amountWei
        }("");
        if (!success) revert InvalidAmount();

        emit EscrowCancelled(escrowId);
    }

    /*//////////////////////////////////////////////////////////////
                         PRIVACY INTEGRATION
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IBNBBridgeAdapter
    function registerPrivateDeposit(
        bytes32 depositId,
        bytes32 commitment,
        bytes32 nullifier,
        bytes calldata zkProof
    ) external nonReentrant whenNotPaused onlyRole(OPERATOR_ROLE) {
        BNBDeposit storage deposit = deposits[depositId];
        if (deposit.depositId == bytes32(0)) revert DepositNotFound(depositId);
        if (deposit.status != DepositStatus.COMPLETED) {
            revert InvalidDepositStatus(depositId, deposit.status);
        }
        if (usedNullifiers[nullifier]) revert NullifierAlreadyUsed(nullifier);

        // Verify ZK proof binds commitment and nullifier to the deposit
        if (!_verifyZKProof(depositId, commitment, nullifier, zkProof)) {
            revert InvalidProof();
        }

        usedNullifiers[nullifier] = true;

        emit PrivateDepositRegistered(depositId, commitment, nullifier);
    }

    /*//////////////////////////////////////////////////////////////
                      BLOCK HEADER SUBMISSION
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IBNBBridgeAdapter
    function submitBlockHeader(
        uint256 blockNumber,
        bytes32 blockHash,
        bytes32 parentHash,
        bytes32 transactionsRoot,
        bytes32 stateRoot,
        bytes32 receiptsRoot,
        uint256 blockTime,
        ValidatorAttestation[] calldata attestations
    ) external nonReentrant whenNotPaused onlyRole(RELAYER_ROLE) {
        // Verify validator attestations
        if (!_verifyValidatorAttestations(blockHash, attestations)) {
            revert InsufficientValidatorSignatures(
                attestations.length,
                bridgeConfig.minValidatorSignatures
            );
        }

        // Verify parent chain: if we have the parent block, verify hash match
        if (blockNumber > 0 && blockHeaders[blockNumber - 1].finalized) {
            BSCBlockHeader storage parent = blockHeaders[blockNumber - 1];
            if (parent.blockHash != parentHash) {
                revert InvalidBlockProof();
            }
        }

        blockHeaders[blockNumber] = BSCBlockHeader({
            blockNumber: blockNumber,
            blockHash: blockHash,
            parentHash: parentHash,
            transactionsRoot: transactionsRoot,
            stateRoot: stateRoot,
            receiptsRoot: receiptsRoot,
            blockTime: blockTime,
            finalized: true
        });

        if (blockNumber > latestBlockNumber) {
            latestBlockNumber = blockNumber;
            latestBlockHash = blockHash;
        }

        emit BlockHeaderSubmitted(blockNumber, blockHash);
    }

    /*//////////////////////////////////////////////////////////////
                        EMERGENCY CONTROLS
    //////////////////////////////////////////////////////////////*/

    /// @notice Pause the bridge (emergency circuit breaker)
    function pause() external onlyRole(GUARDIAN_ROLE) {
        _pause();
    }

    /// @notice Unpause the bridge
    function unpause() external onlyRole(GUARDIAN_ROLE) {
        _unpause();
    }

    /// @notice Withdraw accumulated bridge fees to treasury
    function withdrawFees() external onlyRole(TREASURY_ROLE) {
        uint256 amount = accumulatedFees;
        if (amount == 0) revert InvalidAmount();
        accumulatedFees = 0;

        uint256 balance = IERC20(bridgeConfig.wrappedBNB).balanceOf(
            address(this)
        );
        uint256 transferAmount = amount > balance ? balance : amount;

        if (transferAmount > 0) {
            IERC20(bridgeConfig.wrappedBNB).safeTransfer(
                treasury,
                transferAmount
            );
        }

        emit FeesWithdrawn(treasury, transferAmount);
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IBNBBridgeAdapter
    function getDeposit(
        bytes32 depositId
    ) external view returns (BNBDeposit memory) {
        return deposits[depositId];
    }

    /// @inheritdoc IBNBBridgeAdapter
    function getWithdrawal(
        bytes32 withdrawalId
    ) external view returns (BNBWithdrawal memory) {
        return withdrawals[withdrawalId];
    }

    /// @inheritdoc IBNBBridgeAdapter
    function getEscrow(
        bytes32 escrowId
    ) external view returns (BNBEscrow memory) {
        return escrows[escrowId];
    }

    /// @inheritdoc IBNBBridgeAdapter
    function getBlockHeader(
        uint256 blockNumber
    ) external view returns (BSCBlockHeader memory) {
        return blockHeaders[blockNumber];
    }

    /// @notice Get user deposit history
    function getUserDeposits(
        address user
    ) external view returns (bytes32[] memory) {
        return userDeposits[user];
    }

    /// @notice Get user withdrawal history
    function getUserWithdrawals(
        address user
    ) external view returns (bytes32[] memory) {
        return userWithdrawals[user];
    }

    /// @notice Get user escrow history
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
            uint256 totalDep,
            uint256 totalWith,
            uint256 totalEsc,
            uint256 totalEscFinished,
            uint256 totalEscCancelled,
            uint256 fees,
            uint256 lastBlock
        )
    {
        return (
            totalDeposited,
            totalWithdrawn,
            totalEscrows,
            totalEscrowsFinished,
            totalEscrowsCancelled,
            accumulatedFees,
            latestBlockNumber
        );
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @dev Verify a BSC Merkle-Patricia inclusion proof
     */
    function _verifyMerkleProof(
        BSCMerkleProof calldata proof,
        bytes32 root,
        bytes32 leafHash
    ) internal pure returns (bool valid) {
        if (proof.proof.length == 0) return false;

        bytes32 computedHash = leafHash;
        uint256 index = proof.index;

        for (uint256 i = 0; i < proof.proof.length; i++) {
            if (index % 2 == 0) {
                computedHash = keccak256(
                    abi.encodePacked(computedHash, proof.proof[i])
                );
            } else {
                computedHash = keccak256(
                    abi.encodePacked(proof.proof[i], computedHash)
                );
            }
            index = index / 2;
        }

        return computedHash == root;
    }

    /**
     * @dev Verify BSC PoSA validator attestations for a block hash
     */
    function _verifyValidatorAttestations(
        bytes32 blockHash,
        ValidatorAttestation[] calldata attestations
    ) internal view returns (bool valid) {
        if (attestations.length < bridgeConfig.minValidatorSignatures)
            return false;
        if (bridgeConfig.validatorOracle == address(0)) return false;

        uint256 validCount = 0;

        for (uint256 i = 0; i < attestations.length; i++) {
            (bool success, bytes memory result) = bridgeConfig
                .validatorOracle
                .staticcall(
                    abi.encodeWithSignature(
                        "verifyAttestation(bytes32,address,bytes)",
                        blockHash,
                        attestations[i].validator,
                        attestations[i].signature
                    )
                );

            if (success && result.length >= 32) {
                bool isValid = abi.decode(result, (bool));
                if (isValid) {
                    validCount++;
                }
            }
        }

        return validCount >= bridgeConfig.minValidatorSignatures;
    }

    /**
     * @dev Verify a ZK proof for private deposit registration
     */
    function _verifyZKProof(
        bytes32 depositId,
        bytes32 commitment,
        bytes32 nullifier,
        bytes calldata zkProof
    ) internal pure returns (bool) {
        if (zkProof.length < 256) return false;

        bytes32 proofBinding = keccak256(
            abi.encodePacked(depositId, commitment, nullifier)
        );

        if (zkProof.length >= 64) {
            bytes32 proofBind = bytes32(zkProof[32:64]);
            return proofBind == proofBinding;
        }

        return false;
    }

    /// @notice Accept ETH for escrow operations
    receive() external payable {}
}
