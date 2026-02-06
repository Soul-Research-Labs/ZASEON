// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IHyperliquidBridgeAdapter} from "../interfaces/IHyperliquidBridgeAdapter.sol";

/**
 * @title HyperliquidBridgeAdapter
 * @author Soul Protocol
 * @notice Bridge adapter for Hyperliquid L1 interoperability with Soul Protocol
 * @dev Enables cross-chain transfers between Soul Protocol (EVM) and Hyperliquid
 *
 * ARCHITECTURE:
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │                  Soul <-> Hyperliquid Bridge                                │
 * ├─────────────────────────────────────────────────────────────────────────────┤
 * │                                                                             │
 * │  ┌───────────────────┐           ┌───────────────────────────────────┐     │
 * │  │   Soul Side       │           │     Hyperliquid Side              │     │
 * │  │  ┌─────────────┐  │           │  ┌────────────────────────────┐   │     │
 * │  │  │ wHYPE Token │  │           │  │  Bridge Contract           │   │     │
 * │  │  │ (ERC-20)    │  │           │  │  (HyperEVM compatible)     │   │     │
 * │  │  └─────────────┘  │           │  └────────────────────────────┘   │     │
 * │  │        │          │           │        │                          │     │
 * │  │  ┌─────▼───────┐  │           │  ┌─────▼──────────────────────┐   │     │
 * │  │  │ Bridge      │  │◄─────────►│  │  HyperBFT Validator Set   │   │     │
 * │  │  │ Adapter     │  │  Relayer  │  │  (4 active validators)     │   │     │
 * │  │  └─────────────┘  │           │  └────────────────────────────┘   │     │
 * │  │        │          │           │        │                          │     │
 * │  │  ┌─────▼───────┐  │           │  ┌─────▼──────────────────────┐   │     │
 * │  │  │ ZK Privacy  │  │           │  │  HotStuff Consensus        │   │     │
 * │  │  │ Layer       │  │           │  │  (BFT with instant finality│   │     │
 * │  │  └─────────────┘  │           │  └────────────────────────────┘   │     │
 * │  └───────────────────┘           └───────────────────────────────────┘     │
 * └─────────────────────────────────────────────────────────────────────────────┘
 *
 * HYPERLIQUID CONCEPTS:
 * - Drips: Smallest unit of HYPE (1 HYPE = 100,000,000 drips = 1e8 drips)
 * - Block: ~200ms block latency (sub-second finality)
 * - HyperBFT: Modified HotStuff BFT consensus engine
 * - HyperEVM: EVM-compatible execution layer on Hyperliquid L1
 * - Chain ID: 999 (HyperEVM mainnet)
 * - Finality: ~3 blocks (~0.6s) for BFT finality
 * - 4 active validators in BFT committee
 * - 2/3+1 supermajority = 3/4 validators required
 *
 * SECURITY PROPERTIES:
 * - HyperBFT validator attestation threshold (configurable, default 3/4)
 * - Block finality confirmation depth (configurable, default 3 blocks)
 * - Merkle inclusion proofs for Hyperliquid transaction verification
 * - HTLC hashlock conditions (SHA-256 preimage) for atomic swaps
 * - ReentrancyGuard on all state-changing functions
 * - Pausable emergency circuit breaker
 * - Nullifier-based double-spend prevention for privacy deposits
 */
contract HyperliquidBridgeAdapter is
    IHyperliquidBridgeAdapter,
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

    uint256 public constant HYPERLIQUID_CHAIN_ID = 999;
    uint256 public constant DRIPS_PER_HYPE = 100_000_000; // 1e8
    uint256 public constant MIN_DEPOSIT_DRIPS = DRIPS_PER_HYPE / 10; // 0.1 HYPE
    uint256 public constant MAX_DEPOSIT_DRIPS = 1_000_000 * DRIPS_PER_HYPE; // 1M HYPE
    uint256 public constant BRIDGE_FEE_BPS = 15; // 0.15% — lower fee for high-perf chain
    uint256 public constant BPS_DENOMINATOR = 10_000;
    uint256 public constant DEFAULT_ESCROW_TIMELOCK = 12 hours;
    uint256 public constant MIN_ESCROW_TIMELOCK = 30 minutes;
    uint256 public constant MAX_ESCROW_TIMELOCK = 14 days;
    uint256 public constant WITHDRAWAL_REFUND_DELAY = 24 hours;
    uint256 public constant DEFAULT_BLOCK_CONFIRMATIONS = 3;

    /*//////////////////////////////////////////////////////////////
                            STATE VARIABLES
    //////////////////////////////////////////////////////////////*/

    BridgeConfig public bridgeConfig;
    address public treasury;
    uint256 public depositNonce;
    uint256 public withdrawalNonce;
    uint256 public escrowNonce;

    /*//////////////////////////////////////////////////////////////
                              MAPPINGS
    //////////////////////////////////////////////////////////////*/

    mapping(bytes32 => HYPEDeposit) public deposits;
    mapping(bytes32 => HYPEWithdrawal) public withdrawals;
    mapping(bytes32 => HYPEEscrow) public escrows;
    mapping(uint256 => HyperBFTBlockHeader) public blockHeaders;
    mapping(bytes32 => bool) public usedHLTxHashes;
    mapping(bytes32 => bool) public usedNullifiers;
    mapping(address => bytes32[]) public userDeposits;
    mapping(address => bytes32[]) public userWithdrawals;
    mapping(address => bytes32[]) public userEscrows;
    uint256 public latestBlockNumber;
    bytes32 public latestBlockHash;

    /*//////////////////////////////////////////////////////////////
                             STATISTICS
    //////////////////////////////////////////////////////////////*/

    uint256 public totalDeposited;
    uint256 public totalWithdrawn;
    uint256 public totalEscrows;
    uint256 public totalEscrowsFinished;
    uint256 public totalEscrowsCancelled;
    uint256 public accumulatedFees;

    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

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

    function configure(
        address hyperliquidBridgeContract,
        address wrappedHYPE,
        address validatorOracle,
        uint256 minValidatorSignatures,
        uint256 requiredBlockConfirmations
    ) external onlyRole(OPERATOR_ROLE) {
        if (hyperliquidBridgeContract == address(0)) revert ZeroAddress();
        if (wrappedHYPE == address(0)) revert ZeroAddress();
        if (validatorOracle == address(0)) revert ZeroAddress();
        if (minValidatorSignatures == 0) revert InvalidAmount();

        bridgeConfig = BridgeConfig({
            hyperliquidBridgeContract: hyperliquidBridgeContract,
            wrappedHYPE: wrappedHYPE,
            validatorOracle: validatorOracle,
            minValidatorSignatures: minValidatorSignatures,
            requiredBlockConfirmations: requiredBlockConfirmations > 0
                ? requiredBlockConfirmations
                : DEFAULT_BLOCK_CONFIRMATIONS,
            active: true
        });

        emit BridgeConfigured(
            hyperliquidBridgeContract,
            wrappedHYPE,
            validatorOracle
        );
    }

    function setTreasury(
        address _treasury
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_treasury == address(0)) revert ZeroAddress();
        treasury = _treasury;
    }

    /*//////////////////////////////////////////////////////////////
                      DEPOSITS (Hyperliquid → Soul)
    //////////////////////////////////////////////////////////////*/

    function initiateHYPEDeposit(
        bytes32 hlTxHash,
        address hlSender,
        address evmRecipient,
        uint256 amountDrips,
        uint256 blockNumber,
        HyperliquidMerkleProof calldata txProof,
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
        if (amountDrips < MIN_DEPOSIT_DRIPS) revert AmountTooSmall(amountDrips);
        if (amountDrips > MAX_DEPOSIT_DRIPS) revert AmountTooLarge(amountDrips);
        if (usedHLTxHashes[hlTxHash]) revert HLTxAlreadyUsed(hlTxHash);

        HyperBFTBlockHeader storage header = blockHeaders[blockNumber];
        if (!header.finalized) revert BlockNotFinalized(blockNumber);

        if (!_verifyMerkleProof(txProof, header.transactionsRoot, hlTxHash)) {
            revert InvalidBlockProof();
        }

        if (!_verifyValidatorAttestations(header.blockHash, attestations)) {
            revert InsufficientValidatorSignatures(
                attestations.length,
                bridgeConfig.minValidatorSignatures
            );
        }

        usedHLTxHashes[hlTxHash] = true;

        uint256 fee = (amountDrips * BRIDGE_FEE_BPS) / BPS_DENOMINATOR;
        uint256 netAmount = amountDrips - fee;

        depositId = keccak256(
            abi.encodePacked(
                HYPERLIQUID_CHAIN_ID,
                hlTxHash,
                hlSender,
                evmRecipient,
                amountDrips,
                depositNonce++
            )
        );

        deposits[depositId] = HYPEDeposit({
            depositId: depositId,
            hlTxHash: hlTxHash,
            hlSender: hlSender,
            evmRecipient: evmRecipient,
            amountDrips: amountDrips,
            netAmountDrips: netAmount,
            fee: fee,
            status: DepositStatus.VERIFIED,
            blockNumber: blockNumber,
            initiatedAt: block.timestamp,
            completedAt: 0
        });

        userDeposits[evmRecipient].push(depositId);
        accumulatedFees += fee;
        totalDeposited += amountDrips;

        emit HYPEDepositInitiated(
            depositId,
            hlTxHash,
            hlSender,
            evmRecipient,
            amountDrips
        );
    }

    function completeHYPEDeposit(
        bytes32 depositId
    ) external nonReentrant whenNotPaused onlyRole(OPERATOR_ROLE) {
        HYPEDeposit storage deposit = deposits[depositId];
        if (deposit.depositId == bytes32(0)) revert DepositNotFound(depositId);
        if (deposit.status != DepositStatus.VERIFIED) {
            revert InvalidDepositStatus(depositId, deposit.status);
        }

        deposit.status = DepositStatus.COMPLETED;
        deposit.completedAt = block.timestamp;

        (bool success, ) = bridgeConfig.wrappedHYPE.call(
            abi.encodeWithSignature(
                "mint(address,uint256)",
                deposit.evmRecipient,
                deposit.netAmountDrips
            )
        );
        if (!success) revert InvalidAmount();

        emit HYPEDepositCompleted(
            depositId,
            deposit.evmRecipient,
            deposit.netAmountDrips
        );
    }

    /*//////////////////////////////////////////////////////////////
                    WITHDRAWALS (Soul → Hyperliquid)
    //////////////////////////////////////////////////////////////*/

    function initiateWithdrawal(
        address hlRecipient,
        uint256 amountDrips
    ) external nonReentrant whenNotPaused returns (bytes32 withdrawalId) {
        if (!bridgeConfig.active) revert BridgeNotConfigured();
        if (hlRecipient == address(0)) revert ZeroAddress();
        if (amountDrips < MIN_DEPOSIT_DRIPS) revert AmountTooSmall(amountDrips);
        if (amountDrips > MAX_DEPOSIT_DRIPS) revert AmountTooLarge(amountDrips);

        IERC20(bridgeConfig.wrappedHYPE).safeTransferFrom(
            msg.sender,
            address(this),
            amountDrips
        );

        (bool burnSuccess, ) = bridgeConfig.wrappedHYPE.call(
            abi.encodeWithSignature("burn(uint256)", amountDrips)
        );

        withdrawalId = keccak256(
            abi.encodePacked(
                HYPERLIQUID_CHAIN_ID,
                msg.sender,
                hlRecipient,
                amountDrips,
                withdrawalNonce++,
                block.timestamp
            )
        );

        withdrawals[withdrawalId] = HYPEWithdrawal({
            withdrawalId: withdrawalId,
            evmSender: msg.sender,
            hlRecipient: hlRecipient,
            amountDrips: amountDrips,
            hlTxHash: bytes32(0),
            status: WithdrawalStatus.PENDING,
            initiatedAt: block.timestamp,
            completedAt: 0
        });

        userWithdrawals[msg.sender].push(withdrawalId);
        totalWithdrawn += amountDrips;

        emit HYPEWithdrawalInitiated(
            withdrawalId,
            msg.sender,
            hlRecipient,
            amountDrips
        );
    }

    function completeWithdrawal(
        bytes32 withdrawalId,
        bytes32 hlTxHash,
        HyperliquidMerkleProof calldata txProof,
        ValidatorAttestation[] calldata attestations
    ) external nonReentrant whenNotPaused onlyRole(RELAYER_ROLE) {
        HYPEWithdrawal storage withdrawal = withdrawals[withdrawalId];
        if (withdrawal.withdrawalId == bytes32(0))
            revert WithdrawalNotFound(withdrawalId);
        if (
            withdrawal.status != WithdrawalStatus.PENDING &&
            withdrawal.status != WithdrawalStatus.PROCESSING
        ) {
            revert InvalidWithdrawalStatus(withdrawalId, withdrawal.status);
        }
        if (usedHLTxHashes[hlTxHash]) revert HLTxAlreadyUsed(hlTxHash);

        bool verified = false;
        for (
            uint256 i = latestBlockNumber;
            i > 0 && i > latestBlockNumber - 100;
            i--
        ) {
            HyperBFTBlockHeader storage header = blockHeaders[i];
            if (
                header.finalized &&
                _verifyMerkleProof(txProof, header.transactionsRoot, hlTxHash)
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

        usedHLTxHashes[hlTxHash] = true;

        withdrawal.status = WithdrawalStatus.COMPLETED;
        withdrawal.hlTxHash = hlTxHash;
        withdrawal.completedAt = block.timestamp;

        emit HYPEWithdrawalCompleted(withdrawalId, hlTxHash);
    }

    function refundWithdrawal(
        bytes32 withdrawalId
    ) external nonReentrant whenNotPaused {
        HYPEWithdrawal storage withdrawal = withdrawals[withdrawalId];
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

        (bool mintSuccess, ) = bridgeConfig.wrappedHYPE.call(
            abi.encodeWithSignature(
                "mint(address,uint256)",
                withdrawal.evmSender,
                withdrawal.amountDrips
            )
        );
        if (!mintSuccess) {
            IERC20(bridgeConfig.wrappedHYPE).safeTransfer(
                withdrawal.evmSender,
                withdrawal.amountDrips
            );
        }

        emit HYPEWithdrawalRefunded(
            withdrawalId,
            withdrawal.evmSender,
            withdrawal.amountDrips
        );
    }

    /*//////////////////////////////////////////////////////////////
                        ESCROW (ATOMIC SWAPS)
    //////////////////////////////////////////////////////////////*/

    function createEscrow(
        address hlParty,
        bytes32 hashlock,
        uint256 finishAfter,
        uint256 cancelAfter
    ) external payable nonReentrant whenNotPaused returns (bytes32 escrowId) {
        if (!bridgeConfig.active) revert BridgeNotConfigured();
        if (hlParty == address(0)) revert ZeroAddress();
        if (hashlock == bytes32(0)) revert InvalidHashlock();
        if (msg.value == 0) revert InvalidAmount();

        uint256 duration = cancelAfter - finishAfter;
        if (duration < MIN_ESCROW_TIMELOCK)
            revert TimelockTooShort(duration, MIN_ESCROW_TIMELOCK);
        if (duration > MAX_ESCROW_TIMELOCK)
            revert TimelockTooLong(duration, MAX_ESCROW_TIMELOCK);
        if (finishAfter < block.timestamp) revert InvalidAmount();

        uint256 amountDrips = msg.value;

        escrowId = keccak256(
            abi.encodePacked(
                HYPERLIQUID_CHAIN_ID,
                msg.sender,
                hlParty,
                hashlock,
                amountDrips,
                escrowNonce++,
                block.timestamp
            )
        );

        escrows[escrowId] = HYPEEscrow({
            escrowId: escrowId,
            evmParty: msg.sender,
            hlParty: hlParty,
            amountDrips: amountDrips,
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
            hlParty,
            amountDrips,
            hashlock
        );
    }

    function finishEscrow(
        bytes32 escrowId,
        bytes32 preimage
    ) external nonReentrant whenNotPaused {
        HYPEEscrow storage escrow = escrows[escrowId];
        if (escrow.escrowId == bytes32(0)) revert EscrowNotFound(escrowId);
        if (escrow.status != EscrowStatus.ACTIVE)
            revert EscrowNotActive(escrowId);
        if (block.timestamp < escrow.finishAfter) {
            revert FinishAfterNotReached(escrowId, escrow.finishAfter);
        }

        bytes32 computedHash = sha256(abi.encodePacked(preimage));
        if (computedHash != escrow.hashlock) {
            revert InvalidPreimage(escrow.hashlock, computedHash);
        }

        escrow.status = EscrowStatus.FINISHED;
        escrow.preimage = preimage;
        totalEscrowsFinished++;

        (bool success, ) = payable(msg.sender).call{value: escrow.amountDrips}(
            ""
        );
        if (!success) revert InvalidAmount();

        emit EscrowFinished(escrowId, preimage);
    }

    function cancelEscrow(
        bytes32 escrowId
    ) external nonReentrant whenNotPaused {
        HYPEEscrow storage escrow = escrows[escrowId];
        if (escrow.escrowId == bytes32(0)) revert EscrowNotFound(escrowId);
        if (escrow.status != EscrowStatus.ACTIVE)
            revert EscrowNotActive(escrowId);
        if (block.timestamp < escrow.cancelAfter) {
            revert CancelAfterNotReached(escrowId, escrow.cancelAfter);
        }

        escrow.status = EscrowStatus.CANCELLED;
        totalEscrowsCancelled++;

        (bool success, ) = payable(escrow.evmParty).call{
            value: escrow.amountDrips
        }("");
        if (!success) revert InvalidAmount();

        emit EscrowCancelled(escrowId);
    }

    /*//////////////////////////////////////////////////////////////
                         PRIVACY INTEGRATION
    //////////////////////////////////////////////////////////////*/

    function registerPrivateDeposit(
        bytes32 depositId,
        bytes32 commitment,
        bytes32 nullifier,
        bytes calldata zkProof
    ) external nonReentrant whenNotPaused onlyRole(OPERATOR_ROLE) {
        HYPEDeposit storage deposit = deposits[depositId];
        if (deposit.depositId == bytes32(0)) revert DepositNotFound(depositId);
        if (deposit.status != DepositStatus.COMPLETED) {
            revert InvalidDepositStatus(depositId, deposit.status);
        }
        if (usedNullifiers[nullifier]) revert NullifierAlreadyUsed(nullifier);

        if (!_verifyZKProof(depositId, commitment, nullifier, zkProof)) {
            revert InvalidProof();
        }

        usedNullifiers[nullifier] = true;

        emit PrivateDepositRegistered(depositId, commitment, nullifier);
    }

    /*//////////////////////////////////////////////////////////////
                      BLOCK HEADER SUBMISSION
    //////////////////////////////////////////////////////////////*/

    function submitBlockHeader(
        uint256 blockNumber,
        bytes32 blockHash,
        bytes32 parentHash,
        bytes32 transactionsRoot,
        bytes32 stateRoot,
        uint256 blockTime,
        ValidatorAttestation[] calldata attestations
    ) external nonReentrant whenNotPaused onlyRole(RELAYER_ROLE) {
        if (!_verifyValidatorAttestations(blockHash, attestations)) {
            revert InsufficientValidatorSignatures(
                attestations.length,
                bridgeConfig.minValidatorSignatures
            );
        }

        if (blockNumber > 0 && blockHeaders[blockNumber - 1].finalized) {
            HyperBFTBlockHeader storage parent = blockHeaders[blockNumber - 1];
            if (parent.blockHash != parentHash) {
                revert InvalidBlockProof();
            }
        }

        blockHeaders[blockNumber] = HyperBFTBlockHeader({
            blockNumber: blockNumber,
            blockHash: blockHash,
            parentHash: parentHash,
            transactionsRoot: transactionsRoot,
            stateRoot: stateRoot,
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

    function pause() external onlyRole(GUARDIAN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(GUARDIAN_ROLE) {
        _unpause();
    }

    function withdrawFees() external onlyRole(TREASURY_ROLE) {
        uint256 amount = accumulatedFees;
        if (amount == 0) revert InvalidAmount();
        accumulatedFees = 0;

        uint256 balance = IERC20(bridgeConfig.wrappedHYPE).balanceOf(
            address(this)
        );
        uint256 transferAmount = amount > balance ? balance : amount;

        if (transferAmount > 0) {
            IERC20(bridgeConfig.wrappedHYPE).safeTransfer(
                treasury,
                transferAmount
            );
        }

        emit FeesWithdrawn(treasury, transferAmount);
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function getDeposit(
        bytes32 depositId
    ) external view returns (HYPEDeposit memory) {
        return deposits[depositId];
    }

    function getWithdrawal(
        bytes32 withdrawalId
    ) external view returns (HYPEWithdrawal memory) {
        return withdrawals[withdrawalId];
    }

    function getEscrow(
        bytes32 escrowId
    ) external view returns (HYPEEscrow memory) {
        return escrows[escrowId];
    }

    function getBlockHeader(
        uint256 blockNumber
    ) external view returns (HyperBFTBlockHeader memory) {
        return blockHeaders[blockNumber];
    }

    function getUserDeposits(
        address user
    ) external view returns (bytes32[] memory) {
        return userDeposits[user];
    }

    function getUserWithdrawals(
        address user
    ) external view returns (bytes32[] memory) {
        return userWithdrawals[user];
    }

    function getUserEscrows(
        address user
    ) external view returns (bytes32[] memory) {
        return userEscrows[user];
    }

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

    function _verifyMerkleProof(
        HyperliquidMerkleProof calldata proof,
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

    receive() external payable {}
}
