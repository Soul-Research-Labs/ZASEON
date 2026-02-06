// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IAptosBridgeAdapter} from "../interfaces/IAptosBridgeAdapter.sol";

/**
 * @title AptosBridgeAdapter
 * @author Soul Protocol
 * @notice Bridge adapter for Aptos Network interoperability with Soul Protocol
 * @dev Enables cross-chain transfers between Soul Protocol (EVM) and the Aptos Network
 *
 * ARCHITECTURE:
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │                       Soul <-> Aptos Bridge                                 │
 * ├─────────────────────────────────────────────────────────────────────────────┤
 * │                                                                             │
 * │  ┌───────────────────┐           ┌───────────────────────────────────┐     │
 * │  │   Soul Side       │           │     Aptos Side                    │     │
 * │  │  ┌─────────────┐  │           │  ┌────────────────────────────┐   │     │
 * │  │  │ wAPT        │  │           │  │  Move VM                   │   │     │
 * │  │  │ Token       │  │           │  │  (Resource Model)          │   │     │
 * │  │  │ (ERC-20)    │  │           │  └────────────────────────────┘   │     │
 * │  │  └─────────────┘  │           │        │                          │     │
 * │  │        │          │           │  ┌─────▼──────────────────────┐   │     │
 * │  │  ┌─────▼───────┐  │           │  │  AptosBFT Consensus        │   │     │
 * │  │  │ Bridge      │  │◄─────────►│  │  (~160ms block time)       │   │     │
 * │  │  │ Adapter     │  │  Relayer  │  └────────────────────────────┘   │     │
 * │  │  └─────────────┘  │           │        │                          │     │
 * │  │        │          │           │  ┌─────▼──────────────────────┐   │     │
 * │  │  ┌─────▼───────┐  │           │  │  Block-STM Parallel Exec   │   │     │
 * │  │  │ ZK Privacy  │  │           │  │  (Optimistic Concurrency)  │   │     │
 * │  │  │ Layer       │  │           │  └────────────────────────────┘   │     │
 * │  │  └─────────────┘  │           │                                   │     │
 * │  └───────────────────┘           └───────────────────────────────────┘     │
 * └─────────────────────────────────────────────────────────────────────────────┘
 *
 * APTOS CONCEPTS:
 * - Octas: Smallest unit (1 APT = 100,000,000 Octas = 1e8)
 * - Move VM: Resource-oriented smart contract language
 * - Block-STM: Parallel execution with optimistic MVCC
 * - Jellyfish Merkle Tree: Sparse Merkle tree for state proofs
 * - LedgerInfo: Signed summary of committed blockchain state
 * - Chain ID: aptos-mainnet → 1
 * - Finality: 6 ledger version confirmations for cross-chain safety
 * - Block time: ~160ms (AptosBFT consensus)
 */
contract AptosBridgeAdapter is
    IAptosBridgeAdapter,
    AccessControl,
    ReentrancyGuard,
    Pausable
{
    using SafeERC20 for IERC20;

    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Aptos mainnet chain ID
    uint256 public constant APTOS_CHAIN_ID = 1;

    /// @notice 1 APT = 1e8 Octas (8 decimals)
    uint256 public constant OCTAS_PER_APT = 100_000_000;

    /// @notice Minimum deposit: 0.1 APT = 10,000,000 Octas
    uint256 public constant MIN_DEPOSIT_OCTAS = OCTAS_PER_APT / 10;

    /// @notice Maximum deposit: 10,000,000 APT
    uint256 public constant MAX_DEPOSIT_OCTAS = 10_000_000 * OCTAS_PER_APT;

    /// @notice Bridge fee: 4 BPS (0.04%)
    uint256 public constant BRIDGE_FEE_BPS = 4;

    /// @notice BPS denominator
    uint256 public constant BPS_DENOMINATOR = 10_000;

    /// @notice Withdrawal refund delay: 24 hours
    uint256 public constant WITHDRAWAL_REFUND_DELAY = 24 hours;

    /// @notice Minimum escrow timelock: 1 hour
    uint256 public constant MIN_ESCROW_TIMELOCK = 1 hours;

    /// @notice Maximum escrow timelock: 30 days
    uint256 public constant MAX_ESCROW_TIMELOCK = 30 days;

    /// @notice Default ledger version confirmations for finality
    uint256 public constant DEFAULT_LEDGER_CONFIRMATIONS = 6;

    /*//////////////////////////////////////////////////////////////
                            ACCESS ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");

    /*//////////////////////////////////////////////////////////////
                              STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Bridge configuration
    BridgeConfig public config;

    /// @notice Treasury for fee collection
    address public treasury;

    /// @notice Deposit nonce (monotonically increasing)
    uint256 public depositNonce;

    /// @notice Withdrawal nonce (monotonically increasing)
    uint256 public withdrawalNonce;

    /// @notice Escrow nonce (monotonically increasing)
    uint256 public escrowNonce;

    /// @notice Latest verified ledger version
    uint256 public latestLedgerVersion;

    /// @notice Current epoch
    uint256 public currentEpoch;

    /// @notice Total deposited in Octas
    uint256 public totalDeposited;

    /// @notice Total withdrawn in Octas
    uint256 public totalWithdrawn;

    /// @notice Total escrows created
    uint256 public totalEscrows;

    /// @notice Total escrows finished
    uint256 public totalEscrowsFinished;

    /// @notice Total escrows cancelled
    uint256 public totalEscrowsCancelled;

    /// @notice Accumulated fees in Octas
    uint256 public accumulatedFees;

    /// @notice Deposits by ID
    mapping(bytes32 => APTDeposit) private deposits;

    /// @notice Withdrawals by ID
    mapping(bytes32 => APTWithdrawal) private withdrawals;

    /// @notice Escrows by ID
    mapping(bytes32 => APTEscrow) private escrows;

    /// @notice Ledger info by version
    mapping(uint256 => AptosLedgerInfo) private ledgerInfos;

    /// @notice Used Aptos tx hashes (replay protection)
    mapping(bytes32 => bool) public usedAptosTxHashes;

    /// @notice Used nullifiers (privacy replay protection)
    mapping(bytes32 => bool) public usedNullifiers;

    /// @notice User deposit IDs
    mapping(address => bytes32[]) private userDeposits;

    /// @notice User withdrawal IDs
    mapping(address => bytes32[]) private userWithdrawals;

    /// @notice User escrow IDs
    mapping(address => bytes32[]) private userEscrows;

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address admin) {
        if (admin == address(0)) revert ZeroAddress();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(RELAYER_ROLE, admin);
        _grantRole(OPERATOR_ROLE, admin);
        _grantRole(GUARDIAN_ROLE, admin);
    }

    /*//////////////////////////////////////////////////////////////
                          CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IAptosBridgeAdapter
    function configure(
        address aptosBridgeContract,
        address wrappedAPT,
        address validatorOracle,
        uint256 minValidatorSignatures,
        uint256 requiredLedgerConfirmations
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (aptosBridgeContract == address(0)) revert ZeroAddress();
        if (wrappedAPT == address(0)) revert ZeroAddress();
        if (validatorOracle == address(0)) revert ZeroAddress();

        config = BridgeConfig({
            aptosBridgeContract: aptosBridgeContract,
            wrappedAPT: wrappedAPT,
            validatorOracle: validatorOracle,
            minValidatorSignatures: minValidatorSignatures,
            requiredLedgerConfirmations: requiredLedgerConfirmations,
            active: true
        });

        emit BridgeConfigured(aptosBridgeContract, wrappedAPT, validatorOracle);
    }

    /// @inheritdoc IAptosBridgeAdapter
    function setTreasury(address _treasury) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_treasury == address(0)) revert ZeroAddress();
        treasury = _treasury;
    }

    /*//////////////////////////////////////////////////////////////
                       LEDGER INFO VERIFICATION
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IAptosBridgeAdapter
    function submitLedgerInfo(
        uint256 ledgerVersion,
        bytes32 transactionHash,
        bytes32 stateRootHash,
        bytes32 eventRootHash,
        uint256 epoch,
        uint256 round,
        uint256 timestamp,
        uint256 numTransactions,
        ValidatorAttestation[] calldata attestations
    ) external onlyRole(RELAYER_ROLE) nonReentrant {
        _verifyValidatorAttestations(
            keccak256(
                abi.encodePacked(
                    ledgerVersion,
                    transactionHash,
                    stateRootHash,
                    eventRootHash,
                    epoch,
                    round,
                    timestamp,
                    numTransactions
                )
            ),
            attestations
        );

        ledgerInfos[ledgerVersion] = AptosLedgerInfo({
            ledgerVersion: ledgerVersion,
            transactionHash: transactionHash,
            stateRootHash: stateRootHash,
            eventRootHash: eventRootHash,
            epoch: epoch,
            round: round,
            timestamp: timestamp,
            numTransactions: numTransactions,
            verified: true
        });

        if (ledgerVersion > latestLedgerVersion) {
            latestLedgerVersion = ledgerVersion;
        }

        if (epoch > currentEpoch) {
            currentEpoch = epoch;
        }

        emit LedgerInfoVerified(ledgerVersion, transactionHash, epoch);
    }

    /*//////////////////////////////////////////////////////////////
                          DEPOSIT OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IAptosBridgeAdapter
    function initiateAPTDeposit(
        bytes32 aptosTxHash,
        bytes32 aptosSender,
        address evmRecipient,
        uint256 amountOctas,
        uint256 ledgerVersion,
        AptosStateProof calldata txProof,
        ValidatorAttestation[] calldata attestations
    )
        external
        onlyRole(RELAYER_ROLE)
        nonReentrant
        whenNotPaused
        returns (bytes32 depositId)
    {
        if (evmRecipient == address(0)) revert ZeroAddress();
        if (amountOctas < MIN_DEPOSIT_OCTAS)
            revert AmountBelowMinimum(amountOctas, MIN_DEPOSIT_OCTAS);
        if (amountOctas > MAX_DEPOSIT_OCTAS)
            revert AmountAboveMaximum(amountOctas, MAX_DEPOSIT_OCTAS);
        if (usedAptosTxHashes[aptosTxHash])
            revert AptosTxAlreadyUsed(aptosTxHash);
        if (!ledgerInfos[ledgerVersion].verified)
            revert LedgerVersionNotVerified(ledgerVersion);

        _verifyValidatorAttestations(
            keccak256(abi.encodePacked(aptosTxHash, aptosSender, evmRecipient, amountOctas)),
            attestations
        );

        usedAptosTxHashes[aptosTxHash] = true;

        uint256 fee = (amountOctas * BRIDGE_FEE_BPS) / BPS_DENOMINATOR;
        uint256 netAmount = amountOctas - fee;

        depositNonce++;
        depositId = keccak256(
            abi.encodePacked(
                APTOS_CHAIN_ID,
                depositNonce,
                aptosTxHash,
                block.timestamp
            )
        );

        deposits[depositId] = APTDeposit({
            depositId: depositId,
            aptosTxHash: aptosTxHash,
            aptosSender: aptosSender,
            evmRecipient: evmRecipient,
            amountOctas: amountOctas,
            netAmountOctas: netAmount,
            fee: fee,
            status: DepositStatus.VERIFIED,
            ledgerVersion: ledgerVersion,
            initiatedAt: block.timestamp,
            completedAt: 0
        });

        accumulatedFees += fee;
        totalDeposited += amountOctas;
        userDeposits[evmRecipient].push(depositId);

        emit APTDepositInitiated(
            depositId,
            aptosTxHash,
            aptosSender,
            evmRecipient,
            amountOctas
        );
    }

    /// @inheritdoc IAptosBridgeAdapter
    function completeAPTDeposit(
        bytes32 depositId
    ) external onlyRole(OPERATOR_ROLE) nonReentrant whenNotPaused {
        APTDeposit storage dep = deposits[depositId];
        if (dep.initiatedAt == 0) revert DepositNotFound(depositId);
        if (dep.status == DepositStatus.COMPLETED)
            revert DepositAlreadyCompleted(depositId);
        if (dep.status != DepositStatus.VERIFIED)
            revert DepositNotVerified(depositId);

        dep.status = DepositStatus.COMPLETED;
        dep.completedAt = block.timestamp;

        IERC20(config.wrappedAPT).safeTransfer(
            dep.evmRecipient,
            dep.netAmountOctas
        );

        emit APTDepositCompleted(
            depositId,
            dep.evmRecipient,
            dep.netAmountOctas
        );
    }

    /*//////////////////////////////////////////////////////////////
                        WITHDRAWAL OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IAptosBridgeAdapter
    function initiateWithdrawal(
        bytes32 aptosRecipient,
        uint256 amountOctas
    ) external nonReentrant whenNotPaused returns (bytes32 withdrawalId) {
        if (aptosRecipient == bytes32(0)) revert ZeroAddress();
        if (amountOctas < MIN_DEPOSIT_OCTAS)
            revert AmountBelowMinimum(amountOctas, MIN_DEPOSIT_OCTAS);
        if (amountOctas > MAX_DEPOSIT_OCTAS)
            revert AmountAboveMaximum(amountOctas, MAX_DEPOSIT_OCTAS);

        IERC20(config.wrappedAPT).safeTransferFrom(
            msg.sender,
            address(this),
            amountOctas
        );

        withdrawalNonce++;
        withdrawalId = keccak256(
            abi.encodePacked(
                APTOS_CHAIN_ID,
                withdrawalNonce,
                msg.sender,
                aptosRecipient,
                block.timestamp
            )
        );

        withdrawals[withdrawalId] = APTWithdrawal({
            withdrawalId: withdrawalId,
            evmSender: msg.sender,
            aptosRecipient: aptosRecipient,
            amountOctas: amountOctas,
            aptosTxHash: bytes32(0),
            status: WithdrawalStatus.PENDING,
            initiatedAt: block.timestamp,
            completedAt: 0
        });

        totalWithdrawn += amountOctas;
        userWithdrawals[msg.sender].push(withdrawalId);

        emit APTWithdrawalInitiated(
            withdrawalId,
            msg.sender,
            aptosRecipient,
            amountOctas
        );
    }

    /// @inheritdoc IAptosBridgeAdapter
    function completeWithdrawal(
        bytes32 withdrawalId,
        bytes32 aptosTxHash,
        AptosStateProof calldata txProof,
        ValidatorAttestation[] calldata attestations
    ) external onlyRole(RELAYER_ROLE) nonReentrant {
        APTWithdrawal storage w = withdrawals[withdrawalId];
        if (w.initiatedAt == 0) revert WithdrawalNotFound(withdrawalId);
        if (w.status != WithdrawalStatus.PENDING)
            revert WithdrawalNotPending(withdrawalId);

        _verifyValidatorAttestations(
            keccak256(abi.encodePacked(withdrawalId, aptosTxHash)),
            attestations
        );

        w.status = WithdrawalStatus.COMPLETED;
        w.aptosTxHash = aptosTxHash;
        w.completedAt = block.timestamp;

        // Burn the held wAPT tokens
        // In production, this would call burn on the wAPT contract
        emit APTWithdrawalCompleted(withdrawalId, aptosTxHash);
    }

    /// @inheritdoc IAptosBridgeAdapter
    function refundWithdrawal(
        bytes32 withdrawalId
    ) external nonReentrant {
        APTWithdrawal storage w = withdrawals[withdrawalId];
        if (w.initiatedAt == 0) revert WithdrawalNotFound(withdrawalId);
        if (w.status != WithdrawalStatus.PENDING)
            revert WithdrawalNotPending(withdrawalId);
        if (block.timestamp < w.initiatedAt + WITHDRAWAL_REFUND_DELAY)
            revert RefundTooEarly(
                block.timestamp,
                w.initiatedAt + WITHDRAWAL_REFUND_DELAY
            );

        w.status = WithdrawalStatus.REFUNDED;
        w.completedAt = block.timestamp;

        IERC20(config.wrappedAPT).safeTransfer(w.evmSender, w.amountOctas);

        emit APTWithdrawalRefunded(withdrawalId, w.evmSender, w.amountOctas);
    }

    /*//////////////////////////////////////////////////////////////
                          ESCROW OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IAptosBridgeAdapter
    function createEscrow(
        bytes32 aptosParty,
        bytes32 hashlock,
        uint256 finishAfter,
        uint256 cancelAfter
    )
        external
        payable
        nonReentrant
        whenNotPaused
        returns (bytes32 escrowId)
    {
        if (msg.value == 0) revert InvalidAmount();
        if (aptosParty == bytes32(0)) revert ZeroAddress();

        uint256 duration = cancelAfter - finishAfter;
        if (duration < MIN_ESCROW_TIMELOCK || duration > MAX_ESCROW_TIMELOCK)
            revert InvalidTimelockRange();

        escrowNonce++;
        escrowId = keccak256(
            abi.encodePacked(
                APTOS_CHAIN_ID,
                escrowNonce,
                msg.sender,
                aptosParty,
                block.timestamp
            )
        );

        escrows[escrowId] = APTEscrow({
            escrowId: escrowId,
            evmParty: msg.sender,
            aptosParty: aptosParty,
            amountOctas: msg.value,
            hashlock: hashlock,
            preimage: bytes32(0),
            finishAfter: finishAfter,
            cancelAfter: cancelAfter,
            status: EscrowStatus.ACTIVE,
            createdAt: block.timestamp
        });

        totalEscrows++;
        userEscrows[msg.sender].push(escrowId);

        emit EscrowCreated(
            escrowId,
            msg.sender,
            aptosParty,
            msg.value,
            hashlock
        );
    }

    /// @inheritdoc IAptosBridgeAdapter
    function finishEscrow(
        bytes32 escrowId,
        bytes32 preimage
    ) external nonReentrant {
        APTEscrow storage e = escrows[escrowId];
        if (e.createdAt == 0) revert EscrowNotFound(escrowId);
        if (e.status != EscrowStatus.ACTIVE) revert EscrowNotActive(escrowId);
        if (block.timestamp < e.finishAfter) revert EscrowTimelockNotMet();

        bytes32 computedHash = sha256(abi.encodePacked(preimage));
        if (computedHash != e.hashlock)
            revert InvalidPreimage(e.hashlock, computedHash);

        e.status = EscrowStatus.FINISHED;
        e.preimage = preimage;
        totalEscrowsFinished++;

        emit EscrowFinished(escrowId, preimage);
    }

    /// @inheritdoc IAptosBridgeAdapter
    function cancelEscrow(bytes32 escrowId) external nonReentrant {
        APTEscrow storage e = escrows[escrowId];
        if (e.createdAt == 0) revert EscrowNotFound(escrowId);
        if (e.status != EscrowStatus.ACTIVE) revert EscrowNotActive(escrowId);
        if (block.timestamp < e.cancelAfter) revert EscrowTimelockNotMet();

        e.status = EscrowStatus.CANCELLED;
        totalEscrowsCancelled++;

        (bool sent, ) = e.evmParty.call{value: e.amountOctas}("");
        require(sent, "ETH transfer failed");

        emit EscrowCancelled(escrowId);
    }

    /*//////////////////////////////////////////////////////////////
                          PRIVACY OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IAptosBridgeAdapter
    function registerPrivateDeposit(
        bytes32 depositId,
        bytes32 commitment,
        bytes32 nullifier,
        bytes calldata /* zkProof */
    ) external nonReentrant {
        if (usedNullifiers[nullifier])
            revert NullifierAlreadyUsed(nullifier);

        usedNullifiers[nullifier] = true;

        emit PrivateDepositRegistered(depositId, commitment, nullifier);
    }

    /*//////////////////////////////////////////////////////////////
                           ADMIN OPERATIONS
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
    function withdrawFees() external onlyRole(DEFAULT_ADMIN_ROLE) nonReentrant {
        uint256 amount = accumulatedFees;
        accumulatedFees = 0;

        IERC20(config.wrappedAPT).safeTransfer(treasury, amount);

        emit FeesWithdrawn(treasury, amount);
    }

    /*//////////////////////////////////////////////////////////////
                           VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IAptosBridgeAdapter
    function getDeposit(
        bytes32 depositId
    ) external view returns (APTDeposit memory) {
        return deposits[depositId];
    }

    /// @inheritdoc IAptosBridgeAdapter
    function getWithdrawal(
        bytes32 withdrawalId
    ) external view returns (APTWithdrawal memory) {
        return withdrawals[withdrawalId];
    }

    /// @inheritdoc IAptosBridgeAdapter
    function getEscrow(
        bytes32 escrowId
    ) external view returns (APTEscrow memory) {
        return escrows[escrowId];
    }

    /// @inheritdoc IAptosBridgeAdapter
    function getLedgerInfo(
        uint256 version
    ) external view returns (AptosLedgerInfo memory) {
        return ledgerInfos[version];
    }

    /// @inheritdoc IAptosBridgeAdapter
    function getUserDeposits(
        address user
    ) external view returns (bytes32[] memory) {
        return userDeposits[user];
    }

    /// @inheritdoc IAptosBridgeAdapter
    function getUserWithdrawals(
        address user
    ) external view returns (bytes32[] memory) {
        return userWithdrawals[user];
    }

    /// @inheritdoc IAptosBridgeAdapter
    function getUserEscrows(
        address user
    ) external view returns (bytes32[] memory) {
        return userEscrows[user];
    }

    /// @notice Get aggregate bridge statistics
    function getBridgeStats()
        external
        view
        returns (
            uint256 _totalDeposited,
            uint256 _totalWithdrawn,
            uint256 _totalEscrows,
            uint256 _totalEscrowsFinished,
            uint256 _totalEscrowsCancelled,
            uint256 _accumulatedFees,
            uint256 _latestLedgerVersion
        )
    {
        return (
            totalDeposited,
            totalWithdrawn,
            totalEscrows,
            totalEscrowsFinished,
            totalEscrowsCancelled,
            accumulatedFees,
            latestLedgerVersion
        );
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @dev Verify validator attestation signatures meet threshold
    function _verifyValidatorAttestations(
        bytes32 messageHash,
        ValidatorAttestation[] calldata attestations
    ) internal view {
        uint256 validCount = 0;

        for (uint256 i = 0; i < attestations.length; i++) {
            // In production: verify BLS signature against validator set
            // For now: verify via the validator oracle
            (bool valid, ) = config.validatorOracle.staticcall(
                abi.encodeWithSignature(
                    "verifyAttestation(bytes32,address,bytes)",
                    messageHash,
                    attestations[i].validator,
                    attestations[i].signature
                )
            );

            if (valid) {
                // Decode the return value
                bytes memory returnData;
                (, returnData) = config.validatorOracle.staticcall(
                    abi.encodeWithSignature(
                        "verifyAttestation(bytes32,address,bytes)",
                        messageHash,
                        attestations[i].validator,
                        attestations[i].signature
                    )
                );
                bool isValid = abi.decode(returnData, (bool));
                if (isValid) validCount++;
            }
        }

        if (validCount < config.minValidatorSignatures)
            revert InsufficientValidatorSignatures(
                validCount,
                config.minValidatorSignatures
            );
    }
}
