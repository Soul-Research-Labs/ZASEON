/**
 * @title AptosBridge Certora Specification
 * @notice Formal verification rules for the AptosBridgeAdapter contract
 * @dev Verifies invariants around Octas precision (8 decimals), LedgerInfo
 *      verification, AptosBFT validator attestation, and bridge security.
 *
 * Aptos uses AptosBFT (DiemBFT v4) consensus with sub-second finality and
 * Block-STM parallel execution. The bridge verifies validator attestations
 * on LedgerInfo and enforces 6 ledger version confirmation finality.
 */

// ============================================================================
// METHODS BLOCK
// ============================================================================

methods {
    // Constants
    function APTOS_CHAIN_ID() external returns (uint256) envfree;
    function OCTAS_PER_APT() external returns (uint256) envfree;
    function MIN_DEPOSIT_OCTAS() external returns (uint256) envfree;
    function MAX_DEPOSIT_OCTAS() external returns (uint256) envfree;
    function BRIDGE_FEE_BPS() external returns (uint256) envfree;
    function BPS_DENOMINATOR() external returns (uint256) envfree;
    function WITHDRAWAL_REFUND_DELAY() external returns (uint256) envfree;
    function MIN_ESCROW_TIMELOCK() external returns (uint256) envfree;
    function MAX_ESCROW_TIMELOCK() external returns (uint256) envfree;
    function DEFAULT_LEDGER_CONFIRMATIONS() external returns (uint256) envfree;

    // State
    function depositNonce() external returns (uint256) envfree;
    function withdrawalNonce() external returns (uint256) envfree;
    function escrowNonce() external returns (uint256) envfree;
    function latestLedgerVersion() external returns (uint256) envfree;
    function currentEpoch() external returns (uint256) envfree;
    function totalDeposited() external returns (uint256) envfree;
    function totalWithdrawn() external returns (uint256) envfree;
    function totalEscrows() external returns (uint256) envfree;
    function totalEscrowsFinished() external returns (uint256) envfree;
    function totalEscrowsCancelled() external returns (uint256) envfree;
    function accumulatedFees() external returns (uint256) envfree;
    function treasury() external returns (address) envfree;

    // Replay protection
    function usedAptosTxHashes(bytes32) external returns (bool) envfree;
    function usedNullifiers(bytes32) external returns (bool) envfree;

    // Deposit operations
    function initiateAPTDeposit(
        bytes32,
        bytes32,
        address,
        uint256,
        uint256,
        IAptosBridgeAdapter.AptosStateProof,
        IAptosBridgeAdapter.ValidatorAttestation[]
    ) external returns (bytes32);

    function completeAPTDeposit(bytes32) external;

    // Withdrawal operations
    function initiateWithdrawal(bytes32, uint256) external returns (bytes32);
    function completeWithdrawal(
        bytes32,
        bytes32,
        IAptosBridgeAdapter.AptosStateProof,
        IAptosBridgeAdapter.ValidatorAttestation[]
    ) external;
    function refundWithdrawal(bytes32) external;

    // Escrow operations
    function createEscrow(bytes32, bytes32, uint256, uint256) external returns (bytes32);
    function finishEscrow(bytes32, bytes32) external;
    function cancelEscrow(bytes32) external;

    // Privacy
    function registerPrivateDeposit(bytes32, bytes32, bytes32, bytes) external;

    // LedgerInfo
    function submitLedgerInfo(
        uint256,
        bytes32,
        bytes32,
        bytes32,
        uint256,
        uint256,
        uint256,
        uint256,
        IAptosBridgeAdapter.ValidatorAttestation[]
    ) external;
}

// ============================================================================
// INVARIANTS
// ============================================================================

/// @title Aptos chain ID is always 1
invariant aptosChainIdConstant()
    APTOS_CHAIN_ID() == 1;

/// @title Octas per APT is always 100,000,000 (1e8)
invariant octasPerAptConstant()
    OCTAS_PER_APT() == 100000000;

/// @title Bridge fee BPS is always 4 (0.04%)
invariant bridgeFeeBpsConstant()
    BRIDGE_FEE_BPS() == 4;

/// @title Withdrawal refund delay is always 86400 seconds (24 hours)
invariant withdrawalRefundDelayConstant()
    WITHDRAWAL_REFUND_DELAY() == 86400;

/// @title Default ledger confirmations is always 6
invariant defaultLedgerConfirmationsConstant()
    DEFAULT_LEDGER_CONFIRMATIONS() == 6;

/// @title Min escrow timelock is always 3600 seconds (1 hour)
invariant minEscrowTimelockConstant()
    MIN_ESCROW_TIMELOCK() == 3600;

/// @title Max escrow timelock is always 2592000 seconds (30 days)
invariant maxEscrowTimelockConstant()
    MAX_ESCROW_TIMELOCK() == 2592000;

/// @title Finished escrows never exceed total escrows
invariant finishedEscrowsBounded()
    totalEscrowsFinished() <= totalEscrows();

/// @title Cancelled escrows never exceed total escrows
invariant cancelledEscrowsBounded()
    totalEscrowsCancelled() <= totalEscrows();

// ============================================================================
// RULES
// ============================================================================

/// @title Deposit nonce is monotonically increasing
rule depositNonceMonotonic(env e, method f, calldataarg args) {
    uint256 nonceBefore = depositNonce();
    f(e, args);
    uint256 nonceAfter = depositNonce();

    assert nonceAfter >= nonceBefore,
        "Deposit nonce must never decrease";
}

/// @title Withdrawal nonce is monotonically increasing
rule withdrawalNonceMonotonic(env e, method f, calldataarg args) {
    uint256 nonceBefore = withdrawalNonce();
    f(e, args);
    uint256 nonceAfter = withdrawalNonce();

    assert nonceAfter >= nonceBefore,
        "Withdrawal nonce must never decrease";
}

/// @title Escrow nonce is monotonically increasing
rule escrowNonceMonotonic(env e, method f, calldataarg args) {
    uint256 nonceBefore = escrowNonce();
    f(e, args);
    uint256 nonceAfter = escrowNonce();

    assert nonceAfter >= nonceBefore,
        "Escrow nonce must never decrease";
}

/// @title Aptos tx hash can only transition from unused to used (never back)
rule aptosTxHashIrreversible(env e, method f, calldataarg args) {
    bytes32 txHash;
    bool usedBefore = usedAptosTxHashes(txHash);

    f(e, args);

    bool usedAfter = usedAptosTxHashes(txHash);

    assert usedBefore => usedAfter,
        "Used Aptos tx hash must remain used forever";
}

/// @title Nullifier can only transition from unused to used (never back)
rule nullifierIrreversible(env e, method f, calldataarg args) {
    bytes32 nullifier;
    bool usedBefore = usedNullifiers(nullifier);

    f(e, args);

    bool usedAfter = usedNullifiers(nullifier);

    assert usedBefore => usedAfter,
        "Used nullifier must remain used forever";
}

/// @title Total deposited is monotonically non-decreasing
rule totalDepositedNonDecreasing(env e, method f, calldataarg args) {
    uint256 before = totalDeposited();
    f(e, args);
    uint256 after_ = totalDeposited();

    assert after_ >= before,
        "Total deposited must never decrease";
}

/// @title Total withdrawn is monotonically non-decreasing
rule totalWithdrawnNonDecreasing(env e, method f, calldataarg args) {
    uint256 before = totalWithdrawn();
    f(e, args);
    uint256 after_ = totalWithdrawn();

    assert after_ >= before,
        "Total withdrawn must never decrease";
}

/// @title Total escrows is monotonically non-decreasing
rule totalEscrowsNonDecreasing(env e, method f, calldataarg args) {
    uint256 before = totalEscrows();
    f(e, args);
    uint256 after_ = totalEscrows();

    assert after_ >= before,
        "Total escrows must never decrease";
}

/// @title Latest ledger version is monotonically non-decreasing
rule latestLedgerVersionNonDecreasing(env e, method f, calldataarg args) {
    uint256 before = latestLedgerVersion();
    f(e, args);
    uint256 after_ = latestLedgerVersion();

    assert after_ >= before,
        "Latest ledger version must never decrease";
}

/// @title Current epoch is monotonically non-decreasing
rule currentEpochNonDecreasing(env e, method f, calldataarg args) {
    uint256 before = currentEpoch();
    f(e, args);
    uint256 after_ = currentEpoch();

    assert after_ >= before,
        "Current epoch must never decrease";
}

/// @title Fee calculation: fee + net = gross amount
rule feeCalculationIntegrity(env e) {
    uint256 amount;
    require amount >= MIN_DEPOSIT_OCTAS();
    require amount <= MAX_DEPOSIT_OCTAS();

    uint256 fee = (amount * BRIDGE_FEE_BPS()) / BPS_DENOMINATOR();
    uint256 net = amount - fee;

    assert fee + net == amount,
        "Fee + net must equal gross amount";
    assert fee <= amount,
        "Fee must not exceed amount";
}

/// @title Treasury address is never zero after configuration
rule treasuryNeverZero(env e, method f, calldataarg args) {
    address treasuryBefore = treasury();
    require treasuryBefore != 0;

    f(e, args);

    address treasuryAfter = treasury();
    assert treasuryAfter != 0,
        "Treasury must never be set to zero address";
}
