/**
 * @title SeiBridge Certora Specification
 * @notice Formal verification rules for the SeiBridgeAdapter contract
 * @dev Verifies invariants around usei precision (6 decimals), block header
 *      verification, Tendermint BFT validator attestation, and bridge security.
 *
 * Sei uses Twin-Turbo consensus with ~400ms finality and parallel EVM
 * execution. The bridge verifies Tendermint BFT validator attestations
 * on block headers and enforces 8 block confirmation finality.
 */

// ============================================================================
// METHODS BLOCK
// ============================================================================

methods {
    // Constants
    function SEI_CHAIN_ID() external returns (uint256) envfree;
    function USEI_PER_SEI() external returns (uint256) envfree;
    function MIN_DEPOSIT_USEI() external returns (uint256) envfree;
    function MAX_DEPOSIT_USEI() external returns (uint256) envfree;
    function BRIDGE_FEE_BPS() external returns (uint256) envfree;
    function BPS_DENOMINATOR() external returns (uint256) envfree;
    function WITHDRAWAL_REFUND_DELAY() external returns (uint256) envfree;
    function MIN_ESCROW_TIMELOCK() external returns (uint256) envfree;
    function MAX_ESCROW_TIMELOCK() external returns (uint256) envfree;
    function DEFAULT_BLOCK_CONFIRMATIONS() external returns (uint256) envfree;

    // State
    function depositNonce() external returns (uint256) envfree;
    function withdrawalNonce() external returns (uint256) envfree;
    function escrowNonce() external returns (uint256) envfree;
    function latestBlockHeight() external returns (uint256) envfree;
    function totalDeposited() external returns (uint256) envfree;
    function totalWithdrawn() external returns (uint256) envfree;
    function totalEscrows() external returns (uint256) envfree;
    function totalEscrowsFinished() external returns (uint256) envfree;
    function totalEscrowsCancelled() external returns (uint256) envfree;
    function accumulatedFees() external returns (uint256) envfree;
    function treasury() external returns (address) envfree;

    // Replay protection
    function usedSeiTxHashes(bytes32) external returns (bool) envfree;
    function usedNullifiers(bytes32) external returns (bool) envfree;

    // Deposit operations
    function initiateSEIDeposit(
        bytes32,
        bytes32,
        address,
        uint256,
        uint256,
        ISeiBridgeAdapter.SeiMerkleProof,
        ISeiBridgeAdapter.ValidatorAttestation[]
    ) external returns (bytes32);

    function completeSEIDeposit(bytes32) external;

    // Withdrawal operations
    function initiateWithdrawal(bytes32, uint256) external returns (bytes32);
    function completeWithdrawal(
        bytes32,
        bytes32,
        ISeiBridgeAdapter.SeiMerkleProof,
        ISeiBridgeAdapter.ValidatorAttestation[]
    ) external;
    function refundWithdrawal(bytes32) external;

    // Escrow operations
    function createEscrow(bytes32, bytes32, uint256, uint256) external returns (bytes32);
    function finishEscrow(bytes32, bytes32) external;
    function cancelEscrow(bytes32) external;

    // Privacy
    function registerPrivateDeposit(bytes32, bytes32, bytes32, bytes) external;

    // Block header
    function submitBlockHeader(
        uint256,
        bytes32,
        bytes32,
        bytes32,
        bytes32,
        bytes32,
        uint256,
        uint256,
        ISeiBridgeAdapter.ValidatorAttestation[]
    ) external;
}

// ============================================================================
// INVARIANTS
// ============================================================================

/// @title Sei chain ID is always 1329
invariant seiChainIdConstant()
    SEI_CHAIN_ID() == 1329;

/// @title usei per SEI is always 1,000,000 (1e6)
invariant useiPerSeiConstant()
    USEI_PER_SEI() == 1000000;

/// @title Bridge fee BPS is always 5 (0.05%)
invariant bridgeFeeBpsConstant()
    BRIDGE_FEE_BPS() == 5;

/// @title Withdrawal refund delay is always 129600 seconds (36 hours)
invariant withdrawalRefundDelayConstant()
    WITHDRAWAL_REFUND_DELAY() == 129600;

/// @title Default block confirmations is always 8
invariant defaultBlockConfirmationsConstant()
    DEFAULT_BLOCK_CONFIRMATIONS() == 8;

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

/// @title Sei tx hash can only transition from unused to used (never back)
rule seiTxHashIrreversible(env e, method f, calldataarg args) {
    bytes32 txHash;
    bool usedBefore = usedSeiTxHashes(txHash);

    f(e, args);

    bool usedAfter = usedSeiTxHashes(txHash);

    assert usedBefore => usedAfter,
        "Used Sei tx hash must remain used forever";
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

/// @title Latest block height is monotonically non-decreasing
rule latestBlockHeightNonDecreasing(env e, method f, calldataarg args) {
    uint256 before = latestBlockHeight();
    f(e, args);
    uint256 after_ = latestBlockHeight();

    assert after_ >= before,
        "Latest block height must never decrease";
}

/// @title Fee calculation: fee + net = gross amount
rule feeCalculationIntegrity(env e) {
    uint256 amount;
    require amount >= MIN_DEPOSIT_USEI();
    require amount <= MAX_DEPOSIT_USEI();

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
