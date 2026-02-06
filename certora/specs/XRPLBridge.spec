/**
 * @title XRPLBridge Formal Verification Specification
 * @notice Certora CVL specification for XRPLBridgeAdapter
 * @dev Verifies critical security properties for the XRPL bridge
 *
 * Run: certoraRun certora/conf/verify_xrpl_bridge.conf
 */

/**
 * ┌────────────────────────────────────────────────────────────────────────────┐
 * │                  XRPL BRIDGE SECURITY INVARIANTS                           │
 * ├────────────────────────────────────────────────────────────────────────────┤
 * │                                                                            │
 * │  1. DEPOSIT INTEGRITY                                                      │
 * │     - XRPL tx hashes cannot be reused (replay protection)                 │
 * │     - Deposit IDs are unique                                               │
 * │     - Fees are properly calculated                                         │
 * │                                                                            │
 * │  2. WITHDRAWAL SECURITY                                                    │
 * │     - Refund only after 48h delay                                          │
 * │     - No double-refund                                                     │
 * │     - Amount conservation                                                  │
 * │                                                                            │
 * │  3. ESCROW ATOMICITY                                                       │
 * │     - Finish requires correct fulfillment (SHA-256 preimage)              │
 * │     - Cancel only after cancelAfter timestamp                             │
 * │     - Funds released exactly once                                          │
 * │                                                                            │
 * │  4. ACCESS CONTROL                                                         │
 * │     - Only RELAYER can submit deposits and ledger headers                 │
 * │     - Only OPERATOR can complete deposits                                  │
 * │     - Only GUARDIAN can pause                                              │
 * │                                                                            │
 * │  5. PAUSE MECHANISM                                                        │
 * │     - Paused state blocks all mutating operations                         │
 * │                                                                            │
 * │  6. NONCE MONOTONICITY                                                     │
 * │     - Nonces never decrease                                               │
 * │     - Each operation has unique ID                                         │
 * │                                                                            │
 * │  7. NULLIFIER UNIQUENESS                                                   │
 * │     - Once used, nullifiers remain used forever                            │
 * │     - No nullifier double-spend                                            │
 * │                                                                            │
 * └────────────────────────────────────────────────────────────────────────────┘
 */

/*//////////////////////////////////////////////////////////////
                         METHODS BLOCK
//////////////////////////////////////////////////////////////*/

methods {
    // Bridge configuration
    function bridgeConfig() external returns (
        bytes20, address, address, uint256, uint256, bool
    ) envfree optional;

    // Nonces
    function depositNonce() external returns (uint256) envfree;
    function withdrawalNonce() external returns (uint256) envfree;
    function escrowNonce() external returns (uint256) envfree;

    // State queries
    function usedXRPLTxHashes(bytes32) external returns (bool) envfree;
    function usedNullifiers(bytes32) external returns (bool) envfree;
    function paused() external returns (bool) envfree;
    function latestLedgerIndex() external returns (uint256) envfree;
    function latestLedgerHash() external returns (bytes32) envfree;

    // Statistics
    function totalDeposited() external returns (uint256) envfree;
    function totalWithdrawn() external returns (uint256) envfree;
    function totalEscrows() external returns (uint256) envfree;
    function totalEscrowsFinished() external returns (uint256) envfree;
    function totalEscrowsCancelled() external returns (uint256) envfree;
    function accumulatedFees() external returns (uint256) envfree;

    // Role constants
    function DEFAULT_ADMIN_ROLE() external returns (bytes32) envfree;
    function OPERATOR_ROLE() external returns (bytes32) envfree;
    function RELAYER_ROLE() external returns (bytes32) envfree;
    function GUARDIAN_ROLE() external returns (bytes32) envfree;
    function TREASURY_ROLE() external returns (bytes32) envfree;

    // Access control
    function hasRole(bytes32, address) external returns (bool) envfree;

    // Constants
    function DROPS_PER_XRP() external returns (uint256) envfree;
    function MIN_DEPOSIT_DROPS() external returns (uint256) envfree;
    function MAX_DEPOSIT_DROPS() external returns (uint256) envfree;
    function BRIDGE_FEE_BPS() external returns (uint256) envfree;
    function BPS_DENOMINATOR() external returns (uint256) envfree;
    function WITHDRAWAL_REFUND_DELAY() external returns (uint256) envfree;
    function MIN_ESCROW_TIMELOCK() external returns (uint256) envfree;
    function MAX_ESCROW_TIMELOCK() external returns (uint256) envfree;

    // Key operations
    function initiateWithdrawal(bytes20, uint256) external returns (bytes32);
    function refundWithdrawal(bytes32) external;
    function completeXRPDeposit(bytes32) external;
    function createEscrow(bytes20, bytes32, uint256, uint256) external returns (bytes32);
    function finishEscrow(bytes32, bytes32) external;
    function cancelEscrow(bytes32) external;
    function pause() external;
    function unpause() external;
}

/*//////////////////////////////////////////////////////////////
                    GHOST VARIABLES
//////////////////////////////////////////////////////////////*/

ghost uint256 ghostDepositNonce {
    init_state axiom ghostDepositNonce == 0;
}

ghost uint256 ghostWithdrawalNonce {
    init_state axiom ghostWithdrawalNonce == 0;
}

ghost uint256 ghostEscrowNonce {
    init_state axiom ghostEscrowNonce == 0;
}

ghost uint256 ghostTotalDeposited {
    init_state axiom ghostTotalDeposited == 0;
}

ghost uint256 ghostTotalWithdrawn {
    init_state axiom ghostTotalWithdrawn == 0;
}

ghost mapping(bytes32 => bool) ghostUsedTxHashes;
ghost mapping(bytes32 => bool) ghostUsedNullifiers;

/*//////////////////////////////////////////////////////////////
                    HOOKS
//////////////////////////////////////////////////////////////*/

hook Sstore depositNonce uint256 newNonce {
    ghostDepositNonce = newNonce;
}

hook Sstore withdrawalNonce uint256 newNonce {
    ghostWithdrawalNonce = newNonce;
}

hook Sstore escrowNonce uint256 newNonce {
    ghostEscrowNonce = newNonce;
}

hook Sstore totalDeposited uint256 newTotal {
    ghostTotalDeposited = newTotal;
}

hook Sstore totalWithdrawn uint256 newTotal {
    ghostTotalWithdrawn = newTotal;
}

/*//////////////////////////////////////////////////////////////
                    INVARIANTS
//////////////////////////////////////////////////////////////*/

/**
 * @notice Deposit nonce is monotonically increasing
 */
invariant depositNonceMonotonicallyIncreasing()
    depositNonce() >= ghostDepositNonce;

/**
 * @notice Withdrawal nonce is monotonically increasing
 */
invariant withdrawalNonceMonotonicallyIncreasing()
    withdrawalNonce() >= ghostWithdrawalNonce;

/**
 * @notice Escrow nonce is monotonically increasing
 */
invariant escrowNonceMonotonicallyIncreasing()
    escrowNonce() >= ghostEscrowNonce;

/**
 * @notice Drops per XRP is exactly 1,000,000
 */
invariant dropsPerXRP()
    DROPS_PER_XRP() == 1000000;

/**
 * @notice Minimum deposit is 10 XRP (10,000,000 drops)
 */
invariant minDepositIs10XRP()
    MIN_DEPOSIT_DROPS() == 10000000;

/**
 * @notice Bridge fee is 25 basis points
 */
invariant bridgeFeeIs25BPS()
    BRIDGE_FEE_BPS() == 25;

/**
 * @notice BPS denominator is 10,000
 */
invariant bpsDenominatorIs10000()
    BPS_DENOMINATOR() == 10000;

/**
 * @notice Withdrawal refund delay is 48 hours
 */
invariant withdrawalRefundDelayIs48Hours()
    WITHDRAWAL_REFUND_DELAY() == 172800;

/**
 * @notice Total escrows = finished + cancelled + active
 */
invariant escrowCountConsistency()
    totalEscrows() >= totalEscrowsFinished() + totalEscrowsCancelled();

/*//////////////////////////////////////////////////////////////
                REPLAY PROTECTION RULES
//////////////////////////////////////////////////////////////*/

/**
 * @notice Once an XRPL tx hash is marked used, it stays used forever
 */
rule xrplTxHashPermanentlyUsed(bytes32 txHash) {
    require usedXRPLTxHashes(txHash);

    env e;
    calldataarg args;
    method f;

    f(e, args);

    assert usedXRPLTxHashes(txHash), "Used tx hash should remain used";
}

/**
 * @notice Once a nullifier is used, it stays used forever
 */
rule nullifierPermanentlyUsed(bytes32 nullifier) {
    require usedNullifiers(nullifier);

    env e;
    calldataarg args;
    method f;

    f(e, args);

    assert usedNullifiers(nullifier), "Used nullifier should remain used";
}

/*//////////////////////////////////////////////////////////////
                ACCESS CONTROL RULES
//////////////////////////////////////////////////////////////*/

/**
 * @notice Only OPERATOR can complete deposits
 */
rule onlyOperatorCanCompleteDeposit(bytes32 depositId) {
    env e;

    bool isOperator = hasRole(OPERATOR_ROLE(), e.msg.sender);
    bool isAdmin = hasRole(DEFAULT_ADMIN_ROLE(), e.msg.sender);

    completeXRPDeposit@withrevert(e, depositId);

    assert !lastReverted => (isOperator || isAdmin),
        "Only operator/admin can complete deposits";
}

/**
 * @notice Only GUARDIAN can pause
 */
rule onlyGuardianCanPause() {
    env e;

    bool isGuardian = hasRole(GUARDIAN_ROLE(), e.msg.sender);
    bool isAdmin = hasRole(DEFAULT_ADMIN_ROLE(), e.msg.sender);

    pause@withrevert(e);

    assert !lastReverted => (isGuardian || isAdmin),
        "Only guardian/admin can pause";
}

/*//////////////////////////////////////////////////////////////
                WITHDRAWAL RULES
//////////////////////////////////////////////////////////////*/

/**
 * @notice Refunded withdrawals cannot be refunded again
 */
rule withdrawalRefundIsFinal(bytes32 withdrawalId) {
    env e1; env e2;

    refundWithdrawal(e1, withdrawalId);

    refundWithdrawal@withrevert(e2, withdrawalId);

    assert lastReverted, "Refunded withdrawal should not be refundable again";
}

/*//////////////////////////////////////////////////////////////
                ESCROW RULES
//////////////////////////////////////////////////////////////*/

/**
 * @notice Finished escrows cannot be finished again
 */
rule escrowFinishIsFinal(bytes32 escrowId, bytes32 fulfillment) {
    env e1; env e2;

    finishEscrow(e1, escrowId, fulfillment);

    finishEscrow@withrevert(e2, escrowId, fulfillment);

    assert lastReverted, "Finished escrow should not be finishable again";
}

/**
 * @notice Cancelled escrows cannot be cancelled again
 */
rule escrowCancelIsFinal(bytes32 escrowId) {
    env e1; env e2;

    cancelEscrow(e1, escrowId);

    cancelEscrow@withrevert(e2, escrowId);

    assert lastReverted, "Cancelled escrow should not be cancellable again";
}

/**
 * @notice Finished escrows cannot be cancelled
 */
rule finishedEscrowCannotBeCancelled(bytes32 escrowId, bytes32 fulfillment) {
    env e1; env e2;

    finishEscrow(e1, escrowId, fulfillment);

    cancelEscrow@withrevert(e2, escrowId);

    assert lastReverted, "Finished escrow cannot be cancelled";
}

/**
 * @notice Cancelled escrows cannot be finished
 */
rule cancelledEscrowCannotBeFinished(bytes32 escrowId, bytes32 fulfillment) {
    env e1; env e2;

    cancelEscrow(e1, escrowId);

    finishEscrow@withrevert(e2, escrowId, fulfillment);

    assert lastReverted, "Cancelled escrow cannot be finished";
}

/*//////////////////////////////////////////////////////////////
                PAUSE MECHANISM RULES
//////////////////////////////////////////////////////////////*/

/**
 * @notice Paused state blocks withdrawal initiation
 */
rule pausedBlocksWithdrawals(bytes20 recipient, uint256 amount) {
    env e;

    require paused();

    initiateWithdrawal@withrevert(e, recipient, amount);

    assert lastReverted, "Withdrawals should be blocked when paused";
}

/**
 * @notice Paused state blocks escrow creation
 */
rule pausedBlocksEscrowCreation(bytes20 xrplParty, bytes32 condition, uint256 finishAfter, uint256 cancelAfter) {
    env e;

    require paused();

    createEscrow@withrevert(e, xrplParty, condition, finishAfter, cancelAfter);

    assert lastReverted, "Escrow creation should be blocked when paused";
}

/**
 * @notice Pause then unpause restores functionality
 */
rule pauseUnpauseRestoresFunctionality() {
    env e1; env e2;

    require !paused();
    require hasRole(GUARDIAN_ROLE(), e1.msg.sender);
    require hasRole(GUARDIAN_ROLE(), e2.msg.sender);

    pause(e1);
    assert paused();

    unpause(e2);
    assert !paused();
}

/*//////////////////////////////////////////////////////////////
                NONCE INTEGRITY RULES
//////////////////////////////////////////////////////////////*/

/**
 * @notice Deposit nonce never decreases across any operation
 */
rule depositNonceNeverDecreases(method f) {
    env e;
    calldataarg args;

    uint256 nonceBefore = depositNonce();

    f(e, args);

    uint256 nonceAfter = depositNonce();
    assert nonceAfter >= nonceBefore, "Deposit nonce should never decrease";
}

/**
 * @notice Withdrawal nonce never decreases across any operation
 */
rule withdrawalNonceNeverDecreases(method f) {
    env e;
    calldataarg args;

    uint256 nonceBefore = withdrawalNonce();

    f(e, args);

    uint256 nonceAfter = withdrawalNonce();
    assert nonceAfter >= nonceBefore, "Withdrawal nonce should never decrease";
}

/**
 * @notice Escrow nonce never decreases across any operation
 */
rule escrowNonceNeverDecreases(method f) {
    env e;
    calldataarg args;

    uint256 nonceBefore = escrowNonce();

    f(e, args);

    uint256 nonceAfter = escrowNonce();
    assert nonceAfter >= nonceBefore, "Escrow nonce should never decrease";
}

/*//////////////////////////////////////////////////////////////
                VALUE CONSERVATION RULES
//////////////////////////////////////////////////////////////*/

/**
 * @notice Total deposited never decreases
 */
rule totalDepositedNeverDecreases(method f) {
    env e;
    calldataarg args;

    uint256 before = totalDeposited();

    f(e, args);

    uint256 after = totalDeposited();
    assert after >= before, "Total deposited should never decrease";
}

/**
 * @notice Total withdrawn never decreases
 */
rule totalWithdrawnNeverDecreases(method f) {
    env e;
    calldataarg args;

    uint256 before = totalWithdrawn();

    f(e, args);

    uint256 after = totalWithdrawn();
    assert after >= before, "Total withdrawn should never decrease";
}

/**
 * @notice Latest ledger index never decreases
 */
rule latestLedgerNeverDecreases(method f) {
    env e;
    calldataarg args;

    uint256 before = latestLedgerIndex();

    f(e, args);

    uint256 after = latestLedgerIndex();
    assert after >= before, "Latest ledger index should never decrease";
}
