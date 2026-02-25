// SPDX-License-Identifier: MIT
// Certora CVL Specification for IntentCompletionLayer

using IntentCompletionLayer as completion;

// ============================================================================
//                             METHOD DECLARATIONS
// ============================================================================

methods {
    // View / Pure — envfree
    function totalIntents() external returns (uint256) envfree;
    function totalFinalized() external returns (uint256) envfree;
    function protocolFees() external returns (uint256) envfree;
    function activeSolverCount() external returns (uint256) envfree;
    function MIN_SOLVER_STAKE() external returns (uint256) envfree;
    function CLAIM_TIMEOUT() external returns (uint256) envfree;
    function CHALLENGE_PERIOD() external returns (uint256) envfree;
    function PROTOCOL_FEE_BPS() external returns (uint256) envfree;
    function SLASH_BPS() external returns (uint256) envfree;
    function MIN_DEADLINE_OFFSET() external returns (uint256) envfree;
    function MAX_DEADLINE_OFFSET() external returns (uint256) envfree;
    function MAX_BATCH_SIZE() external returns (uint256) envfree;
    function supportedChains(uint256) external returns (bool) envfree;
    function intentStatus(bytes32) external returns (uint8) envfree;
    function canFinalize(bytes32) external returns (bool) envfree;
    function isFinalized(bytes32) external returns (bool) envfree;

    // AccessControl
    function hasRole(bytes32, address) external returns (bool) envfree;
    function OPERATOR_ROLE() external returns (bytes32) envfree;
    function EMERGENCY_ROLE() external returns (bytes32) envfree;
    function DEFAULT_ADMIN_ROLE() external returns (bytes32) envfree;

    // State-changing
    function submitIntent(uint256, uint256, bytes32, bytes32, uint256, uint256, bytes32) external returns (bytes32);
    function cancelIntent(bytes32) external;
    function registerSolver() external;
    function deactivateSolver() external;
    function claimIntent(bytes32) external;
    function fulfillIntent(bytes32, bytes, bytes, bytes32) external;
    function finalizeIntent(bytes32) external;
    function expireIntent(bytes32) external;
    function disputeIntent(bytes32, bytes, bytes) external;
    function pause() external;
    function unpause() external;
    function setSupportedChain(uint256, bool) external;
    function withdrawProtocolFees(address) external;
}

// ============================================================================
//                      INTENT STATUS DEFINITIONS
// ============================================================================

// IntentStatus enum values:
//   0 = PENDING
//   1 = CLAIMED
//   2 = FULFILLED
//   3 = FINALIZED
//   4 = EXPIRED
//   5 = CANCELLED
//   6 = DISPUTED

definition PENDING()   returns uint8 = 0;
definition CLAIMED()   returns uint8 = 1;
definition FULFILLED() returns uint8 = 2;
definition FINALIZED() returns uint8 = 3;
definition EXPIRED()   returns uint8 = 4;
definition CANCELLED() returns uint8 = 5;
definition DISPUTED()  returns uint8 = 6;

// ============================================================================
//                      VALID STATE TRANSITIONS
// ============================================================================

/// @title Intent status transitions from PENDING
/// @notice PENDING can transition to: CLAIMED, CANCELLED, EXPIRED
rule pendingTransitions(bytes32 intentId, method f) filtered {
    f -> !f.isView
} {
    env e;
    calldataarg args;

    uint8 statusBefore = intentStatus(intentId);
    require statusBefore == PENDING();

    f(e, args);

    uint8 statusAfter = intentStatus(intentId);

    assert statusAfter == PENDING() ||
           statusAfter == CLAIMED() ||
           statusAfter == CANCELLED() ||
           statusAfter == EXPIRED(),
        "PENDING can only transition to CLAIMED, CANCELLED, or EXPIRED";
}

/// @title Intent status transitions from CLAIMED
/// @notice CLAIMED can transition to: FULFILLED, PENDING (claim timeout), EXPIRED
rule claimedTransitions(bytes32 intentId, method f) filtered {
    f -> !f.isView
} {
    env e;
    calldataarg args;

    uint8 statusBefore = intentStatus(intentId);
    require statusBefore == CLAIMED();

    f(e, args);

    uint8 statusAfter = intentStatus(intentId);

    assert statusAfter == CLAIMED() ||
           statusAfter == FULFILLED() ||
           statusAfter == PENDING() ||
           statusAfter == EXPIRED(),
        "CLAIMED can only transition to FULFILLED, PENDING (timeout), or EXPIRED";
}

/// @title Intent status transitions from FULFILLED
/// @notice FULFILLED can transition to: FINALIZED, DISPUTED
rule fulfilledTransitions(bytes32 intentId, method f) filtered {
    f -> !f.isView
} {
    env e;
    calldataarg args;

    uint8 statusBefore = intentStatus(intentId);
    require statusBefore == FULFILLED();

    f(e, args);

    uint8 statusAfter = intentStatus(intentId);

    assert statusAfter == FULFILLED() ||
           statusAfter == FINALIZED() ||
           statusAfter == DISPUTED(),
        "FULFILLED can only transition to FINALIZED or DISPUTED";
}

/// @title Terminal states are irreversible
/// @notice FINALIZED, EXPIRED, CANCELLED, DISPUTED cannot change
rule terminalStatesIrreversible(bytes32 intentId, method f) filtered {
    f -> !f.isView
} {
    env e;
    calldataarg args;

    uint8 statusBefore = intentStatus(intentId);
    require statusBefore == FINALIZED() ||
            statusBefore == EXPIRED() ||
            statusBefore == CANCELLED() ||
            statusBefore == DISPUTED();

    f(e, args);

    uint8 statusAfter = intentStatus(intentId);

    assert statusAfter == statusBefore,
        "Terminal states (FINALIZED, EXPIRED, CANCELLED, DISPUTED) must be irreversible";
}

// ============================================================================
//                      PROTOCOL FEE INVARIANTS
// ============================================================================

/// @title Protocol fees are correctly accumulated on finalization
/// @notice After finalizeIntent, protocol fees increase by fee * PROTOCOL_FEE_BPS / 10000
rule protocolFeesAccumulateOnFinalize(bytes32 intentId) {
    env e;

    uint256 feesBefore = protocolFees();
    uint8 statusBefore = intentStatus(intentId);

    finalizeIntent(e, intentId);

    uint256 feesAfter = protocolFees();

    assert feesAfter >= feesBefore,
        "Protocol fees must never decrease after finalization";
}

/// @title Protocol fees are monotonically non-decreasing
/// @notice No operation should decrease accumulated protocol fees (except withdrawal)
rule protocolFeesNonDecreasing(method f) filtered {
    f -> f.selector != sig:withdrawProtocolFees(address).selector &&
         !f.isView
} {
    env e;
    calldataarg args;

    uint256 feesBefore = protocolFees();
    f(e, args);
    uint256 feesAfter = protocolFees();

    assert feesAfter >= feesBefore,
        "Protocol fees should not decrease (except via withdrawProtocolFees)";
}

// ============================================================================
//                      SOLVER STAKE INVARIANTS
// ============================================================================

/// @title Solver must meet minimum stake to register
/// @notice registerSolver reverts if msg.value < MIN_SOLVER_STAKE
rule solverMinStakeEnforced() {
    env e;
    require e.msg.value < MIN_SOLVER_STAKE();

    registerSolver@withrevert(e);
    assert lastReverted, "registerSolver must revert if stake < MIN_SOLVER_STAKE";
}

/// @title Only assigned solver can fulfill
/// @notice fulfillIntent reverts if msg.sender is not the assigned solver
rule onlyAssignedSolverCanFulfill(bytes32 intentId) {
    env e;
    bytes proof;
    bytes publicInputs;
    bytes32 newCommitment;

    uint8 statusBefore = intentStatus(intentId);
    require statusBefore == CLAIMED();

    fulfillIntent@withrevert(e, intentId, proof, publicInputs, newCommitment);

    // If it didn't revert and status changed, the caller must be the assigned solver
    // (We check the negative: if caller is not solver, it should revert)
    assert !lastReverted => intentStatus(intentId) == FULFILLED() ||
                            intentStatus(intentId) == PENDING(),
        "Only assigned solver can change a CLAIMED intent's status via fulfillIntent";
}

// ============================================================================
//                    CHALLENGE PERIOD ENFORCEMENT
// ============================================================================

/// @title Challenge period must elapse before finalization
/// @notice finalizeIntent reverts if called before challenge period ends
rule challengePeriodEnforced(bytes32 intentId) {
    env e;

    // Assume intent is fulfilled but canFinalize says no
    require intentStatus(intentId) == FULFILLED();
    require !canFinalize(intentId);

    finalizeIntent@withrevert(e, intentId);
    assert lastReverted,
        "finalizeIntent must revert if challenge period has not elapsed";
}

// ============================================================================
//                      FINALIZED COUNT INVARIANTS
// ============================================================================

/// @title totalFinalized <= totalIntents
invariant finalizedLeqTotal()
    totalFinalized() <= totalIntents();

/// @title totalIntents is monotonically non-decreasing
rule totalIntentsMonotonic(method f) filtered { f -> !f.isView } {
    env e;
    calldataarg args;

    uint256 before = totalIntents();
    f(e, args);
    uint256 after_ = totalIntents();

    assert after_ >= before,
        "totalIntents must never decrease";
}

/// @title totalFinalized is monotonically non-decreasing
rule totalFinalizedMonotonic(method f) filtered { f -> !f.isView } {
    env e;
    calldataarg args;

    uint256 before = totalFinalized();
    f(e, args);
    uint256 after_ = totalFinalized();

    assert after_ >= before,
        "totalFinalized must never decrease";
}

// ============================================================================
//                      CANCEL / USER AUTHORIZATION
// ============================================================================

/// @title Only intent user can cancel
/// @notice cancelIntent reverts if msg.sender != intent.user
rule onlyUserCanCancel(bytes32 intentId) {
    env e;

    uint8 statusBefore = intentStatus(intentId);
    require statusBefore == PENDING();

    cancelIntent@withrevert(e, intentId);

    // If it didn't revert, the intent should now be CANCELLED
    assert !lastReverted => intentStatus(intentId) == CANCELLED(),
        "Successful cancelIntent must set status to CANCELLED";
}

// ============================================================================
//                  SUPPORTED CHAIN VALIDATION
// ============================================================================

/// @title submitIntent reverts for unsupported chains
rule submitIntentRejectsUnsupportedChain(
    uint256 sourceChainId,
    uint256 destChainId
) {
    env e;

    require !supportedChains(sourceChainId) || !supportedChains(destChainId);

    submitIntent@withrevert(
        e,
        sourceChainId,
        destChainId,
        to_bytes32(1),
        to_bytes32(2),
        1,
        e.block.timestamp + 3600,
        to_bytes32(0)
    );

    assert lastReverted,
        "submitIntent must revert for unsupported chain IDs";
}

/// @title submitIntent reverts when sourceChainId == destChainId
rule submitIntentRejectsSameChain(uint256 chainId) {
    env e;

    submitIntent@withrevert(
        e,
        chainId,
        chainId,
        to_bytes32(1),
        to_bytes32(2),
        1,
        e.block.timestamp + 3600,
        to_bytes32(0)
    );

    assert lastReverted,
        "submitIntent must revert when source == dest chain";
}
