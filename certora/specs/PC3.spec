/**
 * Certora Formal Verification Specification
 * Soul Protocol - ProofCarryingContainer (PC3)
 */

methods {
    // State accessors
    function totalContainers() external returns (uint256) envfree;
    function totalVerified() external returns (uint256) envfree;
    function paused() external returns (bool) envfree;
    function hasRole(bytes32, address) external returns (bool) envfree;
    function isNullifierConsumed(bytes32) external returns (bool) envfree;
}

/*//////////////////////////////////////////////////////////////
                        INVARIANTS
//////////////////////////////////////////////////////////////*/

/**
 * INV-PC3-001: Verified cannot exceed total containers
 */
invariant verifiedCannotExceedTotal()
    totalVerified() <= totalContainers();

/**
 * INV-PC3-002: Statistics non-negative (uint256 always >= 0)
 */
invariant statisticsNonNegative()
    totalContainers() >= 0 && totalVerified() >= 0;

/*//////////////////////////////////////////////////////////////
                          RULES
//////////////////////////////////////////////////////////////*/

/**
 * RULE-PC3-001: Monotonic container creation
 */
rule monotonicContainerCreation(method f) filtered { f -> !f.isView } {
    mathint countBefore = totalContainers();
    
    env e;
    calldataarg args;
    f(e, args);
    
    mathint countAfter = totalContainers();
    
    assert countAfter >= countBefore, "Container count must be monotonically increasing";
}

/**
 * RULE-PC3-002: Monotonic verified count
 */
rule monotonicVerifiedCount(method f) filtered { f -> !f.isView } {
    mathint countBefore = totalVerified();
    
    env e;
    calldataarg args;
    f(e, args);
    
    mathint countAfter = totalVerified();
    
    assert countAfter >= countBefore, "Verified count must be monotonically increasing";
}

/**
 * RULE-PC3-003: Nullifier permanence
 */
rule nullifierPermanence(bytes32 nullifier) {
    require isNullifierConsumed(nullifier);
    
    env e;
    calldataarg args;
    method f;
    f(e, args);
    
    assert isNullifierConsumed(nullifier), "Consumed nullifier must stay consumed";
}
