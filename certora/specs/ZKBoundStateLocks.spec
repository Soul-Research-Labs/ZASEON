/**
 * Certora Formal Verification Specification
 * Soul Protocol - ZKBoundStateLocks (ZK-SLocks)
 */

methods {
    // View functions
    function nullifierUsed(bytes32) external returns (bool) envfree;
    function verifiers(bytes32) external returns (address) envfree;
    function totalLocksCreated() external returns (uint256) envfree;
    function totalLocksUnlocked() external returns (uint256) envfree;
    function totalOptimisticUnlocks() external returns (uint256) envfree;
    function totalDisputes() external returns (uint256) envfree;
    function paused() external returns (bool) envfree;
    function getActiveLockCount() external returns (uint256) envfree;
}

/*//////////////////////////////////////////////////////////////
                        INVARIANTS
//////////////////////////////////////////////////////////////*/

/**
 * INV-ZKS-001: Total unlocks cannot exceed total created
 */
invariant unlocksCannotExceedCreated()
    totalLocksUnlocked() <= totalLocksCreated();

/**
 * INV-ZKS-002: Disputes cannot exceed optimistic unlocks
 */
invariant disputesCannotExceedOptimistic()
    totalDisputes() <= totalOptimisticUnlocks();

/**
 * INV-ZKS-003: Active locks bounded by created
 */
invariant activeLockBound()
    getActiveLockCount() <= totalLocksCreated();

/*//////////////////////////////////////////////////////////////
                          RULES
//////////////////////////////////////////////////////////////*/

/**
 * RULE-ZKS-001: Monotonic lock creation
 */
rule monotonicLockCreation(method f) filtered { f -> !f.isView } {
    mathint countBefore = totalLocksCreated();
    
    env e;
    calldataarg args;
    f(e, args);
    
    mathint countAfter = totalLocksCreated();
    
    assert countAfter >= countBefore, "Lock count must be monotonically increasing";
}

/**
 * RULE-ZKS-002: Monotonic unlock count
 */
rule monotonicUnlockCount(method f) filtered { f -> !f.isView } {
    mathint countBefore = totalLocksUnlocked();
    
    env e;
    calldataarg args;
    f(e, args);
    
    mathint countAfter = totalLocksUnlocked();
    
    assert countAfter >= countBefore, "Unlock count must be monotonically increasing";
}

/**
 * RULE-ZKS-003: Nullifier permanence
 */
rule nullifierPermanence(bytes32 nullifier) {
    require nullifierUsed(nullifier);
    
    env e;
    calldataarg args;
    method f;
    f(e, args);
    
    assert nullifierUsed(nullifier), "Used nullifier must stay used";
}
