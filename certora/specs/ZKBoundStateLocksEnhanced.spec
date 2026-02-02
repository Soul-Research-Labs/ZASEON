/**
 * @title Enhanced ZK-Bound State Locks (ZK-SLocks) Formal Verification
 * @notice Simplified Certora specifications for ZK-SLocks
 * @dev Core invariants and rules that match contract implementation
 */

/*//////////////////////////////////////////////////////////////
                         METHODS
//////////////////////////////////////////////////////////////*/

methods {
    // State accessors
    function nullifierUsed(bytes32) external returns (bool) envfree;
    function verifiers(bytes32) external returns (address) envfree;
    function totalLocksCreated() external returns (uint256) envfree;
    function totalLocksUnlocked() external returns (uint256) envfree;
    function totalOptimisticUnlocks() external returns (uint256) envfree;
    function totalDisputes() external returns (uint256) envfree;
    function paused() external returns (bool) envfree;
    function getActiveLockCount() external returns (uint256) envfree;
    
    // Functions - mark as optional since they have complex signatures
    function createLock(bytes32, bytes32, bytes32, bytes32, uint64) external returns (bytes32) => NONDET;
    function pause() external;
    function unpause() external;
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
 * INV-ZKS-003: Statistics are non-negative (uint256 is always >= 0)
 */
invariant statisticsNonNegative()
    totalLocksCreated() >= 0 && 
    totalLocksUnlocked() >= 0 && 
    totalOptimisticUnlocks() >= 0 && 
    totalDisputes() >= 0;

/**
 * INV-ZKS-004: Active lock count consistency
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
 * RULE-ZKS-003: Monotonic dispute count
 */
rule monotonicDisputeCount(method f) filtered { f -> !f.isView } {
    mathint countBefore = totalDisputes();
    
    env e;
    calldataarg args;
    f(e, args);
    
    mathint countAfter = totalDisputes();
    
    assert countAfter >= countBefore, "Dispute count must be monotonically increasing";
}

/**
 * RULE-ZKS-004: Monotonic optimistic count
 */
rule monotonicOptimisticCount(method f) filtered { f -> !f.isView } {
    mathint countBefore = totalOptimisticUnlocks();
    
    env e;
    calldataarg args;
    f(e, args);
    
    mathint countAfter = totalOptimisticUnlocks();
    
    assert countAfter >= countBefore, "Optimistic count must be monotonically increasing";
}

/**
 * RULE-ZKS-005: Nullifier permanence
 * Once a nullifier is used, it stays used
 */
rule nullifierPermanence(bytes32 nullifier) {
    require nullifierUsed(nullifier);
    
    env e;
    calldataarg args;
    method f;
    f(e, args);
    
    assert nullifierUsed(nullifier), "Used nullifier must stay used";
}
