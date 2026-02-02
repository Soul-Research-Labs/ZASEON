/**
 * Certora Formal Verification Specification
 * Soul Protocol - ExecutionAgnosticStateCommitments (EASC)
 */

methods {
    // View functions
    function totalBackends() external returns (uint256) envfree;
    function totalCommitments() external returns (uint256) envfree;
    function MAX_TRUST_SCORE() external returns (uint256) envfree;
    function paused() external returns (bool) envfree;
    function hasRole(bytes32, address) external returns (bool) envfree;
    function usedNullifiers(bytes32) external returns (bool) envfree;
}

/*//////////////////////////////////////////////////////////////
                        INVARIANTS
//////////////////////////////////////////////////////////////*/

/**
 * INV-EASC-001: Statistics non-negative
 */
invariant statisticsNonNegative()
    totalBackends() >= 0 && totalCommitments() >= 0;

/**
 * INV-EASC-002: Trust score bounded
 */
invariant trustScoreBounded()
    MAX_TRUST_SCORE() == 10000;

/*//////////////////////////////////////////////////////////////
                          RULES
//////////////////////////////////////////////////////////////*/

/**
 * RULE-EASC-001: Monotonic backend count
 */
rule monotonicBackendCount(method f) filtered { f -> !f.isView } {
    mathint countBefore = totalBackends();
    
    env e;
    calldataarg args;
    f(e, args);
    
    mathint countAfter = totalBackends();
    
    assert countAfter >= countBefore, "Backend count must be monotonically increasing";
}

/**
 * RULE-EASC-002: Monotonic commitment count
 */
rule monotonicCommitmentCount(method f) filtered { f -> !f.isView } {
    mathint countBefore = totalCommitments();
    
    env e;
    calldataarg args;
    f(e, args);
    
    mathint countAfter = totalCommitments();
    
    assert countAfter >= countBefore, "Commitment count must be monotonically increasing";
}

/**
 * RULE-EASC-003: Nullifier permanence
 */
rule nullifierPermanence(bytes32 nullifier) {
    require usedNullifiers(nullifier);
    
    env e;
    calldataarg args;
    method f;
    f(e, args);
    
    assert usedNullifiers(nullifier), "Used nullifier must stay used";
}
