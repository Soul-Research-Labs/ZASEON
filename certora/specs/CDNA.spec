/**
 * Certora Formal Verification Specification
 * Soul Protocol - CrossDomainNullifierAlgebra (CDNA)
 */

methods {
    // View functions
    function totalDomains() external returns (uint256) envfree;
    function totalNullifiers() external returns (uint256) envfree;
    function totalCrossLinks() external returns (uint256) envfree;
    function paused() external returns (bool) envfree;
    function hasRole(bytes32, address) external returns (bool) envfree;
    function nullifierExists(bytes32) external returns (bool) envfree;
}

/*//////////////////////////////////////////////////////////////
                        INVARIANTS
//////////////////////////////////////////////////////////////*/

/**
 * INV-CDNA-001: Statistics non-negative
 */
invariant statisticsNonNegative()
    totalDomains() >= 0 && totalNullifiers() >= 0 && totalCrossLinks() >= 0;

/*//////////////////////////////////////////////////////////////
                          RULES
//////////////////////////////////////////////////////////////*/

/**
 * RULE-CDNA-001: Monotonic domain count
 */
rule monotonicDomainCount(method f) filtered { f -> !f.isView } {
    mathint countBefore = totalDomains();
    
    env e;
    calldataarg args;
    f(e, args);
    
    mathint countAfter = totalDomains();
    
    assert countAfter >= countBefore, "Domain count must be monotonically increasing";
}

/**
 * RULE-CDNA-002: Monotonic nullifier count
 */
rule monotonicNullifierCount(method f) filtered { f -> !f.isView } {
    mathint countBefore = totalNullifiers();
    
    env e;
    calldataarg args;
    f(e, args);
    
    mathint countAfter = totalNullifiers();
    
    assert countAfter >= countBefore, "Nullifier count must be monotonically increasing";
}

/**
 * RULE-CDNA-003: Nullifier permanence
 */
rule nullifierPermanence(bytes32 nullifier) {
    require nullifierExists(nullifier);
    
    env e;
    calldataarg args;
    method f;
    f(e, args);
    
    assert nullifierExists(nullifier), "Existing nullifier must stay existing";
}
