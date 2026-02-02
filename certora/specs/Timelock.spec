/**
 * Certora Formal Verification Specification
 * Soul Protocol - SoulUpgradeTimelock
 */

using SoulUpgradeTimelock as timelock;

methods {
    // View functions
    function STANDARD_DELAY() external returns (uint256) envfree;
    function EXTENDED_DELAY() external returns (uint256) envfree;
    function EMERGENCY_DELAY() external returns (uint256) envfree;
    function EXIT_WINDOW() external returns (uint256) envfree;
    function MAX_DELAY() external returns (uint256) envfree;
    function minSignatures() external returns (uint256) envfree;
    function hasRole(bytes32, address) external returns (bool) envfree;
    function signatureCount(bytes32) external returns (uint256) envfree;
    function upgradeFrozen(address) external returns (bool) envfree;
}

/*//////////////////////////////////////////////////////////////
                        INVARIANTS
//////////////////////////////////////////////////////////////*/

/**
 * INV-TIME-001: Delay ordering
 */
invariant delayOrdering()
    EMERGENCY_DELAY() < STANDARD_DELAY() && 
    STANDARD_DELAY() < EXTENDED_DELAY() &&
    EXTENDED_DELAY() <= MAX_DELAY();

/**
 * INV-TIME-002: Minimum signatures positive
 */
invariant minSignaturesPositive()
    minSignatures() >= 1;

/*//////////////////////////////////////////////////////////////
                          RULES
//////////////////////////////////////////////////////////////*/

/**
 * RULE-TIME-001: Frozen contracts stay frozen
 */
rule frozenPermanence(address target) {
    require upgradeFrozen(target);
    
    env e;
    calldataarg args;
    method f;
    f(e, args);
    
    assert upgradeFrozen(target), "Frozen contracts must stay frozen";
}
