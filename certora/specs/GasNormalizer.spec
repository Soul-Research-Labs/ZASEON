/**
 * Certora Formal Verification Specification
 * Soul Protocol - GasNormalizer
 *
 * This spec verifies critical invariants for the Gas Normalizer
 * which normalizes gas consumption to prevent gas-based deanonymization
 * attacks by ensuring constant gas usage for all privacy operations.
 */

using GasNormalizer as gn;

// ============================================================================
// METHODS
// ============================================================================

methods {
    // View / pure functions
    function normalizationEnabled() external returns (bool) envfree;
    function authorizedCallers(address) external returns (bool) envfree;
    function paused() external returns (bool) envfree;
    function hasRole(bytes32, address) external returns (bool) envfree;
    function OPERATOR_ROLE() external returns (bytes32) envfree;
    function UPGRADER_ROLE() external returns (bytes32) envfree;
    function STANDARD_GAS_TARGET() external returns (uint256) envfree;
    function HIGH_GAS_TARGET() external returns (uint256) envfree;
    function MAX_GAS_TARGET() external returns (uint256) envfree;
    function NORMALIZATION_OVERHEAD() external returns (uint256) envfree;
    function GAS_PER_ITERATION() external returns (uint256) envfree;

    // State-changing functions
    function executeNormalized(address, bytes, uint8, bytes32) external;
    function burnGas(uint256) external;
    function setGasProfile(uint8, uint256, bool) external;
    function setNormalizationEnabled(bool) external;
}

// ============================================================================
// GHOST VARIABLES
// ============================================================================

ghost uint256 ghostTotalExecutions {
    init_state axiom ghostTotalExecutions == 0;
}

ghost bool ghostNormalizationEnabled {
    init_state axiom ghostNormalizationEnabled == false;
}

ghost mapping(address => bool) ghostAuthorizedCallers {
    init_state axiom forall address a. !ghostAuthorizedCallers[a];
}

// ============================================================================
// INVARIANTS
// ============================================================================

/**
 * @title Gas Target Constants Are Ordered
 * @notice STANDARD_GAS_TARGET < HIGH_GAS_TARGET < MAX_GAS_TARGET
 */
invariant gasTargetOrdering()
    STANDARD_GAS_TARGET() < HIGH_GAS_TARGET() &&
    HIGH_GAS_TARGET() < MAX_GAS_TARGET();

/**
 * @title Standard Gas Target Is Positive
 * @notice STANDARD_GAS_TARGET must be greater than zero
 */
invariant standardGasTargetPositive()
    STANDARD_GAS_TARGET() > 0;

/**
 * @title Normalization Overhead Below Standard Target
 * @notice NORMALIZATION_OVERHEAD must be less than STANDARD_GAS_TARGET
 * TODO: Verify this is maintained after any gas profile updates
 */
invariant overheadBelowTarget()
    NORMALIZATION_OVERHEAD() < STANDARD_GAS_TARGET();

// ============================================================================
// RULES
// ============================================================================

/**
 * @title Only Operator Can Toggle Normalization
 * @notice setNormalizationEnabled should revert for non-operators
 * TODO: Verify exact role check behavior
 */
rule onlyOperatorTogglesNormalization(bool enabled) {
    env e;
    require !hasRole(OPERATOR_ROLE(), e.msg.sender);
    require !hasRole(gn.DEFAULT_ADMIN_ROLE(), e.msg.sender);

    setNormalizationEnabled@withrevert(e, enabled);

    assert lastReverted,
        "Only operator should toggle normalization";
}

/**
 * @title Normalization Toggle Changes State
 * @notice setNormalizationEnabled should update the flag
 * TODO: Verify exact state change semantics
 */
rule normalizationToggleChangesState(bool enabled) {
    env e;
    require hasRole(OPERATOR_ROLE(), e.msg.sender);

    setNormalizationEnabled(e, enabled);

    assert normalizationEnabled() == enabled,
        "normalizationEnabled should match the set value";
}
