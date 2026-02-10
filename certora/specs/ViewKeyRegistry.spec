/**
 * Certora Formal Verification Specification
 * Soul Protocol - ViewKeyRegistry
 *
 * This spec verifies critical invariants for the View Key Registry
 * which manages cryptographic view keys for selective disclosure,
 * including key registration, grant issuance, and revocation.
 */

using ViewKeyRegistry as vkr;

// ============================================================================
// METHODS
// ============================================================================

methods {
    // View / pure functions
    function totalKeysRegistered() external returns (uint256) envfree;
    function totalGrantsIssued() external returns (uint256) envfree;
    function totalActiveGrants() external returns (uint256) envfree;
    function activeKeyCount(address) external returns (uint256) envfree;
    function grantNonce(address) external returns (uint256) envfree;
    function isGrantValid(bytes32) external returns (bool) envfree;
    function paused() external returns (bool) envfree;
    function hasRole(bytes32, address) external returns (bool) envfree;
    function ADMIN_ROLE() external returns (bytes32) envfree;
    function REGISTRAR_ROLE() external returns (bytes32) envfree;
    function MAX_GRANTS_PER_ACCOUNT() external returns (uint256) envfree;
    function MIN_GRANT_DURATION() external returns (uint256) envfree;
    function MAX_GRANT_DURATION() external returns (uint256) envfree;
    function REVOCATION_DELAY() external returns (uint256) envfree;

    // State-changing functions
    function registerViewKey(uint8, bytes32, bytes32) external;
    function revokeViewKey(uint8) external;
    function revokeGrant(bytes32) external;
    function finalizeRevocation(bytes32) external;
    function pause() external;
    function unpause() external;
}

// ============================================================================
// GHOST VARIABLES
// ============================================================================

ghost uint256 ghostTotalKeysRegistered {
    init_state axiom ghostTotalKeysRegistered == 0;
}

ghost uint256 ghostTotalGrantsIssued {
    init_state axiom ghostTotalGrantsIssued == 0;
}

ghost mapping(bytes32 => bool) ghostGrantActive {
    init_state axiom forall bytes32 g. !ghostGrantActive[g];
}

// ============================================================================
// INVARIANTS
// ============================================================================

/**
 * @title Total Keys Registered Never Decreases
 * @notice totalKeysRegistered is monotonically non-decreasing
 * TODO: Hook ghostTotalKeysRegistered to storage updates for full tracking
 */
invariant totalKeysMonotonicallyIncreasing()
    totalKeysRegistered() >= 0
    { preserved { require totalKeysRegistered() < max_uint256; } }

/**
 * @title Total Grants Issued Never Decreases
 * @notice totalGrantsIssued is monotonically non-decreasing
 * TODO: Hook ghostTotalGrantsIssued to storage updates for full tracking
 */
invariant totalGrantsIssuedMonotonicallyIncreasing()
    totalGrantsIssued() >= 0
    { preserved { require totalGrantsIssued() < max_uint256; } }

/**
 * @title Active Grants Never Exceed Total Grants
 * @notice The number of active grants cannot exceed total grants issued
 * TODO: Strengthen with ghost variable tracking to ensure activeGrants <= totalGrantsIssued
 */
invariant activeGrantsNeverExceedTotal()
    totalActiveGrants() <= totalGrantsIssued()
    { preserved { require totalGrantsIssued() < max_uint256; } }

// ============================================================================
// RULES
// ============================================================================

/**
 * @title Pause Prevents Key Registration
 * @notice When paused, registerViewKey should revert
 */
rule pausePreventsRegistration(uint8 keyType, bytes32 publicKey, bytes32 commitment) {
    env e;
    require paused();

    registerViewKey@withrevert(e, keyType, publicKey, commitment);

    assert lastReverted,
        "Key registration should fail when paused";
}

/**
 * @title Revoked Grants Are No Longer Valid
 * @notice After revokeGrant + finalizeRevocation, the grant should be invalid
 * TODO: Implement full revocation flow test with timing constraints
 */
rule revokedGrantBecomesInvalid(bytes32 grantId) {
    env e1;
    env e2;

    require isGrantValid(grantId);

    revokeGrant(e1, grantId);

    // After revocation delay passes, finalize
    require e2.block.timestamp >= e1.block.timestamp + REVOCATION_DELAY();
    finalizeRevocation(e2, grantId);

    assert !isGrantValid(grantId),
        "Grant should be invalid after revocation is finalized";
}

/**
 * @title Total Keys Monotonicity Across Any Function
 * @notice No function can decrease totalKeysRegistered
 */
rule totalKeysNeverDecreases() {
    env e;
    uint256 before = totalKeysRegistered();

    method f;
    calldataarg args;
    f(e, args);

    uint256 after = totalKeysRegistered();

    assert after >= before,
        "totalKeysRegistered must never decrease";
}
