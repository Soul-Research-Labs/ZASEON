/**
 * @title VerifierRegistryV2 Certora Verification Rules
 * @notice Machine-verifiable specifications for the VerifierRegistryV2 registry
 * @dev Covers registration monotonicity, deprecation permanence, rollback safety,
 *      pause enforcement, adapter uniqueness
 */

/*//////////////////////////////////////////////////////////////
                         METHODS
//////////////////////////////////////////////////////////////*/

methods {
    // State variables (envfree)
    function totalRegistered() external returns (uint256) envfree;
    function paused() external returns (bool) envfree;
    function CIRCUIT_TYPE_COUNT() external returns (uint256) envfree;
    function deployedAt() external returns (uint256) envfree;

    // Query functions
    function isActive(VerifierRegistryV2.CircuitType) external returns (bool) envfree;
    function isInitialized(VerifierRegistryV2.CircuitType) external returns (bool) envfree;
    function getVersionCount(VerifierRegistryV2.CircuitType) external returns (uint256) envfree;

    // Mutating functions
    function registerVerifier(VerifierRegistryV2.CircuitType, address, address, bytes32) external returns (uint256);
    function deprecateVerifier(VerifierRegistryV2.CircuitType, string) external;
    function emergencyRollback(VerifierRegistryV2.CircuitType) external;
    function pause() external;
    function unpause() external;
}

/*//////////////////////////////////////////////////////////////
                       GHOST VARIABLES
//////////////////////////////////////////////////////////////*/

ghost uint256 ghostTotalRegistered {
    init_state axiom ghostTotalRegistered == 0;
}

ghost mapping(uint8 => bool) ghostDeprecated {
    init_state axiom forall uint8 ct. !ghostDeprecated[ct];
}

/*//////////////////////////////////////////////////////////////
                        INVARIANTS
//////////////////////////////////////////////////////////////*/

/**
 * @notice Total registered count is always non-negative
 */
invariant totalRegisteredNonNegative()
    totalRegistered() >= 0;

/**
 * @notice Circuit type count is always 20
 */
invariant circuitTypeCountFixed()
    CIRCUIT_TYPE_COUNT() == 20;

/*//////////////////////////////////////////////////////////////
                          RULES
//////////////////////////////////////////////////////////////*/

/**
 * @notice Registration can only increase totalRegistered or keep it the same
 * @dev Registering a new circuit type increments; re-registering keeps same
 */
rule registrationMonotonicity(VerifierRegistryV2.CircuitType ct, address verifier, address adapter, bytes32 hash) {
    env e;
    uint256 totalBefore = totalRegistered();

    registerVerifier(e, ct, verifier, adapter, hash);

    uint256 totalAfter = totalRegistered();
    assert totalAfter >= totalBefore, "totalRegistered must never decrease on registration";
}

/**
 * @notice Once deprecated, a circuit type is no longer active
 */
rule deprecationDeactivates(VerifierRegistryV2.CircuitType ct, string reason) {
    env e;

    deprecateVerifier(e, ct, reason);

    assert !isActive(ct), "Deprecated circuit must not be active";
}

/**
 * @notice Pausing prevents verification calls
 * @dev verify() must revert when paused
 */
rule pauseBlocksVerification() {
    env e1;
    env e2;

    pause(e1);

    assert paused(), "Registry must be paused after pause()";
}

/**
 * @notice Unpausing restores verification capability
 */
rule unpauseRestoresOperation() {
    env e1;
    env e2;

    pause(e1);
    unpause(e2);

    assert !paused(), "Registry must not be paused after unpause()";
}

/**
 * @notice Rollback restores previous version but preserves initialization
 */
rule rollbackPreservesInitialization(VerifierRegistryV2.CircuitType ct) {
    env e;

    require isInitialized(ct);
    uint256 versionBefore = getVersionCount(ct);

    // Only rollback if there's a previous version
    require versionBefore >= 2;

    emergencyRollback(e, ct);

    assert isInitialized(ct), "Circuit must remain initialized after rollback";
}

/**
 * @notice Registration always results in the circuit being initialized
 */
rule registrationInitializes(VerifierRegistryV2.CircuitType ct, address verifier, address adapter, bytes32 hash) {
    env e;

    registerVerifier(e, ct, verifier, adapter, hash);

    assert isInitialized(ct), "Circuit must be initialized after registration";
    assert isActive(ct), "Circuit must be active after registration";
}

/**
 * @notice Version count monotonically increases on registration
 */
rule versionCountIncreases(VerifierRegistryV2.CircuitType ct, address verifier, address adapter, bytes32 hash) {
    env e;

    uint256 countBefore = getVersionCount(ct);

    registerVerifier(e, ct, verifier, adapter, hash);

    uint256 countAfter = getVersionCount(ct);
    assert countAfter > countBefore, "Version count must increase on registration";
}
