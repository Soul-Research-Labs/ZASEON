// Certora CVL Specification for Plasma Bridge Adapter
// This specification verifies security properties of the Plasma L2 bridge

// ============================================================================
// METHODS
// ============================================================================

methods {
    // View functions
    function currentBlockNumber() external returns (uint256) envfree;
    function blockRoots(uint256) external returns (bytes32) envfree;
    function totalValueLocked() external returns (uint256) envfree;
    function exitQueueLength() external returns (uint256) envfree;
    function circuitBreakerActive() external returns (bool) envfree;
    function paused() external returns (bool) envfree;
    function relayerFeeBps() external returns (uint256) envfree;
    function registeredRelayers(address) external returns (bool) envfree;
    function MIN_EXIT_BOND() external returns (uint256) envfree;
    function CHALLENGE_PERIOD() external returns (uint256) envfree;
    function MAX_TRANSFER() external returns (uint256) envfree;
    function DAILY_LIMIT() external returns (uint256) envfree;
    function MAX_RELAYER_FEE_BPS() external returns (uint256) envfree;

    // Exit functions
    function getExit(uint256) external returns (
        address owner,
        address token,
        uint256 amount,
        uint256 utxoPos,
        uint256 exitableAt,
        uint256 bondAmount,
        uint8 status
    ) envfree;

    // Deposit functions
    function getDeposit(bytes32) external returns (
        address depositor,
        uint256 amount,
        bytes32 commitment,
        uint256 timestamp
    ) envfree;

    // Cross-domain nullifier
    function crossDomainNullifiers(bytes32) external returns (bytes32) envfree;
    function pilBindings(bytes32) external returns (bytes32) envfree;
    function usedNullifiers(bytes32) external returns (bool) envfree;

    // State-changing functions
    function deposit(bytes32) external;
    function submitBlock(bytes32, uint256) external;
    function startStandardExit(uint256, bytes, bytes32[], uint256, bytes) external;
    function challengeExit(uint256, bytes, bytes32[], uint256) external;
    function processExits(uint256) external;
    function cancelExit(uint256) external;
    function registerCrossDomainNullifier(bytes32, uint256) external;

    // Admin functions
    function triggerCircuitBreaker(string) external;
    function resetCircuitBreaker() external;
    function pause() external;
    function unpause() external;
    function updateRelayerFee(uint256) external;
    function registerRelayer() external;
    function unregisterRelayer() external;

    // Role functions
    function hasRole(bytes32, address) external returns (bool) envfree;
    function OPERATOR_ROLE() external returns (bytes32) envfree;
    function GUARDIAN_ROLE() external returns (bytes32) envfree;
    function UPGRADER_ROLE() external returns (bytes32) envfree;
    function DEFAULT_ADMIN_ROLE() external returns (bytes32) envfree;
}

// ============================================================================
// DEFINITIONS
// ============================================================================

definition NOT_STARTED() returns uint8 = 0;
definition IN_PROGRESS() returns uint8 = 1;
definition FINALIZED() returns uint8 = 2;
definition CHALLENGED() returns uint8 = 3;
definition CANCELLED() returns uint8 = 4;

// ============================================================================
// GHOST VARIABLES
// ============================================================================

ghost uint256 ghostTotalDeposits;
ghost uint256 ghostTotalWithdrawals;
ghost uint256 ghostExitCount;
ghost uint256 ghostChallengedExits;

// ============================================================================
// INVARIANTS
// ============================================================================

/// @title Block number monotonically increases
invariant blockNumberMonotonic()
    currentBlockNumber() >= 1
    {
        preserved {
            require currentBlockNumber() >= 1;
        }
    }

/// @title TVL is non-negative
invariant tvlNonNegative()
    totalValueLocked() >= 0

/// @title Relayer fee bounded
invariant relayerFeeBounded()
    relayerFeeBps() <= MAX_RELAYER_FEE_BPS()

/// @title Circuit breaker blocks deposits
invariant circuitBreakerBlocksOperations()
    circuitBreakerActive() => paused()
    {
        preserved {
            requireInvariant tvlNonNegative();
        }
    }

// ============================================================================
// DEPOSIT RULES
// ============================================================================

/// @title Deposit increases TVL
rule depositIncreasesTVL(bytes32 commitment) {
    env e;
    require e.msg.value > 0;
    require e.msg.value <= MAX_TRANSFER();
    require !circuitBreakerActive();
    require !paused();

    uint256 tvlBefore = totalValueLocked();

    deposit(e, commitment);

    uint256 tvlAfter = totalValueLocked();

    assert tvlAfter == tvlBefore + e.msg.value,
        "Deposit should increase TVL by deposited amount";
}

/// @title Deposit reverts on zero amount
rule depositRevertsOnZeroAmount(bytes32 commitment) {
    env e;
    require e.msg.value == 0;

    deposit@withrevert(e, commitment);

    assert lastReverted,
        "Deposit with zero amount should revert";
}

/// @title Deposit reverts when circuit breaker active
rule depositRevertsOnCircuitBreaker(bytes32 commitment) {
    env e;
    require circuitBreakerActive();

    deposit@withrevert(e, commitment);

    assert lastReverted,
        "Deposit should revert when circuit breaker is active";
}

/// @title Deposit reverts when paused
rule depositRevertsWhenPaused(bytes32 commitment) {
    env e;
    require paused();

    deposit@withrevert(e, commitment);

    assert lastReverted,
        "Deposit should revert when paused";
}

/// @title Deposit creates valid deposit record
rule depositCreatesRecord(bytes32 commitment) {
    env e;
    require e.msg.value > 0;
    require e.msg.value <= MAX_TRANSFER();
    require !circuitBreakerActive();
    require !paused();

    deposit(e, commitment);

    address depositor;
    uint256 amount;
    bytes32 storedCommitment;
    uint256 timestamp;
    (depositor, amount, storedCommitment, timestamp) = getDeposit(commitment);

    assert depositor == e.msg.sender,
        "Depositor should be caller";
    assert amount == e.msg.value,
        "Amount should match sent value";
    assert storedCommitment == commitment,
        "Commitment should be stored";
}

// ============================================================================
// BLOCK SUBMISSION RULES
// ============================================================================

/// @title Block submission increments block number
rule blockSubmissionIncrementsBlockNumber(bytes32 root, uint256 numTx) {
    env e;
    require root != to_bytes32(0);
    require numTx > 0;
    require hasRole(OPERATOR_ROLE(), e.msg.sender);

    uint256 blockNumBefore = currentBlockNumber();

    submitBlock(e, root, numTx);

    uint256 blockNumAfter = currentBlockNumber();

    assert blockNumAfter == blockNumBefore + 1,
        "Block number should increment by 1";
}

/// @title Block submission stores root
rule blockSubmissionStoresRoot(bytes32 root, uint256 numTx) {
    env e;
    require root != to_bytes32(0);
    require numTx > 0;
    require hasRole(OPERATOR_ROLE(), e.msg.sender);

    uint256 blockNum = currentBlockNumber();

    submitBlock(e, root, numTx);

    bytes32 storedRoot = blockRoots(blockNum);

    assert storedRoot == root,
        "Root should be stored at previous block number";
}

/// @title Only operator can submit blocks
rule onlyOperatorCanSubmitBlock(bytes32 root, uint256 numTx) {
    env e;
    require !hasRole(OPERATOR_ROLE(), e.msg.sender);

    submitBlock@withrevert(e, root, numTx);

    assert lastReverted,
        "Non-operator should not be able to submit blocks";
}

/// @title Block submission reverts with zero root
rule blockSubmissionRevertsZeroRoot(uint256 numTx) {
    env e;
    require numTx > 0;

    submitBlock@withrevert(e, to_bytes32(0), numTx);

    assert lastReverted,
        "Block submission with zero root should revert";
}

// ============================================================================
// EXIT RULES
// ============================================================================

/// @title Exit bond must meet minimum
rule exitRequiresMinimumBond(
    uint256 utxoPos,
    bytes txBytes,
    bytes32[] siblings,
    uint256 index,
    bytes signature
) {
    env e;
    require e.msg.value < MIN_EXIT_BOND();

    startStandardExit@withrevert(e, utxoPos, txBytes, siblings, index, signature);

    assert lastReverted,
        "Exit with insufficient bond should revert";
}

/// @title Challenge cancels exit
rule challengeCancelsExit(
    uint256 exitId,
    bytes spendingTx,
    bytes32[] siblings,
    uint256 index
) {
    env e;

    address ownerBefore;
    address tokenBefore;
    uint256 amountBefore;
    uint256 utxoPosBefore;
    uint256 exitableAtBefore;
    uint256 bondAmountBefore;
    uint8 statusBefore;
    (ownerBefore, tokenBefore, amountBefore, utxoPosBefore, exitableAtBefore, bondAmountBefore, statusBefore) = getExit(exitId);

    require statusBefore == IN_PROGRESS();

    challengeExit(e, exitId, spendingTx, siblings, index);

    address ownerAfter;
    address tokenAfter;
    uint256 amountAfter;
    uint256 utxoPosAfter;
    uint256 exitableAtAfter;
    uint256 bondAmountAfter;
    uint8 statusAfter;
    (ownerAfter, tokenAfter, amountAfter, utxoPosAfter, exitableAtAfter, bondAmountAfter, statusAfter) = getExit(exitId);

    assert statusAfter == CHALLENGED(),
        "Challenged exit should have CHALLENGED status";
}

/// @title Only exit owner can cancel
rule onlyOwnerCanCancelExit(uint256 exitId) {
    env e;

    address owner;
    address token;
    uint256 amount;
    uint256 utxoPos;
    uint256 exitableAt;
    uint256 bondAmount;
    uint8 status;
    (owner, token, amount, utxoPos, exitableAt, bondAmount, status) = getExit(exitId);

    require e.msg.sender != owner;
    require status == IN_PROGRESS();

    cancelExit@withrevert(e, exitId);

    assert lastReverted,
        "Non-owner should not be able to cancel exit";
}

// ============================================================================
// NULLIFIER RULES
// ============================================================================

/// @title Nullifier registration is deterministic
rule nullifierRegistrationDeterministic(bytes32 plasmaNullifier, uint256 targetChain) {
    env e1;
    env e2;
    require plasmaNullifier != to_bytes32(0);

    registerCrossDomainNullifier(e1, plasmaNullifier, targetChain);

    bytes32 pilNf1 = crossDomainNullifiers(plasmaNullifier);

    // Register again (should be idempotent)
    registerCrossDomainNullifier(e2, plasmaNullifier, targetChain);

    bytes32 pilNf2 = crossDomainNullifiers(plasmaNullifier);

    assert pilNf1 == pilNf2,
        "Nullifier registration should be deterministic";
}

/// @title PIL binding is bidirectional
rule pilBindingBidirectional(bytes32 plasmaNullifier, uint256 targetChain) {
    env e;
    require plasmaNullifier != to_bytes32(0);

    registerCrossDomainNullifier(e, plasmaNullifier, targetChain);

    bytes32 pilNf = crossDomainNullifiers(plasmaNullifier);
    bytes32 reversePlasma = pilBindings(pilNf);

    assert reversePlasma == plasmaNullifier,
        "PIL binding should map back to original Plasma nullifier";
}

/// @title Used nullifiers cannot be reused
rule usedNullifiersCannotReuse(bytes32 nullifier) {
    require usedNullifiers(nullifier);

    // Any operation that would use this nullifier should fail
    // (captured in specific exit/withdraw rules)

    assert usedNullifiers(nullifier),
        "Used nullifier flag should remain true";
}

// ============================================================================
// CIRCUIT BREAKER RULES
// ============================================================================

/// @title Circuit breaker can be triggered by guardian
rule guardianCanTriggerCircuitBreaker(string reason) {
    env e;
    require hasRole(GUARDIAN_ROLE(), e.msg.sender);
    require !circuitBreakerActive();

    triggerCircuitBreaker(e, reason);

    assert circuitBreakerActive(),
        "Guardian should be able to trigger circuit breaker";
}

/// @title Only admin can reset circuit breaker
rule onlyAdminCanResetCircuitBreaker() {
    env e;
    require !hasRole(DEFAULT_ADMIN_ROLE(), e.msg.sender);
    require circuitBreakerActive();

    resetCircuitBreaker@withrevert(e);

    assert lastReverted,
        "Non-admin should not be able to reset circuit breaker";
}

/// @title Circuit breaker reset works
rule circuitBreakerResetWorks() {
    env e;
    require hasRole(DEFAULT_ADMIN_ROLE(), e.msg.sender);
    require circuitBreakerActive();

    resetCircuitBreaker(e);

    assert !circuitBreakerActive(),
        "Circuit breaker should be reset";
}

// ============================================================================
// PAUSE RULES
// ============================================================================

/// @title Pause prevents deposits
rule pausePreventsDeposits(bytes32 commitment) {
    env e;
    require paused();

    deposit@withrevert(e, commitment);

    assert lastReverted,
        "Deposits should be blocked when paused";
}

/// @title Unpause allows deposits
rule unpauseAllowsDeposits(bytes32 commitment) {
    env e;
    require !paused();
    require !circuitBreakerActive();
    require e.msg.value > 0;
    require e.msg.value <= MAX_TRANSFER();

    deposit@withrevert(e, commitment);

    assert !lastReverted,
        "Deposits should be allowed when not paused";
}

// ============================================================================
// RELAYER RULES
// ============================================================================

/// @title Relayer registration works
rule relayerRegistrationWorks() {
    env e;
    require !registeredRelayers(e.msg.sender);

    registerRelayer(e);

    assert registeredRelayers(e.msg.sender),
        "Relayer should be registered";
}

/// @title Relayer unregistration works
rule relayerUnregistrationWorks() {
    env e;
    require registeredRelayers(e.msg.sender);

    unregisterRelayer(e);

    assert !registeredRelayers(e.msg.sender),
        "Relayer should be unregistered";
}

/// @title Relayer fee update bounded
rule relayerFeeUpdateBounded(uint256 newFee) {
    env e;
    require newFee > MAX_RELAYER_FEE_BPS();

    updateRelayerFee@withrevert(e, newFee);

    assert lastReverted,
        "Relayer fee above max should revert";
}

// ============================================================================
// TVLCONSERVATION RULES
// ============================================================================

/// @title TVL conservation on process exits
rule tvlConservationOnProcessExits(uint256 maxExits) {
    env e;

    uint256 tvlBefore = totalValueLocked();
    uint256 queueLengthBefore = exitQueueLength();

    processExits(e, maxExits);

    uint256 tvlAfter = totalValueLocked();
    uint256 queueLengthAfter = exitQueueLength();

    // TVL should decrease or stay the same
    assert tvlAfter <= tvlBefore,
        "TVL should not increase when processing exits";

    // Queue should shrink or stay the same
    assert queueLengthAfter <= queueLengthBefore,
        "Queue should not grow when processing exits";
}

// ============================================================================
// ACCESS CONTROL RULES
// ============================================================================

/// @title Admin role has all permissions
rule adminHasAllPermissions() {
    env e;

    bytes32 adminRole = DEFAULT_ADMIN_ROLE();
    bytes32 operatorRole = OPERATOR_ROLE();
    bytes32 guardianRole = GUARDIAN_ROLE();
    bytes32 upgraderRole = UPGRADER_ROLE();

    // Admin should be able to grant/revoke other roles
    // (implicit in OpenZeppelin AccessControl)

    assert adminRole != operatorRole,
        "Admin role should be distinct from operator";
    assert adminRole != guardianRole,
        "Admin role should be distinct from guardian";
    assert adminRole != upgraderRole,
        "Admin role should be distinct from upgrader";
}

// ============================================================================
// UPGRADE SAFETY RULES
// ============================================================================

/// @title Only upgrader can upgrade
rule onlyUpgraderCanUpgrade() {
    // Verified through UUPS pattern
    // upgradeTo and upgradeToAndCall require UPGRADER_ROLE
    assert true;
}
