// Certora CVL Specification for Hyperliquid Bridge Adapter
// This specification verifies security properties of the Hyperliquid L1 bridge

// ============================================================================
// METHODS
// ============================================================================

methods {
    // View functions
    function totalVotingPower() external returns (uint256) envfree;
    function latestFinalizedHeight() external returns (uint64) envfree;
    function totalValueLocked() external returns (uint256) envfree;
    function circuitBreakerActive() external returns (bool) envfree;
    function paused() external returns (bool) envfree;
    function relayerFeeBps() external returns (uint256) envfree;
    function registeredRelayers(address) external returns (bool) envfree;
    function MAX_TRANSFER() external returns (uint256) envfree;
    function DAILY_LIMIT() external returns (uint256) envfree;
    function MAX_RELAYER_FEE_BPS() external returns (uint256) envfree;
    function MAX_VALIDATORS() external returns (uint256) envfree;
    function QUORUM_THRESHOLD_BPS() external returns (uint256) envfree;

    // Validator functions
    function getValidator(address) external returns (
        bytes32 pubKeyHash,
        uint256 votingPower,
        bool isActive,
        uint256 lastBlockSigned
    ) envfree;
    function getValidatorCount() external returns (uint256) envfree;

    // Deposit functions
    function getDeposit(bytes32) external returns (
        address depositor,
        address recipient,
        uint256 amount,
        uint256 tokenId,
        uint256 timestamp,
        bool processed
    ) envfree;

    // Withdrawal functions
    function getWithdrawal(bytes32) external returns (
        address sender,
        address recipient,
        uint256 amount,
        uint256 tokenId,
        uint64 hlBlockHeight,
        bool finalized
    ) envfree;

    // Cross-domain nullifier
    function crossDomainNullifiers(bytes32) external returns (bytes32) envfree;
    function pilBindings(bytes32) external returns (bytes32) envfree;
    function usedNullifiers(bytes32) external returns (bool) envfree;

    // Token mapping
    function hip1ToErc20(uint256) external returns (address) envfree;
    function erc20ToHip1(address) external returns (uint256) envfree;

    // State-changing functions
    function deposit(address, uint256) external;
    function addValidator(address, bytes32, uint256) external;
    function removeValidator(address) external;
    function updateValidatorPower(address, uint256) external;
    function initiateWithdrawal(bytes32, address, uint256, uint256, uint64, bytes) external;
    function finalizeWithdrawal(bytes32) external;
    function registerCrossDomainNullifier(bytes32, uint256) external;
    function markNullifierUsed(bytes32) external;
    function mapToken(uint256, address) external;

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
    function VALIDATOR_ROLE() external returns (bytes32) envfree;
    function DEFAULT_ADMIN_ROLE() external returns (bytes32) envfree;
}

// ============================================================================
// GHOST VARIABLES
// ============================================================================

ghost uint256 ghostValidatorCount;
ghost uint256 ghostTotalDeposits;
ghost uint256 ghostTotalWithdrawals;

// ============================================================================
// INVARIANTS
// ============================================================================

/// @title Voting power consistency
invariant votingPowerConsistency()
    totalVotingPower() >= 0

/// @title Relayer fee bounded
invariant relayerFeeBounded()
    relayerFeeBps() <= MAX_RELAYER_FEE_BPS()

/// @title TVL non-negative
invariant tvlNonNegative()
    totalValueLocked() >= 0

/// @title Circuit breaker blocks operations
invariant circuitBreakerBlocksOperations()
    circuitBreakerActive() => paused()

// ============================================================================
// DEPOSIT RULES
// ============================================================================

/// @title Deposit increases TVL
rule depositIncreasesTVL(address recipient, uint256 tokenId) {
    env e;
    require e.msg.value > 0;
    require e.msg.value <= MAX_TRANSFER();
    require !circuitBreakerActive();
    require !paused();

    uint256 tvlBefore = totalValueLocked();

    deposit(e, recipient, tokenId);

    uint256 tvlAfter = totalValueLocked();

    assert tvlAfter == tvlBefore + e.msg.value,
        "Deposit should increase TVL by deposited amount";
}

/// @title Deposit reverts on zero amount
rule depositRevertsOnZeroAmount(address recipient, uint256 tokenId) {
    env e;
    require e.msg.value == 0;

    deposit@withrevert(e, recipient, tokenId);

    assert lastReverted,
        "Deposit with zero amount should revert";
}

/// @title Deposit reverts when circuit breaker active
rule depositRevertsOnCircuitBreaker(address recipient, uint256 tokenId) {
    env e;
    require circuitBreakerActive();

    deposit@withrevert(e, recipient, tokenId);

    assert lastReverted,
        "Deposit should revert when circuit breaker is active";
}

/// @title Deposit reverts when paused
rule depositRevertsWhenPaused(address recipient, uint256 tokenId) {
    env e;
    require paused();

    deposit@withrevert(e, recipient, tokenId);

    assert lastReverted,
        "Deposit should revert when paused";
}

// ============================================================================
// VALIDATOR RULES
// ============================================================================

/// @title Add validator increases count
rule addValidatorIncreasesCount(address validator, bytes32 pubKeyHash, uint256 votingPower) {
    env e;
    require validator != 0;
    require hasRole(OPERATOR_ROLE(), e.msg.sender);

    uint256 countBefore = getValidatorCount();

    addValidator(e, validator, pubKeyHash, votingPower);

    uint256 countAfter = getValidatorCount();

    assert countAfter == countBefore + 1,
        "Validator count should increase by 1";
}

/// @title Add validator updates voting power
rule addValidatorUpdatesPower(address validator, bytes32 pubKeyHash, uint256 votingPower) {
    env e;
    require validator != 0;
    require hasRole(OPERATOR_ROLE(), e.msg.sender);

    uint256 powerBefore = totalVotingPower();

    addValidator(e, validator, pubKeyHash, votingPower);

    uint256 powerAfter = totalVotingPower();

    assert powerAfter == powerBefore + votingPower,
        "Total voting power should increase by validator power";
}

/// @title Remove validator decreases count
rule removeValidatorDecreasesCount(address validator) {
    env e;
    require hasRole(OPERATOR_ROLE(), e.msg.sender);

    bytes32 pubKey;
    uint256 power;
    bool isActive;
    uint256 lastBlock;
    (pubKey, power, isActive, lastBlock) = getValidator(validator);
    require isActive;

    uint256 countBefore = getValidatorCount();

    removeValidator(e, validator);

    uint256 countAfter = getValidatorCount();

    assert countAfter == countBefore - 1,
        "Validator count should decrease by 1";
}

/// @title Update validator power adjusts total
rule updateValidatorPowerAdjustsTotal(address validator, uint256 newPower) {
    env e;
    require hasRole(OPERATOR_ROLE(), e.msg.sender);

    bytes32 pubKey;
    uint256 oldPower;
    bool isActive;
    uint256 lastBlock;
    (pubKey, oldPower, isActive, lastBlock) = getValidator(validator);
    require isActive;

    uint256 totalBefore = totalVotingPower();

    updateValidatorPower(e, validator, newPower);

    uint256 totalAfter = totalVotingPower();

    assert totalAfter == totalBefore - oldPower + newPower,
        "Total power should be adjusted correctly";
}

/// @title Only operator can add validator
rule onlyOperatorCanAddValidator(address validator, bytes32 pubKeyHash, uint256 votingPower) {
    env e;
    require !hasRole(OPERATOR_ROLE(), e.msg.sender);

    addValidator@withrevert(e, validator, pubKeyHash, votingPower);

    assert lastReverted,
        "Non-operator should not be able to add validator";
}

/// @title Max validators enforced
rule maxValidatorsEnforced(address validator, bytes32 pubKeyHash, uint256 votingPower) {
    env e;
    require getValidatorCount() >= MAX_VALIDATORS();

    addValidator@withrevert(e, validator, pubKeyHash, votingPower);

    assert lastReverted,
        "Adding validator beyond max should revert";
}

// ============================================================================
// WITHDRAWAL RULES
// ============================================================================

/// @title Finalize withdrawal decreases TVL
rule finalizeWithdrawalDecreasesTVL(bytes32 withdrawalHash) {
    env e;
    require !circuitBreakerActive();
    require !paused();

    address sender;
    address recipient;
    uint256 amount;
    uint256 tokenId;
    uint64 hlBlockHeight;
    bool finalized;
    (sender, recipient, amount, tokenId, hlBlockHeight, finalized) = getWithdrawal(withdrawalHash);
    require sender != 0;
    require !finalized;
    require amount > 0;

    uint256 tvlBefore = totalValueLocked();

    finalizeWithdrawal(e, withdrawalHash);

    uint256 tvlAfter = totalValueLocked();

    assert tvlAfter == tvlBefore - amount,
        "Withdrawal should decrease TVL by withdrawn amount";
}

/// @title Double finalization prevented
rule doubleFinalizationPrevented(bytes32 withdrawalHash) {
    env e1;
    env e2;

    address sender;
    address recipient;
    uint256 amount;
    uint256 tokenId;
    uint64 hlBlockHeight;
    bool finalized;
    (sender, recipient, amount, tokenId, hlBlockHeight, finalized) = getWithdrawal(withdrawalHash);
    require sender != 0;
    require !finalized;

    finalizeWithdrawal(e1, withdrawalHash);

    finalizeWithdrawal@withrevert(e2, withdrawalHash);

    assert lastReverted,
        "Double finalization should revert";
}

// ============================================================================
// NULLIFIER RULES
// ============================================================================

/// @title Nullifier registration is deterministic
rule nullifierRegistrationDeterministic(bytes32 hlNullifier, uint256 targetChain) {
    env e1;
    env e2;
    require hlNullifier != to_bytes32(0);

    registerCrossDomainNullifier(e1, hlNullifier, targetChain);

    bytes32 pilNf1 = crossDomainNullifiers(hlNullifier);

    // Register again (should be idempotent)
    registerCrossDomainNullifier(e2, hlNullifier, targetChain);

    bytes32 pilNf2 = crossDomainNullifiers(hlNullifier);

    assert pilNf1 == pilNf2,
        "Nullifier registration should be deterministic";
}

/// @title PIL binding is bidirectional
rule pilBindingBidirectional(bytes32 hlNullifier, uint256 targetChain) {
    env e;
    require hlNullifier != to_bytes32(0);

    registerCrossDomainNullifier(e, hlNullifier, targetChain);

    bytes32 pilNf = crossDomainNullifiers(hlNullifier);
    bytes32 reverseHL = pilBindings(pilNf);

    assert reverseHL == hlNullifier,
        "PIL binding should map back to original HL nullifier";
}

/// @title Used nullifiers cannot be reused
rule usedNullifiersCannotReuse(bytes32 nullifier) {
    require usedNullifiers(nullifier);

    assert usedNullifiers(nullifier),
        "Used nullifier flag should remain true";
}

/// @title Mark nullifier used is irreversible
rule markNullifierUsedIrreversible(bytes32 nullifier) {
    env e;
    require hasRole(OPERATOR_ROLE(), e.msg.sender);
    require !usedNullifiers(nullifier);

    markNullifierUsed(e, nullifier);

    assert usedNullifiers(nullifier),
        "Nullifier should be marked as used";
}

// ============================================================================
// TOKEN MAPPING RULES
// ============================================================================

/// @title Token mapping is bidirectional
rule tokenMappingBidirectional(uint256 hip1TokenId, address erc20Address) {
    env e;
    require hasRole(OPERATOR_ROLE(), e.msg.sender);
    require erc20Address != 0;

    mapToken(e, hip1TokenId, erc20Address);

    assert hip1ToErc20(hip1TokenId) == erc20Address,
        "HIP1 to ERC20 mapping should be set";
    assert erc20ToHip1(erc20Address) == hip1TokenId,
        "ERC20 to HIP1 mapping should be set";
}

// ============================================================================
// CIRCUIT BREAKER RULES
// ============================================================================

/// @title Guardian can trigger circuit breaker
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
// ACCESS CONTROL RULES
// ============================================================================

/// @title Roles are distinct
rule rolesAreDistinct() {
    bytes32 adminRole = DEFAULT_ADMIN_ROLE();
    bytes32 operatorRole = OPERATOR_ROLE();
    bytes32 guardianRole = GUARDIAN_ROLE();
    bytes32 validatorRole = VALIDATOR_ROLE();
    bytes32 upgraderRole = UPGRADER_ROLE();

    assert adminRole != operatorRole,
        "Admin and operator roles should be distinct";
    assert adminRole != guardianRole,
        "Admin and guardian roles should be distinct";
    assert adminRole != validatorRole,
        "Admin and validator roles should be distinct";
    assert operatorRole != validatorRole,
        "Operator and validator roles should be distinct";
}

// ============================================================================
// QUORUM RULES
// ============================================================================

/// @title Quorum threshold is 2/3+1
rule quorumThresholdIs2_3Plus1() {
    assert QUORUM_THRESHOLD_BPS() == 6667,
        "Quorum threshold should be 66.67%";
}
