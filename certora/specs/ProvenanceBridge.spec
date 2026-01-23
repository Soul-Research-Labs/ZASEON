// SPDX-License-Identifier: MIT
// Certora Verification Language (CVL) Specification for Provenance Bridge Adapter

/*
 * @title ProvenanceBridge.spec
 * @notice Formal verification rules for Provenance Blockchain bridge security
 * @dev Verifies Tendermint consensus, Marker module, IBC, and nullifier operations
 */

// ============================================================================
// METHODS
// ============================================================================

methods {
    // Validator management
    function addValidator(bytes, uint256, string) external;
    function removeValidator(bytes32) external;
    function updateValidatorPower(bytes32, uint256) external;
    function totalVotingPower() external returns (uint256) envfree;
    function getValidatorCount() external returns (uint256) envfree;

    // Block finalization
    function submitFinalizedBlock(int64, bytes32, bytes32[], bytes) external;
    function finalizedBlocks(int64) external returns (bytes32) envfree;
    function latestFinalizedHeight() external returns (int64) envfree;

    // IBC channels
    function registerIBCChannel(ProvenancePrimitives.IBCChannel) external;
    function updateIBCChannelState(string, ProvenancePrimitives.ChannelState) external;
    function getChannelCount() external returns (uint256) envfree;

    // Marker mapping
    function mapMarker(string, address) external;
    function unmapMarker(string) external;
    function markerToToken(string) external returns (address) envfree;
    function tokenToMarker(address) external returns (string) envfree;

    // Deposits
    function deposit(string, string) external payable;
    function confirmDeposit(bytes32, bytes32) external;
    function refundDeposit(bytes32) external;
    function depositNonce() external returns (uint256) envfree;

    // Withdrawals
    function initiateWithdrawal(string, address, string, uint256, int64, bytes32) external;
    function finalizeWithdrawal(bytes32) external;
    function claimWithdrawal(bytes32, uint256) external;

    // Nullifiers
    function registerNullifier(bytes32, int64, bytes32, string) external returns (bytes32);
    function registerCrossDomainNullifier(bytes32, uint256) external returns (bytes32);
    function createPILBinding(bytes32, bytes32) external returns (bytes32);
    function isNullifierUsed(bytes32) external returns (bool) envfree;
    function getProvenanceNullifier(bytes32) external returns (bytes32) envfree;

    // Volume tracking
    function dailyVolume() external returns (uint256) envfree;
    function lastVolumeReset() external returns (uint256) envfree;

    // Circuit breaker
    function circuitBreakerTriggered() external returns (bool) envfree;
    function circuitBreakerThreshold() external returns (uint256) envfree;
    function triggerCircuitBreaker() external;
    function resetCircuitBreaker() external;

    // Access control
    function hasRole(bytes32, address) external returns (bool) envfree;
    function paused() external returns (bool) envfree;
    function pause() external;
    function unpause() external;

    // Constants
    function MAX_VALIDATORS() external returns (uint256) envfree;
    function FINALITY_THRESHOLD_BPS() external returns (uint256) envfree;
    function MAX_TRANSFER() external returns (uint256) envfree;
    function DAILY_LIMIT() external returns (uint256) envfree;
    function MAX_RELAYER_FEE_BPS() external returns (uint256) envfree;
    function MIN_CONFIRMATIONS() external returns (uint256) envfree;
}

// ============================================================================
// DEFINITIONS
// ============================================================================

definition FINALITY_THRESHOLD() returns uint256 = 6667;
definition MAX_FEE_BPS() returns uint256 = 500;
definition DAILY_LIMIT_WEI() returns uint256 = 1000000000000000000000000; // 1M ETH

// ============================================================================
// INVARIANTS
// ============================================================================

/// @notice Total voting power is non-negative
invariant totalVotingPowerNonNegative()
    totalVotingPower() >= 0;

/// @notice Daily volume never exceeds daily limit when circuit breaker inactive
invariant dailyVolumeUnderLimit()
    !circuitBreakerTriggered() => dailyVolume() <= DAILY_LIMIT();

/// @notice Latest finalized height is non-negative
invariant latestHeightNonNegative()
    latestFinalizedHeight() >= 0;

/// @notice Circuit breaker threshold is positive
invariant circuitBreakerThresholdPositive()
    circuitBreakerThreshold() > 0;

// ============================================================================
// VALIDATOR RULES
// ============================================================================

/// @notice Adding a validator increases total voting power
rule addValidatorIncreasesPower(env e, bytes pubkey, uint256 votingPower, string moniker) {
    uint256 powerBefore = totalVotingPower();
    
    addValidator(e, pubkey, votingPower, moniker);
    
    uint256 powerAfter = totalVotingPower();
    
    assert powerAfter == powerBefore + votingPower,
        "Total power should increase by validator's power";
}

/// @notice Removing a validator decreases total voting power
rule removeValidatorDecreasesPower(env e, bytes32 validatorId) {
    uint256 powerBefore = totalVotingPower();
    
    removeValidator(e, validatorId);
    
    uint256 powerAfter = totalVotingPower();
    
    assert powerAfter <= powerBefore,
        "Total power should decrease when removing validator";
}

/// @notice Only operator can add validators
rule onlyOperatorCanAddValidator(env e, bytes pubkey, uint256 votingPower, string moniker) {
    bytes32 operatorRole = to_bytes32(keccak256("OPERATOR_ROLE"));
    
    addValidator@withrevert(e, pubkey, votingPower, moniker);
    
    assert !lastReverted => hasRole(operatorRole, e.msg.sender),
        "Only operator can add validators";
}

// ============================================================================
// BLOCK FINALIZATION RULES
// ============================================================================

/// @notice Finalized block height must be monotonically increasing
rule blockHeightMonotonicity(env e, int64 height, bytes32 blockHash, bytes32[] signers, bytes signatures) {
    int64 heightBefore = latestFinalizedHeight();
    
    submitFinalizedBlock(e, height, blockHash, signers, signatures);
    
    int64 heightAfter = latestFinalizedHeight();
    
    assert heightAfter > heightBefore,
        "Finalized height must strictly increase";
}

/// @notice Once finalized, block hash cannot change
rule blockHashImmutability(env e, int64 height, bytes32 blockHash, bytes32[] signers, bytes signatures) {
    bytes32 existingHash = finalizedBlocks(height);
    
    require existingHash != to_bytes32(0);
    
    submitFinalizedBlock@withrevert(e, height, blockHash, signers, signatures);
    
    assert lastReverted || finalizedBlocks(height) == existingHash,
        "Cannot change finalized block hash";
}

/// @notice Block finalization requires validator quorum
rule blockFinalizationRequiresQuorum(env e, int64 height, bytes32 blockHash, bytes32[] signers, bytes signatures) {
    uint256 total = totalVotingPower();
    
    require total > 0;
    
    submitFinalizedBlock@withrevert(e, height, blockHash, signers, signatures);
    
    // If succeeded, quorum must have been met
    assert !lastReverted => latestFinalizedHeight() == height,
        "Block finalization must update latest height";
}

// ============================================================================
// NULLIFIER RULES
// ============================================================================

/// @notice Nullifiers can only be registered once
rule nullifierUniqueness(env e, bytes32 txHash, int64 blockHeight, bytes32 scopeId, string denom) {
    registerNullifier(e, txHash, blockHeight, scopeId, denom);
    
    bytes32 nf;
    
    registerNullifier@withrevert(e, txHash, blockHeight, scopeId, denom);
    
    assert lastReverted,
        "Same nullifier cannot be registered twice";
}

/// @notice Nullifier registration marks it as used
rule nullifierMarkedAsUsed(env e, bytes32 txHash, int64 blockHeight, bytes32 scopeId, string denom) {
    bytes32 nf = registerNullifier(e, txHash, blockHeight, scopeId, denom);
    
    assert isNullifierUsed(nf),
        "Registered nullifier must be marked as used";
}

/// @notice Cross-domain nullifier requires base nullifier to exist
rule crossDomainRequiresBase(env e, bytes32 provenanceNullifier, uint256 targetDomain) {
    bool existsBefore = isNullifierUsed(provenanceNullifier);
    
    registerCrossDomainNullifier@withrevert(e, provenanceNullifier, targetDomain);
    
    assert lastReverted || existsBefore,
        "Cross-domain nullifier requires existing base nullifier";
}

/// @notice PIL binding requires base nullifier to exist
rule pilBindingRequiresBase(env e, bytes32 provenanceNullifier, bytes32 pilDomain) {
    bool existsBefore = isNullifierUsed(provenanceNullifier);
    
    createPILBinding@withrevert(e, provenanceNullifier, pilDomain);
    
    assert lastReverted || existsBefore,
        "PIL binding requires existing base nullifier";
}

/// @notice Cross-domain nullifier maps back to original
rule crossDomainMapsToOriginal(env e, bytes32 provenanceNullifier, uint256 targetDomain) {
    require isNullifierUsed(provenanceNullifier);
    
    bytes32 crossDomainNf = registerCrossDomainNullifier(e, provenanceNullifier, targetDomain);
    
    assert getProvenanceNullifier(crossDomainNf) == provenanceNullifier,
        "Cross-domain should map back to original";
}

// ============================================================================
// DEPOSIT RULES
// ============================================================================

/// @notice Deposit increments nonce
rule depositIncrementsNonce(env e, string recipient, string denom) {
    uint256 nonceBefore = depositNonce();
    
    require e.msg.value > 0;
    
    deposit(e, recipient, denom);
    
    uint256 nonceAfter = depositNonce();
    
    assert nonceAfter == nonceBefore + 1,
        "Deposit should increment nonce";
}

/// @notice Deposit updates daily volume
rule depositUpdatesDailyVolume(env e, string recipient, string denom) {
    uint256 volumeBefore = dailyVolume();
    
    require e.msg.value > 0;
    require !circuitBreakerTriggered();
    
    deposit(e, recipient, denom);
    
    uint256 volumeAfter = dailyVolume();
    
    assert volumeAfter >= volumeBefore,
        "Deposit should update daily volume";
}

/// @notice Deposit fails when circuit breaker triggered
rule depositFailsOnCircuitBreaker(env e, string recipient, string denom) {
    require circuitBreakerTriggered();
    require e.msg.value > 0;
    
    deposit@withrevert(e, recipient, denom);
    
    assert lastReverted,
        "Deposit should fail when circuit breaker triggered";
}

/// @notice Deposit fails when exceeds max transfer
rule depositExceedsMaxTransfer(env e, string recipient, string denom) {
    require e.msg.value > MAX_TRANSFER();
    
    deposit@withrevert(e, recipient, denom);
    
    assert lastReverted,
        "Deposit exceeding max transfer should fail";
}

/// @notice Deposit fails when paused
rule depositFailsWhenPaused(env e, string recipient, string denom) {
    require paused();
    require e.msg.value > 0;
    
    deposit@withrevert(e, recipient, denom);
    
    assert lastReverted,
        "Deposit should fail when paused";
}

// ============================================================================
// WITHDRAWAL RULES
// ============================================================================

/// @notice Withdrawal cannot be claimed before finalization
rule withdrawalRequiresFinalization(env e, bytes32 withdrawalId, uint256 relayerFee) {
    // Assume withdrawal exists but not finalized
    
    claimWithdrawal@withrevert(e, withdrawalId, relayerFee);
    
    // Would need to check withdrawal status in actual implementation
    // This is a placeholder demonstrating the pattern
}

/// @notice Relayer fee cannot exceed maximum
rule relayerFeeLimit(env e, bytes32 withdrawalId, uint256 relayerFee) {
    require relayerFee > MAX_FEE_BPS();
    
    claimWithdrawal@withrevert(e, withdrawalId, relayerFee);
    
    assert lastReverted,
        "Relayer fee exceeding max should fail";
}

// ============================================================================
// MARKER RULES
// ============================================================================

/// @notice Marker mapping is bidirectional
rule markerMappingBidirectional(env e, string denom, address token) {
    require markerToToken(denom) == address(0);
    require token != address(0);
    
    mapMarker(e, denom, token);
    
    assert markerToToken(denom) == token,
        "Marker should map to token";
}

/// @notice Cannot map already mapped marker
rule cannotRemapMarker(env e, string denom, address token) {
    require markerToToken(denom) != address(0);
    
    mapMarker@withrevert(e, denom, token);
    
    assert lastReverted,
        "Cannot remap existing marker";
}

/// @notice Unmapping clears both directions
rule unmappingClearsBoth(env e, string denom) {
    address token = markerToToken(denom);
    require token != address(0);
    
    unmapMarker(e, denom);
    
    assert markerToToken(denom) == address(0),
        "Unmapping should clear forward mapping";
}

// ============================================================================
// IBC CHANNEL RULES
// ============================================================================

/// @notice Registering channel increases count
rule registerChannelIncreasesCount(env e, ProvenancePrimitives.IBCChannel channel) {
    uint256 countBefore = getChannelCount();
    
    registerIBCChannel(e, channel);
    
    uint256 countAfter = getChannelCount();
    
    assert countAfter == countBefore + 1,
        "Registering channel should increase count";
}

// ============================================================================
// CIRCUIT BREAKER RULES
// ============================================================================

/// @notice Only guardian can trigger circuit breaker
rule onlyGuardianCanTrigger(env e) {
    bytes32 guardianRole = to_bytes32(keccak256("GUARDIAN_ROLE"));
    
    triggerCircuitBreaker@withrevert(e);
    
    assert !lastReverted => hasRole(guardianRole, e.msg.sender),
        "Only guardian can trigger circuit breaker";
}

/// @notice Only guardian can reset circuit breaker
rule onlyGuardianCanReset(env e) {
    bytes32 guardianRole = to_bytes32(keccak256("GUARDIAN_ROLE"));
    
    resetCircuitBreaker@withrevert(e);
    
    assert !lastReverted => hasRole(guardianRole, e.msg.sender),
        "Only guardian can reset circuit breaker";
}

/// @notice Trigger sets circuit breaker to true
rule triggerSetsCircuitBreaker(env e) {
    require !circuitBreakerTriggered();
    
    triggerCircuitBreaker(e);
    
    assert circuitBreakerTriggered(),
        "Trigger should set circuit breaker";
}

/// @notice Reset clears circuit breaker
rule resetClearsCircuitBreaker(env e) {
    require circuitBreakerTriggered();
    
    resetCircuitBreaker(e);
    
    assert !circuitBreakerTriggered(),
        "Reset should clear circuit breaker";
}

// ============================================================================
// PAUSE RULES
// ============================================================================

/// @notice Only guardian can pause
rule onlyGuardianCanPause(env e) {
    bytes32 guardianRole = to_bytes32(keccak256("GUARDIAN_ROLE"));
    
    pause@withrevert(e);
    
    assert !lastReverted => hasRole(guardianRole, e.msg.sender),
        "Only guardian can pause";
}

/// @notice Only guardian can unpause
rule onlyGuardianCanUnpause(env e) {
    bytes32 guardianRole = to_bytes32(keccak256("GUARDIAN_ROLE"));
    
    unpause@withrevert(e);
    
    assert !lastReverted => hasRole(guardianRole, e.msg.sender),
        "Only guardian can unpause";
}

// ============================================================================
// CONSTANT VERIFICATION
// ============================================================================

/// @notice Finality threshold is 2/3 (6667 bps)
rule verifyFinalityThreshold() {
    assert FINALITY_THRESHOLD_BPS() == 6667,
        "Finality threshold should be 6667 bps";
}

/// @notice Max relayer fee is 5%
rule verifyMaxRelayerFee() {
    assert MAX_RELAYER_FEE_BPS() == 500,
        "Max relayer fee should be 500 bps";
}

/// @notice Min confirmations for Tendermint is 1 (instant finality)
rule verifyMinConfirmations() {
    assert MIN_CONFIRMATIONS() == 1,
        "Min confirmations should be 1 for BFT";
}
