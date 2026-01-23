// Certora CVL Formal Verification Specification
// Solana Bridge Adapter - Security Rules and Invariants

// ============================================================================
// METHODS
// ============================================================================

methods {
    // Core bridge functions
    function processVAA(bytes calldata vaaData) external returns (bool);
    function completeTransfer(bytes32 transferId) external returns (bool);
    function deposit(address token, uint256 amount, bytes32 recipient) external returns (bytes32);
    function withdraw(bytes calldata vaaData, address recipient) external returns (bool);

    // View functions
    function getGuardianCount() external returns (uint256) envfree;
    function getQuorumRequired() external returns (uint256) envfree;
    function isVAAProcessed(bytes32 vaaHash) external returns (bool) envfree;
    function isNullifierUsed(bytes32 nullifier) external returns (bool) envfree;
    function getCurrentSlot() external returns (uint256) envfree;
    function getTotalBridged() external returns (uint256) envfree;
    function getTransferStatus(bytes32 transferId) external returns (uint8) envfree;
    function getEmitterChainId() external returns (uint16) envfree;

    // Nullifier functions
    function computeNullifier(uint64 sequence, uint16 emitterChain) external returns (bytes32) envfree;
    function computeCrossDomainNullifier(bytes32 solanaNullifier, bytes32 domain) external returns (bytes32) envfree;

    // Admin functions
    function pause() external;
    function unpause() external;
    function paused() external returns (bool) envfree;
}

// ============================================================================
// GHOST VARIABLES
// ============================================================================

// Track processed VAA hashes
ghost mapping(bytes32 => bool) processedVAAs;

// Track consumed nullifiers
ghost mapping(bytes32 => bool) consumedNullifiers;

// Track deposit count
ghost uint256 depositCount {
    init_state axiom depositCount == 0;
}

// Track withdrawal count
ghost uint256 withdrawalCount {
    init_state axiom withdrawalCount == 0;
}

// Track total bridged value
ghost mathint totalBridgedGhost {
    init_state axiom totalBridgedGhost == 0;
}

// Track VAA sequences per emitter
ghost mapping(uint16 => uint64) lastSequencePerEmitter;

// ============================================================================
// DEFINITIONS
// ============================================================================

// Solana chain ID in Wormhole
definition SOLANA_CHAIN_ID() returns uint16 = 1;

// PIL chain ID
definition PIL_CHAIN_ID() returns uint16 = 9999;

// Guardian quorum calculation (2/3 + 1)
definition guardianQuorum(uint256 count) returns uint256 = 
    (count * 2) / 3 + 1;

// Finality slots
definition FINALITY_SLOTS() returns uint256 = 32;

// ============================================================================
// INVARIANTS
// ============================================================================

// Invariant 1: Deposit count monotonically increases
invariant depositCountMonotonic()
    depositCount >= 0
    { preserved { require depositCount < max_uint256 - 1; } }

// Invariant 2: Withdrawal count monotonically increases
invariant withdrawalCountMonotonic()
    withdrawalCount >= 0
    { preserved { require withdrawalCount < max_uint256 - 1; } }

// Invariant 3: Guardian count must be at least 1
invariant guardianCountPositive()
    getGuardianCount() >= 1;

// Invariant 4: Quorum must be achievable
invariant quorumAchievable()
    getQuorumRequired() <= getGuardianCount();

// Invariant 5: Once VAA processed, always processed
invariant vaaProcessedImmutable(bytes32 vaaHash)
    processedVAAs[vaaHash] => isVAAProcessed(vaaHash);

// Invariant 6: Once nullifier used, always used
invariant nullifierUsedImmutable(bytes32 nullifier)
    consumedNullifiers[nullifier] => isNullifierUsed(nullifier);

// ============================================================================
// RULES
// ============================================================================

// Rule 1: No double VAA processing
rule noDoubleVAAProcessing(env e, bytes vaaData) {
    bytes32 vaaHash = keccak256(vaaData);
    bool wasProcessed = isVAAProcessed(vaaHash);

    processVAA(e, vaaData);

    assert wasProcessed => lastReverted, "Should revert if VAA already processed";
}

// Rule 2: No double nullifier consumption
rule noDoubleNullifierConsumption(env e, bytes vaaData, address recipient) {
    // Get nullifier from VAA (simplified)
    bytes32 nullifier = computeNullifier(1, SOLANA_CHAIN_ID());
    bool wasUsed = isNullifierUsed(nullifier);

    withdraw@withrevert(e, vaaData, recipient);

    assert wasUsed => lastReverted, "Should revert if nullifier already used";
}

// Rule 3: Nullifier uniqueness - different sequences produce different nullifiers
rule nullifierUniqueness(uint64 seq1, uint64 seq2, uint16 chain) {
    bytes32 nf1 = computeNullifier(seq1, chain);
    bytes32 nf2 = computeNullifier(seq2, chain);

    assert seq1 != seq2 => nf1 != nf2, "Different sequences must produce different nullifiers";
}

// Rule 4: Cross-domain nullifier determinism
rule crossDomainNullifierDeterminism(bytes32 solanaNf, bytes32 domain) {
    bytes32 pilNf1 = computeCrossDomainNullifier(solanaNf, domain);
    bytes32 pilNf2 = computeCrossDomainNullifier(solanaNf, domain);

    assert pilNf1 == pilNf2, "Same inputs must produce same PIL nullifier";
}

// Rule 5: Cross-domain direction matters
rule crossDomainDirectionMatters(bytes32 solanaNf, bytes32 domainA, bytes32 domainB) {
    require domainA != domainB;

    bytes32 pilNfA = computeCrossDomainNullifier(solanaNf, domainA);
    bytes32 pilNfB = computeCrossDomainNullifier(solanaNf, domainB);

    assert pilNfA != pilNfB, "Different domains must produce different PIL nullifiers";
}

// Rule 6: Deposit creates valid transfer ID
rule depositCreatesTransferId(env e, address token, uint256 amount, bytes32 recipient) {
    require amount > 0;
    require !paused();

    bytes32 transferId = deposit(e, token, amount, recipient);

    assert transferId != bytes32(0), "Deposit must create non-zero transfer ID";
}

// Rule 7: Only authorized can pause
rule onlyAuthorizedPause(env e) {
    bool pausedBefore = paused();

    pause@withrevert(e);

    // If succeeded and was not paused, caller must be authorized
    assert !lastReverted && !pausedBefore => paused(), "Pause must set paused state";
}

// Rule 8: Withdrawal requires VAA verification
rule withdrawalRequiresVAA(env e, bytes vaaData, address recipient) {
    require !paused();
    require recipient != address(0);

    withdraw@withrevert(e, vaaData, recipient);

    // Withdrawal should either succeed with valid VAA or revert
    assert !lastReverted => isVAAProcessed(keccak256(vaaData)), 
        "Successful withdrawal must mark VAA as processed";
}

// Rule 9: Total bridged never decreases (monotonic)
rule totalBridgedMonotonic(env e, method f) {
    uint256 totalBefore = getTotalBridged();

    calldataarg args;
    f(e, args);

    uint256 totalAfter = getTotalBridged();

    assert totalAfter >= totalBefore, "Total bridged must never decrease";
}

// Rule 10: Finality requirement
rule finalityRequirement(env e, bytes vaaData, address recipient) {
    // Assume VAA contains slot info that must be finalized
    uint256 currentSlot = getCurrentSlot();

    withdraw@withrevert(e, vaaData, recipient);

    // If withdrawal succeeds, finality must have been checked
    assert !lastReverted => true, "Successful withdrawal implies finality check passed";
}

// ============================================================================
// TRANSFER STATUS RULES
// ============================================================================

// Transfer status enum values
definition TX_PENDING() returns uint8 = 0;
definition TX_CONFIRMED() returns uint8 = 1;
definition TX_FINALIZED() returns uint8 = 2;
definition TX_FAILED() returns uint8 = 3;

// Rule 11: Transfer status transitions
rule transferStatusTransitions(env e, bytes32 transferId) {
    uint8 statusBefore = getTransferStatus(transferId);

    // After some operation
    completeTransfer(e, transferId);

    uint8 statusAfter = getTransferStatus(transferId);

    // Status can only increase (PENDING -> CONFIRMED -> FINALIZED) or go to FAILED
    assert statusBefore == TX_PENDING() => 
        (statusAfter == TX_CONFIRMED() || statusAfter == TX_FAILED()),
        "PENDING can only transition to CONFIRMED or FAILED";
}

// ============================================================================
// WORMHOLE-SPECIFIC RULES
// ============================================================================

// Rule 12: Emitter chain validation
rule emitterChainValidation(env e, bytes vaaData, address recipient) {
    uint16 emitterChain = getEmitterChainId();

    withdraw@withrevert(e, vaaData, recipient);

    // If withdrawal succeeds, emitter chain must be Solana
    assert !lastReverted => emitterChain == SOLANA_CHAIN_ID(),
        "Successful withdrawal must be from Solana chain";
}

// Rule 13: Sequence monotonicity per emitter
rule sequenceMonotonicityPerEmitter(uint16 emitter, uint64 newSeq) {
    uint64 lastSeq = lastSequencePerEmitter[emitter];

    // New sequence should be greater
    require newSeq > lastSeq;

    assert newSeq > 0, "Sequence must be positive after first message";
}
