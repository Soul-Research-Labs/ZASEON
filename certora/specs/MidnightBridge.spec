// Certora CVL Formal Verification Specification
// Midnight Network Bridge Adapter - Security Rules and Invariants

// ============================================================================
// METHODS
// ============================================================================

methods {
    // Shielding functions
    function shield(uint256 amount, bytes32 commitment, bytes calldata proof) external returns (bytes32);
    function unshield(bytes32 nullifier, uint256 amount, bytes calldata proof, address recipient) external returns (bool);

    // Dust (private UTXO) management
    function createDust(bytes32 commitment, bytes calldata rangeProof) external returns (bytes32);
    function spendDust(bytes32 nullifier, bytes calldata spendProof) external returns (bool);
    function getDustStatus(bytes32 commitment) external returns (uint8) envfree;

    // State functions
    function getStateRoot() external returns (bytes32) envfree;
    function getNullifierRoot() external returns (bytes32) envfree;
    function getCommitmentRoot() external returns (bytes32) envfree;

    // Proof verification
    function verifySpendProof(bytes32 nullifier, bytes calldata proof) external returns (bool) envfree;
    function verifyOutputProof(bytes32 commitment, bytes calldata proof) external returns (bool) envfree;
    function verifyRangeProof(bytes32 commitment, bytes calldata proof) external returns (bool) envfree;

    // View functions
    function isNullifierUsed(bytes32 nullifier) external returns (bool) envfree;
    function isCommitmentKnown(bytes32 commitment) external returns (bool) envfree;
    function getCurrentBlockNumber() external returns (uint256) envfree;
    function getTotalShielded() external returns (uint256) envfree;
    function getTotalUnshielded() external returns (uint256) envfree;

    // Nullifier functions
    function computeNullifier(bytes32 commitment, bytes32 owner, uint256 blockNumber) external returns (bytes32) envfree;
    function computeCrossDomainNullifier(bytes32 midnightNullifier, bytes32 domain) external returns (bytes32) envfree;

    // Admin functions
    function pause() external;
    function unpause() external;
    function paused() external returns (bool) envfree;
}

// ============================================================================
// GHOST VARIABLES
// ============================================================================

// Track dust states
ghost mapping(bytes32 => uint8) dustStates;

// Track consumed nullifiers
ghost mapping(bytes32 => bool) consumedNullifiers;

// Track known commitments
ghost mapping(bytes32 => bool) knownCommitments;

// Track current block
ghost uint256 currentBlockGhost {
    init_state axiom currentBlockGhost == 0;
}

// Track total shielded
ghost mathint totalShieldedGhost {
    init_state axiom totalShieldedGhost == 0;
}

// Track total unshielded
ghost mathint totalUnshieldedGhost {
    init_state axiom totalUnshieldedGhost == 0;
}

// ============================================================================
// DEFINITIONS
// ============================================================================

// Dust status
definition DUST_UNKNOWN() returns uint8 = 0;
definition DUST_PENDING() returns uint8 = 1;
definition DUST_COMMITTED() returns uint8 = 2;
definition DUST_SPENT() returns uint8 = 3;

// BLS12-381 field order
definition BLS12_381_ORDER() returns uint256 = 
    52435875175126190479447740508185965837690552500527637822603658699938581184513;

// Finality blocks
definition FINALITY_BLOCKS() returns uint256 = 10;

// ============================================================================
// INVARIANTS
// ============================================================================

// Invariant 1: Current block monotonically increases
invariant currentBlockMonotonic()
    getCurrentBlockNumber() >= currentBlockGhost
    { preserved { currentBlockGhost = getCurrentBlockNumber(); } }

// Invariant 2: Once nullifier used, always used
invariant nullifierUsedImmutable(bytes32 nullifier)
    consumedNullifiers[nullifier] => isNullifierUsed(nullifier);

// Invariant 3: Once commitment known, always known
invariant commitmentKnownImmutable(bytes32 commitment)
    knownCommitments[commitment] => isCommitmentKnown(commitment);

// Invariant 4: Dust states are valid
invariant dustStateValid(bytes32 commitment)
    dustStates[commitment] <= DUST_SPENT();

// Invariant 5: Value conservation - shielded >= unshielded + outstanding
invariant valueConservation()
    getTotalShielded() >= getTotalUnshielded();

// ============================================================================
// RULES
// ============================================================================

// Rule 1: No double nullifier consumption
rule noDoubleNullifierConsumption(env e, bytes32 nullifier, uint256 amount, bytes proof, address recipient) {
    bool wasUsed = isNullifierUsed(nullifier);

    unshield@withrevert(e, nullifier, amount, proof, recipient);

    assert wasUsed => lastReverted, "Should revert if nullifier already used";
}

// Rule 2: No double dust spending
rule noDoubleDustSpending(env e, bytes32 nullifier, bytes spendProof) {
    bool wasUsed = isNullifierUsed(nullifier);

    spendDust@withrevert(e, nullifier, spendProof);

    assert wasUsed => lastReverted, "Should revert if dust already spent";
}

// Rule 3: Nullifier uniqueness - different commitments produce different nullifiers
rule nullifierUniqueness(bytes32 commitment1, bytes32 commitment2, bytes32 owner, uint256 blockNumber) {
    require commitment1 != commitment2;

    bytes32 nf1 = computeNullifier(commitment1, owner, blockNumber);
    bytes32 nf2 = computeNullifier(commitment2, owner, blockNumber);

    assert nf1 != nf2, "Different commitments must produce different nullifiers";
}

// Rule 4: Owner affects nullifier
rule ownerAffectsNullifier(bytes32 commitment, bytes32 owner1, bytes32 owner2, uint256 blockNumber) {
    require owner1 != owner2;

    bytes32 nf1 = computeNullifier(commitment, owner1, blockNumber);
    bytes32 nf2 = computeNullifier(commitment, owner2, blockNumber);

    assert nf1 != nf2, "Different owners must produce different nullifiers";
}

// Rule 5: Block number affects nullifier
rule blockNumberAffectsNullifier(bytes32 commitment, bytes32 owner, uint256 block1, uint256 block2) {
    require block1 != block2;

    bytes32 nf1 = computeNullifier(commitment, owner, block1);
    bytes32 nf2 = computeNullifier(commitment, owner, block2);

    assert nf1 != nf2, "Different block numbers must produce different nullifiers";
}

// Rule 6: Cross-domain nullifier determinism
rule crossDomainNullifierDeterminism(bytes32 midnightNf, bytes32 domain) {
    bytes32 pilNf1 = computeCrossDomainNullifier(midnightNf, domain);
    bytes32 pilNf2 = computeCrossDomainNullifier(midnightNf, domain);

    assert pilNf1 == pilNf2, "Same inputs must produce same PIL nullifier";
}

// Rule 7: Cross-domain direction matters
rule crossDomainDirectionMatters(bytes32 midnightNf, bytes32 domainA, bytes32 domainB) {
    require domainA != domainB;

    bytes32 pilNfA = computeCrossDomainNullifier(midnightNf, domainA);
    bytes32 pilNfB = computeCrossDomainNullifier(midnightNf, domainB);

    assert pilNfA != pilNfB, "Different domains must produce different PIL nullifiers";
}

// Rule 8: Shield creates valid dust
rule shieldCreatesDust(env e, uint256 amount, bytes32 commitment, bytes proof) {
    require amount > 0;
    require !paused();

    bytes32 dustId = shield(e, amount, commitment, proof);

    assert dustId != bytes32(0), "Shield must create non-zero dust ID";
    assert isCommitmentKnown(commitment), "Commitment must be known after shielding";
}

// Rule 9: Unshield requires valid proof
rule unshieldRequiresProof(env e, bytes32 nullifier, uint256 amount, bytes proof, address recipient) {
    require !paused();
    require recipient != address(0);

    bool proofValid = verifySpendProof(nullifier, proof);

    unshield@withrevert(e, nullifier, amount, proof, recipient);

    // If proof is invalid, should revert
    assert !proofValid => lastReverted, "Unshield requires valid spend proof";
}

// Rule 10: Dust status transitions
rule dustStatusTransitions(env e, bytes32 nullifier, bytes spendProof) {
    // Get commitment from nullifier (simplified - would need inverse lookup)
    bytes32 commitment = nullifier;  // Placeholder
    uint8 statusBefore = getDustStatus(commitment);

    spendDust(e, nullifier, spendProof);

    uint8 statusAfter = getDustStatus(commitment);

    // COMMITTED -> SPENT is valid
    assert statusBefore == DUST_COMMITTED() => statusAfter == DUST_SPENT(),
        "COMMITTED can only transition to SPENT";
}

// Rule 11: Total shielded increases on shield
rule totalShieldedIncreases(env e, uint256 amount, bytes32 commitment, bytes proof) {
    uint256 shieldedBefore = getTotalShielded();

    require amount > 0;

    shield(e, amount, commitment, proof);

    uint256 shieldedAfter = getTotalShielded();

    assert shieldedAfter == shieldedBefore + amount, "Total shielded must increase by amount";
}

// Rule 12: Total unshielded increases on unshield
rule totalUnshieldedIncreases(env e, bytes32 nullifier, uint256 amount, bytes proof, address recipient) {
    uint256 unshieldedBefore = getTotalUnshielded();

    require amount > 0;
    require !isNullifierUsed(nullifier);

    unshield(e, nullifier, amount, proof, recipient);

    uint256 unshieldedAfter = getTotalUnshielded();

    assert unshieldedAfter == unshieldedBefore + amount, "Total unshielded must increase by amount";
}

// ============================================================================
// ZK PROOF VERIFICATION RULES
// ============================================================================

// Rule 13: Spend proof verification is deterministic
rule spendProofVerificationDeterministic(bytes32 nullifier, bytes proof) {
    bool result1 = verifySpendProof(nullifier, proof);
    bool result2 = verifySpendProof(nullifier, proof);

    assert result1 == result2, "Spend proof verification must be deterministic";
}

// Rule 14: Output proof verification is deterministic
rule outputProofVerificationDeterministic(bytes32 commitment, bytes proof) {
    bool result1 = verifyOutputProof(commitment, proof);
    bool result2 = verifyOutputProof(commitment, proof);

    assert result1 == result2, "Output proof verification must be deterministic";
}

// Rule 15: Range proof verification is deterministic
rule rangeProofVerificationDeterministic(bytes32 commitment, bytes proof) {
    bool result1 = verifyRangeProof(commitment, proof);
    bool result2 = verifyRangeProof(commitment, proof);

    assert result1 == result2, "Range proof verification must be deterministic";
}

// ============================================================================
// STATE ROOT RULES
// ============================================================================

// Rule 16: State root changes on shield
rule stateRootChangesOnShield(env e, uint256 amount, bytes32 commitment, bytes proof) {
    bytes32 rootBefore = getStateRoot();

    shield(e, amount, commitment, proof);

    bytes32 rootAfter = getStateRoot();

    assert rootAfter != rootBefore, "State root must change on shield";
}

// Rule 17: Nullifier root changes on unshield
rule nullifierRootChangesOnUnshield(env e, bytes32 nullifier, uint256 amount, bytes proof, address recipient) {
    bytes32 rootBefore = getNullifierRoot();

    require !isNullifierUsed(nullifier);

    unshield(e, nullifier, amount, proof, recipient);

    bytes32 rootAfter = getNullifierRoot();

    assert rootAfter != rootBefore, "Nullifier root must change on unshield";
}
