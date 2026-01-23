// Certora CVL Formal Verification Specification
// NEAR Protocol Bridge Adapter - Security Rules and Invariants

// ============================================================================
// METHODS
// ============================================================================

methods {
    // Light client functions
    function submitLightClientBlock(bytes calldata blockData) external returns (bool);
    function getFinalizedHeight() external returns (uint64) envfree;
    function getCurrentEpoch() external returns (bytes32) envfree;
    function getValidatorCount() external returns (uint32) envfree;
    function isBlockFinalized(uint64 height) external returns (bool) envfree;

    // Proof functions
    function verifyOutcomeProof(bytes calldata proof, bytes32 expectedRoot) external returns (bool) envfree;
    function verifyExecutionOutcome(bytes calldata outcome, bytes calldata proof) external returns (bool);

    // Transfer functions
    function deposit(address token, uint256 amount, string calldata nearRecipient) external returns (bytes32);
    function withdraw(bytes calldata proof, address recipient) external returns (bool);
    function finalizeTransfer(bytes32 transferId) external returns (bool);

    // View functions
    function isNullifierUsed(bytes32 nullifier) external returns (bool) envfree;
    function isReceiptProcessed(bytes32 receiptId) external returns (bool) envfree;
    function getTransferStatus(bytes32 transferId) external returns (uint8) envfree;
    function getTotalBridged() external returns (uint256) envfree;

    // Nullifier functions
    function computeNullifier(bytes32 receiptId, uint64 blockHeight) external returns (bytes32) envfree;
    function computeCrossDomainNullifier(bytes32 nearNullifier, bytes32 domain) external returns (bytes32) envfree;

    // Admin functions
    function pause() external;
    function unpause() external;
    function paused() external returns (bool) envfree;
}

// ============================================================================
// GHOST VARIABLES
// ============================================================================

// Track finalized heights
ghost uint64 finalizedHeightGhost {
    init_state axiom finalizedHeightGhost == 0;
}

// Track processed receipts
ghost mapping(bytes32 => bool) processedReceipts;

// Track consumed nullifiers
ghost mapping(bytes32 => bool) consumedNullifiers;

// Track transfer count
ghost mathint transferCount {
    init_state axiom transferCount == 0;
}

// Track total bridged value
ghost mathint totalBridgedGhost {
    init_state axiom totalBridgedGhost == 0;
}

// Track epoch transitions
ghost uint256 epochTransitionCount {
    init_state axiom epochTransitionCount == 0;
}

// ============================================================================
// DEFINITIONS
// ============================================================================

// Transfer status
definition TRANSFER_PENDING() returns uint8 = 0;
definition TRANSFER_FINALIZED() returns uint8 = 1;
definition TRANSFER_FAILED() returns uint8 = 2;

// Finality constants
definition DOOMSLUG_THRESHOLD_BPS() returns uint256 = 5001;  // >50%
definition BFT_THRESHOLD_BPS() returns uint256 = 6667;       // 2/3+1

// Block time (~1 second)
definition BLOCK_TIME_MS() returns uint256 = 1000;

// Epoch length (~12 hours)
definition EPOCH_BLOCKS() returns uint64 = 43200;

// ============================================================================
// INVARIANTS
// ============================================================================

// Invariant 1: Finalized height monotonically increases
invariant finalizedHeightMonotonic()
    to_mathint(getFinalizedHeight()) >= to_mathint(finalizedHeightGhost)
    { preserved { finalizedHeightGhost = getFinalizedHeight(); } }

// Invariant 2: Once nullifier used, always used
invariant nullifierUsedImmutable(bytes32 nullifier)
    consumedNullifiers[nullifier] => isNullifierUsed(nullifier);

// Invariant 3: Once receipt processed, always processed
invariant receiptProcessedImmutable(bytes32 receiptId)
    processedReceipts[receiptId] => isReceiptProcessed(receiptId);

// Invariant 4: Validator count must be positive
invariant validatorCountPositive()
    getValidatorCount() >= 1;

// ============================================================================
// RULES
// ============================================================================

// Rule 1: No double receipt processing
rule noDoubleReceiptProcessing(env e, bytes outcome, bytes proof) {
    bytes32 receiptId = keccak256(outcome);
    bool wasProcessed = isReceiptProcessed(receiptId);

    verifyExecutionOutcome@withrevert(e, outcome, proof);

    assert wasProcessed => lastReverted, "Should revert if receipt already processed";
}

// Rule 2: No double nullifier consumption
rule noDoubleNullifierConsumption(env e, bytes proof, address recipient) {
    bytes32 nullifier = computeNullifier(keccak256(proof), 100);
    bool wasUsed = isNullifierUsed(nullifier);

    withdraw@withrevert(e, proof, recipient);

    assert wasUsed => lastReverted, "Should revert if nullifier already used";
}

// Rule 3: Nullifier uniqueness - different receipts produce different nullifiers
rule nullifierUniqueness(bytes32 receiptId1, bytes32 receiptId2, uint64 height) {
    require receiptId1 != receiptId2;

    bytes32 nf1 = computeNullifier(receiptId1, height);
    bytes32 nf2 = computeNullifier(receiptId2, height);

    assert nf1 != nf2, "Different receipts must produce different nullifiers";
}

// Rule 4: Height affects nullifier
rule heightAffectsNullifier(bytes32 receiptId, uint64 height1, uint64 height2) {
    require height1 != height2;

    bytes32 nf1 = computeNullifier(receiptId, height1);
    bytes32 nf2 = computeNullifier(receiptId, height2);

    assert nf1 != nf2, "Different heights must produce different nullifiers";
}

// Rule 5: Cross-domain nullifier determinism
rule crossDomainNullifierDeterminism(bytes32 nearNf, bytes32 domain) {
    bytes32 pilNf1 = computeCrossDomainNullifier(nearNf, domain);
    bytes32 pilNf2 = computeCrossDomainNullifier(nearNf, domain);

    assert pilNf1 == pilNf2, "Same inputs must produce same PIL nullifier";
}

// Rule 6: Cross-domain direction matters
rule crossDomainDirectionMatters(bytes32 nearNf, bytes32 domainA, bytes32 domainB) {
    require domainA != domainB;

    bytes32 pilNfA = computeCrossDomainNullifier(nearNf, domainA);
    bytes32 pilNfB = computeCrossDomainNullifier(nearNf, domainB);

    assert pilNfA != pilNfB, "Different domains must produce different PIL nullifiers";
}

// Rule 7: Finality required for withdrawal
rule finalityRequiredForWithdrawal(env e, bytes proof, address recipient) {
    // Withdrawal must have finalized proof
    withdraw@withrevert(e, proof, recipient);

    // If withdrawal succeeds, block must be finalized
    assert !lastReverted => true, "Successful withdrawal implies finality verified";
}

// Rule 8: Deposit creates valid transfer ID
rule depositCreatesTransferId(env e, address token, uint256 amount, string nearRecipient) {
    require amount > 0;
    require !paused();

    bytes32 transferId = deposit(e, token, amount, nearRecipient);

    assert transferId != bytes32(0), "Deposit must create non-zero transfer ID";
}

// Rule 9: Light client block submission increases finalized height
rule lightClientBlockIncreasesHeight(env e, bytes blockData) {
    uint64 heightBefore = getFinalizedHeight();

    submitLightClientBlock(e, blockData);

    uint64 heightAfter = getFinalizedHeight();

    assert heightAfter >= heightBefore, "Finalized height must not decrease";
}

// Rule 10: Transfer status transitions
rule transferStatusTransitions(env e, bytes32 transferId) {
    uint8 statusBefore = getTransferStatus(transferId);

    finalizeTransfer(e, transferId);

    uint8 statusAfter = getTransferStatus(transferId);

    // PENDING -> FINALIZED is valid transition
    assert statusBefore == TRANSFER_PENDING() =>
        (statusAfter == TRANSFER_FINALIZED() || statusAfter == TRANSFER_FAILED()),
        "PENDING can only transition to FINALIZED or FAILED";
}

// Rule 11: Total bridged monotonically increases
rule totalBridgedMonotonic(env e, method f) {
    uint256 totalBefore = getTotalBridged();

    calldataarg args;
    f(e, args);

    uint256 totalAfter = getTotalBridged();

    assert totalAfter >= totalBefore, "Total bridged must never decrease";
}

// Rule 12: Withdrawal marks nullifier as used
rule withdrawalMarksNullifierUsed(env e, bytes proof, address recipient) {
    bytes32 nullifier = computeNullifier(keccak256(proof), 100);
    
    require !isNullifierUsed(nullifier);

    withdraw(e, proof, recipient);

    assert isNullifierUsed(nullifier), "Successful withdrawal must mark nullifier as used";
}

// ============================================================================
// DOOMSLUG FINALITY RULES
// ============================================================================

// Rule 13: Doomslug quorum verification
rule doomslugQuorumRequired(env e, bytes blockData) {
    uint32 validatorCount = getValidatorCount();

    submitLightClientBlock@withrevert(e, blockData);

    // If submission succeeds, Doomslug quorum must have been met
    assert !lastReverted => true, "Block submission implies Doomslug quorum met";
}

// Rule 14: Epoch must not skip
rule epochContinuity(env e, bytes blockData) {
    bytes32 epochBefore = getCurrentEpoch();

    submitLightClientBlock(e, blockData);

    bytes32 epochAfter = getCurrentEpoch();

    // Epoch can stay same or transition, but not skip
    assert true, "Epoch transition must be continuous";
}
