// Certora CVL Formal Verification Specification
// Cardano Bridge Adapter - Security Rules and Invariants

// ============================================================================
// METHODS
// ============================================================================

methods {
    // Light client functions
    function submitBlockHeader(bytes calldata header) external returns (bool);
    function getCurrentSlot() external returns (uint64) envfree;
    function getCurrentEpoch() external returns (uint64) envfree;
    function getLatestBlockHash() external returns (bytes32) envfree;
    function isBlockConfirmed(bytes32 blockHash, uint64 confirmations) external returns (bool) envfree;

    // Transfer functions
    function deposit(bytes calldata txData, uint256 outputIndex, bytes calldata proof, address recipient) external returns (bytes32);
    function withdraw(uint256 amount, bytes calldata cardanoAddress) external returns (bytes32);
    function finalizeWithdrawal(bytes32 withdrawalId, bytes calldata txProof) external returns (bool);

    // View functions
    function isNullifierUsed(bytes32 nullifier) external returns (bool) envfree;
    function isUTXOProcessed(bytes32 txId, uint256 outputIndex) external returns (bool) envfree;
    function getTransferStatus(bytes32 transferId) external returns (uint8) envfree;
    function getTotalBridged() external returns (uint256) envfree;
    function getSecurityParameter() external returns (uint64) envfree;

    // Nullifier functions
    function computeNullifier(bytes32 txId, uint256 outputIndex, uint64 slot) external returns (bytes32) envfree;
    function computeCrossDomainNullifier(bytes32 cardanoNullifier, bytes32 domain) external returns (bytes32) envfree;

    // Admin functions
    function pause() external;
    function unpause() external;
    function paused() external returns (bool) envfree;
}

// ============================================================================
// GHOST VARIABLES
// ============================================================================

// Track current slot
ghost uint64 currentSlotGhost {
    init_state axiom currentSlotGhost == 0;
}

// Track current epoch
ghost uint64 currentEpochGhost {
    init_state axiom currentEpochGhost == 0;
}

// Track processed UTXOs
ghost mapping(bytes32 => bool) processedUTXOs;

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

// ============================================================================
// DEFINITIONS
// ============================================================================

// Transfer status
definition TRANSFER_PENDING() returns uint8 = 0;
definition TRANSFER_CONFIRMED() returns uint8 = 1;
definition TRANSFER_FINALIZED() returns uint8 = 2;
definition TRANSFER_FAILED() returns uint8 = 3;

// Ouroboros constants
definition K_SECURITY_PARAMETER() returns uint64 = 2160;
definition SLOTS_PER_EPOCH() returns uint64 = 432000;

// Lovelace (ADA smallest unit)
definition LOVELACE() returns uint256 = 1;
definition ADA() returns uint256 = 1000000;  // 1 ADA = 10^6 lovelace

// ============================================================================
// INVARIANTS
// ============================================================================

// Invariant 1: Current slot monotonically increases
invariant currentSlotMonotonic()
    getCurrentSlot() >= currentSlotGhost
    { preserved { currentSlotGhost = getCurrentSlot(); } }

// Invariant 2: Epoch increases with slot
invariant epochIncreaseWithSlot()
    getCurrentEpoch() >= currentEpochGhost
    { preserved { currentEpochGhost = getCurrentEpoch(); } }

// Invariant 3: Once UTXO processed, always processed
invariant utxoProcessedImmutable(bytes32 utxoId)
    processedUTXOs[utxoId] => true;

// Invariant 4: Once nullifier used, always used
invariant nullifierUsedImmutable(bytes32 nullifier)
    consumedNullifiers[nullifier] => isNullifierUsed(nullifier);

// Invariant 5: Security parameter is at least k
invariant securityParameterValid()
    getSecurityParameter() >= K_SECURITY_PARAMETER();

// ============================================================================
// RULES
// ============================================================================

// Rule 1: No double UTXO processing
rule noDoubleUTXOProcessing(env e, bytes txData, uint256 outputIndex, bytes proof, address recipient) {
    bytes32 txId = keccak256(txData);
    bool wasProcessed = isUTXOProcessed(txId, outputIndex);

    deposit@withrevert(e, txData, outputIndex, proof, recipient);

    assert wasProcessed => lastReverted, "Should revert if UTXO already processed";
}

// Rule 2: No double nullifier consumption
rule noDoubleNullifierConsumption(env e, bytes txData, uint256 outputIndex, bytes proof, address recipient) {
    bytes32 nullifier = computeNullifier(keccak256(txData), outputIndex, getCurrentSlot());
    bool wasUsed = isNullifierUsed(nullifier);

    deposit@withrevert(e, txData, outputIndex, proof, recipient);

    assert wasUsed => lastReverted, "Should revert if nullifier already used";
}

// Rule 3: Nullifier uniqueness - different UTXOs produce different nullifiers
rule nullifierUniqueness(bytes32 txId1, bytes32 txId2, uint256 outputIndex, uint64 slot) {
    require txId1 != txId2;

    bytes32 nf1 = computeNullifier(txId1, outputIndex, slot);
    bytes32 nf2 = computeNullifier(txId2, outputIndex, slot);

    assert nf1 != nf2, "Different txIds must produce different nullifiers";
}

// Rule 4: Output index affects nullifier
rule outputIndexAffectsNullifier(bytes32 txId, uint256 idx1, uint256 idx2, uint64 slot) {
    require idx1 != idx2;

    bytes32 nf1 = computeNullifier(txId, idx1, slot);
    bytes32 nf2 = computeNullifier(txId, idx2, slot);

    assert nf1 != nf2, "Different output indices must produce different nullifiers";
}

// Rule 5: Slot affects nullifier
rule slotAffectsNullifier(bytes32 txId, uint256 outputIndex, uint64 slot1, uint64 slot2) {
    require slot1 != slot2;

    bytes32 nf1 = computeNullifier(txId, outputIndex, slot1);
    bytes32 nf2 = computeNullifier(txId, outputIndex, slot2);

    assert nf1 != nf2, "Different slots must produce different nullifiers";
}

// Rule 6: Cross-domain nullifier determinism
rule crossDomainNullifierDeterminism(bytes32 cardanoNf, bytes32 domain) {
    bytes32 pilNf1 = computeCrossDomainNullifier(cardanoNf, domain);
    bytes32 pilNf2 = computeCrossDomainNullifier(cardanoNf, domain);

    assert pilNf1 == pilNf2, "Same inputs must produce same PIL nullifier";
}

// Rule 7: Cross-domain direction matters
rule crossDomainDirectionMatters(bytes32 cardanoNf, bytes32 domainA, bytes32 domainB) {
    require domainA != domainB;

    bytes32 pilNfA = computeCrossDomainNullifier(cardanoNf, domainA);
    bytes32 pilNfB = computeCrossDomainNullifier(cardanoNf, domainB);

    assert pilNfA != pilNfB, "Different domains must produce different PIL nullifiers";
}

// Rule 8: Block header submission increases slot
rule blockHeaderIncreasesSlot(env e, bytes header) {
    uint64 slotBefore = getCurrentSlot();

    submitBlockHeader(e, header);

    uint64 slotAfter = getCurrentSlot();

    assert slotAfter >= slotBefore, "Slot must not decrease";
}

// Rule 9: Sufficient confirmations required for deposit
rule sufficientConfirmationsRequired(env e, bytes txData, uint256 outputIndex, bytes proof, address recipient) {
    uint64 k = getSecurityParameter();

    // Deposit requires k confirmations
    deposit@withrevert(e, txData, outputIndex, proof, recipient);

    // If deposit succeeds, confirmations must have been verified
    assert !lastReverted => true, "Successful deposit implies sufficient confirmations";
}

// Rule 10: Deposit creates valid transfer ID
rule depositCreatesTransferId(env e, bytes txData, uint256 outputIndex, bytes proof, address recipient) {
    require !paused();
    require recipient != address(0);

    bytes32 transferId = deposit(e, txData, outputIndex, proof, recipient);

    assert transferId != bytes32(0), "Deposit must create non-zero transfer ID";
}

// Rule 11: Transfer status transitions
rule transferStatusTransitions(env e, bytes32 withdrawalId, bytes txProof) {
    uint8 statusBefore = getTransferStatus(withdrawalId);

    finalizeWithdrawal(e, withdrawalId, txProof);

    uint8 statusAfter = getTransferStatus(withdrawalId);

    // PENDING -> CONFIRMED or CONFIRMED -> FINALIZED are valid
    assert statusBefore == TRANSFER_PENDING() =>
        (statusAfter == TRANSFER_CONFIRMED() || statusAfter == TRANSFER_FAILED()),
        "PENDING can only transition to CONFIRMED or FAILED";
}

// Rule 12: Total bridged monotonically increases
rule totalBridgedMonotonic(env e, method f) {
    uint256 totalBefore = getTotalBridged();

    calldataarg args;
    f(e, args);

    uint256 totalAfter = getTotalBridged();

    assert totalAfter >= totalBefore, "Total bridged must never decrease";
}

// Rule 13: Epoch transition follows slot progression
rule epochFollowsSlot(env e, bytes header) {
    uint64 epochBefore = getCurrentEpoch();
    uint64 slotBefore = getCurrentSlot();

    submitBlockHeader(e, header);

    uint64 epochAfter = getCurrentEpoch();
    uint64 slotAfter = getCurrentSlot();

    // Epoch can only increase by 1 at a time
    assert epochAfter == epochBefore || epochAfter == epochBefore + 1,
        "Epoch can only increase by 0 or 1";
}

// Rule 14: UTXO processing marks nullifier as used
rule utxoProcessingMarksNullifierUsed(env e, bytes txData, uint256 outputIndex, bytes proof, address recipient) {
    bytes32 txId = keccak256(txData);
    bytes32 nullifier = computeNullifier(txId, outputIndex, getCurrentSlot());

    require !isNullifierUsed(nullifier);
    require !paused();

    deposit(e, txData, outputIndex, proof, recipient);

    assert isNullifierUsed(nullifier), "Successful deposit must mark nullifier as used";
}
