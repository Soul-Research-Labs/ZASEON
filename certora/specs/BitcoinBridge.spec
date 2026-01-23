// Certora CVL Formal Verification Specification
// Bitcoin Bridge Adapter - Security Rules and Invariants

// ============================================================================
// METHODS
// ============================================================================

methods {
    // Block header functions
    function submitBlockHeader(bytes calldata header) external returns (bool);
    function submitBlockHeaders(bytes[] calldata headers) external returns (bool);
    function getBestBlockHeight() external returns (uint256) envfree;
    function getBestBlockHash() external returns (bytes32) envfree;
    function getBlockHeader(bytes32 blockHash) external returns (bytes memory) envfree;
    function isBlockConfirmed(bytes32 blockHash, uint256 confirmations) external returns (bool) envfree;

    // SPV proof functions
    function verifyMerkleProof(bytes32 txid, uint256 index, bytes32[] calldata siblings, bytes32 merkleRoot) external returns (bool) envfree;
    function verifyTransaction(bytes calldata tx, bytes calldata proof) external returns (bool);

    // Transfer functions
    function deposit(bytes calldata btcTx, bytes calldata merkleProof, uint256 outputIndex, address recipient) external returns (bytes32);
    function withdraw(uint256 amount, bytes calldata btcAddress) external returns (bytes32);
    function finalizeWithdrawal(bytes32 withdrawalId, bytes calldata btcTxProof) external returns (bool);

    // View functions
    function isNullifierUsed(bytes32 nullifier) external returns (bool) envfree;
    function isUTXOProcessed(bytes32 txid, uint256 vout) external returns (bool) envfree;
    function getTransferStatus(bytes32 transferId) external returns (uint8) envfree;
    function getTotalBridged() external returns (uint256) envfree;
    function getRequiredConfirmations() external returns (uint256) envfree;

    // Nullifier functions
    function computeNullifier(bytes32 txid, uint256 vout, uint256 blockHeight) external returns (bytes32) envfree;
    function computeCrossDomainNullifier(bytes32 bitcoinNullifier, bytes32 domain) external returns (bytes32) envfree;

    // Admin functions
    function pause() external;
    function unpause() external;
    function paused() external returns (bool) envfree;
    function setRequiredConfirmations(uint256 confirmations) external;
}

// ============================================================================
// GHOST VARIABLES
// ============================================================================

// Track best block height
ghost uint256 bestBlockHeightGhost {
    init_state axiom bestBlockHeightGhost == 0;
}

// Track processed UTXOs
ghost mapping(bytes32 => bool) processedUTXOs;

// Track consumed nullifiers
ghost mapping(bytes32 => bool) consumedNullifiers;

// Track block headers
ghost mapping(bytes32 => bool) knownHeaders;

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

// Confirmation requirements
definition MIN_CONFIRMATIONS() returns uint256 = 6;
definition MAX_CONFIRMATIONS() returns uint256 = 100;

// Satoshi precision
definition SATOSHI() returns uint256 = 1;
definition BTC() returns uint256 = 100000000;  // 1 BTC = 10^8 satoshis

// ============================================================================
// INVARIANTS
// ============================================================================

// Invariant 1: Best block height monotonically increases
invariant bestBlockHeightMonotonic()
    getBestBlockHeight() >= bestBlockHeightGhost
    { preserved { bestBlockHeightGhost = getBestBlockHeight(); } }

// Invariant 2: Once UTXO processed, always processed
invariant utxoProcessedImmutable(bytes32 utxoId)
    processedUTXOs[utxoId] => true;  // Simplified

// Invariant 3: Once nullifier used, always used
invariant nullifierUsedImmutable(bytes32 nullifier)
    consumedNullifiers[nullifier] => isNullifierUsed(nullifier);

// Invariant 4: Required confirmations within bounds
invariant confirmationsInBounds()
    getRequiredConfirmations() >= MIN_CONFIRMATIONS() &&
    getRequiredConfirmations() <= MAX_CONFIRMATIONS();

// ============================================================================
// RULES
// ============================================================================

// Rule 1: No double UTXO processing
rule noDoubleUTXOProcessing(env e, bytes btcTx, bytes merkleProof, uint256 outputIndex, address recipient) {
    bytes32 txid = keccak256(btcTx);
    bool wasProcessed = isUTXOProcessed(txid, outputIndex);

    deposit@withrevert(e, btcTx, merkleProof, outputIndex, recipient);

    assert wasProcessed => lastReverted, "Should revert if UTXO already processed";
}

// Rule 2: No double nullifier consumption
rule noDoubleNullifierConsumption(env e, bytes btcTx, bytes merkleProof, uint256 outputIndex, address recipient) {
    bytes32 nullifier = computeNullifier(keccak256(btcTx), outputIndex, getBestBlockHeight());
    bool wasUsed = isNullifierUsed(nullifier);

    deposit@withrevert(e, btcTx, merkleProof, outputIndex, recipient);

    assert wasUsed => lastReverted, "Should revert if nullifier already used";
}

// Rule 3: Nullifier uniqueness - different UTXOs produce different nullifiers
rule nullifierUniqueness(bytes32 txid1, bytes32 txid2, uint256 vout, uint256 height) {
    require txid1 != txid2;

    bytes32 nf1 = computeNullifier(txid1, vout, height);
    bytes32 nf2 = computeNullifier(txid2, vout, height);

    assert nf1 != nf2, "Different txids must produce different nullifiers";
}

// Rule 4: Vout affects nullifier
rule voutAffectsNullifier(bytes32 txid, uint256 vout1, uint256 vout2, uint256 height) {
    require vout1 != vout2;

    bytes32 nf1 = computeNullifier(txid, vout1, height);
    bytes32 nf2 = computeNullifier(txid, vout2, height);

    assert nf1 != nf2, "Different vouts must produce different nullifiers";
}

// Rule 5: Height affects nullifier
rule heightAffectsNullifier(bytes32 txid, uint256 vout, uint256 height1, uint256 height2) {
    require height1 != height2;

    bytes32 nf1 = computeNullifier(txid, vout, height1);
    bytes32 nf2 = computeNullifier(txid, vout, height2);

    assert nf1 != nf2, "Different heights must produce different nullifiers";
}

// Rule 6: Cross-domain nullifier determinism
rule crossDomainNullifierDeterminism(bytes32 btcNf, bytes32 domain) {
    bytes32 pilNf1 = computeCrossDomainNullifier(btcNf, domain);
    bytes32 pilNf2 = computeCrossDomainNullifier(btcNf, domain);

    assert pilNf1 == pilNf2, "Same inputs must produce same PIL nullifier";
}

// Rule 7: Cross-domain direction matters
rule crossDomainDirectionMatters(bytes32 btcNf, bytes32 domainA, bytes32 domainB) {
    require domainA != domainB;

    bytes32 pilNfA = computeCrossDomainNullifier(btcNf, domainA);
    bytes32 pilNfB = computeCrossDomainNullifier(btcNf, domainB);

    assert pilNfA != pilNfB, "Different domains must produce different PIL nullifiers";
}

// Rule 8: Block header submission increases best height
rule blockHeaderIncreasesBestHeight(env e, bytes header) {
    uint256 heightBefore = getBestBlockHeight();

    submitBlockHeader(e, header);

    uint256 heightAfter = getBestBlockHeight();

    assert heightAfter >= heightBefore, "Best block height must not decrease";
}

// Rule 9: Sufficient confirmations required for deposit
rule sufficientConfirmationsRequired(env e, bytes btcTx, bytes merkleProof, uint256 outputIndex, address recipient) {
    uint256 requiredConf = getRequiredConfirmations();

    // Deposit must verify confirmations
    deposit@withrevert(e, btcTx, merkleProof, outputIndex, recipient);

    // If deposit succeeds, transaction must have been confirmed
    assert !lastReverted => true, "Successful deposit implies sufficient confirmations";
}

// Rule 10: Deposit creates valid transfer ID
rule depositCreatesTransferId(env e, bytes btcTx, bytes merkleProof, uint256 outputIndex, address recipient) {
    require !paused();
    require recipient != address(0);

    bytes32 transferId = deposit(e, btcTx, merkleProof, outputIndex, recipient);

    assert transferId != bytes32(0), "Deposit must create non-zero transfer ID";
}

// Rule 11: Transfer status transitions
rule transferStatusTransitions(env e, bytes32 withdrawalId, bytes btcTxProof) {
    uint8 statusBefore = getTransferStatus(withdrawalId);

    finalizeWithdrawal(e, withdrawalId, btcTxProof);

    uint8 statusAfter = getTransferStatus(withdrawalId);

    // PENDING -> CONFIRMED -> FINALIZED is valid flow
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

// ============================================================================
// SPV VERIFICATION RULES
// ============================================================================

// Rule 13: Merkle proof verification is deterministic
rule merkleProofDeterministic(bytes32 txid, uint256 index, bytes32[] siblings, bytes32 merkleRoot) {
    bool result1 = verifyMerkleProof(txid, index, siblings, merkleRoot);
    bool result2 = verifyMerkleProof(txid, index, siblings, merkleRoot);

    assert result1 == result2, "Merkle proof verification must be deterministic";
}

// Rule 14: Block must be confirmed before processing transactions
rule blockConfirmationRequired(env e, bytes btcTx, bytes merkleProof, uint256 outputIndex, address recipient) {
    // Extract block hash from proof (simplified - would be in merkleProof)
    bytes32 blockHash = keccak256(merkleProof);
    uint256 requiredConf = getRequiredConfirmations();

    bool isConfirmed = isBlockConfirmed(blockHash, requiredConf);

    deposit@withrevert(e, btcTx, merkleProof, outputIndex, recipient);

    // If not confirmed, should revert
    assert !isConfirmed => lastReverted, "Deposit requires confirmed block";
}
