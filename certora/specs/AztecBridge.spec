// Certora CVL Formal Verification Specification
// Aztec Bridge Adapter - Security Rules and Invariants

// ============================================================================
// METHODS
// ============================================================================

methods {
    // Note management functions
    function createNote(bytes32 noteHash, address owner, uint256 value) external returns (bytes32);
    function consumeNote(bytes32 noteHash, bytes calldata proof) external returns (bool);
    function getNoteStatus(bytes32 noteHash) external returns (uint8) envfree;

    // L1 <-> L2 messaging
    function sendL1ToL2Message(bytes32 recipient, bytes calldata content, bytes32 secretHash, uint256 deadline) external returns (bytes32);
    function consumeL1ToL2Message(bytes32 messageHash, bytes calldata proof) external returns (bool);
    function sendL2ToL1Message(address recipient, bytes calldata content) external returns (bytes32);
    function processL2ToL1Message(bytes32 messageHash, bytes calldata proof) external returns (bool);

    // Transfer functions
    function deposit(address token, uint256 amount, bytes32 l2Recipient) external returns (bytes32);
    function withdraw(bytes32 noteHash, bytes calldata proof, address recipient) external returns (bool);

    // Tree root functions
    function getNoteHashTreeRoot() external returns (bytes32) envfree;
    function getNullifierTreeRoot() external returns (bytes32) envfree;
    function getPublicDataTreeRoot() external returns (bytes32) envfree;

    // View functions
    function isNullifierUsed(bytes32 nullifier) external returns (bool) envfree;
    function isL1MessageConsumed(bytes32 messageHash) external returns (bool) envfree;
    function getCurrentBlockNumber() external returns (uint256) envfree;
    function getTotalBridged() external returns (uint256) envfree;

    // Nullifier functions
    function computeNullifier(bytes32 noteHash, bytes32 secretKey, uint256 blockNumber) external returns (bytes32) envfree;
    function computeCrossDomainNullifier(bytes32 aztecNullifier, bytes32 domain) external returns (bytes32) envfree;
    function computeMessageHash(bytes32 sender, bytes32 recipient, bytes calldata content) external returns (bytes32) envfree;

    // Admin functions
    function pause() external;
    function unpause() external;
    function paused() external returns (bool) envfree;
}

// ============================================================================
// GHOST VARIABLES
// ============================================================================

// Track note states
ghost mapping(bytes32 => uint8) noteStates;

// Track consumed nullifiers
ghost mapping(bytes32 => bool) consumedNullifiers;

// Track consumed L1 messages
ghost mapping(bytes32 => bool) consumedL1Messages;

// Track current block
ghost uint256 currentBlockGhost {
    init_state axiom currentBlockGhost == 0;
}

// Track note count
ghost mathint noteCount {
    init_state axiom noteCount == 0;
}

// Track total bridged value
ghost mathint totalBridgedGhost {
    init_state axiom totalBridgedGhost == 0;
}

// ============================================================================
// DEFINITIONS
// ============================================================================

// Note status
definition NOTE_PENDING() returns uint8 = 0;
definition NOTE_COMMITTED() returns uint8 = 1;
definition NOTE_SPENT() returns uint8 = 2;

// BN254 field order
definition BN254_ORDER() returns uint256 = 
    21888242871839275222246405745257275088548364400416034343698204186575808495617;

// Grumpkin curve order
definition GRUMPKIN_ORDER() returns uint256 = 
    21888242871839275222246405745257275088696311157297823662689037894645226208583;

// Finality blocks
definition FINALITY_BLOCKS() returns uint256 = 5;

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

// Invariant 3: Once L1 message consumed, always consumed
invariant l1MessageConsumedImmutable(bytes32 messageHash)
    consumedL1Messages[messageHash] => isL1MessageConsumed(messageHash);

// Invariant 4: Note states are valid
invariant noteStateValid(bytes32 noteHash)
    noteStates[noteHash] <= NOTE_SPENT();

// ============================================================================
// RULES
// ============================================================================

// Rule 1: No double note spending
rule noDoubleNoteSpending(env e, bytes32 noteHash, bytes proof) {
    uint8 statusBefore = getNoteStatus(noteHash);

    consumeNote@withrevert(e, noteHash, proof);

    assert statusBefore == NOTE_SPENT() => lastReverted,
        "Should revert if note already spent";
}

// Rule 2: No double nullifier consumption
rule noDoubleNullifierConsumption(env e, bytes32 noteHash, bytes proof, address recipient) {
    bytes32 nullifier = computeNullifier(noteHash, bytes32(0), getCurrentBlockNumber());
    bool wasUsed = isNullifierUsed(nullifier);

    withdraw@withrevert(e, noteHash, proof, recipient);

    assert wasUsed => lastReverted, "Should revert if nullifier already used";
}

// Rule 3: No double L1 message consumption
rule noDoubleL1MessageConsumption(env e, bytes32 messageHash, bytes proof) {
    bool wasConsumed = isL1MessageConsumed(messageHash);

    consumeL1ToL2Message@withrevert(e, messageHash, proof);

    assert wasConsumed => lastReverted, "Should revert if L1 message already consumed";
}

// Rule 4: Nullifier uniqueness - different notes produce different nullifiers
rule nullifierUniqueness(bytes32 noteHash1, bytes32 noteHash2, bytes32 secretKey, uint256 blockNumber) {
    require noteHash1 != noteHash2;

    bytes32 nf1 = computeNullifier(noteHash1, secretKey, blockNumber);
    bytes32 nf2 = computeNullifier(noteHash2, secretKey, blockNumber);

    assert nf1 != nf2, "Different notes must produce different nullifiers";
}

// Rule 5: Secret key affects nullifier
rule secretKeyAffectsNullifier(bytes32 noteHash, bytes32 key1, bytes32 key2, uint256 blockNumber) {
    require key1 != key2;

    bytes32 nf1 = computeNullifier(noteHash, key1, blockNumber);
    bytes32 nf2 = computeNullifier(noteHash, key2, blockNumber);

    assert nf1 != nf2, "Different keys must produce different nullifiers";
}

// Rule 6: Cross-domain nullifier determinism
rule crossDomainNullifierDeterminism(bytes32 aztecNf, bytes32 domain) {
    bytes32 pilNf1 = computeCrossDomainNullifier(aztecNf, domain);
    bytes32 pilNf2 = computeCrossDomainNullifier(aztecNf, domain);

    assert pilNf1 == pilNf2, "Same inputs must produce same PIL nullifier";
}

// Rule 7: Cross-domain direction matters
rule crossDomainDirectionMatters(bytes32 aztecNf, bytes32 domainA, bytes32 domainB) {
    require domainA != domainB;

    bytes32 pilNfA = computeCrossDomainNullifier(aztecNf, domainA);
    bytes32 pilNfB = computeCrossDomainNullifier(aztecNf, domainB);

    assert pilNfA != pilNfB, "Different domains must produce different PIL nullifiers";
}

// Rule 8: Deposit creates valid transfer ID
rule depositCreatesTransferId(env e, address token, uint256 amount, bytes32 l2Recipient) {
    require amount > 0;
    require !paused();

    bytes32 transferId = deposit(e, token, amount, l2Recipient);

    assert transferId != bytes32(0), "Deposit must create non-zero transfer ID";
}

// Rule 9: L1 to L2 message creates valid hash
rule l1ToL2MessageCreatesHash(env e, bytes32 recipient, bytes content, bytes32 secretHash, uint256 deadline) {
    require deadline > e.block.timestamp;
    require !paused();

    bytes32 messageHash = sendL1ToL2Message(e, recipient, content, secretHash, deadline);

    assert messageHash != bytes32(0), "L1 to L2 message must create non-zero hash";
}

// Rule 10: Note status transitions
rule noteStatusTransitions(env e, bytes32 noteHash, bytes proof) {
    uint8 statusBefore = getNoteStatus(noteHash);

    consumeNote(e, noteHash, proof);

    uint8 statusAfter = getNoteStatus(noteHash);

    // COMMITTED -> SPENT is valid
    assert statusBefore == NOTE_COMMITTED() => statusAfter == NOTE_SPENT(),
        "COMMITTED can only transition to SPENT";
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
rule withdrawalMarksNullifierUsed(env e, bytes32 noteHash, bytes proof, address recipient) {
    bytes32 nullifier = computeNullifier(noteHash, bytes32(0), getCurrentBlockNumber());

    require !isNullifierUsed(nullifier);
    require !paused();
    require getNoteStatus(noteHash) == NOTE_COMMITTED();

    withdraw(e, noteHash, proof, recipient);

    assert isNullifierUsed(nullifier), "Successful withdrawal must mark nullifier as used";
}

// ============================================================================
// TREE ROOT RULES
// ============================================================================

// Rule 13: Note hash tree root changes on note creation
rule noteHashTreeRootChanges(env e, bytes32 noteHash, address owner, uint256 value) {
    bytes32 rootBefore = getNoteHashTreeRoot();

    createNote(e, noteHash, owner, value);

    bytes32 rootAfter = getNoteHashTreeRoot();

    // Root should change (new note added)
    assert rootAfter != rootBefore, "Note hash tree root must change on note creation";
}

// Rule 14: Nullifier tree root changes on note spending
rule nullifierTreeRootChanges(env e, bytes32 noteHash, bytes proof) {
    bytes32 rootBefore = getNullifierTreeRoot();
    require getNoteStatus(noteHash) == NOTE_COMMITTED();

    consumeNote(e, noteHash, proof);

    bytes32 rootAfter = getNullifierTreeRoot();

    // Nullifier tree root should change
    assert rootAfter != rootBefore, "Nullifier tree root must change on note spending";
}
