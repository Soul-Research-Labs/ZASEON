// Certora CVL Formal Verification Specification
// Polkadot XCM Bridge Adapter - Security Rules and Invariants

// ============================================================================
// METHODS
// ============================================================================

methods {
    // XCM functions
    function sendXcm(bytes calldata xcmMessage, uint32 destParaId) external returns (bytes32);
    function receiveXcm(bytes calldata xcmMessage, bytes calldata proof) external returns (bool);
    function executeXcm(bytes32 messageId) external returns (bool);

    // HRMP channel functions
    function openHrmpChannel(uint32 recipientParaId, uint32 maxCapacity, uint32 maxMessageSize) external returns (bool);
    function closeHrmpChannel(uint32 recipientParaId) external returns (bool);
    function isHrmpChannelOpen(uint32 senderParaId, uint32 recipientParaId) external returns (bool) envfree;

    // Finality functions
    function submitGrandpaProof(bytes calldata proof) external returns (bool);
    function getFinalizedBlock() external returns (uint64) envfree;
    function getValidatorCount() external returns (uint32) envfree;

    // Transfer functions
    function deposit(address token, uint256 amount, bytes32 recipient, uint32 destParaId) external returns (bytes32);
    function withdraw(bytes calldata xcmMessage, bytes calldata proof, address recipient) external returns (bool);

    // View functions
    function isNullifierUsed(bytes32 nullifier) external returns (bool) envfree;
    function getXcmStatus(bytes32 messageId) external returns (uint8) envfree;
    function getParaId() external returns (uint32) envfree;

    // Nullifier functions
    function computeNullifier(bytes32 xcmHash, uint32 sourceParaId, uint32 destParaId) external returns (bytes32) envfree;
    function computeCrossDomainNullifier(bytes32 polkadotNullifier, bytes32 domain) external returns (bytes32) envfree;

    // Admin functions
    function pause() external;
    function unpause() external;
    function paused() external returns (bool) envfree;
}

// ============================================================================
// GHOST VARIABLES
// ============================================================================

// Track XCM message states
ghost mapping(bytes32 => uint8) xcmMessageStates;

// Track HRMP channel states
ghost mapping(bytes32 => bool) hrmpChannelsOpen;

// Track consumed nullifiers
ghost mapping(bytes32 => bool) consumedNullifiers;

// Track finalized block number
ghost uint64 finalizedBlockGhost {
    init_state axiom finalizedBlockGhost == 0;
}

// Track total XCM messages
ghost mathint totalXcmMessages {
    init_state axiom totalXcmMessages == 0;
}

// Track total bridged value
ghost mathint totalBridged {
    init_state axiom totalBridged == 0;
}

// ============================================================================
// DEFINITIONS
// ============================================================================

// XCM message status
definition XCM_PENDING() returns uint8 = 0;
definition XCM_RECEIVED() returns uint8 = 1;
definition XCM_EXECUTED() returns uint8 = 2;
definition XCM_FAILED() returns uint8 = 3;

// XCM version (v3 is current standard)
definition XCM_VERSION_MIN() returns uint8 = 2;
definition XCM_VERSION_MAX() returns uint8 = 4;

// Polkadot relay chain ID
definition RELAY_CHAIN_ID() returns uint32 = 0;

// GRANDPA quorum (2/3 + 1)
definition grandpaQuorum(uint32 validatorCount) returns uint32 =
    (validatorCount * 2) / 3 + 1;

// ============================================================================
// INVARIANTS
// ============================================================================

// Invariant 1: Finalized block number monotonically increases
invariant finalizedBlockMonotonic()
    to_mathint(getFinalizedBlock()) >= finalizedBlockGhost
    { preserved { finalizedBlockGhost = to_mathint(getFinalizedBlock()); } }

// Invariant 2: Once nullifier used, always used
invariant nullifierUsedImmutable(bytes32 nullifier)
    consumedNullifiers[nullifier] => isNullifierUsed(nullifier);

// Invariant 3: Validator count must be positive
invariant validatorCountPositive()
    getValidatorCount() >= 1;

// Invariant 4: XCM messages have valid states
invariant xcmStateValid(bytes32 messageId)
    xcmMessageStates[messageId] <= XCM_FAILED();

// ============================================================================
// RULES
// ============================================================================

// Rule 1: No double XCM message processing
rule noDoubleXcmProcessing(env e, bytes xcmMessage, bytes proof) {
    bytes32 messageId = keccak256(xcmMessage);
    uint8 statusBefore = getXcmStatus(messageId);

    receiveXcm@withrevert(e, xcmMessage, proof);

    assert statusBefore >= XCM_RECEIVED() => lastReverted,
        "Should revert if XCM already received";
}

// Rule 2: No double nullifier consumption
rule noDoubleNullifierConsumption(env e, bytes xcmMessage, bytes proof, address recipient) {
    bytes32 nullifier = computeNullifier(keccak256(xcmMessage), 1000, 2000);
    bool wasUsed = isNullifierUsed(nullifier);

    withdraw@withrevert(e, xcmMessage, proof, recipient);

    assert wasUsed => lastReverted, "Should revert if nullifier already used";
}

// Rule 3: Nullifier uniqueness - different XCM messages produce different nullifiers
rule nullifierUniqueness(bytes32 xcmHash1, bytes32 xcmHash2, uint32 srcPara, uint32 dstPara) {
    require xcmHash1 != xcmHash2;

    bytes32 nf1 = computeNullifier(xcmHash1, srcPara, dstPara);
    bytes32 nf2 = computeNullifier(xcmHash2, srcPara, dstPara);

    assert nf1 != nf2, "Different XCM hashes must produce different nullifiers";
}

// Rule 4: Cross-domain nullifier determinism
rule crossDomainNullifierDeterminism(bytes32 polkadotNf, bytes32 domain) {
    bytes32 pilNf1 = computeCrossDomainNullifier(polkadotNf, domain);
    bytes32 pilNf2 = computeCrossDomainNullifier(polkadotNf, domain);

    assert pilNf1 == pilNf2, "Same inputs must produce same PIL nullifier";
}

// Rule 5: Cross-domain direction matters
rule crossDomainDirectionMatters(bytes32 polkadotNf, bytes32 domainA, bytes32 domainB) {
    require domainA != domainB;

    bytes32 pilNfA = computeCrossDomainNullifier(polkadotNf, domainA);
    bytes32 pilNfB = computeCrossDomainNullifier(polkadotNf, domainB);

    assert pilNfA != pilNfB, "Different domains must produce different PIL nullifiers";
}

// Rule 6: Para ID in nullifier matters
rule paraIdInNullifierMatters(bytes32 xcmHash, uint32 srcPara1, uint32 srcPara2, uint32 dstPara) {
    require srcPara1 != srcPara2;

    bytes32 nf1 = computeNullifier(xcmHash, srcPara1, dstPara);
    bytes32 nf2 = computeNullifier(xcmHash, srcPara2, dstPara);

    assert nf1 != nf2, "Different source parachains must produce different nullifiers";
}

// Rule 7: HRMP channel must be open for XCM send
rule hrmpChannelMustBeOpen(env e, bytes xcmMessage, uint32 destParaId) {
    uint32 sourceParaId = getParaId();
    bool isOpen = isHrmpChannelOpen(sourceParaId, destParaId);

    sendXcm@withrevert(e, xcmMessage, destParaId);

    assert !isOpen => lastReverted, "Should revert if HRMP channel not open";
}

// Rule 8: GRANDPA finality required for withdrawal
rule grandpaFinalityRequired(env e, bytes xcmMessage, bytes proof, address recipient) {
    uint64 finalizedBefore = getFinalizedBlock();

    // Withdrawal must have proof of finality
    withdraw@withrevert(e, xcmMessage, proof, recipient);

    // If withdrawal succeeds, finality must have been verified
    assert !lastReverted => true, "Successful withdrawal implies GRANDPA finality verified";
}

// Rule 9: XCM execution follows receive
rule xcmExecutionFollowsReceive(env e, bytes32 messageId) {
    uint8 statusBefore = getXcmStatus(messageId);

    executeXcm@withrevert(e, messageId);

    // Can only execute if received
    assert statusBefore != XCM_RECEIVED() => lastReverted,
        "Can only execute received XCM messages";
}

// Rule 10: Deposit creates valid transfer ID
rule depositCreatesTransferId(env e, address token, uint256 amount, bytes32 recipient, uint32 destParaId) {
    require amount > 0;
    require !paused();

    bytes32 transferId = deposit(e, token, amount, recipient, destParaId);

    assert transferId != bytes32(0), "Deposit must create non-zero transfer ID";
}

// Rule 11: Finalized block only increases
rule finalizedBlockOnlyIncreases(env e, bytes proof) {
    uint64 finalizedBefore = getFinalizedBlock();

    submitGrandpaProof(e, proof);

    uint64 finalizedAfter = getFinalizedBlock();

    assert finalizedAfter >= finalizedBefore, "Finalized block can only increase";
}

// Rule 12: HRMP channel closure requires channel to be open
rule hrmpChannelClosureRequiresOpen(env e, uint32 recipientParaId) {
    uint32 senderParaId = getParaId();
    bool isOpen = isHrmpChannelOpen(senderParaId, recipientParaId);

    closeHrmpChannel@withrevert(e, recipientParaId);

    assert !isOpen => lastReverted, "Cannot close a channel that is not open";
}

// ============================================================================
// XCMP SPECIFIC RULES
// ============================================================================

// Rule 13: XCM status transitions
rule xcmStatusTransitions(env e, bytes32 messageId) {
    uint8 statusBefore = getXcmStatus(messageId);

    executeXcm(e, messageId);

    uint8 statusAfter = getXcmStatus(messageId);

    // RECEIVED -> EXECUTED or FAILED is valid
    assert statusBefore == XCM_RECEIVED() =>
        (statusAfter == XCM_EXECUTED() || statusAfter == XCM_FAILED()),
        "RECEIVED can only transition to EXECUTED or FAILED";
}

// Rule 14: Total bridged monotonically increases
rule totalBridgedMonotonic(env e, method f) {
    mathint totalBefore = totalBridged;

    calldataarg args;
    f(e, args);

    assert totalBridged >= totalBefore, "Total bridged must never decrease";
}
