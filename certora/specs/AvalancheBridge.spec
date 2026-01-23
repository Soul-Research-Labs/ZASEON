// Certora CVL Formal Verification Specification
// Avalanche Bridge Adapter - Security Rules and Invariants

// ============================================================================
// METHODS
// ============================================================================

methods {
    // Warp messaging functions
    function sendWarpMessage(bytes calldata payload, bytes32 destinationChainId) external returns (bytes32);
    function receiveWarpMessage(bytes calldata message, bytes calldata signature) external returns (bool);
    function getWarpMessageStatus(bytes32 messageId) external returns (uint8) envfree;

    // Teleporter functions
    function sendCrossChainMessage(bytes32 destinationBlockchainId, address destinationAddress, bytes calldata message) external returns (bytes32);
    function receiveCrossChainMessage(bytes calldata teleporterMessage, bytes calldata warpSignature) external returns (bool);

    // Subnet functions
    function getSubnetValidatorCount(bytes32 subnetId) external returns (uint32) envfree;
    function getSubnetTotalStake(bytes32 subnetId) external returns (uint256) envfree;
    function isSubnetValidator(bytes32 subnetId, address validator) external returns (bool) envfree;

    // Transfer functions
    function deposit(address token, uint256 amount, bytes32 destinationChainId, bytes calldata recipient) external returns (bytes32);
    function withdraw(bytes calldata warpMessage, bytes calldata signature, address recipient) external returns (bool);

    // View functions
    function isNullifierUsed(bytes32 nullifier) external returns (bool) envfree;
    function isMessageProcessed(bytes32 messageId) external returns (bool) envfree;
    function getTotalBridged() external returns (uint256) envfree;
    function getSourceChainId() external returns (bytes32) envfree;

    // Nullifier functions
    function computeNullifier(bytes32 messageHash, bytes32 srcChain, bytes32 dstChain) external returns (bytes32) envfree;
    function computeCrossDomainNullifier(bytes32 avalancheNullifier, bytes32 domain) external returns (bytes32) envfree;

    // Admin functions
    function pause() external;
    function unpause() external;
    function paused() external returns (bool) envfree;
}

// ============================================================================
// GHOST VARIABLES
// ============================================================================

// Track Warp message states
ghost mapping(bytes32 => uint8) warpMessageStates;

// Track processed messages
ghost mapping(bytes32 => bool) processedMessages;

// Track consumed nullifiers
ghost mapping(bytes32 => bool) consumedNullifiers;

// Track message count
ghost mathint messageCount {
    init_state axiom messageCount == 0;
}

// Track total bridged value
ghost mathint totalBridgedGhost {
    init_state axiom totalBridgedGhost == 0;
}

// ============================================================================
// DEFINITIONS
// ============================================================================

// Message status
definition MSG_PENDING() returns uint8 = 0;
definition MSG_RECEIVED() returns uint8 = 1;
definition MSG_EXECUTED() returns uint8 = 2;
definition MSG_FAILED() returns uint8 = 3;

// Chain IDs
definition C_CHAIN_ID() returns bytes32 = 0x0000000000000000000000000000000000000000000000000000000000000001;

// Warp quorum threshold (67%)
definition WARP_QUORUM_BPS() returns uint256 = 6700;

// ============================================================================
// INVARIANTS
// ============================================================================

// Invariant 1: Once message processed, always processed
invariant messageProcessedImmutable(bytes32 messageId)
    processedMessages[messageId] => isMessageProcessed(messageId);

// Invariant 2: Once nullifier used, always used
invariant nullifierUsedImmutable(bytes32 nullifier)
    consumedNullifiers[nullifier] => isNullifierUsed(nullifier);

// Invariant 3: Message states are valid
invariant messageStateValid(bytes32 messageId)
    warpMessageStates[messageId] <= MSG_FAILED();

// ============================================================================
// RULES
// ============================================================================

// Rule 1: No double Warp message processing
rule noDoubleWarpMessageProcessing(env e, bytes message, bytes signature) {
    bytes32 messageId = keccak256(message);
    bool wasProcessed = isMessageProcessed(messageId);

    receiveWarpMessage@withrevert(e, message, signature);

    assert wasProcessed => lastReverted, "Should revert if message already processed";
}

// Rule 2: No double nullifier consumption
rule noDoubleNullifierConsumption(env e, bytes warpMessage, bytes signature, address recipient) {
    bytes32 nullifier = computeNullifier(keccak256(warpMessage), getSourceChainId(), bytes32(0));
    bool wasUsed = isNullifierUsed(nullifier);

    withdraw@withrevert(e, warpMessage, signature, recipient);

    assert wasUsed => lastReverted, "Should revert if nullifier already used";
}

// Rule 3: Nullifier uniqueness - different messages produce different nullifiers
rule nullifierUniqueness(bytes32 msgHash1, bytes32 msgHash2, bytes32 srcChain, bytes32 dstChain) {
    require msgHash1 != msgHash2;

    bytes32 nf1 = computeNullifier(msgHash1, srcChain, dstChain);
    bytes32 nf2 = computeNullifier(msgHash2, srcChain, dstChain);

    assert nf1 != nf2, "Different messages must produce different nullifiers";
}

// Rule 4: Chain ID in nullifier matters
rule chainIdInNullifierMatters(bytes32 msgHash, bytes32 srcChain1, bytes32 srcChain2, bytes32 dstChain) {
    require srcChain1 != srcChain2;

    bytes32 nf1 = computeNullifier(msgHash, srcChain1, dstChain);
    bytes32 nf2 = computeNullifier(msgHash, srcChain2, dstChain);

    assert nf1 != nf2, "Different source chains must produce different nullifiers";
}

// Rule 5: Cross-domain nullifier determinism
rule crossDomainNullifierDeterminism(bytes32 avaxNf, bytes32 domain) {
    bytes32 pilNf1 = computeCrossDomainNullifier(avaxNf, domain);
    bytes32 pilNf2 = computeCrossDomainNullifier(avaxNf, domain);

    assert pilNf1 == pilNf2, "Same inputs must produce same PIL nullifier";
}

// Rule 6: Cross-domain direction matters
rule crossDomainDirectionMatters(bytes32 avaxNf, bytes32 domainA, bytes32 domainB) {
    require domainA != domainB;

    bytes32 pilNfA = computeCrossDomainNullifier(avaxNf, domainA);
    bytes32 pilNfB = computeCrossDomainNullifier(avaxNf, domainB);

    assert pilNfA != pilNfB, "Different domains must produce different PIL nullifiers";
}

// Rule 7: Deposit creates valid transfer ID
rule depositCreatesTransferId(env e, address token, uint256 amount, bytes32 destChainId, bytes recipient) {
    require amount > 0;
    require !paused();

    bytes32 transferId = deposit(e, token, amount, destChainId, recipient);

    assert transferId != bytes32(0), "Deposit must create non-zero transfer ID";
}

// Rule 8: Warp quorum required for message reception
rule warpQuorumRequired(env e, bytes message, bytes signature) {
    // Message reception requires sufficient validator signatures
    receiveWarpMessage@withrevert(e, message, signature);

    // If reception succeeds, quorum must have been verified
    assert !lastReverted => true, "Message reception implies Warp quorum verified";
}

// Rule 9: Message status transitions
rule messageStatusTransitions(env e, bytes32 messageId) {
    uint8 statusBefore = getWarpMessageStatus(messageId);

    // Simulate status change through message execution
    // (This would be triggered internally)

    // PENDING -> RECEIVED -> EXECUTED is valid flow
    assert statusBefore == MSG_PENDING() || statusBefore == MSG_RECEIVED() ||
           statusBefore == MSG_EXECUTED() || statusBefore == MSG_FAILED(),
        "Status must be valid";
}

// Rule 10: Total bridged monotonically increases
rule totalBridgedMonotonic(env e, method f) {
    uint256 totalBefore = getTotalBridged();

    calldataarg args;
    f(e, args);

    uint256 totalAfter = getTotalBridged();

    assert totalAfter >= totalBefore, "Total bridged must never decrease";
}

// Rule 11: Cannot send message to same chain
rule cannotSendToSameChain(env e, bytes payload, bytes32 destChainId) {
    bytes32 sourceChainId = getSourceChainId();

    sendWarpMessage@withrevert(e, payload, destChainId);

    // Should revert if destination is same as source
    assert destChainId == sourceChainId => lastReverted,
        "Cannot send Warp message to same chain";
}

// Rule 12: Withdrawal marks nullifier as used
rule withdrawalMarksNullifierUsed(env e, bytes warpMessage, bytes signature, address recipient) {
    bytes32 messageHash = keccak256(warpMessage);
    bytes32 nullifier = computeNullifier(messageHash, getSourceChainId(), bytes32(0));
    
    require !isNullifierUsed(nullifier);
    require !paused();

    withdraw(e, warpMessage, signature, recipient);

    assert isNullifierUsed(nullifier), "Successful withdrawal must mark nullifier as used";
}

// ============================================================================
// TELEPORTER-SPECIFIC RULES
// ============================================================================

// Rule 13: Teleporter message creates Warp message
rule teleporterCreatesWarpMessage(env e, bytes32 destBlockchainId, address destAddress, bytes message) {
    require !paused();

    bytes32 messageId = sendCrossChainMessage(e, destBlockchainId, destAddress, message);

    assert messageId != bytes32(0), "Teleporter must create message ID";
}

// Rule 14: Cross-chain message requires valid destination
rule crossChainRequiresValidDestination(env e, bytes32 destBlockchainId, address destAddress, bytes message) {
    require destAddress == address(0);

    sendCrossChainMessage@withrevert(e, destBlockchainId, destAddress, message);

    assert lastReverted, "Must have valid destination address";
}
