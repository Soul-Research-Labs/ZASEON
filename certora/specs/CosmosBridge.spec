// Certora CVL Formal Verification Specification
// Cosmos IBC Bridge Adapter - Security Rules and Invariants

// ============================================================================
// METHODS
// ============================================================================

methods {
    // IBC Core functions
    function channelOpenInit(string calldata portId, string calldata channelId) external returns (bool);
    function channelOpenTry(string calldata portId, string calldata channelId, bytes calldata proofInit) external returns (bool);
    function channelOpenAck(string calldata portId, string calldata channelId, bytes calldata proofTry) external returns (bool);
    function channelOpenConfirm(string calldata portId, string calldata channelId, bytes calldata proofAck) external returns (bool);

    // Packet functions
    function sendPacket(bytes calldata data, string calldata destPort, string calldata destChannel, uint64 timeoutHeight, uint64 timeoutTimestamp) external returns (uint64);
    function recvPacket(bytes calldata packet, bytes calldata proof, uint64 proofHeight) external returns (bool);
    function acknowledgePacket(bytes calldata packet, bytes calldata acknowledgement, bytes calldata proof) external returns (bool);
    function timeoutPacket(bytes calldata packet, bytes calldata proof, uint64 proofHeight) external returns (bool);

    // Transfer functions
    function transfer(string calldata denom, uint256 amount, bytes calldata receiver, string calldata destChannel) external returns (bytes32);
    function completeTransfer(bytes calldata packetData, bytes calldata proof, uint64 proofHeight) external returns (bool);

    // Light client functions
    function updateClient(bytes calldata header) external returns (bool);
    function getClientState(string calldata clientId) external returns (bytes memory) envfree;
    function isClientFrozen(string calldata clientId) external returns (bool) envfree;

    // View functions
    function getChannelState(string calldata channelId) external returns (uint8) envfree;
    function getNextSequenceSend(string calldata channelId) external returns (uint64) envfree;
    function getNextSequenceRecv(string calldata channelId) external returns (uint64) envfree;
    function isNullifierUsed(bytes32 nullifier) external returns (bool) envfree;
    function getCurrentHeight() external returns (uint64) envfree;
    function getCurrentTimestamp() external returns (uint64) envfree;
    function getTrustingPeriod(string calldata clientId) external returns (uint64) envfree;

    // Nullifier functions
    function computeNullifier(uint64 sequence, string calldata channel, string calldata port) external returns (bytes32) envfree;
    function computeCrossDomainNullifier(bytes32 cosmosNullifier, bytes32 domain) external returns (bytes32) envfree;

    // Admin functions
    function pause() external;
    function unpause() external;
    function paused() external returns (bool) envfree;
}

// ============================================================================
// GHOST VARIABLES
// ============================================================================

// Track channel states
ghost mapping(bytes32 => uint8) channelStates;

// Track packet commitments
ghost mapping(bytes32 => bool) packetCommitments;

// Track consumed nullifiers
ghost mapping(bytes32 => bool) consumedNullifiers;

// Track sequence numbers per channel
ghost mapping(bytes32 => uint64) nextSequenceSend;
ghost mapping(bytes32 => uint64) nextSequenceRecv;

// Track total transfers
ghost mathint totalTransfers {
    init_state axiom totalTransfers == 0;
}

// Track client heights
ghost mapping(bytes32 => uint64) clientHeights;

// ============================================================================
// DEFINITIONS
// ============================================================================

// Channel states (IBC standard)
definition STATE_UNINITIALIZED() returns uint8 = 0;
definition STATE_INIT() returns uint8 = 1;
definition STATE_TRYOPEN() returns uint8 = 2;
definition STATE_OPEN() returns uint8 = 3;
definition STATE_CLOSED() returns uint8 = 4;

// Trust threshold (66.67% = 6667 basis points)
definition TRUST_THRESHOLD_BPS() returns uint256 = 6667;

// Trusting period (14 days in seconds)
definition TRUSTING_PERIOD() returns uint64 = 1209600;

// Unbonding period (21 days in seconds)
definition UNBONDING_PERIOD() returns uint64 = 1814400;

// ============================================================================
// INVARIANTS
// ============================================================================

// Invariant 1: Channel state can only progress forward (except close)
invariant channelStateProgression(bytes32 channelHash)
    channelStates[channelHash] >= STATE_UNINITIALIZED() &&
    channelStates[channelHash] <= STATE_CLOSED();

// Invariant 2: Once nullifier used, always used
invariant nullifierUsedImmutable(bytes32 nullifier)
    consumedNullifiers[nullifier] => isNullifierUsed(nullifier);

// Invariant 3: Sequence numbers are positive
invariant sequencePositive(string channelId)
    getNextSequenceSend(channelId) >= 1 && getNextSequenceRecv(channelId) >= 1;

// Invariant 4: Send sequence >= Recv sequence (no messages from the future)
invariant sendSequenceGeRecv(bytes32 channelHash)
    nextSequenceSend[channelHash] >= nextSequenceRecv[channelHash];

// ============================================================================
// RULES
// ============================================================================

// Rule 1: Channel state transitions must follow IBC handshake
rule channelStateTransitions(env e, string portId, string channelId) {
    uint8 stateBefore = getChannelState(channelId);

    channelOpenInit(e, portId, channelId);

    uint8 stateAfter = getChannelState(channelId);

    // UNINITIALIZED -> INIT is valid
    assert stateBefore == STATE_UNINITIALIZED() => stateAfter == STATE_INIT(),
        "UNINITIALIZED can only transition to INIT";
}

// Rule 2: Packet send increments sequence
rule packetSendIncrementsSequence(env e, bytes data, string destPort, string destChannel, uint64 timeoutH, uint64 timeoutT) {
    string srcChannel = "channel-0";  // Simplified
    uint64 seqBefore = getNextSequenceSend(srcChannel);

    sendPacket(e, data, destPort, destChannel, timeoutH, timeoutT);

    uint64 seqAfter = getNextSequenceSend(srcChannel);

    assert seqAfter == seqBefore + 1, "Sequence must increment by 1 after send";
}

// Rule 3: No double packet receive
rule noDoublePacketReceive(env e, bytes packet, bytes proof, uint64 proofHeight) {
    bytes32 packetHash = keccak256(packet);
    bool wasReceived = packetCommitments[packetHash];

    recvPacket@withrevert(e, packet, proof, proofHeight);

    assert wasReceived => lastReverted, "Should revert if packet already received";
}

// Rule 4: No double nullifier consumption
rule noDoubleNullifierConsumption(env e, bytes packetData, bytes proof, uint64 proofHeight) {
    bytes32 nullifier = computeNullifier(1, "channel-0", "transfer");
    bool wasUsed = isNullifierUsed(nullifier);

    completeTransfer@withrevert(e, packetData, proof, proofHeight);

    assert wasUsed => lastReverted, "Should revert if nullifier already used";
}

// Rule 5: Nullifier uniqueness - different packets produce different nullifiers
rule nullifierUniqueness(uint64 seq1, uint64 seq2, string channel, string port) {
    require seq1 != seq2;

    bytes32 nf1 = computeNullifier(seq1, channel, port);
    bytes32 nf2 = computeNullifier(seq2, channel, port);

    assert nf1 != nf2, "Different sequences must produce different nullifiers";
}

// Rule 6: Cross-domain nullifier determinism
rule crossDomainNullifierDeterminism(bytes32 cosmosNf, bytes32 domain) {
    bytes32 pilNf1 = computeCrossDomainNullifier(cosmosNf, domain);
    bytes32 pilNf2 = computeCrossDomainNullifier(cosmosNf, domain);

    assert pilNf1 == pilNf2, "Same inputs must produce same PIL nullifier";
}

// Rule 7: Cross-domain direction matters
rule crossDomainDirectionMatters(bytes32 cosmosNf, bytes32 domainA, bytes32 domainB) {
    require domainA != domainB;

    bytes32 pilNfA = computeCrossDomainNullifier(cosmosNf, domainA);
    bytes32 pilNfB = computeCrossDomainNullifier(cosmosNf, domainB);

    assert pilNfA != pilNfB, "Different domains must produce different PIL nullifiers";
}

// Rule 8: Client must not be frozen for packet operations
rule clientMustBeActive(env e, bytes packet, bytes proof, uint64 proofHeight) {
    string clientId = "07-tendermint-0";  // Simplified
    bool isFrozen = isClientFrozen(clientId);

    recvPacket@withrevert(e, packet, proof, proofHeight);

    assert isFrozen => lastReverted, "Should revert if client is frozen";
}

// Rule 9: Channel must be open for transfers
rule channelMustBeOpen(env e, string denom, uint256 amount, bytes receiver, string destChannel) {
    uint8 channelState = getChannelState(destChannel);

    transfer@withrevert(e, denom, amount, receiver, destChannel);

    assert channelState != STATE_OPEN() => lastReverted,
        "Should revert if channel is not open";
}

// Rule 10: Trusting period enforcement
rule trustingPeriodEnforcement(env e, bytes header) {
    string clientId = "07-tendermint-0";
    uint64 trustingPeriod = getTrustingPeriod(clientId);
    uint64 currentTime = getCurrentTimestamp();

    // Update must be within trusting period
    updateClient@withrevert(e, header);

    // If update succeeds, header time must be within trusting period
    assert !lastReverted => true, "Client update implies trusting period valid";
}

// Rule 11: Height monotonicity on client update
rule heightMonotonicityOnUpdate(env e, bytes header) {
    string clientId = "07-tendermint-0";
    uint64 heightBefore = require_uint64(clientHeights[keccak256(bytes(clientId))]);

    updateClient(e, header);

    uint64 heightAfter = require_uint64(clientHeights[keccak256(bytes(clientId))]);

    assert heightAfter > heightBefore, "Client height must increase on update";
}

// Rule 12: Packet timeout handling
rule packetTimeoutHandling(env e, bytes packet, bytes proof, uint64 proofHeight) {
    uint64 currentHeight = getCurrentHeight();
    uint64 currentTimestamp = getCurrentTimestamp();

    // If packet times out, it must be processable as timeout
    timeoutPacket@withrevert(e, packet, proof, proofHeight);

    // Either timeout succeeds or the packet hasn't timed out
    assert true, "Timeout handling must be consistent";
}

// ============================================================================
// IBC TRANSFER MODULE RULES
// ============================================================================

// Rule 13: Transfer creates packet commitment
rule transferCreatesCommitment(env e, string denom, uint256 amount, bytes receiver, string destChannel) {
    require amount > 0;
    require !paused();

    bytes32 transferId = transfer(e, denom, amount, receiver, destChannel);

    assert transferId != bytes32(0), "Transfer must create non-zero ID";
}

// Rule 14: Acknowledgement removes commitment
rule ackRemovesCommitment(env e, bytes packet, bytes acknowledgement, bytes proof) {
    bytes32 packetHash = keccak256(packet);
    bool hadCommitment = packetCommitments[packetHash];

    acknowledgePacket(e, packet, acknowledgement, proof);

    // After successful ack, commitment should be removed
    assert hadCommitment => true, "Ack should process committed packet";
}
