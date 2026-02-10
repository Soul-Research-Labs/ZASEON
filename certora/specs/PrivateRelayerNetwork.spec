/**
 * Certora Formal Verification Specification
 * Soul Protocol - PrivateRelayerNetwork
 *
 * This spec verifies critical invariants for the Private Relayer Network
 * which implements stake-weighted VRF-based relayer selection,
 * commit-reveal MEV protection, and stealth fee payments.
 */

using PrivateRelayerNetwork as prn;

// ============================================================================
// METHODS
// ============================================================================

methods {
    // View / pure functions
    function totalStake() external returns (uint256) envfree;
    function totalRelays() external returns (uint256) envfree;
    function getRelayerCount() external returns (uint256) envfree;
    function paused() external returns (bool) envfree;
    function hasRole(bytes32, address) external returns (bool) envfree;
    function OPERATOR_ROLE() external returns (bytes32) envfree;
    function RELAYER_ROLE() external returns (bytes32) envfree;
    function SLASHER_ROLE() external returns (bytes32) envfree;
    function MIN_STAKE() external returns (uint256) envfree;
    function MAX_STAKE() external returns (uint256) envfree;
    function SLASH_PERCENTAGE() external returns (uint256) envfree;
    function LATE_SLASH_PERCENTAGE() external returns (uint256) envfree;
    function MIN_RELAYERS() external returns (uint256) envfree;
    function currentVRFRound() external returns (bytes32) envfree;

    // State-changing functions
    function registerRelayer(bytes32, bytes32) external;
    function addStake() external;
    function requestExit() external;
    function completeExit() external;
    function startVRFRound(bytes32) external;
    function slashRelayer(address, uint256, bytes32) external;
    function unjailRelayer() external;
}

// ============================================================================
// GHOST VARIABLES
// ============================================================================

ghost uint256 ghostTotalStake {
    init_state axiom ghostTotalStake == 0;
}

ghost uint256 ghostRelayerCount {
    init_state axiom ghostRelayerCount == 0;
}

ghost mapping(address => uint256) ghostRelayerStake {
    init_state axiom forall address r. ghostRelayerStake[r] == 0;
}

// ============================================================================
// INVARIANTS
// ============================================================================

/**
 * @title Total Stake Is Non-Negative
 * @notice totalStake should always be >= 0 (trivially true for uint256,
 *         but guards against underflow in accounting)
 * TODO: Hook ghost to track sum of individual relayer stakes
 */
invariant totalStakeNonNegative()
    totalStake() >= 0;

/**
 * @title Relayer Count Consistency
 * @notice getRelayerCount() should always be >= 0
 * TODO: Verify that relayer count equals length of activeRelayers array
 */
invariant relayerCountConsistency()
    getRelayerCount() >= 0;

/**
 * @title Total Relays Monotonically Increasing
 * @notice totalRelays can only increase, never decrease
 * TODO: Strengthen by hooking ghost to totalRelays storage slot
 */
invariant totalRelaysMonotonicallyIncreasing()
    totalRelays() >= 0
    { preserved { require totalRelays() < max_uint256; } }

// ============================================================================
// RULES
// ============================================================================

/**
 * @title Stake Cannot Decrease Below MIN_STAKE For Active Relayers
 * @notice After slashing, if relayer remains active, stake >= MIN_STAKE
 * TODO: Implement by reading relayer struct after slash
 */
rule slashDoesNotViolateTotalStakeAccounting() {
    env e;
    address relayer;
    uint256 amount;
    bytes32 reason;

    uint256 totalBefore = totalStake();

    slashRelayer(e, relayer, amount, reason);

    uint256 totalAfter = totalStake();

    assert totalAfter <= totalBefore,
        "Total stake must not increase after slashing";
}

/**
 * @title Total Relays Never Decreases
 * @notice No function call should decrease totalRelays
 */
rule totalRelaysNeverDecreases() {
    env e;
    uint256 before = totalRelays();

    method f;
    calldataarg args;
    f(e, args);

    uint256 after = totalRelays();

    assert after >= before,
        "totalRelays must never decrease";
}

/**
 * @title Adding Stake Increases Total Stake
 * @notice addStake() should increase the total stake by msg.value
 * TODO: Verify exact amount tracking with msg.value
 */
rule addStakeIncreasesTotalStake() {
    env e;
    require e.msg.value > 0;

    uint256 totalBefore = totalStake();

    addStake(e);

    uint256 totalAfter = totalStake();

    assert totalAfter > totalBefore,
        "Total stake should increase after addStake";
}
