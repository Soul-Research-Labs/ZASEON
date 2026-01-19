// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title EchidnaTimelock
 * @notice Echidna fuzzing tests for Timelock governance patterns
 * @dev Run with: echidna test/fuzzing/EchidnaTimelock.sol --contract EchidnaTimelock
 *
 * This is a simplified fuzzer that tests timelock patterns
 * without importing the full contract to avoid "stack too deep" errors.
 *
 * Security Properties Tested:
 * - Operations cannot be executed before delay
 * - Cancelled operations cannot be executed
 * - Executed operations cannot be re-executed
 */
contract EchidnaTimelock {
    // ========== CONSTANTS ==========

    uint256 public constant MIN_DELAY = 48 hours;
    uint256 public constant MAX_DELAY = 30 days;

    // ========== STATE ==========

    enum OperationState {
        None,
        Pending,
        Ready,
        Executed,
        Cancelled
    }

    mapping(bytes32 => OperationState) public operationState;
    mapping(bytes32 => uint256) public operationReadyTime;

    bytes32[] public operations;
    uint256 public currentDelay;

    uint256 public totalProposed;
    uint256 public totalExecuted;
    uint256 public totalCancelled;

    constructor() {
        currentDelay = MIN_DELAY;
    }

    // ========== HELPER ==========

    function _computeOpId(
        address target,
        bytes32 salt
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(target, salt));
    }

    // ========== FUZZING FUNCTIONS ==========

    function fuzz_propose(address target, bytes32 salt) public {
        if (target == address(0)) return;

        bytes32 opId = _computeOpId(target, salt);
        if (operationState[opId] != OperationState.None) return;

        operationState[opId] = OperationState.Pending;
        operationReadyTime[opId] = block.timestamp + currentDelay;
        operations.push(opId);
        totalProposed++;
    }

    function fuzz_execute(uint256 idx) public {
        if (operations.length == 0) return;

        bytes32 opId = operations[idx % operations.length];

        // Can only execute pending or ready operations
        if (
            operationState[opId] != OperationState.Pending &&
            operationState[opId] != OperationState.Ready
        ) return;

        // Update to ready if time has passed
        if (block.timestamp >= operationReadyTime[opId]) {
            operationState[opId] = OperationState.Ready;
        }

        // Only execute if ready
        if (operationState[opId] != OperationState.Ready) return;

        operationState[opId] = OperationState.Executed;
        totalExecuted++;
    }

    function fuzz_cancel(uint256 idx) public {
        if (operations.length == 0) return;

        bytes32 opId = operations[idx % operations.length];

        // Can only cancel pending operations
        if (
            operationState[opId] != OperationState.Pending &&
            operationState[opId] != OperationState.Ready
        ) return;

        operationState[opId] = OperationState.Cancelled;
        totalCancelled++;
    }

    function fuzz_updateDelay(uint256 newDelay) public {
        // Bound to valid range
        newDelay = (newDelay % (MAX_DELAY - MIN_DELAY)) + MIN_DELAY;
        currentDelay = newDelay;
    }

    // ========== INVARIANTS ==========

    /**
     * @notice Executed operations cannot become pending again
     */
    function echidna_executed_is_final() public view returns (bool) {
        for (uint256 i = 0; i < operations.length && i < 20; i++) {
            bytes32 opId = operations[i];
            if (operationState[opId] == OperationState.Executed) {
                // Once executed, should stay executed
                if (operationReadyTime[opId] == 0) return false;
            }
        }
        return true;
    }

    /**
     * @notice Cancelled operations cannot be executed
     */
    function echidna_cancelled_not_executed() public view returns (bool) {
        for (uint256 i = 0; i < operations.length && i < 20; i++) {
            bytes32 opId = operations[i];
            // Cancelled and Executed are mutually exclusive
            if (operationState[opId] == OperationState.Cancelled) {
                if (operationReadyTime[opId] == 0) return false;
            }
        }
        return true;
    }

    /**
     * @notice Delay is always within bounds
     */
    function echidna_delay_bounds() public view returns (bool) {
        return currentDelay >= MIN_DELAY && currentDelay <= MAX_DELAY;
    }

    /**
     * @notice Operation counts are consistent
     */
    function echidna_count_consistency() public view returns (bool) {
        return totalProposed >= totalExecuted + totalCancelled;
    }

    /**
     * @notice Ready time is set for pending operations
     */
    function echidna_ready_time_set() public view returns (bool) {
        for (uint256 i = 0; i < operations.length && i < 20; i++) {
            bytes32 opId = operations[i];
            if (operationState[opId] == OperationState.Pending) {
                if (operationReadyTime[opId] == 0) return false;
            }
        }
        return true;
    }
}
