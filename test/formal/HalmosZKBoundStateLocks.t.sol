// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {ZKBoundStateLocks} from "contracts/primitives/ZKBoundStateLocks.sol";
import {MockProofVerifier} from "contracts/mocks/MockProofVerifier.sol";

/**
 * @title HalmosZKBoundStateLocks
 * @notice Symbolic tests for ZKBoundStateLocks — uses the REAL contract.
 * @dev Run: halmos --contract HalmosZKBoundStateLocks --solver-timeout-assertion 60000
 */
contract HalmosZKBoundStateLocks is SymTest, Test {
    ZKBoundStateLocks internal locks;
    MockProofVerifier internal verifier;

    function setUp() public {
        verifier = new MockProofVerifier();
        locks = new ZKBoundStateLocks(address(verifier));
    }

    /// @notice Creating a lock increments totalLocksCreated by exactly 1.
    function check_createLockIncrementsCount(
        bytes32 oldState,
        bytes32 predicate,
        bytes32 policy,
        bytes32 domain,
        uint64 deadline
    ) public {
        vm.assume(deadline > block.timestamp);

        uint256 countBefore = locks.totalLocksCreated();

        locks.createLock(oldState, predicate, policy, domain, deadline);

        uint256 countAfter = locks.totalLocksCreated();
        assertEq(
            countAfter,
            countBefore + 1,
            "Create must increase count by 1"
        );
    }

    /// @notice Active lock count is bounded by totalLocksCreated.
    function check_activeLocksBounded(
        bytes32 s1,
        bytes32 p1,
        bytes32 pol1,
        bytes32 d1,
        uint64 dl1,
        bytes32 s2,
        bytes32 p2,
        bytes32 pol2,
        bytes32 d2,
        uint64 dl2
    ) public {
        vm.assume(dl1 > block.timestamp && dl2 > block.timestamp);

        locks.createLock(s1, p1, pol1, d1, dl1);
        locks.createLock(s2, p2, pol2, d2, dl2);

        assertLe(
            locks.getActiveLockCount(),
            locks.totalLocksCreated(),
            "Active locks must be <= total created"
        );
    }

    /// @notice Unlock count never exceeds created count.
    function check_unlockedNeverExceedsCreated() public view {
        assertLe(
            locks.totalLocksUnlocked(),
            locks.totalLocksCreated(),
            "Unlocked must be <= created"
        );
    }

    /// @notice Lock creation reverts when paused.
    function check_pauseBlocksCreate(
        bytes32 s,
        bytes32 p,
        bytes32 pol,
        bytes32 d,
        uint64 dl
    ) public {
        vm.assume(dl > block.timestamp);
        locks.pause();

        try locks.createLock(s, p, pol, d, dl) {
            assert(false);
        } catch {
            // expected
        }
    }

    /// @notice generateNullifier is a pure deterministic function.
    function check_nullifierDeterministic(
        bytes32 secret,
        bytes32 lockId,
        bytes32 domain
    ) public {
        bytes32 a = locks.generateNullifier(secret, lockId, domain);
        bytes32 b = locks.generateNullifier(secret, lockId, domain);
        assertEq(a, b, "Same inputs must produce same nullifier");
    }
}
