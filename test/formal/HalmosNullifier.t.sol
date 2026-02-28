// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {NullifierRegistryV3} from "contracts/core/NullifierRegistryV3.sol";

/**
 * @title HalmosNullifier
 * @notice Symbolic tests for NullifierRegistryV3 — uses the REAL contract.
 * @dev Run: halmos --contract HalmosNullifier --solver-timeout-assertion 60000
 */
contract HalmosNullifier is SymTest, Test {
    NullifierRegistryV3 internal registry;

    function setUp() public {
        registry = new NullifierRegistryV3();
    }

    /// @notice Double-registration of the same nullifier must revert.
    function check_doubleRegisterReverts(
        bytes32 nullifier,
        bytes32 commitment
    ) public {
        registry.registerNullifier(nullifier, commitment);

        // Second registration of the same nullifier must revert.
        try registry.registerNullifier(nullifier, commitment) {
            assert(false); // should not succeed
        } catch {
            // expected
        }
    }

    /// @notice After a successful registration the nullifier is marked as existing.
    function check_registerMarksUsed(
        bytes32 nullifier,
        bytes32 commitment
    ) public {
        vm.assume(!registry.exists(nullifier));

        registry.registerNullifier(nullifier, commitment);

        assertTrue(
            registry.exists(nullifier),
            "Nullifier must exist after registration"
        );
    }

    /// @notice totalNullifiers increases by exactly 1 on single registration.
    function check_singleRegisterIncrementsCount(
        bytes32 nullifier,
        bytes32 commitment
    ) public {
        vm.assume(!registry.exists(nullifier));

        (uint256 countBefore, , ) = registry.getTreeStats();

        registry.registerNullifier(nullifier, commitment);

        (uint256 countAfter, , ) = registry.getTreeStats();
        assertEq(countAfter, countBefore + 1, "Count must increase by 1");
    }

    /// @notice Registration must revert when contract is paused.
    function check_pauseBlocksRegistration(
        bytes32 nullifier,
        bytes32 commitment
    ) public {
        registry.pause();

        try registry.registerNullifier(nullifier, commitment) {
            assert(false);
        } catch {
            // expected — EnforcedPause
        }
    }
}
