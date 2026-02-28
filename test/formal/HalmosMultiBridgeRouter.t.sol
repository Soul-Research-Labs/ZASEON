// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {MultiBridgeRouter} from "contracts/bridge/MultiBridgeRouter.sol";
import {IMultiBridgeRouter} from "contracts/interfaces/IMultiBridgeRouter.sol";

/**
 * @title HalmosMultiBridgeRouter
 * @notice Symbolic tests for MultiBridgeRouter — uses the REAL contract.
 * @dev Run: halmos --contract HalmosMultiBridgeRouter --solver-timeout-assertion 60000
 */
contract HalmosMultiBridgeRouter is SymTest, Test {
    MultiBridgeRouter internal router;
    address internal admin;

    function setUp() public {
        admin = address(this);
        router = new MultiBridgeRouter(admin);
    }

    /// @notice Non-admin cannot register a bridge adapter.
    function check_onlyAdminCanRegisterAdapter(address caller) public {
        vm.assume(caller != admin);

        vm.prank(caller);
        try
            router.registerAdapter(
                IMultiBridgeRouter.BridgeType.HYPERLANE,
                address(0xBEEF),
                80,
                1000 ether
            )
        {
            assert(false); // must not succeed
        } catch {
            // expected
        }
    }

    /// @notice Pausing blocks routeMessage.
    function check_pauseBlocksRoute(
        uint256 destChain,
        bytes memory message
    ) public {
        router.pause();

        try router.routeMessage(destChain, message, 0) {
            assert(false);
        } catch {
            // expected
        }
    }

    /// @notice Admin can pause and then unpause.
    function check_pauseUnpauseCycle() public {
        assertFalse(router.paused());

        router.pause();
        assertTrue(router.paused());

        router.unpause();
        assertFalse(router.paused());
    }

    /// @notice Non-admin cannot pause the router.
    function check_nonAdminCannotPause(address caller) public {
        vm.assume(caller != admin);

        vm.prank(caller);
        try router.pause() {
            assert(false);
        } catch {
            // expected
        }
    }
}
