// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {UniversalShieldedPool} from "contracts/privacy/UniversalShieldedPool.sol";

/**
 * @title HalmosShieldedPool
 * @notice Symbolic tests for UniversalShieldedPool — uses the REAL contract.
 * @dev Run: halmos --contract HalmosShieldedPool --solver-timeout-assertion 60000
 */
contract HalmosShieldedPool is SymTest, Test {
    UniversalShieldedPool internal pool;

    function setUp() public {
        pool = new UniversalShieldedPool(address(this), address(0), true);
    }

    /// @notice Leaf index must increase after a deposit.
    function check_depositIncreasesLeafIndex(bytes32 commitment) public {
        vm.assume(commitment != bytes32(0));

        uint256 indexBefore = pool.nextLeafIndex();

        pool.depositETH{value: 0.01 ether}(commitment);

        uint256 indexAfter = pool.nextLeafIndex();
        assertGt(
            indexAfter,
            indexBefore,
            "Leaf index must increase after deposit"
        );
    }

    /// @notice TREE_DEPTH and ROOT_HISTORY_SIZE are immutable constants.
    function check_immutableConstants() public view {
        assertEq(pool.TREE_DEPTH(), 32, "Tree depth must be 32");
        assertEq(pool.ROOT_HISTORY_SIZE(), 100, "Root history must be 100");
    }

    /// @notice Deposit bounds must be enforced — below minimum reverts.
    function check_depositBelowMinReverts(bytes32 commitment) public {
        vm.assume(commitment != bytes32(0));

        // MIN_DEPOSIT is 0.001 ether (1e15 wei)
        try pool.depositETH{value: 1e14}(commitment) {
            assert(false); // must reject deposit below minimum
        } catch {
            // expected
        }
    }

    /// @notice Deposit bounds — above maximum reverts.
    function check_depositAboveMaxReverts(bytes32 commitment) public {
        vm.assume(commitment != bytes32(0));
        vm.deal(address(this), 20_000 ether);

        // MAX_DEPOSIT is 10_000 ether
        try pool.depositETH{value: 10_001 ether}(commitment) {
            assert(false); // must reject
        } catch {
            // expected
        }
    }

    /// @notice Deposits blocked when paused.
    function check_pauseBlocksDeposit(bytes32 commitment) public {
        vm.assume(commitment != bytes32(0));
        pool.pause();

        try pool.depositETH{value: 0.01 ether}(commitment) {
            assert(false);
        } catch {
            // expected
        }
    }

    receive() external payable {}
}
