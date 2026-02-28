// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {CrossChainProofHubV3} from "contracts/bridge/CrossChainProofHubV3.sol";

/**
 * @title HalmosCrossChainProofHub
 * @notice Symbolic tests for CrossChainProofHubV3 — uses the REAL contract.
 * @dev Run: halmos --contract HalmosCrossChainProofHub --solver-timeout-assertion 60000
 */
contract HalmosCrossChainProofHub is SymTest, Test {
    CrossChainProofHubV3 internal hub;

    function setUp() public {
        hub = new CrossChainProofHubV3();
    }

    /// @notice Deployer's own chain is auto-supported.
    function check_ownChainSupported() public view {
        assertTrue(
            hub.supportedChains(block.chainid),
            "Deployer chain must be supported"
        );
    }

    /// @notice addSupportedChain can be called by admin.
    function check_addChain(uint256 chainId) public {
        vm.assume(chainId != block.chainid && chainId != 0);

        hub.addSupportedChain(chainId);

        assertTrue(
            hub.supportedChains(chainId),
            "Chain must be supported after adding"
        );
    }

    /// @notice Non-admin cannot add a supported chain.
    function check_nonAdminCannotAddChain(
        address caller,
        uint256 chainId
    ) public {
        vm.assume(caller != address(this));

        vm.prank(caller);
        try hub.addSupportedChain(chainId) {
            assert(false);
        } catch {
            // expected — caller lacks DEFAULT_ADMIN_ROLE
        }
    }

    /// @notice Stake deposit increases relayer stake.
    function check_depositStakeAccounting() public {
        vm.deal(address(this), 100 ether);

        // Grant RELAYER_ROLE to this contract first
        hub.grantRole(hub.RELAYER_ROLE(), address(this));

        hub.depositStake{value: 10 ether}();

        (uint256 stake, , ) = hub.getRelayerStats(address(this));
        assertGe(stake, 10 ether, "Stake must be recorded");
    }

    /// @notice Pausing blocks proof submission.
    function check_pauseBlocksSubmission(bytes memory proof) public {
        hub.pause();

        try hub.submitProof(proof, hex"", bytes32(0), 1, 2) {
            assert(false);
        } catch {
            // expected
        }
    }
}
