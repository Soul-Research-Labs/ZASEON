// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {CrossChainProofHubV3Upgradeable} from "../../contracts/upgradeable/CrossChainProofHubV3Upgradeable.sol";

contract CrossChainProofHubV3UpgradeableTest is Test {
    CrossChainProofHubV3Upgradeable public impl;
    CrossChainProofHubV3Upgradeable public hub;
    address admin = address(this);

    function setUp() public {
        impl = new CrossChainProofHubV3Upgradeable();
        bytes memory data = abi.encodeCall(impl.initialize, (admin));
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), data);
        hub = CrossChainProofHubV3Upgradeable(payable(address(proxy)));
    }

    function test_InitializerSetsAdmin() public view {
        assertTrue(hub.hasRole(hub.DEFAULT_ADMIN_ROLE(), admin));
    }

    function test_InitializerSetsEmergency() public view {
        assertTrue(hub.hasRole(hub.EMERGENCY_ROLE(), admin));
    }

    function test_ContractVersion() public view {
        assertEq(hub.contractVersion(), 1);
    }

    function test_CannotDoubleInitialize() public {
        vm.expectRevert();
        hub.initialize(admin);
    }

    function test_DefaultChallengePeriod() public view {
        assertEq(hub.challengePeriod(), 1 hours);
    }

    function test_DefaultMinRelayerStake() public view {
        assertEq(hub.minRelayerStake(), 0.1 ether);
    }

    function test_DefaultMinChallengerStake() public view {
        assertEq(hub.minChallengerStake(), 0.05 ether);
    }

    function test_CurrentChainSupported() public view {
        assertTrue(hub.supportedChains(block.chainid));
    }

    function test_SetChallengePeriod() public {
        hub.setChallengePeriod(2 hours);
        assertEq(hub.challengePeriod(), 2 hours);
    }

    function test_AddSupportedChain() public {
        hub.addSupportedChain(42161); // Arbitrum
        assertTrue(hub.supportedChains(42161));
    }

    function test_RemoveSupportedChain() public {
        hub.addSupportedChain(42161);
        hub.removeSupportedChain(42161);
        assertFalse(hub.supportedChains(42161));
    }

    function test_PauseUnpause() public {
        hub.pause();
        assertTrue(hub.paused());
        hub.unpause();
        assertFalse(hub.paused());
    }

    function test_DepositStake() public {
        // Grant RELAYER_ROLE to admin so we can deposit
        hub.grantRole(hub.RELAYER_ROLE(), admin);
        hub.depositStake{value: 1 ether}();
    }

    function test_ConfirmRoleSeparation() public {
        hub.confirmRoleSeparation();
        assertTrue(hub.rolesSeparated());
    }
}
