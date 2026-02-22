// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {EnhancedKillSwitch} from "../../contracts/security/EnhancedKillSwitch.sol";
import "../../contracts/interfaces/IEnhancedKillSwitch.sol";

contract EnhancedKillSwitchTest is Test {
    EnhancedKillSwitch public killSwitch;
    address public admin;
    address public guardian1 = address(0xA1);
    address public guardian2 = address(0xA2);
    address public guardian3 = address(0xA3);

    function setUp() public {
        admin = address(this);
        address[] memory guardians = new address[](3);
        guardians[0] = guardian1;
        guardians[1] = guardian2;
        guardians[2] = guardian3;

        killSwitch = new EnhancedKillSwitch(admin, guardians);
    }

    // ======= Initial State =======

    function test_initialLevel() public view {
        assertEq(
            uint256(killSwitch.currentLevel()),
            uint256(IEnhancedKillSwitch.EmergencyLevel.NONE)
        );
    }

    function test_initialGuardians() public view {
        address[] memory gs = killSwitch.getGuardians();
        assertEq(gs.length, 3);
    }

    function test_initialPermissions() public view {
        assertTrue(
            killSwitch.isActionAllowed(IEnhancedKillSwitch.ActionType.DEPOSIT)
        );
        assertTrue(
            killSwitch.isActionAllowed(IEnhancedKillSwitch.ActionType.WITHDRAWAL)
        );
        assertTrue(
            killSwitch.isActionAllowed(IEnhancedKillSwitch.ActionType.BRIDGE)
        );
    }

    // ======= Level 1: WARNING =======

    function test_escalateToWarning() public {
        vm.prank(guardian1);
        killSwitch.escalateEmergency(
            IEnhancedKillSwitch.EmergencyLevel.WARNING,
            "suspicious activity"
        );

        assertEq(
            uint256(killSwitch.currentLevel()),
            uint256(IEnhancedKillSwitch.EmergencyLevel.WARNING)
        );
    }

    function test_warningAllowsAllActions() public {
        vm.prank(guardian1);
        killSwitch.escalateEmergency(
            IEnhancedKillSwitch.EmergencyLevel.WARNING,
            "test"
        );

        assertTrue(
            killSwitch.isActionAllowed(IEnhancedKillSwitch.ActionType.DEPOSIT)
        );
        assertTrue(
            killSwitch.isActionAllowed(IEnhancedKillSwitch.ActionType.WITHDRAWAL)
        );
        assertTrue(
            killSwitch.isActionAllowed(IEnhancedKillSwitch.ActionType.BRIDGE)
        );
    }

    // ======= Level 2: DEGRADED =======

    function test_escalateToDegraded() public {
        vm.prank(guardian1);
        killSwitch.escalateEmergency(
            IEnhancedKillSwitch.EmergencyLevel.WARNING,
            "step1"
        );

        vm.prank(guardian1);
        killSwitch.escalateEmergency(
            IEnhancedKillSwitch.EmergencyLevel.DEGRADED,
            "step2"
        );

        assertEq(
            uint256(killSwitch.currentLevel()),
            uint256(IEnhancedKillSwitch.EmergencyLevel.DEGRADED)
        );
    }

    function test_degradedBlocksDeposits() public {
        _escalateToDegraded();

        assertFalse(
            killSwitch.isActionAllowed(IEnhancedKillSwitch.ActionType.DEPOSIT)
        );
        assertTrue(
            killSwitch.isActionAllowed(IEnhancedKillSwitch.ActionType.WITHDRAWAL)
        );
        assertTrue(
            killSwitch.isActionAllowed(
                IEnhancedKillSwitch.ActionType.EMERGENCY_WITHDRAWAL
            )
        );
    }

    function test_degradedBlocksBridge() public {
        _escalateToDegraded();

        assertFalse(
            killSwitch.isActionAllowed(IEnhancedKillSwitch.ActionType.BRIDGE)
        );
    }

    // ======= Level 3: HALTED (requires confirmations + cooldown) =======

    function test_haltedRequiresConfirmations() public {
        _escalateToDegraded();

        vm.prank(guardian1);
        killSwitch.escalateEmergency(
            IEnhancedKillSwitch.EmergencyLevel.HALTED,
            "critical"
        );

        // Level should still be DEGRADED (pending)
        assertEq(
            uint256(killSwitch.pendingLevel()),
            uint256(IEnhancedKillSwitch.EmergencyLevel.HALTED)
        );
    }

    function test_haltedAfterConfirmationsAndCooldown() public {
        _escalateToDegraded();

        vm.prank(guardian1);
        killSwitch.escalateEmergency(
            IEnhancedKillSwitch.EmergencyLevel.HALTED,
            "critical"
        );

        vm.prank(guardian2);
        killSwitch.confirmEscalation(IEnhancedKillSwitch.EmergencyLevel.HALTED);

        vm.warp(block.timestamp + killSwitch.LEVEL_3_COOLDOWN() + 1);

        vm.prank(guardian1);
        killSwitch.executeEscalation();

        assertEq(
            uint256(killSwitch.currentLevel()),
            uint256(IEnhancedKillSwitch.EmergencyLevel.HALTED)
        );
    }

    function test_haltedBlocksMostActions() public {
        _escalateToHalted();

        assertFalse(
            killSwitch.isActionAllowed(IEnhancedKillSwitch.ActionType.DEPOSIT)
        );
        assertFalse(
            killSwitch.isActionAllowed(IEnhancedKillSwitch.ActionType.WITHDRAWAL)
        );
        assertFalse(
            killSwitch.isActionAllowed(IEnhancedKillSwitch.ActionType.BRIDGE)
        );
        assertTrue(
            killSwitch.isActionAllowed(
                IEnhancedKillSwitch.ActionType.EMERGENCY_WITHDRAWAL
            )
        );
    }

    // ======= Recovery =======

    function test_initiateRecovery() public {
        _escalateToDegraded();
        killSwitch.initiateRecovery(IEnhancedKillSwitch.EmergencyLevel.NONE);
    }

    function test_executeRecovery_fromWarning() public {
        vm.prank(guardian1);
        killSwitch.escalateEmergency(
            IEnhancedKillSwitch.EmergencyLevel.WARNING,
            "test"
        );

        killSwitch.initiateRecovery(IEnhancedKillSwitch.EmergencyLevel.NONE);

        vm.prank(guardian1);
        killSwitch.confirmRecovery();
        vm.prank(guardian2);
        killSwitch.confirmRecovery();

        vm.warp(block.timestamp + killSwitch.FULL_RECOVERY_DELAY() + 1);

        killSwitch.executeRecovery();

        assertEq(
            uint256(killSwitch.currentLevel()),
            uint256(IEnhancedKillSwitch.EmergencyLevel.NONE)
        );
    }

    function test_executeRecovery_reverts_beforeDelay() public {
        vm.prank(guardian1);
        killSwitch.escalateEmergency(
            IEnhancedKillSwitch.EmergencyLevel.WARNING,
            "test"
        );

        killSwitch.initiateRecovery(IEnhancedKillSwitch.EmergencyLevel.NONE);

        vm.expectRevert(IEnhancedKillSwitch.RecoveryDelayNotPassed.selector);
        killSwitch.executeRecovery();
    }

    // ======= Access Control =======

    function test_onlyGuardianCanEscalate() public {
        vm.prank(address(0xDEAD));
        vm.expectRevert(IEnhancedKillSwitch.NotGuardian.selector);
        killSwitch.escalateEmergency(
            IEnhancedKillSwitch.EmergencyLevel.WARNING,
            "unauth"
        );
    }

    // ======= Protected Contracts =======

    function test_setProtectedContract() public {
        address prot = address(0xFE);
        killSwitch.setProtectedContract(prot, true);
        assertTrue(killSwitch.protectedContracts(prot));
    }

    function test_unsetProtectedContract() public {
        address prot = address(0xFE);
        killSwitch.setProtectedContract(prot, true);
        killSwitch.setProtectedContract(prot, false);
        assertFalse(killSwitch.protectedContracts(prot));
    }

    // ======= Admin =======

    function test_addGuardian() public {
        address newGuardian = address(0xF1);
        killSwitch.addGuardian(newGuardian);

        address[] memory gs = killSwitch.getGuardians();
        assertEq(gs.length, 4);
        assertTrue(killSwitch.isGuardian(newGuardian));
    }

    function test_removeGuardian() public {
        killSwitch.removeGuardian(guardian3);

        address[] memory gs = killSwitch.getGuardians();
        assertEq(gs.length, 2);
        assertFalse(killSwitch.isGuardian(guardian3));
    }

    function test_cancelEscalation() public {
        _escalateToDegraded();

        vm.prank(guardian1);
        killSwitch.escalateEmergency(
            IEnhancedKillSwitch.EmergencyLevel.HALTED,
            "cancel test"
        );

        killSwitch.cancelEscalation();

        assertEq(
            uint256(killSwitch.pendingLevel()),
            uint256(IEnhancedKillSwitch.EmergencyLevel.NONE)
        );
    }

    // ======= View =======

    function test_getProtocolState() public view {
        IEnhancedKillSwitch.ProtocolState memory state = killSwitch
            .getProtocolState();
        assertTrue(state.depositsEnabled);
        assertTrue(state.withdrawalsEnabled);
        assertTrue(state.bridgingEnabled);
    }

    function test_getIncidents_empty() public view {
        IEnhancedKillSwitch.EmergencyIncident[] memory incidents = killSwitch
            .getIncidents();
        assertEq(incidents.length, 0);
    }

    function test_getIncidents_afterEscalation() public {
        vm.prank(guardian1);
        killSwitch.escalateEmergency(
            IEnhancedKillSwitch.EmergencyLevel.WARNING,
            "test incident"
        );

        IEnhancedKillSwitch.EmergencyIncident[] memory incidents = killSwitch
            .getIncidents();
        assertEq(incidents.length, 1);
    }

    // ======= Fuzz =======

    function testFuzz_cannotDowngrade(uint8 level) public {
        level = uint8(bound(level, 1, 2));
        vm.prank(guardian1);
        killSwitch.escalateEmergency(
            IEnhancedKillSwitch.EmergencyLevel(level),
            "test"
        );

        vm.prank(guardian1);
        vm.expectRevert(IEnhancedKillSwitch.InvalidLevel.selector);
        killSwitch.escalateEmergency(
            IEnhancedKillSwitch.EmergencyLevel.NONE,
            "downgrade"
        );
    }

    // ======= Helpers =======

    function _escalateToDegraded() internal {
        vm.prank(guardian1);
        killSwitch.escalateEmergency(
            IEnhancedKillSwitch.EmergencyLevel.WARNING,
            "w"
        );
        vm.prank(guardian1);
        killSwitch.escalateEmergency(
            IEnhancedKillSwitch.EmergencyLevel.DEGRADED,
            "d"
        );
    }

    function _escalateToHalted() internal {
        _escalateToDegraded();

        vm.prank(guardian1);
        killSwitch.escalateEmergency(
            IEnhancedKillSwitch.EmergencyLevel.HALTED,
            "h"
        );

        vm.prank(guardian2);
        killSwitch.confirmEscalation(IEnhancedKillSwitch.EmergencyLevel.HALTED);

        vm.warp(block.timestamp + killSwitch.LEVEL_3_COOLDOWN() + 1);

        vm.prank(guardian1);
        killSwitch.executeEscalation();
    }
}
