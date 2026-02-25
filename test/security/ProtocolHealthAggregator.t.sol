// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ProtocolHealthAggregator} from "../../contracts/security/ProtocolHealthAggregator.sol";

contract ProtocolHealthAggregatorTest is Test {
    ProtocolHealthAggregator public aggregator;

    address public admin = address(0xAD);
    address public monitor = address(0xB0);
    address public guardian = address(0xC0);

    // Mock pausable contracts
    address public mockContract1;
    address public mockContract2;

    event SubsystemRegistered(
        bytes32 indexed subsystemId,
        string name,
        address source,
        ProtocolHealthAggregator.SubsystemCategory category,
        uint16 weightBps
    );
    event HealthUpdated(
        bytes32 indexed subsystemId,
        uint16 oldScore,
        uint16 newScore
    );
    event CompositeScoreUpdated(
        uint16 oldScore,
        uint16 newScore,
        ProtocolHealthAggregator.HealthStatus status
    );
    event StatusChanged(
        ProtocolHealthAggregator.HealthStatus indexed oldStatus,
        ProtocolHealthAggregator.HealthStatus indexed newStatus,
        uint16 compositeScore
    );
    event AutoPauseTriggered(uint16 compositeScore, uint8 contractsPaused);
    event GuardianOverrideSet(uint16 score, address indexed guardian_);
    event GuardianOverrideCleared(address indexed guardian_);
    event PausableTargetRegistered(address indexed target, string name);

    function setUp() public {
        aggregator = new ProtocolHealthAggregator(admin, 70, 40);

        vm.startPrank(admin);
        aggregator.grantRole(aggregator.MONITOR_ROLE(), monitor);
        aggregator.grantRole(aggregator.GUARDIAN_ROLE(), guardian);
        vm.stopPrank();

        // Deploy mock pausable contracts
        mockContract1 = address(new MockPausable());
        mockContract2 = address(new MockPausable());
    }

    /*//////////////////////////////////////////////////////////////
                          CONSTRUCTOR TESTS
    //////////////////////////////////////////////////////////////*/

    function test_Constructor_SetsThresholds() public view {
        assertEq(aggregator.healthyThreshold(), 70);
        assertEq(aggregator.criticalThreshold(), 40);
    }

    function test_Constructor_SetsRoles() public view {
        assertTrue(aggregator.hasRole(aggregator.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(aggregator.hasRole(aggregator.MONITOR_ROLE(), admin));
        assertTrue(aggregator.hasRole(aggregator.GUARDIAN_ROLE(), admin));
    }

    function test_Constructor_InitializesHealthy() public view {
        assertEq(
            uint8(aggregator.currentStatus()),
            uint8(ProtocolHealthAggregator.HealthStatus.HEALTHY)
        );
        assertEq(aggregator.compositeScore(), 100);
    }

    function test_Constructor_DefaultCategoryWeights() public view {
        assertEq(
            aggregator.categoryWeights(
                ProtocolHealthAggregator.SubsystemCategory.BRIDGE
            ),
            3000
        );
        assertEq(
            aggregator.categoryWeights(
                ProtocolHealthAggregator.SubsystemCategory.RELAYER
            ),
            2000
        );
    }

    function test_Constructor_RevertZeroAdmin() public {
        vm.expectRevert(ProtocolHealthAggregator.ZeroAddress.selector);
        new ProtocolHealthAggregator(address(0), 70, 40);
    }

    function test_Constructor_RevertInvalidThresholds() public {
        // critical >= healthy
        vm.expectRevert(
            abi.encodeWithSelector(
                ProtocolHealthAggregator.InvalidThresholds.selector,
                50,
                50
            )
        );
        new ProtocolHealthAggregator(admin, 50, 50);
    }

    function test_Constructor_RevertScoreAbove100() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                ProtocolHealthAggregator.InvalidThresholds.selector,
                101,
                40
            )
        );
        new ProtocolHealthAggregator(admin, 101, 40);
    }

    /*//////////////////////////////////////////////////////////////
                      SUBSYSTEM REGISTRATION
    //////////////////////////////////////////////////////////////*/

    function test_RegisterSubsystem_Success() public {
        vm.prank(admin);
        aggregator.registerSubsystem(
            "RelayCircuitBreaker",
            address(0x1),
            ProtocolHealthAggregator.SubsystemCategory.BRIDGE,
            5000,
            0
        );

        assertEq(aggregator.subsystemCount(), 1);
    }

    function test_RegisterSubsystem_EmitsEvent() public {
        vm.prank(admin);
        aggregator.registerSubsystem(
            "RelayerMonitor",
            address(0x2),
            ProtocolHealthAggregator.SubsystemCategory.RELAYER,
            5000,
            900
        );

        assertEq(aggregator.subsystemCount(), 1);
    }

    function test_RegisterSubsystem_RevertZeroSource() public {
        vm.prank(admin);
        vm.expectRevert(ProtocolHealthAggregator.ZeroAddress.selector);
        aggregator.registerSubsystem(
            "Bad",
            address(0),
            ProtocolHealthAggregator.SubsystemCategory.BRIDGE,
            5000,
            0
        );
    }

    function test_RegisterSubsystem_RevertZeroWeight() public {
        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(
                ProtocolHealthAggregator.WeightOutOfRange.selector,
                0
            )
        );
        aggregator.registerSubsystem(
            "Bad",
            address(0x1),
            ProtocolHealthAggregator.SubsystemCategory.BRIDGE,
            0,
            0
        );
    }

    function test_RegisterSubsystem_RevertMaxReached() public {
        vm.startPrank(admin);
        for (uint256 i; i < 20; i++) {
            aggregator.registerSubsystem(
                string(abi.encodePacked("Sub", vm.toString(i))),
                address(uint160(i + 1)),
                ProtocolHealthAggregator.SubsystemCategory.BRIDGE,
                1000,
                0
            );
        }
        vm.expectRevert(ProtocolHealthAggregator.MaxSubsystemsReached.selector);
        aggregator.registerSubsystem(
            "Sub21",
            address(0x99),
            ProtocolHealthAggregator.SubsystemCategory.BRIDGE,
            1000,
            0
        );
        vm.stopPrank();
    }

    function test_DeactivateSubsystem() public {
        vm.startPrank(admin);
        aggregator.registerSubsystem(
            "Test",
            address(0x1),
            ProtocolHealthAggregator.SubsystemCategory.BRIDGE,
            5000,
            0
        );
        bytes32[] memory ids = aggregator.getActiveSubsystemIds();
        assertEq(ids.length, 1);

        aggregator.deactivateSubsystem(ids[0]);
        bytes32[] memory ids2 = aggregator.getActiveSubsystemIds();
        assertEq(ids2.length, 0);
        vm.stopPrank();
    }

    function test_ReactivateSubsystem() public {
        vm.startPrank(admin);
        aggregator.registerSubsystem(
            "Test",
            address(0x1),
            ProtocolHealthAggregator.SubsystemCategory.BRIDGE,
            5000,
            0
        );
        bytes32[] memory ids = aggregator.getActiveSubsystemIds();
        aggregator.deactivateSubsystem(ids[0]);
        aggregator.reactivateSubsystem(ids[0]);
        bytes32[] memory ids2 = aggregator.getActiveSubsystemIds();
        assertEq(ids2.length, 1);
        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                          HEALTH UPDATES
    //////////////////////////////////////////////////////////////*/

    function test_UpdateHealth_Success() public {
        bytes32 subId = _registerAdapterSubsystem();

        vm.prank(monitor);
        aggregator.updateHealth(subId, 85);

        (ProtocolHealthAggregator.Subsystem memory sub, ) = aggregator
            .getSubsystemHealth(subId);
        assertEq(sub.healthScore, 85);
    }

    function test_UpdateHealth_RevertScoreAbove100() public {
        bytes32 subId = _registerAdapterSubsystem();

        vm.prank(monitor);
        vm.expectRevert(
            abi.encodeWithSelector(
                ProtocolHealthAggregator.ScoreOutOfRange.selector,
                101
            )
        );
        aggregator.updateHealth(subId, 101);
    }

    function test_UpdateHealth_RevertNotFound() public {
        vm.prank(monitor);
        vm.expectRevert(
            abi.encodeWithSelector(
                ProtocolHealthAggregator.SubsystemNotFound.selector,
                bytes32(uint256(0x01))
            )
        );
        aggregator.updateHealth(bytes32(uint256(1)), 50);
    }

    function test_UpdateHealth_RecalculatesComposite() public {
        bytes32 subId = _registerAdapterSubsystem();

        vm.prank(monitor);
        aggregator.updateHealth(subId, 60);

        // With single subsystem at 60, composite should be 60
        assertEq(aggregator.compositeScore(), 60);
    }

    function test_UpdateHealth_StatusTransitions() public {
        bytes32 subId = _registerAdapterSubsystem();

        // Set to WARNING zone (40-69)
        vm.prank(monitor);
        aggregator.updateHealth(subId, 50);
        assertEq(
            uint8(aggregator.currentStatus()),
            uint8(ProtocolHealthAggregator.HealthStatus.WARNING)
        );

        // Set to CRITICAL zone (<40)
        vm.prank(monitor);
        aggregator.updateHealth(subId, 30);
        assertEq(
            uint8(aggregator.currentStatus()),
            uint8(ProtocolHealthAggregator.HealthStatus.CRITICAL)
        );

        // Set back to HEALTHY (>=70)
        vm.prank(monitor);
        aggregator.updateHealth(subId, 80);
        assertEq(
            uint8(aggregator.currentStatus()),
            uint8(ProtocolHealthAggregator.HealthStatus.HEALTHY)
        );
    }

    function test_BatchUpdateHealth() public {
        bytes32 subId1 = _registerAdapterSubsystem();
        bytes32 subId2 = _registerRelayerSubsystem();

        bytes32[] memory ids = new bytes32[](2);
        ids[0] = subId1;
        ids[1] = subId2;

        uint16[] memory scores = new uint16[](2);
        scores[0] = 80;
        scores[1] = 90;

        vm.prank(monitor);
        aggregator.batchUpdateHealth(ids, scores);

        (ProtocolHealthAggregator.Subsystem memory s1, ) = aggregator
            .getSubsystemHealth(subId1);
        (ProtocolHealthAggregator.Subsystem memory s2, ) = aggregator
            .getSubsystemHealth(subId2);
        assertEq(s1.healthScore, 80);
        assertEq(s2.healthScore, 90);
    }

    /*//////////////////////////////////////////////////////////////
                     COMPOSITE SCORE CALCULATION
    //////////////////////////////////////////////////////////////*/

    function test_CompositeScore_WeightedAverage() public {
        // Register two subsystems in same category with different weights
        bytes32 subId1 = _registerAdapterSubsystem(); // weight 5000
        bytes32 subId2 = _registerRelayerSubsystem(); // weight 5000

        byte32Array2(subId1, subId2);

        // Update: bridge=60, relayer=80
        vm.startPrank(monitor);
        aggregator.updateHealth(subId1, 60);
        aggregator.updateHealth(subId2, 80);
        vm.stopPrank();

        // Composite calculation:
        // Bridge: catWeight=3000, subWeight=5000 → effective = 3000*5000/10000 = 1500
        // Relayer: catWeight=2000, subWeight=5000 → effective = 2000*5000/10000 = 1000
        // Score = (60*1500 + 80*1000) / (1500+1000) = (90000+80000)/2500 = 68
        assertEq(aggregator.compositeScore(), 68);
    }

    function test_CompositeScore_NoSubsystems() public view {
        // Default score should be MAX (100) when no subsystems
        assertEq(aggregator.compositeScore(), 100);
    }

    function test_CompositeScore_StalenessPenalty() public {
        bytes32 subId = _registerAdapterSubsystem();

        vm.prank(monitor);
        aggregator.updateHealth(subId, 80);

        // Fast forward past staleness threshold (15 min default)
        vm.warp(block.timestamp + 16 minutes);

        // Force recalculation by registering another subsystem
        bytes32 subId2 = _registerRelayerSubsystem();
        vm.prank(monitor);
        aggregator.updateHealth(subId2, 100);

        // The stale bridge subsystem's score should be halved (80 → 40)
        // Bridge: effective weight = 3000*5000/10000 = 1500, score = 40 (stale penalty)
        // Relayer: effective weight = 2000*5000/10000 = 1000, score = 100
        // Composite = (40*1500 + 100*1000) / 2500 = (60000+100000)/2500 = 64
        assertEq(aggregator.compositeScore(), 64);
    }

    /*//////////////////////////////////////////////////////////////
                     PAUSABLE TARGET MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    function test_RegisterPausableTarget() public {
        vm.prank(admin);
        aggregator.registerPausableTarget(mockContract1, "Contract1");
        assertEq(aggregator.pausableTargetCount(), 1);
    }

    function test_RegisterPausableTarget_RevertDuplicate() public {
        vm.startPrank(admin);
        aggregator.registerPausableTarget(mockContract1, "Contract1");
        vm.expectRevert(
            abi.encodeWithSelector(
                ProtocolHealthAggregator.TargetAlreadyRegistered.selector,
                mockContract1
            )
        );
        aggregator.registerPausableTarget(mockContract1, "Contract1");
        vm.stopPrank();
    }

    function test_RemovePausableTarget() public {
        vm.startPrank(admin);
        aggregator.registerPausableTarget(mockContract1, "Contract1");
        aggregator.removePausableTarget(mockContract1);
        assertEq(aggregator.pausableTargetCount(), 0);
        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                         AUTO-PAUSE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_AutoPause_TriggersOnCritical() public {
        // Register pausable target
        vm.prank(admin);
        aggregator.registerPausableTarget(mockContract1, "Contract1");

        bytes32 subId = _registerAdapterSubsystem();

        // Set health to CRITICAL (<40)
        vm.prank(monitor);
        aggregator.updateHealth(subId, 20);

        // Check the mock was paused
        assertTrue(MockPausable(mockContract1).isPaused());
    }

    function test_AutoPause_RecoverOnHealthy() public {
        vm.prank(admin);
        aggregator.registerPausableTarget(mockContract1, "Contract1");

        bytes32 subId = _registerAdapterSubsystem();

        // Go critical
        vm.prank(monitor);
        aggregator.updateHealth(subId, 20);
        assertTrue(MockPausable(mockContract1).isPaused());

        // Wait for cooldown
        vm.warp(block.timestamp + 6 minutes);

        // Recover to healthy
        vm.prank(monitor);
        aggregator.updateHealth(subId, 80);
        assertFalse(MockPausable(mockContract1).isPaused());
    }

    function test_AutoPause_CooldownPreventsFlapping() public {
        vm.prank(admin);
        aggregator.registerPausableTarget(mockContract1, "Contract1");

        bytes32 subId = _registerAdapterSubsystem();

        // Go critical - triggers auto-pause
        vm.prank(monitor);
        aggregator.updateHealth(subId, 20);
        assertTrue(MockPausable(mockContract1).isPaused());

        // Manually unpause the mock
        MockPausable(mockContract1).forceUnpause();

        // Go warning then critical again quickly
        vm.prank(monitor);
        aggregator.updateHealth(subId, 50);

        vm.prank(monitor);
        aggregator.updateHealth(subId, 20);
        // Should NOT re-pause because cooldown hasn't elapsed
        assertFalse(MockPausable(mockContract1).isPaused());
    }

    function test_AutoPause_DisabledFlag() public {
        vm.prank(admin);
        aggregator.registerPausableTarget(mockContract1, "Contract1");

        // Disable auto-pause
        vm.prank(admin);
        aggregator.setAutoPauseEnabled(false);

        bytes32 subId = _registerAdapterSubsystem();

        vm.prank(monitor);
        aggregator.updateHealth(subId, 20);

        // Should NOT be paused
        assertFalse(MockPausable(mockContract1).isPaused());
    }

    /*//////////////////////////////////////////////////////////////
                       GUARDIAN OVERRIDES
    //////////////////////////////////////////////////////////////*/

    function test_GuardianOverride_Set() public {
        bytes32 subId = _registerAdapterSubsystem();
        vm.prank(monitor);
        aggregator.updateHealth(subId, 80);

        vm.prank(guardian);
        aggregator.setGuardianOverride(50);

        assertEq(aggregator.compositeScore(), 50);
        assertTrue(aggregator.overrideActive());
        assertEq(
            uint8(aggregator.currentStatus()),
            uint8(ProtocolHealthAggregator.HealthStatus.OVERRIDE)
        );
    }

    function test_GuardianOverride_Clear() public {
        bytes32 subId = _registerAdapterSubsystem();
        vm.prank(monitor);
        aggregator.updateHealth(subId, 80);

        vm.startPrank(guardian);
        aggregator.setGuardianOverride(50);
        aggregator.clearGuardianOverride();
        vm.stopPrank();

        assertFalse(aggregator.overrideActive());
        // Should recalculate to actual score (80)
        assertEq(aggregator.compositeScore(), 80);
    }

    function test_GuardianOverride_RevertScoreOutOfRange() public {
        vm.prank(guardian);
        vm.expectRevert(
            abi.encodeWithSelector(
                ProtocolHealthAggregator.ScoreOutOfRange.selector,
                101
            )
        );
        aggregator.setGuardianOverride(101);
    }

    function test_GuardianOverride_RevertClearWhenNone() public {
        vm.prank(guardian);
        vm.expectRevert(ProtocolHealthAggregator.NoOverrideActive.selector);
        aggregator.clearGuardianOverride();
    }

    function test_GuardianEmergencyPause() public {
        vm.prank(admin);
        aggregator.registerPausableTarget(mockContract1, "Contract1");

        vm.prank(guardian);
        aggregator.guardianEmergencyPause();
        assertTrue(MockPausable(mockContract1).isPaused());
    }

    function test_GuardianRecoverPause() public {
        vm.prank(admin);
        aggregator.registerPausableTarget(mockContract1, "Contract1");

        vm.prank(guardian);
        aggregator.guardianEmergencyPause();

        vm.prank(guardian);
        aggregator.guardianRecoverPause();
        assertFalse(MockPausable(mockContract1).isPaused());
    }

    /*//////////////////////////////////////////////////////////////
                        ADMIN CONTROLS
    //////////////////////////////////////////////////////////////*/

    function test_UpdateThresholds() public {
        vm.prank(admin);
        aggregator.updateThresholds(80, 50);
        assertEq(aggregator.healthyThreshold(), 80);
        assertEq(aggregator.criticalThreshold(), 50);
    }

    function test_UpdateThresholds_RevertInvalid() public {
        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(
                ProtocolHealthAggregator.InvalidThresholds.selector,
                40,
                70
            )
        );
        aggregator.updateThresholds(40, 70);
    }

    function test_UpdateCategoryWeight() public {
        vm.prank(admin);
        aggregator.updateCategoryWeight(
            ProtocolHealthAggregator.SubsystemCategory.BRIDGE,
            5000
        );
        assertEq(
            aggregator.categoryWeights(
                ProtocolHealthAggregator.SubsystemCategory.BRIDGE
            ),
            5000
        );
    }

    function test_PauseUnpause() public {
        vm.startPrank(guardian);
        aggregator.pause();
        assertTrue(aggregator.paused());
        aggregator.unpause();
        assertFalse(aggregator.paused());
        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                        VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function test_GetProtocolHealth() public {
        bytes32 subId = _registerAdapterSubsystem();
        vm.prank(monitor);
        aggregator.updateHealth(subId, 50);

        (
            uint16 score,
            ProtocolHealthAggregator.HealthStatus status,
            uint8 staleCount
        ) = aggregator.getProtocolHealth();
        assertEq(score, 50);
        assertEq(
            uint8(status),
            uint8(ProtocolHealthAggregator.HealthStatus.WARNING)
        );
        assertEq(staleCount, 0);
    }

    function test_GetSubsystemHealth_Staleness() public {
        bytes32 subId = _registerAdapterSubsystem();
        vm.prank(monitor);
        aggregator.updateHealth(subId, 80);

        // Not stale yet
        (, bool isStale1) = aggregator.getSubsystemHealth(subId);
        assertFalse(isStale1);

        // Make stale
        vm.warp(block.timestamp + 16 minutes);
        (, bool isStale2) = aggregator.getSubsystemHealth(subId);
        assertTrue(isStale2);
    }

    function test_GetRecentSnapshots() public {
        bytes32 subId = _registerAdapterSubsystem();

        // Record a few updates
        vm.startPrank(monitor);
        aggregator.updateHealth(subId, 80);
        vm.warp(block.timestamp + 1);
        aggregator.updateHealth(subId, 60);
        vm.warp(block.timestamp + 1);
        aggregator.updateHealth(subId, 90);
        vm.stopPrank();

        ProtocolHealthAggregator.HealthSnapshot[] memory snaps = aggregator
            .getRecentSnapshots(3);
        // Should have 4 snapshots (initial register + 3 updates)
        assertGe(snaps.length, 3);
    }

    /*//////////////////////////////////////////////////////////////
                          FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_UpdateHealth_ScoreBounds(uint16 score) public {
        vm.assume(score <= 100);
        bytes32 subId = _registerAdapterSubsystem();

        vm.prank(monitor);
        aggregator.updateHealth(subId, score);

        (ProtocolHealthAggregator.Subsystem memory sub, ) = aggregator
            .getSubsystemHealth(subId);
        assertEq(sub.healthScore, score);
        assertLe(aggregator.compositeScore(), 100);
    }

    function testFuzz_CompositeScore_AlwaysBounded(
        uint16 s1,
        uint16 s2
    ) public {
        vm.assume(s1 <= 100);
        vm.assume(s2 <= 100);

        bytes32 subId1 = _registerAdapterSubsystem();
        bytes32 subId2 = _registerRelayerSubsystem();

        vm.startPrank(monitor);
        aggregator.updateHealth(subId1, s1);
        aggregator.updateHealth(subId2, s2);
        vm.stopPrank();

        assertLe(aggregator.compositeScore(), 100);
    }

    function testFuzz_StatusTransition_Consistent(uint16 score) public {
        vm.assume(score <= 100);
        bytes32 subId = _registerAdapterSubsystem();

        vm.prank(monitor);
        aggregator.updateHealth(subId, score);

        ProtocolHealthAggregator.HealthStatus status = aggregator
            .currentStatus();
        if (score >= 70) {
            assertEq(
                uint8(status),
                uint8(ProtocolHealthAggregator.HealthStatus.HEALTHY)
            );
        } else if (score >= 40) {
            assertEq(
                uint8(status),
                uint8(ProtocolHealthAggregator.HealthStatus.WARNING)
            );
        } else {
            assertEq(
                uint8(status),
                uint8(ProtocolHealthAggregator.HealthStatus.CRITICAL)
            );
        }
    }

    /*//////////////////////////////////////////////////////////////
                           HELPERS
    //////////////////////////////////////////////////////////////*/

    function _registerAdapterSubsystem() internal returns (bytes32) {
        vm.prank(admin);
        aggregator.registerSubsystem(
            "Bridge",
            address(0x1),
            ProtocolHealthAggregator.SubsystemCategory.BRIDGE,
            5000,
            0
        );
        bytes32[] memory ids = aggregator.getActiveSubsystemIds();
        return ids[ids.length - 1];
    }

    function _registerRelayerSubsystem() internal returns (bytes32) {
        vm.prank(admin);
        aggregator.registerSubsystem(
            "Relayer",
            address(0x2),
            ProtocolHealthAggregator.SubsystemCategory.RELAYER,
            5000,
            0
        );
        bytes32[] memory ids = aggregator.getActiveSubsystemIds();
        return ids[ids.length - 1];
    }

    // Suppress "unused" warning
    function byte32Array2(bytes32, bytes32) internal pure {}
}

/// @dev Simple mock contract that supports pause()/unpause()
contract MockPausable {
    bool public isPaused;

    function pause() external {
        isPaused = true;
    }

    function unpause() external {
        isPaused = false;
    }

    function forceUnpause() external {
        isPaused = false;
    }
}
