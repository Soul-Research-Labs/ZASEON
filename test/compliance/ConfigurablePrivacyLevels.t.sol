// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/compliance/ConfigurablePrivacyLevels.sol";

contract ConfigurablePrivacyLevelsTest is Test {
    ConfigurablePrivacyLevels public privacy;

    address public admin = makeAddr("admin");
    address public user1 = makeAddr("user1");
    address public user2 = makeAddr("user2");

    bytes32 public constant COMMIT_1 = keccak256("commit1");
    bytes32 public constant COMMIT_2 = keccak256("commit2");
    bytes32 public constant META_HASH = keccak256("metadata");

    event PrivacyConfigSet(
        bytes32 indexed commitment,
        address indexed owner,
        ConfigurablePrivacyLevels.PrivacyLevel level,
        uint48 retentionUntil
    );
    event UserDefaultLevelSet(
        address indexed user,
        ConfigurablePrivacyLevels.PrivacyLevel level
    );
    event JurisdictionPolicySet(
        bytes2 indexed jurisdiction,
        ConfigurablePrivacyLevels.PrivacyLevel minLevel,
        ConfigurablePrivacyLevels.PrivacyLevel maxLevel
    );
    event FeeTierUpdated(
        ConfigurablePrivacyLevels.PrivacyLevel indexed level,
        uint256 baseFeeGwei,
        uint256 multiplierBps
    );
    event GlobalMinLevelUpdated(
        ConfigurablePrivacyLevels.PrivacyLevel oldLevel,
        ConfigurablePrivacyLevels.PrivacyLevel newLevel
    );

    function setUp() public {
        privacy = new ConfigurablePrivacyLevels(admin);
    }

    /*//////////////////////////////////////////////////////////////
                   PRIVACY CONFIG TESTS
    //////////////////////////////////////////////////////////////*/

    function test_SetPrivacyConfig_Maximum() public {
        vm.prank(user1);
        privacy.setPrivacyConfig(
            COMMIT_1,
            ConfigurablePrivacyLevels.PrivacyLevel.MAXIMUM,
            bytes32(0),
            0
        );

        (
            ConfigurablePrivacyLevels.PrivacyLevel level,
            bytes32 metadataHash,
            uint48 retentionUntil,
            bool auditorRequired
        ) = privacy.commitmentPrivacy(COMMIT_1);

        assertEq(
            uint8(level),
            uint8(ConfigurablePrivacyLevels.PrivacyLevel.MAXIMUM)
        );
        assertEq(metadataHash, bytes32(0));
        assertEq(retentionUntil, 0);
        assertFalse(auditorRequired);
    }

    function test_SetPrivacyConfig_Compliant() public {
        vm.prank(user1);
        privacy.setPrivacyConfig(
            COMMIT_1,
            ConfigurablePrivacyLevels.PrivacyLevel.COMPLIANT,
            META_HASH,
            365 days
        );

        (
            ConfigurablePrivacyLevels.PrivacyLevel level,
            ,
            uint48 retentionUntil,
            bool auditorRequired
        ) = privacy.commitmentPrivacy(COMMIT_1);

        assertEq(
            uint8(level),
            uint8(ConfigurablePrivacyLevels.PrivacyLevel.COMPLIANT)
        );
        assertTrue(auditorRequired);
        assertGt(retentionUntil, 0);
    }

    function test_SetPrivacyConfig_Transparent() public {
        vm.prank(user1);
        privacy.setPrivacyConfig(
            COMMIT_1,
            ConfigurablePrivacyLevels.PrivacyLevel.TRANSPARENT,
            META_HASH,
            30 days
        );

        (, , , bool auditorRequired) = privacy.commitmentPrivacy(COMMIT_1);
        assertTrue(auditorRequired);
    }

    function test_SetPrivacyConfig_EmitsEvent() public {
        vm.prank(user1);
        vm.expectEmit(true, true, false, true);
        emit PrivacyConfigSet(
            COMMIT_1,
            user1,
            ConfigurablePrivacyLevels.PrivacyLevel.HIGH,
            0
        );
        privacy.setPrivacyConfig(
            COMMIT_1,
            ConfigurablePrivacyLevels.PrivacyLevel.HIGH,
            META_HASH,
            0
        );
    }

    function test_RevertOnRetentionTooLong() public {
        vm.prank(user1);
        vm.expectRevert(
            ConfigurablePrivacyLevels.RetentionPeriodTooLong.selector
        );
        privacy.setPrivacyConfig(
            COMMIT_1,
            ConfigurablePrivacyLevels.PrivacyLevel.HIGH,
            META_HASH,
            3651 days
        );
    }

    /*//////////////////////////////////////////////////////////////
                  GLOBAL MINIMUM LEVEL TESTS
    //////////////////////////////////////////////////////////////*/

    function test_GlobalMinLevel_Enforced() public {
        vm.prank(admin);
        privacy.setGlobalMinLevel(
            ConfigurablePrivacyLevels.PrivacyLevel.MEDIUM
        );

        // MAXIMUM (0) is below MEDIUM (2) → should revert
        vm.prank(user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                ConfigurablePrivacyLevels.PrivacyLevelBelowMinimum.selector,
                ConfigurablePrivacyLevels.PrivacyLevel.MAXIMUM,
                ConfigurablePrivacyLevels.PrivacyLevel.MEDIUM
            )
        );
        privacy.setPrivacyConfig(
            COMMIT_1,
            ConfigurablePrivacyLevels.PrivacyLevel.MAXIMUM,
            bytes32(0),
            0
        );
    }

    function test_GlobalMinLevel_AllowsEqual() public {
        vm.prank(admin);
        privacy.setGlobalMinLevel(
            ConfigurablePrivacyLevels.PrivacyLevel.MEDIUM
        );

        // MEDIUM (2) == min (2) → should pass
        vm.prank(user1);
        privacy.setPrivacyConfig(
            COMMIT_1,
            ConfigurablePrivacyLevels.PrivacyLevel.MEDIUM,
            META_HASH,
            0
        );
    }

    function test_GlobalMinLevel_AllowsAbove() public {
        vm.prank(admin);
        privacy.setGlobalMinLevel(
            ConfigurablePrivacyLevels.PrivacyLevel.MEDIUM
        );

        // COMPLIANT (3) > MEDIUM (2) → should pass
        vm.prank(user1);
        privacy.setPrivacyConfig(
            COMMIT_1,
            ConfigurablePrivacyLevels.PrivacyLevel.COMPLIANT,
            META_HASH,
            0
        );
    }

    /*//////////////////////////////////////////////////////////////
                     USER DEFAULT LEVEL TESTS
    //////////////////////////////////////////////////////////////*/

    function test_SetDefaultLevel() public {
        vm.prank(user1);
        privacy.setDefaultLevel(ConfigurablePrivacyLevels.PrivacyLevel.HIGH);

        assertEq(
            uint8(privacy.userDefaultLevel(user1)),
            uint8(ConfigurablePrivacyLevels.PrivacyLevel.HIGH)
        );
    }

    function test_SetDefaultLevel_RevertBelowGlobalMin() public {
        vm.prank(admin);
        privacy.setGlobalMinLevel(
            ConfigurablePrivacyLevels.PrivacyLevel.COMPLIANT
        );

        vm.prank(user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                ConfigurablePrivacyLevels.PrivacyLevelBelowMinimum.selector,
                ConfigurablePrivacyLevels.PrivacyLevel.MAXIMUM,
                ConfigurablePrivacyLevels.PrivacyLevel.COMPLIANT
            )
        );
        privacy.setDefaultLevel(ConfigurablePrivacyLevels.PrivacyLevel.MAXIMUM);
    }

    /*//////////////////////////////////////////////////////////////
                    EFFECTIVE LEVEL TESTS
    //////////////////////////////////////////////////////////////*/

    function test_GetEffectiveLevel_CommitmentSpecific() public {
        vm.prank(user1);
        privacy.setPrivacyConfig(
            COMMIT_1,
            ConfigurablePrivacyLevels.PrivacyLevel.HIGH,
            META_HASH,
            30 days
        );

        ConfigurablePrivacyLevels.PrivacyLevel level = privacy
            .getEffectiveLevel(COMMIT_1, user1);
        assertEq(
            uint8(level),
            uint8(ConfigurablePrivacyLevels.PrivacyLevel.HIGH)
        );
    }

    function test_GetEffectiveLevel_FallsBackToDefault() public {
        vm.prank(user1);
        privacy.setDefaultLevel(
            ConfigurablePrivacyLevels.PrivacyLevel.COMPLIANT
        );

        // No commitment config → should return user default
        ConfigurablePrivacyLevels.PrivacyLevel level = privacy
            .getEffectiveLevel(COMMIT_1, user1);
        assertEq(
            uint8(level),
            uint8(ConfigurablePrivacyLevels.PrivacyLevel.COMPLIANT)
        );
    }

    function test_GetEffectiveLevel_UnsetDefault() public {
        // Neither commitment nor user default set → MAXIMUM (0)
        ConfigurablePrivacyLevels.PrivacyLevel level = privacy
            .getEffectiveLevel(COMMIT_1, user1);
        assertEq(
            uint8(level),
            uint8(ConfigurablePrivacyLevels.PrivacyLevel.MAXIMUM)
        );
    }

    /*//////////////////////////////////////////////////////////////
                    JURISDICTION POLICY TESTS
    //////////////////////////////////////////////////////////////*/

    function test_SetJurisdictionPolicy() public {
        vm.prank(admin);
        privacy.setJurisdictionPolicy(
            bytes2("US"),
            ConfigurablePrivacyLevels.PrivacyLevel.COMPLIANT,
            ConfigurablePrivacyLevels.PrivacyLevel.TRANSPARENT,
            365 days
        );

        (
            ConfigurablePrivacyLevels.PrivacyLevel minLevel,
            ConfigurablePrivacyLevels.PrivacyLevel maxLevel,
            uint256 retentionPeriod,
            bool active
        ) = privacy.jurisdictionPolicies(bytes2("US"));

        assertEq(
            uint8(minLevel),
            uint8(ConfigurablePrivacyLevels.PrivacyLevel.COMPLIANT)
        );
        assertEq(
            uint8(maxLevel),
            uint8(ConfigurablePrivacyLevels.PrivacyLevel.TRANSPARENT)
        );
        assertEq(retentionPeriod, 365 days);
        assertTrue(active);
    }

    function test_IsLevelAllowed_NoPolicy() public {
        // No policy set for "JP" → all levels allowed
        assertTrue(
            privacy.isLevelAllowedForJurisdiction(
                ConfigurablePrivacyLevels.PrivacyLevel.MAXIMUM,
                bytes2("JP")
            )
        );
        assertTrue(
            privacy.isLevelAllowedForJurisdiction(
                ConfigurablePrivacyLevels.PrivacyLevel.TRANSPARENT,
                bytes2("JP")
            )
        );
    }

    function test_IsLevelAllowed_WithPolicy() public {
        vm.prank(admin);
        privacy.setJurisdictionPolicy(
            bytes2("US"),
            ConfigurablePrivacyLevels.PrivacyLevel.COMPLIANT,
            ConfigurablePrivacyLevels.PrivacyLevel.TRANSPARENT,
            365 days
        );

        // MAXIMUM < COMPLIANT → not allowed
        assertFalse(
            privacy.isLevelAllowedForJurisdiction(
                ConfigurablePrivacyLevels.PrivacyLevel.MAXIMUM,
                bytes2("US")
            )
        );
        // COMPLIANT in range → allowed
        assertTrue(
            privacy.isLevelAllowedForJurisdiction(
                ConfigurablePrivacyLevels.PrivacyLevel.COMPLIANT,
                bytes2("US")
            )
        );
        // TRANSPARENT in range → allowed
        assertTrue(
            privacy.isLevelAllowedForJurisdiction(
                ConfigurablePrivacyLevels.PrivacyLevel.TRANSPARENT,
                bytes2("US")
            )
        );
    }

    function test_RevertOnInvalidPolicyRange() public {
        vm.prank(admin);
        vm.expectRevert(ConfigurablePrivacyLevels.InvalidPrivacyLevel.selector);
        privacy.setJurisdictionPolicy(
            bytes2("US"),
            ConfigurablePrivacyLevels.PrivacyLevel.TRANSPARENT, // min > max → invalid
            ConfigurablePrivacyLevels.PrivacyLevel.MAXIMUM,
            365 days
        );
    }

    /*//////////////////////////////////////////////////////////////
                       FEE TIER TESTS
    //////////////////////////////////////////////////////////////*/

    function test_DefaultFeeTiers() public {
        (uint256 baseFee, uint256 multiplier) = privacy.feeTiers(
            ConfigurablePrivacyLevels.PrivacyLevel.MAXIMUM
        );
        assertEq(baseFee, 100);
        assertEq(multiplier, 15000);

        (baseFee, multiplier) = privacy.feeTiers(
            ConfigurablePrivacyLevels.PrivacyLevel.TRANSPARENT
        );
        assertEq(baseFee, 30);
        assertEq(multiplier, 5000);
    }

    function test_CalculateFee() public view {
        uint256 fee = privacy.calculateFee(
            ConfigurablePrivacyLevels.PrivacyLevel.MAXIMUM,
            10000
        );
        // baseFee(100) + 10000 * 15000 / 10000 = 100 + 15000 = 15100
        assertEq(fee, 15100);
    }

    function test_SetFeeTier() public {
        vm.prank(admin);
        privacy.setFeeTier(
            ConfigurablePrivacyLevels.PrivacyLevel.MEDIUM,
            200,
            20000
        );

        (uint256 baseFee, uint256 multiplier) = privacy.feeTiers(
            ConfigurablePrivacyLevels.PrivacyLevel.MEDIUM
        );
        assertEq(baseFee, 200);
        assertEq(multiplier, 20000);
    }

    function test_RevertOnSetFeeTier_NotAdmin() public {
        vm.prank(user1);
        vm.expectRevert();
        privacy.setFeeTier(
            ConfigurablePrivacyLevels.PrivacyLevel.MEDIUM,
            200,
            20000
        );
    }

    /*//////////////////////////////////////////////////////////////
                    AUDITOR ACCESS REQUIRED
    //////////////////////////////////////////////////////////////*/

    function test_RequiresAuditorAccess_Compliant() public {
        vm.prank(user1);
        privacy.setPrivacyConfig(
            COMMIT_1,
            ConfigurablePrivacyLevels.PrivacyLevel.COMPLIANT,
            META_HASH,
            0
        );
        assertTrue(privacy.requiresAuditorAccess(COMMIT_1));
    }

    function test_RequiresAuditorAccess_Maximum() public {
        // Not set → default is MAXIMUM with no auditor access
        assertFalse(privacy.requiresAuditorAccess(COMMIT_1));
    }

    /*//////////////////////////////////////////////////////////////
                          FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_SetPrivacyConfig(
        bytes32 commitment,
        uint8 levelRaw,
        uint256 retention
    ) public {
        levelRaw = uint8(bound(levelRaw, 0, 4)); // 5 enum values
        retention = bound(retention, 0, 3650 days);

        ConfigurablePrivacyLevels.PrivacyLevel level = ConfigurablePrivacyLevels
            .PrivacyLevel(levelRaw);

        vm.prank(user1);
        privacy.setPrivacyConfig(commitment, level, META_HASH, retention);

        (ConfigurablePrivacyLevels.PrivacyLevel stored, , , ) = privacy
            .commitmentPrivacy(commitment);
        assertEq(uint8(stored), levelRaw);
    }

    function testFuzz_CalculateFee(
        uint8 levelRaw,
        uint256 baseAmount
    ) public view {
        levelRaw = uint8(bound(levelRaw, 0, 4));
        baseAmount = bound(baseAmount, 0, 1e18);

        uint256 fee = privacy.calculateFee(
            ConfigurablePrivacyLevels.PrivacyLevel(levelRaw),
            baseAmount
        );
        assertGe(fee, 0); // No overflow
    }

    function testFuzz_JurisdictionPolicy(bytes2 jurisdiction) public {
        vm.prank(admin);
        privacy.setJurisdictionPolicy(
            jurisdiction,
            ConfigurablePrivacyLevels.PrivacyLevel.MEDIUM,
            ConfigurablePrivacyLevels.PrivacyLevel.TRANSPARENT,
            90 days
        );

        assertTrue(
            privacy.isLevelAllowedForJurisdiction(
                ConfigurablePrivacyLevels.PrivacyLevel.COMPLIANT,
                jurisdiction
            )
        );
        assertFalse(
            privacy.isLevelAllowedForJurisdiction(
                ConfigurablePrivacyLevels.PrivacyLevel.MAXIMUM,
                jurisdiction
            )
        );
    }

    /*//////////////////////////////////////////////////////////////
                      ADMIN ACCESS CONTROL
    //////////////////////////////////////////////////////////////*/

    function test_RevertOnSetGlobalMinLevel_NotAdmin() public {
        vm.prank(user1);
        vm.expectRevert();
        privacy.setGlobalMinLevel(
            ConfigurablePrivacyLevels.PrivacyLevel.COMPLIANT
        );
    }

    function test_RevertOnSetJurisdictionPolicy_NotAdmin() public {
        vm.prank(user1);
        vm.expectRevert();
        privacy.setJurisdictionPolicy(
            bytes2("US"),
            ConfigurablePrivacyLevels.PrivacyLevel.COMPLIANT,
            ConfigurablePrivacyLevels.PrivacyLevel.TRANSPARENT,
            365 days
        );
    }

    function test_TotalConfigs() public {
        assertEq(privacy.totalConfigs(), 0);

        vm.prank(user1);
        privacy.setPrivacyConfig(
            COMMIT_1,
            ConfigurablePrivacyLevels.PrivacyLevel.HIGH,
            META_HASH,
            0
        );
        assertEq(privacy.totalConfigs(), 1);

        vm.prank(user2);
        privacy.setPrivacyConfig(
            COMMIT_2,
            ConfigurablePrivacyLevels.PrivacyLevel.MEDIUM,
            META_HASH,
            0
        );
        assertEq(privacy.totalConfigs(), 2);
    }
}
