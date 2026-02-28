// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/privacy/PrivacyTierRouter.sol";

contract PrivacyTierRouterTest is Test {
    PrivacyTierRouter public router;
    address public admin = address(this);
    address public user1 = makeAddr("user1");
    address public user2 = makeAddr("user2");
    address public operator = makeAddr("operator");

    uint32 constant SRC_CHAIN = 1;
    uint32 constant DST_CHAIN = 42161;

    function setUp() public {
        router = new PrivacyTierRouter(admin);
        router.grantRole(router.OPERATOR_ROLE(), operator);
    }

    /*//////////////////////////////////////////////////////////////
                       SUBMISSION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_SubmitOperation_Standard() public {
        vm.prank(user1);
        bytes32 opId = router.submitOperation(
            SRC_CHAIN,
            DST_CHAIN,
            IPrivacyTierRouter.PrivacyTier.STANDARD,
            1 ether
        );

        IPrivacyTierRouter.PrivacyOperation memory op = router.getOperation(
            opId
        );
        assertEq(op.sender, user1);
        assertEq(
            uint8(op.tier),
            uint8(IPrivacyTierRouter.PrivacyTier.STANDARD)
        );
        assertEq(op.value, 1 ether);
        assertFalse(op.completed);
        assertEq(router.totalOperations(), 1);
    }

    function test_SubmitOperation_AutoEscalateEnhanced() public {
        vm.prank(user1);
        bytes32 opId = router.submitOperation(
            SRC_CHAIN,
            DST_CHAIN,
            IPrivacyTierRouter.PrivacyTier.STANDARD,
            15 ether // above 10 ETH threshold
        );

        IPrivacyTierRouter.PrivacyOperation memory op = router.getOperation(
            opId
        );
        assertEq(
            uint8(op.tier),
            uint8(IPrivacyTierRouter.PrivacyTier.ENHANCED)
        );
    }

    function test_SubmitOperation_AutoEscalateMaximum() public {
        vm.prank(user1);
        bytes32 opId = router.submitOperation(
            SRC_CHAIN,
            DST_CHAIN,
            IPrivacyTierRouter.PrivacyTier.STANDARD,
            200 ether // above 100 ETH threshold
        );

        IPrivacyTierRouter.PrivacyOperation memory op = router.getOperation(
            opId
        );
        assertEq(uint8(op.tier), uint8(IPrivacyTierRouter.PrivacyTier.MAXIMUM));
    }

    function test_SubmitOperation_UserDefaultFloor() public {
        vm.prank(user1);
        router.setUserDefaultTier(IPrivacyTierRouter.PrivacyTier.ENHANCED);

        vm.prank(user1);
        bytes32 opId = router.submitOperation(
            SRC_CHAIN,
            DST_CHAIN,
            IPrivacyTierRouter.PrivacyTier.STANDARD, // request standard
            1 ether // below threshold
        );

        // Should be enhanced (user default floor)
        IPrivacyTierRouter.PrivacyOperation memory op = router.getOperation(
            opId
        );
        assertEq(
            uint8(op.tier),
            uint8(IPrivacyTierRouter.PrivacyTier.ENHANCED)
        );
    }

    function test_SubmitOperation_ExplicitHigherTierRespected() public {
        vm.prank(user1);
        bytes32 opId = router.submitOperation(
            SRC_CHAIN,
            DST_CHAIN,
            IPrivacyTierRouter.PrivacyTier.MAXIMUM, // explicit maximum
            1 ether // low value
        );

        IPrivacyTierRouter.PrivacyOperation memory op = router.getOperation(
            opId
        );
        assertEq(uint8(op.tier), uint8(IPrivacyTierRouter.PrivacyTier.MAXIMUM));
    }

    /*//////////////////////////////////////////////////////////////
                       LIFECYCLE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_AssignCluster() public {
        vm.prank(user1);
        bytes32 opId = router.submitOperation(
            SRC_CHAIN,
            DST_CHAIN,
            IPrivacyTierRouter.PrivacyTier.STANDARD,
            1 ether
        );

        bytes32 clusterId = keccak256("cluster1");
        vm.prank(operator);
        router.assignCluster(opId, clusterId);

        IPrivacyTierRouter.PrivacyOperation memory op = router.getOperation(
            opId
        );
        assertEq(op.assignedCluster, clusterId);
    }

    function test_CompleteOperation() public {
        vm.prank(user1);
        bytes32 opId = router.submitOperation(
            SRC_CHAIN,
            DST_CHAIN,
            IPrivacyTierRouter.PrivacyTier.STANDARD,
            1 ether
        );

        vm.prank(operator);
        router.completeOperation(opId, true);

        IPrivacyTierRouter.PrivacyOperation memory op = router.getOperation(
            opId
        );
        assertTrue(op.completed);
        assertEq(router.completedOperations(), 1);
    }

    function test_CompleteOperation_DoubleCompleteReverts() public {
        vm.prank(user1);
        bytes32 opId = router.submitOperation(
            SRC_CHAIN,
            DST_CHAIN,
            IPrivacyTierRouter.PrivacyTier.STANDARD,
            1 ether
        );

        vm.prank(operator);
        router.completeOperation(opId, true);

        vm.prank(operator);
        vm.expectRevert(
            abi.encodeWithSelector(
                IPrivacyTierRouter.OperationAlreadyCompleted.selector,
                opId
            )
        );
        router.completeOperation(opId, true);
    }

    /*//////////////////////////////////////////////////////////////
                       TIER CONFIG TESTS
    //////////////////////////////////////////////////////////////*/

    function test_ConfigureTier() public {
        IPrivacyTierRouter.TierConfig memory config = IPrivacyTierRouter
            .TierConfig({
                minRelayers: 7,
                requireRingSig: true,
                requireConstantTime: true,
                requireMixnet: true,
                requireRecursiveProof: true,
                escalationThreshold: 50 ether
            });

        router.configureTier(IPrivacyTierRouter.PrivacyTier.ENHANCED, config);

        IPrivacyTierRouter.TierConfig memory stored = router.getTierConfig(
            IPrivacyTierRouter.PrivacyTier.ENHANCED
        );
        assertEq(stored.minRelayers, 7);
        assertTrue(stored.requireMixnet);
        assertEq(stored.escalationThreshold, 50 ether);
    }

    function test_ConfigureTier_ZeroRelayersReverts() public {
        IPrivacyTierRouter.TierConfig memory config = IPrivacyTierRouter
            .TierConfig({
                minRelayers: 0,
                requireRingSig: false,
                requireConstantTime: false,
                requireMixnet: false,
                requireRecursiveProof: false,
                escalationThreshold: 0
            });

        vm.expectRevert(
            abi.encodeWithSelector(
                IPrivacyTierRouter.InvalidTierConfig.selector,
                IPrivacyTierRouter.PrivacyTier.STANDARD
            )
        );
        router.configureTier(IPrivacyTierRouter.PrivacyTier.STANDARD, config);
    }

    /*//////////////////////////////////////////////////////////////
                       VIEW TESTS
    //////////////////////////////////////////////////////////////*/

    function test_GetEffectiveTier() public {
        IPrivacyTierRouter.PrivacyTier tier = router.getEffectiveTier(
            user1,
            1 ether
        );
        assertEq(uint8(tier), uint8(IPrivacyTierRouter.PrivacyTier.STANDARD));

        tier = router.getEffectiveTier(user1, 50 ether);
        assertEq(uint8(tier), uint8(IPrivacyTierRouter.PrivacyTier.ENHANCED));

        tier = router.getEffectiveTier(user1, 200 ether);
        assertEq(uint8(tier), uint8(IPrivacyTierRouter.PrivacyTier.MAXIMUM));
    }

    function test_GetDefaultTierConfig() public {
        IPrivacyTierRouter.TierConfig memory std = router.getTierConfig(
            IPrivacyTierRouter.PrivacyTier.STANDARD
        );
        assertEq(std.minRelayers, 1);
        assertFalse(std.requireRingSig);

        IPrivacyTierRouter.TierConfig memory enh = router.getTierConfig(
            IPrivacyTierRouter.PrivacyTier.ENHANCED
        );
        assertEq(enh.minRelayers, 3);
        assertTrue(enh.requireRingSig);

        IPrivacyTierRouter.TierConfig memory max = router.getTierConfig(
            IPrivacyTierRouter.PrivacyTier.MAXIMUM
        );
        assertEq(max.minRelayers, 5);
        assertTrue(max.requireRecursiveProof);
    }

    /*//////////////////////////////////////////////////////////////
                       FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_TierEscalationMonotonicity(uint256 value) public {
        vm.assume(value <= 1000 ether);

        vm.prank(user1);
        IPrivacyTierRouter.PrivacyTier tier = router.getEffectiveTier(
            user1,
            value
        );

        if (value >= 100 ether) {
            assertEq(
                uint8(tier),
                uint8(IPrivacyTierRouter.PrivacyTier.MAXIMUM)
            );
        } else if (value >= 10 ether) {
            assertEq(
                uint8(tier),
                uint8(IPrivacyTierRouter.PrivacyTier.ENHANCED)
            );
        } else {
            assertEq(
                uint8(tier),
                uint8(IPrivacyTierRouter.PrivacyTier.STANDARD)
            );
        }
    }
}
