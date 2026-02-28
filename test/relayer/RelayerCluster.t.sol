// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/relayer/RelayerCluster.sol";

contract RelayerClusterTest is Test {
    RelayerCluster public cluster;
    address public admin = address(this);
    address public router = makeAddr("router");
    address public relayer1 = makeAddr("relayer1");
    address public relayer2 = makeAddr("relayer2");
    address public relayer3 = makeAddr("relayer3");
    address public relayer4 = makeAddr("relayer4");

    uint32 constant SRC_CHAIN = 1;
    uint32 constant DST_CHAIN = 42161;
    uint256 constant MIN_STAKE = 1 ether;

    function setUp() public {
        cluster = new RelayerCluster(admin);
        cluster.grantRole(cluster.ROUTER_ROLE(), router);
        vm.deal(relayer1, 100 ether);
        vm.deal(relayer2, 100 ether);
        vm.deal(relayer3, 100 ether);
        vm.deal(relayer4, 100 ether);
    }

    /*//////////////////////////////////////////////////////////////
                       CLUSTER CREATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_CreateCluster() public {
        bytes32 cid = cluster.createCluster(
            SRC_CHAIN,
            DST_CHAIN,
            MIN_STAKE,
            10
        );
        IRelayerCluster.ClusterInfo memory info = cluster.getCluster(cid);

        assertEq(info.sourceChainId, SRC_CHAIN);
        assertEq(info.destChainId, DST_CHAIN);
        assertEq(info.minStakePerMember, MIN_STAKE);
        assertEq(info.memberCount, 0);
        assertFalse(info.active);
        assertEq(info.healthScore, 100);
    }

    function test_CreateCluster_SameChainPairReverts() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                IRelayerCluster.InvalidChainPair.selector,
                SRC_CHAIN,
                SRC_CHAIN
            )
        );
        cluster.createCluster(SRC_CHAIN, SRC_CHAIN, MIN_STAKE, 10);
    }

    function test_CreateCluster_InvalidMaxMembers() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                IRelayerCluster.InvalidChainPair.selector,
                SRC_CHAIN,
                DST_CHAIN
            )
        );
        cluster.createCluster(SRC_CHAIN, DST_CHAIN, MIN_STAKE, 2); // below MIN_CLUSTER_SIZE
    }

    /*//////////////////////////////////////////////////////////////
                       JOIN/LEAVE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_JoinCluster() public {
        bytes32 cid = cluster.createCluster(
            SRC_CHAIN,
            DST_CHAIN,
            MIN_STAKE,
            10
        );

        vm.prank(relayer1);
        cluster.joinCluster{value: 2 ether}(cid);

        assertTrue(cluster.isClusterMember(cid, relayer1));
        IRelayerCluster.ClusterInfo memory info = cluster.getCluster(cid);
        assertEq(info.memberCount, 1);
        assertEq(info.totalStake, 2 ether);
        assertFalse(info.active); // not enough members yet
    }

    function test_JoinCluster_InsufficientStake() public {
        bytes32 cid = cluster.createCluster(
            SRC_CHAIN,
            DST_CHAIN,
            MIN_STAKE,
            10
        );

        vm.prank(relayer1);
        vm.expectRevert(
            abi.encodeWithSelector(
                IRelayerCluster.InsufficientClusterStake.selector,
                0.5 ether,
                MIN_STAKE
            )
        );
        cluster.joinCluster{value: 0.5 ether}(cid);
    }

    function test_AutoActivation_On3Members() public {
        bytes32 cid = cluster.createCluster(
            SRC_CHAIN,
            DST_CHAIN,
            MIN_STAKE,
            10
        );

        vm.prank(relayer1);
        cluster.joinCluster{value: 1 ether}(cid);
        vm.prank(relayer2);
        cluster.joinCluster{value: 1 ether}(cid);

        // Still inactive
        assertFalse(cluster.getCluster(cid).active);

        vm.prank(relayer3);
        cluster.joinCluster{value: 1 ether}(cid);

        // Now active
        assertTrue(cluster.getCluster(cid).active);
        assertEq(cluster.getCluster(cid).memberCount, 3);
    }

    function test_LeaveCluster_ReturnsStake() public {
        bytes32 cid = cluster.createCluster(
            SRC_CHAIN,
            DST_CHAIN,
            MIN_STAKE,
            10
        );

        vm.prank(relayer1);
        cluster.joinCluster{value: 5 ether}(cid);

        uint256 balBefore = relayer1.balance;

        vm.prank(relayer1);
        cluster.leaveCluster(cid);

        assertEq(relayer1.balance, balBefore + 5 ether);
        assertFalse(cluster.isClusterMember(cid, relayer1));
    }

    function test_LeaveCluster_NotMemberReverts() public {
        bytes32 cid = cluster.createCluster(
            SRC_CHAIN,
            DST_CHAIN,
            MIN_STAKE,
            10
        );

        vm.prank(relayer1);
        vm.expectRevert(
            abi.encodeWithSelector(
                IRelayerCluster.NotInCluster.selector,
                cid,
                relayer1
            )
        );
        cluster.leaveCluster(cid);
    }

    function test_AutoDeactivation_OnMemberLeave() public {
        bytes32 cid = _createActiveCluster();

        assertTrue(cluster.getCluster(cid).active);

        // Leave brings count below MIN_CLUSTER_SIZE
        vm.prank(relayer1);
        cluster.leaveCluster(cid);

        assertFalse(cluster.getCluster(cid).active);
    }

    /*//////////////////////////////////////////////////////////////
                       RELAY RECORDING TESTS
    //////////////////////////////////////////////////////////////*/

    function test_RecordRelay_UpdatesHealth() public {
        bytes32 cid = _createActiveCluster();

        vm.prank(router);
        cluster.recordRelay(cid, relayer1, true, 100);

        (uint256 total, uint256 successful) = cluster.getRelayStats(cid);
        assertEq(total, 1);
        assertEq(successful, 1);
        assertEq(cluster.getCluster(cid).healthScore, 100);
    }

    function test_RecordRelay_HealthDegradation() public {
        bytes32 cid = _createActiveCluster();

        // Build up health buffer with successes first, then add failures
        // to bring health below 50% threshold
        vm.startPrank(router);
        cluster.recordRelay(cid, relayer1, true, 100); // 1/1 = 100%
        cluster.recordRelay(cid, relayer2, true, 100); // 2/2 = 100%
        cluster.recordRelay(cid, relayer3, true, 100); // 3/3 = 100%
        cluster.recordRelay(cid, relayer1, true, 100); // 4/4 = 100%
        // Now add failures to degrade health below 50
        cluster.recordRelay(cid, relayer1, false, 500); // 4/5 = 80%
        cluster.recordRelay(cid, relayer2, false, 500); // 4/6 = 66%
        cluster.recordRelay(cid, relayer3, false, 500); // 4/7 = 57%
        cluster.recordRelay(cid, relayer1, false, 500); // 4/8 = 50%
        cluster.recordRelay(cid, relayer2, false, 500); // 4/9 = 44% → deactivated
        vm.stopPrank();

        // 4/9 = 44% health → auto-deactivated (threshold 50)
        assertFalse(cluster.getCluster(cid).active);
    }

    function test_RecordRelay_NonMemberReverts() public {
        bytes32 cid = _createActiveCluster();

        vm.prank(router);
        vm.expectRevert(
            abi.encodeWithSelector(
                IRelayerCluster.NotInCluster.selector,
                cid,
                relayer4
            )
        );
        cluster.recordRelay(cid, relayer4, true, 100);
    }

    /*//////////////////////////////////////////////////////////////
                       BEST CLUSTER TESTS
    //////////////////////////////////////////////////////////////*/

    function test_GetBestCluster() public {
        bytes32 cid = _createActiveCluster();

        bytes32 best = cluster.getBestCluster(SRC_CHAIN, DST_CHAIN);
        assertEq(best, cid);
    }

    function test_GetBestCluster_NoneActive() public view {
        bytes32 best = cluster.getBestCluster(SRC_CHAIN, DST_CHAIN);
        assertEq(best, bytes32(0));
    }

    /*//////////////////////////////////////////////////////////////
                       RELAYER CLUSTER TRACKING
    //////////////////////////////////////////////////////////////*/

    function test_RelayerClusterTracking() public {
        bytes32 cid1 = cluster.createCluster(
            SRC_CHAIN,
            DST_CHAIN,
            MIN_STAKE,
            10
        );
        bytes32 cid2 = cluster.createCluster(SRC_CHAIN, 10, MIN_STAKE, 10);

        vm.startPrank(relayer1);
        cluster.joinCluster{value: 1 ether}(cid1);
        cluster.joinCluster{value: 1 ether}(cid2);
        vm.stopPrank();

        bytes32[] memory clusters = cluster.getRelayerClusters(relayer1);
        assertEq(clusters.length, 2);
    }

    /*//////////////////////////////////////////////////////////////
                       FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_StakeAccumulation(
        uint96 stake1,
        uint96 stake2,
        uint96 stake3
    ) public {
        stake1 = uint96(bound(uint256(stake1), 1 ether, 50 ether));
        stake2 = uint96(bound(uint256(stake2), 1 ether, 50 ether));
        stake3 = uint96(bound(uint256(stake3), 1 ether, 50 ether));

        bytes32 cid = cluster.createCluster(
            SRC_CHAIN,
            DST_CHAIN,
            MIN_STAKE,
            10
        );

        vm.prank(relayer1);
        cluster.joinCluster{value: stake1}(cid);
        vm.prank(relayer2);
        cluster.joinCluster{value: stake2}(cid);
        vm.prank(relayer3);
        cluster.joinCluster{value: stake3}(cid);

        IRelayerCluster.ClusterInfo memory info = cluster.getCluster(cid);
        assertEq(
            info.totalStake,
            uint256(stake1) + uint256(stake2) + uint256(stake3)
        );
        assertTrue(info.active);
    }

    /*//////////////////////////////////////////////////////////////
                       HELPERS
    //////////////////////////////////////////////////////////////*/

    function _createActiveCluster() internal returns (bytes32 cid) {
        cid = cluster.createCluster(SRC_CHAIN, DST_CHAIN, MIN_STAKE, 10);

        vm.prank(relayer1);
        cluster.joinCluster{value: 1 ether}(cid);
        vm.prank(relayer2);
        cluster.joinCluster{value: 1 ether}(cid);
        vm.prank(relayer3);
        cluster.joinCluster{value: 1 ether}(cid);
    }
}
