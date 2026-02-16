// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {PrivacyRouter} from "../../contracts/core/PrivacyRouter.sol";
import {IPrivacyRouter} from "../../contracts/interfaces/IPrivacyRouter.sol";
import {UniversalShieldedPool} from "../../contracts/privacy/UniversalShieldedPool.sol";

/**
 * @title PrivacyRouterTest
 * @notice Tests for the Privacy Router facade
 */
contract PrivacyRouterTest is Test {
    PrivacyRouter public router;
    UniversalShieldedPool public pool;

    address public admin = makeAddr("admin");
    address public user = makeAddr("user");
    address public recipient = makeAddr("recipient");

    bytes32 public constant OPERATOR_ROLE =
        0x97667070c54ef182b0f5858b034beac1b6f3089aa2d3188bb1e8929f4fa9b929;

    /// @dev BN254 scalar field order
    uint256 internal constant FIELD_SIZE =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    /// @dev Helper: produce a valid BN254 commitment from arbitrary seed
    function _validCommitment(
        bytes memory seed
    ) internal pure returns (bytes32) {
        return bytes32((uint256(keccak256(seed)) % (FIELD_SIZE - 1)) + 1);
    }

    function setUp() public {
        vm.startPrank(admin);

        // Deploy pool with testMode=false so deposits are accepted
        pool = new UniversalShieldedPool(admin, address(0), false);

        // Deploy router with pool and mock component addresses
        router = new PrivacyRouter(
            admin,
            address(pool),
            makeAddr("crossChainHub"),
            makeAddr("stealthRegistry"),
            makeAddr("nullifierManager"),
            makeAddr("compliance"),
            makeAddr("proofTranslator")
        );

        // Disable compliance for testing
        router.setComplianceEnabled(false);

        vm.stopPrank();

        vm.deal(user, 100 ether);
    }

    /*//////////////////////////////////////////////////////////////
                          INITIALIZATION
    //////////////////////////////////////////////////////////////*/

    function test_InitializeCorrectly() public view {
        assertEq(router.shieldedPool(), address(pool));
        assertFalse(router.complianceEnabled());
        assertEq(router.operationNonce(), 0);
    }

    function test_ComponentAddresses() public {
        assertEq(router.shieldedPool(), address(pool));
        assertEq(router.crossChainHub(), makeAddr("crossChainHub"));
        assertEq(router.stealthRegistry(), makeAddr("stealthRegistry"));
    }

    /*//////////////////////////////////////////////////////////////
                        DEPOSIT ETH VIA ROUTER
    //////////////////////////////////////////////////////////////*/

    function test_DepositETH() public {
        bytes32 commitment = _validCommitment(
            abi.encodePacked("router_secret", uint256(1 ether))
        );

        vm.prank(user);
        bytes32 opId = router.depositETH{value: 1 ether}(commitment);

        assertTrue(opId != bytes32(0), "Operation ID should be generated");

        // Check receipt
        (
            bytes32 receiptId,
            IPrivacyRouter.OperationType opType,
            ,
            bytes32 commitHash,
            bool success
        ) = router.receipts(opId);
        assertEq(receiptId, opId);
        assertEq(uint8(opType), uint8(IPrivacyRouter.OperationType.DEPOSIT));
        assertEq(commitHash, commitment);
        assertTrue(success);
    }

    function test_RevertDepositETHZeroAmount() public {
        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(IPrivacyRouter.ZeroAmount.selector)
        );
        router.depositETH{value: 0}(keccak256("zero"));
    }

    /*//////////////////////////////////////////////////////////////
                       QUERY FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function test_GetOperationCount() public {
        bytes32 c1 = _validCommitment(abi.encodePacked("op1", uint256(1)));
        bytes32 c2 = _validCommitment(abi.encodePacked("op2", uint256(2)));

        vm.startPrank(user);
        router.depositETH{value: 1 ether}(c1);
        router.depositETH{value: 1 ether}(c2);
        vm.stopPrank();

        assertEq(
            router.getOperationCount(IPrivacyRouter.OperationType.DEPOSIT),
            2
        );
        assertEq(
            router.getOperationCount(IPrivacyRouter.OperationType.WITHDRAW),
            0
        );
    }

    function test_GetReceipt() public {
        bytes32 commitment = _validCommitment(
            abi.encodePacked("receipt_test", uint256(1))
        );

        vm.prank(user);
        bytes32 opId = router.depositETH{value: 1 ether}(commitment);

        IPrivacyRouter.OperationReceipt memory receipt = router.getReceipt(
            opId
        );
        assertEq(receipt.operationId, opId);
        assertTrue(receipt.success);
        assertEq(receipt.timestamp, block.timestamp);
    }

    function test_CheckComplianceDisabled() public view {
        assertTrue(
            router.checkCompliance(user),
            "Should pass when compliance disabled"
        );
    }

    /*//////////////////////////////////////////////////////////////
                       ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function test_SetComponent() public {
        address newPool = makeAddr("newPool");

        vm.prank(admin);
        router.setComponent("shieldedPool", newPool);

        assertEq(router.shieldedPool(), newPool);
    }

    function test_RevertSetComponentZeroAddress() public {
        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(IPrivacyRouter.ZeroAddress.selector)
        );
        router.setComponent("shieldedPool", address(0));
    }

    function test_RevertSetInvalidComponent() public {
        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(IPrivacyRouter.InvalidParams.selector)
        );
        router.setComponent("invalidName", makeAddr("something"));
    }

    function test_SetComplianceEnabled() public {
        vm.prank(admin);
        router.setComplianceEnabled(true);
        assertTrue(router.complianceEnabled());
    }

    function test_SetMinimumKYCTier() public {
        vm.prank(admin);
        router.setMinimumKYCTier(2);
        assertEq(router.minimumKYCTier(), 2);
    }

    function test_PauseAndUnpause() public {
        vm.startPrank(admin);
        router.pause();

        vm.expectRevert();
        vm.stopPrank();
        vm.prank(user);
        router.depositETH{value: 1 ether}(_validCommitment("paused"));

        vm.prank(admin);
        router.unpause();

        // Should work again
        vm.prank(user);
        router.depositETH{value: 1 ether}(_validCommitment("unpaused"));
    }

    /*//////////////////////////////////////////////////////////////
                       CROSS-CHAIN REVERT
    //////////////////////////////////////////////////////////////*/

    function test_CrossChainTransferForwardsToHub() public {
        // crossChainHub is an EOA (makeAddr), so the low-level call succeeds
        // but the operation should still complete and emit an event
        IPrivacyRouter.CrossChainTransferParams memory params = IPrivacyRouter
            .CrossChainTransferParams({
                destChainId: 42161,
                recipientStealth: keccak256("stealth"),
                amount: 1 ether,
                privacyLevel: 3,
                proofSystem: 0,
                proof: new bytes(128),
                publicInputs: new bytes32[](1),
                proofHash: keccak256("proof")
            });

        vm.prank(user);
        bytes32 opId = router.initiatePrivateTransfer{value: 1 ether}(params);
        assertTrue(opId != bytes32(0));
    }

    function test_RevertConstructorZeroAdmin() public {
        vm.expectRevert(IPrivacyRouter.ZeroAddress.selector);
        new PrivacyRouter(
            address(0),
            address(pool),
            makeAddr("a"),
            makeAddr("b"),
            makeAddr("c"),
            makeAddr("d"),
            makeAddr("e")
        );
    }

    function test_RevertConstructorZeroPool() public {
        vm.expectRevert(IPrivacyRouter.ZeroAddress.selector);
        new PrivacyRouter(
            admin,
            address(0),
            makeAddr("a"),
            makeAddr("b"),
            makeAddr("c"),
            makeAddr("d"),
            makeAddr("e")
        );
    }

    /*//////////////////////////////////////////////////////////////
                           FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_DepositETHGeneratesUniqueOpIds(
        uint256 amount1,
        uint256 amount2
    ) public {
        amount1 = bound(amount1, 0.001 ether, 10 ether);
        amount2 = bound(amount2, 0.001 ether, 10 ether);
        vm.deal(user, amount1 + amount2);

        bytes32 c1 = _validCommitment(abi.encodePacked("fuzz1", amount1));
        bytes32 c2 = _validCommitment(abi.encodePacked("fuzz2", amount2));
        vm.assume(c1 != c2);

        vm.startPrank(user);
        bytes32 opId1 = router.depositETH{value: amount1}(c1);
        bytes32 opId2 = router.depositETH{value: amount2}(c2);
        vm.stopPrank();

        assertTrue(opId1 != opId2, "Operation IDs should be unique");
    }
}
