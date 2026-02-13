// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/security/FlashLoanGuard.sol";

/// @dev Mock ERC20 token for testing
contract MockERC20 {
    mapping(address => uint256) public balanceOf;

    function setBalance(address account, uint256 amount) external {
        balanceOf[account] = amount;
    }
}

/// @dev Mock oracle that returns a configurable price
contract MockOracle {
    int256 public price;

    constructor(int256 _price) {
        price = _price;
    }

    function setPrice(int256 _price) external {
        price = _price;
    }

    function latestAnswer() external view returns (int256) {
        return price;
    }
}

/// @dev Mock oracle that always reverts
contract RevertingOracle {
    function latestAnswer() external pure {
        revert("oracle down");
    }
}

contract FlashLoanGuardTest is Test {
    FlashLoanGuard public guard;
    MockERC20 public token;
    MockOracle public oracle;
    address public admin = address(0xA);
    address public user1 = address(0x1);
    address public user2 = address(0x2);

    function setUp() public {
        guard = new FlashLoanGuard(500, 1000, admin); // 5% TVL delta, 10% price deviation
        token = new MockERC20();
        oracle = new MockOracle(1000e8); // $1000

        // Whitelist token
        vm.prank(admin);
        guard.whitelistToken(address(token), address(oracle), 500); // 5% max deviation
    }

    // ============= Constructor =============

    function test_Constructor_SetsMaxTVLDelta() public view {
        assertEq(guard.maxTVLDeltaBps(), 500);
    }

    function test_Constructor_SetsMaxPriceDeviation() public view {
        assertEq(guard.maxPriceDeviationBps(), 1000);
    }

    function test_Constructor_AdminRoles() public view {
        assertTrue(guard.hasRole(guard.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(guard.hasRole(guard.OPERATOR_ROLE(), admin));
        assertTrue(guard.hasRole(guard.GUARDIAN_ROLE(), admin));
    }

    // ============= Constants =============

    function test_Constants() public view {
        assertEq(guard.MAX_OPS_PER_BLOCK(), 3);
        assertEq(guard.MAX_OPS_PER_EPOCH(), 50);
        assertEq(guard.EPOCH_LENGTH(), 100);
    }

    // ============= Validate Operation =============

    function test_ValidateOperation_ETH_Success() public {
        // Set up TVL so delta check can work
        vm.prank(admin);
        guard.updateTVL(100 ether);

        bool safe = guard.validateOperation(user1, address(0), 1 ether);
        assertTrue(safe);
    }

    function test_ValidateOperation_BlocksAfterMaxOps() public {
        // Set up TVL
        vm.prank(admin);
        guard.updateTVL(100 ether);

        // First 3 calls should succeed (MAX_OPS_PER_BLOCK = 3)
        guard.validateOperation(user1, address(0), 0.1 ether);
        guard.validateOperation(user1, address(0), 0.1 ether);
        guard.validateOperation(user1, address(0), 0.1 ether);

        // 4th call in same block should return false
        bool safe = guard.validateOperation(user1, address(0), 0.1 ether);
        assertFalse(safe);
    }

    function test_ValidateOperation_NewBlockResetsCounter() public {
        vm.prank(admin);
        guard.updateTVL(100 ether);

        guard.validateOperation(user1, address(0), 0.1 ether);
        guard.validateOperation(user1, address(0), 0.1 ether);
        guard.validateOperation(user1, address(0), 0.1 ether);

        // Advance to next block
        vm.roll(block.number + 1);

        // Should succeed again
        bool safe = guard.validateOperation(user1, address(0), 0.1 ether);
        assertTrue(safe);
    }

    function test_ValidateOperation_VelocityLimit() public {
        vm.prank(admin);
        guard.updateTVL(1000 ether);

        // MAX_OPS_PER_EPOCH = 50, MAX_OPS_PER_BLOCK = 3
        // Consume epoch-level operations across multiple blocks
        for (uint256 i = 0; i < 16; i++) {
            vm.roll(block.number + 1);
            guard.validateOperation(user1, address(0), 0.01 ether);
            guard.validateOperation(user1, address(0), 0.01 ether);
            guard.validateOperation(user1, address(0), 0.01 ether);
        }
        // Consumed 48 ops across 16 blocks. Next block:
        vm.roll(block.number + 1);
        guard.validateOperation(user1, address(0), 0.01 ether);
        guard.validateOperation(user1, address(0), 0.01 ether);

        // 50th op should succeed, 51st should fail
        bool safe = guard.validateOperation(user1, address(0), 0.01 ether);
        assertFalse(safe);
    }

    function test_ValidateOperation_TVLDeltaExceeded() public {
        vm.prank(admin);
        guard.updateTVL(100 ether);

        // maxTVLDeltaBps = 500 (5%), so max delta = 5 ether
        // A value of 6 ether should fail
        bool safe = guard.validateOperation(user1, address(0), 6 ether);
        assertFalse(safe);
    }

    function test_ValidateOperation_RevertWhenPaused() public {
        vm.prank(admin);
        guard.pause();
        vm.expectRevert();
        guard.validateOperation(user1, address(0), 1 ether);
    }

    function test_ValidateOperation_WithToken_OracleDown() public {
        // Deploy a reverting oracle
        RevertingOracle badOracle = new RevertingOracle();
        vm.prank(admin);
        guard.whitelistToken(address(0xBEEF), address(badOracle), 500);

        vm.prank(admin);
        guard.updateTVL(100 ether);

        // Should return false when oracle reverts (fail closed)
        bool safe = guard.validateOperation(user1, address(0xBEEF), 1 ether);
        assertFalse(safe);
    }

    // ============= canOperateThisBlock =============

    function test_CanOperateThisBlock_Default() public view {
        assertTrue(guard.canOperateThisBlock(user1));
    }

    function test_CanOperateThisBlock_AfterMaxOps() public {
        vm.prank(admin);
        guard.updateTVL(100 ether);

        guard.validateOperation(user1, address(0), 0.1 ether);
        guard.validateOperation(user1, address(0), 0.1 ether);
        guard.validateOperation(user1, address(0), 0.1 ether);

        assertFalse(guard.canOperateThisBlock(user1));
    }

    // ============= getRemainingOperations =============

    function test_GetRemainingOperations_Fresh() public view {
        assertEq(guard.getRemainingOperations(user1), 50);
    }

    function test_GetRemainingOperations_AfterSome() public {
        vm.prank(admin);
        guard.updateTVL(100 ether);
        guard.validateOperation(user1, address(0), 0.1 ether);
        assertEq(guard.getRemainingOperations(user1), 49);
    }

    function test_GetRemainingOperations_ResetAfterEpoch() public {
        vm.prank(admin);
        guard.updateTVL(100 ether);
        guard.validateOperation(user1, address(0), 0.1 ether);

        // Advance past epoch length (100 blocks)
        vm.roll(block.number + 101);
        assertEq(guard.getRemainingOperations(user1), 50);
    }

    // ============= Admin Functions =============

    function test_WhitelistToken() public {
        address newToken = address(0xCCC);
        address newOracle = address(0xDDD);
        vm.prank(admin);
        guard.whitelistToken(newToken, newOracle, 300);

        (address priceOracle, uint256 maxDev, bool isWhitelisted, , ) = guard
            .tokenConfigs(newToken);
        assertEq(priceOracle, newOracle);
        assertEq(maxDev, 300);
        assertTrue(isWhitelisted);
    }

    function test_WhitelistToken_RevertNotOperator() public {
        vm.prank(user1);
        vm.expectRevert();
        guard.whitelistToken(address(0xCCC), address(0xDDD), 300);
    }

    function test_UpdateTVLDeltaLimit() public {
        vm.prank(admin);
        guard.updateTVLDeltaLimit(1000);
        assertEq(guard.maxTVLDeltaBps(), 1000);
    }

    function test_UpdateTVLDeltaLimit_RevertNotAdmin() public {
        vm.prank(user1);
        vm.expectRevert();
        guard.updateTVLDeltaLimit(1000);
    }

    function test_RegisterProtectedContract() public {
        vm.prank(admin);
        guard.registerProtectedContract(address(0xABC));
        assertTrue(guard.protectedContracts(address(0xABC)));
    }

    function test_UpdateTVL() public {
        vm.prank(admin);
        guard.updateTVL(500 ether);
        assertEq(guard.lastTVL(), 500 ether);
    }

    function test_Pause() public {
        vm.prank(admin);
        guard.pause();
        assertTrue(guard.paused());
    }

    function test_Unpause() public {
        vm.prank(admin);
        guard.pause();
        vm.prank(admin);
        guard.unpause();
        assertFalse(guard.paused());
    }

    function test_Pause_RevertNotGuardian() public {
        vm.prank(user1);
        vm.expectRevert();
        guard.pause();
    }

    // ============= Fuzz =============

    function testFuzz_ValidateOperation_Velocity(uint8 ops) public {
        vm.prank(admin);
        guard.updateTVL(10000 ether);

        uint256 totalOps = bound(ops, 1, 60);
        uint256 successCount;

        for (uint256 i = 0; i < totalOps; i++) {
            // Every 3 ops, advance a block
            if (i > 0 && i % 3 == 0) vm.roll(block.number + 1);
            bool safe = guard.validateOperation(user1, address(0), 0.01 ether);
            if (safe) successCount++;
        }

        // Should have at most MAX_OPS_PER_EPOCH successful ops
        assertLe(successCount, 50);
    }

    function testFuzz_TVLDelta(uint256 tvl, uint256 value) public {
        tvl = bound(tvl, 1 ether, 10000 ether);
        value = bound(value, 0, tvl);

        vm.prank(admin);
        guard.updateTVL(tvl);

        bool safe = guard.validateOperation(user1, address(0), value);

        uint256 maxDelta = (tvl * 500) / 10000; // 5%
        if (value > maxDelta) {
            assertFalse(safe);
        }
        // If value <= maxDelta, it should be safe (first op in block)
    }
}
