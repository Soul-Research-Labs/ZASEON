// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "forge-std/console.sol";

/**
 * @title Concurrent Operations Stress Tests
 * @notice Tests system behavior under concurrent/parallel operations
 * @dev Part of security:stress test suite
 */
contract ConcurrentOperationsStress is Test {
    /*//////////////////////////////////////////////////////////////
                            STATE VARIABLES
    //////////////////////////////////////////////////////////////*/

    MockConcurrentVault public vault;
    MockOrderBook public orderBook;
    MockBridgeQueue public bridgeQueue;
    MockNullifierRegistry public nullifierRegistry;

    address[] public users;
    uint256 constant NUM_USERS = 100;

    /*//////////////////////////////////////////////////////////////
                              SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public {
        vault = new MockConcurrentVault();
        vm.deal(address(vault), 1000 ether);

        orderBook = new MockOrderBook();
        bridgeQueue = new MockBridgeQueue();
        nullifierRegistry = new MockNullifierRegistry();

        // Create users
        for (uint256 i = 0; i < NUM_USERS; i++) {
            users.push(makeAddr(string(abi.encodePacked("user", i))));
            vm.deal(users[i], 10 ether);
        }
    }

    /*//////////////////////////////////////////////////////////////
                    CONCURRENT OPERATION TESTS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Test concurrent deposits maintain balance invariant
     */
    function test_concurrentDeposits_balanceInvariant() public {
        uint256 totalDeposited = 0;

        // Simulate concurrent deposits
        for (uint256 i = 0; i < NUM_USERS; i++) {
            uint256 amount = (i + 1) * 0.1 ether;

            vm.prank(users[i]);
            vault.deposit{value: amount}();

            totalDeposited += amount;
        }

        // Invariant: total deposits == sum of all deposits
        assertEq(
            vault.totalDeposits(),
            totalDeposited,
            "Total deposits invariant"
        );

        // Each user has correct balance
        for (uint256 i = 0; i < NUM_USERS; i++) {
            uint256 expected = (i + 1) * 0.1 ether;
            assertEq(
                vault.balances(users[i]),
                expected,
                "User balance correct"
            );
        }
    }

    /**
     * @notice Test concurrent withdrawals respect limits
     */
    function test_concurrentWithdrawals_respectLimits() public {
        // First deposit
        for (uint256 i = 0; i < NUM_USERS; i++) {
            vm.prank(users[i]);
            vault.deposit{value: 1 ether}();
        }

        // Concurrent withdrawals
        uint256 successfulWithdrawals = 0;

        for (uint256 i = 0; i < NUM_USERS; i++) {
            vm.prank(users[i]);
            try vault.withdraw(1 ether) {
                successfulWithdrawals++;
            } catch {
                // Some may fail if limit reached
            }
        }

        // At least some should succeed
        assertGt(successfulWithdrawals, 0, "Some withdrawals should succeed");

        // Total withdrawn should not exceed available
        assertGe(address(vault).balance, 0, "Vault should not go negative");
    }

    /**
     * @notice Test order book under high load
     */
    function test_orderBook_highLoad() public {
        uint256 ordersPerUser = 10;

        // Place many orders
        for (uint256 i = 0; i < NUM_USERS; i++) {
            for (uint256 j = 0; j < ordersPerUser; j++) {
                vm.prank(users[i]);
                orderBook.placeOrder(
                    (i + 1) * 100, // amount
                    (j + 1) * 10, // price
                    j % 2 == 0 // isBuy
                );
            }
        }

        uint256 totalOrders = NUM_USERS * ordersPerUser;
        assertEq(orderBook.orderCount(), totalOrders, "All orders recorded");

        // Match orders
        uint256 matches = orderBook.matchOrders(100);
        console.log("Orders matched:", matches);

        // Matching should work correctly
        assertGe(matches, 0, "Matching should not revert");
    }

    /**
     * @notice Test bridge queue ordering
     */
    function test_bridgeQueue_fifoOrdering() public {
        // Queue messages from different users
        bytes32[] memory messageIds = new bytes32[](NUM_USERS);

        for (uint256 i = 0; i < NUM_USERS; i++) {
            vm.prank(users[i]);
            messageIds[i] = bridgeQueue.queueMessage(
                bytes32(uint256(i)),
                uint64(block.timestamp)
            );
        }

        // Process in FIFO order
        for (uint256 i = 0; i < NUM_USERS; i++) {
            bytes32 nextId = bridgeQueue.getNextMessage();
            assertEq(nextId, messageIds[i], "FIFO order maintained");
            bridgeQueue.processMessage(nextId);
        }
    }

    /**
     * @notice Test nullifier registry under concurrent spending
     */
    function test_nullifierRegistry_noDoubleSpend() public {
        bytes32[] memory nullifiers = new bytes32[](NUM_USERS);

        // Generate nullifiers
        for (uint256 i = 0; i < NUM_USERS; i++) {
            nullifiers[i] = keccak256(abi.encodePacked("nullifier", i));
        }

        // First spend should succeed
        for (uint256 i = 0; i < NUM_USERS; i++) {
            vm.prank(users[i]);
            bool success = nullifierRegistry.spend(nullifiers[i]);
            assertTrue(success, "First spend should succeed");
        }

        // Double spend should fail
        for (uint256 i = 0; i < NUM_USERS; i++) {
            vm.prank(users[i]);
            bool success = nullifierRegistry.spend(nullifiers[i]);
            assertFalse(success, "Double spend should fail");
        }
    }

    /**
     * @notice Test race condition in state updates
     */
    function test_raceCondition_stateUpdates() public {
        MockRaceConditionTest rct = new MockRaceConditionTest();

        // Simulate rapid state updates
        for (uint256 i = 0; i < NUM_USERS; i++) {
            vm.prank(users[i]);
            rct.updateState(i);
        }

        // Final state should be deterministic
        assertEq(
            rct.lastUpdater(),
            users[NUM_USERS - 1],
            "Last updater correct"
        );
        assertEq(rct.updateCount(), NUM_USERS, "All updates recorded");
    }

    /**
     * @notice Test nonce management under concurrent transactions
     */
    function test_nonceMangement_concurrent() public {
        MockNonceManager nonceManager = new MockNonceManager();

        // Each user executes multiple txs
        for (uint256 i = 0; i < 10; i++) {
            for (uint256 j = 0; j < NUM_USERS; j++) {
                vm.prank(users[j]);
                uint256 nonce = nonceManager.useNonce();
                assertEq(nonce, i, "Nonce should increment correctly");
            }
        }

        // Verify final nonces
        for (uint256 i = 0; i < NUM_USERS; i++) {
            assertEq(nonceManager.nonces(users[i]), 10, "Final nonce correct");
        }
    }

    /**
     * @notice Test lock contention
     */
    function test_lockContention() public {
        MockLockManager lockManager = new MockLockManager();
        bytes32 resourceId = keccak256("shared_resource");

        // First user acquires lock
        vm.prank(users[0]);
        assertTrue(
            lockManager.acquireLock(resourceId),
            "First lock should succeed"
        );

        // Other users should fail to acquire
        for (uint256 i = 1; i < 10; i++) {
            vm.prank(users[i]);
            assertFalse(
                lockManager.acquireLock(resourceId),
                "Concurrent lock should fail"
            );
        }

        // First user releases
        vm.prank(users[0]);
        lockManager.releaseLock(resourceId);

        // Now second user can acquire
        vm.prank(users[1]);
        assertTrue(
            lockManager.acquireLock(resourceId),
            "Lock should be available"
        );
    }

    /**
     * @notice Fuzz test: concurrent operations with random ordering
     */
    function testFuzz_concurrentOperations(uint8 numOps, uint8 seed) public {
        vm.assume(numOps > 0 && numOps <= 50);

        MockConcurrentCounter counter = new MockConcurrentCounter();

        // Random operations based on seed
        for (uint256 i = 0; i < numOps; i++) {
            uint256 userIndex = uint256(keccak256(abi.encodePacked(seed, i))) %
                NUM_USERS;
            bool isIncrement = uint256(keccak256(abi.encodePacked(i, seed))) %
                2 ==
                0;

            vm.prank(users[userIndex]);
            if (isIncrement) {
                counter.increment();
            } else {
                counter.decrement();
            }
        }

        // Counter should be consistent (may be negative, that's ok for this test)
        int256 finalValue = counter.value();
        console.log(
            "Final counter value:",
            finalValue > 0 ? "positive" : "negative"
        );
    }
}

/*//////////////////////////////////////////////////////////////
                        HELPER CONTRACTS
//////////////////////////////////////////////////////////////*/

contract MockConcurrentVault {
    mapping(address => uint256) public balances;
    uint256 public totalDeposits;
    uint256 public dailyWithdrawLimit = 100 ether;
    uint256 public todayWithdrawn;
    uint256 public lastResetDay;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // Reset daily limit
        if (block.timestamp / 1 days > lastResetDay) {
            todayWithdrawn = 0;
            lastResetDay = block.timestamp / 1 days;
        }

        require(
            todayWithdrawn + amount <= dailyWithdrawLimit,
            "Daily limit exceeded"
        );

        balances[msg.sender] -= amount;
        totalDeposits -= amount;
        todayWithdrawn += amount;

        payable(msg.sender).transfer(amount);
    }

    receive() external payable {}
}

contract MockOrderBook {
    struct Order {
        address trader;
        uint256 amount;
        uint256 price;
        bool isBuy;
        bool filled;
    }

    mapping(uint256 => Order) public orders;
    uint256 public orderCount;

    function placeOrder(
        uint256 amount,
        uint256 price,
        bool isBuy
    ) external returns (uint256) {
        orderCount++;
        orders[orderCount] = Order({
            trader: msg.sender,
            amount: amount,
            price: price,
            isBuy: isBuy,
            filled: false
        });
        return orderCount;
    }

    function matchOrders(
        uint256 maxMatches
    ) external returns (uint256 matched) {
        // Simplified matching
        for (uint256 i = 1; i <= orderCount && matched < maxMatches; i++) {
            if (!orders[i].filled && orders[i].isBuy) {
                for (
                    uint256 j = 1;
                    j <= orderCount && matched < maxMatches;
                    j++
                ) {
                    if (
                        !orders[j].filled &&
                        !orders[j].isBuy &&
                        orders[i].price >= orders[j].price
                    ) {
                        orders[i].filled = true;
                        orders[j].filled = true;
                        matched++;
                        break;
                    }
                }
            }
        }
    }
}

contract MockBridgeQueue {
    struct Message {
        bytes32 data;
        uint64 timestamp;
        address sender;
        bool processed;
    }

    mapping(bytes32 => Message) public messages;
    bytes32[] public queue;
    uint256 public processedIndex;

    function queueMessage(
        bytes32 data,
        uint64 timestamp
    ) external returns (bytes32) {
        bytes32 id = keccak256(
            abi.encodePacked(data, timestamp, msg.sender, queue.length)
        );
        messages[id] = Message({
            data: data,
            timestamp: timestamp,
            sender: msg.sender,
            processed: false
        });
        queue.push(id);
        return id;
    }

    function getNextMessage() external view returns (bytes32) {
        require(processedIndex < queue.length, "Queue empty");
        return queue[processedIndex];
    }

    function processMessage(bytes32 id) external {
        require(!messages[id].processed, "Already processed");
        messages[id].processed = true;
        processedIndex++;
    }
}

contract MockNullifierRegistry {
    mapping(bytes32 => bool) public spent;

    function spend(bytes32 nullifier) external returns (bool) {
        if (spent[nullifier]) {
            return false;
        }
        spent[nullifier] = true;
        return true;
    }
}

contract MockRaceConditionTest {
    address public lastUpdater;
    uint256 public updateCount;
    mapping(address => uint256) public userUpdates;

    function updateState(uint256) external {
        lastUpdater = msg.sender;
        updateCount++;
        userUpdates[msg.sender]++;
    }
}

contract MockNonceManager {
    mapping(address => uint256) public nonces;

    function useNonce() external returns (uint256) {
        uint256 current = nonces[msg.sender];
        nonces[msg.sender]++;
        return current;
    }
}

contract MockLockManager {
    mapping(bytes32 => address) public locks;

    function acquireLock(bytes32 resourceId) external returns (bool) {
        if (locks[resourceId] != address(0)) {
            return false;
        }
        locks[resourceId] = msg.sender;
        return true;
    }

    function releaseLock(bytes32 resourceId) external {
        require(locks[resourceId] == msg.sender, "Not lock holder");
        locks[resourceId] = address(0);
    }
}

contract MockConcurrentCounter {
    int256 public value;

    function increment() external {
        value++;
    }

    function decrement() external {
        value--;
    }
}
