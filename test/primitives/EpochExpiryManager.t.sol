// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/primitives/EpochExpiryManager.sol";

contract EpochExpiryManagerTest is Test {
    EpochExpiryManager public manager;
    address public admin = address(this);
    address public lockManager = makeAddr("lockManager");

    uint32 constant SRC_CHAIN = 1;
    uint32 constant DST_CHAIN = 42161;

    function setUp() public {
        manager = new EpochExpiryManager(admin);
        manager.grantRole(manager.LOCK_MANAGER_ROLE(), lockManager);
    }

    /*//////////////////////////////////////////////////////////////
                       EPOCH CONFIG TESTS
    //////////////////////////////////////////////////////////////*/

    function test_DefaultConfig() public view {
        (
            uint256 epochDuration,
            uint256 epochsToExpiry,
            uint64 genesis,
            bool configured
        ) = manager.getEpochConfig(SRC_CHAIN, DST_CHAIN);

        assertEq(epochDuration, 1 hours);
        assertEq(epochsToExpiry, 24);
        assertGt(genesis, 0);
        assertFalse(configured); // using defaults
    }

    function test_ConfigureEpoch() public {
        manager.configureEpoch(SRC_CHAIN, DST_CHAIN, 30 minutes, 48);

        (
            uint256 epochDuration,
            uint256 epochsToExpiry,
            ,
            bool configured
        ) = manager.getEpochConfig(SRC_CHAIN, DST_CHAIN);

        assertEq(epochDuration, 30 minutes);
        assertEq(epochsToExpiry, 48);
        assertTrue(configured);
    }

    function test_ConfigureEpoch_InvalidDuration() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                IEpochExpiryManager.InvalidEpochDuration.selector,
                1 minutes
            )
        );
        manager.configureEpoch(SRC_CHAIN, DST_CHAIN, 1 minutes, 24); // below MIN_EPOCH_DURATION
    }

    function test_ConfigureEpoch_InvalidEpochsToExpiry() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                IEpochExpiryManager.InvalidEpochsToExpiry.selector,
                0
            )
        );
        manager.configureEpoch(SRC_CHAIN, DST_CHAIN, 1 hours, 0); // below MIN_EPOCHS_TO_EXPIRY
    }

    /*//////////////////////////////////////////////////////////////
                       LOCK REGISTRATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_RegisterLock() public {
        bytes32 lockId = keccak256("lock1");

        vm.prank(lockManager);
        manager.registerLock(lockId, SRC_CHAIN, DST_CHAIN);

        IEpochExpiryManager.ManagedLock memory lock = manager.getLock(lockId);
        assertEq(lock.lockId, lockId);
        assertEq(lock.locker, lockManager);
        assertEq(lock.sourceChainId, SRC_CHAIN);
        assertEq(lock.destChainId, DST_CHAIN);
        assertFalse(lock.expired);
        assertFalse(lock.reclaimed);
        assertEq(lock.expiryEpoch, lock.createdEpoch + 24); // default 24 epochs
    }

    function test_RegisterLock_DuplicateReverts() public {
        bytes32 lockId = keccak256("lock1");

        vm.prank(lockManager);
        manager.registerLock(lockId, SRC_CHAIN, DST_CHAIN);

        vm.prank(lockManager);
        vm.expectRevert(
            abi.encodeWithSelector(
                IEpochExpiryManager.LockAlreadyManaged.selector,
                lockId
            )
        );
        manager.registerLock(lockId, SRC_CHAIN, DST_CHAIN);
    }

    /*//////////////////////////////////////////////////////////////
                       EXPIRY TESTS
    //////////////////////////////////////////////////////////////*/

    function test_CheckAndExpire_NotExpiredYet() public {
        bytes32 lockId = keccak256("lock1");

        vm.prank(lockManager);
        manager.registerLock(lockId, SRC_CHAIN, DST_CHAIN);

        bool expired = manager.checkAndExpire(lockId);
        assertFalse(expired);
    }

    function test_CheckAndExpire_AfterEpochsElapsed() public {
        bytes32 lockId = keccak256("lock1");

        vm.prank(lockManager);
        manager.registerLock(lockId, SRC_CHAIN, DST_CHAIN);

        // Fast-forward 25 hours (25 epochs with 1-hour default)
        vm.warp(block.timestamp + 25 hours);

        bool expired = manager.checkAndExpire(lockId);
        assertTrue(expired);

        IEpochExpiryManager.ManagedLock memory lock = manager.getLock(lockId);
        assertTrue(lock.expired);
    }

    function test_IsExpired_View() public {
        bytes32 lockId = keccak256("lock1");

        vm.prank(lockManager);
        manager.registerLock(lockId, SRC_CHAIN, DST_CHAIN);

        assertFalse(manager.isExpired(lockId));

        vm.warp(block.timestamp + 25 hours);
        assertTrue(manager.isExpired(lockId));
    }

    /*//////////////////////////////////////////////////////////////
                       RECLAIM TESTS
    //////////////////////////////////////////////////////////////*/

    function test_ReclaimExpired() public {
        bytes32 lockId = keccak256("lock1");

        vm.prank(lockManager);
        manager.registerLock(lockId, SRC_CHAIN, DST_CHAIN);

        vm.warp(block.timestamp + 25 hours);

        vm.prank(lockManager);
        manager.reclaimExpired(lockId);

        IEpochExpiryManager.ManagedLock memory lock = manager.getLock(lockId);
        assertTrue(lock.expired);
        assertTrue(lock.reclaimed);
        assertEq(manager.totalReclaimed(), 1);
    }

    function test_ReclaimExpired_NotExpiredReverts() public {
        bytes32 lockId = keccak256("lock1");

        vm.prank(lockManager);
        manager.registerLock(lockId, SRC_CHAIN, DST_CHAIN);

        vm.prank(lockManager);
        vm.expectRevert(); // LockNotExpired
        manager.reclaimExpired(lockId);
    }

    function test_ReclaimExpired_NotOwnerReverts() public {
        bytes32 lockId = keccak256("lock1");

        vm.prank(lockManager);
        manager.registerLock(lockId, SRC_CHAIN, DST_CHAIN);

        vm.warp(block.timestamp + 25 hours);

        address notOwner = makeAddr("notOwner");
        vm.prank(notOwner);
        vm.expectRevert(
            abi.encodeWithSelector(
                IEpochExpiryManager.NotLockOwner.selector,
                lockId,
                notOwner
            )
        );
        manager.reclaimExpired(lockId);
    }

    function test_ReclaimExpired_DoubleReclaimReverts() public {
        bytes32 lockId = keccak256("lock1");

        vm.prank(lockManager);
        manager.registerLock(lockId, SRC_CHAIN, DST_CHAIN);

        vm.warp(block.timestamp + 25 hours);

        vm.prank(lockManager);
        manager.reclaimExpired(lockId);

        vm.prank(lockManager);
        vm.expectRevert(
            abi.encodeWithSelector(
                IEpochExpiryManager.LockAlreadyReclaimed.selector,
                lockId
            )
        );
        manager.reclaimExpired(lockId);
    }

    /*//////////////////////////////////////////////////////////////
                       BATCH EXPIRY TESTS
    //////////////////////////////////////////////////////////////*/

    function test_BatchExpire() public {
        bytes32 lock1 = keccak256("lock1");
        bytes32 lock2 = keccak256("lock2");
        bytes32 lock3 = keccak256("lock3");

        vm.startPrank(lockManager);
        manager.registerLock(lock1, SRC_CHAIN, DST_CHAIN);
        manager.registerLock(lock2, SRC_CHAIN, DST_CHAIN);
        manager.registerLock(lock3, SRC_CHAIN, DST_CHAIN);
        vm.stopPrank();

        vm.warp(block.timestamp + 25 hours);

        bytes32[] memory lockIds = new bytes32[](3);
        lockIds[0] = lock1;
        lockIds[1] = lock2;
        lockIds[2] = lock3;

        uint256 expired = manager.batchExpire(lockIds);
        assertEq(expired, 3);
        assertEq(manager.totalExpired(), 3);
    }

    /*//////////////////////////////////////////////////////////////
                       EPOCH CALCULATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_GetCurrentEpoch() public {
        uint256 epoch0 = manager.getCurrentEpoch(SRC_CHAIN, DST_CHAIN);

        vm.warp(block.timestamp + 1 hours);
        uint256 epoch1 = manager.getCurrentEpoch(SRC_CHAIN, DST_CHAIN);
        assertEq(epoch1, epoch0 + 1);

        vm.warp(block.timestamp + 5 hours);
        uint256 epoch6 = manager.getCurrentEpoch(SRC_CHAIN, DST_CHAIN);
        assertEq(epoch6, epoch0 + 6);
    }

    function test_CustomEpochDuration() public {
        manager.configureEpoch(SRC_CHAIN, DST_CHAIN, 30 minutes, 10);

        uint256 epoch0 = manager.getCurrentEpoch(SRC_CHAIN, DST_CHAIN);

        vm.warp(block.timestamp + 30 minutes);
        uint256 epoch1 = manager.getCurrentEpoch(SRC_CHAIN, DST_CHAIN);
        assertEq(epoch1, epoch0 + 1);
    }

    /*//////////////////////////////////////////////////////////////
                       FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_ExactExpiryTiming(uint256 timeOffset) public {
        // Ensure time offset is within a reasonable range
        vm.assume(timeOffset < 365 days);

        bytes32 lockId = keccak256(abi.encode("fuzz_lock", timeOffset));

        vm.prank(lockManager);
        manager.registerLock(lockId, SRC_CHAIN, DST_CHAIN);

        IEpochExpiryManager.ManagedLock memory lock = manager.getLock(lockId);

        vm.warp(block.timestamp + timeOffset);

        (uint256 epochDuration, , uint64 genesis, ) = manager.getEpochConfig(
            SRC_CHAIN,
            DST_CHAIN
        );
        uint256 currentEpoch = (block.timestamp - genesis) / epochDuration;

        bool expectedExpired = currentEpoch >= lock.expiryEpoch;
        assertEq(manager.isExpired(lockId), expectedExpired);
    }
}
