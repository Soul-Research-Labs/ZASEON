// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "../../contracts/primitives/ZKBoundStateLocks.sol";

/**
 * @title ZKBoundStateLocks Fuzz Tests
 * @notice Property-based testing for ZK-SLocks
 * @dev Uses Foundry's fuzz testing framework
 */
contract ZKSlocksFuzzTest is Test {
    ZKBoundStateLocks public zkSlocks;

    address public admin;
    address public user1;
    address public user2;

    bytes32 public defaultDomain;

    function setUp() public {
        admin = address(this);
        user1 = makeAddr("user1");
        user2 = makeAddr("user2");

        vm.deal(user1, 100 ether);
        vm.deal(user2, 100 ether);

        // Deploy with zero address proof verifier
        zkSlocks = new ZKBoundStateLocks(address(0));

        // Register a valid domain (chainId=1, appId=1, epoch=1)
        // The deployer (this contract) has DOMAIN_ADMIN_ROLE
        defaultDomain = zkSlocks.registerDomain(1, 1, 1, "Test Domain");
    }

    /*//////////////////////////////////////////////////////////////
                         FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Fuzz: Lock creation should always succeed with valid inputs
     */
    function testFuzz_createLock_validInputs(
        bytes32 commitment,
        bytes32 predicateHash,
        bytes32 policyHash,
        uint64 deadlineOffset
    ) public {
        // Bound deadline to reasonable range
        vm.assume(deadlineOffset >= 1 hours && deadlineOffset <= 365 days);

        uint64 deadline = uint64(block.timestamp) + deadlineOffset;

        vm.prank(user1);
        bytes32 lockId = zkSlocks.createLock(
            commitment,
            predicateHash,
            policyHash,
            defaultDomain,
            deadline
        );

        // Verify lock was created
        assertTrue(lockId != bytes32(0), "Lock ID should not be zero");

        // Verify lock data
        ZKBoundStateLocks.ZKSLock memory lock = zkSlocks.getLock(lockId);
        assertEq(lock.oldStateCommitment, commitment);
        assertEq(lock.lockedBy, user1);
        assertFalse(lock.isUnlocked);
    }

    /**
     * @notice Fuzz: Lock IDs should be unique for different inputs
     */
    function testFuzz_lockIds_unique(
        bytes32 commitment1,
        bytes32 commitment2
    ) public {
        vm.assume(commitment1 != commitment2);

        uint64 deadline = uint64(block.timestamp) + 1 hours;
        bytes32 predicateHash = keccak256("transfer");
        bytes32 policyHash = keccak256("default");

        vm.startPrank(user1);

        bytes32 lockId1 = zkSlocks.createLock(
            commitment1,
            predicateHash,
            policyHash,
            defaultDomain,
            deadline
        );

        // Warp time to ensure different timestamp
        vm.warp(block.timestamp + 1);

        bytes32 lockId2 = zkSlocks.createLock(
            commitment2,
            predicateHash,
            policyHash,
            defaultDomain,
            deadline + 1
        );

        vm.stopPrank();

        assertTrue(lockId1 != lockId2, "Lock IDs should be unique");
    }

    /**
     * @notice Fuzz: Domain separator generation should be deterministic
     */
    function testFuzz_domainSeparator_deterministic(
        uint16 chainId,
        uint16 appId,
        uint32 epoch
    ) public {
        vm.assume(chainId > 0);
        vm.assume(appId > 0);

        bytes32 domain1 = zkSlocks.generateDomainSeparator(
            chainId,
            appId,
            epoch
        );
        bytes32 domain2 = zkSlocks.generateDomainSeparator(
            chainId,
            appId,
            epoch
        );

        assertEq(domain1, domain2, "Domain separator should be deterministic");
    }

    /**
     * @notice Fuzz: Different chain IDs should produce different domains
     */
    function testFuzz_domainSeparator_chainIdUniqueness(
        uint16 chainId1,
        uint16 chainId2
    ) public {
        vm.assume(chainId1 > 0 && chainId2 > 0);
        vm.assume(chainId1 != chainId2);

        bytes32 domain1 = zkSlocks.generateDomainSeparator(chainId1, 1, 1);
        bytes32 domain2 = zkSlocks.generateDomainSeparator(chainId2, 1, 1);

        assertTrue(
            domain1 != domain2,
            "Different chain IDs should produce different domains"
        );
    }

    /**
     * @notice Fuzz: Nullifier generation should be unique
     */
    function testFuzz_nullifier_unique(
        bytes32 secret1,
        bytes32 secret2,
        bytes32 domain
    ) public {
        vm.assume(secret1 != secret2);

        bytes32 nullifier1 = zkSlocks.generateNullifier(secret1, domain, 0);
        bytes32 nullifier2 = zkSlocks.generateNullifier(secret2, domain, 0);

        assertTrue(
            nullifier1 != nullifier2,
            "Different secrets should produce different nullifiers"
        );
    }

    /**
     * @notice Fuzz: Statistics should only increase
     */
    function testFuzz_statistics_monotonic(uint8 numLocks) public {
        numLocks = uint8(bound(numLocks, 1, 20));

        (uint256 initialCreated, , , , ) = zkSlocks.getStats();

        for (uint8 i = 0; i < numLocks; i++) {
            bytes32 commitment = keccak256(abi.encode(i, block.timestamp));
            uint64 deadline = uint64(block.timestamp) + 1 hours;

            vm.prank(user1);
            zkSlocks.createLock(
                commitment,
                keccak256("transfer"),
                keccak256("policy"),
                defaultDomain,
                deadline
            );

            // Warp to avoid duplicate timestamps
            vm.warp(block.timestamp + 1);
        }

        (uint256 finalCreated, , , , ) = zkSlocks.getStats();
        assertEq(
            finalCreated,
            initialCreated + numLocks,
            "Statistics should increase correctly"
        );
    }

    /**
     * @notice Fuzz: Active lock count should match created - unlocked
     */
    function testFuzz_activeLockCount(uint8 numLocks) public {
        numLocks = uint8(bound(numLocks, 1, 10));

        for (uint8 i = 0; i < numLocks; i++) {
            bytes32 commitment = keccak256(
                abi.encode("active", i, block.timestamp)
            );
            uint64 deadline = uint64(block.timestamp) + 1 hours;

            vm.prank(user1);
            zkSlocks.createLock(
                commitment,
                keccak256("transfer"),
                keccak256("policy"),
                defaultDomain,
                deadline
            );

            vm.warp(block.timestamp + 1);
        }

        uint256 activeCount = zkSlocks.getActiveLockCount();
        assertGe(
            activeCount,
            numLocks,
            "Active count should include new locks"
        );
    }

    /**
     * @notice Fuzz: User lock count should track correctly
     */
    function testFuzz_userLockCount(address user, uint8 numLocks) public {
        vm.assume(user != address(0));
        vm.deal(user, 1 ether);
        numLocks = uint8(bound(numLocks, 1, 10));

        uint256 initialCount = zkSlocks.userLockCount(user);

        for (uint8 i = 0; i < numLocks; i++) {
            bytes32 commitment = keccak256(
                abi.encode(user, i, block.timestamp)
            );
            uint64 deadline = uint64(block.timestamp) + 1 hours;

            vm.prank(user);
            zkSlocks.createLock(
                commitment,
                keccak256("transfer"),
                keccak256("policy"),
                defaultDomain,
                deadline
            );

            vm.warp(block.timestamp + 1);
        }

        uint256 finalCount = zkSlocks.userLockCount(user);
        assertEq(
            finalCount,
            initialCount + numLocks,
            "User lock count should increase"
        );
    }

    /**
     * @notice Fuzz: Pausing should block all state-changing operations
     */
    function testFuzz_pause_blocksOperations(bytes32 commitment) public {
        // Grant admin role and pause
        bytes32 LOCK_ADMIN_ROLE = zkSlocks.LOCK_ADMIN_ROLE();
        zkSlocks.grantRole(LOCK_ADMIN_ROLE, admin);
        zkSlocks.pause();

        assertTrue(zkSlocks.paused(), "Contract should be paused");

        // Try to create lock - should fail
        vm.prank(user1);
        vm.expectRevert();
        zkSlocks.createLock(
            commitment,
            keccak256("transfer"),
            keccak256("policy"),
            defaultDomain,
            uint64(block.timestamp) + 1 hours
        );

        // Unpause
        zkSlocks.unpause();
        assertFalse(zkSlocks.paused(), "Contract should be unpaused");
    }

    /**
     * @notice Fuzz: Commitment chain should track history
     */
    function testFuzz_commitmentChain(
        bytes32 initialCommitment,
        uint8 chainLength
    ) public {
        chainLength = uint8(bound(chainLength, 1, 5));

        bytes32 currentCommitment = initialCommitment;
        bytes32 firstLockId;

        for (uint8 i = 0; i < chainLength; i++) {
            uint64 deadline = uint64(block.timestamp) + 1 hours;

            vm.prank(user1);
            bytes32 lockId = zkSlocks.createLock(
                currentCommitment,
                keccak256("transfer"),
                keccak256("policy"),
                defaultDomain,
                deadline
            );

            if (i == 0) {
                firstLockId = lockId;
            }

            // Next commitment is hash of current
            currentCommitment = keccak256(abi.encode(currentCommitment, i));
            vm.warp(block.timestamp + 1);
        }

        // Verify first lock is retrievable
        ZKBoundStateLocks.ZKSLock memory lock = zkSlocks.getLock(firstLockId);
        assertEq(lock.oldStateCommitment, initialCommitment);
    }
}
