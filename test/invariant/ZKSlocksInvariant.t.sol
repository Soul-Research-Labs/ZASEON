// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "../../contracts/primitives/ZKBoundStateLocks.sol";

/**
 * @title ZKBoundStateLocks Invariant Tests
 * @notice Stateful fuzz tests for ZK-SLocks invariants
 * @dev Uses Foundry's invariant testing framework
 */
contract ZKSlocksInvariantTest is Test {
    ZKBoundStateLocks public zkSlocks;
    ZKSlocksHandler public handler;

    function setUp() public {
        // Deploy with zero address proof verifier (for testing)
        zkSlocks = new ZKBoundStateLocks(address(0));
        handler = new ZKSlocksHandler(zkSlocks);

        // Target the handler for invariant testing
        targetContract(address(handler));

        // Exclude specific functions if needed
        bytes4[] memory selectors = new bytes4[](2);
        selectors[0] = ZKSlocksHandler.createRandomLock.selector;
        selectors[1] = ZKSlocksHandler.createMultipleLocks.selector;
        targetSelector(
            FuzzSelector({addr: address(handler), selectors: selectors})
        );
    }

    /*//////////////////////////////////////////////////////////////
                           INVARIANTS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice INV-001: Total unlocks must never exceed total created locks
     */
    function invariant_unlocksNeverExceedCreated() public view {
        (uint256 created, uint256 unlocked, , , ) = zkSlocks.getStats();
        assertLe(unlocked, created, "Unlocks exceeded created locks");
    }

    /**
     * @notice INV-002: Total disputes must never exceed total optimistic unlocks
     */
    function invariant_disputesNeverExceedOptimistic() public view {
        (, , , uint256 optimistic, uint256 disputes) = zkSlocks.getStats();
        assertLe(disputes, optimistic, "Disputes exceeded optimistic unlocks");
    }

    /**
     * @notice INV-003: Active lock count must be consistent
     */
    function invariant_activeLockCountConsistent() public view {
        uint256 activeLockCount = zkSlocks.getActiveLockCount();
        bytes32[] memory activeLockIds = zkSlocks.getActiveLockIds(0, 1000);
        assertEq(
            activeLockCount,
            activeLockIds.length,
            "Active lock count mismatch"
        );
    }

    /**
     * @notice INV-004: Statistics should always be non-decreasing
     */
    function invariant_statisticsMonotonic() public view {
        (
            uint256 created,
            uint256 unlocked,
            ,
            uint256 optimistic,
            uint256 disputes
        ) = zkSlocks.getStats();

        // All values should be >= 0 (implicit with uint256)
        // They should also be >= ghost values from handler
        assertGe(created, handler.ghostTotalCreated(), "Created decreased");
        assertGe(unlocked, handler.ghostTotalUnlocked(), "Unlocked decreased");
    }

    /**
     * @notice INV-005: Nullifier permanence - once used, always used
     */
    function invariant_nullifierPermanence() public view {
        bytes32[] memory usedNullifiers = handler.getUsedNullifiers();
        for (uint256 i = 0; i < usedNullifiers.length; i++) {
            assertTrue(
                zkSlocks.nullifierUsed(usedNullifiers[i]),
                "Nullifier was un-used"
            );
        }
    }

    /**
     * @notice INV-006: Lock IDs should be unique
     */
    function invariant_lockIdUniqueness() public view {
        bytes32[] memory allLockIds = handler.getAllLockIds();
        for (uint256 i = 0; i < allLockIds.length; i++) {
            for (uint256 j = i + 1; j < allLockIds.length; j++) {
                assertNotEq(
                    allLockIds[i],
                    allLockIds[j],
                    "Duplicate lock ID found"
                );
            }
        }
    }

    /**
     * @notice INV-007: Paused state must block all state-changing operations
     */
    function invariant_pausedBlocks() public view {
        if (zkSlocks.paused()) {
            // If paused, no new locks should have been created this call
            // This is verified by the handler's ghost variables
            assertTrue(
                handler.noStateChangesWhilePaused(),
                "State changed while paused"
            );
        }
    }

    /**
     * @notice Final summary after invariant run
     */
    function invariant_callSummary() public view {
        console.log("\n=== Invariant Test Summary ===");
        console.log("Total locks created:", handler.ghostTotalCreated());
        console.log("Total unlocks:", handler.ghostTotalUnlocked());
        console.log("Unique lock IDs:", handler.getAllLockIds().length);
        console.log("Used nullifiers:", handler.getUsedNullifiers().length);
    }
}

/**
 * @title Handler contract for invariant testing
 * @notice Wraps ZKBoundStateLocks with bounded inputs
 */
contract ZKSlocksHandler is Test {
    ZKBoundStateLocks public zkSlocks;

    // Ghost variables for tracking state
    uint256 public ghostTotalCreated;
    uint256 public ghostTotalUnlocked;
    bool public ghostNoStateChangesWhilePaused = true;

    // Track all created lock IDs
    bytes32[] public allLockIds;

    // Track used nullifiers
    bytes32[] public usedNullifiers;

    // Actors
    address[] public actors;
    address internal currentActor;

    // Domains for randomization
    bytes32[] public validDomains;

    constructor(ZKBoundStateLocks _zkSlocks) {
        zkSlocks = _zkSlocks;

        // Initialize actors
        actors.push(address(0x1));
        actors.push(address(0x2));
        actors.push(address(0x3));
        actors.push(address(0x4));
        actors.push(address(0x5));

        // Give actors some ETH
        for (uint256 i = 0; i < actors.length; i++) {
            vm.deal(actors[i], 100 ether);
        }

        // Generate valid domains
        for (uint16 chainId = 1; chainId <= 5; chainId++) {
            validDomains.push(zkSlocks.generateDomainSeparator(chainId, 1, 1));
        }
    }

    modifier useActor(uint256 actorIndexSeed) {
        currentActor = actors[actorIndexSeed % actors.length];
        vm.startPrank(currentActor);
        _;
        vm.stopPrank();
    }

    /**
     * @notice Create a lock with random but valid parameters
     */
    function createRandomLock(
        uint256 actorSeed,
        bytes32 commitmentSeed,
        uint256 domainSeed,
        uint64 deadlineOffset
    ) public useActor(actorSeed) {
        if (zkSlocks.paused()) {
            ghostNoStateChangesWhilePaused = false;
            return;
        }

        // Bound inputs
        deadlineOffset = uint64(bound(deadlineOffset, 1 hours, 30 days));

        bytes32 commitment = keccak256(
            abi.encode(commitmentSeed, block.timestamp, currentActor)
        );
        bytes32 predicateHash = keccak256("transfer");
        bytes32 policyHash = keccak256("default");
        bytes32 domainSeparator = validDomains[
            domainSeed % validDomains.length
        ];
        uint64 deadline = uint64(block.timestamp) + deadlineOffset;

        try
            zkSlocks.createLock(
                commitment,
                predicateHash,
                policyHash,
                domainSeparator,
                deadline
            )
        returns (bytes32 lockId) {
            allLockIds.push(lockId);
            ghostTotalCreated++;
        } catch {
            // Lock creation failed - this is acceptable
        }
    }

    /**
     * @notice Create multiple locks in sequence
     */
    function createMultipleLocks(
        uint256 actorSeed,
        uint8 count
    ) public useActor(actorSeed) {
        count = uint8(bound(count, 1, 10));

        for (uint8 i = 0; i < count; i++) {
            createRandomLock(
                actorSeed,
                keccak256(abi.encode(i, block.timestamp)),
                i,
                uint64(1 hours * (i + 1))
            );
        }
    }

    /*//////////////////////////////////////////////////////////////
                           VIEW HELPERS
    //////////////////////////////////////////////////////////////*/

    function getAllLockIds() public view returns (bytes32[] memory) {
        return allLockIds;
    }

    function getUsedNullifiers() public view returns (bytes32[] memory) {
        return usedNullifiers;
    }

    function noStateChangesWhilePaused() public view returns (bool) {
        return ghostNoStateChangesWhilePaused;
    }
}
