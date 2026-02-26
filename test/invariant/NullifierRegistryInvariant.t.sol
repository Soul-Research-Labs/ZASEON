// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "forge-std/StdInvariant.sol";
import "../../contracts/core/NullifierRegistryV3.sol";

/**
 * @title NullifierRegistryInvariant
 * @notice Invariant tests for NullifierRegistryV3
 * @dev Ensures:
 *  - Nullifier monotonicity: once used, always used
 *  - Total count == sum of per-chain counts
 *  - No duplicate registrations accepted
 *  - Merkle root always valid after insertions
 *  - Index assignments are strictly sequential
 *
 * Run with: forge test --match-contract NullifierRegistryInvariant -vvv
 */
contract NullifierRegistryInvariant is StdInvariant, Test {
    NullifierRegistryV3 public registry;
    NullifierRegistryHandler public handler;

    function setUp() public {
        registry = new NullifierRegistryV3();
        handler = new NullifierRegistryHandler(registry);
        targetContract(address(handler));
    }

    /// @notice Once a nullifier is used, it must stay used forever
    function invariant_nullifierPermanence() public view {
        bytes32[] memory registered = handler.ghost_registeredNullifiers();
        for (uint256 i = 0; i < registered.length; i++) {
            assertTrue(
                registry.isNullifierUsed(registered[i]),
                "Registered nullifier became unused"
            );
        }
    }

    /// @notice totalNullifiers must equal the number of unique registered nullifiers
    function invariant_totalCountAccurate() public view {
        assertEq(
            registry.totalNullifiers(),
            handler.ghost_uniqueCount(),
            "Total nullifiers count mismatch"
        );
    }

    /// @notice totalNullifiers >= chainNullifierCount for this chain
    function invariant_chainCountBound() public view {
        assertGe(
            registry.totalNullifiers(),
            registry.chainNullifierCount(block.chainid),
            "Chain count exceeds total"
        );
    }

    /// @notice No duplicate nullifier registrations should succeed
    function invariant_noDuplicates() public view {
        assertEq(
            handler.ghost_duplicateAccepted(),
            0,
            "Duplicate nullifier was accepted"
        );
    }

    /// @notice Current merkle root should be in historical roots
    function invariant_currentRootIsHistorical() public view {
        if (registry.totalNullifiers() > 0) {
            assertTrue(
                registry.historicalRoots(registry.merkleRoot()),
                "Current root not in history"
            );
        }
    }

    /// @notice Indices must be strictly sequential (0, 1, 2, ...)
    function invariant_sequentialIndices() public view {
        bytes32[] memory registered = handler.ghost_registeredNullifiers();
        for (uint256 i = 0; i < registered.length; i++) {
            INullifierRegistryV3.NullifierData memory data = registry
                .getNullifierData(registered[i]);
            assertEq(data.index, i, "Non-sequential index assignment");
        }
    }

    /// @notice totalNullifiers is monotonically increasing
    function invariant_totalMonotonic() public view {
        assertGe(
            registry.totalNullifiers(),
            handler.ghost_previousTotal(),
            "totalNullifiers decreased"
        );
    }
}

/**
 * @title NullifierRegistryHandler
 * @notice Fuzzable handler for NullifierRegistryV3 invariant testing
 */
contract NullifierRegistryHandler is Test {
    NullifierRegistryV3 public registry;

    // Ghost tracking
    bytes32[] private _registeredNullifiers;
    uint256 public ghost_uniqueCount;
    uint256 public ghost_duplicateAccepted;
    uint256 public ghost_previousTotal;

    uint256 private _nonce;

    constructor(NullifierRegistryV3 _registry) {
        registry = _registry;
    }

    function ghost_registeredNullifiers()
        external
        view
        returns (bytes32[] memory)
    {
        return _registeredNullifiers;
    }

    /// @notice Register a single nullifier
    function registerNullifier(uint256 seed) external {
        bytes32 nullifier = keccak256(abi.encodePacked("nullifier", _nonce));
        bytes32 commitment = keccak256(abi.encodePacked("commitment", _nonce));
        _nonce++;

        ghost_previousTotal = registry.totalNullifiers();

        try registry.registerNullifier(nullifier, commitment) returns (
            uint256
        ) {
            _registeredNullifiers.push(nullifier);
            ghost_uniqueCount++;
        } catch {
            // Expected for various reasons (paused, etc.)
        }
    }

    /// @notice Register a batch of nullifiers
    function batchRegister(uint8 countSeed) external {
        uint256 count = bound(uint256(countSeed), 1, 10);

        bytes32[] memory nullifierArr = new bytes32[](count);
        bytes32[] memory commitmentArr = new bytes32[](count);

        for (uint256 i = 0; i < count; i++) {
            nullifierArr[i] = keccak256(
                abi.encodePacked("batch_nullifier", _nonce, i)
            );
            commitmentArr[i] = keccak256(
                abi.encodePacked("batch_commitment", _nonce, i)
            );
        }
        _nonce++;

        ghost_previousTotal = registry.totalNullifiers();

        try
            registry.batchRegisterNullifiers(nullifierArr, commitmentArr)
        returns (uint256) {
            for (uint256 i = 0; i < count; i++) {
                _registeredNullifiers.push(nullifierArr[i]);
                ghost_uniqueCount++;
            }
        } catch {
            // Expected if batch too large, paused, etc.
        }
    }

    /// @notice Attempt to register a duplicate nullifier (should always fail)
    function registerDuplicate(uint256 indexSeed) external {
        if (_registeredNullifiers.length == 0) return;

        uint256 idx = bound(indexSeed, 0, _registeredNullifiers.length - 1);
        bytes32 existingNullifier = _registeredNullifiers[idx];
        bytes32 commitment = keccak256(abi.encodePacked("dup", indexSeed));

        ghost_previousTotal = registry.totalNullifiers();

        try registry.registerNullifier(existingNullifier, commitment) {
            // This should never succeed
            ghost_duplicateAccepted++;
        } catch {
            // Good — duplicate rejected
        }
    }

    /// @notice Verify a random nullifier's existence
    function checkExists(uint256 indexSeed) external view {
        if (_registeredNullifiers.length == 0) return;

        uint256 idx = bound(indexSeed, 0, _registeredNullifiers.length - 1);
        // Should always be true for registered nullifiers
        assert(registry.isNullifierUsed(_registeredNullifiers[idx]));
    }
}
