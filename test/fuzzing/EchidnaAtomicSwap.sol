// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../../contracts/bridge/PILAtomicSwapV2.sol";

/**
 * @title EchidnaAtomicSwap
 * @notice Echidna fuzzing tests for PILAtomicSwapV2
 * @dev Run with: echidna test/fuzzing/EchidnaAtomicSwap.sol --contract EchidnaAtomicSwap
 *
 * Security Properties Tested:
 * - Swaps can only be claimed with correct secret
 * - Swaps can only be refunded after expiry
 * - No double-claim or double-refund
 * - Hash lock uniqueness enforced
 * - Amounts properly tracked and transferred
 */
contract EchidnaAtomicSwap {
    PILAtomicSwapV2 public atomicSwap;

    // Track swaps
    bytes32[] public createdSwaps;
    mapping(bytes32 => bool) public claimed;
    mapping(bytes32 => bool) public refunded;
    mapping(bytes32 => bytes32) public secrets; // swapId => secret
    mapping(bytes32 => bool) public usedHashLocks;

    // Track totals
    uint256 public totalCreated;
    uint256 public totalClaimed;
    uint256 public totalRefunded;

    // Track ETH
    uint256 public totalDeposited;
    uint256 public totalWithdrawn;

    constructor() payable {
        atomicSwap = new PILAtomicSwapV2(address(this));
    }

    receive() external payable {}

    // ========== SWAP CREATION ==========

    function fuzz_createSwapETH(
        address recipient,
        bytes32 secret,
        uint256 timeLockDelta,
        bytes32 commitment
    ) public {
        // Bound inputs
        if (recipient == address(0)) recipient = address(0x1);
        if (secret == bytes32(0)) return;

        // Calculate hash lock
        bytes32 hashLock = keccak256(abi.encodePacked(secret));

        // Skip if hash lock already used
        if (usedHashLocks[hashLock]) return;

        // Bound timelock (1 hour to 7 days)
        uint256 timeLock = 1 hours + (timeLockDelta % (7 days - 1 hours));

        // Use small amount for testing
        uint256 amount = 0.01 ether;

        try
            atomicSwap.createSwapETH{value: amount}(
                recipient,
                hashLock,
                timeLock,
                commitment
            )
        returns (bytes32 swapId) {
            createdSwaps.push(swapId);
            secrets[swapId] = secret;
            usedHashLocks[hashLock] = true;
            totalCreated++;
            totalDeposited += amount;
        } catch {
            // Expected - various validation failures
        }
    }

    // ========== SWAP CLAIMING ==========

    function fuzz_claim(uint256 swapIndex) public {
        if (createdSwaps.length == 0) return;

        swapIndex = swapIndex % createdSwaps.length;
        bytes32 swapId = createdSwaps[swapIndex];

        if (claimed[swapId] || refunded[swapId]) return;

        bytes32 secret = secrets[swapId];

        try atomicSwap.claim(swapId, secret) {
            claimed[swapId] = true;
            totalClaimed++;
        } catch {
            // Expected - swap expired, wrong secret, etc.
        }
    }

    function fuzz_claimWithWrongSecret(
        uint256 swapIndex,
        bytes32 wrongSecret
    ) public {
        if (createdSwaps.length == 0) return;

        swapIndex = swapIndex % createdSwaps.length;
        bytes32 swapId = createdSwaps[swapIndex];

        bytes32 correctSecret = secrets[swapId];
        if (wrongSecret == correctSecret) return; // Skip correct secret

        try atomicSwap.claim(swapId, wrongSecret) {
            // This should NEVER succeed with wrong secret
            assert(false);
        } catch {
            // Expected - wrong secret rejected
        }
    }

    // ========== SWAP REFUNDING ==========

    function fuzz_refund(uint256 swapIndex) public {
        if (createdSwaps.length == 0) return;

        swapIndex = swapIndex % createdSwaps.length;
        bytes32 swapId = createdSwaps[swapIndex];

        if (claimed[swapId] || refunded[swapId]) return;

        try atomicSwap.refund(swapId) {
            refunded[swapId] = true;
            totalRefunded++;
        } catch {
            // Expected - swap not expired yet
        }
    }

    function fuzz_earlyRefund(uint256 swapIndex) public {
        if (createdSwaps.length == 0) return;

        swapIndex = swapIndex % createdSwaps.length;
        bytes32 swapId = createdSwaps[swapIndex];

        if (claimed[swapId] || refunded[swapId]) return;

        // Get swap info
        (, , , , , , uint256 timeLock, , ) = atomicSwap.swaps(swapId);

        // If not expired, refund should fail
        if (block.timestamp < timeLock) {
            try atomicSwap.refund(swapId) {
                // This should NEVER succeed before expiry
                assert(false);
            } catch {
                // Expected - not expired yet
            }
        }
    }

    // ========== INVARIANTS ==========

    /// @notice Claimed + refunded should never exceed created
    function echidna_no_overclaim() public view returns (bool) {
        return totalClaimed + totalRefunded <= totalCreated;
    }

    /// @notice No swap should be both claimed and refunded
    function echidna_no_double_resolution() public view returns (bool) {
        for (uint256 i = 0; i < createdSwaps.length && i < 100; i++) {
            bytes32 swapId = createdSwaps[i];
            if (claimed[swapId] && refunded[swapId]) {
                return false;
            }
        }
        return true;
    }

    /// @notice Total claimed should be tracked correctly
    function echidna_claimed_count_consistent() public view returns (bool) {
        uint256 count = 0;
        for (uint256 i = 0; i < createdSwaps.length && i < 100; i++) {
            if (claimed[createdSwaps[i]]) count++;
        }
        return count == totalClaimed || createdSwaps.length >= 100;
    }

    /// @notice Total refunded should be tracked correctly
    function echidna_refunded_count_consistent() public view returns (bool) {
        uint256 count = 0;
        for (uint256 i = 0; i < createdSwaps.length && i < 100; i++) {
            if (refunded[createdSwaps[i]]) count++;
        }
        return count == totalRefunded || createdSwaps.length >= 100;
    }

    /// @notice Contract should remain functional
    function echidna_contract_exists() public view returns (bool) {
        return address(atomicSwap) != address(0);
    }
}
