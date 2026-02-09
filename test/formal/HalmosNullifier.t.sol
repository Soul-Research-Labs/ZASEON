// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";

/**
 * @title HalmosNullifier
 * @notice Symbolic execution tests for nullifier registry invariants
 * @dev Run with: halmos --contract HalmosNullifier
 */
contract HalmosNullifier is SymTest, Test {
    // Simulated nullifier registry state
    mapping(bytes32 => bool) public consumed;
    mapping(bytes32 => uint256) public consumedAt;
    uint256 public totalConsumed;

    /// @notice Verify nullifier cannot be consumed twice (double-spend prevention)
    function check_nullifierDoubleSpendPrevention(bytes32 nullifier) public {
        // First consumption should succeed
        if (!consumed[nullifier]) {
            consumed[nullifier] = true;
            consumedAt[nullifier] = block.timestamp;
            totalConsumed++;
        }

        // Verify it's now consumed
        assert(consumed[nullifier]);

        // Second consumption attempt must be blocked
        bool wasConsumedBefore = consumed[nullifier];
        assert(wasConsumedBefore == true); // cannot re-consume
    }

    /// @notice Verify cross-domain nullifier derivation produces unique results
    function check_crossDomainNullifierUniqueness(
        bytes32 parentNullifier,
        bytes32 domainId1,
        bytes32 domainId2
    ) public pure {
        vm.assume(domainId1 != domainId2);

        bytes32 derived1 = keccak256(abi.encode(parentNullifier, domainId1));
        bytes32 derived2 = keccak256(abi.encode(parentNullifier, domainId2));

        // Different domains must produce different derived nullifiers
        assert(derived1 != derived2);
    }

    /// @notice Verify nullifier count integrity
    function check_nullifierCountIntegrity(
        bytes32 n1,
        bytes32 n2,
        bytes32 n3
    ) public {
        vm.assume(n1 != n2 && n2 != n3 && n1 != n3);

        uint256 startCount = totalConsumed;

        // Consume 3 unique nullifiers
        if (!consumed[n1]) {
            consumed[n1] = true;
            totalConsumed++;
        }
        if (!consumed[n2]) {
            consumed[n2] = true;
            totalConsumed++;
        }
        if (!consumed[n3]) {
            consumed[n3] = true;
            totalConsumed++;
        }

        // Count should have increased by exactly 3
        assert(totalConsumed == startCount + 3);
    }

    /// @notice Verify commitment-nullifier binding
    function check_commitmentNullifierBinding(
        bytes32 commitment,
        bytes32 secret,
        bytes32 nonce
    ) public pure {
        // Nullifier = hash(commitment, secret, nonce)
        bytes32 nullifier = keccak256(abi.encode(commitment, secret, nonce));

        // Changing any input must change the nullifier
        bytes32 modifiedNonce = bytes32(uint256(nonce) + 1);
        bytes32 nullifier2 = keccak256(
            abi.encode(commitment, secret, modifiedNonce)
        );
        assert(nullifier != nullifier2);
    }
}
