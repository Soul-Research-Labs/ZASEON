// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../../contracts/primitives/CrossDomainNullifierAlgebra.sol";

/**
 * @title EchidnaIntegration
 * @notice Integration fuzzing tests for PIL v2 cross-domain nullifier algebra
 * @dev Run with: echidna test/fuzzing/EchidnaIntegration.sol --contract EchidnaIntegration
 *
 * Security Properties Tested:
 * - Cross-domain nullifier uniqueness
 * - Nullifier computation determinism
 * - Domain isolation
 */
contract EchidnaIntegration {
    CrossDomainNullifierAlgebra public cdna;

    // Track domains and nullifiers
    bytes32[] public domainSeparators;
    bytes32[] public computedNullifiers;

    mapping(bytes32 => bool) public usedSeparators;
    mapping(bytes32 => bool) public usedNullifiers;

    uint256 public totalSeparators;
    uint256 public totalNullifiers;

    constructor() {
        cdna = new CrossDomainNullifierAlgebra();
    }

    // ========== DOMAIN SEPARATOR COMPUTATION ==========

    function fuzz_computeDomainSeparator(
        uint64 chainId,
        bytes32 appId,
        uint64 epochId
    ) public {
        if (chainId == 0 || appId == bytes32(0)) return;

        bytes32 separator = cdna.computeDomainSeparator(
            chainId,
            appId,
            epochId
        );

        if (!usedSeparators[separator]) {
            usedSeparators[separator] = true;
            domainSeparators.push(separator);
            totalSeparators++;
        }
    }

    // ========== NULLIFIER COMPUTATION ==========

    function fuzz_computeNullifier(
        bytes32 secret,
        bytes32 domainSeparator,
        bytes32 transitionId
    ) public {
        if (secret == bytes32(0) || domainSeparator == bytes32(0)) return;

        bytes32 nullifier = cdna.computeNullifier(
            secret,
            domainSeparator,
            transitionId
        );

        if (!usedNullifiers[nullifier]) {
            usedNullifiers[nullifier] = true;
            computedNullifiers.push(nullifier);
            totalNullifiers++;
        }
    }

    function fuzz_crossDomainComputation(
        bytes32 secret,
        uint64 chainId1,
        uint64 chainId2,
        bytes32 appId,
        bytes32 transitionId
    ) public {
        if (secret == bytes32(0) || appId == bytes32(0)) return;
        if (chainId1 == 0 || chainId2 == 0) return;

        bytes32 separator1 = cdna.computeDomainSeparator(chainId1, appId, 1);
        bytes32 separator2 = cdna.computeDomainSeparator(chainId2, appId, 1);

        bytes32 nullifier1 = cdna.computeNullifier(
            secret,
            separator1,
            transitionId
        );
        bytes32 nullifier2 = cdna.computeNullifier(
            secret,
            separator2,
            transitionId
        );

        // Different chains should produce different nullifiers
        if (chainId1 != chainId2) {
            assert(separator1 != separator2);
            assert(nullifier1 != nullifier2);
        } else {
            // Same chain should produce same results
            assert(separator1 == separator2);
            assert(nullifier1 == nullifier2);
        }
    }

    function fuzz_nullifierDeterminism(
        bytes32 secret,
        bytes32 separator,
        bytes32 transitionId
    ) public {
        if (secret == bytes32(0) || separator == bytes32(0)) return;

        // Computation should be deterministic
        bytes32 first = cdna.computeNullifier(secret, separator, transitionId);
        bytes32 second = cdna.computeNullifier(secret, separator, transitionId);

        assert(first == second);
    }

    function fuzz_separatorDeterminism(
        uint64 chainId,
        bytes32 appId,
        uint64 epochId
    ) public {
        if (chainId == 0 || appId == bytes32(0)) return;

        bytes32 first = cdna.computeDomainSeparator(chainId, appId, epochId);
        bytes32 second = cdna.computeDomainSeparator(chainId, appId, epochId);

        assert(first == second);
    }

    // ========== INVARIANTS ==========

    /// @notice CDNA should remain functional
    function echidna_cdna_exists() public view returns (bool) {
        return address(cdna) != address(0);
    }

    /// @notice Domain separator computation is deterministic
    function echidna_separator_determinism() public view returns (bool) {
        bytes32 sep1 = cdna.computeDomainSeparator(1, keccak256("test"), 1);
        bytes32 sep2 = cdna.computeDomainSeparator(1, keccak256("test"), 1);
        return sep1 == sep2;
    }

    /// @notice Nullifier computation is deterministic
    function echidna_nullifier_determinism() public view returns (bool) {
        bytes32 sep = cdna.computeDomainSeparator(1, keccak256("test"), 1);
        bytes32 nul1 = cdna.computeNullifier(
            keccak256("secret"),
            sep,
            keccak256("tx1")
        );
        bytes32 nul2 = cdna.computeNullifier(
            keccak256("secret"),
            sep,
            keccak256("tx1")
        );
        return nul1 == nul2;
    }

    /// @notice Different inputs produce different outputs
    function echidna_input_sensitivity() public view returns (bool) {
        bytes32 sep1 = cdna.computeDomainSeparator(1, keccak256("test"), 1);
        bytes32 sep2 = cdna.computeDomainSeparator(2, keccak256("test"), 1);
        return sep1 != sep2;
    }

    /// @notice Counting works correctly
    function echidna_counts_consistent() public view returns (bool) {
        return
            totalSeparators == domainSeparators.length &&
            totalNullifiers == computedNullifiers.length;
    }
}
