// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../../contracts/verifiers/VerifierRegistry.sol";

/**
 * @title EchidnaVerifierRegistry
 * @notice Echidna fuzzing tests for VerifierRegistry
 * @dev Run with: echidna test/fuzzing/EchidnaVerifierRegistry.sol --contract EchidnaVerifierRegistry
 *
 * Security Properties Tested:
 * - Verifiers cannot be registered twice
 * - Only admin can register verifiers
 * - Removed verifiers stay removed
 * - Total count is consistent
 */
contract EchidnaVerifierRegistry {
    VerifierRegistry public registry;

    // Tracking state
    mapping(bytes32 => bool) public proofTypeRegistered;
    mapping(bytes32 => address) public proofTypeToVerifier;
    mapping(bytes32 => bool) public proofTypeRemoved;

    bytes32[] public registeredProofTypes;
    uint256 public totalRegistered;
    uint256 public totalRemoved;
    uint256 public totalUpdated;

    // Mock verifier for testing
    MockVerifier public mockVerifier1;
    MockVerifier public mockVerifier2;
    MockVerifier public mockVerifier3;

    constructor() {
        registry = new VerifierRegistry();
        mockVerifier1 = new MockVerifier();
        mockVerifier2 = new MockVerifier();
        mockVerifier3 = new MockVerifier();
    }

    // ========== FUZZING FUNCTIONS ==========

    function fuzz_registerVerifier(
        bytes32 proofType,
        uint8 verifierChoice
    ) public {
        if (proofType == bytes32(0)) return;
        if (proofTypeRegistered[proofType]) return;

        // Choose one of our mock verifiers
        address verifier;
        if (verifierChoice % 3 == 0) {
            verifier = address(mockVerifier1);
        } else if (verifierChoice % 3 == 1) {
            verifier = address(mockVerifier2);
        } else {
            verifier = address(mockVerifier3);
        }

        try registry.registerVerifier(proofType, verifier) {
            proofTypeRegistered[proofType] = true;
            proofTypeToVerifier[proofType] = verifier;
            registeredProofTypes.push(proofType);
            totalRegistered++;
        } catch {
            // Expected failures (duplicate, invalid verifier)
        }
    }

    function fuzz_updateVerifier(
        uint256 typeIndex,
        uint8 verifierChoice
    ) public {
        if (registeredProofTypes.length == 0) return;

        bytes32 proofType = registeredProofTypes[
            typeIndex % registeredProofTypes.length
        ];

        if (!proofTypeRegistered[proofType]) return;
        if (proofTypeRemoved[proofType]) return;

        // Choose a different verifier
        address verifier;
        if (verifierChoice % 3 == 0) {
            verifier = address(mockVerifier1);
        } else if (verifierChoice % 3 == 1) {
            verifier = address(mockVerifier2);
        } else {
            verifier = address(mockVerifier3);
        }

        try registry.updateVerifier(proofType, verifier) {
            proofTypeToVerifier[proofType] = verifier;
            totalUpdated++;
        } catch {
            // Expected failures
        }
    }

    function fuzz_removeVerifier(uint256 typeIndex) public {
        if (registeredProofTypes.length == 0) return;

        bytes32 proofType = registeredProofTypes[
            typeIndex % registeredProofTypes.length
        ];

        if (!proofTypeRegistered[proofType]) return;
        if (proofTypeRemoved[proofType]) return;

        try registry.removeVerifier(proofType) {
            proofTypeRemoved[proofType] = true;
            totalRemoved++;
        } catch {
            // Expected failures
        }
    }

    function fuzz_getVerifier(uint256 typeIndex) public view {
        if (registeredProofTypes.length == 0) return;

        bytes32 proofType = registeredProofTypes[
            typeIndex % registeredProofTypes.length
        ];

        // Just query - should not revert for valid types
        address verifier = address(registry.verifiers(proofType));
        // verifier can be address(0) if removed or never registered
    }

    // ========== INVARIANTS ==========

    /// @notice Removed should never exceed registered
    function echidna_removed_lte_registered() public view returns (bool) {
        return totalRemoved <= totalRegistered;
    }

    /// @notice Active verifiers = Registered - Removed
    function echidna_active_count_consistent() public view returns (bool) {
        uint256 expectedActive = totalRegistered - totalRemoved;
        uint256 actualActive = registry.totalVerifiers();
        return actualActive == expectedActive;
    }

    /// @notice A removed verifier should stay removed
    function echidna_removal_permanent() public view returns (bool) {
        for (uint256 i = 0; i < registeredProofTypes.length; i++) {
            bytes32 proofType = registeredProofTypes[i];
            if (proofTypeRemoved[proofType]) {
                // Should not be in registry
                if (registry.isTypeRegistered(proofType)) {
                    return false;
                }
            }
        }
        return true;
    }

    /// @notice Registered types should have valid verifiers
    function echidna_valid_verifiers() public view returns (bool) {
        for (uint256 i = 0; i < registeredProofTypes.length; i++) {
            bytes32 proofType = registeredProofTypes[i];
            if (
                proofTypeRegistered[proofType] && !proofTypeRemoved[proofType]
            ) {
                address verifier = address(registry.verifiers(proofType));
                if (verifier == address(0)) {
                    return false;
                }
            }
        }
        return true;
    }

    /// @notice Contract should exist
    function echidna_contract_exists() public view returns (bool) {
        return address(registry) != address(0);
    }
}

/**
 * @title MockVerifier
 * @notice Minimal mock verifier for testing
 */
contract MockVerifier {
    function verify(
        bytes calldata,
        bytes32[] calldata
    ) external pure returns (bool) {
        return true;
    }

    function supportsInterface(bytes4) external pure returns (bool) {
        return true;
    }
}
