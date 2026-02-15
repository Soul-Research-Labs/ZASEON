// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {VerifierRegistryV2} from "../../contracts/verifiers/VerifierRegistryV2.sol";

/// @title VerifierRegistryBridgeTest
/// @notice Tests VerifierRegistryV2's bytes32-to-CircuitType bridge for CrossChainProofHubV3 compatibility
contract VerifierRegistryBridgeTest is Test {
    VerifierRegistryV2 public registry;
    address admin = address(this);

    address constant ADAPTER_A = address(0x2001);
    address constant ADAPTER_B = address(0x2002);

    // Must match VerifierRegistryV2.CircuitType enum
    function setUp() public {
        registry = new VerifierRegistryV2();
    }

    /// @notice getVerifier(bytes32) returns address(0) for unmapped proof types
    function test_GetVerifierUnmapped() public view {
        bytes32 proofType = keccak256("SOME_PROOF");
        assertEq(registry.getVerifier(proofType), address(0));
    }

    /// @notice setProofTypeMapping maps bytes32 to CircuitType
    function test_SetProofTypeMapping() public {
        // Register a verifier for PRIVATE_TRANSFER
        VerifierRegistryV2.CircuitType ct = VerifierRegistryV2
            .CircuitType
            .PRIVATE_TRANSFER;
        registry.registerVerifier(ct, ADAPTER_A, ADAPTER_A, keccak256("hash1"));

        // Map a bytes32 proof type to that CircuitType
        bytes32 proofType = keccak256("PRIVATE_TRANSFER_V1");
        registry.setProofTypeMapping(proofType, ct);

        // Now getVerifier should return the adapter
        assertEq(registry.getVerifier(proofType), ADAPTER_A);
    }

    /// @notice batchSetProofTypeMappings sets multiple mappings
    function test_BatchSetProofTypeMappings() public {
        // Register adapters
        VerifierRegistryV2.CircuitType ct0 = VerifierRegistryV2
            .CircuitType
            .PRIVATE_TRANSFER;
        VerifierRegistryV2.CircuitType ct1 = VerifierRegistryV2
            .CircuitType
            .MERKLE_PROOF;
        registry.registerVerifier(
            ct0,
            ADAPTER_A,
            ADAPTER_A,
            keccak256("hashA")
        );
        registry.registerVerifier(
            ct1,
            ADAPTER_B,
            ADAPTER_B,
            keccak256("hashB")
        );

        bytes32[] memory proofTypes = new bytes32[](2);
        proofTypes[0] = keccak256("TRANSFER_V2");
        proofTypes[1] = keccak256("MERKLE_V3");

        VerifierRegistryV2.CircuitType[]
            memory circuits = new VerifierRegistryV2.CircuitType[](2);
        circuits[0] = ct0;
        circuits[1] = ct1;

        registry.batchSetProofTypeMappings(proofTypes, circuits);

        assertEq(registry.getVerifier(proofTypes[0]), ADAPTER_A);
        assertEq(registry.getVerifier(proofTypes[1]), ADAPTER_B);
    }

    /// @notice getVerifier returns address(0) for deprecated adapter
    function test_GetVerifierDeprecated() public {
        VerifierRegistryV2.CircuitType ct = VerifierRegistryV2
            .CircuitType
            .PRIVATE_TRANSFER;
        registry.registerVerifier(ct, ADAPTER_A, ADAPTER_A, keccak256("hashC"));

        bytes32 proofType = keccak256("TRANSFER_V1");
        registry.setProofTypeMapping(proofType, ct);

        // Deprecate the verifier
        registry.deprecateVerifier(ct, "test deprecation");

        // getVerifier should return address(0) for deprecated
        assertEq(registry.getVerifier(proofType), address(0));
    }

    /// @notice proofTypeMapped tracking
    function test_ProofTypeMappedFlag() public {
        bytes32 proofType = keccak256("TEST");
        assertFalse(registry.proofTypeMapped(proofType));

        registry.setProofTypeMapping(
            proofType,
            VerifierRegistryV2.CircuitType.PRIVATE_TRANSFER
        );
        assertTrue(registry.proofTypeMapped(proofType));
    }
}
