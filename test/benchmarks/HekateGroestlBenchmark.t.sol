// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "../../contracts/verifiers/HekateGroestlVerifier.sol";

/// @title Hekate-Groestl Benchmark Tests
/// @notice Gas benchmarks comparing Hekate-Groestl vs keccak256 for ZK verification
contract HekateGroestlBenchmark is Test {
    HekateGroestlVerifier public verifier;

    uint256 constant ITERATIONS = 100;

    function setUp() public {
        // Constructor: (address _admin, address _noirVerifier)
        verifier = new HekateGroestlVerifier(address(this), address(0));
        // Disable strict mode for testing without a real verifier
        verifier.setStrictMode(false);
    }

    /// @notice Benchmark proof verification gas costs
    function testBenchmark_verifyProof() public view {
        bytes memory proof = abi.encodePacked(
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            bytes32(uint256(3)),
            bytes32(uint256(4)),
            bytes32(uint256(5)),
            bytes32(uint256(6)),
            bytes32(uint256(7)),
            bytes32(uint256(8))
        );

        // Public inputs: inputHash, outputHash (packed as bytes)
        bytes memory publicInputs = abi.encodePacked(
            bytes32(uint256(1)),
            bytes32(uint256(2))
        );

        console.log("=== Hekate-Groestl verifyProof Benchmark ===");
        console.log("Iterations: %d", ITERATIONS);

        uint256 gasStart = gasleft();
        for (uint256 i = 0; i < ITERATIONS; i++) {
            verifier.verifyProof(proof, publicInputs);
        }
        uint256 gasUsed = gasStart - gasleft();

        console.log("Total gas: %d", gasUsed);
        console.log("Avg gas per verify: %d", gasUsed / ITERATIONS);
    }

    /// @notice Benchmark merkle proof verification
    function testBenchmark_verifyMerkleProof() public view {
        bytes32 leaf = keccak256(abi.encodePacked("test_leaf"));
        bytes32[] memory proof = new bytes32[](8);
        bool[] memory indices = new bool[](8);

        for (uint256 i = 0; i < 8; i++) {
            proof[i] = keccak256(abi.encodePacked("sibling", i));
            indices[i] = i % 2 == 0;
        }

        bytes32 root = leaf;
        for (uint256 i = 0; i < 8; i++) {
            if (indices[i]) {
                root = keccak256(abi.encodePacked(root, proof[i]));
            } else {
                root = keccak256(abi.encodePacked(proof[i], root));
            }
        }

        console.log("=== Hekate-Groestl verifyMerkleProof Benchmark ===");
        console.log("Depth: 8");
        console.log("Iterations: %d", ITERATIONS);

        uint256 gasStart = gasleft();
        for (uint256 i = 0; i < ITERATIONS; i++) {
            verifier.verifyMerkleProof(leaf, proof, indices, root);
        }
        uint256 gasUsed = gasStart - gasleft();

        console.log("Total gas: %d", gasUsed);
        console.log("Avg gas per merkle verify: %d", gasUsed / ITERATIONS);
    }

    /// @notice Benchmark batch verification using the verify function with uint256[] inputs
    function testBenchmark_batchVerify() public view {
        uint256 batchSize = 10;

        console.log("=== Hekate-Groestl Batch Verify Benchmark ===");
        console.log("Batch size: %d", batchSize);
        console.log("Iterations: %d", ITERATIONS / 10);

        uint256 gasStart = gasleft();
        for (uint256 iter = 0; iter < ITERATIONS / 10; iter++) {
            for (uint256 i = 0; i < batchSize; i++) {
                bytes memory proof = abi.encodePacked(
                    bytes32(uint256(i + 1)),
                    bytes32(uint256(i + 2)),
                    bytes32(uint256(i + 3)),
                    bytes32(uint256(i + 4)),
                    bytes32(uint256(i + 5)),
                    bytes32(uint256(i + 6)),
                    bytes32(uint256(i + 7)),
                    bytes32(uint256(i + 8))
                );

                uint256[] memory inputs = new uint256[](2);
                inputs[0] = i + 1;
                inputs[1] = i + 2;

                verifier.verify(proof, inputs);
            }
        }
        uint256 gasUsed = gasStart - gasleft();

        console.log("Total gas: %d", gasUsed);
        console.log("Avg gas per batch: %d", gasUsed / (ITERATIONS / 10));
        console.log(
            "Avg gas per proof: %d",
            gasUsed / (ITERATIONS / 10) / batchSize
        );
    }

    /// @notice Compare against keccak256 baseline
    function testBenchmark_keccak256Baseline() public view {
        bytes32 input = bytes32(uint256(12345));

        console.log("=== keccak256 Baseline Benchmark ===");
        console.log("Iterations: %d", ITERATIONS * 10);

        uint256 gasStart = gasleft();
        bytes32 result;
        for (uint256 i = 0; i < ITERATIONS * 10; i++) {
            result = keccak256(abi.encodePacked(input, i));
        }
        uint256 gasUsed = gasStart - gasleft();

        // Use result to prevent optimization
        require(result != bytes32(0) || result == bytes32(0), "benchmark");

        console.log("Total gas: %d", gasUsed);
        console.log("Avg gas per hash: %d", gasUsed / (ITERATIONS * 10));
    }

    /// @notice Benchmark with varying proof sizes
    function testBenchmark_varyingProofSizes() public view {
        bytes memory publicInputs = abi.encodePacked(
            bytes32(uint256(1)),
            bytes32(uint256(2))
        );

        console.log("=== Varying Proof Sizes Benchmark ===");

        uint256[4] memory sizes = [
            uint256(256),
            uint256(512),
            uint256(1024),
            uint256(2048)
        ];

        for (uint256 s = 0; s < 4; s++) {
            bytes memory proof = new bytes(sizes[s]);
            for (uint256 i = 0; i < sizes[s]; i++) {
                proof[i] = bytes1(uint8(i % 256));
            }

            uint256 gasStart = gasleft();
            for (uint256 i = 0; i < 10; i++) {
                verifier.verifyProof(proof, publicInputs);
            }
            uint256 gasUsed = gasStart - gasleft();

            console.log("Size %d bytes - Avg gas: %d", sizes[s], gasUsed / 10);
        }
    }

    /// @notice Benchmark stats tracking overhead
    function testBenchmark_statsOverhead() public {
        bytes memory proof = abi.encodePacked(
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            bytes32(uint256(3)),
            bytes32(uint256(4)),
            bytes32(uint256(5)),
            bytes32(uint256(6)),
            bytes32(uint256(7)),
            bytes32(uint256(8))
        );

        bytes memory publicInputs = abi.encodePacked(
            bytes32(uint256(1)),
            bytes32(uint256(2))
        );

        console.log("=== Stats Tracking Overhead Benchmark ===");

        uint256 gasStart = gasleft();
        for (uint256 i = 0; i < ITERATIONS; i++) {
            verifier.verifyProof(proof, publicInputs);
        }
        uint256 viewOnlyGas = gasStart - gasleft();

        gasStart = gasleft();
        for (uint256 i = 0; i < ITERATIONS; i++) {
            verifier.verifyAndRecord(proof, publicInputs);
        }
        uint256 stateChangingGas = gasStart - gasleft();

        console.log("View-only verifyProof avg: %d", viewOnlyGas / ITERATIONS);
        console.log(
            "State-changing verifyAndRecord avg: %d",
            stateChangingGas / ITERATIONS
        );
        console.log(
            "Stats overhead per call: %d",
            (stateChangingGas - viewOnlyGas) / ITERATIONS
        );
    }
}

/// @title Hekate-Groestl Integration Tests
/// @notice Unit tests for HekateGroestlVerifier functionality
contract HekateGroestlIntegrationTest is Test {
    HekateGroestlVerifier public verifier;

    event ProofVerified(bytes32 indexed proofHash, bool valid, uint256 gasUsed);

    function setUp() public {
        verifier = new HekateGroestlVerifier(address(this), address(0));
        verifier.setStrictMode(false);
    }

    function testVerify_basicProof() public view {
        bytes memory proof = abi.encodePacked(
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            bytes32(uint256(3)),
            bytes32(uint256(4)),
            bytes32(uint256(5)),
            bytes32(uint256(6)),
            bytes32(uint256(7)),
            bytes32(uint256(8))
        );

        bytes memory publicInputs = abi.encodePacked(
            bytes32(uint256(1)),
            bytes32(uint256(2))
        );

        bool result = verifier.verifyProof(proof, publicInputs);
        assertTrue(result, "Basic proof should verify");
    }

    function testVerify_emptyProof() public view {
        bytes memory shortProof = "";

        bytes memory publicInputs = abi.encodePacked(
            bytes32(uint256(1)),
            bytes32(uint256(2))
        );

        // Empty proof should return false (not revert in view function)
        bool result = verifier.verifyProof(shortProof, publicInputs);
        assertFalse(result);
    }

    function testVerify_emptyPublicInputs() public view {
        bytes memory proof = abi.encodePacked(
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            bytes32(uint256(3)),
            bytes32(uint256(4)),
            bytes32(uint256(5)),
            bytes32(uint256(6)),
            bytes32(uint256(7)),
            bytes32(uint256(8))
        );

        bytes memory publicInputs = "";
        bool result = verifier.verifyProof(proof, publicInputs);
        assertFalse(result);
    }

    function testVerifyMerkle_validProof() public view {
        bytes32 leaf = keccak256(abi.encodePacked("test"));
        bytes32 sibling = keccak256(abi.encodePacked("sibling"));

        bytes32 root = keccak256(abi.encodePacked(leaf, sibling));

        bytes32[] memory proof = new bytes32[](1);
        proof[0] = sibling;

        bool[] memory indices = new bool[](1);
        indices[0] = true;

        bool result = verifier.verifyMerkleProof(leaf, proof, indices, root);
        assertTrue(result, "Valid merkle proof should verify");
    }

    function testVerifyMerkle_invalidRoot() public view {
        bytes32 leaf = keccak256(abi.encodePacked("test"));
        bytes32 sibling = keccak256(abi.encodePacked("sibling"));

        bytes32 wrongRoot = keccak256(abi.encodePacked("wrong"));

        bytes32[] memory proof = new bytes32[](1);
        proof[0] = sibling;

        bool[] memory indices = new bool[](1);
        indices[0] = true;

        bool result = verifier.verifyMerkleProof(
            leaf,
            proof,
            indices,
            wrongRoot
        );
        assertFalse(result, "Invalid root should fail");
    }

    function testBatchVerify_multipleProofs() public view {
        uint256 batchSize = 5;

        for (uint256 i = 0; i < batchSize; i++) {
            bytes memory proof = abi.encodePacked(
                bytes32(uint256(i * 8 + 1)),
                bytes32(uint256(i * 8 + 2)),
                bytes32(uint256(i * 8 + 3)),
                bytes32(uint256(i * 8 + 4)),
                bytes32(uint256(i * 8 + 5)),
                bytes32(uint256(i * 8 + 6)),
                bytes32(uint256(i * 8 + 7)),
                bytes32(uint256(i * 8 + 8))
            );

            uint256[] memory inputs = new uint256[](2);
            inputs[0] = i + 1;
            inputs[1] = i + 2;

            bool result = verifier.verify(proof, inputs);
            assertTrue(result, "Each proof should verify");
        }
    }

    function testSetNoirVerifier() public {
        address newVerifier = address(0x1234);

        verifier.setNoirVerifier(newVerifier);

        (, address noirAddr, ) = verifier.getStats();
        assertEq(noirAddr, newVerifier);
    }

    function testSetStrictMode() public {
        verifier.setStrictMode(true);

        (, , bool strict) = verifier.getStats();
        assertTrue(strict);

        verifier.setStrictMode(false);
        (, , strict) = verifier.getStats();
        assertFalse(strict);
    }

    function testVerifyAndRecord_updatesStats() public {
        bytes memory proof = abi.encodePacked(
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            bytes32(uint256(3)),
            bytes32(uint256(4)),
            bytes32(uint256(5)),
            bytes32(uint256(6)),
            bytes32(uint256(7)),
            bytes32(uint256(8))
        );

        bytes memory publicInputs = abi.encodePacked(
            bytes32(uint256(1)),
            bytes32(uint256(2))
        );

        verifier.verifyAndRecord(proof, publicInputs);

        (uint256 total, address noirAddr, bool strict) = verifier.getStats();
        assertEq(total, 1);
        assertEq(noirAddr, address(0));
        assertFalse(strict);
    }

    function testFuzz_verifyMerkleProof(
        bytes32 leafSeed,
        bytes32 siblingSeed
    ) public view {
        bytes32 leaf = keccak256(abi.encodePacked(leafSeed));
        bytes32 sibling = keccak256(abi.encodePacked(siblingSeed));

        bytes32 rootLeft = keccak256(abi.encodePacked(leaf, sibling));
        bytes32 rootRight = keccak256(abi.encodePacked(sibling, leaf));

        bytes32[] memory proof = new bytes32[](1);
        proof[0] = sibling;

        bool[] memory indicesLeft = new bool[](1);
        indicesLeft[0] = true;

        bool[] memory indicesRight = new bool[](1);
        indicesRight[0] = false;

        assertTrue(
            verifier.verifyMerkleProof(leaf, proof, indicesLeft, rootLeft)
        );
        assertTrue(
            verifier.verifyMerkleProof(leaf, proof, indicesRight, rootRight)
        );
    }
}
