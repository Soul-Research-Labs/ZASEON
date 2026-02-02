// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "forge-std/console.sol";

/**
 * @title Gas Limit Stress Tests
 * @notice Tests gas consumption under extreme conditions
 * @dev Part of security:stress test suite
 */
contract GasLimitStress is Test {
    /*//////////////////////////////////////////////////////////////
                            STATE VARIABLES
    //////////////////////////////////////////////////////////////*/

    MockBatchProcessor public batchProcessor;
    MockMerkleTree public merkleTree;
    MockLargeStorage public largeStorage;

    /*//////////////////////////////////////////////////////////////
                              SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public {
        batchProcessor = new MockBatchProcessor();
        merkleTree = new MockMerkleTree();
        largeStorage = new MockLargeStorage();
    }

    /*//////////////////////////////////////////////////////////////
                          GAS STRESS TESTS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Test batch processing gas limits
     */
    function test_batchProcessing_gasLimits() public {
        uint256[] memory batchSizes = new uint256[](5);
        batchSizes[0] = 10;
        batchSizes[1] = 50;
        batchSizes[2] = 100;
        batchSizes[3] = 200;
        batchSizes[4] = 500;

        for (uint256 i = 0; i < batchSizes.length; i++) {
            bytes32[] memory items = new bytes32[](batchSizes[i]);
            for (uint256 j = 0; j < batchSizes[i]; j++) {
                items[j] = keccak256(abi.encodePacked(i, j));
            }

            uint256 gasBefore = gasleft();
            batchProcessor.processBatch(items);
            uint256 gasUsed = gasBefore - gasleft();

            console.log("Batch size:", batchSizes[i], "Gas used:", gasUsed);

            // Ensure gas stays under block limit (30M)
            assertLt(gasUsed, 30_000_000, "Should stay under block gas limit");
        }
    }

    /**
     * @notice Test large loop gas consumption
     */
    function test_largeLoop_gasConsumption() public {
        uint256 gasPerIteration;

        for (uint256 iterations = 100; iterations <= 10000; iterations *= 10) {
            uint256 gasBefore = gasleft();
            batchProcessor.processLoop(iterations);
            uint256 gasUsed = gasBefore - gasleft();

            gasPerIteration = gasUsed / iterations;
            console.log(
                "Iterations:",
                iterations,
                "Gas/iteration:",
                gasPerIteration
            );

            // Gas per iteration should be relatively constant
            assertLt(
                gasPerIteration,
                10000,
                "Gas per iteration should be bounded"
            );
        }
    }

    /**
     * @notice Test merkle tree operations at scale
     */
    function test_merkleTree_scalability() public {
        uint256[] memory treeSizes = new uint256[](4);
        treeSizes[0] = 100;
        treeSizes[1] = 1000;
        treeSizes[2] = 5000;
        treeSizes[3] = 10000;

        for (uint256 i = 0; i < treeSizes.length; i++) {
            // Build tree
            for (uint256 j = 0; j < treeSizes[i]; j++) {
                merkleTree.addLeaf(keccak256(abi.encodePacked(j)));
            }

            // Measure proof verification
            bytes32[] memory proof = new bytes32[](20); // Max depth
            uint256 gasBefore = gasleft();
            merkleTree.verifyProof(proof, keccak256("test"));
            uint256 gasUsed = gasBefore - gasleft();

            console.log("Tree size:", treeSizes[i], "Verify gas:", gasUsed);

            // Verification should be O(log n)
            assertLt(gasUsed, 100000, "Proof verification should be efficient");

            merkleTree.reset();
        }
    }

    /**
     * @notice Test storage operations at scale
     */
    function test_storageOperations_atScale() public {
        uint256[] memory sizes = new uint256[](4);
        sizes[0] = 100;
        sizes[1] = 500;
        sizes[2] = 1000;
        sizes[3] = 2000;

        for (uint256 i = 0; i < sizes.length; i++) {
            uint256 gasBefore = gasleft();

            for (uint256 j = 0; j < sizes[i]; j++) {
                largeStorage.store(j, keccak256(abi.encodePacked(j)));
            }

            uint256 gasUsed = gasBefore - gasleft();
            uint256 gasPerStore = gasUsed / sizes[i];

            console.log("Stores:", sizes[i], "Gas/store:", gasPerStore);

            // First store is ~20k, subsequent same-slot ~5k
            // New slots ~20k each
            assertLt(gasPerStore, 25000, "Storage gas should be bounded");
        }
    }

    /**
     * @notice Test memory expansion gas costs
     */
    function test_memoryExpansion_gasCosts() public {
        // Reduced sizes to stay within reasonable gas limits
        uint256[] memory memorySizes = new uint256[](4);
        memorySizes[0] = 1 * 1024; // 1 KB
        memorySizes[1] = 10 * 1024; // 10 KB
        memorySizes[2] = 100 * 1024; // 100 KB
        memorySizes[3] = 500 * 1024; // 500 KB - max practical allocation

        for (uint256 i = 0; i < memorySizes.length; i++) {
            uint256 gasBefore = gasleft();
            batchProcessor.allocateMemory(memorySizes[i]);
            uint256 gasUsed = gasBefore - gasleft();

            console.log("Memory (KB):", memorySizes[i] / 1024, "Gas:", gasUsed);

            // Memory expansion is quadratic, so larger allocations are expensive
            // 500KB is the practical limit before exceeding block gas
            assertLt(gasUsed, 50_000_000, "Memory allocation should complete");
        }
    }

    /**
     * @notice Test signature verification batch gas
     */
    function test_signatureBatch_gasLimits() public {
        MockSignatureVerifier verifier = new MockSignatureVerifier();

        uint256[] memory batchSizes = new uint256[](4);
        batchSizes[0] = 10;
        batchSizes[1] = 50;
        batchSizes[2] = 100;
        batchSizes[3] = 200;

        for (uint256 i = 0; i < batchSizes.length; i++) {
            bytes32[] memory messages = new bytes32[](batchSizes[i]);
            bytes[] memory signatures = new bytes[](batchSizes[i]);
            address[] memory signers = new address[](batchSizes[i]);

            for (uint256 j = 0; j < batchSizes[i]; j++) {
                messages[j] = keccak256(abi.encodePacked(j));
                signatures[j] = new bytes(65);
                signers[j] = address(uint160(j + 1));
            }

            uint256 gasBefore = gasleft();
            verifier.verifyBatch(messages, signatures, signers);
            uint256 gasUsed = gasBefore - gasleft();

            console.log("Sig batch:", batchSizes[i], "Gas:", gasUsed);

            // ~3000 gas per ECRECOVER
            uint256 expectedMax = batchSizes[i] * 5000;
            assertLt(
                gasUsed,
                expectedMax,
                "Batch verification should be efficient"
            );
        }
    }

    /**
     * @notice Fuzz test: batch size gas correlation
     */
    function testFuzz_batchSizeGas(uint8 batchSize) public {
        vm.assume(batchSize > 0 && batchSize <= 100);

        bytes32[] memory items = new bytes32[](batchSize);
        for (uint256 i = 0; i < batchSize; i++) {
            items[i] = keccak256(abi.encodePacked(i));
        }

        uint256 gasBefore = gasleft();
        batchProcessor.processBatch(items);
        uint256 gasUsed = gasBefore - gasleft();

        // Gas should scale linearly with batch size
        // Storage writes cost ~20k per SSTORE, plus overhead
        uint256 maxExpected = 50_000 + (uint256(batchSize) * 25_000);
        assertLt(gasUsed, maxExpected, "Gas should scale linearly");
    }
}

/*//////////////////////////////////////////////////////////////
                        HELPER CONTRACTS
//////////////////////////////////////////////////////////////*/

contract MockBatchProcessor {
    mapping(bytes32 => bool) public processed;
    uint256 public counter;

    function processBatch(bytes32[] memory items) external {
        for (uint256 i = 0; i < items.length; i++) {
            processed[items[i]] = true;
        }
    }

    function processLoop(uint256 iterations) external {
        for (uint256 i = 0; i < iterations; i++) {
            counter++;
        }
    }

    function allocateMemory(uint256 size) external pure returns (bytes memory) {
        bytes memory data = new bytes(size);
        // Touch memory to force expansion
        for (uint256 i = 0; i < size; i += 32) {
            assembly {
                mstore(add(add(data, 32), i), i)
            }
        }
        return data;
    }
}

contract MockMerkleTree {
    bytes32[] public leaves;
    bytes32 public root;

    function addLeaf(bytes32 leaf) external {
        leaves.push(leaf);
    }

    function verifyProof(
        bytes32[] memory proof,
        bytes32 leaf
    ) external pure returns (bool) {
        bytes32 computedHash = leaf;

        for (uint256 i = 0; i < proof.length; i++) {
            if (proof[i] != bytes32(0)) {
                computedHash = keccak256(
                    abi.encodePacked(computedHash, proof[i])
                );
            }
        }

        return true; // Simplified
    }

    function reset() external {
        delete leaves;
    }
}

contract MockLargeStorage {
    mapping(uint256 => bytes32) public data;

    function store(uint256 key, bytes32 value) external {
        data[key] = value;
    }
}

contract MockSignatureVerifier {
    function verifyBatch(
        bytes32[] memory messages,
        bytes[] memory signatures,
        address[] memory signers
    ) external pure returns (bool[] memory) {
        bool[] memory results = new bool[](messages.length);

        for (uint256 i = 0; i < messages.length; i++) {
            // Simplified - in reality would use ecrecover
            results[i] = signatures[i].length == 65 && signers[i] != address(0);
        }

        return results;
    }
}
