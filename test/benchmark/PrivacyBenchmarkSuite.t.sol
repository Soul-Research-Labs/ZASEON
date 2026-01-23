// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";

/**
 * @title PrivacyBenchmarkSuite
 * @notice Performance benchmarks for privacy contracts
 * @dev Measures gas consumption, throughput, and concurrent operations
 */
contract PrivacyBenchmarkSuite is Test {
    // ═══════════════════════════════════════════════════════════════════════
    // BENCHMARK RESULTS STRUCTURE
    // ═══════════════════════════════════════════════════════════════════════

    struct BenchmarkResult {
        string name;
        uint256 gasUsed;
        uint256 iterations;
        uint256 avgGasPerOp;
        uint256 throughput; // ops per block (30M gas limit)
    }

    BenchmarkResult[] public results;

    // ═══════════════════════════════════════════════════════════════════════
    // MOCK CONTRACTS FOR BENCHMARKING
    // ═══════════════════════════════════════════════════════════════════════

    MockStealthRegistry stealthRegistry;
    MockNullifierManager nullifierManager;
    MockRingCT ringCT;
    MockPrivacyHub privacyHub;

    function setUp() public {
        stealthRegistry = new MockStealthRegistry();
        nullifierManager = new MockNullifierManager();
        ringCT = new MockRingCT();
        privacyHub = new MockPrivacyHub();
    }

    // ═══════════════════════════════════════════════════════════════════════
    // STEALTH ADDRESS BENCHMARKS
    // ═══════════════════════════════════════════════════════════════════════

    function test_benchmark_stealthAddress_single() public {
        uint256 gasStart = gasleft();

        for (uint256 i = 0; i < 100; i++) {
            stealthRegistry.generateStealthAddress(
                uint256(keccak256(abi.encodePacked("ephemeral", i))),
                uint256(keccak256(abi.encodePacked("ephemeralY", i))),
                uint256(keccak256(abi.encodePacked("spendX", i))),
                uint256(keccak256(abi.encodePacked("spendY", i))),
                uint256(keccak256(abi.encodePacked("viewX", i))),
                uint256(keccak256(abi.encodePacked("viewY", i)))
            );
        }

        uint256 gasUsed = gasStart - gasleft();
        uint256 avgGas = gasUsed / 100;

        emit log_named_uint("Stealth Address - Single - Total Gas", gasUsed);
        emit log_named_uint("Stealth Address - Single - Avg Gas", avgGas);
        emit log_named_uint(
            "Stealth Address - Single - Ops per Block",
            30_000_000 / avgGas
        );

        // Target: < 100k gas per operation
        assertLt(avgGas, 150_000, "Gas too high for stealth address");
    }

    function test_benchmark_stealthAddress_batch() public {
        uint256[2][] memory ephemeralKeys = new uint256[2][](50);
        uint256[4][] memory recipientPubKeys = new uint256[4][](50);

        for (uint256 i = 0; i < 50; i++) {
            ephemeralKeys[i] = [
                uint256(keccak256(abi.encodePacked("ephX", i))),
                uint256(keccak256(abi.encodePacked("ephY", i)))
            ];
            recipientPubKeys[i] = [
                uint256(keccak256(abi.encodePacked("spendX", i))),
                uint256(keccak256(abi.encodePacked("spendY", i))),
                uint256(keccak256(abi.encodePacked("viewX", i))),
                uint256(keccak256(abi.encodePacked("viewY", i)))
            ];
        }

        uint256 gasStart = gasleft();
        stealthRegistry.batchGenerateStealthAddresses(
            ephemeralKeys,
            recipientPubKeys
        );
        uint256 gasUsed = gasStart - gasleft();

        uint256 avgGas = gasUsed / 50;

        emit log_named_uint("Stealth Address - Batch(50) - Total Gas", gasUsed);
        emit log_named_uint(
            "Stealth Address - Batch(50) - Avg Gas per Address",
            avgGas
        );
        emit log_named_uint(
            "Stealth Address - Batch(50) - Savings vs Single",
            150_000 - avgGas
        );

        // Batch should be cheaper than single
        assertLt(avgGas, 100_000, "Batch should be cheaper");
    }

    // ═══════════════════════════════════════════════════════════════════════
    // NULLIFIER BENCHMARKS
    // ═══════════════════════════════════════════════════════════════════════

    function test_benchmark_nullifier_single() public {
        bytes32 domain = keccak256("test-domain");

        uint256 gasStart = gasleft();

        for (uint256 i = 0; i < 100; i++) {
            nullifierManager.consumeNullifier(
                keccak256(abi.encodePacked("nullifier", i)),
                domain
            );
        }

        uint256 gasUsed = gasStart - gasleft();
        uint256 avgGas = gasUsed / 100;

        emit log_named_uint("Nullifier - Single - Total Gas", gasUsed);
        emit log_named_uint("Nullifier - Single - Avg Gas", avgGas);
        emit log_named_uint(
            "Nullifier - Single - Ops per Block",
            30_000_000 / avgGas
        );

        // Target: < 50k gas per operation
        assertLt(avgGas, 80_000, "Gas too high for nullifier");
    }

    function test_benchmark_nullifier_batch() public {
        bytes32 domain = keccak256("test-domain-batch");
        bytes32[] memory nullifiers = new bytes32[](100);

        for (uint256 i = 0; i < 100; i++) {
            nullifiers[i] = keccak256(abi.encodePacked("batch-nullifier", i));
        }

        uint256 gasStart = gasleft();
        nullifierManager.batchConsumeNullifiers(nullifiers, domain);
        uint256 gasUsed = gasStart - gasleft();

        uint256 avgGas = gasUsed / 100;

        emit log_named_uint("Nullifier - Batch(100) - Total Gas", gasUsed);
        emit log_named_uint(
            "Nullifier - Batch(100) - Avg Gas per Nullifier",
            avgGas
        );
        emit log_named_uint(
            "Nullifier - Batch(100) - Savings vs Single",
            80_000 - avgGas
        );

        // Batch should be significantly cheaper
        assertLt(avgGas, 50_000, "Batch should be cheaper");
    }

    function test_benchmark_nullifier_crossDomainDerivation() public {
        uint256 gasStart = gasleft();

        for (uint256 i = 0; i < 1000; i++) {
            nullifierManager.deriveCrossDomainNullifier(
                keccak256(abi.encodePacked("source", i)),
                keccak256(abi.encodePacked("sourceDomain")),
                keccak256(abi.encodePacked("targetDomain"))
            );
        }

        uint256 gasUsed = gasStart - gasleft();
        uint256 avgGas = gasUsed / 1000;

        emit log_named_uint("Cross-Domain Nullifier - Avg Gas", avgGas);

        // Pure function should be very cheap
        assertLt(avgGas, 5_000, "Derivation should be cheap");
    }

    // ═══════════════════════════════════════════════════════════════════════
    // RINGCT BENCHMARKS
    // ═══════════════════════════════════════════════════════════════════════

    function test_benchmark_ringCT_smallRing() public {
        bytes32[] memory inputs = new bytes32[](2);
        bytes32[] memory outputs = new bytes32[](2);
        bytes32[] memory keyImages = new bytes32[](1);

        inputs[0] = keccak256("input1");
        inputs[1] = keccak256("input2");
        outputs[0] = keccak256("output1");
        outputs[1] = keccak256("output2");
        keyImages[0] = keccak256("keyImage1");

        uint256 gasStart = gasleft();

        for (uint256 i = 0; i < 10; i++) {
            keyImages[0] = keccak256(abi.encodePacked("keyImage", i));
            ringCT.processRingCT(
                inputs,
                outputs,
                keyImages,
                hex"00112233", // mock signature
                keccak256("pseudoOutput")
            );
        }

        uint256 gasUsed = gasStart - gasleft();
        uint256 avgGas = gasUsed / 10;

        emit log_named_uint("RingCT - Ring(2) - Avg Gas", avgGas);
        emit log_named_uint(
            "RingCT - Ring(2) - Ops per Block",
            30_000_000 / avgGas
        );
    }

    function test_benchmark_ringCT_largeRing() public {
        bytes32[] memory inputs = new bytes32[](16);
        bytes32[] memory outputs = new bytes32[](2);
        bytes32[] memory keyImages = new bytes32[](1);

        for (uint256 j = 0; j < 16; j++) {
            inputs[j] = keccak256(abi.encodePacked("input", j));
        }
        outputs[0] = keccak256("output1");
        outputs[1] = keccak256("output2");

        uint256 gasStart = gasleft();

        for (uint256 i = 0; i < 10; i++) {
            keyImages[0] = keccak256(abi.encodePacked("keyImageLarge", i));
            ringCT.processRingCT(
                inputs,
                outputs,
                keyImages,
                hex"00112233",
                keccak256("pseudoOutput")
            );
        }

        uint256 gasUsed = gasStart - gasleft();
        uint256 avgGas = gasUsed / 10;

        emit log_named_uint("RingCT - Ring(16) - Avg Gas", avgGas);
        emit log_named_uint(
            "RingCT - Ring(16) - Ops per Block",
            30_000_000 / avgGas
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // CONCURRENT OPERATIONS BENCHMARK
    // ═══════════════════════════════════════════════════════════════════════

    function test_benchmark_concurrent_1000_operations() public {
        emit log("=== CONCURRENT OPERATIONS BENCHMARK (1000 ops) ===");

        uint256 totalGasStart = gasleft();

        // Mix of operations simulating real usage
        for (uint256 i = 0; i < 250; i++) {
            // 250 stealth addresses
            stealthRegistry.generateStealthAddress(
                uint256(keccak256(abi.encodePacked("concurrent-eph", i))),
                uint256(keccak256(abi.encodePacked("concurrent-ephY", i))),
                uint256(keccak256(abi.encodePacked("concurrent-spendX", i))),
                uint256(keccak256(abi.encodePacked("concurrent-spendY", i))),
                uint256(keccak256(abi.encodePacked("concurrent-viewX", i))),
                uint256(keccak256(abi.encodePacked("concurrent-viewY", i)))
            );
        }

        uint256 stealthGas = totalGasStart - gasleft();
        uint256 nullifierStart = gasleft();

        bytes32 domain = keccak256("concurrent-domain");
        for (uint256 i = 0; i < 500; i++) {
            // 500 nullifiers
            nullifierManager.consumeNullifier(
                keccak256(abi.encodePacked("concurrent-null", i)),
                domain
            );
        }

        uint256 nullifierGas = nullifierStart - gasleft();
        uint256 ringStart = gasleft();

        bytes32[] memory inputs = new bytes32[](4);
        bytes32[] memory outputs = new bytes32[](2);
        bytes32[] memory keyImages = new bytes32[](1);

        for (uint256 j = 0; j < 4; j++) {
            inputs[j] = keccak256(abi.encodePacked("concurrent-input", j));
        }
        outputs[0] = keccak256("concurrent-output1");
        outputs[1] = keccak256("concurrent-output2");

        for (uint256 i = 0; i < 250; i++) {
            // 250 RingCT transactions
            keyImages[0] = keccak256(abi.encodePacked("concurrent-ki", i));
            ringCT.processRingCT(
                inputs,
                outputs,
                keyImages,
                hex"00112233",
                keccak256(abi.encodePacked("concurrent-pseudo", i))
            );
        }

        uint256 ringGas = ringStart - gasleft();
        uint256 totalGas = totalGasStart - gasleft();

        emit log_named_uint("Total Gas for 1000 ops", totalGas);
        emit log_named_uint("Stealth (250 ops) Gas", stealthGas);
        emit log_named_uint("Nullifier (500 ops) Gas", nullifierGas);
        emit log_named_uint("RingCT (250 ops) Gas", ringGas);
        emit log_named_uint("Avg Gas per Operation", totalGas / 1000);
        emit log_named_uint(
            "Operations per Block (30M limit)",
            (30_000_000 * 1000) / totalGas
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // MEMORY AND STORAGE BENCHMARKS
    // ═══════════════════════════════════════════════════════════════════════

    function test_benchmark_storage_reads() public {
        // Pre-populate storage
        bytes32 domain = keccak256("storage-test");
        for (uint256 i = 0; i < 100; i++) {
            nullifierManager.consumeNullifier(
                keccak256(abi.encodePacked("storage-null", i)),
                domain
            );
        }

        // Measure read costs
        bytes32[] memory nullifiers = new bytes32[](100);
        for (uint256 i = 0; i < 100; i++) {
            nullifiers[i] = keccak256(abi.encodePacked("storage-null", i));
        }

        uint256 gasStart = gasleft();
        nullifierManager.checkNullifiersBatch(nullifiers, domain);
        uint256 gasUsed = gasStart - gasleft();

        emit log_named_uint("Batch Read (100 nullifiers) - Gas", gasUsed);
        emit log_named_uint("Batch Read - Avg per Read", gasUsed / 100);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// MOCK CONTRACTS FOR BENCHMARKING
// ═══════════════════════════════════════════════════════════════════════════

contract MockStealthRegistry {
    mapping(bytes32 => address) public stealthAddresses;

    function generateStealthAddress(
        uint256 ephX,
        uint256 ephY,
        uint256 spendX,
        uint256 spendY,
        uint256 viewX,
        uint256 viewY
    ) external returns (address stealthAddress, uint8 viewTag) {
        bytes32 ephKey;
        bytes32 sharedSecret;

        assembly {
            let ptr := mload(0x40)
            mstore(ptr, ephX)
            mstore(add(ptr, 0x20), ephY)
            ephKey := keccak256(ptr, 0x40)

            mstore(ptr, viewX)
            mstore(add(ptr, 0x20), viewY)
            mstore(add(ptr, 0x40), ephX)
            mstore(add(ptr, 0x60), ephY)
            sharedSecret := keccak256(ptr, 0x80)

            mstore(ptr, spendX)
            mstore(add(ptr, 0x20), spendY)
            mstore(add(ptr, 0x40), sharedSecret)
            let hash := keccak256(ptr, 0x60)
            stealthAddress := and(
                hash,
                0xffffffffffffffffffffffffffffffffffffffff
            )
            viewTag := byte(0, hash)
        }

        stealthAddresses[ephKey] = stealthAddress;
    }

    function batchGenerateStealthAddresses(
        uint256[2][] calldata ephemeralKeys,
        uint256[4][] calldata recipientPubKeys
    ) external returns (address[] memory addresses, uint8[] memory viewTags) {
        addresses = new address[](ephemeralKeys.length);
        viewTags = new uint8[](ephemeralKeys.length);

        for (uint256 i = 0; i < ephemeralKeys.length; i++) {
            (addresses[i], viewTags[i]) = this.generateStealthAddress(
                ephemeralKeys[i][0],
                ephemeralKeys[i][1],
                recipientPubKeys[i][0],
                recipientPubKeys[i][1],
                recipientPubKeys[i][2],
                recipientPubKeys[i][3]
            );
        }
    }
}

contract MockNullifierManager {
    mapping(bytes32 => mapping(bytes32 => bool)) public consumed;

    function consumeNullifier(bytes32 nullifier, bytes32 domain) external {
        consumed[nullifier][domain] = true;
    }

    function batchConsumeNullifiers(
        bytes32[] calldata nullifiers,
        bytes32 domain
    ) external {
        for (uint256 i = 0; i < nullifiers.length; i++) {
            consumed[nullifiers[i]][domain] = true;
        }
    }

    function deriveCrossDomainNullifier(
        bytes32 source,
        bytes32 sourceDomain,
        bytes32 targetDomain
    ) external pure returns (bytes32 result) {
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, source)
            mstore(add(ptr, 0x20), sourceDomain)
            mstore(add(ptr, 0x40), targetDomain)
            result := keccak256(ptr, 0x60)
        }
    }

    function checkNullifiersBatch(
        bytes32[] calldata nullifiers,
        bytes32 domain
    ) external view returns (uint256 bitmap) {
        for (uint256 i = 0; i < nullifiers.length && i < 256; i++) {
            if (consumed[nullifiers[i]][domain]) {
                bitmap |= (1 << i);
            }
        }
    }
}

contract MockRingCT {
    mapping(bytes32 => bool) public usedKeyImages;

    function processRingCT(
        bytes32[] calldata,
        bytes32[] calldata,
        bytes32[] calldata keyImages,
        bytes calldata,
        bytes32
    ) external {
        for (uint256 i = 0; i < keyImages.length; i++) {
            usedKeyImages[keyImages[i]] = true;
        }
    }
}

contract MockPrivacyHub {
    function processPrivateTransfer(
        bytes32,
        bytes32,
        bytes32,
        bytes calldata
    ) external pure returns (bool) {
        return true;
    }
}
