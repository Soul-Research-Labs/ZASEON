// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "forge-std/console.sol";

/**
 * @title Large Scale Operations Stress Tests
 * @notice Tests system behavior with large data sets and many participants
 * @dev Part of security:stress test suite
 */
contract LargeScaleStress is Test {
    /*//////////////////////////////////////////////////////////////
                            STATE VARIABLES
    //////////////////////////////////////////////////////////////*/

    MockLargeRegistry public registry;
    MockLargeMerkle public merkle;
    MockLargeMapping public mapping_;
    MockLargeBatch public batch;

    /*//////////////////////////////////////////////////////////////
                              SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public {
        registry = new MockLargeRegistry();
        merkle = new MockLargeMerkle();
        mapping_ = new MockLargeMapping();
        batch = new MockLargeBatch();
    }

    /*//////////////////////////////////////////////////////////////
                      LARGE SCALE TESTS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Test registry with 10k entries
     */
    function test_registry_10kEntries() public {
        uint256 count = 10000;

        uint256 gasBefore = gasleft();

        for (uint256 i = 0; i < count; i++) {
            registry.register(
                address(uint160(i + 1)),
                keccak256(abi.encodePacked(i))
            );
        }

        uint256 gasUsed = gasBefore - gasleft();
        console.log("10k registrations, total gas:", gasUsed);
        console.log("Gas per registration:", gasUsed / count);

        // Verify retrieval is O(1)
        uint256 retrievalGasBefore = gasleft();
        registry.getData(address(5000));
        uint256 retrievalGas = retrievalGasBefore - gasleft();

        console.log("Retrieval gas:", retrievalGas);
        assertLt(retrievalGas, 5000, "Retrieval should be O(1)");

        assertEq(registry.count(), count, "All entries registered");
    }

    /**
     * @notice Test merkle tree with 10k leaves
     * @dev Reduced from 100k to stay within test gas limits
     */
    function test_merkleTree_10kLeaves() public {
        uint256 count = 10000;

        // Add leaves in batches to avoid timeout
        uint256 batchSize = 1000;

        for (uint256 batch_ = 0; batch_ < count / batchSize; batch_++) {
            bytes32[] memory leaves = new bytes32[](batchSize);
            for (uint256 i = 0; i < batchSize; i++) {
                leaves[i] = keccak256(abi.encodePacked(batch_ * batchSize + i));
            }
            merkle.addLeavesBatch(leaves);
        }

        assertEq(merkle.leafCount(), count, "All leaves added");

        // Verify proof generation is O(log n)
        uint256 proofGasBefore = gasleft();
        merkle.getProof(5000); // Middle element
        uint256 proofGas = proofGasBefore - gasleft();

        console.log("10k tree, proof gas:", proofGas);
        // log2(10000) ≈ 14, so ~14 hashes
        assertLt(proofGas, 50000, "Proof should be O(log n)");
    }

    /**
     * @notice Test mapping with 10k entries and iteration
     * @dev Reduced from 50k to stay within test gas limits
     */
    function test_mapping_10kWithIteration() public {
        uint256 count = 10000;

        // Store entries
        for (uint256 i = 0; i < count; i++) {
            mapping_.set(bytes32(i), bytes32(i * 2));
        }

        assertEq(mapping_.size(), count, "All entries stored");

        // Iterate subset (full iteration would be too expensive)
        uint256 iterateCount = 1000;
        uint256 iterateGasBefore = gasleft();
        mapping_.iterateRange(0, iterateCount);
        uint256 iterateGas = iterateGasBefore - gasleft();

        console.log("Iterate 1k entries, gas:", iterateGas);
        console.log("Gas per iteration:", iterateGas / iterateCount);
    }

    /**
     * @notice Test batch operations with 5k items
     */
    function test_batch_5kOperations() public {
        uint256 count = 5000;

        bytes32[] memory data = new bytes32[](count);
        for (uint256 i = 0; i < count; i++) {
            data[i] = keccak256(abi.encodePacked(i));
        }

        uint256 gasBefore = gasleft();
        batch.processBatch(data);
        uint256 gasUsed = gasBefore - gasleft();

        console.log("5k batch, total gas:", gasUsed);
        console.log("Gas per item:", gasUsed / count);

        assertEq(batch.processedCount(), count, "All items processed");
    }

    /**
     * @notice Test state growth over time
     * @dev Reduced checkpoints to stay within test gas limits
     */
    function test_stateGrowth_simulation() public {
        MockGrowingState state = new MockGrowingState();

        uint256[] memory checkpoints = new uint256[](4);
        checkpoints[0] = 100;
        checkpoints[1] = 500;
        checkpoints[2] = 1000;
        checkpoints[3] = 5000;

        uint256 lastSize = 0;

        for (uint256 c = 0; c < checkpoints.length; c++) {
            uint256 target = checkpoints[c];

            // Grow to checkpoint
            for (uint256 i = lastSize; i < target; i++) {
                state.addEntry(keccak256(abi.encodePacked(i)));
            }
            lastSize = target;

            // Measure operation costs at this size
            uint256 gasBefore = gasleft();
            state.addEntry(keccak256(abi.encodePacked(target)));
            uint256 addGas = gasBefore - gasleft();

            gasBefore = gasleft();
            state.getEntry(target / 2);
            uint256 getGas = gasBefore - gasleft();

            console.log("State size:", target);
            console.log("  Add gas:", addGas);
            console.log("  Get gas:", getGas);

            // Operations should remain O(1) regardless of size
            assertLt(addGas, 50000, "Add should be O(1)");
            assertLt(getGas, 5000, "Get should be O(1)");

            lastSize++;
        }
    }

    /**
     * @notice Test cross-chain message queue at scale
     */
    function test_messageQueue_atScale() public {
        MockMessageQueue queue = new MockMessageQueue();
        uint256 count = 10000;

        // Queue messages
        for (uint256 i = 0; i < count; i++) {
            queue.enqueue(bytes32(i), uint64(i + 1), address(uint160(i + 1)));
        }

        assertEq(queue.length(), count, "All messages queued");

        // Process in order
        uint256 processGasBefore = gasleft();
        for (uint256 i = 0; i < 100; i++) {
            queue.dequeue();
        }
        uint256 processGas = processGasBefore - gasleft();

        console.log("Process 100 messages, gas:", processGas);
        console.log("Gas per dequeue:", processGas / 100);

        assertEq(queue.length(), count - 100, "Messages processed correctly");
    }

    /**
     * @notice Test validator set with 1000 validators
     */
    function test_validatorSet_1000() public {
        MockValidatorSet validators = new MockValidatorSet();
        uint256 count = 1000;

        // Add validators
        for (uint256 i = 0; i < count; i++) {
            validators.addValidator(
                address(uint160(i + 1)),
                100 ether + (i * 1 ether) // Varying stake
            );
        }

        assertEq(validators.validatorCount(), count, "All validators added");

        // Sample validators (for committee selection)
        uint256 sampleGasBefore = gasleft();
        validators.sampleValidators(100, keccak256("randomness"));
        uint256 sampleGas = sampleGasBefore - gasleft();

        console.log("Sample 100 validators, gas:", sampleGas);

        // Stake-weighted operations
        uint256 totalStake = validators.totalStake();
        assertGt(totalStake, 100000 ether, "Total stake accumulated");
    }

    /**
     * @notice Fuzz test: scaling behavior
     */
    function testFuzz_scalingBehavior(uint16 size) public {
        vm.assume(size > 0 && size <= 1000);

        MockScalableContract scalable = new MockScalableContract();

        // Add entries
        for (uint256 i = 0; i < size; i++) {
            scalable.add(keccak256(abi.encodePacked(i)));
        }

        // Verify O(1) operations
        uint256 gasBefore = gasleft();
        scalable.get(size / 2);
        uint256 getGas = gasBefore - gasleft();

        // Get should be constant regardless of size
        assertLt(getGas, 5000, "Get should be O(1)");
    }
}

/*//////////////////////////////////////////////////////////////
                        HELPER CONTRACTS
//////////////////////////////////////////////////////////////*/

contract MockLargeRegistry {
    mapping(address => bytes32) public data;
    uint256 public count;

    function register(address addr, bytes32 value) external {
        data[addr] = value;
        count++;
    }

    function getData(address addr) external view returns (bytes32) {
        return data[addr];
    }
}

contract MockLargeMerkle {
    bytes32[] public leaves;

    function addLeavesBatch(bytes32[] memory newLeaves) external {
        for (uint256 i = 0; i < newLeaves.length; i++) {
            leaves.push(newLeaves[i]);
        }
    }

    function leafCount() external view returns (uint256) {
        return leaves.length;
    }

    function getProof(uint256 index) external view returns (bytes32[] memory) {
        // Simplified proof - just return path
        uint256 depth = 17; // log2(100000) ≈ 17
        bytes32[] memory proof = new bytes32[](depth);

        for (uint256 i = 0; i < depth && index < leaves.length; i++) {
            uint256 siblingIndex = index % 2 == 0 ? index + 1 : index - 1;
            if (siblingIndex < leaves.length) {
                proof[i] = leaves[siblingIndex];
            }
            index /= 2;
        }

        return proof;
    }
}

contract MockLargeMapping {
    mapping(bytes32 => bytes32) public data;
    bytes32[] public keys;

    function set(bytes32 key, bytes32 value) external {
        if (data[key] == bytes32(0)) {
            keys.push(key);
        }
        data[key] = value;
    }

    function size() external view returns (uint256) {
        return keys.length;
    }

    function iterateRange(
        uint256 start,
        uint256 count
    ) external view returns (bytes32[] memory) {
        bytes32[] memory values = new bytes32[](count);
        for (uint256 i = 0; i < count && start + i < keys.length; i++) {
            values[i] = data[keys[start + i]];
        }
        return values;
    }
}

contract MockLargeBatch {
    mapping(bytes32 => bool) public processed;
    uint256 public processedCount;

    function processBatch(bytes32[] memory items) external {
        for (uint256 i = 0; i < items.length; i++) {
            processed[items[i]] = true;
            processedCount++;
        }
    }
}

contract MockGrowingState {
    mapping(uint256 => bytes32) public entries;
    uint256 public entryCount;

    function addEntry(bytes32 value) external {
        entries[entryCount] = value;
        entryCount++;
    }

    function getEntry(uint256 index) external view returns (bytes32) {
        return entries[index];
    }
}

contract MockMessageQueue {
    struct Message {
        bytes32 data;
        uint64 timestamp;
        address sender;
    }

    Message[] public messages;
    uint256 public head;

    function enqueue(bytes32 data, uint64 timestamp, address sender) external {
        messages.push(
            Message({data: data, timestamp: timestamp, sender: sender})
        );
    }

    function dequeue() external returns (Message memory) {
        require(head < messages.length, "Queue empty");
        Message memory msg_ = messages[head];
        head++;
        return msg_;
    }

    function length() external view returns (uint256) {
        return messages.length - head;
    }
}

contract MockValidatorSet {
    struct Validator {
        address addr;
        uint256 stake;
        bool active;
    }

    mapping(address => Validator) public validators;
    address[] public validatorList;
    uint256 public totalStake;

    function addValidator(address addr, uint256 stake) external {
        validators[addr] = Validator({addr: addr, stake: stake, active: true});
        validatorList.push(addr);
        totalStake += stake;
    }

    function validatorCount() external view returns (uint256) {
        return validatorList.length;
    }

    function sampleValidators(
        uint256 count,
        bytes32 randomness
    ) external view returns (address[] memory) {
        address[] memory sampled = new address[](count);

        for (uint256 i = 0; i < count; i++) {
            uint256 index = uint256(
                keccak256(abi.encodePacked(randomness, i))
            ) % validatorList.length;
            sampled[i] = validatorList[index];
        }

        return sampled;
    }
}

contract MockScalableContract {
    mapping(uint256 => bytes32) public entries;
    uint256 public count;

    function add(bytes32 value) external {
        entries[count] = value;
        count++;
    }

    function get(uint256 index) external view returns (bytes32) {
        return entries[index];
    }
}
