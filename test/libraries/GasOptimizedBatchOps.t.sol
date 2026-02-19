// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {GasOptimizedBatchOps} from "../../contracts/libraries/GasOptimizedBatchOps.sol";

/// @dev Wrapper contract to expose library internal functions as external
///      This is needed because library functions with calldata params cannot be
///      called directly from test contracts (memory → calldata is not implicit).
contract BatchOpsWrapper {
    function batchComputeCommitments(
        uint256[] calldata values,
        bytes32[] calldata blindings
    ) external pure returns (bytes32[] memory) {
        return GasOptimizedBatchOps.batchComputeCommitments(values, blindings);
    }

    function batchComputeNullifiers(
        bytes32[] calldata secrets,
        uint256[] calldata leafIndices
    ) external pure returns (bytes32[] memory) {
        return
            GasOptimizedBatchOps.batchComputeNullifiers(secrets, leafIndices);
    }

    function batchComputeLeaves(
        bytes32[] calldata commitments
    ) external pure returns (bytes32[] memory) {
        return GasOptimizedBatchOps.batchComputeLeaves(commitments);
    }

    function batchCheckMembership(
        uint256 bitmap,
        uint8[] calldata indices
    ) external pure returns (bool, uint256) {
        return GasOptimizedBatchOps.batchCheckMembership(bitmap, indices);
    }

    function deduplicateSorted(
        bytes32[] calldata sorted
    ) external pure returns (bytes32[] memory) {
        return GasOptimizedBatchOps.deduplicateSorted(sorted);
    }

    function hashBatch(
        address[] calldata targets,
        bytes[] calldata callDatas
    ) external pure returns (bytes32) {
        return GasOptimizedBatchOps.hashBatch(targets, callDatas);
    }

    function sum(uint256[] calldata values) external pure returns (uint256) {
        return GasOptimizedBatchOps.sum(values);
    }

    function minMax(
        uint256[] calldata values
    ) external pure returns (uint256, uint256) {
        return GasOptimizedBatchOps.minMax(values);
    }

    function weightedAverage(
        uint256[] calldata values,
        uint256[] calldata weights
    ) external pure returns (uint256) {
        return GasOptimizedBatchOps.weightedAverage(values, weights);
    }
}

contract GasOptimizedBatchOpsTest is Test {
    using GasOptimizedBatchOps for uint256;

    BatchOpsWrapper internal wrapper;

    function setUp() public {
        wrapper = new BatchOpsWrapper();
    }

    /*//////////////////////////////////////////////////////////////
                      BATCH COMPUTE COMMITMENTS
    //////////////////////////////////////////////////////////////*/

    function test_BatchComputeCommitments_Single() public view {
        uint256[] memory values = new uint256[](1);
        values[0] = 100;
        bytes32[] memory blindings = new bytes32[](1);
        blindings[0] = bytes32(uint256(0xdead));

        bytes32[] memory commits = wrapper.batchComputeCommitments(
            values,
            blindings
        );
        assertEq(commits.length, 1);
        assertEq(
            commits[0],
            keccak256(abi.encodePacked(uint256(100), bytes32(uint256(0xdead))))
        );
    }

    function test_BatchComputeCommitments_Multiple() public view {
        uint256[] memory values = new uint256[](3);
        values[0] = 100;
        values[1] = 200;
        values[2] = 300;
        bytes32[] memory blindings = new bytes32[](3);
        blindings[0] = bytes32(uint256(1));
        blindings[1] = bytes32(uint256(2));
        blindings[2] = bytes32(uint256(3));

        bytes32[] memory commits = wrapper.batchComputeCommitments(
            values,
            blindings
        );
        assertEq(commits.length, 3);
        for (uint256 i; i < 3; i++) {
            assertEq(
                commits[i],
                keccak256(abi.encodePacked(values[i], blindings[i]))
            );
        }
    }

    function test_BatchComputeCommitments_RevertEmpty() public {
        uint256[] memory values = new uint256[](0);
        bytes32[] memory blindings = new bytes32[](0);

        vm.expectRevert(GasOptimizedBatchOps.EmptyArray.selector);
        wrapper.batchComputeCommitments(values, blindings);
    }

    function test_BatchComputeCommitments_RevertLengthMismatch() public {
        uint256[] memory values = new uint256[](2);
        bytes32[] memory blindings = new bytes32[](3);

        vm.expectRevert(
            abi.encodeWithSelector(
                GasOptimizedBatchOps.LengthMismatch.selector,
                2,
                3
            )
        );
        wrapper.batchComputeCommitments(values, blindings);
    }

    /*//////////////////////////////////////////////////////////////
                      BATCH COMPUTE NULLIFIERS
    //////////////////////////////////////////////////////////////*/

    function test_BatchComputeNullifiers_Single() public view {
        bytes32[] memory secrets = new bytes32[](1);
        secrets[0] = bytes32(uint256(0xbeef));
        uint256[] memory indices = new uint256[](1);
        indices[0] = 42;

        bytes32[] memory nullifiers = wrapper.batchComputeNullifiers(
            secrets,
            indices
        );
        assertEq(nullifiers.length, 1);
        assertEq(
            nullifiers[0],
            keccak256(abi.encodePacked(bytes32(uint256(0xbeef)), uint256(42)))
        );
    }

    function test_BatchComputeNullifiers_RevertEmpty() public {
        vm.expectRevert(GasOptimizedBatchOps.EmptyArray.selector);
        wrapper.batchComputeNullifiers(new bytes32[](0), new uint256[](0));
    }

    /*//////////////////////////////////////////////////////////////
                       BATCH COMPUTE LEAVES
    //////////////////////////////////////////////////////////////*/

    function test_BatchComputeLeaves_Deterministic() public view {
        bytes32[] memory commits = new bytes32[](2);
        commits[0] = bytes32(uint256(1));
        commits[1] = bytes32(uint256(2));

        bytes32[] memory leaves = wrapper.batchComputeLeaves(commits);
        assertEq(leaves.length, 2);
        assertEq(leaves[0], keccak256(abi.encodePacked(bytes32(uint256(1)))));
        assertEq(leaves[1], keccak256(abi.encodePacked(bytes32(uint256(2)))));
    }

    function test_BatchComputeLeaves_RevertEmpty() public {
        vm.expectRevert(GasOptimizedBatchOps.EmptyArray.selector);
        wrapper.batchComputeLeaves(new bytes32[](0));
    }

    /*//////////////////////////////////////////////////////////////
                        BITMAP OPERATIONS
    //////////////////////////////////////////////////////////////*/

    function test_SetBit() public pure {
        uint256 bitmap = 0;
        bitmap = GasOptimizedBatchOps.setBit(bitmap, 0);
        assertEq(bitmap, 1);

        bitmap = GasOptimizedBatchOps.setBit(bitmap, 7);
        assertEq(bitmap, 129); // 2^0 + 2^7

        bitmap = GasOptimizedBatchOps.setBit(bitmap, 255);
        assertTrue(bitmap > 0);
    }

    function test_GetBit() public pure {
        uint256 bitmap = 0;
        assertFalse(GasOptimizedBatchOps.getBit(bitmap, 0));

        bitmap = GasOptimizedBatchOps.setBit(bitmap, 5);
        assertTrue(GasOptimizedBatchOps.getBit(bitmap, 5));
        assertFalse(GasOptimizedBatchOps.getBit(bitmap, 4));
    }

    function test_ClearBit() public pure {
        uint256 bitmap = GasOptimizedBatchOps.setBit(0, 5);
        assertTrue(GasOptimizedBatchOps.getBit(bitmap, 5));

        bitmap = GasOptimizedBatchOps.clearBit(bitmap, 5);
        assertFalse(GasOptimizedBatchOps.getBit(bitmap, 5));
    }

    function test_PopCount() public pure {
        assertEq(GasOptimizedBatchOps.popCount(0), 0);
        assertEq(GasOptimizedBatchOps.popCount(1), 1);
        assertEq(GasOptimizedBatchOps.popCount(3), 2); // 0b11
        assertEq(GasOptimizedBatchOps.popCount(255), 8); // 0b11111111
        assertEq(GasOptimizedBatchOps.popCount(type(uint256).max), 256);
    }

    function test_BatchCheckMembership_AllPresent() public view {
        uint256 bitmap = 0;
        bitmap = GasOptimizedBatchOps.setBit(bitmap, 1);
        bitmap = GasOptimizedBatchOps.setBit(bitmap, 5);
        bitmap = GasOptimizedBatchOps.setBit(bitmap, 10);

        uint8[] memory indices = new uint8[](3);
        indices[0] = 1;
        indices[1] = 5;
        indices[2] = 10;

        (bool allPresent, uint256 count) = wrapper.batchCheckMembership(
            bitmap,
            indices
        );
        assertTrue(allPresent);
        assertEq(count, 3);
    }

    function test_BatchCheckMembership_Partial() public view {
        uint256 bitmap = GasOptimizedBatchOps.setBit(0, 1);

        uint8[] memory indices = new uint8[](2);
        indices[0] = 1;
        indices[1] = 2;

        (bool allPresent, uint256 count) = wrapper.batchCheckMembership(
            bitmap,
            indices
        );
        assertFalse(allPresent);
        assertEq(count, 1);
    }

    function test_BatchCheckMembership_RevertEmpty() public {
        vm.expectRevert(GasOptimizedBatchOps.EmptyArray.selector);
        wrapper.batchCheckMembership(0, new uint8[](0));
    }

    /*//////////////////////////////////////////////////////////////
                       PACKING OPERATIONS
    //////////////////////////////////////////////////////////////*/

    function test_Pack128_Roundtrip() public pure {
        uint128 high = 12345;
        uint128 low = 67890;
        uint256 packed = GasOptimizedBatchOps.pack128(high, low);
        (uint128 h, uint128 l) = GasOptimizedBatchOps.unpack128(packed);
        assertEq(h, high);
        assertEq(l, low);
    }

    function test_Pack128_MaxValues() public pure {
        uint128 high = type(uint128).max;
        uint128 low = type(uint128).max;
        uint256 packed = GasOptimizedBatchOps.pack128(high, low);
        assertEq(packed, type(uint256).max);
        (uint128 h, uint128 l) = GasOptimizedBatchOps.unpack128(packed);
        assertEq(h, high);
        assertEq(l, low);
    }

    function test_Pack64_Roundtrip() public pure {
        uint64 a = 111;
        uint64 b = 222;
        uint64 c = 333;
        uint64 d = 444;
        uint256 packed = GasOptimizedBatchOps.pack64(a, b, c, d);
        (uint64 a2, uint64 b2, uint64 c2, uint64 d2) = GasOptimizedBatchOps
            .unpack64(packed);
        assertEq(a2, a);
        assertEq(b2, b);
        assertEq(c2, c);
        assertEq(d2, d);
    }

    function test_Pack64_MaxValues() public pure {
        uint64 maxVal = type(uint64).max;
        uint256 packed = GasOptimizedBatchOps.pack64(
            maxVal,
            maxVal,
            maxVal,
            maxVal
        );
        (uint64 a, uint64 b, uint64 c, uint64 d) = GasOptimizedBatchOps
            .unpack64(packed);
        assertEq(a, maxVal);
        assertEq(b, maxVal);
        assertEq(c, maxVal);
        assertEq(d, maxVal);
    }

    /*//////////////////////////////////////////////////////////////
                      DEDUPLICATION
    //////////////////////////////////////////////////////////////*/

    function test_DeduplicateSorted_NoDuplicates() public view {
        bytes32[] memory arr = new bytes32[](3);
        arr[0] = bytes32(uint256(1));
        arr[1] = bytes32(uint256(2));
        arr[2] = bytes32(uint256(3));

        bytes32[] memory result = wrapper.deduplicateSorted(arr);
        assertEq(result.length, 3);
    }

    function test_DeduplicateSorted_WithDuplicates() public view {
        bytes32[] memory arr = new bytes32[](5);
        arr[0] = bytes32(uint256(1));
        arr[1] = bytes32(uint256(1));
        arr[2] = bytes32(uint256(2));
        arr[3] = bytes32(uint256(2));
        arr[4] = bytes32(uint256(3));

        bytes32[] memory result = wrapper.deduplicateSorted(arr);
        assertEq(result.length, 3);
        assertEq(result[0], bytes32(uint256(1)));
        assertEq(result[1], bytes32(uint256(2)));
        assertEq(result[2], bytes32(uint256(3)));
    }

    function test_DeduplicateSorted_AllSame() public view {
        bytes32[] memory arr = new bytes32[](4);
        arr[0] = bytes32(uint256(7));
        arr[1] = bytes32(uint256(7));
        arr[2] = bytes32(uint256(7));
        arr[3] = bytes32(uint256(7));

        bytes32[] memory result = wrapper.deduplicateSorted(arr);
        assertEq(result.length, 1);
        assertEq(result[0], bytes32(uint256(7)));
    }

    function test_DeduplicateSorted_Empty() public view {
        bytes32[] memory result = wrapper.deduplicateSorted(new bytes32[](0));
        assertEq(result.length, 0);
    }

    function test_DeduplicateSorted_Single() public view {
        bytes32[] memory arr = new bytes32[](1);
        arr[0] = bytes32(uint256(42));
        bytes32[] memory result = wrapper.deduplicateSorted(arr);
        assertEq(result.length, 1);
        assertEq(result[0], bytes32(uint256(42)));
    }

    /*//////////////////////////////////////////////////////////////
                       MULTICALL HELPERS
    //////////////////////////////////////////////////////////////*/

    function test_HashBatch_Deterministic() public view {
        address[] memory targets = new address[](2);
        targets[0] = address(0x1);
        targets[1] = address(0x2);

        bytes[] memory callDatas = new bytes[](2);
        callDatas[0] = hex"aabbccdd";
        callDatas[1] = hex"11223344";

        bytes32 hash1 = wrapper.hashBatch(targets, callDatas);
        bytes32 hash2 = wrapper.hashBatch(targets, callDatas);
        assertEq(hash1, hash2);
    }

    function test_HashBatch_RevertEmpty() public {
        vm.expectRevert(GasOptimizedBatchOps.EmptyArray.selector);
        wrapper.hashBatch(new address[](0), new bytes[](0));
    }

    function test_HashBatch_RevertLengthMismatch() public {
        address[] memory targets = new address[](2);
        targets[0] = address(0x1);
        targets[1] = address(0x2);
        bytes[] memory callDatas = new bytes[](1);
        callDatas[0] = hex"00";

        vm.expectRevert(
            abi.encodeWithSelector(
                GasOptimizedBatchOps.LengthMismatch.selector,
                2,
                1
            )
        );
        wrapper.hashBatch(targets, callDatas);
    }

    function test_DomainSeparatedBatchHash() public pure {
        bytes32 batchHash = bytes32(uint256(0x123));
        bytes32 domainHash = GasOptimizedBatchOps.domainSeparatedBatchHash(
            1,
            0,
            batchHash
        );
        assertFalse(domainHash == bytes32(0));

        // Different chain ID → different hash
        bytes32 domainHash2 = GasOptimizedBatchOps.domainSeparatedBatchHash(
            42,
            0,
            batchHash
        );
        assertFalse(domainHash == domainHash2);
    }

    /*//////////////////////////////////////////////////////////////
                      AGGREGATE FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function test_Sum() public view {
        uint256[] memory values = new uint256[](3);
        values[0] = 10;
        values[1] = 20;
        values[2] = 30;
        assertEq(wrapper.sum(values), 60);
    }

    function test_Sum_Empty() public view {
        assertEq(wrapper.sum(new uint256[](0)), 0);
    }

    function test_MinMax() public view {
        uint256[] memory values = new uint256[](4);
        values[0] = 50;
        values[1] = 10;
        values[2] = 80;
        values[3] = 30;

        (uint256 min, uint256 max) = wrapper.minMax(values);
        assertEq(min, 10);
        assertEq(max, 80);
    }

    function test_MinMax_Single() public view {
        uint256[] memory values = new uint256[](1);
        values[0] = 42;
        (uint256 min, uint256 max) = wrapper.minMax(values);
        assertEq(min, 42);
        assertEq(max, 42);
    }

    function test_MinMax_RevertEmpty() public {
        vm.expectRevert(GasOptimizedBatchOps.EmptyArray.selector);
        wrapper.minMax(new uint256[](0));
    }

    function test_WeightedAverage() public view {
        uint256[] memory values = new uint256[](2);
        values[0] = 80;
        values[1] = 60;
        uint256[] memory weights = new uint256[](2);
        weights[0] = 3;
        weights[1] = 1;

        // (80*3 + 60*1) / (3+1) = 300/4 = 75
        assertEq(wrapper.weightedAverage(values, weights), 75);
    }

    function test_WeightedAverage_ZeroWeight() public view {
        uint256[] memory values = new uint256[](1);
        values[0] = 100;
        uint256[] memory weights = new uint256[](1);
        weights[0] = 0;

        assertEq(wrapper.weightedAverage(values, weights), 0);
    }

    function test_WeightedAverage_RevertLengthMismatch() public {
        uint256[] memory values = new uint256[](2);
        uint256[] memory weights = new uint256[](3);

        vm.expectRevert(
            abi.encodeWithSelector(
                GasOptimizedBatchOps.LengthMismatch.selector,
                2,
                3
            )
        );
        wrapper.weightedAverage(values, weights);
    }

    /*//////////////////////////////////////////////////////////////
                          FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_Pack128_Roundtrip(uint128 high, uint128 low) public pure {
        uint256 packed = GasOptimizedBatchOps.pack128(high, low);
        (uint128 h, uint128 l) = GasOptimizedBatchOps.unpack128(packed);
        assertEq(h, high);
        assertEq(l, low);
    }

    function testFuzz_Pack64_Roundtrip(
        uint64 a,
        uint64 b,
        uint64 c,
        uint64 d
    ) public pure {
        uint256 packed = GasOptimizedBatchOps.pack64(a, b, c, d);
        (uint64 a2, uint64 b2, uint64 c2, uint64 d2) = GasOptimizedBatchOps
            .unpack64(packed);
        assertEq(a2, a);
        assertEq(b2, b);
        assertEq(c2, c);
        assertEq(d2, d);
    }

    function testFuzz_SetGetBit(uint8 index) public pure {
        uint256 bitmap = GasOptimizedBatchOps.setBit(0, index);
        assertTrue(GasOptimizedBatchOps.getBit(bitmap, index));

        bitmap = GasOptimizedBatchOps.clearBit(bitmap, index);
        assertFalse(GasOptimizedBatchOps.getBit(bitmap, index));
    }

    function testFuzz_PopCount_SetNBits(uint8 n) public pure {
        vm.assume(n <= 255);
        uint256 bitmap;
        for (uint8 i; i < n; i++) {
            bitmap = GasOptimizedBatchOps.setBit(bitmap, i);
        }
        assertEq(GasOptimizedBatchOps.popCount(bitmap), n);
    }

    function testFuzz_CommitmentDeterminism(
        uint256 value,
        bytes32 blinding
    ) public view {
        uint256[] memory values = new uint256[](1);
        values[0] = value;
        bytes32[] memory blindings = new bytes32[](1);
        blindings[0] = blinding;

        bytes32[] memory c1 = wrapper.batchComputeCommitments(
            values,
            blindings
        );
        bytes32[] memory c2 = wrapper.batchComputeCommitments(
            values,
            blindings
        );
        assertEq(c1[0], c2[0]);
    }

    function testFuzz_WeightedAverage_SingleValue(
        uint128 value,
        uint128 weight
    ) public view {
        vm.assume(weight > 0);
        uint256[] memory values = new uint256[](1);
        values[0] = uint256(value);
        uint256[] memory weights = new uint256[](1);
        weights[0] = uint256(weight);

        assertEq(wrapper.weightedAverage(values, weights), value);
    }
}
