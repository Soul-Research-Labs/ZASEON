// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {GasOptimizations} from "../../contracts/libraries/GasOptimizations.sol";
import {BatchProcessing} from "../../contracts/libraries/BatchProcessing.sol";

/// @title Harness contract that exposes internal library functions
contract GasOptHarness {
    using GasOptimizations for *;

    // --- Hashing ---
    function efficientHash(
        bytes32 a,
        bytes32 b
    ) external pure returns (bytes32) {
        return GasOptimizations.efficientHash(a, b);
    }

    function efficientHash3(
        bytes32 a,
        bytes32 b,
        bytes32 c
    ) external pure returns (bytes32) {
        return GasOptimizations.efficientHash3(a, b, c);
    }

    function efficientHashAddressUint(
        address addr,
        uint256 value
    ) external pure returns (bytes32) {
        return GasOptimizations.efficientHashAddressUint(addr, value);
    }

    function batchHash(
        bytes32[] memory leaves
    ) external pure returns (bytes32[] memory) {
        return GasOptimizations.batchHash(leaves);
    }

    // --- Packing ---
    function packUint128(uint128 a, uint128 b) external pure returns (uint256) {
        return GasOptimizations.packUint128(a, b);
    }

    function unpackUint128(
        uint256 packed
    ) external pure returns (uint128, uint128) {
        return GasOptimizations.unpackUint128(packed);
    }

    function packUint64(
        uint64 a,
        uint64 b,
        uint64 c,
        uint64 d
    ) external pure returns (uint256) {
        return GasOptimizations.packUint64(a, b, c, d);
    }

    function unpackUint64(
        uint256 packed
    ) external pure returns (uint64, uint64, uint64, uint64) {
        return GasOptimizations.unpackUint64(packed);
    }

    function packAddressWithData(
        address addr,
        uint96 data
    ) external pure returns (uint256) {
        return GasOptimizations.packAddressWithData(addr, data);
    }

    function unpackAddressWithData(
        uint256 packed
    ) external pure returns (address, uint96) {
        return GasOptimizations.unpackAddressWithData(packed);
    }

    // --- Bitmap ---
    function getBit(
        uint256 bitmap,
        uint256 index
    ) external pure returns (bool) {
        return GasOptimizations.getBit(bitmap, index);
    }

    function setBit(
        uint256 bitmap,
        uint256 index
    ) external pure returns (uint256) {
        return GasOptimizations.setBit(bitmap, index);
    }

    function clearBit(
        uint256 bitmap,
        uint256 index
    ) external pure returns (uint256) {
        return GasOptimizations.clearBit(bitmap, index);
    }

    function popCount(uint256 bitmap) external pure returns (uint256) {
        return GasOptimizations.popCount(bitmap);
    }

    // --- Array ---
    function binarySearch(
        bytes32[] memory arr,
        bytes32 val
    ) external pure returns (bool, uint256) {
        return GasOptimizations.binarySearch(arr, val);
    }

    function safeSum(uint256[] memory values) external pure returns (uint256) {
        return GasOptimizations.safeSum(values);
    }

    function safeIncrement(uint256 value) external pure returns (uint256) {
        return GasOptimizations.safeIncrement(value);
    }

    // --- Merkle ---
    function verifyMerkleProof(
        bytes32[] calldata proof,
        bytes32 root,
        bytes32 leaf
    ) external pure returns (bool) {
        return GasOptimizations.verifyMerkleProof(proof, root, leaf);
    }

    function computeMerkleRoot(
        bytes32[] memory leaves
    ) external pure returns (bytes32) {
        return GasOptimizations.computeMerkleRoot(leaves);
    }

    // --- Min/Max ---
    function max(uint256 a, uint256 b) external pure returns (uint256) {
        return GasOptimizations.max(a, b);
    }

    function min(uint256 a, uint256 b) external pure returns (uint256) {
        return GasOptimizations.min(a, b);
    }
}

/// @title Harness for BatchProcessing library (needs storage mappings)
contract BatchHarness {
    mapping(bytes32 => bool) public isSpentMapping;
    mapping(bytes32 => bytes32) public nullifierToCommitment;

    function setSpent(bytes32 nullifier) external {
        isSpentMapping[nullifier] = true;
    }

    function batchCheckNullifiers(
        bytes32[] calldata nullifiers
    ) external view returns (BatchProcessing.NullifierBatchResult memory) {
        return BatchProcessing.batchCheckNullifiers(nullifiers, isSpentMapping);
    }

    function batchRegisterNullifiers(
        bytes32[] calldata nullifiers,
        bytes32[] calldata commitments
    ) external returns (uint256, uint256) {
        return
            BatchProcessing.batchRegisterNullifiers(
                nullifiers,
                commitments,
                isSpentMapping,
                nullifierToCommitment
            );
    }

    function batchVerifyMerkleProofs(
        bytes32[] calldata leaves,
        bytes32[][] calldata proofs,
        bytes32 root
    ) external pure returns (uint256, uint256) {
        return BatchProcessing.batchVerifyMerkleProofs(leaves, proofs, root);
    }

    function batchHash(
        bytes32[] calldata a,
        bytes32[] calldata b
    ) external pure returns (bytes32[] memory) {
        return BatchProcessing.batchHash(a, b);
    }

    function allUnique(bytes32[] calldata values) external pure returns (bool) {
        return BatchProcessing.allUnique(values);
    }

    function safeSum(
        uint256[] calldata values
    ) external pure returns (uint256) {
        return BatchProcessing.safeSum(values);
    }
}

/**
 * @title LibraryTests
 * @notice Tests for GasOptimizations and BatchProcessing libraries
 */
contract LibraryTests is Test {
    GasOptHarness public gas_;
    BatchHarness public batch_;

    function setUp() public {
        gas_ = new GasOptHarness();
        batch_ = new BatchHarness();
    }

    // =========================================================================
    // GAS OPTIMIZATIONS — HASHING
    // =========================================================================

    function test_EfficientHash_Deterministic() public view {
        bytes32 a = bytes32(uint256(1));
        bytes32 b = bytes32(uint256(2));
        assertEq(gas_.efficientHash(a, b), gas_.efficientHash(a, b));
    }

    function test_EfficientHash_MatchesAbiEncode() public view {
        bytes32 a = bytes32(uint256(42));
        bytes32 b = bytes32(uint256(99));
        assertEq(gas_.efficientHash(a, b), keccak256(abi.encode(a, b)));
    }

    function test_EfficientHash3_Deterministic() public view {
        bytes32 a = bytes32(uint256(1));
        bytes32 b = bytes32(uint256(2));
        bytes32 c = bytes32(uint256(3));
        assertEq(gas_.efficientHash3(a, b, c), gas_.efficientHash3(a, b, c));
    }

    function test_EfficientHashAddressUint() public view {
        address addr = address(0xBEEF);
        uint256 val = 12345;
        bytes32 result = gas_.efficientHashAddressUint(addr, val);
        assertTrue(result != bytes32(0));
    }

    function test_BatchHash_Empty() public view {
        bytes32[] memory leaves = new bytes32[](0);
        bytes32[] memory result = gas_.batchHash(leaves);
        assertEq(result.length, 0);
    }

    function test_BatchHash_SingleLeaf() public view {
        bytes32[] memory leaves = new bytes32[](1);
        leaves[0] = bytes32(uint256(42));
        bytes32[] memory result = gas_.batchHash(leaves);
        assertEq(result.length, 1);
        // Single leaf hashes with itself
        assertEq(result[0], keccak256(abi.encode(leaves[0], leaves[0])));
    }

    function test_BatchHash_TwoLeaves() public view {
        bytes32[] memory leaves = new bytes32[](2);
        leaves[0] = bytes32(uint256(1));
        leaves[1] = bytes32(uint256(2));
        bytes32[] memory result = gas_.batchHash(leaves);
        assertEq(result.length, 1);
    }

    // =========================================================================
    // GAS OPTIMIZATIONS — PACKING
    // =========================================================================

    function test_PackUnpackUint128_Roundtrip() public view {
        uint128 a = 123456789;
        uint128 b = 987654321;
        uint256 packed = gas_.packUint128(a, b);
        (uint128 ua, uint128 ub) = gas_.unpackUint128(packed);
        assertEq(ua, a);
        assertEq(ub, b);
    }

    function testFuzz_PackUnpackUint128(uint128 a, uint128 b) public view {
        uint256 packed = gas_.packUint128(a, b);
        (uint128 ua, uint128 ub) = gas_.unpackUint128(packed);
        assertEq(ua, a);
        assertEq(ub, b);
    }

    function test_PackUnpackUint64_Roundtrip() public view {
        uint64 a = 1;
        uint64 b = 2;
        uint64 c = 3;
        uint64 d = 4;
        uint256 packed = gas_.packUint64(a, b, c, d);
        (uint64 ua, uint64 ub, uint64 uc, uint64 ud) = gas_.unpackUint64(
            packed
        );
        assertEq(ua, a);
        assertEq(ub, b);
        assertEq(uc, c);
        assertEq(ud, d);
    }

    function testFuzz_PackUnpackUint64(
        uint64 a,
        uint64 b,
        uint64 c,
        uint64 d
    ) public view {
        uint256 packed = gas_.packUint64(a, b, c, d);
        (uint64 ua, uint64 ub, uint64 uc, uint64 ud) = gas_.unpackUint64(
            packed
        );
        assertEq(ua, a);
        assertEq(ub, b);
        assertEq(uc, c);
        assertEq(ud, d);
    }

    function test_PackUnpackAddressData_Roundtrip() public view {
        address addr = address(0x1234567890AbcdEF1234567890aBcdef12345678);
        uint96 data = 42;
        uint256 packed = gas_.packAddressWithData(addr, data);
        (address ua, uint96 ud) = gas_.unpackAddressWithData(packed);
        assertEq(ua, addr);
        assertEq(ud, data);
    }

    function testFuzz_PackUnpackAddressData(
        address addr,
        uint96 data
    ) public view {
        uint256 packed = gas_.packAddressWithData(addr, data);
        (address ua, uint96 ud) = gas_.unpackAddressWithData(packed);
        assertEq(ua, addr);
        assertEq(ud, data);
    }

    // =========================================================================
    // GAS OPTIMIZATIONS — BITMAP
    // =========================================================================

    function test_SetAndGetBit() public view {
        uint256 bitmap = 0;
        bitmap = gas_.setBit(bitmap, 0);
        assertTrue(gas_.getBit(bitmap, 0));
        assertFalse(gas_.getBit(bitmap, 1));
    }

    function test_ClearBit() public view {
        uint256 bitmap = gas_.setBit(0, 5);
        assertTrue(gas_.getBit(bitmap, 5));
        bitmap = gas_.clearBit(bitmap, 5);
        assertFalse(gas_.getBit(bitmap, 5));
    }

    function test_Bitmap_IndexOutOfBounds() public {
        vm.expectRevert(GasOptimizations.IndexOutOfBounds.selector);
        gas_.getBit(0, 256);
    }

    function test_PopCount() public view {
        uint256 bitmap = 0;
        bitmap = gas_.setBit(bitmap, 0);
        bitmap = gas_.setBit(bitmap, 3);
        bitmap = gas_.setBit(bitmap, 7);
        assertEq(gas_.popCount(bitmap), 3);
    }

    function test_PopCount_Zero() public view {
        assertEq(gas_.popCount(0), 0);
    }

    function test_PopCount_AllSet() public view {
        assertEq(gas_.popCount(type(uint256).max), 256);
    }

    // =========================================================================
    // GAS OPTIMIZATIONS — BINARY SEARCH
    // =========================================================================

    function test_BinarySearch_Found() public view {
        bytes32[] memory arr = new bytes32[](5);
        for (uint256 i = 0; i < 5; i++) {
            arr[i] = bytes32(uint256(i * 10));
        }
        (bool found, uint256 index) = gas_.binarySearch(
            arr,
            bytes32(uint256(20))
        );
        assertTrue(found);
        assertEq(index, 2);
    }

    function test_BinarySearch_NotFound() public view {
        bytes32[] memory arr = new bytes32[](3);
        arr[0] = bytes32(uint256(1));
        arr[1] = bytes32(uint256(3));
        arr[2] = bytes32(uint256(5));
        (bool found, ) = gas_.binarySearch(arr, bytes32(uint256(2)));
        assertFalse(found);
    }

    function test_BinarySearch_Empty() public view {
        bytes32[] memory arr = new bytes32[](0);
        (bool found, ) = gas_.binarySearch(arr, bytes32(uint256(1)));
        assertFalse(found);
    }

    // =========================================================================
    // GAS OPTIMIZATIONS — MIN/MAX
    // =========================================================================

    function test_Max() public view {
        assertEq(gas_.max(5, 10), 10);
        assertEq(gas_.max(10, 5), 10);
        assertEq(gas_.max(7, 7), 7);
    }

    function test_Min() public view {
        assertEq(gas_.min(5, 10), 5);
        assertEq(gas_.min(10, 5), 5);
        assertEq(gas_.min(7, 7), 7);
    }

    // =========================================================================
    // GAS OPTIMIZATIONS — SAFE ARITHMETIC
    // =========================================================================

    function test_SafeSum() public view {
        uint256[] memory vals = new uint256[](3);
        vals[0] = 10;
        vals[1] = 20;
        vals[2] = 30;
        assertEq(gas_.safeSum(vals), 60);
    }

    function test_SafeIncrement() public view {
        assertEq(gas_.safeIncrement(0), 1);
        assertEq(gas_.safeIncrement(99), 100);
    }

    function test_SafeIncrement_MaxReverts() public {
        vm.expectRevert(GasOptimizations.Overflow.selector);
        gas_.safeIncrement(type(uint256).max);
    }

    // =========================================================================
    // GAS OPTIMIZATIONS — MERKLE
    // =========================================================================

    function test_ComputeMerkleRoot_SingleLeaf() public view {
        bytes32[] memory leaves = new bytes32[](1);
        leaves[0] = bytes32(uint256(42));
        assertEq(gas_.computeMerkleRoot(leaves), leaves[0]);
    }

    function test_ComputeMerkleRoot_Empty() public view {
        bytes32[] memory leaves = new bytes32[](0);
        assertEq(gas_.computeMerkleRoot(leaves), bytes32(0));
    }

    function test_ComputeMerkleRoot_TwoLeaves() public view {
        bytes32[] memory leaves = new bytes32[](2);
        leaves[0] = bytes32(uint256(1));
        leaves[1] = bytes32(uint256(2));
        bytes32 root = gas_.computeMerkleRoot(leaves);
        assertTrue(root != bytes32(0));
    }

    function test_VerifyMerkleProof_Valid() public view {
        // Build a simple 2-leaf tree and verify
        bytes32 leaf0 = bytes32(uint256(1));
        bytes32 leaf1 = bytes32(uint256(2));

        // Sort for consistent hashing
        bytes32 left = leaf0 < leaf1 ? leaf0 : leaf1;
        bytes32 right = leaf0 < leaf1 ? leaf1 : leaf0;
        bytes32 root = keccak256(abi.encode(left, right));

        bytes32[] memory proof = new bytes32[](1);
        proof[0] = leaf1;

        assertTrue(gas_.verifyMerkleProof(proof, root, leaf0));
    }

    // =========================================================================
    // BATCH PROCESSING — NULLIFIER CHECKS
    // =========================================================================

    function test_BatchCheckNullifiers_AllUnspent() public view {
        bytes32[] memory nullifiers = new bytes32[](3);
        nullifiers[0] = bytes32(uint256(1));
        nullifiers[1] = bytes32(uint256(2));
        nullifiers[2] = bytes32(uint256(3));

        BatchProcessing.NullifierBatchResult memory result = batch_
            .batchCheckNullifiers(nullifiers);
        assertTrue(result.allUnspent);
        assertEq(result.spentBitmap, 0);
        assertEq(result.checkedCount, 3);
    }

    function test_BatchCheckNullifiers_SomeSpent() public {
        bytes32 n1 = bytes32(uint256(1));
        bytes32 n2 = bytes32(uint256(2));
        bytes32 n3 = bytes32(uint256(3));

        batch_.setSpent(n2); // Mark middle one as spent

        bytes32[] memory nullifiers = new bytes32[](3);
        nullifiers[0] = n1;
        nullifiers[1] = n2;
        nullifiers[2] = n3;

        BatchProcessing.NullifierBatchResult memory result = batch_
            .batchCheckNullifiers(nullifiers);
        assertFalse(result.allUnspent);
        // Bit 1 should be set (n2 is spent)
        assertEq(result.spentBitmap & (1 << 1), (1 << 1));
        // Bits 0 and 2 should not be set
        assertEq(result.spentBitmap & (1 << 0), 0);
        assertEq(result.spentBitmap & (1 << 2), 0);
    }

    function test_BatchCheckNullifiers_Empty_Reverts() public {
        bytes32[] memory empty = new bytes32[](0);
        vm.expectRevert(BatchProcessing.BatchEmpty.selector);
        batch_.batchCheckNullifiers(empty);
    }

    // =========================================================================
    // BATCH PROCESSING — NULLIFIER REGISTRATION
    // =========================================================================

    function test_BatchRegister_Success() public {
        bytes32[] memory nullifiers = new bytes32[](3);
        bytes32[] memory commitments = new bytes32[](3);
        for (uint256 i = 0; i < 3; i++) {
            nullifiers[i] = keccak256(abi.encode("n", i));
            commitments[i] = keccak256(abi.encode("c", i));
        }

        (uint256 registered, uint256 failBitmap) = batch_
            .batchRegisterNullifiers(nullifiers, commitments);
        assertEq(registered, 3);
        assertEq(failBitmap, 0);

        // Verify they're now spent
        assertTrue(batch_.isSpentMapping(nullifiers[0]));
        assertTrue(batch_.isSpentMapping(nullifiers[1]));
        assertTrue(batch_.isSpentMapping(nullifiers[2]));
    }

    function test_BatchRegister_SkipsDuplicates() public {
        bytes32 dup = keccak256(abi.encode("dup"));
        batch_.setSpent(dup);

        bytes32[] memory nullifiers = new bytes32[](2);
        nullifiers[0] = dup;
        nullifiers[1] = keccak256(abi.encode("new"));
        bytes32[] memory commitments = new bytes32[](2);
        commitments[0] = bytes32(uint256(1));
        commitments[1] = bytes32(uint256(2));

        (uint256 registered, uint256 failBitmap) = batch_
            .batchRegisterNullifiers(nullifiers, commitments);
        assertEq(registered, 1);
        // Bit 0 should be set (duplicate)
        assertEq(failBitmap & 1, 1);
    }

    function test_BatchRegister_NoCommitments() public {
        bytes32[] memory nullifiers = new bytes32[](2);
        nullifiers[0] = keccak256(abi.encode("a"));
        nullifiers[1] = keccak256(abi.encode("b"));
        bytes32[] memory empty = new bytes32[](0);

        (uint256 registered, ) = batch_.batchRegisterNullifiers(
            nullifiers,
            empty
        );
        assertEq(registered, 2);
    }

    function test_BatchRegister_LengthMismatch_Reverts() public {
        bytes32[] memory nullifiers = new bytes32[](2);
        bytes32[] memory commitments = new bytes32[](3);
        vm.expectRevert(BatchProcessing.ArrayLengthMismatch.selector);
        batch_.batchRegisterNullifiers(nullifiers, commitments);
    }

    // =========================================================================
    // BATCH PROCESSING — BATCH HASH
    // =========================================================================

    function test_BatchHash_Correct() public view {
        bytes32[] memory a = new bytes32[](2);
        bytes32[] memory b = new bytes32[](2);
        a[0] = bytes32(uint256(1));
        a[1] = bytes32(uint256(2));
        b[0] = bytes32(uint256(3));
        b[1] = bytes32(uint256(4));

        bytes32[] memory result = batch_.batchHash(a, b);
        assertEq(result.length, 2);
        assertEq(result[0], GasOptimizations.efficientHash(a[0], b[0]));
        assertEq(result[1], GasOptimizations.efficientHash(a[1], b[1]));
    }

    // =========================================================================
    // BATCH PROCESSING — ALL UNIQUE
    // =========================================================================

    function test_AllUnique_True() public view {
        bytes32[] memory vals = new bytes32[](3);
        vals[0] = bytes32(uint256(1));
        vals[1] = bytes32(uint256(2));
        vals[2] = bytes32(uint256(3));
        assertTrue(batch_.allUnique(vals));
    }

    function test_AllUnique_False() public view {
        bytes32[] memory vals = new bytes32[](3);
        vals[0] = bytes32(uint256(1));
        vals[1] = bytes32(uint256(2));
        vals[2] = bytes32(uint256(1)); // Duplicate
        assertFalse(batch_.allUnique(vals));
    }

    function test_AllUnique_SingleElement() public view {
        bytes32[] memory vals = new bytes32[](1);
        vals[0] = bytes32(uint256(42));
        assertTrue(batch_.allUnique(vals));
    }

    function test_AllUnique_Empty() public view {
        bytes32[] memory vals = new bytes32[](0);
        assertTrue(batch_.allUnique(vals));
    }

    // =========================================================================
    // BATCH PROCESSING — SAFE SUM
    // =========================================================================

    function test_SafeSum_Correct() public view {
        uint256[] memory vals = new uint256[](3);
        vals[0] = 100;
        vals[1] = 200;
        vals[2] = 300;
        assertEq(batch_.safeSum(vals), 600);
    }

    // =========================================================================
    // FUZZ TESTS
    // =========================================================================

    function testFuzz_EfficientHash_Deterministic(
        bytes32 a,
        bytes32 b
    ) public view {
        assertEq(gas_.efficientHash(a, b), gas_.efficientHash(a, b));
    }

    function testFuzz_SetClearBit(uint8 idx) public view {
        uint256 bitmap = gas_.setBit(0, idx);
        assertTrue(gas_.getBit(bitmap, idx));
        bitmap = gas_.clearBit(bitmap, idx);
        assertFalse(gas_.getBit(bitmap, idx));
    }

    function testFuzz_PopCount(uint256 bitmap) public view {
        uint256 count = gas_.popCount(bitmap);
        assertTrue(count <= 256);
    }

    function testFuzz_ComputeMerkleRoot_Deterministic(
        bytes32 a,
        bytes32 b
    ) public view {
        bytes32[] memory leaves = new bytes32[](2);
        leaves[0] = a;
        leaves[1] = b;
        bytes32 root1 = gas_.computeMerkleRoot(leaves);

        leaves[0] = a;
        leaves[1] = b;
        bytes32 root2 = gas_.computeMerkleRoot(leaves);
        assertEq(root1, root2);
    }
}
