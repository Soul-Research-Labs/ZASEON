// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/libraries/VerifierGasUtils.sol";

/// @dev Harness exposing internal library functions for testing
contract GasUtilsHarness {
    function toBytes32Array(
        uint256[] calldata inputs
    ) external pure returns (bytes32[] memory) {
        return VerifierGasUtils.toBytes32Array(inputs);
    }

    function toUint256Array(
        bytes32[] calldata inputs
    ) external pure returns (uint256[] memory) {
        return VerifierGasUtils.toUint256Array(inputs);
    }

    function validateFieldElements(uint256[] calldata inputs) external pure {
        VerifierGasUtils.validateFieldElements(inputs);
    }

    function isValidFieldElement(uint256 value) external pure returns (bool) {
        return VerifierGasUtils.isValidFieldElement(value);
    }

    function computeProofHash(
        bytes calldata proof,
        uint256[] calldata publicInputs
    ) external pure returns (bytes32) {
        return VerifierGasUtils.computeProofHash(proof, publicInputs);
    }

    function computeProofHashB32(
        bytes calldata proof,
        bytes32[] calldata publicInputs
    ) external pure returns (bytes32) {
        return VerifierGasUtils.computeProofHashB32(proof, publicInputs);
    }

    function ecAdd(
        uint256 x1,
        uint256 y1,
        uint256 x2,
        uint256 y2
    ) external view returns (uint256, uint256) {
        return VerifierGasUtils.ecAdd(x1, y1, x2, y2);
    }

    function ecMul(
        uint256 x,
        uint256 y,
        uint256 s
    ) external view returns (uint256, uint256) {
        return VerifierGasUtils.ecMul(x, y, s);
    }

    function batchChallenge(
        bytes32[] memory proofHashes
    ) external pure returns (uint256) {
        return VerifierGasUtils.batchChallenge(proofHashes);
    }

    function computePowers(
        uint256 challenge,
        uint256 count
    ) external pure returns (uint256[] memory) {
        return VerifierGasUtils.computePowers(challenge, count);
    }

    function BN254_SCALAR_FIELD() external pure returns (uint256) {
        return VerifierGasUtils.BN254_SCALAR_FIELD;
    }
}

contract VerifierGasUtilsTest is Test {
    GasUtilsHarness h;
    uint256 constant FIELD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    /// @dev BN254 generator point G1
    uint256 constant G1_X = 1;
    uint256 constant G1_Y = 2;

    function setUp() public {
        h = new GasUtilsHarness();
    }

    // ── Field constant ──

    function test_fieldConstant() public view {
        assertEq(h.BN254_SCALAR_FIELD(), FIELD);
    }

    // ── Array conversion ──

    function test_toBytes32Array() public view {
        uint256[] memory uints = new uint256[](3);
        uints[0] = 1;
        uints[1] = 2;
        uints[2] = type(uint256).max;
        bytes32[] memory result = h.toBytes32Array(uints);
        assertEq(result.length, 3);
        assertEq(uint256(result[0]), 1);
        assertEq(uint256(result[2]), type(uint256).max);
    }

    function test_toUint256Array() public view {
        bytes32[] memory b32s = new bytes32[](2);
        b32s[0] = bytes32(uint256(42));
        b32s[1] = bytes32(uint256(99));
        uint256[] memory result = h.toUint256Array(b32s);
        assertEq(result.length, 2);
        assertEq(result[0], 42);
        assertEq(result[1], 99);
    }

    function test_roundtrip_uint256_bytes32() public view {
        uint256[] memory original = new uint256[](2);
        original[0] = 123;
        original[1] = 456;
        bytes32[] memory mid = h.toBytes32Array(original);
        uint256[] memory back = h.toUint256Array(mid);
        assertEq(back[0], original[0]);
        assertEq(back[1], original[1]);
    }

    function test_emptyArray() public view {
        uint256[] memory empty = new uint256[](0);
        bytes32[] memory result = h.toBytes32Array(empty);
        assertEq(result.length, 0);
    }

    // ── Field element validation ──

    function test_isValidFieldElement_zero() public view {
        assertTrue(h.isValidFieldElement(0));
    }

    function test_isValidFieldElement_one() public view {
        assertTrue(h.isValidFieldElement(1));
    }

    function test_isValidFieldElement_maxValid() public view {
        assertTrue(h.isValidFieldElement(FIELD - 1));
    }

    function test_isValidFieldElement_field() public view {
        assertFalse(h.isValidFieldElement(FIELD));
    }

    function test_isValidFieldElement_overField() public view {
        assertFalse(h.isValidFieldElement(FIELD + 1));
    }

    function test_isValidFieldElement_maxUint() public view {
        assertFalse(h.isValidFieldElement(type(uint256).max));
    }

    function test_validateFieldElements_valid() public view {
        uint256[] memory inputs = new uint256[](3);
        inputs[0] = 0;
        inputs[1] = 42;
        inputs[2] = FIELD - 1;
        h.validateFieldElements(inputs); // should not revert
    }

    function test_validateFieldElements_outOfBounds() public {
        uint256[] memory inputs = new uint256[](2);
        inputs[0] = 1;
        inputs[1] = FIELD; // invalid
        vm.expectRevert();
        h.validateFieldElements(inputs);
    }

    // ── Proof hash ──

    function test_computeProofHash_deterministic() public view {
        bytes memory proof = hex"aabb";
        uint256[] memory inputs = new uint256[](1);
        inputs[0] = 42;
        bytes32 hash1 = h.computeProofHash(proof, inputs);
        bytes32 hash2 = h.computeProofHash(proof, inputs);
        assertEq(hash1, hash2);
        assertTrue(hash1 != bytes32(0));
    }

    function test_computeProofHash_differentInputs() public view {
        bytes memory proof = hex"aabb";
        uint256[] memory inputs1 = new uint256[](1);
        inputs1[0] = 1;
        uint256[] memory inputs2 = new uint256[](1);
        inputs2[0] = 2;
        assertTrue(
            h.computeProofHash(proof, inputs1) !=
                h.computeProofHash(proof, inputs2)
        );
    }

    function test_computeProofHashB32_deterministic() public view {
        bytes memory proof = hex"aabb";
        bytes32[] memory inputs = new bytes32[](1);
        inputs[0] = bytes32(uint256(42));
        bytes32 hash1 = h.computeProofHashB32(proof, inputs);
        bytes32 hash2 = h.computeProofHashB32(proof, inputs);
        assertEq(hash1, hash2);
    }

    // ── EC operations (BN254 precompiles) ──

    function test_ecAdd_identity() public view {
        // G1 + 0 = G1 (point at infinity addition)
        // ecAdd(1, 2, 0, 0) should return (1, 2)
        (uint256 rx, uint256 ry) = h.ecAdd(G1_X, G1_Y, 0, 0);
        assertEq(rx, G1_X);
        assertEq(ry, G1_Y);
    }

    function test_ecMul_byOne() public view {
        // 1 * G = G
        (uint256 rx, uint256 ry) = h.ecMul(G1_X, G1_Y, 1);
        assertEq(rx, G1_X);
        assertEq(ry, G1_Y);
    }

    function test_ecMul_byZero() public view {
        // 0 * G = identity (0, 0)
        (uint256 rx, uint256 ry) = h.ecMul(G1_X, G1_Y, 0);
        assertEq(rx, 0);
        assertEq(ry, 0);
    }

    function test_ecAdd_selfDouble() public view {
        // G + G should equal 2*G
        (uint256 addX, uint256 addY) = h.ecAdd(G1_X, G1_Y, G1_X, G1_Y);
        (uint256 mulX, uint256 mulY) = h.ecMul(G1_X, G1_Y, 2);
        assertEq(addX, mulX);
        assertEq(addY, mulY);
    }

    // ── Batch challenge ──

    function test_batchChallenge_deterministic() public view {
        bytes32[] memory hashes = new bytes32[](2);
        hashes[0] = keccak256("proof1");
        hashes[1] = keccak256("proof2");
        uint256 c1 = h.batchChallenge(hashes);
        uint256 c2 = h.batchChallenge(hashes);
        assertEq(c1, c2);
    }

    function test_batchChallenge_differentHashes() public view {
        bytes32[] memory h1 = new bytes32[](1);
        h1[0] = keccak256("a");
        bytes32[] memory h2 = new bytes32[](1);
        h2[0] = keccak256("b");
        assertTrue(h.batchChallenge(h1) != h.batchChallenge(h2));
    }

    // ── Compute powers ──

    function test_computePowers_count3() public view {
        uint256[] memory powers = h.computePowers(5, 3);
        assertEq(powers.length, 3);
        // powers[0] = 1, powers[1] = 5, powers[2] = 25 (mod field)
        assertEq(powers[0], 1);
        assertEq(powers[1], 5);
        assertEq(powers[2], 25);
    }

    function test_computePowers_countZero() public view {
        uint256[] memory powers = h.computePowers(99, 0);
        assertEq(powers.length, 0);
    }

    function test_computePowers_countOne() public view {
        uint256[] memory powers = h.computePowers(99, 1);
        assertEq(powers.length, 1);
        assertEq(powers[0], 1); // challenge^0 = 1
    }

    // ── Fuzz: field element boundary ──

    function testFuzz_isValidFieldElement(uint256 value) public view {
        bool valid = h.isValidFieldElement(value);
        assertEq(valid, value < FIELD);
    }
}
