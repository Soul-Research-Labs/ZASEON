// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/internal/helpers/StackOptimizedHelper.sol";

/// @dev Harness to expose internal library functions
contract StackOptimizedHarness {
    function computeDomainHash(
        bytes32 domainSeparator,
        bytes32 structHash
    ) external pure returns (bytes32) {
        return StackOptimizedHelper.computeDomainHash(domainSeparator, structHash);
    }

    function computeLockId(
        bytes32 stateCommitment,
        bytes32 predicateHash,
        bytes32 domainSeparator,
        address creator,
        uint256 nonce
    ) external pure returns (bytes32) {
        return StackOptimizedHelper.computeLockId(
            stateCommitment, predicateHash, domainSeparator, creator, nonce
        );
    }

    function computeNullifier(
        bytes32 secret,
        bytes32 domainSeparator,
        bytes32 transitionId
    ) external pure returns (bytes32) {
        return StackOptimizedHelper.computeNullifier(secret, domainSeparator, transitionId);
    }

    function validateProofStructure(
        bytes memory proofData,
        uint256 minLength,
        uint256 maxLength
    ) external pure returns (bool) {
        return StackOptimizedHelper.validateProofStructure(proofData, minLength, maxLength);
    }

    function isTimestampValid(
        uint256 timestamp,
        uint256 minTime,
        uint256 maxTime
    ) external pure returns (bool) {
        return StackOptimizedHelper.isTimestampValid(timestamp, minTime, maxTime);
    }

    function isDeadlineExpired(
        uint256 deadline,
        uint256 buffer
    ) external view returns (bool) {
        return StackOptimizedHelper.isDeadlineExpired(deadline, buffer);
    }

    function packUint128(uint128 high, uint128 low) external pure returns (uint256) {
        return StackOptimizedHelper.packUint128(high, low);
    }

    function unpackUint128(uint256 packed) external pure returns (uint128, uint128) {
        return StackOptimizedHelper.unpackUint128(packed);
    }

    function packAddressUint96(address addr, uint96 value) external pure returns (uint256) {
        return StackOptimizedHelper.packAddressUint96(addr, value);
    }

    function computeMerkleRoot(
        bytes32 leaf,
        bytes32[] memory path,
        uint256 indices
    ) external pure returns (bytes32) {
        return StackOptimizedHelper.computeMerkleRoot(leaf, path, indices);
    }

    function safeGet(bytes32[] memory arr, uint256 index) external pure returns (bytes32) {
        return StackOptimizedHelper.safeGet(arr, index);
    }
}

contract StackOptimizedHelperTest is Test {
    StackOptimizedHarness lib;

    function setUp() public {
        lib = new StackOptimizedHarness();
    }

    /* ══════════════════════════════════════════════════
              COMPUTE DOMAIN HASH (EIP-712 style)
       ══════════════════════════════════════════════════ */

    function test_computeDomainHash_deterministic() public view {
        bytes32 domain = bytes32(uint256(1));
        bytes32 structH = bytes32(uint256(2));
        assertEq(
            lib.computeDomainHash(domain, structH),
            lib.computeDomainHash(domain, structH)
        );
    }

    function test_computeDomainHash_followsEIP712() public view {
        bytes32 domain = bytes32(uint256(0xAABB));
        bytes32 structH = bytes32(uint256(0xCCDD));
        bytes32 expected = keccak256(abi.encodePacked("\x19\x01", domain, structH));
        assertEq(lib.computeDomainHash(domain, structH), expected);
    }

    function testFuzz_computeDomainHash(bytes32 d, bytes32 s) public view {
        bytes32 expected = keccak256(abi.encodePacked("\x19\x01", d, s));
        assertEq(lib.computeDomainHash(d, s), expected);
    }

    /* ══════════════════════════════════════════════════
              COMPUTE LOCK ID
       ══════════════════════════════════════════════════ */

    function test_computeLockId_deterministic() public view {
        bytes32 state = bytes32(uint256(1));
        bytes32 pred = bytes32(uint256(2));
        bytes32 domain = bytes32(uint256(3));
        address creator = address(0xBEEF);
        uint256 nonce = 42;

        assertEq(
            lib.computeLockId(state, pred, domain, creator, nonce),
            lib.computeLockId(state, pred, domain, creator, nonce)
        );
    }

    function test_computeLockId_differentNonces() public view {
        bytes32 state = bytes32(uint256(1));
        bytes32 pred = bytes32(uint256(2));
        bytes32 domain = bytes32(uint256(3));
        address creator = address(0xBEEF);

        assertNotEq(
            lib.computeLockId(state, pred, domain, creator, 0),
            lib.computeLockId(state, pred, domain, creator, 1)
        );
    }

    function test_computeLockId_matchesKeccak() public view {
        bytes32 state = bytes32(uint256(1));
        bytes32 pred = bytes32(uint256(2));
        bytes32 domain = bytes32(uint256(3));
        address creator = address(0xBEEF);
        uint256 nonce = 42;
        bytes32 expected = keccak256(abi.encodePacked(state, pred, domain, creator, nonce));
        assertEq(lib.computeLockId(state, pred, domain, creator, nonce), expected);
    }

    /* ══════════════════════════════════════════════════
              COMPUTE NULLIFIER
       ══════════════════════════════════════════════════ */

    function test_computeNullifier_deterministic() public view {
        bytes32 secret = bytes32(uint256(0xAA));
        bytes32 domain = bytes32(uint256(0xBB));
        bytes32 transition = bytes32(uint256(0xCC));
        assertEq(
            lib.computeNullifier(secret, domain, transition),
            lib.computeNullifier(secret, domain, transition)
        );
    }

    function test_computeNullifier_matchesKeccak() public view {
        bytes32 secret = bytes32(uint256(0xAA));
        bytes32 domain = bytes32(uint256(0xBB));
        bytes32 transition = bytes32(uint256(0xCC));
        bytes32 expected = keccak256(abi.encodePacked(secret, domain, transition));
        assertEq(lib.computeNullifier(secret, domain, transition), expected);
    }

    function testFuzz_computeNullifier(bytes32 s, bytes32 d, bytes32 t) public view {
        bytes32 expected = keccak256(abi.encodePacked(s, d, t));
        assertEq(lib.computeNullifier(s, d, t), expected);
    }

    /* ══════════════════════════════════════════════════
              VALIDATE PROOF STRUCTURE
       ══════════════════════════════════════════════════ */

    function test_validateProofStructure_valid() public view {
        bytes memory proof = new bytes(256);
        assertTrue(lib.validateProofStructure(proof, 100, 500));
    }

    function test_validateProofStructure_tooShort() public view {
        bytes memory proof = new bytes(50);
        assertFalse(lib.validateProofStructure(proof, 100, 500));
    }

    function test_validateProofStructure_tooLong() public view {
        bytes memory proof = new bytes(600);
        assertFalse(lib.validateProofStructure(proof, 100, 500));
    }

    function test_validateProofStructure_exactMin() public view {
        bytes memory proof = new bytes(100);
        assertTrue(lib.validateProofStructure(proof, 100, 500));
    }

    function test_validateProofStructure_exactMax() public view {
        bytes memory proof = new bytes(500);
        assertTrue(lib.validateProofStructure(proof, 100, 500));
    }

    /* ══════════════════════════════════════════════════
              TIMESTAMP VALIDATION
       ══════════════════════════════════════════════════ */

    function test_isTimestampValid_inRange() public view {
        assertTrue(lib.isTimestampValid(500, 100, 1000));
    }

    function test_isTimestampValid_atMin() public view {
        assertTrue(lib.isTimestampValid(100, 100, 1000));
    }

    function test_isTimestampValid_atMax() public view {
        assertTrue(lib.isTimestampValid(1000, 100, 1000));
    }

    function test_isTimestampValid_belowMin() public view {
        assertFalse(lib.isTimestampValid(99, 100, 1000));
    }

    function test_isTimestampValid_aboveMax() public view {
        assertFalse(lib.isTimestampValid(1001, 100, 1000));
    }

    /* ══════════════════════════════════════════════════
              DEADLINE EXPIRED
       ══════════════════════════════════════════════════ */

    function test_isDeadlineExpired_notExpired() public {
        vm.warp(1000);
        assertFalse(lib.isDeadlineExpired(2000, 0));
    }

    function test_isDeadlineExpired_expired() public {
        vm.warp(3000);
        assertTrue(lib.isDeadlineExpired(2000, 0));
    }

    function test_isDeadlineExpired_withBuffer() public {
        vm.warp(2050);
        // deadline=2000, buffer=100 => expires at 2100
        assertFalse(lib.isDeadlineExpired(2000, 100));
    }

    function test_isDeadlineExpired_bufferExceeded() public {
        vm.warp(2200);
        assertTrue(lib.isDeadlineExpired(2000, 100));
    }

    /* ══════════════════════════════════════════════════
              PACKING UTILITIES
       ══════════════════════════════════════════════════ */

    function test_packUnpackUint128_roundTrip() public view {
        uint128 high = 12345;
        uint128 low = 67890;
        uint256 packed = lib.packUint128(high, low);
        (uint128 h, uint128 l) = lib.unpackUint128(packed);
        assertEq(h, high);
        assertEq(l, low);
    }

    function testFuzz_packUnpackUint128(uint128 high, uint128 low) public view {
        uint256 packed = lib.packUint128(high, low);
        (uint128 h, uint128 l) = lib.unpackUint128(packed);
        assertEq(h, high);
        assertEq(l, low);
    }

    function test_packAddressUint96() public view {
        address addr = address(0xBEEF);
        uint96 val = 42;
        uint256 packed = lib.packAddressUint96(addr, val);
        assertGt(packed, 0);
    }

    /* ══════════════════════════════════════════════════
              MERKLE ROOT
       ══════════════════════════════════════════════════ */

    function test_computeMerkleRoot_singleLeaf() public view {
        bytes32 leaf = bytes32(uint256(0xABCD));
        bytes32[] memory path = new bytes32[](0);
        bytes32 root = lib.computeMerkleRoot(leaf, path, 0);
        assertEq(root, leaf);
    }

    function test_computeMerkleRoot_withPath() public view {
        bytes32 leaf = bytes32(uint256(1));
        bytes32[] memory path = new bytes32[](1);
        path[0] = bytes32(uint256(2));

        // indices=0 means left, so hash(leaf, sibling)
        bytes32 rootLeft = lib.computeMerkleRoot(leaf, path, 0);
        assertEq(rootLeft, keccak256(abi.encodePacked(leaf, path[0])));

        // indices=1 means right, so hash(sibling, leaf)
        bytes32 rootRight = lib.computeMerkleRoot(leaf, path, 1);
        assertEq(rootRight, keccak256(abi.encodePacked(path[0], leaf)));

        assertNotEq(rootLeft, rootRight);
    }

    function test_computeMerkleRoot_deterministic() public view {
        bytes32 leaf = bytes32(uint256(42));
        bytes32[] memory path = new bytes32[](2);
        path[0] = bytes32(uint256(100));
        path[1] = bytes32(uint256(200));
        assertEq(
            lib.computeMerkleRoot(leaf, path, 0),
            lib.computeMerkleRoot(leaf, path, 0)
        );
    }

    /* ══════════════════════════════════════════════════
              SAFE GET
       ══════════════════════════════════════════════════ */

    function test_safeGet_validIndex() public view {
        bytes32[] memory arr = new bytes32[](3);
        arr[0] = bytes32(uint256(10));
        arr[1] = bytes32(uint256(20));
        arr[2] = bytes32(uint256(30));
        assertEq(lib.safeGet(arr, 1), bytes32(uint256(20)));
    }

    function test_safeGet_outOfBounds() public view {
        bytes32[] memory arr = new bytes32[](2);
        arr[0] = bytes32(uint256(10));
        arr[1] = bytes32(uint256(20));
        assertEq(lib.safeGet(arr, 5), bytes32(0));
    }

    function test_safeGet_emptyArray() public view {
        bytes32[] memory arr = new bytes32[](0);
        assertEq(lib.safeGet(arr, 0), bytes32(0));
    }
}
