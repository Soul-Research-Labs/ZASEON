// SPDX-License-Identifier: MIT
// Coverage stub – assembly-free version of GasOptimizations library
pragma solidity ^0.8.20;

library GasOptimizations {
    error ArrayLengthMismatch();
    error IndexOutOfBounds();
    error Overflow();
    error ZeroValue();

    function efficientHash(
        bytes32 a,
        bytes32 b
    ) internal pure returns (bytes32 result) {
        result = keccak256(abi.encodePacked(a, b));
    }

    function efficientHash3(
        bytes32 a,
        bytes32 b,
        bytes32 c
    ) internal pure returns (bytes32 result) {
        result = keccak256(abi.encodePacked(a, b, c));
    }

    function efficientHashAddressUint(
        address addr,
        uint256 value
    ) internal pure returns (bytes32 result) {
        result = keccak256(abi.encodePacked(addr, value));
    }

    function batchHash(
        bytes32[] memory leaves
    ) internal pure returns (bytes32[] memory hashes) {
        uint256 len = leaves.length / 2;
        if (leaves.length % 2 != 0) len++;
        hashes = new bytes32[](len);
        for (uint256 i = 0; i < len; i++) {
            uint256 left = i * 2;
            uint256 right = left + 1 < leaves.length ? left + 1 : left;
            hashes[i] = keccak256(
                abi.encodePacked(leaves[left], leaves[right])
            );
        }
    }

    function packUint128(
        uint128 a,
        uint128 b
    ) internal pure returns (uint256 packed) {
        packed = (uint256(a) << 128) | uint256(b);
    }

    function unpackUint128(
        uint256 packed
    ) internal pure returns (uint128 a, uint128 b) {
        a = uint128(packed >> 128);
        b = uint128(packed);
    }

    function packUint64(
        uint64 a,
        uint64 b,
        uint64 c,
        uint64 d
    ) internal pure returns (uint256 packed) {
        packed =
            (uint256(a) << 192) |
            (uint256(b) << 128) |
            (uint256(c) << 64) |
            uint256(d);
    }

    function unpackUint64(
        uint256 packed
    ) internal pure returns (uint64 a, uint64 b, uint64 c, uint64 d) {
        a = uint64(packed >> 192);
        b = uint64(packed >> 128);
        c = uint64(packed >> 64);
        d = uint64(packed);
    }

    function packAddressWithData(
        address addr,
        uint96 data
    ) internal pure returns (uint256 packed) {
        packed = (uint256(uint160(addr)) << 96) | uint256(data);
    }

    function unpackAddressWithData(
        uint256 packed
    ) internal pure returns (address addr, uint96 data) {
        addr = address(uint160(packed >> 96));
        data = uint96(packed);
    }

    function getBit(
        uint256 bitmap,
        uint256 index
    ) internal pure returns (bool) {
        return (bitmap >> index) & 1 == 1;
    }

    function setBit(
        uint256 bitmap,
        uint256 index
    ) internal pure returns (uint256) {
        return bitmap | (1 << index);
    }

    function clearBit(
        uint256 bitmap,
        uint256 index
    ) internal pure returns (uint256) {
        return bitmap & ~(1 << index);
    }

    function popCount(uint256 bitmap) internal pure returns (uint256 count) {
        while (bitmap != 0) {
            bitmap &= bitmap - 1;
            count++;
        }
    }

    function binarySearch(
        bytes32[] memory sortedArray,
        bytes32 value
    ) internal pure returns (bool found, uint256 index) {
        if (sortedArray.length == 0) return (false, 0);
        uint256 lo = 0;
        uint256 hi = sortedArray.length - 1;
        while (lo <= hi) {
            uint256 mid = (lo + hi) / 2;
            if (sortedArray[mid] == value) return (true, mid);
            if (sortedArray[mid] < value) lo = mid + 1;
            else {
                if (mid == 0) break;
                hi = mid - 1;
            }
        }
        return (false, 0);
    }

    function safeSum(
        uint256[] memory values
    ) internal pure returns (uint256 total) {
        for (uint256 i = 0; i < values.length; i++) {
            total += values[i];
        }
    }

    function copyCalldataArray(
        bytes32[] calldata source
    ) internal pure returns (bytes32[] memory dest) {
        dest = new bytes32[](source.length);
        for (uint256 i = 0; i < source.length; i++) {
            dest[i] = source[i];
        }
    }

    function max(uint256 a, uint256 b) internal pure returns (uint256 result) {
        result = a >= b ? a : b;
    }

    function min(uint256 a, uint256 b) internal pure returns (uint256 result) {
        result = a <= b ? a : b;
    }

    function safeIncrement(uint256 value) internal pure returns (uint256) {
        return value + 1;
    }

    function unsafeIncrement(uint256 value) internal pure returns (uint256) {
        return value + 1;
    }

    function verifyMerkleProof(
        bytes32[] calldata proof,
        bytes32 root,
        bytes32 leaf
    ) internal pure returns (bool) {
        bytes32 computedHash = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 proofElement = proof[i];
            if (computedHash <= proofElement) {
                computedHash = keccak256(
                    abi.encodePacked(computedHash, proofElement)
                );
            } else {
                computedHash = keccak256(
                    abi.encodePacked(proofElement, computedHash)
                );
            }
        }
        return computedHash == root;
    }

    function computeMerkleRoot(
        bytes32[] memory leaves
    ) internal pure returns (bytes32) {
        if (leaves.length == 0) return bytes32(0);
        if (leaves.length == 1) return leaves[0];
        bytes32[] memory next = batchHash(leaves);
        return computeMerkleRoot(next);
    }
}
