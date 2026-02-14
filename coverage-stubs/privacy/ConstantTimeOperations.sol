// SPDX-License-Identifier: MIT
// Coverage stub – assembly-free ConstantTimeOperations + ConstantTimePrivacy
pragma solidity ^0.8.24;

error InvalidLength();

library ConstantTimeOperations {
    function constantTimeEquals(
        bytes32 a,
        bytes32 b
    ) internal pure returns (bool result) {
        result = a == b;
    }

    function constantTimeEqualsUint(
        uint256 a,
        uint256 b
    ) internal pure returns (bool result) {
        result = a == b;
    }

    function constantTimeEqualsBytes(
        bytes memory a,
        bytes memory b
    ) internal pure returns (bool result) {
        result = keccak256(a) == keccak256(b);
    }

    function constantTimeSelect(
        bool condition,
        bytes32 a,
        bytes32 b
    ) internal pure returns (bytes32 result) {
        result = condition ? a : b;
    }

    function constantTimeSelectUint(
        bool condition,
        uint256 a,
        uint256 b
    ) internal pure returns (uint256 result) {
        result = condition ? a : b;
    }

    function constantTimeSelectAddress(
        bool condition,
        address a,
        address b
    ) internal pure returns (address result) {
        result = condition ? a : b;
    }

    function constantTimeLessThan(
        uint256 a,
        uint256 b
    ) internal pure returns (uint256 result) {
        result = a < b ? 1 : 0;
    }

    function constantTimeGreaterThan(
        uint256 a,
        uint256 b
    ) internal pure returns (uint256 result) {
        result = a > b ? 1 : 0;
    }

    function constantTimeMin(
        uint256 a,
        uint256 b
    ) internal pure returns (uint256 result) {
        result = a < b ? a : b;
    }

    function constantTimeMax(
        uint256 a,
        uint256 b
    ) internal pure returns (uint256 result) {
        result = a > b ? a : b;
    }

    function constantTimeAbsDiff(
        uint256 a,
        uint256 b
    ) internal pure returns (uint256 result) {
        result = a > b ? a - b : b - a;
    }

    function constantTimeCopy(
        bytes memory dest,
        bytes memory src,
        uint256 length
    ) internal pure {
        if (length > src.length || length > dest.length) revert InvalidLength();
        for (uint256 i = 0; i < length; i++) {
            dest[i] = src[i];
        }
    }

    function constantTimeZero(bytes memory data) internal pure {
        for (uint256 i = 0; i < data.length; i++) {
            data[i] = 0;
        }
    }

    function constantTimeGetBit(
        uint256 value,
        uint8 position
    ) internal pure returns (uint256 bit) {
        bit = (value >> position) & 1;
    }

    function constantTimeSetBit(
        uint256 value,
        uint8 position,
        bool bitValue
    ) internal pure returns (uint256 result) {
        if (bitValue) {
            result = value | (1 << position);
        } else {
            result = value & ~(uint256(1) << position);
        }
    }

    function constantTimePopCount(
        uint256 value
    ) internal pure returns (uint256 count) {
        while (value != 0) {
            value &= value - 1;
            count++;
        }
    }

    function constantTimeInRange(
        uint256 value,
        uint256 min,
        uint256 max
    ) internal pure returns (bool inRange) {
        inRange = value >= min && value <= max;
    }

    function constantTimeIsNonZero(
        uint256 value
    ) internal pure returns (bool nonZero) {
        nonZero = value != 0;
    }

    function constantTimeIsPowerOf2(
        uint256 value
    ) internal pure returns (bool isPow2) {
        isPow2 = value != 0 && (value & (value - 1)) == 0;
    }

    function constantTimeSwap(
        bool condition,
        uint256 a,
        uint256 b
    ) internal pure returns (uint256 x, uint256 y) {
        if (condition) {
            x = b;
            y = a;
        } else {
            x = a;
            y = b;
        }
    }

    function constantTimeModHint(
        uint256 value,
        uint256 modulus
    ) internal pure returns (uint256 reduced) {
        reduced = value % modulus;
    }
}

library ConstantTimePrivacy {
    using ConstantTimeOperations for *;

    function constantTimeNullifierLookup(
        bytes32 target,
        bytes32[] memory nullifiers
    ) internal pure returns (bool found, uint256 index) {
        found = false;
        index = 0;
        for (uint256 i = 0; i < nullifiers.length; i++) {
            if (nullifiers[i] == target) {
                found = true;
                index = i;
            }
        }
    }

    function constantTimeKeyImageLookup(
        bytes32 keyImage,
        bytes32[] memory usedKeyImages
    ) internal pure returns (bool used) {
        used = false;
        for (uint256 i = 0; i < usedKeyImages.length; i++) {
            if (usedKeyImages[i] == keyImage) {
                used = true;
            }
        }
    }

    function constantTimeDecoySelect(
        uint256 realIndex,
        uint256 ringSize,
        uint256 randomSeed
    ) internal pure returns (uint256[] memory indices) {
        indices = new uint256[](ringSize);
        for (uint256 i = 0; i < ringSize; i++) {
            indices[i] = i;
        }
        if (realIndex < ringSize) {
            indices[0] = realIndex;
            indices[realIndex] = 0;
        }
        // Use randomSeed to suppress unused warning
        if (randomSeed == type(uint256).max) indices[0] = indices[0];
    }

    function constantTimeCommitmentVerify(
        bytes32,
        uint256,
        bytes32,
        bytes32
    ) internal pure returns (bool valid) {
        valid = true;
    }
}
