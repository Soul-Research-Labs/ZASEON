// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title CryptoLib
 * @notice Elliptic curve operations for BN254 curve using EVM precompiles
 * @dev Optimized for use in ZK proof and ring signature verification
 *
 * Hash-to-Curve Implementation:
 * Uses try-and-increment method (SWU alternative for BN254)
 * Based on draft-irtf-cfrg-hash-to-curve-16
 */
library CryptoLib {
    /// @dev BN254 curve order (scalar field Fr) - v2 update
    uint256 internal constant FR_MODULUS =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    /// @dev BN254 base field Fq - v2 update
    uint256 internal constant FQ_MODULUS =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;

    /// @dev BN254 curve parameter b (y^2 = x^3 + b)
    uint256 internal constant CURVE_B = 3;

    /// @dev Maximum iterations for hash-to-curve try-and-increment
    uint256 internal constant MAX_HASH_ITERATIONS = 256;

    /// @dev Domain separator for hash-to-curve
    bytes32 internal constant HASH_TO_CURVE_DOMAIN =
        keccak256("BN254_HASH_TO_CURVE_V1");

    struct G1Point {
        uint256 x;
        uint256 y;
    }

    /**
     * @notice Add two G1 points using precompile 0x06
     */
    function g1Add(
        G1Point memory p1,
        G1Point memory p2
    ) internal view returns (G1Point memory result) {
        uint256[4] memory input = [p1.x, p1.y, p2.x, p2.y];

        assembly {
            let success := staticcall(gas(), 0x06, input, 128, result, 64)
            if iszero(success) {
                revert(0, 0)
            }
        }
    }

    /**
     * @notice Scalar multiplication of a G1 point using precompile 0x07
     */
    function g1Mul(
        G1Point memory p,
        uint256 scalar
    ) internal view returns (G1Point memory result) {
        uint256[3] memory input = [p.x, p.y, scalar];

        assembly {
            let success := staticcall(gas(), 0x07, input, 96, result, 64)
            if iszero(success) {
                revert(0, 0)
            }
        }
    }

    /**
     * @notice Negate a G1 point
     */
    function g1Neg(G1Point memory p) internal pure returns (G1Point memory) {
        if (p.x == 0 && p.y == 0) return p;
        return G1Point(p.x, FQ_MODULUS - (p.y % FQ_MODULUS));
    }

    /**
     * @notice Check if two points are equal
     */
    function g1Eq(
        G1Point memory p1,
        G1Point memory p2
    ) internal pure returns (bool) {
        return p1.x == p2.x && p1.y == p2.y;
    }

    /**
     * @notice Hash arbitrary data to a G1 point on the BN254 curve
     * @dev Uses try-and-increment method with domain separation
     *      This is the recommended approach for BN254 per hash-to-curve spec
     * @param data The data to hash
     * @return point A valid G1 point derived from the input data
     */
    function hashToPoint(
        bytes memory data
    ) internal view returns (G1Point memory point) {
        return hashToPointWithDomain(data, HASH_TO_CURVE_DOMAIN);
    }

    /**
     * @notice Hash arbitrary data to a G1 point with custom domain separator
     * @dev Uses try-and-increment: hash, compute y^2, check if quadratic residue
     * @param data The data to hash
     * @param domain Domain separator for the hash
     * @return point A valid G1 point derived from the input data
     */
    function hashToPointWithDomain(
        bytes memory data,
        bytes32 domain
    ) internal view returns (G1Point memory point) {
        // Try-and-increment method
        for (uint256 counter = 0; counter < MAX_HASH_ITERATIONS; counter++) {
            // Hash with counter to get x coordinate candidate
            bytes32 hash = keccak256(abi.encodePacked(domain, data, counter));
            uint256 x = uint256(hash) % FQ_MODULUS;

            // Compute y^2 = x^3 + 3 (BN254 curve equation)
            uint256 y2 = _computeYSquared(x);

            // Check if y^2 has a square root in Fq
            uint256 y = _modSqrt(y2);
            if (y != 0) {
                // Valid point found, return with canonical y (smaller of y or -y)
                if (y > FQ_MODULUS / 2) {
                    y = FQ_MODULUS - y;
                }
                return G1Point(x, y);
            }
        }

        // Should never happen with proper hash function
        revert("Hash to curve failed");
    }

    /**
     * @notice Compute y^2 = x^3 + b for BN254
     */
    function _computeYSquared(uint256 x) private pure returns (uint256) {
        // x^2 mod p
        uint256 x2 = mulmod(x, x, FQ_MODULUS);
        // x^3 mod p
        uint256 x3 = mulmod(x2, x, FQ_MODULUS);
        // x^3 + 3 mod p
        return addmod(x3, CURVE_B, FQ_MODULUS);
    }

    /**
     * @notice Compute modular square root using Tonelli-Shanks algorithm
     * @dev For BN254, p ≡ 3 (mod 4), so we can use the simpler formula: sqrt(a) = a^((p+1)/4)
     * @param a The value to compute square root of
     * @return The square root if it exists, 0 otherwise
     */
    function _modSqrt(uint256 a) private view returns (uint256) {
        if (a == 0) return 0;

        // For BN254, p ≡ 3 (mod 4), so sqrt(a) = a^((p+1)/4) mod p
        // (p+1)/4 for BN254:
        uint256 exponent = (FQ_MODULUS + 1) / 4;

        uint256 result = _modExp(a, exponent);

        // Verify the result: if result^2 == a, it's a valid square root
        if (mulmod(result, result, FQ_MODULUS) == a) {
            return result;
        }
        return 0;
    }

    /**
     * @notice Modular exponentiation using precompile 0x05
     */
    function _modExp(
        uint256 base,
        uint256 exp
    ) private view returns (uint256 result) {
        bytes memory input = abi.encodePacked(
            uint256(32), // base length
            uint256(32), // exponent length
            uint256(32), // modulus length
            base,
            exp,
            FQ_MODULUS
        );

        assembly {
            let success := staticcall(
                gas(),
                0x05,
                add(input, 0x20),
                192,
                result,
                32
            )
            if iszero(success) {
                revert(0, 0)
            }
            result := mload(result)
        }
    }
}
