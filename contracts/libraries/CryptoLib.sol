// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title CryptoLib
 * @notice Elliptic curve operations for BN254 curve using EVM precompiles
 * @dev Optimized for use in ZK proof and ring signature verification
 */
library CryptoLib {
    /// @v2-update BN254 curve order (scalar field Fr)
    uint256 constant FR_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    
    /// @v2-update BN254 base field Fq
    uint256 constant FQ_MODULUS = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    struct G1Point {
        uint256 x;
        uint256 y;
    }

    /**
     * @notice Add two G1 points using precompile 0x06
     */
    function g1Add(G1Point memory p1, G1Point memory p2) internal view returns (G1Point memory result) {
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
    function g1Mul(G1Point memory p, uint256 scalar) internal view returns (G1Point memory result) {
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
    function g1Eq(G1Point memory p1, G1Point memory p2) internal pure returns (bool) {
        return p1.x == p2.x && p1.y == p2.y;
    }
}
