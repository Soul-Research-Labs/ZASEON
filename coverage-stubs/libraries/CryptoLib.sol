// SPDX-License-Identifier: MIT
// Coverage stub – assembly-free version of CryptoLib
pragma solidity ^0.8.20;

library CryptoLib {
    uint256 internal constant FR_MODULUS =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 internal constant FQ_MODULUS =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;
    uint256 internal constant CURVE_B = 3;
    uint256 internal constant MAX_HASH_ITERATIONS = 256;
    bytes32 internal constant HASH_TO_CURVE_DOMAIN =
        keccak256("BN254_HASH_TO_CURVE_V1");

    struct G1Point {
        uint256 x;
        uint256 y;
    }

    function g1Add(
        G1Point memory,
        G1Point memory
    ) internal pure returns (G1Point memory result) {
        result = G1Point(1, 2);
    }

    function g1Mul(
        G1Point memory,
        uint256
    ) internal pure returns (G1Point memory result) {
        result = G1Point(1, 2);
    }

    function g1Neg(G1Point memory p) internal pure returns (G1Point memory) {
        if (p.x == 0 && p.y == 0) return G1Point(0, 0);
        return G1Point(p.x, FQ_MODULUS - p.y);
    }

    function g1Eq(
        G1Point memory p1,
        G1Point memory p2
    ) internal pure returns (bool) {
        return p1.x == p2.x && p1.y == p2.y;
    }

    function hashToPoint(
        bytes memory
    ) internal pure returns (G1Point memory point) {
        point = G1Point(1, 2);
    }

    function hashToPointWithDomain(
        bytes memory,
        bytes32
    ) internal pure returns (G1Point memory point) {
        point = G1Point(1, 2);
    }
}
