// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title GasOptimizedVerifier (STUB)
/// @notice Simplified stub for coverage generation
library GasOptimizedVerifier {
    function ecAdd(uint256 x1, uint256 y1, uint256 x2, uint256 y2) internal pure returns (uint256 x, uint256 y) {
        return (x1 + x2, y1 + y2);
    }

    function ecMul(uint256 px, uint256 py, uint256 s) internal pure returns (uint256 x, uint256 y) {
        return (px * s, py * s);
    }

    function pairingCheck(
        uint256[2] memory, uint256[2][2] memory, uint256[2] memory,
        uint256[2] memory, uint256[2][2] memory, uint256[2] memory,
        uint256[2][2] memory, uint256[2][2] memory
    ) internal pure returns (bool) {
        return true;
    }

    function batchVerify(
        uint256[8][] memory, uint256[][] memory, uint256[18] memory, uint256
    ) internal pure returns (bool) {
        return true;
    }
}

contract BatchProofVerifier {
    struct VerificationKey {
        uint256[2] alpha;
        uint256[2][2] beta;
        uint256[2][2] gamma;
        uint256[2][2] delta;
        uint256[2][] ic;
    }
    mapping(bytes32 => VerificationKey) internal _verificationKeys;

    function registerVk(bytes32 vkId, VerificationKey calldata vk) external {
        _verificationKeys[vkId] = vk;
    }

    function verify(bytes32, uint256[8] calldata, uint256[] calldata) external pure returns (bool) {
        return true;
    }

    function batchVerify(bytes32, uint256[8][] calldata, uint256[][] calldata) external pure returns (bool) {
        return true;
    }

    function getVkAlpha(bytes32 vkId) external view returns (uint256[2] memory) {
        return _verificationKeys[vkId].alpha;
    }
}
