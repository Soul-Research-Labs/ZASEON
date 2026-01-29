// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Groth16VerifierBN254 (STUB)
/// @notice Simplified stub for coverage generation
contract Groth16VerifierBN254 {
    bool public initialized;
    address public immutable owner;

    constructor() {
        owner = msg.sender;
    }

    function setVerificationKey(
        uint256[2] calldata,
        uint256[4] calldata,
        uint256[4] calldata,
        uint256[4] calldata,
        uint256[2][] calldata
    ) external {
        initialized = true;
    }

    function verifyProof(
        bytes calldata proof,
        bytes calldata publicInputs
    ) external view returns (bool valid) {
        if (!initialized) return false;
        if (proof.length != 256) return false;
        return true;
    }

    function verifyProofParsed(
        uint256[2] calldata,
        uint256[2][2] calldata,
        uint256[2] calldata,
        uint256[] calldata
    ) external view returns (bool valid) {
        return initialized;
    }

    function batchVerifyProofs(
        bytes[] calldata proofs,
        bytes[] calldata publicInputsArray
    ) external view returns (bool allValid) {
        if (proofs.length != publicInputsArray.length) return false;
        return true;
    }

    function getICCount() external pure returns (uint256 count) {
        return 0;
    }
}
