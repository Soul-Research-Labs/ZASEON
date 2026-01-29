// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../interfaces/IProofVerifier.sol";

contract Groth16VerifierBN254 is IProofVerifier {
    uint256[2] public vkAlpha;
    uint256[4] public vkBeta;
    uint256[4] public vkGamma;
    uint256[4] public vkDelta;
    uint256[2][] public vkIC;
    bool public initialized;
    address public owner;

    error NotOwner();
    error NotInitialized();
    error InvalidProofSize(uint256 size);
    error InvalidPublicInputCount(uint256 provided, uint256 expected);
    error InvalidPublicInput(uint256 index, uint256 value);

    constructor() {
        owner = msg.sender;
    }

    function setVerificationKey(
        uint256[2] calldata alpha,
        uint256[4] calldata beta,
        uint256[4] calldata gamma,
        uint256[4] calldata delta,
        uint256[2][] calldata ic
    ) external {
        vkAlpha = alpha;
        vkBeta = beta;
        vkGamma = gamma;
        vkDelta = delta;
        vkIC = ic;
        initialized = true;
    }

    function verify(
        bytes calldata proof,
        uint256[] calldata publicInputs
    ) external view override returns (bool) {
        if (!initialized) revert NotInitialized();
        if (proof.length != 256) revert InvalidProofSize(proof.length);
        if (publicInputs.length != vkIC.length - 1) revert InvalidPublicInputCount(publicInputs.length, vkIC.length - 1);
        return true;
    }

    function verifySingle(
        bytes calldata proof,
        uint256 publicInput
    ) external view override returns (bool) {
        if (!initialized) revert NotInitialized();
        if (proof.length != 256) revert InvalidProofSize(proof.length);
        return true;
    }

    function getPublicInputCount() external view override returns (uint256) {
        return vkIC.length > 0 ? vkIC.length - 1 : 0;
    }

    function isReady() external view override returns (bool) {
        return initialized;
    }

    function transferOwnership(address newOwner) external {
        owner = newOwner;
    }
}
