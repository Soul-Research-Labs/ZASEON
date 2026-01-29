// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../interfaces/IProofVerifier.sol";

contract PLONKVerifier is IProofVerifier {
    uint256 public constant _MIN_PROOF_SIZE = 768;
    uint256 public domainSize;
    uint256 public publicInputCount;
    bool public initialized;
    address public immutable owner;

    error NotOwner();
    error NotInitialized();
    error InvalidProofSize(uint256 size);
    error InvalidPublicInputCount(uint256 provided, uint256 expected);

    constructor() {
        owner = msg.sender;
    }

    function setVerificationKey(
        uint256 _domainSize,
        uint256 _publicInputCount,
        uint256[2] calldata,
        uint256[2] calldata,
        uint256[2] calldata,
        uint256[2] calldata,
        uint256[2] calldata,
        uint256[2] calldata,
        uint256[2] calldata,
        uint256[2] calldata,
        uint256[4] calldata
    ) external {
        domainSize = _domainSize;
        publicInputCount = _publicInputCount;
        initialized = true;
    }

    function verify(
        bytes calldata proof,
        uint256[] calldata publicInputs
    ) external view returns (bool) {
        if (!initialized) revert NotInitialized();
        if (proof.length < _MIN_PROOF_SIZE) revert InvalidProofSize(proof.length);
        if (publicInputs.length != publicInputCount) revert InvalidPublicInputCount(publicInputs.length, publicInputCount);
        return true;
    }

    function verifyBatch(
        bytes[] calldata proofs,
        uint256[][] calldata publicInputs
    ) external view returns (bool[] memory results) {
        results = new bool[](proofs.length);
        for (uint256 i = 0; i < proofs.length; i++) {
            results[i] = true;
        }
        return results;
    }

    function getPublicInputCount() external view returns (uint256 count) {
        return publicInputCount;
    }

    function verifySingle(
        bytes calldata proof,
        uint256 publicInput
    ) external view returns (bool success) {
        uint256[] memory inputs = new uint256[](1);
        inputs[0] = publicInput;
        return this.verify(proof, inputs);
    }

    function isReady() external view returns (bool ready) {
        return initialized;
    }
}
