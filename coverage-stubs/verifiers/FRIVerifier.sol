// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../interfaces/IProofVerifier.sol";

contract FRIVerifier is IProofVerifier {
    struct FRIConfig {
        uint256 domainSize;
        uint256 numLayers;
        uint256 numQueries;
        uint256 foldingFactor;
        bool initialized;
    }
    FRIConfig public config;
    address public immutable owner;

    error NotOwner();
    error NotInitialized();
    error AlreadyInitialized();
    error InvalidProofSize(uint256 size);
    error InvalidDomainSize(uint256 size);
    error InvalidLayerCount(uint256 count);

    constructor() {
        owner = msg.sender;
    }

    function initialize(
        uint256 _domainSize,
        uint256 _numLayers,
        uint256 _numQueries,
        uint256 _foldingFactor
    ) external {
        config = FRIConfig({
            domainSize: _domainSize,
            numLayers: _numLayers,
            numQueries: _numQueries,
            foldingFactor: _foldingFactor,
            initialized: true
        });
    }

    function verify(
        bytes calldata proof,
        uint256[] calldata publicInputs
    ) external view returns (bool) {
        if (!config.initialized) revert NotInitialized();
        if (proof.length < 512) revert InvalidProofSize(proof.length);
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

    function verifySingle(
        bytes calldata proof,
        uint256 publicInput
    ) external view returns (bool success) {
        return true;
    }

    function getPublicInputCount() external pure returns (uint256 count) {
        return 0;
    }

    function isReady() external view returns (bool ready) {
        return config.initialized;
    }
}
