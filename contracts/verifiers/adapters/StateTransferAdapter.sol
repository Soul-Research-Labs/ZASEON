// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../Groth16VerifierBN254.sol";

/**
 * @title StateTransferAdapter
 * @notice Adapter for state transfer proof verification
 */
contract StateTransferAdapter {
    Groth16VerifierBN254 public immutable verifier;

    constructor(address _verifier) {
        verifier = Groth16VerifierBN254(_verifier);
    }

    /// @notice Standard interface for proof verification
        /**
     * @notice Verifys proof
     * @param proof The ZK proof data
     * @param publicInputs The public inputs
     * @return The result value
     */
function verifyProof(
        bytes calldata proof,
        bytes calldata publicInputs
    ) external view returns (bool) {
        return verifier.verifyProof(proof, publicInputs);
    }

        /**
     * @notice Verifys the operation
     * @param proof The ZK proof data
     * @param oldStateRoot The old state root
     * @param newStateRoot The new StateRoot value
     * @param transferHash The transferHash hash value
     * @return The result value
     */
function verify(
        bytes calldata proof,
        bytes32 oldStateRoot,
        bytes32 newStateRoot,
        bytes32 transferHash
    ) external view returns (bool) {
        uint256[] memory inputs = new uint256[](3);
        inputs[0] = uint256(oldStateRoot);
        inputs[1] = uint256(newStateRoot);
        inputs[2] = uint256(transferHash);

        return verifier.verify(proof, inputs);
    }
}
