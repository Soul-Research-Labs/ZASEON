// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../Groth16VerifierBN254.sol";

/**
 * @title PedersenCommitmentAdapter
 * @notice Adapter for Pedersen commitment proof verification
 */
contract PedersenCommitmentAdapter {
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

    /// @notice Verify commitment ownership
        /**
     * @notice Verifys commitment
     * @param proof The ZK proof data
     * @param commitment The cryptographic commitment
     * @param ownerPubkey The owner pubkey
     * @return The result value
     */
function verifyCommitment(
        bytes calldata proof,
        bytes32 commitment,
        bytes32 ownerPubkey
    ) external view returns (bool) {
        uint256[] memory inputs = new uint256[](2);
        inputs[0] = uint256(commitment);
        inputs[1] = uint256(ownerPubkey);
        return verifier.verify(proof, inputs);
    }

        /**
     * @notice Verifys the operation
     * @param proof The ZK proof data
     * @param commitment The cryptographic commitment
     * @param value The value to set
     * @param blinding The blinding
     * @return The result value
     */
function verify(
        bytes calldata proof,
        bytes32 commitment,
        uint256 value,
        bytes32 blinding
    ) external view returns (bool) {
        uint256[] memory inputs = new uint256[](3);
        inputs[0] = uint256(commitment);
        inputs[1] = value;
        inputs[2] = uint256(blinding);

        return verifier.verify(proof, inputs);
    }
}
