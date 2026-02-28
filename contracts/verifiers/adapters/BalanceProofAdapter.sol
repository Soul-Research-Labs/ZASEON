// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../Groth16VerifierBN254.sol";

/**
 * @title BalanceProofAdapter
 * @notice Adapter for balance proof verification
 * @custom:deprecated LEGACY — wraps Groth16VerifierBN254 from the Circom era.
 *                    Use UltraHonkAdapter with the corresponding Noir/UltraHonk verifier instead.
 */
contract BalanceProofAdapter {
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
     * @param balance The balance
     * @param minRequired The minRequired bound
     * @param commitment The cryptographic commitment
     * @return The result value
     */
    function verify(
        bytes calldata proof,
        uint256 balance,
        uint256 minRequired,
        bytes32 commitment
    ) external view returns (bool) {
        uint256[] memory inputs = new uint256[](3);
        inputs[0] = balance;
        inputs[1] = minRequired;
        inputs[2] = uint256(commitment);

        return verifier.verify(proof, inputs);
    }
}
