// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../Groth16VerifierBN254.sol";

/**
 * @title AggregatorAdapter
 * @notice Adapter for aggregated proof verification
 * @custom:deprecated LEGACY — wraps Groth16VerifierBN254 from the Circom era.
 *                    Use UltraHonkAdapter with the corresponding Noir/UltraHonk verifier instead.
 */
contract AggregatorAdapter {
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
     * @notice Verifys batch
     * @param aggregatedProof The aggregated proof
     * @param publicInputs The public inputs
     * @return The result value
     */
    function verifyBatch(
        bytes calldata aggregatedProof,
        bytes32[] calldata publicInputs
    ) external view returns (bool) {
        uint256[] memory inputs = new uint256[](publicInputs.length);
        for (uint256 i = 0; i < publicInputs.length; ) {
            inputs[i] = uint256(publicInputs[i]);
            unchecked {
                ++i;
            }
        }

        return verifier.verify(aggregatedProof, inputs);
    }
}
