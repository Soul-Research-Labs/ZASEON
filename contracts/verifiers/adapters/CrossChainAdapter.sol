// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./NoirVerifierAdapter.sol";

/**
 * @title CrossChainAdapter
 * @notice Adapter for the Cross-Chain Proof Relay Noir circuit
 * @custom:deprecated LEGACY — public input counts do not match UltraHonk-generated verifiers.
 *                    Use UltraHonkAdapter with the corresponding generated verifier instead.
 * @dev Mapped to 7 public signals: [isValid, dest_hash, dest_cid, relayer_pub, commitment, timestamp, fee]
 */
contract CrossChainAdapter is NoirVerifierAdapter {
    constructor(address _noirVerifier) NoirVerifierAdapter(_noirVerifier) {}

    /**
     * @notice Verifys the operation
     * @param proof The ZK proof data
     * @param publicInputs The public inputs
     * @return The result value
     */
    function verify(
        bytes32 /* circuitHash */,
        bytes calldata proof,
        bytes calldata publicInputs
    ) external view override returns (bool) {
        bytes32[] memory inputs = _prepareSignals(publicInputs);

        // Exact count validation as per exhaustive spec
        require(
            inputs.length == getPublicInputCount(),
            "SIG_COUNT_MISMATCH: CROSS_CHAIN"
        );

        // Signal[0] is the return boolean from Noir main
        bool circuitPassed = uint256(inputs[0]) == 1;

        if (!circuitPassed) return false;

        return INoirVerifier(noirVerifier).verify(proof, inputs);
    }

    /**
     * @notice Returns the public input count
     * @return The result value
     */
    function getPublicInputCount() public pure override returns (uint256) {
        return 7;
    }
}
