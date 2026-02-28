// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./NoirVerifierAdapter.sol";

/**
 * @title SwapProofAdapter
 * @notice Adapter for the Swap Proof Noir circuit
 * @custom:deprecated LEGACY — public input counts do not match UltraHonk-generated verifiers.
 *                    Use UltraHonkAdapter with the corresponding generated verifier instead.
 * @dev Mapped to 11 public signals:
 *      Inputs: [old_root, new_root, pool_id, nullifier, min_out, fee] (6)
 *      Pool: [res_in, res_out, new_in, new_out, fee_rate] (5)
 */
contract SwapProofAdapter is NoirVerifierAdapter {
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

        // Exact count validation: 11 public signals
        require(
            inputs.length == getPublicInputCount(),
            "SIG_COUNT_MISMATCH: SWAP_PROOF"
        );

        return INoirVerifier(noirVerifier).verify(proof, inputs);
    }

    /**
     * @notice Returns the public input count
     * @return The result value
     */
    function getPublicInputCount() public pure override returns (uint256) {
        return 11;
    }
}
