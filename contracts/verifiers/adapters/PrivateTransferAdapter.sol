// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./NoirVerifierAdapter.sol";

/**
 * @title PrivateTransferAdapter
 * @notice Adapter for the Private Transfer Noir circuit
 * @custom:deprecated LEGACY — public input counts do not match UltraHonk-generated verifiers.
 *                    Use UltraHonkAdapter with the corresponding generated verifier instead.
 * @dev Mapped to 16 public signals:
 *      Inputs: [merkle_root, nullifier[2], commitment[2], fee] (6)
 *      Outputs Struct: [key_images[2], stealth[2], eph_x[2], eph_y[2], tags[2]] (10)
 */
contract PrivateTransferAdapter is NoirVerifierAdapter {
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

        // Total signals: 16 (Inputs + Struct members mapped to flat array)
        require(
            inputs.length == getPublicInputCount(),
            "SIG_COUNT_MISMATCH: PRIVATE_TRANSFER"
        );

        return INoirVerifier(noirVerifier).verify(proof, inputs);
    }

    /**
     * @notice Returns the public input count
     * @return The result value
     */
    function getPublicInputCount() public pure override returns (uint256) {
        return 16;
    }
}
