// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./NoirVerifierAdapter.sol";

/**
 * @title PolicyVerifierAdapter
 * @notice Adapter for the Policy Compliance Noir circuit
 */
contract PolicyVerifierAdapter is NoirVerifierAdapter {
    constructor(address _noirVerifier) NoirVerifierAdapter(_noirVerifier) {}

    /**
     * @notice Custom verification for Policy compliance
     * @dev Decodes policy-specific public inputs: policy_hash, user_commitment, merkle_root
     */
    function verify(
        bytes32 /* circuitHash */,
        bytes calldata proof,
        bytes calldata publicInputs
    ) external view override returns (bool) {
        // Policy Noir circuit has 4 public inputs:
        // 1. isValid (return)
        // 2. policy_hash
        // 3. user_commitment
        // 4. merkle_root
        
        bytes32[] memory inputs = _prepareSignals(publicInputs);
        require(inputs.length == getPublicInputCount(), "SIG_COUNT_MISMATCH: POLICY");

        // Signal[0] is the return boolean from Noir main
        bool circuitPassed = uint256(inputs[0]) == 1;

        if (!circuitPassed) return false;
        
        return INoirVerifier(noirVerifier).verify(proof, inputs);
    }

    function getPublicInputCount() public pure override returns (uint256) {
        return 4;
    }
}
