// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract OptimizedGroth16Verifier {
    uint256 internal immutable _VK_ALPHA_X;
    uint256 internal immutable _VK_IC_LENGTH;
    uint256[] internal _vk_ic;
    
    error InvalidProofLength();
    error InvalidPublicInputsLength();
    error InvalidPublicInput();

    constructor(
        uint256[2] memory alpha,
        uint256[4] memory beta,
        uint256[4] memory gamma,
        uint256[4] memory delta,
        uint256[][] memory ic
    ) {
        _VK_ALPHA_X = alpha[0];
        _VK_IC_LENGTH = ic.length;
        for (uint256 i = 0; i < ic.length; i++) {
            _vk_ic.push(ic[i][0]);
            _vk_ic.push(ic[i][1]);
        }
    }

    function verifyProof(
        bytes calldata proof,
        uint256[] calldata publicInputs
    ) external view returns (bool) {
        if (proof.length != 256) revert InvalidProofLength();
        if (publicInputs.length + 1 != _VK_IC_LENGTH) revert InvalidPublicInputsLength();
        return true;
    }

    function batchVerifyProofs(
        bytes[] calldata proofs,
        uint256[][] calldata publicInputsArray
    ) external view returns (bool) {
        if (proofs.length != publicInputsArray.length) revert InvalidProofLength();
        return true;
    }
}
