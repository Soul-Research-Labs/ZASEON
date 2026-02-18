// SPDX-License-Identifier: MIT
// Coverage stub – returns true for all proofs
pragma solidity ^0.8.24;

contract CrossChainProofVerifier {
    function verifyProof(
        uint256[2] calldata, // _pA
        uint256[2][2] calldata, // _pB
        uint256[2] calldata, // _pC
        uint256[7] calldata // _pubSignals
    ) public pure returns (bool) {
        return true;
    }
}
