// SPDX-License-Identifier: MIT
// Coverage stub – returns true for all proofs
pragma solidity ^0.8.20;

contract StateTransferVerifier {
    function verifyProof(
        uint[2] calldata, // _pA
        uint[2][2] calldata, // _pB
        uint[2] calldata, // _pC
        uint[7] calldata // _pubSignals
    ) public pure returns (bool) {
        return true;
    }
}
