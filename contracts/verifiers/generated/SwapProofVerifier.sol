// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Aztec
// @notice STUB VERIFIER — replace with real bb-generated verifier when
//         barretenberg fixes the on_curve assertion (bb >= 3.1.0).
//         Circuit compiles and VK exists at noir/target/swap_proof_vk/vk.
pragma solidity ^0.8.24;

interface IVerifier {
    function verify(bytes calldata _proof, bytes32[] calldata _publicInputs) external returns (bool);
}

contract SwapProofVerifier is IVerifier {
    error StubVerifierNotDeployed();

    function verify(bytes calldata, bytes32[] calldata) external pure override returns (bool) {
        revert StubVerifierNotDeployed();
    }
}
