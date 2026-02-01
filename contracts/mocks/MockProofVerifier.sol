// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title MockProofVerifier
 * @notice Mock proof verifier that always returns true for testing
 * @dev Used in integration tests that require a proof verifier contract
 */
contract MockProofVerifier {
    /// @notice Always returns true for any proof
    function verifyProof(
        bytes calldata /* proof */,
        bytes calldata /* publicInputs */
    ) external pure returns (bool) {
        return true;
    }
    
    /// @notice Alternative verification signature with bytes32 array
    function verifyProof(
        bytes calldata /* proof */,
        bytes32[] calldata /* publicInputs */
    ) external pure returns (bool) {
        return true;
    }
    
    /// @notice IZKVerifier compatible interface
    function verifyProof(
        bytes calldata /* proof */,
        uint256[] calldata /* publicInputs */
    ) external pure returns (bool) {
        return true;
    }
    
    /// @notice Noir verifier interface
    function verify(
        bytes calldata /* proof */,
        bytes32[] calldata /* signals */
    ) external pure returns (bool) {
        return true;
    }
    
    /// @notice Get verification key hash (mock)
    function getVerificationKeyHash() external pure returns (bytes32) {
        return keccak256("MOCK_VK_HASH");
    }
}
