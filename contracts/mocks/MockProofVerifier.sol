// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../interfaces/IProofVerifier.sol";

/// @title MockProofVerifier
/// @notice Mock verifier for testing - always returns true
/// @dev DO NOT use in production
contract MockProofVerifier is IProofVerifier {
    bool public shouldVerify = true;

    /// @notice Sets whether verification should pass or fail
    /// @param _shouldVerify True to pass all verifications
    function setVerificationResult(bool _shouldVerify) external {
        shouldVerify = _shouldVerify;
    }

    /// @notice Verifies a proof (mock implementation) - IProofVerifier interface
    /// @param proof The proof bytes (ignored)
    /// @param publicInputs The public inputs as uint256 array (ignored)
    /// @return success Always returns shouldVerify value
    function verify(
        bytes calldata proof,
        uint256[] calldata publicInputs
    ) external view override returns (bool success) {
        // Silence unused variable warnings
        proof;
        publicInputs;
        return shouldVerify;
    }

    /// @notice Verify with single public input
    /// @param proof The proof bytes (ignored)
    /// @param publicInput Single public input (ignored)
    /// @return success Always returns shouldVerify value
    function verifySingle(
        bytes calldata proof,
        uint256 publicInput
    ) external view override returns (bool success) {
        proof;
        publicInput;
        return shouldVerify;
    }

    /// @notice Get expected number of public inputs
    /// @return count Returns 0 for mock (accepts any number)
    function getPublicInputCount()
        external
        pure
        override
        returns (uint256 count)
    {
        return 0;
    }

    /// @notice Check if verifier is ready
    /// @return ready Always returns true
    function isReady() external pure override returns (bool ready) {
        return true;
    }

    /// @notice Legacy verifyProof for backwards compatibility
    /// @param proof The proof bytes (ignored)
    /// @param publicInputs The public inputs (ignored)
    /// @return valid Always returns shouldVerify value
    function verifyProof(
        bytes calldata proof,
        bytes calldata publicInputs
    ) external view returns (bool valid) {
        // Silence unused variable warnings
        proof;
        publicInputs;
        return shouldVerify;
    }
}
