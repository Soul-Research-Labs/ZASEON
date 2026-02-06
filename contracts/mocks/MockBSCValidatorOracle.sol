// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * @title MockBSCValidatorOracle
 * @notice Mock oracle for verifying BSC PoSA validator attestations in tests
 * @dev Simulates the BNB Chain PoSA validator set and signature verification.
 *      In production, this would verify actual ECDSA signatures from BSC
 *      validators against the current validator set.
 *
 * BNB Chain PoSA Validator Set:
 * - 21 active validators elected via staking
 * - Validators produce blocks in rotation (~3s block time)
 * - Epoch length: 200 blocks
 * - Validator set changes at epoch boundaries
 * - Verification requires ≥15/21 validator signatures (2/3 + 1 supermajority)
 *
 * This mock allows tests to:
 * 1. Register/remove validators
 * 2. Configure whether attestation verification succeeds or fails
 * 3. Track verification call counts for assertions
 */
contract MockBSCValidatorOracle is AccessControl {
    /*//////////////////////////////////////////////////////////////
                              STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Set of registered validator addresses
    mapping(address => bool) public validators;

    /// @notice Number of registered validators
    uint256 public validatorCount;

    /// @notice Whether verification should succeed (test toggle)
    bool public verificationResult;

    /// @notice Count of verification calls (for test assertions)
    uint256 public verifyCallCount;

    /// @notice Per-validator call count
    mapping(address => uint256) public validatorCallCount;

    /*//////////////////////////////////////////////////////////////
                            EVENTS
    //////////////////////////////////////////////////////////////*/

    event ValidatorRegistered(address indexed validator);
    event ValidatorRemoved(address indexed validator);
    event AttestationVerified(
        bytes32 indexed blockHash,
        address indexed validator,
        bool result
    );

    /*//////////////////////////////////////////////////////////////
                          CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        verificationResult = true; // Default: verifications succeed
    }

    /*//////////////////////////////////////////////////////////////
                     VALIDATOR MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /// @notice Register a validator address
    function registerValidator(
        address validator
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(!validators[validator], "Already registered");
        validators[validator] = true;
        validatorCount++;
        emit ValidatorRegistered(validator);
    }

    /// @notice Remove a validator address
    function removeValidator(
        address validator
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(validators[validator], "Not registered");
        validators[validator] = false;
        validatorCount--;
        emit ValidatorRemoved(validator);
    }

    /// @notice Batch register validators
    function registerValidators(
        address[] calldata _validators
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        for (uint256 i = 0; i < _validators.length; i++) {
            if (!validators[_validators[i]]) {
                validators[_validators[i]] = true;
                validatorCount++;
                emit ValidatorRegistered(_validators[i]);
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                     VERIFICATION (CALLED BY BRIDGE)
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Verify a validator's attestation of a block hash
     * @dev Called by BNBBridgeAdapter via staticcall
     * @param blockHash The block hash being attested to
     * @param validator The validator's address
     * @param signature The ECDSA signature (ignored in mock)
     * @return valid Whether the attestation is valid
     */
    function verifyAttestation(
        bytes32 blockHash,
        address validator,
        bytes calldata signature
    ) external view returns (bool valid) {
        // Suppress unused variable warnings
        blockHash;
        signature;

        // In mock: check if validator is registered + global toggle
        if (!validators[validator]) return false;
        return verificationResult;
    }

    /**
     * @notice Non-view version for testing (tracks call counts)
     */
    function verifyAttestationAndTrack(
        bytes32 blockHash,
        address validator,
        bytes calldata signature
    ) external returns (bool valid) {
        signature; // suppress warning
        verifyCallCount++;
        validatorCallCount[validator]++;

        bool result = validators[validator] && verificationResult;
        emit AttestationVerified(blockHash, validator, result);
        return result;
    }

    /*//////////////////////////////////////////////////////////////
                        TEST CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Set whether verification should succeed or fail
    function setVerificationResult(
        bool _result
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        verificationResult = _result;
    }

    /// @notice Check if an address is a registered validator
    function isValidator(address validator) external view returns (bool) {
        return validators[validator];
    }
}
