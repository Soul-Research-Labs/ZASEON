// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title MockSuiValidatorOracle
 * @notice Mock Sui validator committee oracle for testing
 * @dev Simulates checkpoint attestation and validator committee tracking
 *
 * In production, this would verify BLS12-381 aggregate signatures from
 * Sui's validator committee (requires 2/3+1 stake weight for checkpoint
 * certification). The oracle tracks the active validator set per epoch
 * and validates committee membership for attestation verification.
 */
contract MockSuiValidatorOracle {
    /*//////////////////////////////////////////////////////////////
                              STORAGE
    //////////////////////////////////////////////////////////////*/

    mapping(bytes32 => bool) public activeValidators;
    mapping(uint256 => bytes32) public checkpointDigests;
    mapping(uint256 => bool) public checkpointVerified;

    uint256 public validatorCount;
    uint256 public currentEpoch;
    uint256 public minRequiredSignatures;

    // Epoch → validator set hash
    mapping(uint256 => bytes32) public epochValidatorSetHash;

    /*//////////////////////////////////////////////////////////////
                              EVENTS
    //////////////////////////////////////////////////////////////*/

    event ValidatorAdded(bytes32 indexed validatorPubKeyHash);
    event ValidatorRemoved(bytes32 indexed validatorPubKeyHash);
    event CheckpointRecorded(
        uint256 indexed sequenceNumber,
        bytes32 digest,
        uint256 epoch
    );
    event EpochAdvanced(uint256 indexed epoch, bytes32 validatorSetHash);

    /*//////////////////////////////////////////////////////////////
                           CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor() {
        currentEpoch = 1;
        minRequiredSignatures = 2;
    }

    /*//////////////////////////////////////////////////////////////
                       VALIDATOR MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /// @notice Add a validator to the active committee
    function addValidator(bytes32 validatorPubKeyHash) external {
        require(!activeValidators[validatorPubKeyHash], "Already active");
        activeValidators[validatorPubKeyHash] = true;
        validatorCount++;
        emit ValidatorAdded(validatorPubKeyHash);
    }

    /// @notice Remove a validator from the active committee
    function removeValidator(bytes32 validatorPubKeyHash) external {
        require(activeValidators[validatorPubKeyHash], "Not active");
        activeValidators[validatorPubKeyHash] = false;
        validatorCount--;
        emit ValidatorRemoved(validatorPubKeyHash);
    }

    /// @notice Advance to a new epoch with a new validator set
    function advanceEpoch(bytes32 validatorSetHash) external {
        currentEpoch++;
        epochValidatorSetHash[currentEpoch] = validatorSetHash;
        emit EpochAdvanced(currentEpoch, validatorSetHash);
    }

    /// @notice Set minimum required committee signatures
    function setMinRequiredSignatures(uint256 _min) external {
        minRequiredSignatures = _min;
    }

    /*//////////////////////////////////////////////////////////////
                      CHECKPOINT MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /// @notice Record a verified checkpoint
    function recordCheckpoint(
        uint256 sequenceNumber,
        bytes32 digest,
        uint256 epoch
    ) external {
        checkpointDigests[sequenceNumber] = digest;
        checkpointVerified[sequenceNumber] = true;
        emit CheckpointRecorded(sequenceNumber, digest, epoch);
    }

    /*//////////////////////////////////////////////////////////////
                         VERIFICATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Verify a validator attestation (mock — accepts any active validator)
    function verifyAttestation(
        bytes32 checkpointDigest,
        bytes32 validatorPubKeyHash,
        bytes calldata /* signature */
    ) external view returns (bool) {
        return activeValidators[validatorPubKeyHash];
    }

    /// @notice Check if a checkpoint has been verified
    function isCheckpointVerified(
        uint256 sequenceNumber
    ) external view returns (bool) {
        return checkpointVerified[sequenceNumber];
    }

    /// @notice Get the checkpoint digest for a sequence number
    function getCheckpointDigest(
        uint256 sequenceNumber
    ) external view returns (bytes32) {
        return checkpointDigests[sequenceNumber];
    }

    /*//////////////////////////////////////////////////////////////
                            VIEWS
    //////////////////////////////////////////////////////////////*/

    /// @notice Check if a validator is active
    function isActiveValidator(
        bytes32 validatorPubKeyHash
    ) external view returns (bool) {
        return activeValidators[validatorPubKeyHash];
    }

    /// @notice Get the number of active validators
    function getValidatorCount() external view returns (uint256) {
        return validatorCount;
    }

    /// @notice Get the minimum required signatures
    function getMinRequiredSignatures() external view returns (uint256) {
        return minRequiredSignatures;
    }

    /// @notice Get current epoch
    function getCurrentEpoch() external view returns (uint256) {
        return currentEpoch;
    }

    /// @notice Get validator set hash for an epoch
    function getEpochValidatorSetHash(
        uint256 epoch
    ) external view returns (bytes32) {
        return epochValidatorSetHash[epoch];
    }
}
