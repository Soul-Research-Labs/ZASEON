// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title MockSeiValidatorOracle
 * @notice Mock Sei validator oracle for testing
 * @dev Simulates Tendermint BFT validator set tracking and attestation verification
 *
 * In production, this would verify ed25519 signatures from Sei's Tendermint
 * validator set, checking that attestations carry at least 2/3+1 of total
 * voting power. The oracle tracks the active validator set and their stake
 * weights across epochs.
 */
contract MockSeiValidatorOracle {
    /*//////////////////////////////////////////////////////////////
                              STORAGE
    //////////////////////////////////////////////////////////////*/

    mapping(address => bool) public activeValidators;
    mapping(address => uint256) public validatorVotingPower;
    mapping(uint256 => bytes32) public blockHashes;
    mapping(uint256 => bool) public blockVerified;

    uint256 public validatorCount;
    uint256 public totalVotingPower;
    uint256 public minRequiredSignatures;

    /*//////////////////////////////////////////////////////////////
                              EVENTS
    //////////////////////////////////////////////////////////////*/

    event ValidatorAdded(address indexed validator, uint256 votingPower);
    event ValidatorRemoved(address indexed validator);
    event BlockRecorded(uint256 indexed height, bytes32 blockHash);

    /*//////////////////////////////////////////////////////////////
                           CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor() {
        minRequiredSignatures = 2;
    }

    /*//////////////////////////////////////////////////////////////
                       VALIDATOR MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /// @notice Add a validator to the active set
    function addValidator(address validator, uint256 votingPower) external {
        require(!activeValidators[validator], "Already active");
        activeValidators[validator] = true;
        validatorVotingPower[validator] = votingPower;
        validatorCount++;
        totalVotingPower += votingPower;
        emit ValidatorAdded(validator, votingPower);
    }

    /// @notice Remove a validator from the active set
    function removeValidator(address validator) external {
        require(activeValidators[validator], "Not active");
        totalVotingPower -= validatorVotingPower[validator];
        activeValidators[validator] = false;
        validatorVotingPower[validator] = 0;
        validatorCount--;
        emit ValidatorRemoved(validator);
    }

    /// @notice Set minimum required signatures
    function setMinRequiredSignatures(uint256 _min) external {
        minRequiredSignatures = _min;
    }

    /*//////////////////////////////////////////////////////////////
                       BLOCK MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /// @notice Record a verified block
    function recordBlock(uint256 height, bytes32 blockHash) external {
        blockHashes[height] = blockHash;
        blockVerified[height] = true;
        emit BlockRecorded(height, blockHash);
    }

    /*//////////////////////////////////////////////////////////////
                         VERIFICATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Verify a validator attestation (mock — accepts any active validator)
    function verifyAttestation(
        bytes32 blockHash,
        address validator,
        bytes calldata /* signature */
    ) external view returns (bool) {
        return activeValidators[validator];
    }

    /// @notice Check if a block has been verified
    function isBlockVerified(uint256 height) external view returns (bool) {
        return blockVerified[height];
    }

    /// @notice Get voting power for a validator
    function getVotingPower(address validator) external view returns (uint256) {
        return validatorVotingPower[validator];
    }

    /*//////////////////////////////////////////////////////////////
                            VIEWS
    //////////////////////////////////////////////////////////////*/

    /// @notice Check if a validator is active
    function isActiveValidator(address validator) external view returns (bool) {
        return activeValidators[validator];
    }

    /// @notice Get the number of active validators
    function getValidatorCount() external view returns (uint256) {
        return validatorCount;
    }

    /// @notice Get total voting power
    function getTotalVotingPower() external view returns (uint256) {
        return totalVotingPower;
    }

    /// @notice Get minimum required signatures
    function getMinRequiredSignatures() external view returns (uint256) {
        return minRequiredSignatures;
    }
}
