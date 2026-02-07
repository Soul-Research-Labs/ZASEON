// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title MockCardanoLightClient
/// @notice Mock light client for Cardano Ouroboros Praos consensus verification in testing
/// @dev Simulates Ouroboros Praos slot leader election and chain validation
contract MockCardanoLightClient {
    struct ValidatorInfo {
        bool active;
        uint256 votingPower;
    }

    mapping(address => ValidatorInfo) public validators;
    mapping(uint256 => bytes32) public blockHashes;
    address[] public validatorList;
    uint256 public totalVotingPower;
    uint256 public currentEpoch;

    event ValidatorAdded(address indexed validator, uint256 votingPower);
    event ValidatorRemoved(address indexed validator);
    event AttestationVerified(
        address indexed validator,
        uint256 indexed slot,
        bytes32 headerHash
    );
    event HeaderRecorded(uint256 indexed slot, bytes32 headerHash);
    event EpochAdvanced(uint256 indexed newEpoch);

    /// @notice Add a stake pool operator to the validator set
    /// @param validator Address of the validator (SPO)
    /// @param votingPower Voting power (stake) of the validator
    function addValidator(address validator, uint256 votingPower) external {
        require(!validators[validator].active, "Already active");
        validators[validator] = ValidatorInfo({
            active: true,
            votingPower: votingPower
        });
        validatorList.push(validator);
        totalVotingPower += votingPower;
        emit ValidatorAdded(validator, votingPower);
    }

    /// @notice Remove a validator from the set
    /// @param validator Address of the validator to remove
    function removeValidator(address validator) external {
        require(validators[validator].active, "Not active");
        totalVotingPower -= validators[validator].votingPower;
        validators[validator].active = false;
        validators[validator].votingPower = 0;
        for (uint256 i = 0; i < validatorList.length; i++) {
            if (validatorList[i] == validator) {
                validatorList[i] = validatorList[validatorList.length - 1];
                validatorList.pop();
                break;
            }
        }
        emit ValidatorRemoved(validator);
    }

    /// @notice Mock verify an Ouroboros Praos attestation
    /// @param validator Address of the attesting validator
    /// @param slot Slot number being attested
    /// @param headerHash Hash of the block header
    /// @return valid True if the validator is active
    function verifyAttestation(
        address validator,
        uint256 slot,
        bytes32 headerHash
    ) external returns (bool valid) {
        valid = validators[validator].active;
        if (valid) {
            emit AttestationVerified(validator, slot, headerHash);
        }
    }

    /// @notice Record a block header hash at a given slot
    /// @param slot The slot number
    /// @param headerHash The header hash
    function recordHeader(uint256 slot, bytes32 headerHash) external {
        blockHashes[slot] = headerHash;
        emit HeaderRecorded(slot, headerHash);
    }

    /// @notice Advance the epoch
    function advanceEpoch() external {
        currentEpoch++;
        emit EpochAdvanced(currentEpoch);
    }

    /// @notice Get the number of validators
    /// @return count Number of validators in the set
    function getValidatorCount() external view returns (uint256 count) {
        return validatorList.length;
    }

    /// @notice Check if a validator is active
    /// @param validator Address to check
    /// @return True if the validator is active
    function isActiveValidator(address validator) external view returns (bool) {
        return validators[validator].active;
    }
}
