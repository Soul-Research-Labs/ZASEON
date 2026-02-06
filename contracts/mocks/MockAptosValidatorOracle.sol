// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title MockAptosValidatorOracle
 * @notice Mock AptosBFT validator oracle for testing
 * @dev Tracks validators with voting power for AptosBFT consensus verification.
 *      In production, this would interface with an on-chain light client that
 *      verifies BLS signatures from the Aptos validator set.
 *
 * Aptos uses AptosBFT (DiemBFT v4) with epoch-based validator rotation.
 * Consensus requires 2/3+1 of total voting power for block commitment.
 */
contract MockAptosValidatorOracle {
    struct ValidatorInfo {
        bool active;
        uint256 votingPower;
    }

    mapping(address => ValidatorInfo) public validators;
    mapping(uint256 => bytes32) public ledgerHashes; // version => hash

    address[] public validatorList;
    uint256 public totalVotingPower;
    uint256 public currentEpoch;

    event ValidatorAdded(address indexed validator, uint256 votingPower);
    event ValidatorRemoved(address indexed validator);
    event LedgerRecorded(uint256 indexed version, bytes32 ledgerHash);
    event EpochAdvanced(uint256 newEpoch);

    /// @notice Add a validator with voting power
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

    /// @notice Remove a validator
    function removeValidator(address validator) external {
        require(validators[validator].active, "Not active");
        totalVotingPower -= validators[validator].votingPower;
        validators[validator].active = false;
        validators[validator].votingPower = 0;
        emit ValidatorRemoved(validator);
    }

    /// @notice Verify a validator attestation
    /// @dev Mock implementation — accepts any signature from an active validator
    function verifyAttestation(
        bytes32 /* messageHash */,
        address validator,
        bytes calldata /* signature */
    ) external view returns (bool) {
        return validators[validator].active;
    }

    /// @notice Record a ledger version hash
    function recordLedger(uint256 version, bytes32 ledgerHash) external {
        ledgerHashes[version] = ledgerHash;
        emit LedgerRecorded(version, ledgerHash);
    }

    /// @notice Advance the epoch
    function advanceEpoch() external {
        currentEpoch++;
        emit EpochAdvanced(currentEpoch);
    }

    /// @notice Check if a ledger version is recorded
    function isLedgerVerified(uint256 version) external view returns (bool) {
        return ledgerHashes[version] != bytes32(0);
    }

    /// @notice Get voting power of a validator
    function getVotingPower(address validator) external view returns (uint256) {
        return validators[validator].votingPower;
    }

    /// @notice Get total voting power
    function getTotalVotingPower() external view returns (uint256) {
        return totalVotingPower;
    }

    /// @notice Get number of active validators
    function validatorCount() external view returns (uint256) {
        uint256 count = 0;
        for (uint256 i = 0; i < validatorList.length; i++) {
            if (validators[validatorList[i]].active) count++;
        }
        return count;
    }
}
