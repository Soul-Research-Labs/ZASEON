// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title MockCantonMediatorOracle
 * @notice Mock Canton mediator oracle for testing
 * @dev Simulates Canton Network's mediator node set with attestation verification
 *
 * Canton Network uses a unique consensus model:
 * - ~20 mediator nodes in the Global Synchronizer
 * - 2/3+1 supermajority required for confirmation
 * - ~2 second sequencing rounds
 * - Privacy-preserving: mediators confirm without seeing tx content
 * - Domain topology determines trust boundaries
 */
contract MockCantonMediatorOracle {
    mapping(address => bool) public isMediator;
    address[] public mediators;
    uint256 public mediatorCount;
    bool public shouldReturnValid;

    constructor() {
        shouldReturnValid = true;
    }

    function addMediator(address mediator) external {
        require(!isMediator[mediator], "Already a mediator");
        isMediator[mediator] = true;
        mediators.push(mediator);
        mediatorCount++;
    }

    function removeMediator(address mediator) external {
        require(isMediator[mediator], "Not a mediator");
        isMediator[mediator] = false;
        mediatorCount--;
        for (uint256 i = 0; i < mediators.length; i++) {
            if (mediators[i] == mediator) {
                mediators[i] = mediators[mediators.length - 1];
                mediators.pop();
                break;
            }
        }
    }

    function setShouldReturnValid(bool _valid) external {
        shouldReturnValid = _valid;
    }

    /**
     * @notice Verify a mediator attestation for a round hash
     * @dev In production, this would verify the actual signature against the mediator set
     * @param roundHash The round hash being attested
     * @param mediator The mediator address
     * @param signature The signature bytes (ignored in mock)
     * @return valid Whether the attestation is valid
     */
    function verifyAttestation(
        bytes32 roundHash,
        address mediator,
        bytes calldata signature
    ) external view returns (bool valid) {
        if (!shouldReturnValid) return false;
        if (!isMediator[mediator]) return false;
        if (roundHash == bytes32(0)) return false;
        if (signature.length == 0) return false;
        return true;
    }

    /**
     * @notice Get current active mediator set
     * @return The list of active mediators
     */
    function getActiveMediators() external view returns (address[] memory) {
        return mediators;
    }

    /**
     * @notice Check if supermajority is met
     * @dev Canton requires 2/3+1 mediators for confirmation
     * @param signatoryCount Number of valid signatories
     * @return Whether supermajority is reached
     */
    function isSuperMajority(
        uint256 signatoryCount
    ) external view returns (bool) {
        if (mediatorCount == 0) return false;
        return signatoryCount * 3 > mediatorCount * 2;
    }

    /**
     * @notice Get minimum required signatures for confirmation
     * @return The minimum number of mediator signatures needed
     */
    function getMinRequiredSignatures() external view returns (uint256) {
        if (mediatorCount == 0) return 0;
        return (mediatorCount * 2) / 3 + 1;
    }

    /**
     * @notice Batch verify multiple attestations
     * @param roundHash The round hash
     * @param _mediators Array of mediator addresses
     * @param signatures Array of signatures
     * @return validCount The number of valid attestations
     */
    function batchVerifyAttestations(
        bytes32 roundHash,
        address[] calldata _mediators,
        bytes[] calldata signatures
    ) external view returns (uint256 validCount) {
        require(_mediators.length == signatures.length, "Length mismatch");

        for (uint256 i = 0; i < _mediators.length; i++) {
            if (
                shouldReturnValid &&
                isMediator[_mediators[i]] &&
                roundHash != bytes32(0) &&
                signatures[i].length > 0
            ) {
                validCount++;
            }
        }
    }
}
