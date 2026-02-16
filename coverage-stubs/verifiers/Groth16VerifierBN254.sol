// SPDX-License-Identifier: MIT
// Coverage stub – assembly-free Groth16VerifierBN254
pragma solidity ^0.8.20;

import "../../contracts/interfaces/IProofVerifier.sol";

contract Groth16VerifierBN254 is IProofVerifier {
    error NotOwner();
    error NotInitialized();
    error AlreadyInitialized();
    error InvalidProofSize(uint256 size);
    error InvalidPublicInputCount(uint256 provided, uint256 expected);
    error InvalidPublicInput(uint256 index, uint256 value);
    error PairingCheckFailed();
    error PrecompileFailed();
    error InvalidOwner();

    event VerificationKeySet(uint256 icLength);
    event ProofVerified(bytes32 indexed proofHash, bool result);
    event OwnershipTransferred(
        address indexed previousOwner,
        address indexed newOwner
    );

    uint256[2] public vkAlpha;
    uint256[4] public vkBeta;
    uint256[4] public vkGamma;
    uint256[4] public vkDelta;
    uint256[2][] public vkIC;
    bool public initialized;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function setVerificationKey(
        uint256[2] calldata alpha,
        uint256[4] calldata beta,
        uint256[4] calldata gamma,
        uint256[4] calldata delta,
        uint256[2][] calldata ic
    ) external {
        if (msg.sender != owner) revert NotOwner();
        vkAlpha = alpha;
        vkBeta = beta;
        vkGamma = gamma;
        vkDelta = delta;
        delete vkIC;
        for (uint256 i = 0; i < ic.length; i++) {
            vkIC.push(ic[i]);
        }
        initialized = true;
        emit VerificationKeySet(ic.length);
    }

    function verify(
        bytes calldata,
        uint256[] calldata
    ) external pure override returns (bool) {
        return true;
    }

    function verifySingle(
        bytes calldata,
        uint256
    ) external pure override returns (bool) {
        return true;
    }

    function getPublicInputCount() external view override returns (uint256) {
        return vkIC.length > 0 ? vkIC.length - 1 : 0;
    }

    function verifyProof(
        bytes calldata,
        bytes calldata
    ) external pure override returns (bool) {
        return true;
    }

    function isReady() external view override returns (bool) {
        return initialized;
    }

    function transferOwnership(address newOwner) external {
        if (msg.sender != owner) revert NotOwner();
        if (newOwner == address(0)) revert InvalidOwner();
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }
}
