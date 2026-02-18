// SPDX-License-Identifier: MIT
// Coverage stub – assembly-free VerifierRegistry
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "../../contracts/interfaces/IProofVerifier.sol";

contract VerifierRegistry is AccessControl, IVerifierRegistry {
    bytes32 public constant REGISTRY_ADMIN_ROLE =
        keccak256("REGISTRY_ADMIN_ROLE");
    bytes32 public constant VALIDITY_PROOF = keccak256("VALIDITY_PROOF");
    bytes32 public constant POLICY_PROOF = keccak256("POLICY_PROOF");
    bytes32 public constant NULLIFIER_PROOF = keccak256("NULLIFIER_PROOF");
    bytes32 public constant STATE_TRANSITION_PROOF =
        keccak256("STATE_TRANSITION_PROOF");
    bytes32 public constant CROSS_DOMAIN_PROOF =
        keccak256("CROSS_DOMAIN_PROOF");
    bytes32 public constant RANGE_PROOF = keccak256("RANGE_PROOF");
    bytes32 public constant MEMBERSHIP_PROOF = keccak256("MEMBERSHIP_PROOF");
    bytes32 public constant HEKATE_GROESTL_PROOF = keccak256("HEKATE_GROESTL");
    bytes32 public constant GKR_RECURSION_PROOF =
        keccak256("GKR_RECURSION_PROOF");
    bytes32 public constant BINIUS_PROOF = keccak256("BINIUS_PROOF");

    mapping(bytes32 => IProofVerifier) public verifiers;
    mapping(bytes32 => mapping(uint256 => IProofVerifier))
        public versionedVerifiers;
    mapping(bytes32 => uint256) public activeVersions;
    mapping(bytes32 => uint256) public versionCounts;
    bytes32[] public registeredTypes;
    mapping(bytes32 => bool) public isTypeRegistered;
    uint256 public totalVerifiers;

    event VerifierRegistered(
        bytes32 indexed proofType,
        address indexed verifier,
        address indexed registrar
    );
    event VerifierVersionRegistered(
        bytes32 indexed proofType,
        uint256 indexed version,
        address indexed verifier
    );
    event VerifierUpdated(
        bytes32 indexed proofType,
        address indexed oldVerifier,
        address indexed newVerifier
    );
    event VerifierVersionSwitched(
        bytes32 indexed proofType,
        uint256 oldVersion,
        uint256 newVersion
    );
    event VerifierRemoved(bytes32 indexed proofType, address indexed verifier);

    error VerifierNotFound(bytes32 proofType);
    error VerifierAlreadyRegistered(bytes32 proofType);
    error InvalidVerifier();
    error ZeroAddress();
    error VersionNotFound(bytes32 proofType, uint256 version);

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(REGISTRY_ADMIN_ROLE, msg.sender);
    }

    function registerVerifier(
        bytes32 proofType,
        address verifier
    ) external onlyRole(REGISTRY_ADMIN_ROLE) {
        if (verifier == address(0)) revert ZeroAddress();
        if (address(verifiers[proofType]) != address(0))
            revert VerifierAlreadyRegistered(proofType);
        verifiers[proofType] = IProofVerifier(verifier);
        if (!isTypeRegistered[proofType]) {
            registeredTypes.push(proofType);
            isTypeRegistered[proofType] = true;
        }
        totalVerifiers++;
        emit VerifierRegistered(proofType, verifier, msg.sender);
    }

    function registerVerifierVersion(
        bytes32 proofType,
        address verifier
    ) external onlyRole(REGISTRY_ADMIN_ROLE) {
        if (verifier == address(0)) revert ZeroAddress();
        uint256 version = versionCounts[proofType]++;
        versionedVerifiers[proofType][version] = IProofVerifier(verifier);
        emit VerifierVersionRegistered(proofType, version, verifier);
    }

    function switchVersion(
        bytes32 proofType,
        uint256 version
    ) external onlyRole(REGISTRY_ADMIN_ROLE) {
        if (address(versionedVerifiers[proofType][version]) == address(0))
            revert VersionNotFound(proofType, version);
        uint256 oldVersion = activeVersions[proofType];
        activeVersions[proofType] = version;
        verifiers[proofType] = versionedVerifiers[proofType][version];
        emit VerifierVersionSwitched(proofType, oldVersion, version);
    }

    function updateVerifier(
        bytes32 proofType,
        address newVerifier
    ) external onlyRole(REGISTRY_ADMIN_ROLE) {
        if (newVerifier == address(0)) revert ZeroAddress();
        address old = address(verifiers[proofType]);
        if (old == address(0)) revert VerifierNotFound(proofType);
        verifiers[proofType] = IProofVerifier(newVerifier);
        emit VerifierUpdated(proofType, old, newVerifier);
    }

    function removeVerifier(
        bytes32 proofType
    ) external onlyRole(REGISTRY_ADMIN_ROLE) {
        address old = address(verifiers[proofType]);
        if (old == address(0)) revert VerifierNotFound(proofType);
        delete verifiers[proofType];
        totalVerifiers--;
        emit VerifierRemoved(proofType, old);
    }

    function getVerifier(
        bytes32 proofType
    ) external view override returns (IProofVerifier) {
        IProofVerifier v = verifiers[proofType];
        if (address(v) == address(0)) revert VerifierNotFound(proofType);
        return v;
    }

    function hasVerifier(
        bytes32 proofType
    ) external view override returns (bool) {
        return address(verifiers[proofType]) != address(0);
    }

    function getAllProofTypes() external view returns (bytes32[] memory) {
        return registeredTypes;
    }

    function verifyProof(
        bytes32 proofType,
        bytes calldata proof,
        uint256[] calldata publicInputs
    ) external view returns (bool success) {
        IProofVerifier v = verifiers[proofType];
        if (address(v) == address(0)) revert VerifierNotFound(proofType);
        return v.verify(proof, publicInputs);
    }

    function verifySingleInput(
        bytes32 proofType,
        bytes calldata proof,
        uint256 publicInput
    ) external view returns (bool success) {
        IProofVerifier v = verifiers[proofType];
        if (address(v) == address(0)) revert VerifierNotFound(proofType);
        return v.verifySingle(proof, publicInput);
    }
}
