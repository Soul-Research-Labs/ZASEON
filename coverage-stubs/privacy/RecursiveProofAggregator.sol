// SPDX-License-Identifier: AGPL-3.0-only
// Coverage stub – assembly-free RecursiveProofAggregator
pragma solidity ^0.8.24;

import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

contract RecursiveProofAggregator is
    AccessControlUpgradeable,
    ReentrancyGuardUpgradeable,
    PausableUpgradeable,
    UUPSUpgradeable
{
    bytes32 public constant AGGREGATOR_ROLE = keccak256("AGGREGATOR_ROLE");
    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");
    bytes32 public constant EMERGENCY_ROLE = keccak256("EMERGENCY_ROLE");
    uint256 public constant MAX_BATCH_SIZE = 128;
    uint256 public constant MIN_BATCH_SIZE = 2;
    uint256 public constant AGGREGATION_WINDOW = 1 hours;
    uint256 public constant BN254_ORDER =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    enum ProofSystem {
        GROTH16,
        PLONK,
        STARK,
        NOVA,
        SUPERNOVA,
        HALO2
    }
    enum BatchState {
        OPEN,
        AGGREGATING,
        VERIFIED,
        FINALIZED,
        EXPIRED
    }

    struct ProofSubmission {
        bytes32 proofId;
        bytes32 batchId;
        ProofSystem system;
        bytes32 commitmentHash;
        bytes32 publicInputHash;
        uint256 chainId;
        uint64 submittedAt;
        bool verified;
        bool aggregated;
    }
    struct AggregationBatch {
        bytes32 batchId;
        address creator;
        BatchState state;
        ProofSystem system;
        bytes32[] proofIds;
        bytes32 aggregatedProofHash;
        bytes32 merkleRoot;
        uint256 proofCount;
        uint64 createdAt;
        uint64 aggregatedAt;
        uint64 expiresAt;
    }
    struct NovaProof {
        bytes32 U;
        bytes32 W;
        bytes32 u;
        bytes32 w;
        bytes32 T;
        uint256 step;
        bytes foldingProof;
    }
    struct Groth16Proof {
        uint256[2] a;
        uint256[2][2] b;
        uint256[2] c;
    }
    struct PLONKProof {
        bytes32 commitmentA;
        bytes32 commitmentB;
        bytes32 commitmentC;
        bytes32 commitmentZ;
        bytes32 commitmentT1;
        bytes32 commitmentT2;
        bytes32 commitmentT3;
        bytes32 commitmentWzeta;
        bytes32 commitmentWzetaOmega;
        bytes evaluation;
    }
    struct CrossChainProofBundle {
        bytes32 bundleId;
        uint256[] chainIds;
        bytes32[] proofRoots;
        bytes32 aggregatedRoot;
        bytes aggregatedProof;
        bool verified;
    }

    error ProofSubmissionFailed(bytes32 proofId);
    error BatchDoesNotExist(bytes32 batchId);
    error BatchNotOpen(bytes32 batchId);
    error BatchTooLarge(uint256 size, uint256 maxSize);
    error BatchTooSmall(uint256 size, uint256 minSize);
    error AggregationFailed(bytes32 batchId);
    error VerificationFailed(bytes32 proofId);
    error ProofAlreadySubmitted(bytes32 proofId);
    error InvalidProofSystem(ProofSystem system);
    error IncompatibleProofSystems();
    error FoldingError(uint256 step);
    error InvalidNovaProof();
    error CrossChainProofMismatch();
    error BatchExpired(bytes32 batchId);
    error NotBatchCreator(bytes32 batchId);
    error ZeroAddress();
    error InvalidProof();

    event ProofSubmitted(
        bytes32 indexed proofId,
        bytes32 indexed batchId,
        ProofSystem system,
        uint256 chainId
    );
    event BatchCreated(
        bytes32 indexed batchId,
        ProofSystem system,
        address creator
    );
    event BatchAggregated(
        bytes32 indexed batchId,
        bytes32 aggregatedProofHash,
        uint256 proofCount
    );
    event BatchVerified(bytes32 indexed batchId, bytes32 merkleRoot);
    event BatchFinalized(bytes32 indexed batchId);
    event NovaFoldingStep(
        bytes32 indexed batchId,
        uint256 step,
        bytes32 U,
        bytes32 u
    );
    event CrossChainBundleCreated(bytes32 indexed bundleId, uint256 chainCount);
    event CrossChainBundleVerified(
        bytes32 indexed bundleId,
        bytes32 aggregatedRoot
    );
    event VerifierUpdated(ProofSystem indexed system, address verifier);

    mapping(bytes32 => ProofSubmission) public proofSubmissions;
    mapping(bytes32 => AggregationBatch) internal _batches;
    mapping(ProofSystem => bytes32) public activeBatches;
    mapping(bytes32 => NovaProof) public novaStates;
    mapping(bytes32 => CrossChainProofBundle) public crossChainBundles;
    mapping(bytes32 => bool) public verifiedRoots;
    mapping(ProofSystem => address) public verifiers;
    uint256 public totalProofsSubmitted;
    uint256 public totalProofsAggregated;
    uint256 public totalBatches;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address admin) external initializer {
        __AccessControl_init();
        __ReentrancyGuard_init();
        __Pausable_init();
        __UUPSUpgradeable_init();
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(AGGREGATOR_ROLE, admin);
        _grantRole(VERIFIER_ROLE, admin);
        _grantRole(UPGRADER_ROLE, admin);
        _grantRole(EMERGENCY_ROLE, admin);
    }

    function _authorizeUpgrade(
        address
    ) internal override onlyRole(UPGRADER_ROLE) {}

    function submitProof(
        ProofSystem system,
        bytes32 commitmentHash,
        bytes32 publicInputHash,
        uint256 chainId
    ) external whenNotPaused returns (bytes32 proofId) {
        proofId = keccak256(
            abi.encodePacked(totalProofsSubmitted, msg.sender, block.timestamp)
        );
        bytes32 batchId = activeBatches[system];
        if (batchId == bytes32(0)) {
            batchId = keccak256(abi.encodePacked(totalBatches, msg.sender));
            AggregationBatch storage batch = _batches[batchId];
            batch.batchId = batchId;
            batch.creator = msg.sender;
            batch.state = BatchState.OPEN;
            batch.system = system;
            batch.createdAt = uint64(block.timestamp);
            batch.expiresAt = uint64(block.timestamp + AGGREGATION_WINDOW);
            activeBatches[system] = batchId;
            totalBatches++;
            emit BatchCreated(batchId, system, msg.sender);
        }
        _batches[batchId].proofIds.push(proofId);
        _batches[batchId].proofCount++;
        proofSubmissions[proofId] = ProofSubmission(
            proofId,
            batchId,
            system,
            commitmentHash,
            publicInputHash,
            chainId,
            uint64(block.timestamp),
            false,
            false
        );
        totalProofsSubmitted++;
        emit ProofSubmitted(proofId, batchId, system, chainId);
    }

    function submitNovaFolding(
        bytes32 batchId,
        NovaProof calldata novaProof
    ) external onlyRole(AGGREGATOR_ROLE) {
        if (_batches[batchId].createdAt == 0) revert BatchDoesNotExist(batchId);
        novaStates[batchId] = novaProof;
        emit NovaFoldingStep(batchId, novaProof.step, novaProof.U, novaProof.u);
    }

    function finalizeBatchAggregation(
        bytes32 batchId,
        bytes32 aggregatedProofHash,
        bytes32 merkleRoot
    ) external onlyRole(AGGREGATOR_ROLE) {
        AggregationBatch storage batch = _batches[batchId];
        if (batch.createdAt == 0) revert BatchDoesNotExist(batchId);
        batch.aggregatedProofHash = aggregatedProofHash;
        batch.merkleRoot = merkleRoot;
        batch.state = BatchState.VERIFIED;
        batch.aggregatedAt = uint64(block.timestamp);
        totalProofsAggregated += batch.proofCount;
        emit BatchAggregated(batchId, aggregatedProofHash, batch.proofCount);
        emit BatchVerified(batchId, merkleRoot);
    }

    function triggerAggregation(
        bytes32 batchId
    ) external onlyRole(AGGREGATOR_ROLE) {
        AggregationBatch storage batch = _batches[batchId];
        if (batch.createdAt == 0) revert BatchDoesNotExist(batchId);
        batch.state = BatchState.AGGREGATING;
    }

    function createCrossChainBundle(
        uint256[] calldata chainIds,
        bytes32[] calldata proofRoots
    ) external onlyRole(AGGREGATOR_ROLE) returns (bytes32 bundleId) {
        bundleId = keccak256(abi.encodePacked(chainIds, block.timestamp));
        crossChainBundles[bundleId] = CrossChainProofBundle(
            bundleId,
            chainIds,
            proofRoots,
            bytes32(0),
            "",
            false
        );
        emit CrossChainBundleCreated(bundleId, chainIds.length);
    }

    function finalizeCrossChainBundle(
        bytes32 bundleId,
        bytes32 aggregatedRoot,
        bytes calldata aggregatedProof
    ) external onlyRole(AGGREGATOR_ROLE) {
        CrossChainProofBundle storage bundle = crossChainBundles[bundleId];
        bundle.aggregatedRoot = aggregatedRoot;
        bundle.aggregatedProof = aggregatedProof;
        bundle.verified = true;
        verifiedRoots[aggregatedRoot] = true;
        emit CrossChainBundleVerified(bundleId, aggregatedRoot);
    }

    function verifyAggregatedProof(
        bytes32,
        bytes calldata,
        bytes calldata
    ) external pure returns (bool) {
        return true;
    }

    function getBatch(
        bytes32 batchId
    ) external view returns (AggregationBatch memory) {
        return _batches[batchId];
    }

    function getProofSubmission(
        bytes32 proofId
    ) external view returns (ProofSubmission memory) {
        return proofSubmissions[proofId];
    }

    function getCrossChainBundle(
        bytes32 bundleId
    ) external view returns (CrossChainProofBundle memory) {
        return crossChainBundles[bundleId];
    }

    function getNovaState(
        bytes32 batchId
    ) external view returns (NovaProof memory) {
        return novaStates[batchId];
    }

    function isRootVerified(bytes32 root) external view returns (bool) {
        return verifiedRoots[root];
    }

    function setVerifier(
        ProofSystem system,
        address verifier
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        verifiers[system] = verifier;
        emit VerifierUpdated(system, verifier);
    }

    function pause() external onlyRole(EMERGENCY_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }
}
