// SPDX-License-Identifier: MIT
// Coverage stub – assembly-free ProofAggregator
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

struct BatchProofInput {
    bytes32 proofHash;
    bytes32 publicInputsHash;
    bytes32 commitment;
    uint64 sourceChainId;
    uint64 destChainId;
}

contract ProofAggregator is AccessControl, ReentrancyGuard {
    bytes32 public constant AGGREGATOR_ROLE = keccak256("AGGREGATOR_ROLE");
    bytes32 public constant VERIFIER_ADMIN_ROLE =
        keccak256("VERIFIER_ADMIN_ROLE");
    uint256 public constant MAX_BATCH_SIZE = 256;
    uint256 public constant MIN_BATCH_SIZE = 2;

    enum AggregationType {
        MERKLE,
        RECURSIVE,
        ACCUMULATOR
    }

    struct ProofData {
        bytes32 proofHash;
        bytes32 publicInputsHash;
        uint64 chainId;
        uint64 timestamp;
        bool verified;
    }

    struct AggregatedBatch {
        bytes32 batchId;
        bytes32 merkleRoot;
        bytes32 aggregatedProofHash;
        bytes32[] proofHashes;
        uint256 proofCount;
        uint64 createdAt;
        uint64 verifiedAt;
        bool isVerified;
        AggregationType aggregationType;
    }

    mapping(bytes32 => ProofData) public proofData;
    mapping(bytes32 => AggregatedBatch) public aggregatedBatches;
    mapping(bytes32 => bytes32) public proofToBatch;
    address public aggregatedProofVerifier;
    uint256 public totalBatches;
    uint256 public totalProofsAggregated;

    event ProofAdded(
        bytes32 indexed proofHash,
        bytes32 publicInputsHash,
        uint64 chainId
    );
    event BatchCreated(
        bytes32 indexed batchId,
        bytes32 merkleRoot,
        uint256 proofCount,
        AggregationType aggregationType
    );
    event BatchVerified(
        bytes32 indexed batchId,
        bytes32 aggregatedProofHash,
        uint256 gasUsed
    );
    event AggregatedProofVerified(bytes32 indexed batchId, bool valid);
    event VerifierUpdated(
        address indexed oldVerifier,
        address indexed newVerifier
    );

    error BatchTooLarge(uint256 size, uint256 max);
    error BatchTooSmall(uint256 size, uint256 min);
    error BatchNotFound(bytes32 batchId);
    error BatchAlreadyVerified(bytes32 batchId);
    error ProofAlreadyAdded(bytes32 proofHash);
    error ProofNotFound(bytes32 proofHash);
    error InvalidMerkleProof();
    error VerifierNotSet();
    error InvalidAggregatedProof();
    error EmptyProofArray();
    error LengthMismatch();
    error MerkleRootMismatch();

    constructor(address _aggregatedProofVerifier) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(AGGREGATOR_ROLE, msg.sender);
        _grantRole(VERIFIER_ADMIN_ROLE, msg.sender);
        aggregatedProofVerifier = _aggregatedProofVerifier;
    }

    function registerProof(
        bytes32 proofHash,
        bytes32 publicInputsHash,
        uint64 chainId
    ) external onlyRole(AGGREGATOR_ROLE) {
        if (proofData[proofHash].timestamp != 0)
            revert ProofAlreadyAdded(proofHash);
        proofData[proofHash] = ProofData(
            proofHash,
            publicInputsHash,
            chainId,
            uint64(block.timestamp),
            false
        );
        emit ProofAdded(proofHash, publicInputsHash, chainId);
    }

    function registerProofsBatch(
        bytes32[] calldata proofHashes,
        bytes32[] calldata publicInputsHashes,
        uint64[] calldata chainIds
    ) external onlyRole(AGGREGATOR_ROLE) {
        if (
            proofHashes.length != publicInputsHashes.length ||
            proofHashes.length != chainIds.length
        ) revert LengthMismatch();
        for (uint256 i = 0; i < proofHashes.length; i++) {
            proofData[proofHashes[i]] = ProofData(
                proofHashes[i],
                publicInputsHashes[i],
                chainIds[i],
                uint64(block.timestamp),
                false
            );
        }
    }

    function createMerkleBatch(
        bytes32[] calldata proofHashes
    ) external onlyRole(AGGREGATOR_ROLE) returns (bytes32 batchId) {
        if (proofHashes.length < MIN_BATCH_SIZE)
            revert BatchTooSmall(proofHashes.length, MIN_BATCH_SIZE);
        if (proofHashes.length > MAX_BATCH_SIZE)
            revert BatchTooLarge(proofHashes.length, MAX_BATCH_SIZE);
        batchId = keccak256(abi.encodePacked(totalBatches, block.timestamp));
        bytes32 root = keccak256(abi.encodePacked(proofHashes));
        AggregatedBatch storage batch = aggregatedBatches[batchId];
        batch.batchId = batchId;
        batch.merkleRoot = root;
        batch.proofHashes = proofHashes;
        batch.proofCount = proofHashes.length;
        batch.createdAt = uint64(block.timestamp);
        batch.aggregationType = AggregationType.MERKLE;
        totalBatches++;
        totalProofsAggregated += proofHashes.length;
        emit BatchCreated(
            batchId,
            root,
            proofHashes.length,
            AggregationType.MERKLE
        );
    }

    function verifyMerkleBatch(
        bytes32 batchId,
        bytes calldata,
        bytes calldata
    ) external returns (bool) {
        AggregatedBatch storage batch = aggregatedBatches[batchId];
        if (batch.createdAt == 0) revert BatchNotFound(batchId);
        if (batch.isVerified) revert BatchAlreadyVerified(batchId);
        batch.isVerified = true;
        batch.verifiedAt = uint64(block.timestamp);
        return true;
    }

    function verifyProofInBatch(
        bytes32,
        bytes32[] calldata,
        uint256
    ) external pure returns (bool valid) {
        return true;
    }

    function createRecursiveBatch(
        bytes32[] calldata proofHashes,
        bytes32 aggregatedProofHash
    ) external onlyRole(AGGREGATOR_ROLE) returns (bytes32 batchId) {
        batchId = keccak256(
            abi.encodePacked(totalBatches, block.timestamp, uint8(1))
        );
        AggregatedBatch storage batch = aggregatedBatches[batchId];
        batch.batchId = batchId;
        batch.aggregatedProofHash = aggregatedProofHash;
        batch.proofHashes = proofHashes;
        batch.proofCount = proofHashes.length;
        batch.createdAt = uint64(block.timestamp);
        batch.aggregationType = AggregationType.RECURSIVE;
        totalBatches++;
    }

    function verifyRecursiveBatch(
        bytes32 batchId,
        bytes calldata,
        bytes calldata
    ) external returns (bool) {
        AggregatedBatch storage batch = aggregatedBatches[batchId];
        if (batch.createdAt == 0) revert BatchNotFound(batchId);
        batch.isVerified = true;
        batch.verifiedAt = uint64(block.timestamp);
        return true;
    }

    function createAccumulatorBatch(
        bytes32[] calldata proofHashes,
        bytes32
    ) external onlyRole(AGGREGATOR_ROLE) returns (bytes32 batchId) {
        batchId = keccak256(
            abi.encodePacked(totalBatches, block.timestamp, uint8(2))
        );
        AggregatedBatch storage batch = aggregatedBatches[batchId];
        batch.batchId = batchId;
        batch.proofHashes = proofHashes;
        batch.proofCount = proofHashes.length;
        batch.createdAt = uint64(block.timestamp);
        batch.aggregationType = AggregationType.ACCUMULATOR;
        totalBatches++;
    }

    function getBatch(
        bytes32 batchId
    )
        external
        view
        returns (
            bytes32 merkleRoot,
            bytes32 aggregatedProofHash,
            uint256 proofCount,
            uint64 createdAt,
            uint64 verifiedAt,
            bool isVerified,
            AggregationType aggregationType
        )
    {
        AggregatedBatch storage b = aggregatedBatches[batchId];
        return (
            b.merkleRoot,
            b.aggregatedProofHash,
            b.proofCount,
            b.createdAt,
            b.verifiedAt,
            b.isVerified,
            b.aggregationType
        );
    }

    function getBatchProofs(
        bytes32 batchId
    ) external view returns (bytes32[] memory) {
        return aggregatedBatches[batchId].proofHashes;
    }

    function isProofVerified(bytes32 proofHash) external view returns (bool) {
        return proofData[proofHash].verified;
    }

    function estimateGasSavings(
        uint256 numProofs
    )
        external
        pure
        returns (
            uint256 individualGas,
            uint256 batchedGas,
            uint256 savings,
            uint256 savingsPercent
        )
    {
        individualGas = numProofs * 300000;
        batchedGas = 300000 + (numProofs * 50000);
        savings = individualGas - batchedGas;
        savingsPercent = (savings * 100) / individualGas;
    }

    function setAggregatedProofVerifier(
        address _verifier
    ) external onlyRole(VERIFIER_ADMIN_ROLE) {
        emit VerifierUpdated(aggregatedProofVerifier, _verifier);
        aggregatedProofVerifier = _verifier;
    }
}
