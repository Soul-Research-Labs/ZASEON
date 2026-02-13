// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/verifiers/ProofAggregator.sol";

/// @dev Mock verifier that always returns true
contract MockAggregatedVerifier {
    function verifyProof(
        bytes calldata,
        bytes calldata
    ) external pure returns (bool) {
        return true;
    }
}

/// @dev Mock verifier that always returns false
contract MockFailVerifier {
    function verifyProof(
        bytes calldata,
        bytes calldata
    ) external pure returns (bool) {
        return false;
    }
}

/// @dev Mock verifier that reverts
contract MockRevertVerifier {
    function verifyProof(bytes calldata, bytes calldata) external pure {
        revert("verification failed");
    }

    // Fallback verify signature also reverts
    function verify(bytes calldata, bytes calldata) external pure {
        revert("also failed");
    }
}

contract ProofAggregatorTest is Test {
    ProofAggregator public aggregator;
    MockAggregatedVerifier public mockVerifier;
    MockFailVerifier public failVerifier;
    address public admin;

    function setUp() public {
        admin = address(this);
        mockVerifier = new MockAggregatedVerifier();
        failVerifier = new MockFailVerifier();
        aggregator = new ProofAggregator(address(mockVerifier));
    }

    // ============= Constructor =============

    function test_Constructor_SetsVerifier() public view {
        assertEq(aggregator.aggregatedProofVerifier(), address(mockVerifier));
    }

    function test_Constructor_AdminRoles() public view {
        assertTrue(aggregator.hasRole(aggregator.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(aggregator.hasRole(aggregator.AGGREGATOR_ROLE(), admin));
        assertTrue(aggregator.hasRole(aggregator.VERIFIER_ADMIN_ROLE(), admin));
    }

    function test_Constants() public view {
        assertEq(aggregator.MAX_BATCH_SIZE(), 256);
        assertEq(aggregator.MIN_BATCH_SIZE(), 2);
    }

    // ============= Proof Registration =============

    function test_RegisterProof() public {
        bytes32 proofHash = keccak256("proof1");
        bytes32 inputsHash = keccak256("inputs1");
        aggregator.registerProof(proofHash, inputsHash, 1);

        (bytes32 ph, bytes32 ih, uint64 chainId, , bool verified) = aggregator
            .proofData(proofHash);
        assertEq(ph, proofHash);
        assertEq(ih, inputsHash);
        assertEq(chainId, 1);
        assertFalse(verified);
    }

    function test_RegisterProof_RevertDuplicate() public {
        bytes32 proofHash = keccak256("proof1");
        aggregator.registerProof(proofHash, keccak256("a"), 1);
        vm.expectRevert(
            abi.encodeWithSelector(
                ProofAggregator.ProofAlreadyAdded.selector,
                proofHash
            )
        );
        aggregator.registerProof(proofHash, keccak256("b"), 1);
    }

    function test_RegisterProofsBatch() public {
        bytes32[] memory hashes = new bytes32[](3);
        bytes32[] memory inputs = new bytes32[](3);
        uint64[] memory chains = new uint64[](3);
        for (uint256 i = 0; i < 3; i++) {
            hashes[i] = keccak256(abi.encodePacked("proof", i));
            inputs[i] = keccak256(abi.encodePacked("input", i));
            chains[i] = uint64(i + 1);
        }
        aggregator.registerProofsBatch(hashes, inputs, chains);
        (bytes32 ph, , , , ) = aggregator.proofData(hashes[0]);
        assertEq(ph, hashes[0]);
    }

    function test_RegisterProofsBatch_RevertLengthMismatch() public {
        bytes32[] memory hashes = new bytes32[](2);
        bytes32[] memory inputs = new bytes32[](3);
        uint64[] memory chains = new uint64[](2);
        vm.expectRevert(ProofAggregator.LengthMismatch.selector);
        aggregator.registerProofsBatch(hashes, inputs, chains);
    }

    function test_RegisterProof_RevertNotAggregator() public {
        vm.prank(address(0xBAD));
        vm.expectRevert();
        aggregator.registerProof(bytes32(uint256(1)), bytes32(uint256(2)), 1);
    }

    // ============= Merkle Batch =============

    function test_CreateMerkleBatch() public {
        bytes32[] memory proofHashes = _registerProofs(4);
        bytes32 batchId = aggregator.createMerkleBatch(proofHashes);
        assertTrue(batchId != bytes32(0));

        (
            bytes32 merkleRoot,
            ,
            uint256 proofCount,
            ,
            ,
            bool isVerified,
            ProofAggregator.AggregationType aggType
        ) = aggregator.getBatch(batchId);
        assertTrue(merkleRoot != bytes32(0));
        assertEq(proofCount, 4);
        assertFalse(isVerified);
        assertEq(uint8(aggType), uint8(ProofAggregator.AggregationType.MERKLE));
    }

    function test_CreateMerkleBatch_RevertEmpty() public {
        bytes32[] memory empty = new bytes32[](0);
        vm.expectRevert(ProofAggregator.EmptyProofArray.selector);
        aggregator.createMerkleBatch(empty);
    }

    function test_CreateMerkleBatch_RevertTooSmall() public {
        bytes32[] memory one = _registerProofs(1);
        vm.expectRevert(
            abi.encodeWithSelector(ProofAggregator.BatchTooSmall.selector, 1, 2)
        );
        aggregator.createMerkleBatch(one);
    }

    function test_CreateMerkleBatch_RevertUnregisteredProof() public {
        bytes32[] memory proofs = new bytes32[](2);
        proofs[0] = keccak256("unregistered1");
        proofs[1] = keccak256("unregistered2");
        vm.expectRevert(
            abi.encodeWithSelector(
                ProofAggregator.ProofNotFound.selector,
                proofs[0]
            )
        );
        aggregator.createMerkleBatch(proofs);
    }

    function test_CreateMerkleBatch_IncrementsTotalBatches() public {
        bytes32[] memory proofs1 = _registerProofs(2);
        aggregator.createMerkleBatch(proofs1);
        assertEq(aggregator.totalBatches(), 1);

        bytes32[] memory proofs2 = _registerMoreProofs(2, 10);
        aggregator.createMerkleBatch(proofs2);
        assertEq(aggregator.totalBatches(), 2);
    }

    function test_CreateMerkleBatch_UpdatesTotalProofsAggregated() public {
        bytes32[] memory proofs = _registerProofs(5);
        aggregator.createMerkleBatch(proofs);
        assertEq(aggregator.totalProofsAggregated(), 5);
    }

    function test_VerifyMerkleBatch() public {
        bytes32[] memory proofHashes = _registerProofs(3);
        bytes32 batchId = aggregator.createMerkleBatch(proofHashes);

        // Build public inputs containing the merkle root as first 32 bytes
        (bytes32 merkleRoot, , , , , , ) = aggregator.getBatch(batchId);
        bytes memory publicInputs = abi.encodePacked(merkleRoot);
        bytes memory proof = hex"deadbeef";

        bool verified = aggregator.verifyMerkleBatch(
            batchId,
            proof,
            publicInputs
        );
        assertTrue(verified);

        (, , , , , bool isVerified, ) = aggregator.getBatch(batchId);
        assertTrue(isVerified);
    }

    function test_VerifyMerkleBatch_MarksIndividualProofsVerified() public {
        bytes32[] memory proofHashes = _registerProofs(3);
        bytes32 batchId = aggregator.createMerkleBatch(proofHashes);

        (bytes32 merkleRoot, , , , , , ) = aggregator.getBatch(batchId);
        bytes memory publicInputs = abi.encodePacked(merkleRoot);
        aggregator.verifyMerkleBatch(batchId, hex"aabb", publicInputs);

        for (uint256 i = 0; i < proofHashes.length; i++) {
            assertTrue(aggregator.isProofVerified(proofHashes[i]));
        }
    }

    function test_VerifyMerkleBatch_RevertAlreadyVerified() public {
        bytes32[] memory proofHashes = _registerProofs(2);
        bytes32 batchId = aggregator.createMerkleBatch(proofHashes);

        (bytes32 merkleRoot, , , , , , ) = aggregator.getBatch(batchId);
        bytes memory publicInputs = abi.encodePacked(merkleRoot);
        aggregator.verifyMerkleBatch(batchId, hex"aabb", publicInputs);

        vm.expectRevert(
            abi.encodeWithSelector(
                ProofAggregator.BatchAlreadyVerified.selector,
                batchId
            )
        );
        aggregator.verifyMerkleBatch(batchId, hex"aabb", publicInputs);
    }

    function test_VerifyMerkleBatch_RevertMerkleRootMismatch() public {
        bytes32[] memory proofHashes = _registerProofs(2);
        bytes32 batchId = aggregator.createMerkleBatch(proofHashes);

        // Wrong merkle root
        bytes memory wrongInputs = abi.encodePacked(bytes32(uint256(999)));
        vm.expectRevert(ProofAggregator.MerkleRootMismatch.selector);
        aggregator.verifyMerkleBatch(batchId, hex"aabb", wrongInputs);
    }

    function test_VerifyMerkleBatch_RevertVerifierNotSet() public {
        aggregator.setAggregatedProofVerifier(address(0));

        bytes32[] memory proofHashes = _registerProofs(2);
        bytes32 batchId = aggregator.createMerkleBatch(proofHashes);

        (bytes32 merkleRoot, , , , , , ) = aggregator.getBatch(batchId);
        bytes memory publicInputs = abi.encodePacked(merkleRoot);

        vm.expectRevert(ProofAggregator.VerifierNotSet.selector);
        aggregator.verifyMerkleBatch(batchId, hex"aabb", publicInputs);
    }

    function test_VerifyMerkleBatch_RevertInvalidProof() public {
        // Use fail verifier
        aggregator.setAggregatedProofVerifier(address(failVerifier));

        bytes32[] memory proofHashes = _registerProofs(2);
        bytes32 batchId = aggregator.createMerkleBatch(proofHashes);

        (bytes32 merkleRoot, , , , , , ) = aggregator.getBatch(batchId);
        bytes memory publicInputs = abi.encodePacked(merkleRoot);

        vm.expectRevert(ProofAggregator.InvalidAggregatedProof.selector);
        aggregator.verifyMerkleBatch(batchId, hex"bad0", publicInputs);
    }

    // ============= Recursive Batch =============

    function test_CreateRecursiveBatch() public {
        bytes32[] memory proofHashes = _registerProofs(3);
        bytes32 aggHash = keccak256("recursive_proof");
        bytes32 batchId = aggregator.createRecursiveBatch(proofHashes, aggHash);

        (
            ,
            bytes32 aggregatedProofHash,
            uint256 proofCount,
            ,
            ,
            ,
            ProofAggregator.AggregationType aggType
        ) = aggregator.getBatch(batchId);
        assertEq(aggregatedProofHash, aggHash);
        assertEq(proofCount, 3);
        assertEq(
            uint8(aggType),
            uint8(ProofAggregator.AggregationType.RECURSIVE)
        );
    }

    function test_VerifyRecursiveBatch() public {
        bytes32[] memory proofHashes = _registerProofs(3);
        bytes memory recursiveProof = hex"deadbeef";
        bytes32 aggHash = keccak256(recursiveProof);
        bytes32 batchId = aggregator.createRecursiveBatch(proofHashes, aggHash);

        bool verified = aggregator.verifyRecursiveBatch(
            batchId,
            recursiveProof,
            abi.encodePacked(aggHash)
        );
        assertTrue(verified);
    }

    function test_VerifyRecursiveBatch_RevertProofHashMismatch() public {
        bytes32[] memory proofHashes = _registerProofs(2);
        bytes32 aggHash = keccak256("expected_proof");
        bytes32 batchId = aggregator.createRecursiveBatch(proofHashes, aggHash);

        vm.expectRevert(ProofAggregator.InvalidAggregatedProof.selector);
        aggregator.verifyRecursiveBatch(
            batchId,
            hex"baddeed0",
            abi.encodePacked(aggHash)
        );
    }

    // ============= Accumulator Batch =============

    function test_CreateAccumulatorBatch() public {
        bytes32[] memory proofHashes = _registerProofs(4);
        bytes32 accumulator = keccak256("initial_accumulator");
        bytes32 batchId = aggregator.createAccumulatorBatch(
            proofHashes,
            accumulator
        );

        (
            ,
            ,
            uint256 proofCount,
            ,
            ,
            ,
            ProofAggregator.AggregationType aggType
        ) = aggregator.getBatch(batchId);
        assertEq(proofCount, 4);
        assertEq(
            uint8(aggType),
            uint8(ProofAggregator.AggregationType.ACCUMULATOR)
        );
    }

    // ============= View Functions =============

    function test_GetBatchProofs() public {
        bytes32[] memory proofHashes = _registerProofs(3);
        bytes32 batchId = aggregator.createMerkleBatch(proofHashes);

        bytes32[] memory stored = aggregator.getBatchProofs(batchId);
        assertEq(stored.length, 3);
        for (uint256 i = 0; i < 3; i++) {
            assertEq(stored[i], proofHashes[i]);
        }
    }

    function test_IsProofVerified_DefaultFalse() public view {
        assertFalse(aggregator.isProofVerified(keccak256("nonexistent")));
    }

    function test_EstimateGasSavings() public view {
        (
            uint256 individual,
            uint256 batched,
            uint256 savings,
            uint256 pct
        ) = aggregator.estimateGasSavings(10);
        assertEq(individual, 10 * 280_000);
        assertEq(batched, 300_000 + 10 * 25_000);
        assertTrue(savings > 0);
        assertTrue(pct > 0);
    }

    function test_EstimateGasSavings_SingleProof() public view {
        (uint256 individual, uint256 batched, uint256 savings, ) = aggregator
            .estimateGasSavings(1);
        assertEq(individual, 280_000);
        assertEq(batched, 325_000);
        // Single proof has no savings (batched > individual)
        assertEq(savings, 0);
    }

    // ============= Admin =============

    function test_SetAggregatedProofVerifier() public {
        address newVerifier = address(0xBEEF);
        aggregator.setAggregatedProofVerifier(newVerifier);
        assertEq(aggregator.aggregatedProofVerifier(), newVerifier);
    }

    function test_SetAggregatedProofVerifier_RevertNotAdmin() public {
        vm.prank(address(0xBAD));
        vm.expectRevert();
        aggregator.setAggregatedProofVerifier(address(0xBEEF));
    }

    // ============= VerifyProofInBatch =============

    function test_VerifyProofInBatch_NotInBatch() public view {
        assertFalse(
            aggregator.verifyProofInBatch(
                keccak256("nope"),
                new bytes32[](0),
                0
            )
        );
    }

    // ============= Fuzz =============

    function testFuzz_RegisterProof_UniqueHashes(
        bytes32 hash1,
        bytes32 hash2
    ) public {
        vm.assume(hash1 != hash2 && hash1 != bytes32(0) && hash2 != bytes32(0));
        aggregator.registerProof(hash1, keccak256("a"), 1);
        aggregator.registerProof(hash2, keccak256("b"), 2);
        (bytes32 ph1, , , , ) = aggregator.proofData(hash1);
        (bytes32 ph2, , , , ) = aggregator.proofData(hash2);
        assertEq(ph1, hash1);
        assertEq(ph2, hash2);
    }

    function testFuzz_BatchSize(uint8 size) public {
        uint256 batchSize = bound(size, 2, 50);
        bytes32[] memory proofs = _registerProofs(batchSize);
        bytes32 batchId = aggregator.createMerkleBatch(proofs);
        (, , uint256 count, , , , ) = aggregator.getBatch(batchId);
        assertEq(count, batchSize);
    }

    // ============= Helpers =============

    function _registerProofs(
        uint256 count
    ) internal returns (bytes32[] memory hashes) {
        return _registerMoreProofs(count, 0);
    }

    function _registerMoreProofs(
        uint256 count,
        uint256 offset
    ) internal returns (bytes32[] memory hashes) {
        hashes = new bytes32[](count);
        for (uint256 i = 0; i < count; i++) {
            hashes[i] = keccak256(abi.encodePacked("proof_", i + offset));
            aggregator.registerProof(
                hashes[i],
                keccak256(abi.encodePacked("input_", i + offset)),
                uint64(i + 1)
            );
        }
    }
}
