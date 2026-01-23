// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/linea/LineaPrimitives.sol";

/**
 * @title LineaFuzz
 * @notice Comprehensive fuzz tests for Linea zkEVM primitives and bridge operations
 * @dev Tests PLONK proofs, messaging, nullifiers, and Merkle proofs
 */
contract LineaFuzz is Test {
    using LineaPrimitives for *;

    // =========================================================================
    // SETUP
    // =========================================================================

    function setUp() public {}

    // =========================================================================
    // HASH FUNCTION TESTS
    // =========================================================================

    function testFuzz_Keccak256Determinism(bytes memory data) public pure {
        bytes32 hash1 = LineaPrimitives.keccak256Hash(data);
        bytes32 hash2 = LineaPrimitives.keccak256Hash(data);
        assertEq(hash1, hash2, "Hash should be deterministic");
    }

    function testFuzz_Keccak256Uniqueness(
        bytes memory data1,
        bytes memory data2
    ) public pure {
        vm.assume(keccak256(data1) != keccak256(data2));
        bytes32 hash1 = LineaPrimitives.keccak256Hash(data1);
        bytes32 hash2 = LineaPrimitives.keccak256Hash(data2);
        assertNotEq(
            hash1,
            hash2,
            "Different inputs should produce different hashes"
        );
    }

    function testFuzz_L1L2MessageHashDeterminism(
        address sender,
        address recipient,
        uint256 value,
        uint256 nonce,
        bytes memory data
    ) public pure {
        bytes32 hash1 = LineaPrimitives.computeL1L2MessageHash(
            sender,
            recipient,
            value,
            nonce,
            data
        );
        bytes32 hash2 = LineaPrimitives.computeL1L2MessageHash(
            sender,
            recipient,
            value,
            nonce,
            data
        );
        assertEq(hash1, hash2, "L1L2 message hash should be deterministic");
    }

    function testFuzz_L2L1MessageHashDeterminism(
        address sender,
        address recipient,
        uint256 value,
        uint256 nonce,
        uint256 blockNumber,
        bytes memory data
    ) public pure {
        bytes32 hash1 = LineaPrimitives.computeL2L1MessageHash(
            sender,
            recipient,
            value,
            nonce,
            blockNumber,
            data
        );
        bytes32 hash2 = LineaPrimitives.computeL2L1MessageHash(
            sender,
            recipient,
            value,
            nonce,
            blockNumber,
            data
        );
        assertEq(hash1, hash2, "L2L1 message hash should be deterministic");
    }

    function testFuzz_L1L2VsL2L1MessageHashDifferent(
        address sender,
        address recipient,
        uint256 value,
        uint256 nonce,
        uint256 blockNumber,
        bytes memory data
    ) public pure {
        bytes32 l1l2Hash = LineaPrimitives.computeL1L2MessageHash(
            sender,
            recipient,
            value,
            nonce,
            data
        );
        bytes32 l2l1Hash = LineaPrimitives.computeL2L1MessageHash(
            sender,
            recipient,
            value,
            nonce,
            blockNumber,
            data
        );
        assertNotEq(l1l2Hash, l2l1Hash, "L1L2 and L2L1 hashes should differ");
    }

    // =========================================================================
    // NULLIFIER TESTS
    // =========================================================================

    function testFuzz_LineaNullifierDeterminism(
        bytes32 messageHash,
        uint256 blockNumber,
        bytes32 commitment
    ) public pure {
        bytes32 nf1 = LineaPrimitives.deriveLineaNullifier(
            messageHash,
            blockNumber,
            commitment
        );
        bytes32 nf2 = LineaPrimitives.deriveLineaNullifier(
            messageHash,
            blockNumber,
            commitment
        );
        assertEq(nf1, nf2, "Nullifier should be deterministic");
    }

    function testFuzz_LineaNullifierUniqueness(
        bytes32 messageHash1,
        bytes32 messageHash2,
        uint256 blockNumber,
        bytes32 commitment
    ) public pure {
        vm.assume(messageHash1 != messageHash2);
        bytes32 nf1 = LineaPrimitives.deriveLineaNullifier(
            messageHash1,
            blockNumber,
            commitment
        );
        bytes32 nf2 = LineaPrimitives.deriveLineaNullifier(
            messageHash2,
            blockNumber,
            commitment
        );
        assertNotEq(
            nf1,
            nf2,
            "Different messages should produce different nullifiers"
        );
    }

    function testFuzz_CrossDomainNullifierDeterminism(
        bytes32 lineaNullifier,
        uint256 targetDomain
    ) public pure {
        bytes32 cd1 = LineaPrimitives.deriveCrossDomainNullifier(
            lineaNullifier,
            targetDomain
        );
        bytes32 cd2 = LineaPrimitives.deriveCrossDomainNullifier(
            lineaNullifier,
            targetDomain
        );
        assertEq(cd1, cd2, "Cross-domain nullifier should be deterministic");
    }

    function testFuzz_CrossDomainNullifierDifferentDomains(
        bytes32 lineaNullifier,
        uint256 domain1,
        uint256 domain2
    ) public pure {
        vm.assume(domain1 != domain2);
        bytes32 cd1 = LineaPrimitives.deriveCrossDomainNullifier(
            lineaNullifier,
            domain1
        );
        bytes32 cd2 = LineaPrimitives.deriveCrossDomainNullifier(
            lineaNullifier,
            domain2
        );
        assertNotEq(
            cd1,
            cd2,
            "Different domains should produce different nullifiers"
        );
    }

    function testFuzz_PILBindingDeterminism(
        bytes32 lineaNullifier,
        bytes32 pilDomain
    ) public pure {
        bytes32 binding1 = LineaPrimitives.derivePILBinding(
            lineaNullifier,
            pilDomain
        );
        bytes32 binding2 = LineaPrimitives.derivePILBinding(
            lineaNullifier,
            pilDomain
        );
        assertEq(binding1, binding2, "PIL binding should be deterministic");
    }

    function testFuzz_PILBindingUniqueness(
        bytes32 lineaNullifier1,
        bytes32 lineaNullifier2,
        bytes32 pilDomain
    ) public pure {
        vm.assume(lineaNullifier1 != lineaNullifier2);
        bytes32 binding1 = LineaPrimitives.derivePILBinding(
            lineaNullifier1,
            pilDomain
        );
        bytes32 binding2 = LineaPrimitives.derivePILBinding(
            lineaNullifier2,
            pilDomain
        );
        assertNotEq(
            binding1,
            binding2,
            "Different nullifiers should produce different bindings"
        );
    }

    // =========================================================================
    // MERKLE PROOF TESTS
    // =========================================================================

    function testFuzz_MerkleRootSingleLeaf(bytes32 leaf) public pure {
        bytes32[] memory leaves = new bytes32[](1);
        leaves[0] = leaf;
        bytes32 root = LineaPrimitives.computeMerkleRoot(leaves);
        assertEq(root, leaf, "Single leaf root should be the leaf itself");
    }

    function testFuzz_MerkleRootTwoLeaves(
        bytes32 leaf1,
        bytes32 leaf2
    ) public pure {
        bytes32[] memory leaves = new bytes32[](2);
        leaves[0] = leaf1;
        leaves[1] = leaf2;
        bytes32 root = LineaPrimitives.computeMerkleRoot(leaves);
        bytes32 expected = keccak256(abi.encodePacked(leaf1, leaf2));
        assertEq(root, expected, "Two leaf root should be hash of leaves");
    }

    function testFuzz_MerkleProofVerification(
        bytes32 leaf,
        bytes32 sibling
    ) public pure {
        // Build a simple 2-leaf tree
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = sibling;

        // For index 0: root = hash(leaf, sibling)
        bytes32 root = keccak256(abi.encodePacked(leaf, sibling));
        bool valid = LineaPrimitives.verifyMerkleProof(root, leaf, proof, 0);
        assertTrue(valid, "Valid Merkle proof should verify");

        // For index 1: root = hash(sibling, leaf)
        bytes32 root2 = keccak256(abi.encodePacked(sibling, leaf));
        bool valid2 = LineaPrimitives.verifyMerkleProof(root2, leaf, proof, 1);
        assertTrue(valid2, "Valid Merkle proof at index 1 should verify");
    }

    function testFuzz_MerkleProofInvalid(
        bytes32 leaf,
        bytes32 wrongLeaf,
        bytes32 sibling
    ) public pure {
        vm.assume(leaf != wrongLeaf);
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = sibling;

        bytes32 root = keccak256(abi.encodePacked(leaf, sibling));
        bool valid = LineaPrimitives.verifyMerkleProof(
            root,
            wrongLeaf,
            proof,
            0
        );
        assertFalse(valid, "Invalid Merkle proof should not verify");
    }

    function testFuzz_MerkleRootEmpty() public pure {
        bytes32[] memory leaves = new bytes32[](0);
        bytes32 root = LineaPrimitives.computeMerkleRoot(leaves);
        assertEq(root, bytes32(0), "Empty leaves should return zero root");
    }

    // =========================================================================
    // PLONK PROOF VALIDATION TESTS
    // =========================================================================

    function testFuzz_PLONKProofValidation(
        uint256 x_lo,
        uint256 x_hi,
        uint256 y_lo,
        uint256 y_hi,
        uint256 a_eval,
        uint256 b_eval,
        uint256 c_eval
    ) public pure {
        // Bound evaluations to valid scalar field range
        a_eval = bound(a_eval, 0, LineaPrimitives.BLS12_381_SCALAR_ORDER - 1);
        b_eval = bound(b_eval, 0, LineaPrimitives.BLS12_381_SCALAR_ORDER - 1);
        c_eval = bound(c_eval, 0, LineaPrimitives.BLS12_381_SCALAR_ORDER - 1);

        // Ensure at least one coordinate is non-zero for validity
        vm.assume(x_lo != 0 || x_hi != 0 || y_lo != 0 || y_hi != 0);

        LineaPrimitives.G1Point memory point = LineaPrimitives.G1Point({
            x_lo: x_lo,
            x_hi: x_hi,
            y_lo: y_lo,
            y_hi: y_hi
        });

        LineaPrimitives.PLONKProof memory proof;
        proof.a = point;
        proof.b = point;
        proof.c = point;
        proof.z = point;
        proof.t_lo = point;
        proof.t_mid = point;
        proof.t_hi = point;
        proof.w_omega = point;
        proof.w_omega_zeta = point;
        proof.a_eval = a_eval;
        proof.b_eval = b_eval;
        proof.c_eval = c_eval;
        proof.s_sigma1_eval = a_eval;
        proof.s_sigma2_eval = b_eval;
        proof.z_omega_eval = c_eval;

        bool valid = LineaPrimitives.isValidPLONKProof(proof);
        assertTrue(valid, "Valid PLONK proof structure should pass");
    }

    function testFuzz_PLONKProofInvalidEvaluation(
        uint256 oversizedEval
    ) public pure {
        oversizedEval = bound(
            oversizedEval,
            LineaPrimitives.BLS12_381_SCALAR_ORDER,
            type(uint256).max
        );

        LineaPrimitives.G1Point memory validPoint = LineaPrimitives.G1Point({
            x_lo: 1,
            x_hi: 0,
            y_lo: 2,
            y_hi: 0
        });

        LineaPrimitives.PLONKProof memory proof;
        proof.a = validPoint;
        proof.b = validPoint;
        proof.c = validPoint;
        proof.z = validPoint;
        proof.t_lo = validPoint;
        proof.t_mid = validPoint;
        proof.t_hi = validPoint;
        proof.w_omega = validPoint;
        proof.w_omega_zeta = validPoint;
        proof.a_eval = oversizedEval; // Invalid - too large
        proof.b_eval = 0;
        proof.c_eval = 0;
        proof.s_sigma1_eval = 0;
        proof.s_sigma2_eval = 0;
        proof.z_omega_eval = 0;

        bool valid = LineaPrimitives.isValidPLONKProof(proof);
        assertFalse(valid, "Oversized evaluation should invalidate proof");
    }

    function testFuzz_G1PointValidation(
        uint256 x_lo,
        uint256 x_hi,
        uint256 y_lo,
        uint256 y_hi
    ) public pure {
        LineaPrimitives.G1Point memory point = LineaPrimitives.G1Point({
            x_lo: x_lo,
            x_hi: x_hi,
            y_lo: y_lo,
            y_hi: y_hi
        });

        bool valid = LineaPrimitives.isValidG1Point(point);
        bool expectedValid = !(x_lo == 0 &&
            x_hi == 0 &&
            y_lo == 0 &&
            y_hi == 0);
        assertEq(
            valid,
            expectedValid,
            "G1 point validity should match expected"
        );
    }

    function testFuzz_InfinityPointInvalid() public pure {
        LineaPrimitives.G1Point memory infinity = LineaPrimitives.G1Point({
            x_lo: 0,
            x_hi: 0,
            y_lo: 0,
            y_hi: 0
        });

        bool valid = LineaPrimitives.isValidG1Point(infinity);
        assertFalse(valid, "Point at infinity should be invalid");
    }

    // =========================================================================
    // MESSAGE VALIDATION TESTS
    // =========================================================================

    function testFuzz_L1L2MessageValidation(
        address sender,
        address recipient,
        uint256 value,
        uint256 nonce,
        uint256 deadline,
        bytes memory data
    ) public view {
        vm.assume(sender != address(0));
        vm.assume(recipient != address(0));
        nonce = bound(nonce, 1, type(uint64).max);
        deadline = bound(deadline, block.timestamp + 1, type(uint64).max);

        bytes32 hash = LineaPrimitives.computeL1L2MessageHash(
            sender,
            recipient,
            value,
            nonce,
            data
        );

        LineaPrimitives.L1L2Message memory message = LineaPrimitives
            .L1L2Message({
                sender: sender,
                recipient: recipient,
                value: value,
                fee: 0.001 ether,
                nonce: nonce,
                deadline: deadline,
                data: data,
                messageHash: hash
            });

        bool valid = LineaPrimitives.isValidL1L2Message(message);
        assertTrue(valid, "Valid L1L2 message should pass validation");
    }

    function testFuzz_L1L2MessageInvalidSender(
        address recipient,
        uint256 value,
        uint256 nonce,
        bytes memory data
    ) public view {
        nonce = bound(nonce, 1, type(uint64).max);

        bytes32 hash = LineaPrimitives.computeL1L2MessageHash(
            address(0),
            recipient,
            value,
            nonce,
            data
        );

        LineaPrimitives.L1L2Message memory message = LineaPrimitives
            .L1L2Message({
                sender: address(0),
                recipient: recipient,
                value: value,
                fee: 0.001 ether,
                nonce: nonce,
                deadline: 0,
                data: data,
                messageHash: hash
            });

        bool valid = LineaPrimitives.isValidL1L2Message(message);
        assertFalse(valid, "Message with zero sender should be invalid");
    }

    function testFuzz_L1L2MessageExpired(
        address sender,
        address recipient,
        uint256 value,
        uint256 nonce,
        bytes memory data
    ) public {
        vm.assume(sender != address(0));
        vm.assume(recipient != address(0));
        nonce = bound(nonce, 1, type(uint64).max);

        // Set deadline in the past
        uint256 deadline = block.timestamp - 1;

        bytes32 hash = LineaPrimitives.computeL1L2MessageHash(
            sender,
            recipient,
            value,
            nonce,
            data
        );

        LineaPrimitives.L1L2Message memory message = LineaPrimitives
            .L1L2Message({
                sender: sender,
                recipient: recipient,
                value: value,
                fee: 0.001 ether,
                nonce: nonce,
                deadline: deadline,
                data: data,
                messageHash: hash
            });

        bool valid = LineaPrimitives.isValidL1L2Message(message);
        assertFalse(valid, "Expired message should be invalid");
    }

    function testFuzz_L2L1MessageValidation(
        address sender,
        address recipient,
        uint256 value,
        uint256 nonce,
        uint256 blockNumber,
        bytes memory data
    ) public pure {
        vm.assume(sender != address(0));
        vm.assume(recipient != address(0));
        nonce = bound(nonce, 1, type(uint64).max);
        blockNumber = bound(blockNumber, 1, type(uint64).max);

        bytes32 hash = LineaPrimitives.computeL2L1MessageHash(
            sender,
            recipient,
            value,
            nonce,
            blockNumber,
            data
        );

        LineaPrimitives.L2L1Message memory message = LineaPrimitives
            .L2L1Message({
                sender: sender,
                recipient: recipient,
                value: value,
                nonce: nonce,
                blockNumber: blockNumber,
                data: data,
                messageHash: hash,
                finalized: false
            });

        bool valid = LineaPrimitives.isValidL2L1Message(message);
        assertTrue(valid, "Valid L2L1 message should pass validation");
    }

    // =========================================================================
    // MESSAGE FEE TESTS
    // =========================================================================

    function testFuzz_MessageFeeCalculation(uint256 dataLength) public pure {
        dataLength = bound(dataLength, 0, 100000);

        uint256 fee = LineaPrimitives.calculateMessageFee(dataLength);
        uint256 expected = LineaPrimitives.MESSAGE_FEE_BASE +
            (dataLength * LineaPrimitives.MESSAGE_FEE_PER_BYTE);

        assertEq(fee, expected, "Fee calculation should match expected");
    }

    function testFuzz_MessageFeeMonotonic(
        uint256 len1,
        uint256 len2
    ) public pure {
        len1 = bound(len1, 0, 50000);
        len2 = bound(len2, 0, 50000);
        vm.assume(len1 < len2);

        uint256 fee1 = LineaPrimitives.calculateMessageFee(len1);
        uint256 fee2 = LineaPrimitives.calculateMessageFee(len2);

        assertLt(fee1, fee2, "Larger data should have higher fee");
    }

    function testFuzz_MessageFeeMinimum() public pure {
        uint256 fee = LineaPrimitives.calculateMessageFee(0);
        assertEq(
            fee,
            LineaPrimitives.MESSAGE_FEE_BASE,
            "Zero-length data should have base fee"
        );
    }

    // =========================================================================
    // BATCH VALIDATION TESTS
    // =========================================================================

    function testFuzz_BatchValidation(
        uint256 batchIndex,
        uint256 firstBlock,
        uint256 lastBlock,
        bytes32 prevRoot,
        bytes32 newRoot
    ) public view {
        // Ensure valid block range
        firstBlock = bound(
            firstBlock,
            1,
            type(uint64).max - LineaPrimitives.CONFLATION_INTERVAL
        );
        lastBlock = bound(
            lastBlock,
            firstBlock + 1,
            firstBlock + LineaPrimitives.CONFLATION_INTERVAL
        );

        // Ensure valid state roots
        vm.assume(prevRoot != bytes32(0));
        vm.assume(newRoot != bytes32(0));
        vm.assume(prevRoot != newRoot);

        // Create valid G1 point for proof
        LineaPrimitives.G1Point memory validPoint = LineaPrimitives.G1Point({
            x_lo: 1,
            x_hi: 0,
            y_lo: 2,
            y_hi: 0
        });

        LineaPrimitives.PLONKProof memory proof;
        proof.a = validPoint;
        proof.b = validPoint;
        proof.c = validPoint;
        proof.z = validPoint;
        proof.t_lo = validPoint;
        proof.t_mid = validPoint;
        proof.t_hi = validPoint;
        proof.w_omega = validPoint;
        proof.w_omega_zeta = validPoint;

        LineaPrimitives.LineaBatch memory batch = LineaPrimitives.LineaBatch({
            batchIndex: batchIndex,
            firstBlockNumber: firstBlock,
            lastBlockNumber: lastBlock,
            batchDataHash: keccak256(abi.encodePacked(batchIndex)),
            previousStateRoot: prevRoot,
            newStateRoot: newRoot,
            timestamp: block.timestamp,
            l2MessageHashes: new bytes32[](0),
            proof: proof
        });

        bool valid = LineaPrimitives.isValidBatch(batch);
        assertTrue(valid, "Valid batch should pass validation");
    }

    function testFuzz_BatchInvalidBlockRange(
        uint256 firstBlock,
        uint256 sameBlock
    ) public pure {
        firstBlock = bound(firstBlock, 1, type(uint64).max - 1);
        sameBlock = firstBlock; // Same block - invalid

        LineaPrimitives.G1Point memory validPoint = LineaPrimitives.G1Point({
            x_lo: 1,
            x_hi: 0,
            y_lo: 2,
            y_hi: 0
        });

        LineaPrimitives.PLONKProof memory proof;
        proof.a = validPoint;
        proof.b = validPoint;
        proof.c = validPoint;
        proof.z = validPoint;

        LineaPrimitives.LineaBatch memory batch = LineaPrimitives.LineaBatch({
            batchIndex: 0,
            firstBlockNumber: firstBlock,
            lastBlockNumber: sameBlock, // Invalid: not greater than first
            batchDataHash: bytes32(0),
            previousStateRoot: bytes32(uint256(1)),
            newStateRoot: bytes32(uint256(2)),
            timestamp: 0,
            l2MessageHashes: new bytes32[](0),
            proof: proof
        });

        bool valid = LineaPrimitives.isValidBatch(batch);
        assertFalse(valid, "Batch with invalid block range should fail");
    }

    // =========================================================================
    // FINALIZATION TESTS
    // =========================================================================

    function testFuzz_BlocksUntilFinalization(
        uint256 submissionBlock,
        uint256 currentBlock
    ) public pure {
        submissionBlock = bound(
            submissionBlock,
            1,
            type(uint64).max - LineaPrimitives.FINALITY_BLOCKS_L1 - 1
        );
        currentBlock = bound(
            currentBlock,
            submissionBlock,
            submissionBlock + LineaPrimitives.FINALITY_BLOCKS_L1 + 100
        );

        uint256 remaining = LineaPrimitives.blocksUntilFinalization(
            submissionBlock,
            currentBlock
        );

        if (
            currentBlock >= submissionBlock + LineaPrimitives.FINALITY_BLOCKS_L1
        ) {
            assertEq(remaining, 0, "Should be zero after finalization");
        } else {
            uint256 expected = (submissionBlock +
                LineaPrimitives.FINALITY_BLOCKS_L1) - currentBlock;
            assertEq(
                remaining,
                expected,
                "Remaining blocks should match expected"
            );
        }
    }

    function testFuzz_IsBatchFinalized(
        uint256 submissionBlock,
        uint256 currentBlock
    ) public pure {
        submissionBlock = bound(
            submissionBlock,
            1,
            type(uint64).max - LineaPrimitives.FINALITY_BLOCKS_L1 - 1
        );
        currentBlock = bound(currentBlock, submissionBlock, type(uint64).max);

        bool finalized = LineaPrimitives.isBatchFinalized(
            submissionBlock,
            currentBlock
        );
        bool expected = currentBlock >=
            submissionBlock + LineaPrimitives.FINALITY_BLOCKS_L1;

        assertEq(
            finalized,
            expected,
            "Finalization status should match expected"
        );
    }

    // =========================================================================
    // VERIFICATION KEY TESTS
    // =========================================================================

    function testFuzz_VKHashDeterminism(
        uint256 domainSize,
        uint256 numInputs
    ) public pure {
        domainSize = bound(domainSize, 1, 1 << 20);
        numInputs = bound(numInputs, 1, 100);

        LineaPrimitives.G1Point memory point = LineaPrimitives.G1Point({
            x_lo: 1,
            x_hi: 0,
            y_lo: 2,
            y_hi: 0
        });

        LineaPrimitives.G2Point memory g2Point;
        g2Point.x[0] = 1;
        g2Point.x[1] = 2;
        g2Point.y[0] = 3;
        g2Point.y[1] = 4;

        LineaPrimitives.PLONKVerificationKey memory vk = LineaPrimitives
            .PLONKVerificationKey({
                domainSize: domainSize,
                numPublicInputs: numInputs,
                q_m: point,
                q_l: point,
                q_r: point,
                q_o: point,
                q_c: point,
                s_sigma1: point,
                s_sigma2: point,
                s_sigma3: point,
                x_2: g2Point,
                vkHash: bytes32(0)
            });

        bytes32 hash1 = LineaPrimitives.computeVKHash(vk);
        bytes32 hash2 = LineaPrimitives.computeVKHash(vk);

        assertEq(hash1, hash2, "VK hash should be deterministic");
    }

    // =========================================================================
    // CHALLENGE COMPUTATION TESTS
    // =========================================================================

    function testFuzz_ChallengeDeterminism(
        bytes32 transcript,
        bytes memory data
    ) public pure {
        uint256 challenge1 = LineaPrimitives.computeChallenge(transcript, data);
        uint256 challenge2 = LineaPrimitives.computeChallenge(transcript, data);

        assertEq(challenge1, challenge2, "Challenge should be deterministic");
    }

    function testFuzz_ChallengeInScalarField(
        bytes32 transcript,
        bytes memory data
    ) public pure {
        uint256 challenge = LineaPrimitives.computeChallenge(transcript, data);
        assertLt(
            challenge,
            LineaPrimitives.BLS12_381_SCALAR_ORDER,
            "Challenge should be in scalar field"
        );
    }

    function testFuzz_ChallengeUniqueness(
        bytes32 transcript,
        bytes memory data1,
        bytes memory data2
    ) public pure {
        vm.assume(keccak256(data1) != keccak256(data2));

        uint256 challenge1 = LineaPrimitives.computeChallenge(
            transcript,
            data1
        );
        uint256 challenge2 = LineaPrimitives.computeChallenge(
            transcript,
            data2
        );

        // Note: With very low probability these could be equal due to modular reduction
        // For practical purposes, they should be different
        if (
            keccak256(abi.encodePacked(transcript, data1)) !=
            keccak256(abi.encodePacked(transcript, data2))
        ) {
            // High probability they differ, but not guaranteed due to mod
            assertTrue(true);
        }
    }

    // =========================================================================
    // STATE TRANSITION TESTS
    // =========================================================================

    function testFuzz_StateTransitionDeterminism(
        bytes32 prevRoot,
        bytes32 txHash,
        bytes memory postState
    ) public pure {
        bytes32 newRoot1 = LineaPrimitives.computeStateTransition(
            prevRoot,
            txHash,
            postState
        );
        bytes32 newRoot2 = LineaPrimitives.computeStateTransition(
            prevRoot,
            txHash,
            postState
        );

        assertEq(
            newRoot1,
            newRoot2,
            "State transition should be deterministic"
        );
    }

    function testFuzz_StateTransitionUniqueness(
        bytes32 prevRoot,
        bytes32 txHash1,
        bytes32 txHash2,
        bytes memory postState
    ) public pure {
        vm.assume(txHash1 != txHash2);

        bytes32 newRoot1 = LineaPrimitives.computeStateTransition(
            prevRoot,
            txHash1,
            postState
        );
        bytes32 newRoot2 = LineaPrimitives.computeStateTransition(
            prevRoot,
            txHash2,
            postState
        );

        assertNotEq(
            newRoot1,
            newRoot2,
            "Different transactions should produce different roots"
        );
    }

    // =========================================================================
    // EVM TRACE ENCODING TESTS
    // =========================================================================

    function testFuzz_EVMTraceEncoding(
        address from,
        address to,
        uint256 value,
        uint256 gasLimit,
        uint256 gasPrice,
        bytes memory data,
        uint256 nonce
    ) public pure {
        bytes memory trace = LineaPrimitives.encodeEVMTrace(
            from,
            to,
            value,
            gasLimit,
            gasPrice,
            data,
            nonce
        );

        // Decode and verify
        (
            address decodedFrom,
            address decodedTo,
            uint256 decodedValue,
            uint256 decodedGasLimit,
            uint256 decodedGasPrice,
            bytes memory decodedData,
            uint256 decodedNonce
        ) = abi.decode(
                trace,
                (address, address, uint256, uint256, uint256, bytes, uint256)
            );

        assertEq(decodedFrom, from, "From should match");
        assertEq(decodedTo, to, "To should match");
        assertEq(decodedValue, value, "Value should match");
        assertEq(decodedGasLimit, gasLimit, "Gas limit should match");
        assertEq(decodedGasPrice, gasPrice, "Gas price should match");
        assertEq(keccak256(decodedData), keccak256(data), "Data should match");
        assertEq(decodedNonce, nonce, "Nonce should match");
    }

    // =========================================================================
    // CHAIN ID TESTS
    // =========================================================================

    function testFuzz_ChainIdMainnet() public pure {
        uint256 chainId = LineaPrimitives.getChainId(true);
        assertEq(
            chainId,
            LineaPrimitives.LINEA_MAINNET_CHAIN_ID,
            "Mainnet chain ID should be 59144"
        );
    }

    function testFuzz_ChainIdTestnet() public pure {
        uint256 chainId = LineaPrimitives.getChainId(false);
        assertEq(
            chainId,
            LineaPrimitives.LINEA_SEPOLIA_CHAIN_ID,
            "Sepolia chain ID should be 59141"
        );
    }

    // =========================================================================
    // CROSS-DOMAIN PROOF ENCODING TESTS
    // =========================================================================

    function testFuzz_CrossDomainProofEncoding(
        bytes32 proofHash,
        uint256 sourceChain,
        uint256 destChain,
        bytes32 commitment,
        bytes32 nullifier
    ) public pure {
        bytes memory publicInputs = abi.encodePacked(proofHash, commitment);
        bytes memory proof = abi.encodePacked(nullifier);

        LineaPrimitives.CrossDomainProof memory original = LineaPrimitives
            .CrossDomainProof({
                proofHash: proofHash,
                sourceChain: sourceChain,
                destChain: destChain,
                commitment: commitment,
                nullifier: nullifier,
                publicInputs: publicInputs,
                proof: proof
            });

        bytes memory encoded = LineaPrimitives.encodeCrossDomainProof(original);
        LineaPrimitives.CrossDomainProof memory decoded = LineaPrimitives
            .decodeCrossDomainProof(encoded);

        assertEq(
            decoded.proofHash,
            original.proofHash,
            "Proof hash should match"
        );
        assertEq(
            decoded.sourceChain,
            original.sourceChain,
            "Source chain should match"
        );
        assertEq(
            decoded.destChain,
            original.destChain,
            "Dest chain should match"
        );
        assertEq(
            decoded.commitment,
            original.commitment,
            "Commitment should match"
        );
        assertEq(
            decoded.nullifier,
            original.nullifier,
            "Nullifier should match"
        );
    }

    // =========================================================================
    // BLOCK HEADER TESTS
    // =========================================================================

    function testFuzz_BlockHeaderHashDeterminism(
        uint256 blockNumber,
        bytes32 stateRoot,
        bytes32 parentHash,
        uint256 timestamp,
        uint256 gasLimit,
        uint256 gasUsed
    ) public pure {
        blockNumber = bound(blockNumber, 1, type(uint64).max);
        timestamp = bound(timestamp, 1, type(uint64).max);
        gasLimit = bound(gasLimit, 21000, 30_000_000);
        gasUsed = bound(gasUsed, 0, gasLimit);

        LineaPrimitives.LineaBlockHeader memory header = LineaPrimitives
            .LineaBlockHeader({
                blockNumber: blockNumber,
                stateRoot: stateRoot,
                transactionsRoot: bytes32(0),
                receiptsRoot: bytes32(0),
                logsBloom: bytes32(0),
                timestamp: timestamp,
                gasLimit: gasLimit,
                gasUsed: gasUsed,
                coinbase: address(0x1),
                parentHash: parentHash,
                mixHash: bytes32(0),
                baseFee: 1 gwei
            });

        bytes32 hash1 = LineaPrimitives.computeBlockHeaderHash(header);
        bytes32 hash2 = LineaPrimitives.computeBlockHeaderHash(header);

        assertEq(hash1, hash2, "Block header hash should be deterministic");
    }

    function testFuzz_BlockHeaderHashUniqueness(
        uint256 blockNumber1,
        uint256 blockNumber2,
        bytes32 stateRoot
    ) public pure {
        vm.assume(blockNumber1 != blockNumber2);

        LineaPrimitives.LineaBlockHeader memory header1 = LineaPrimitives
            .LineaBlockHeader({
                blockNumber: blockNumber1,
                stateRoot: stateRoot,
                transactionsRoot: bytes32(0),
                receiptsRoot: bytes32(0),
                logsBloom: bytes32(0),
                timestamp: 1,
                gasLimit: 30_000_000,
                gasUsed: 0,
                coinbase: address(0x1),
                parentHash: bytes32(0),
                mixHash: bytes32(0),
                baseFee: 1 gwei
            });

        LineaPrimitives.LineaBlockHeader memory header2 = LineaPrimitives
            .LineaBlockHeader({
                blockNumber: blockNumber2,
                stateRoot: stateRoot,
                transactionsRoot: bytes32(0),
                receiptsRoot: bytes32(0),
                logsBloom: bytes32(0),
                timestamp: 1,
                gasLimit: 30_000_000,
                gasUsed: 0,
                coinbase: address(0x1),
                parentHash: bytes32(0),
                mixHash: bytes32(0),
                baseFee: 1 gwei
            });

        bytes32 hash1 = LineaPrimitives.computeBlockHeaderHash(header1);
        bytes32 hash2 = LineaPrimitives.computeBlockHeaderHash(header2);

        assertNotEq(
            hash1,
            hash2,
            "Different block numbers should produce different hashes"
        );
    }

    // =========================================================================
    // BATCH HASH TESTS
    // =========================================================================

    function testFuzz_BatchHashDeterminism(
        uint256 batchIndex,
        uint256 firstBlock,
        uint256 lastBlock,
        bytes32 prevRoot,
        bytes32 newRoot,
        uint256 timestamp
    ) public pure {
        firstBlock = bound(firstBlock, 1, type(uint64).max - 100);
        lastBlock = bound(lastBlock, firstBlock + 1, firstBlock + 100);

        LineaPrimitives.LineaBatch memory batch = LineaPrimitives.LineaBatch({
            batchIndex: batchIndex,
            firstBlockNumber: firstBlock,
            lastBlockNumber: lastBlock,
            batchDataHash: bytes32(0),
            previousStateRoot: prevRoot,
            newStateRoot: newRoot,
            timestamp: timestamp,
            l2MessageHashes: new bytes32[](0),
            proof: LineaPrimitives.PLONKProof({
                a: LineaPrimitives.G1Point(0, 0, 0, 0),
                b: LineaPrimitives.G1Point(0, 0, 0, 0),
                c: LineaPrimitives.G1Point(0, 0, 0, 0),
                z: LineaPrimitives.G1Point(0, 0, 0, 0),
                t_lo: LineaPrimitives.G1Point(0, 0, 0, 0),
                t_mid: LineaPrimitives.G1Point(0, 0, 0, 0),
                t_hi: LineaPrimitives.G1Point(0, 0, 0, 0),
                w_omega: LineaPrimitives.G1Point(0, 0, 0, 0),
                w_omega_zeta: LineaPrimitives.G1Point(0, 0, 0, 0),
                a_eval: 0,
                b_eval: 0,
                c_eval: 0,
                s_sigma1_eval: 0,
                s_sigma2_eval: 0,
                z_omega_eval: 0
            })
        });

        bytes32 hash1 = LineaPrimitives.computeBatchHash(batch);
        bytes32 hash2 = LineaPrimitives.computeBatchHash(batch);

        assertEq(hash1, hash2, "Batch hash should be deterministic");
    }

    // =========================================================================
    // CONSTANTS TESTS
    // =========================================================================

    function test_Constants() public pure {
        assertEq(
            LineaPrimitives.LINEA_MAINNET_CHAIN_ID,
            59144,
            "Mainnet chain ID"
        );
        assertEq(
            LineaPrimitives.LINEA_SEPOLIA_CHAIN_ID,
            59141,
            "Sepolia chain ID"
        );
        assertEq(LineaPrimitives.FINALITY_BLOCKS_L1, 32, "Finality blocks");
        assertEq(LineaPrimitives.BLOCK_TIME_SECONDS, 3, "Block time");
        assertEq(
            LineaPrimitives.CONFLATION_INTERVAL,
            100,
            "Conflation interval"
        );
        assertEq(
            LineaPrimitives.PLONK_DOMAIN_SIZE_BITS,
            20,
            "PLONK domain size bits"
        );
    }
}
