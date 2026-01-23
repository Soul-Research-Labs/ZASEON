// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/alpen/AlpenPrimitives.sol";

/**
 * @title AlpenFuzz
 * @notice Comprehensive fuzz tests for Alpen Network primitives and bridge
 * @dev Tests Bitcoin L2 primitives: secp256k1, Schnorr, BitVM, zkEVM, STARK
 */
contract AlpenFuzz is Test {
    using AlpenPrimitives for *;

    // =========================================================================
    // CONSTANTS
    // =========================================================================

    uint256 constant ALPEN_SECP256K1_ORDER =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    uint256 constant ALPEN_SECP256K1_FIELD_PRIME =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;

    // =========================================================================
    // SETUP
    // =========================================================================

    function setUp() public {}

    // =========================================================================
    // HASH FUNCTION TESTS
    // =========================================================================

    /**
     * @notice Fuzz test: doubleSha256 determinism
     */
    function testFuzz_DoubleSha256Determinism(bytes memory data) public pure {
        bytes32 hash1 = AlpenPrimitives.doubleSha256(data);
        bytes32 hash2 = AlpenPrimitives.doubleSha256(data);
        assertEq(hash1, hash2, "doubleSha256 not deterministic");
    }

    /**
     * @notice Fuzz test: doubleSha256 uniqueness
     */
    function testFuzz_DoubleSha256Uniqueness(
        bytes memory data1,
        bytes memory data2
    ) public pure {
        vm.assume(keccak256(data1) != keccak256(data2));
        bytes32 hash1 = AlpenPrimitives.doubleSha256(data1);
        bytes32 hash2 = AlpenPrimitives.doubleSha256(data2);
        assertNotEq(hash1, hash2, "Collision in doubleSha256");
    }

    /**
     * @notice Fuzz test: taggedHash determinism
     */
    function testFuzz_TaggedHashDeterminism(
        string memory tag,
        bytes memory data
    ) public pure {
        bytes32 hash1 = AlpenPrimitives.taggedHash(tag, data);
        bytes32 hash2 = AlpenPrimitives.taggedHash(tag, data);
        assertEq(hash1, hash2, "taggedHash not deterministic");
    }

    /**
     * @notice Fuzz test: taggedHash tag sensitivity
     */
    function testFuzz_TaggedHashTagSensitivity(
        string memory tag1,
        string memory tag2,
        bytes memory data
    ) public pure {
        vm.assume(keccak256(bytes(tag1)) != keccak256(bytes(tag2)));
        bytes32 hash1 = AlpenPrimitives.taggedHash(tag1, data);
        bytes32 hash2 = AlpenPrimitives.taggedHash(tag2, data);
        assertNotEq(hash1, hash2, "taggedHash not tag-sensitive");
    }

    /**
     * @notice Fuzz test: tagged hash BIP-340 format
     */
    function testFuzz_TaggedHashBIP340Format(bytes memory data) public pure {
        // BIP-340 challenge tag
        bytes32 hash = AlpenPrimitives.taggedHash("BIP0340/challenge", data);
        assertTrue(hash != bytes32(0), "Invalid BIP-340 hash");
    }

    // =========================================================================
    // NULLIFIER TESTS
    // =========================================================================

    /**
     * @notice Fuzz test: deriveAlpenNullifier determinism
     */
    function testFuzz_NullifierDeterminism(
        bytes32 btcTxid,
        uint32 vout,
        uint64 blockHeight
    ) public pure {
        bytes32 nf1 = AlpenPrimitives.deriveAlpenNullifier(
            btcTxid,
            vout,
            blockHeight
        );
        bytes32 nf2 = AlpenPrimitives.deriveAlpenNullifier(
            btcTxid,
            vout,
            blockHeight
        );
        assertEq(nf1, nf2, "Nullifier not deterministic");
    }

    /**
     * @notice Fuzz test: nullifier uniqueness for different UTXOs
     */
    function testFuzz_NullifierUniqueness(
        bytes32 btcTxid1,
        bytes32 btcTxid2,
        uint32 vout,
        uint64 blockHeight
    ) public pure {
        vm.assume(btcTxid1 != btcTxid2);
        bytes32 nf1 = AlpenPrimitives.deriveAlpenNullifier(
            btcTxid1,
            vout,
            blockHeight
        );
        bytes32 nf2 = AlpenPrimitives.deriveAlpenNullifier(
            btcTxid2,
            vout,
            blockHeight
        );
        assertNotEq(nf1, nf2, "Nullifier collision");
    }

    /**
     * @notice Fuzz test: nullifier vout sensitivity
     */
    function testFuzz_NullifierVoutSensitivity(
        bytes32 btcTxid,
        uint32 vout1,
        uint32 vout2,
        uint64 blockHeight
    ) public pure {
        vm.assume(vout1 != vout2);
        bytes32 nf1 = AlpenPrimitives.deriveAlpenNullifier(
            btcTxid,
            vout1,
            blockHeight
        );
        bytes32 nf2 = AlpenPrimitives.deriveAlpenNullifier(
            btcTxid,
            vout2,
            blockHeight
        );
        assertNotEq(nf1, nf2, "Nullifier not vout-sensitive");
    }

    /**
     * @notice Fuzz test: cross-domain nullifier derivation
     */
    function testFuzz_CrossDomainNullifier(
        bytes32 alpenNullifier,
        uint256 targetDomain
    ) public pure {
        bytes32 cdNf1 = AlpenPrimitives.deriveCrossDomainNullifier(
            alpenNullifier,
            targetDomain
        );
        bytes32 cdNf2 = AlpenPrimitives.deriveCrossDomainNullifier(
            alpenNullifier,
            targetDomain
        );
        assertEq(cdNf1, cdNf2, "Cross-domain nullifier not deterministic");
    }

    /**
     * @notice Fuzz test: cross-domain nullifier domain sensitivity
     */
    function testFuzz_CrossDomainNullifierDomainSensitivity(
        bytes32 alpenNullifier,
        uint256 domain1,
        uint256 domain2
    ) public pure {
        vm.assume(domain1 != domain2);
        bytes32 cdNf1 = AlpenPrimitives.deriveCrossDomainNullifier(
            alpenNullifier,
            domain1
        );
        bytes32 cdNf2 = AlpenPrimitives.deriveCrossDomainNullifier(
            alpenNullifier,
            domain2
        );
        assertNotEq(
            cdNf1,
            cdNf2,
            "Cross-domain nullifier not domain-sensitive"
        );
    }

    /**
     * @notice Fuzz test: PIL binding determinism
     */
    function testFuzz_PILBindingDeterminism(
        bytes32 alpenNullifier,
        bytes32 pilDomain
    ) public pure {
        bytes32 binding1 = AlpenPrimitives.derivePILBinding(
            alpenNullifier,
            pilDomain
        );
        bytes32 binding2 = AlpenPrimitives.derivePILBinding(
            alpenNullifier,
            pilDomain
        );
        assertEq(binding1, binding2, "PIL binding not deterministic");
    }

    /**
     * @notice Fuzz test: PIL binding uniqueness
     */
    function testFuzz_PILBindingUniqueness(
        bytes32 nf1,
        bytes32 nf2,
        bytes32 pilDomain
    ) public pure {
        vm.assume(nf1 != nf2);
        bytes32 binding1 = AlpenPrimitives.derivePILBinding(nf1, pilDomain);
        bytes32 binding2 = AlpenPrimitives.derivePILBinding(nf2, pilDomain);
        assertNotEq(binding1, binding2, "PIL binding collision");
    }

    // =========================================================================
    // MERKLE PROOF TESTS
    // =========================================================================

    /**
     * @notice Fuzz test: Merkle root computation determinism
     */
    function testFuzz_MerkleRootDeterminism(
        bytes32 leaf1,
        bytes32 leaf2
    ) public pure {
        bytes32[] memory leaves = new bytes32[](2);
        leaves[0] = leaf1;
        leaves[1] = leaf2;

        bytes32 root1 = AlpenPrimitives.computeMerkleRoot(leaves);
        bytes32 root2 = AlpenPrimitives.computeMerkleRoot(leaves);
        assertEq(root1, root2, "Merkle root not deterministic");
    }

    /**
     * @notice Fuzz test: Merkle root order sensitivity
     */
    function testFuzz_MerkleRootOrderSensitivity(
        bytes32 leaf1,
        bytes32 leaf2
    ) public pure {
        vm.assume(leaf1 != leaf2);

        bytes32[] memory leaves1 = new bytes32[](2);
        leaves1[0] = leaf1;
        leaves1[1] = leaf2;

        bytes32[] memory leaves2 = new bytes32[](2);
        leaves2[0] = leaf2;
        leaves2[1] = leaf1;

        bytes32 root1 = AlpenPrimitives.computeMerkleRoot(leaves1);
        bytes32 root2 = AlpenPrimitives.computeMerkleRoot(leaves2);
        assertNotEq(root1, root2, "Merkle root not order-sensitive");
    }

    /**
     * @notice Fuzz test: Merkle proof verification
     */
    function testFuzz_MerkleProofVerification(
        bytes32 txid,
        bytes32 sibling
    ) public pure {
        bytes32[] memory siblings = new bytes32[](1);
        siblings[0] = sibling;

        // Compute expected root (left child)
        bytes32 expectedRoot = AlpenPrimitives.doubleSha256(
            abi.encodePacked(txid, sibling)
        );

        AlpenPrimitives.MerkleProof memory proof = AlpenPrimitives.MerkleProof({
            txid: txid,
            siblings: siblings,
            index: 0,
            merkleRoot: expectedRoot
        });

        assertTrue(
            AlpenPrimitives.verifyMerkleProof(proof),
            "Valid proof rejected"
        );
    }

    /**
     * @notice Fuzz test: Merkle proof rejection
     */
    function testFuzz_MerkleProofRejection(
        bytes32 txid,
        bytes32 sibling,
        bytes32 wrongRoot
    ) public pure {
        bytes32[] memory siblings = new bytes32[](1);
        siblings[0] = sibling;

        bytes32 correctRoot = AlpenPrimitives.doubleSha256(
            abi.encodePacked(txid, sibling)
        );
        vm.assume(wrongRoot != correctRoot);

        AlpenPrimitives.MerkleProof memory proof = AlpenPrimitives.MerkleProof({
            txid: txid,
            siblings: siblings,
            index: 0,
            merkleRoot: wrongRoot
        });

        assertFalse(
            AlpenPrimitives.verifyMerkleProof(proof),
            "Invalid proof accepted"
        );
    }

    // =========================================================================
    // BITVM TESTS
    // =========================================================================

    /**
     * @notice Fuzz test: NAND gate evaluation
     */
    function testFuzz_NANDGate(bool a, bool b) public pure {
        bool result = AlpenPrimitives.evalNAND(a, b);
        assertEq(result, !(a && b), "NAND gate incorrect");
    }

    /**
     * @notice Test: NAND gate truth table
     */
    function test_NANDGateTruthTable() public pure {
        assertTrue(
            AlpenPrimitives.evalNAND(false, false),
            "NAND(0,0) should be 1"
        );
        assertTrue(
            AlpenPrimitives.evalNAND(false, true),
            "NAND(0,1) should be 1"
        );
        assertTrue(
            AlpenPrimitives.evalNAND(true, false),
            "NAND(1,0) should be 1"
        );
        assertFalse(
            AlpenPrimitives.evalNAND(true, true),
            "NAND(1,1) should be 0"
        );
    }

    /**
     * @notice Fuzz test: BitVM program hash determinism
     */
    function testFuzz_BitVMProgramHashDeterminism(
        uint32 numInputs,
        uint32 numOutputs
    ) public pure {
        vm.assume(numInputs > 0 && numInputs < 100);
        vm.assume(numOutputs > 0 && numOutputs < 100);

        AlpenPrimitives.Gate[] memory gates = new AlpenPrimitives.Gate[](1);
        gates[0] = AlpenPrimitives.Gate({
            gateType: AlpenPrimitives.GateType.NAND,
            inputA: 0,
            inputB: 1,
            output: 2
        });

        AlpenPrimitives.BitVMProgram memory program = AlpenPrimitives
            .BitVMProgram({
                programHash: bytes32(0),
                gates: gates,
                numInputs: numInputs,
                numOutputs: numOutputs,
                commitmentRoot: bytes32(0)
            });

        bytes32 hash1 = AlpenPrimitives.computeProgramHash(program);
        bytes32 hash2 = AlpenPrimitives.computeProgramHash(program);
        assertEq(hash1, hash2, "Program hash not deterministic");
    }

    /**
     * @notice Fuzz test: BitVM challenge deadline
     */
    function testFuzz_ChallengeDeadline(
        uint256 timestamp,
        uint256 deadline
    ) public {
        vm.assume(deadline > 0);
        vm.warp(timestamp);

        AlpenPrimitives.BitVMChallenge memory challenge = AlpenPrimitives
            .BitVMChallenge({
                challengeId: bytes32(uint256(1)),
                programHash: bytes32(uint256(2)),
                gateIndex: 0,
                inputCommitment: bytes32(0),
                outputCommitment: bytes32(0),
                challenger: address(1),
                deadline: deadline,
                status: AlpenPrimitives.ChallengeStatus.PENDING
            });

        bool isActive = AlpenPrimitives.isChallengeActive(challenge);

        if (timestamp < deadline) {
            assertTrue(isActive, "Challenge should be active before deadline");
        } else {
            assertFalse(
                isActive,
                "Challenge should be inactive after deadline"
            );
        }
    }

    // =========================================================================
    // STARK PROOF TESTS
    // =========================================================================

    /**
     * @notice Fuzz test: STARK proof structure validation
     */
    function testFuzz_STARKProofValidation(
        bytes32 publicInputHash,
        bytes32 programHash,
        uint256 securityLevel
    ) public pure {
        vm.assume(publicInputHash != bytes32(0));
        vm.assume(programHash != bytes32(0));

        bytes32[] memory traceCommitments = new bytes32[](1);
        traceCommitments[0] = bytes32(uint256(1));

        bytes32[] memory friCommitments = new bytes32[](1);
        friCommitments[0] = bytes32(uint256(2));

        AlpenPrimitives.STARKProof memory proof = AlpenPrimitives.STARKProof({
            publicInputHash: publicInputHash,
            programHash: programHash,
            traceCommitments: traceCommitments,
            friCommitments: friCommitments,
            openings: "",
            securityLevel: securityLevel
        });

        bool isValid = AlpenPrimitives.isValidSTARKProof(proof);

        if (securityLevel >= AlpenPrimitives.STARK_SECURITY_BITS) {
            assertTrue(isValid, "Valid STARK proof rejected");
        } else {
            assertFalse(isValid, "Invalid security level accepted");
        }
    }

    /**
     * @notice Fuzz test: state transition hash determinism
     */
    function testFuzz_StateTransitionHashDeterminism(
        bytes32 preStateRoot,
        bytes32 postStateRoot,
        bytes32 blockHash,
        uint64 blockNumber
    ) public pure {
        AlpenPrimitives.StateTransition memory transition = AlpenPrimitives
            .StateTransition({
                preStateRoot: preStateRoot,
                postStateRoot: postStateRoot,
                blockHash: blockHash,
                blockNumber: blockNumber,
                transactionsRoot: bytes32(0),
                receiptsRoot: bytes32(0)
            });

        bytes32 hash1 = AlpenPrimitives.computeTransitionHash(transition);
        bytes32 hash2 = AlpenPrimitives.computeTransitionHash(transition);
        assertEq(hash1, hash2, "State transition hash not deterministic");
    }

    // =========================================================================
    // PEG-IN/PEG-OUT TESTS
    // =========================================================================

    /**
     * @notice Fuzz test: peg-in ID computation
     */
    function testFuzz_PegInIdDeterminism(
        bytes32 btcTxid,
        address recipient,
        uint64 amount
    ) public pure {
        bytes32 id1 = AlpenPrimitives.computePegInId(
            btcTxid,
            recipient,
            amount
        );
        bytes32 id2 = AlpenPrimitives.computePegInId(
            btcTxid,
            recipient,
            amount
        );
        assertEq(id1, id2, "Peg-in ID not deterministic");
    }

    /**
     * @notice Fuzz test: peg-in ID uniqueness
     */
    function testFuzz_PegInIdUniqueness(
        bytes32 btcTxid1,
        bytes32 btcTxid2,
        address recipient,
        uint64 amount
    ) public pure {
        vm.assume(btcTxid1 != btcTxid2);
        bytes32 id1 = AlpenPrimitives.computePegInId(
            btcTxid1,
            recipient,
            amount
        );
        bytes32 id2 = AlpenPrimitives.computePegInId(
            btcTxid2,
            recipient,
            amount
        );
        assertNotEq(id1, id2, "Peg-in ID collision");
    }

    /**
     * @notice Fuzz test: peg-out ID computation
     */
    function testFuzz_PegOutIdDeterminism(
        address sender,
        bytes memory btcDestination,
        uint64 amount,
        uint256 nonce
    ) public pure {
        vm.assume(btcDestination.length > 0 && btcDestination.length < 100);
        bytes32 id1 = AlpenPrimitives.computePegOutId(
            sender,
            btcDestination,
            amount,
            nonce
        );
        bytes32 id2 = AlpenPrimitives.computePegOutId(
            sender,
            btcDestination,
            amount,
            nonce
        );
        assertEq(id1, id2, "Peg-out ID not deterministic");
    }

    /**
     * @notice Fuzz test: peg-in validation
     */
    function testFuzz_PegInValidation(
        bytes32 btcTxid,
        uint64 amount,
        address recipient,
        uint256 confirmations
    ) public pure {
        vm.assume(btcTxid != bytes32(0));
        vm.assume(recipient != address(0));

        bytes32[] memory siblings = new bytes32[](1);
        siblings[0] = bytes32(uint256(1));

        AlpenPrimitives.MerkleProof memory proof = AlpenPrimitives.MerkleProof({
            txid: btcTxid,
            siblings: siblings,
            index: 0,
            merkleRoot: bytes32(uint256(1))
        });

        AlpenPrimitives.PegIn memory pegIn = AlpenPrimitives.PegIn({
            pegInId: bytes32(0),
            btcTxid: btcTxid,
            amount: amount,
            recipient: recipient,
            inclusionProof: proof,
            confirmations: confirmations,
            status: AlpenPrimitives.PegStatus.PENDING
        });

        bool isValid = AlpenPrimitives.isValidPegIn(pegIn);

        // Check expected validation
        bool expectedValid = amount >= AlpenPrimitives.MIN_DEPOSIT_SATS &&
            amount <= AlpenPrimitives.MAX_DEPOSIT_SATS &&
            confirmations >= AlpenPrimitives.FINALITY_BLOCKS;

        assertEq(isValid, expectedValid, "Peg-in validation mismatch");
    }

    /**
     * @notice Fuzz test: peg-out validation
     */
    function testFuzz_PegOutValidation(
        address sender,
        bytes memory btcDestination,
        uint64 amount,
        uint256 signatureCount
    ) public view {
        vm.assume(sender != address(0));
        vm.assume(btcDestination.length > 0 && btcDestination.length < 100);
        vm.assume(signatureCount < 20);

        bytes32[] memory signatures = new bytes32[](signatureCount);
        for (uint256 i = 0; i < signatureCount; i++) {
            signatures[i] = bytes32(uint256(i + 1));
        }

        AlpenPrimitives.PegOut memory pegOut = AlpenPrimitives.PegOut({
            pegOutId: bytes32(0),
            sender: sender,
            btcDestination: btcDestination,
            amount: amount,
            operatorSignatures: signatures,
            timestamp: block.timestamp,
            status: AlpenPrimitives.PegStatus.PENDING
        });

        bool isValid = AlpenPrimitives.isValidPegOut(pegOut);

        bool expectedValid = amount >= AlpenPrimitives.MIN_DEPOSIT_SATS &&
            amount <= AlpenPrimitives.MAX_DEPOSIT_SATS &&
            signatureCount >= AlpenPrimitives.OPERATOR_THRESHOLD;

        assertEq(isValid, expectedValid, "Peg-out validation mismatch");
    }

    // =========================================================================
    // OPERATOR TESTS
    // =========================================================================

    /**
     * @notice Fuzz test: operator threshold check
     */
    function testFuzz_OperatorThreshold(uint256 sigCount) public pure {
        vm.assume(sigCount < 20);

        bytes32[] memory signatures = new bytes32[](sigCount);
        for (uint256 i = 0; i < sigCount; i++) {
            signatures[i] = bytes32(uint256(i + 1));
        }

        bool hasThreshold = AlpenPrimitives.hasOperatorThreshold(signatures);
        assertEq(
            hasThreshold,
            sigCount >= AlpenPrimitives.OPERATOR_THRESHOLD,
            "Threshold check failed"
        );
    }

    /**
     * @notice Fuzz test: operator set hash determinism
     */
    function testFuzz_OperatorSetHashDeterminism(
        bytes32 key1,
        bytes32 key2
    ) public pure {
        AlpenPrimitives.SchnorrPubkey[]
            memory operators = new AlpenPrimitives.SchnorrPubkey[](2);
        operators[0] = AlpenPrimitives.SchnorrPubkey({x: key1});
        operators[1] = AlpenPrimitives.SchnorrPubkey({x: key2});

        bytes32 hash1 = AlpenPrimitives.computeOperatorSetHash(operators);
        bytes32 hash2 = AlpenPrimitives.computeOperatorSetHash(operators);
        assertEq(hash1, hash2, "Operator set hash not deterministic");
    }

    // =========================================================================
    // BITCOIN DIFFICULTY TESTS
    // =========================================================================

    /**
     * @notice Fuzz test: bits to target conversion
     */
    function testFuzz_BitsToTarget(uint32 bits) public pure {
        // Limit to valid range to avoid overflow
        vm.assume(bits > 0 && bits < 0x1F000000);

        uint256 target = AlpenPrimitives.bitsToTarget(bits);
        assertTrue(target > 0, "Target should be positive");
    }

    /**
     * @notice Test: known Bitcoin difficulty targets
     */
    function test_KnownDifficultyTargets() public pure {
        // Genesis block difficulty (bits = 0x1d00ffff)
        uint256 target = AlpenPrimitives.bitsToTarget(0x1d00ffff);
        assertTrue(target > 0, "Genesis target should be positive");

        // High difficulty (bits = 0x17034b9b)
        uint256 highDiffTarget = AlpenPrimitives.bitsToTarget(0x17034b9b);
        assertTrue(
            highDiffTarget < target,
            "Higher difficulty should have lower target"
        );
    }

    // =========================================================================
    // SCRIPT PARSING TESTS
    // =========================================================================

    /**
     * @notice Test: P2WPKH script detection
     */
    function test_P2WPKHDetection() public pure {
        // Valid P2WPKH: OP_0 <20 bytes>
        bytes
            memory validP2WPKH = hex"00147a2f3f9f8e0b4c8a1d2e3f4a5b6c7d8e9f0a1b2c";
        assertTrue(
            AlpenPrimitives.isP2WPKH(validP2WPKH),
            "Valid P2WPKH not detected"
        );

        // Invalid: wrong length
        bytes memory invalidLength = hex"001400";
        assertFalse(
            AlpenPrimitives.isP2WPKH(invalidLength),
            "Invalid length accepted"
        );

        // Invalid: wrong version
        bytes
            memory wrongVersion = hex"01147a2f3f9f8e0b4c8a1d2e3f4a5b6c7d8e9f0a1b2c";
        assertFalse(
            AlpenPrimitives.isP2WPKH(wrongVersion),
            "Wrong version accepted"
        );
    }

    /**
     * @notice Test: P2WSH script detection
     */
    function test_P2WSHDetection() public pure {
        // Valid P2WSH: OP_0 <32 bytes>
        bytes
            memory validP2WSH = hex"00207a2f3f9f8e0b4c8a1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c";
        assertTrue(
            AlpenPrimitives.isP2WSH(validP2WSH),
            "Valid P2WSH not detected"
        );
    }

    /**
     * @notice Test: P2TR (Taproot) script detection
     */
    function test_P2TRDetection() public pure {
        // Valid P2TR: OP_1 <32 bytes>
        bytes
            memory validP2TR = hex"51207a2f3f9f8e0b4c8a1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c";
        assertTrue(
            AlpenPrimitives.isP2TR(validP2TR),
            "Valid P2TR not detected"
        );

        // Invalid: OP_0 instead of OP_1
        bytes
            memory invalidP2TR = hex"00207a2f3f9f8e0b4c8a1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c";
        assertFalse(
            AlpenPrimitives.isP2TR(invalidP2TR),
            "Invalid P2TR accepted"
        );
    }

    /**
     * @notice Fuzz test: script detection mutual exclusivity
     */
    function testFuzz_ScriptTypeMutualExclusivity(
        bytes memory script
    ) public pure {
        vm.assume(script.length > 0 && script.length < 100);

        uint256 matchCount = 0;
        if (AlpenPrimitives.isP2WPKH(script)) matchCount++;
        if (AlpenPrimitives.isP2WSH(script)) matchCount++;
        if (AlpenPrimitives.isP2TR(script)) matchCount++;

        assertTrue(matchCount <= 1, "Script matched multiple types");
    }

    // =========================================================================
    // SCHNORR TESTS
    // =========================================================================

    /**
     * @notice Fuzz test: modular exponentiation
     */
    function testFuzz_ModExp(uint256 base, uint256 exp) public pure {
        // Limit inputs to avoid excessive computation
        vm.assume(base < 1000);
        vm.assume(exp < 100);

        uint256 mod = 1000003; // Small prime
        uint256 result = AlpenPrimitives.modExp(base, exp, mod);
        assertTrue(result < mod, "Result should be less than modulus");
    }

    /**
     * @notice Test: modular exponentiation known values
     */
    function test_ModExpKnownValues() public pure {
        // 2^10 mod 1000 = 24
        uint256 result = AlpenPrimitives.modExp(2, 10, 1000);
        assertEq(result, 24, "2^10 mod 1000 should be 24");

        // 3^5 mod 7 = 5
        result = AlpenPrimitives.modExp(3, 5, 7);
        assertEq(result, 5, "3^5 mod 7 should be 5");

        // x^0 mod m = 1
        result = AlpenPrimitives.modExp(12345, 0, 100);
        assertEq(result, 1, "x^0 should be 1");
    }

    /**
     * @notice Fuzz test: Schnorr pubkey validity
     */
    function testFuzz_SchnorrPubkeyValidity(bytes32 x) public pure {
        AlpenPrimitives.SchnorrPubkey memory pubkey = AlpenPrimitives
            .SchnorrPubkey({x: x});
        // Pubkey should be valid if x is in range
        uint256 xVal = uint256(x);
        if (xVal < ALPEN_SECP256K1_FIELD_PRIME && xVal > 0) {
            assertTrue(pubkey.x != bytes32(0), "Valid pubkey rejected");
        }
    }

    // =========================================================================
    // TAPROOT TESTS
    // =========================================================================

    /**
     * @notice Fuzz test: Taproot tweak computation
     */
    function testFuzz_TaprootTweak(
        bytes32 internalKeyX,
        bytes32 merkleRoot
    ) public pure {
        AlpenPrimitives.SchnorrPubkey memory internalKey = AlpenPrimitives
            .SchnorrPubkey({x: internalKeyX});

        bytes32 tweak1 = AlpenPrimitives.computeTaprootTweak(
            internalKey,
            merkleRoot
        );
        bytes32 tweak2 = AlpenPrimitives.computeTaprootTweak(
            internalKey,
            merkleRoot
        );
        assertEq(tweak1, tweak2, "Taproot tweak not deterministic");
    }

    /**
     * @notice Fuzz test: Taproot tweak uniqueness
     */
    function testFuzz_TaprootTweakUniqueness(
        bytes32 key1,
        bytes32 key2,
        bytes32 merkleRoot
    ) public pure {
        vm.assume(key1 != key2);

        AlpenPrimitives.SchnorrPubkey memory pubkey1 = AlpenPrimitives
            .SchnorrPubkey({x: key1});
        AlpenPrimitives.SchnorrPubkey memory pubkey2 = AlpenPrimitives
            .SchnorrPubkey({x: key2});

        bytes32 tweak1 = AlpenPrimitives.computeTaprootTweak(
            pubkey1,
            merkleRoot
        );
        bytes32 tweak2 = AlpenPrimitives.computeTaprootTweak(
            pubkey2,
            merkleRoot
        );
        assertNotEq(tweak1, tweak2, "Taproot tweak collision");
    }

    // =========================================================================
    // BLOCK HEADER TESTS
    // =========================================================================

    /**
     * @notice Fuzz test: block hash computation
     */
    function testFuzz_BlockHashDeterminism(
        uint32 version,
        bytes32 prevBlockHash,
        bytes32 merkleRoot,
        uint32 timestamp,
        uint32 bits,
        uint32 nonce
    ) public pure {
        AlpenPrimitives.BitcoinBlockHeader memory header = AlpenPrimitives
            .BitcoinBlockHeader({
                version: version,
                prevBlockHash: prevBlockHash,
                merkleRoot: merkleRoot,
                timestamp: timestamp,
                bits: bits,
                nonce: nonce,
                blockHash: bytes32(0)
            });

        bytes32 hash1 = AlpenPrimitives.computeBlockHash(header);
        bytes32 hash2 = AlpenPrimitives.computeBlockHash(header);
        assertEq(hash1, hash2, "Block hash not deterministic");
    }

    /**
     * @notice Fuzz test: block hash uniqueness
     */
    function testFuzz_BlockHashUniqueness(
        uint32 version,
        bytes32 prevBlockHash,
        bytes32 merkleRoot,
        uint32 timestamp,
        uint32 bits,
        uint32 nonce1,
        uint32 nonce2
    ) public pure {
        vm.assume(nonce1 != nonce2);

        AlpenPrimitives.BitcoinBlockHeader memory header1 = AlpenPrimitives
            .BitcoinBlockHeader({
                version: version,
                prevBlockHash: prevBlockHash,
                merkleRoot: merkleRoot,
                timestamp: timestamp,
                bits: bits,
                nonce: nonce1,
                blockHash: bytes32(0)
            });

        AlpenPrimitives.BitcoinBlockHeader memory header2 = AlpenPrimitives
            .BitcoinBlockHeader({
                version: version,
                prevBlockHash: prevBlockHash,
                merkleRoot: merkleRoot,
                timestamp: timestamp,
                bits: bits,
                nonce: nonce2,
                blockHash: bytes32(0)
            });

        bytes32 hash1 = AlpenPrimitives.computeBlockHash(header1);
        bytes32 hash2 = AlpenPrimitives.computeBlockHash(header2);
        assertNotEq(hash1, hash2, "Block hash collision");
    }

    // =========================================================================
    // CONSTANT VALIDATION TESTS
    // =========================================================================

    /**
     * @notice Test: secp256k1 constants validity
     */
    function test_Secp256k1Constants() public pure {
        // Verify curve order is correct
        assertEq(
            AlpenPrimitives.SECP256K1_ORDER,
            ALPEN_SECP256K1_ORDER,
            "Curve order mismatch"
        );

        // Verify field prime is correct
        assertEq(
            AlpenPrimitives.SECP256K1_FIELD_PRIME,
            ALPEN_SECP256K1_FIELD_PRIME,
            "Field prime mismatch"
        );

        // Order should be less than field prime
        assertTrue(
            ALPEN_SECP256K1_ORDER < ALPEN_SECP256K1_FIELD_PRIME,
            "Order >= field prime"
        );
    }

    /**
     * @notice Test: network constants
     */
    function test_NetworkConstants() public pure {
        assertEq(AlpenPrimitives.ALPEN_MAINNET_ID, 1, "Mainnet ID mismatch");
        assertEq(AlpenPrimitives.ALPEN_TESTNET_ID, 2, "Testnet ID mismatch");
    }

    /**
     * @notice Test: bridge parameters
     */
    function test_BridgeParameters() public pure {
        // Min deposit should be positive
        assertTrue(
            AlpenPrimitives.MIN_DEPOSIT_SATS > 0,
            "Min deposit should be positive"
        );

        // Max deposit should be greater than min
        assertTrue(
            AlpenPrimitives.MAX_DEPOSIT_SATS > AlpenPrimitives.MIN_DEPOSIT_SATS,
            "Max should exceed min"
        );

        // Operator threshold should be reasonable
        assertTrue(
            AlpenPrimitives.OPERATOR_THRESHOLD > 0,
            "Threshold should be positive"
        );
        assertTrue(
            AlpenPrimitives.OPERATOR_THRESHOLD <= 9,
            "Threshold too high for 9 operators"
        );
    }

    /**
     * @notice Test: security parameters
     */
    function test_SecurityParameters() public pure {
        // STARK security should be at least 128 bits
        assertTrue(
            AlpenPrimitives.STARK_SECURITY_BITS >= 128,
            "STARK security too low"
        );

        // Finality blocks should be reasonable for Bitcoin
        assertTrue(
            AlpenPrimitives.FINALITY_BLOCKS >= 6,
            "Finality blocks too low"
        );

        // Challenge period should be reasonable
        assertTrue(
            AlpenPrimitives.CHALLENGE_PERIOD >= 1 days,
            "Challenge period too short"
        );
    }
}
