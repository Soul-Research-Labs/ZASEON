// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/primitives/HomomorphicHiding.sol";

/// @dev Mock range proof verifier
contract MockRangeVerifier {
    bool public shouldPass;

    constructor(bool _shouldPass) {
        shouldPass = _shouldPass;
    }

    function verify(bytes calldata) external view returns (bool) {
        return shouldPass;
    }

    function setShouldPass(bool _v) external {
        shouldPass = _v;
    }
}

contract HomomorphicHidingTest is Test {
    HomomorphicHiding public hh;
    MockRangeVerifier public goodVerifier;
    MockRangeVerifier public badVerifier;

    address admin = address(0xAD01);
    address operator = address(0xBEEF);
    address verifier = address(0xCEEF);
    address user = address(0xDE01);

    bytes32 COMMITMENT_MANAGER_ROLE;
    bytes32 VERIFIER_ROLE;
    bytes32 OPERATOR_ROLE;

    bytes32 constant GEN_G = keccak256("generatorG");
    bytes32 constant GEN_H = keccak256("generatorH");

    function setUp() public {
        vm.startPrank(admin);
        hh = new HomomorphicHiding();

        // Cache roles
        COMMITMENT_MANAGER_ROLE = hh.COMMITMENT_MANAGER_ROLE();
        VERIFIER_ROLE = hh.VERIFIER_ROLE();
        OPERATOR_ROLE = hh.OPERATOR_ROLE();

        // Grant roles
        hh.grantRole(OPERATOR_ROLE, operator);
        hh.grantRole(VERIFIER_ROLE, verifier);
        hh.grantRole(COMMITMENT_MANAGER_ROLE, admin);

        // Deploy verifiers
        goodVerifier = new MockRangeVerifier(true);
        badVerifier = new MockRangeVerifier(false);
        hh.setRangeProofVerifier(address(goodVerifier));

        vm.stopPrank();
    }

    // ──────── Deployment ────────

    function test_deployment_setsAdmin() public view {
        assertTrue(hh.hasRole(hh.DEFAULT_ADMIN_ROLE(), admin));
    }

    function test_deployment_setsRoles() public view {
        assertTrue(hh.hasRole(OPERATOR_ROLE, operator));
        assertTrue(hh.hasRole(VERIFIER_ROLE, verifier));
    }

    function test_deployment_initialCounters() public view {
        assertEq(hh.totalCommitments(), 0);
        assertEq(hh.totalOperations(), 0);
    }

    // ──────── Create Commitment ────────

    function test_createCommitment_success() public {
        bytes32 commitment = keccak256("secret_value");
        uint64 expiry = uint64(block.timestamp + 1 days);

        vm.prank(user);
        bytes32 commitmentId = hh.createCommitment(
            commitment,
            GEN_G,
            GEN_H,
            expiry
        );

        assertTrue(commitmentId != bytes32(0));
        assertEq(hh.totalCommitments(), 1);

        HomomorphicHiding.HiddenCommitment memory c = hh.getCommitment(
            commitmentId
        );
        assertEq(c.commitment, commitment);
        assertEq(c.generatorG, GEN_G);
        assertEq(c.generatorH, GEN_H);
        assertEq(c.owner, user);
        assertTrue(c.isActive);
        assertFalse(c.isRevealed);
    }

    function test_createCommitment_emitsEvent() public {
        bytes32 commitment = keccak256("v1");
        vm.prank(user);
        vm.expectEmit(false, true, false, true);
        emit HomomorphicHiding.CommitmentCreated(bytes32(0), user, commitment);
        hh.createCommitment(
            commitment,
            GEN_G,
            GEN_H,
            uint64(block.timestamp + 1 hours)
        );
    }

    function test_createCommitment_multipleFromSameOwner() public {
        vm.startPrank(user);
        hh.createCommitment(
            keccak256("v1"),
            GEN_G,
            GEN_H,
            uint64(block.timestamp + 1 hours)
        );
        hh.createCommitment(
            keccak256("v2"),
            GEN_G,
            GEN_H,
            uint64(block.timestamp + 1 hours)
        );
        vm.stopPrank();

        bytes32[] memory owned = hh.getOwnerCommitments(user);
        assertEq(owned.length, 2);
        assertEq(hh.totalCommitments(), 2);
    }

    function test_createCommitment_revertsWhenPaused() public {
        vm.prank(admin);
        hh.pause();
        vm.expectRevert();
        vm.prank(user);
        hh.createCommitment(
            keccak256("v1"),
            GEN_G,
            GEN_H,
            uint64(block.timestamp + 1 hours)
        );
    }

    // ──────── Reveal Commitment ────────

    function test_revealCommitment_success() public {
        uint256 value = 42;
        bytes32 randomness = keccak256("randomness");
        // Commitment must be keccak256(abi.encodePacked(genG, value, genH, randomness))
        bytes32 commitment = keccak256(
            abi.encodePacked(GEN_G, value, GEN_H, randomness)
        );

        vm.prank(user);
        bytes32 cid = hh.createCommitment(
            commitment,
            GEN_G,
            GEN_H,
            uint64(block.timestamp + 1 days)
        );

        vm.prank(user);
        hh.revealCommitment(cid, value, randomness);

        HomomorphicHiding.HiddenCommitment memory c = hh.getCommitment(cid);
        assertTrue(c.isRevealed);
    }

    function test_revealCommitment_nonOwnerReverts() public {
        uint256 value = 42;
        bytes32 randomness = keccak256("r");
        bytes32 commitment = keccak256(
            abi.encodePacked(GEN_G, value, GEN_H, randomness)
        );

        vm.prank(user);
        bytes32 cid = hh.createCommitment(
            commitment,
            GEN_G,
            GEN_H,
            uint64(block.timestamp + 1 days)
        );

        vm.prank(operator);
        vm.expectRevert();
        hh.revealCommitment(cid, value, randomness);
    }

    function test_revealCommitment_doubleRevealReverts() public {
        uint256 value = 42;
        bytes32 randomness = keccak256("r2");
        bytes32 commitment = keccak256(
            abi.encodePacked(GEN_G, value, GEN_H, randomness)
        );

        vm.prank(user);
        bytes32 cid = hh.createCommitment(
            commitment,
            GEN_G,
            GEN_H,
            uint64(block.timestamp + 1 days)
        );

        vm.prank(user);
        hh.revealCommitment(cid, value, randomness);

        vm.prank(user);
        vm.expectRevert();
        hh.revealCommitment(cid, value, randomness);
    }

    // ──────── Homomorphic Operations ────────

    function test_homomorphicAdd_success() public {
        vm.startPrank(user);
        bytes32 cidA = hh.createCommitment(
            keccak256("a"),
            GEN_G,
            GEN_H,
            uint64(block.timestamp + 1 days)
        );
        bytes32 cidB = hh.createCommitment(
            keccak256("b"),
            GEN_G,
            GEN_H,
            uint64(block.timestamp + 1 days)
        );
        vm.stopPrank();

        vm.prank(operator);
        (bytes32 resultId, bytes32 result) = hh.homomorphicAdd(cidA, cidB);

        assertTrue(resultId != bytes32(0));
        assertTrue(result != bytes32(0));
        assertEq(hh.totalOperations(), 1);

        HomomorphicHiding.OperationResult memory op = hh.getOperation(resultId);
        assertEq(op.inputA, cidA);
        assertEq(op.inputB, cidB);
        assertTrue(op.opType == HomomorphicHiding.OperationType.Add);
    }

    function test_homomorphicSubtract_success() public {
        vm.startPrank(user);
        bytes32 cidA = hh.createCommitment(
            keccak256("a"),
            GEN_G,
            GEN_H,
            uint64(block.timestamp + 1 days)
        );
        bytes32 cidB = hh.createCommitment(
            keccak256("b"),
            GEN_G,
            GEN_H,
            uint64(block.timestamp + 1 days)
        );
        vm.stopPrank();

        vm.prank(operator);
        (bytes32 resultId, bytes32 result) = hh.homomorphicSubtract(cidA, cidB);

        assertTrue(resultId != bytes32(0));
        assertTrue(result != bytes32(0));

        HomomorphicHiding.OperationResult memory op = hh.getOperation(resultId);
        assertTrue(op.opType == HomomorphicHiding.OperationType.Subtract);
    }

    function test_homomorphicScalarMultiply_success() public {
        vm.prank(user);
        bytes32 cid = hh.createCommitment(
            keccak256("a"),
            GEN_G,
            GEN_H,
            uint64(block.timestamp + 1 days)
        );

        vm.prank(operator);
        (bytes32 resultId, bytes32 result) = hh.homomorphicScalarMultiply(
            cid,
            5
        );

        assertTrue(resultId != bytes32(0));
        assertTrue(result != bytes32(0));

        HomomorphicHiding.OperationResult memory op = hh.getOperation(resultId);
        assertTrue(op.opType == HomomorphicHiding.OperationType.ScalarMultiply);
    }

    function test_homomorphicOps_requireOperatorRole() public {
        vm.startPrank(user);
        bytes32 cidA = hh.createCommitment(
            keccak256("a"),
            GEN_G,
            GEN_H,
            uint64(block.timestamp + 1 days)
        );
        bytes32 cidB = hh.createCommitment(
            keccak256("b"),
            GEN_G,
            GEN_H,
            uint64(block.timestamp + 1 days)
        );
        vm.stopPrank();

        vm.prank(user); // user doesn't have OPERATOR_ROLE
        vm.expectRevert();
        hh.homomorphicAdd(cidA, cidB);
    }

    function test_homomorphicAdd_inactiveCommitmentReverts() public {
        vm.prank(user);
        bytes32 cidA = hh.createCommitment(
            keccak256("a"),
            GEN_G,
            GEN_H,
            uint64(block.timestamp + 1 days)
        );
        vm.prank(user);
        bytes32 cidB = hh.createCommitment(
            keccak256("b"),
            GEN_G,
            GEN_H,
            uint64(block.timestamp + 1 days)
        );

        // Deactivate commitment A
        vm.prank(admin);
        hh.deactivateCommitment(cidA);

        vm.prank(operator);
        vm.expectRevert();
        hh.homomorphicAdd(cidA, cidB);
    }

    // ──────── Range Proofs ────────

    function test_submitRangeProof_success() public {
        vm.prank(user);
        bytes32 cid = hh.createCommitment(
            keccak256("a"),
            GEN_G,
            GEN_H,
            uint64(block.timestamp + 1 days)
        );

        vm.prank(user);
        bytes32 proofId = hh.submitRangeProof(cid, 0, 100, bytes("proof_data"));

        assertTrue(proofId != bytes32(0));
        HomomorphicHiding.RangeProof memory rp = hh.getRangeProof(proofId);
        assertEq(rp.commitmentId, cid);
        assertEq(rp.lowerBound, 0);
        assertEq(rp.upperBound, 100);
        assertFalse(rp.isVerified);
    }

    function test_verifyRangeProof_success() public {
        vm.prank(user);
        bytes32 cid = hh.createCommitment(
            keccak256("a"),
            GEN_G,
            GEN_H,
            uint64(block.timestamp + 1 days)
        );

        vm.prank(user);
        bytes32 proofId = hh.submitRangeProof(cid, 0, 100, bytes("proof_data"));

        vm.prank(verifier);
        bool valid = hh.verifyRangeProof(proofId);

        assertTrue(valid);
        HomomorphicHiding.RangeProof memory rp = hh.getRangeProof(proofId);
        assertTrue(rp.isVerified);
    }

    function test_verifyRangeProof_requiresVerifierRole() public {
        vm.prank(user);
        bytes32 cid = hh.createCommitment(
            keccak256("a"),
            GEN_G,
            GEN_H,
            uint64(block.timestamp + 1 days)
        );
        vm.prank(user);
        bytes32 proofId = hh.submitRangeProof(cid, 0, 100, bytes("proof_data"));

        vm.prank(user);
        vm.expectRevert();
        hh.verifyRangeProof(proofId);
    }

    // ──────── Aggregate Proofs ────────

    function test_createAggregateProof_success() public {
        vm.startPrank(user);
        bytes32 cidA = hh.createCommitment(
            keccak256("a"),
            GEN_G,
            GEN_H,
            uint64(block.timestamp + 1 days)
        );
        bytes32 cidB = hh.createCommitment(
            keccak256("b"),
            GEN_G,
            GEN_H,
            uint64(block.timestamp + 1 days)
        );
        vm.stopPrank();

        bytes32[] memory ids = new bytes32[](2);
        ids[0] = cidA;
        ids[1] = cidB;

        vm.prank(user);
        bytes32 proofId = hh.createAggregateProof(ids, bytes("agg_proof"));

        assertTrue(proofId != bytes32(0));
        HomomorphicHiding.AggregateProof memory ap = hh.getAggregateProof(
            proofId
        );
        assertEq(ap.commitmentIds.length, 2);
        assertTrue(ap.aggregateCommitment != bytes32(0));
    }

    // ──────── Admin Functions ────────

    function test_pause_unpause() public {
        vm.prank(admin);
        hh.pause();
        assertTrue(hh.paused());

        vm.prank(admin);
        hh.unpause();
        assertFalse(hh.paused());
    }

    function test_pause_requiresAdmin() public {
        vm.prank(user);
        vm.expectRevert();
        hh.pause();
    }

    function test_deactivateCommitment() public {
        vm.prank(user);
        bytes32 cid = hh.createCommitment(
            keccak256("v"),
            GEN_G,
            GEN_H,
            uint64(block.timestamp + 1 days)
        );

        assertTrue(hh.isCommitmentValid(cid));

        vm.prank(admin);
        hh.deactivateCommitment(cid);

        assertFalse(hh.isCommitmentValid(cid));
    }

    function test_setRangeProofVerifier() public {
        address newV = address(0xBEEF01);
        vm.prank(admin);
        hh.setRangeProofVerifier(newV);
        assertEq(hh.rangeProofVerifier(), newV);
    }

    function test_setRangeProofVerifier_nonAdminReverts() public {
        vm.prank(user);
        vm.expectRevert();
        hh.setRangeProofVerifier(address(0xBEEF01));
    }

    // ──────── View Functions ────────

    function test_isCommitmentValid_expired() public {
        vm.warp(1000);
        vm.prank(user);
        bytes32 cid = hh.createCommitment(
            keccak256("v"),
            GEN_G,
            GEN_H,
            uint64(block.timestamp + 100)
        );

        assertTrue(hh.isCommitmentValid(cid));

        vm.warp(block.timestamp + 200);
        assertFalse(hh.isCommitmentValid(cid));
    }

    function test_getOwnerCommitments_empty() public view {
        bytes32[] memory owned = hh.getOwnerCommitments(address(0xDEAD));
        assertEq(owned.length, 0);
    }

    // ──────── Fuzz Tests ────────

    function testFuzz_createCommitment_anyValue(
        bytes32 commitment,
        bytes32 gG,
        bytes32 gH
    ) public {
        vm.assume(commitment != bytes32(0));
        vm.assume(gG != bytes32(0));
        vm.assume(gH != bytes32(0));

        vm.prank(user);
        bytes32 cid = hh.createCommitment(
            commitment,
            gG,
            gH,
            uint64(block.timestamp + 1 days)
        );
        assertTrue(cid != bytes32(0));
    }

    function testFuzz_scalarMultiply_anyScalar(uint256 scalar) public {
        vm.assume(scalar > 0 && scalar < type(uint128).max);
        vm.prank(user);
        bytes32 cid = hh.createCommitment(
            keccak256("v"),
            GEN_G,
            GEN_H,
            uint64(block.timestamp + 1 days)
        );

        vm.prank(operator);
        (bytes32 resultId, ) = hh.homomorphicScalarMultiply(cid, scalar);
        assertTrue(resultId != bytes32(0));
    }
}
