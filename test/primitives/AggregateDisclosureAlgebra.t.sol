// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/primitives/AggregateDisclosureAlgebra.sol";

/// @dev Mock disclosure proof verifier
contract MockDisclosureVerifier {
    bool public result;

    constructor(bool _result) {
        result = _result;
    }

    function verify(bytes calldata) external view returns (bool) {
        return result;
    }

    function setResult(bool _v) external {
        result = _v;
    }
}

contract AggregateDisclosureAlgebraTest is Test {
    AggregateDisclosureAlgebra public ada;
    MockDisclosureVerifier public goodVerifier;
    MockDisclosureVerifier public badVerifier;

    address admin = address(0xAD01);
    address issuer = address(0xBE01);
    address subject = address(0xCE01);
    address verifier_ = address(0xDE01);
    address alice = address(0xEE01);

    bytes32 DISCLOSURE_ADMIN_ROLE;
    bytes32 VERIFIER_ROLE;
    bytes32 ISSUER_ROLE;

    bytes32 constant ATTR_AGE = keccak256("age");
    bytes32 constant ATTR_NAME = keccak256("name");

    function setUp() public {
        vm.warp(10_000);

        vm.startPrank(admin);
        ada = new AggregateDisclosureAlgebra();

        DISCLOSURE_ADMIN_ROLE = ada.DISCLOSURE_ADMIN_ROLE();
        VERIFIER_ROLE = ada.VERIFIER_ROLE();
        ISSUER_ROLE = ada.ISSUER_ROLE();

        ada.grantRole(ISSUER_ROLE, issuer);
        ada.grantRole(VERIFIER_ROLE, verifier_);
        ada.grantRole(DISCLOSURE_ADMIN_ROLE, admin);

        goodVerifier = new MockDisclosureVerifier(true);
        badVerifier = new MockDisclosureVerifier(false);
        ada.setDisclosureProofVerifier(address(goodVerifier));
        vm.stopPrank();
    }

    // ──────── Deployment ────────

    function test_deploy_roles() public view {
        assertTrue(ada.hasRole(ada.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(ada.hasRole(ISSUER_ROLE, issuer));
        assertTrue(ada.hasRole(VERIFIER_ROLE, verifier_));
    }

    function test_deploy_counters() public view {
        assertEq(ada.totalCredentials(), 0);
        assertEq(ada.totalDisclosures(), 0);
        assertEq(ada.totalAggregates(), 0);
    }

    // ──────── Attribute Registration ────────

    function test_registerAttribute() public {
        vm.prank(admin);
        bytes32 attrHash = ada.registerAttribute("age", true, true);

        assertTrue(attrHash != bytes32(0));
    }

    function test_registerAttribute_nonAdminReverts() public {
        vm.prank(alice);
        vm.expectRevert();
        ada.registerAttribute("age", true, true);
    }

    // ──────── Credential Issuance ────────

    function _registerAndIssue() internal returns (bytes32) {
        vm.prank(admin);
        bytes32 attrHash = ada.registerAttribute("age", true, true);

        vm.prank(issuer);
        bytes32 credId = ada.issueCredential(
            subject,
            attrHash,
            keccak256("age_25"),
            uint64(block.timestamp + 1 days)
        );
        return credId;
    }

    function test_issueCredential_success() public {
        bytes32 credId = _registerAndIssue();
        assertTrue(credId != bytes32(0));
        assertEq(ada.totalCredentials(), 1);

        AggregateDisclosureAlgebra.AttributeCredential memory cred = ada
            .getCredential(credId);
        assertEq(cred.issuer, issuer);
        assertEq(cred.subject, subject);
        assertFalse(cred.isRevoked);
    }

    function test_issueCredential_nonIssuerReverts() public {
        vm.prank(admin);
        bytes32 attrHash = ada.registerAttribute("name", false, false);

        vm.prank(alice);
        vm.expectRevert();
        ada.issueCredential(
            subject,
            attrHash,
            keccak256("val"),
            uint64(block.timestamp + 1 days)
        );
    }

    function test_issueCredential_whenPausedReverts() public {
        vm.prank(admin);
        bytes32 attrHash = ada.registerAttribute("field", false, false);

        vm.prank(admin);
        ada.pause();

        vm.prank(issuer);
        vm.expectRevert();
        ada.issueCredential(
            subject,
            attrHash,
            keccak256("v"),
            uint64(block.timestamp + 1 hours)
        );
    }

    // ──────── Credential Revocation ────────

    function test_revokeCredential() public {
        bytes32 credId = _registerAndIssue();

        vm.prank(issuer);
        ada.revokeCredential(credId);

        AggregateDisclosureAlgebra.AttributeCredential memory cred = ada
            .getCredential(credId);
        assertTrue(cred.isRevoked);
        assertFalse(ada.isCredentialValid(credId));
    }

    function test_revokeCredential_nonIssuerReverts() public {
        bytes32 credId = _registerAndIssue();

        vm.prank(alice);
        vm.expectRevert();
        ada.revokeCredential(credId);
    }

    // ──────── Selective Disclosure ────────

    function test_createSelectiveDisclosure() public {
        bytes32 credId = _registerAndIssue();

        bytes32[] memory hidden = new bytes32[](1);
        hidden[0] = keccak256("hidden_attr");

        vm.prank(subject);
        bytes32 dId = ada.createSelectiveDisclosure(
            credId,
            keccak256("revealed"),
            hidden,
            bytes("zk_proof"),
            verifier_,
            uint64(block.timestamp + 1 hours)
        );

        assertTrue(dId != bytes32(0));
        assertEq(ada.totalDisclosures(), 1);
    }

    function test_createSelectiveDisclosure_nonSubjectReverts() public {
        bytes32 credId = _registerAndIssue();

        bytes32[] memory hidden = new bytes32[](0);

        vm.prank(alice); // not the subject
        vm.expectRevert();
        ada.createSelectiveDisclosure(
            credId,
            keccak256("r"),
            hidden,
            bytes("p"),
            verifier_,
            uint64(block.timestamp + 1 hours)
        );
    }

    function test_createSelectiveDisclosure_revokedCredReverts() public {
        bytes32 credId = _registerAndIssue();

        vm.prank(issuer);
        ada.revokeCredential(credId);

        bytes32[] memory hidden = new bytes32[](0);
        vm.prank(subject);
        vm.expectRevert();
        ada.createSelectiveDisclosure(
            credId,
            keccak256("r"),
            hidden,
            bytes("p"),
            verifier_,
            uint64(block.timestamp + 1 hours)
        );
    }

    // ──────── Verify Selective Disclosure ────────

    function test_verifySelectiveDisclosure() public {
        bytes32 credId = _registerAndIssue();

        bytes32[] memory hidden = new bytes32[](0);
        vm.prank(subject);
        bytes32 dId = ada.createSelectiveDisclosure(
            credId,
            keccak256("r"),
            hidden,
            bytes("proof"),
            verifier_,
            uint64(block.timestamp + 1 hours)
        );

        vm.prank(verifier_);
        bool valid = ada.verifySelectiveDisclosure(dId);
        assertTrue(valid);
    }

    function test_verifySelectiveDisclosure_consumed() public {
        bytes32 credId = _registerAndIssue();

        bytes32[] memory hidden = new bytes32[](0);
        vm.prank(subject);
        bytes32 dId = ada.createSelectiveDisclosure(
            credId,
            keccak256("r"),
            hidden,
            bytes("proof"),
            verifier_,
            uint64(block.timestamp + 1 hours)
        );

        vm.prank(verifier_);
        ada.verifySelectiveDisclosure(dId);

        // Second verification should fail (already consumed)
        vm.prank(verifier_);
        vm.expectRevert();
        ada.verifySelectiveDisclosure(dId);
    }

    // ──────── Aggregate Disclosure ────────

    function test_createAggregateDisclosure_AND() public {
        bytes32 credId = _registerAndIssue();

        bytes32[] memory hidden = new bytes32[](0);
        vm.startPrank(subject);
        bytes32 d1 = ada.createSelectiveDisclosure(
            credId,
            keccak256("r1"),
            hidden,
            bytes("p1"),
            verifier_,
            uint64(block.timestamp + 1 hours)
        );
        bytes32 d2 = ada.createSelectiveDisclosure(
            credId,
            keccak256("r2"),
            hidden,
            bytes("p2"),
            verifier_,
            uint64(block.timestamp + 1 hours)
        );
        vm.stopPrank();

        bytes32[] memory dIds = new bytes32[](2);
        dIds[0] = d1;
        dIds[1] = d2;

        vm.prank(subject);
        bytes32 aggId = ada.createAggregateDisclosure(
            dIds,
            AggregateDisclosureAlgebra.AggregationType.AND,
            0
        );

        assertTrue(aggId != bytes32(0));
        assertEq(ada.totalAggregates(), 1);
    }

    function test_createAggregateDisclosure_thresholdZeroReverts() public {
        bytes32 credId = _registerAndIssue();

        bytes32[] memory hidden = new bytes32[](0);
        vm.prank(subject);
        bytes32 d1 = ada.createSelectiveDisclosure(
            credId,
            keccak256("r1"),
            hidden,
            bytes("p1"),
            verifier_,
            uint64(block.timestamp + 1 hours)
        );

        bytes32[] memory dIds = new bytes32[](1);
        dIds[0] = d1;

        vm.prank(subject);
        vm.expectRevert();
        ada.createAggregateDisclosure(
            dIds,
            AggregateDisclosureAlgebra.AggregationType.THRESHOLD,
            0 // invalid threshold
        );
    }

    function test_verifyAggregateDisclosure() public {
        bytes32 credId = _registerAndIssue();

        bytes32[] memory hidden = new bytes32[](0);
        vm.startPrank(subject);
        bytes32 d1 = ada.createSelectiveDisclosure(
            credId,
            keccak256("r1"),
            hidden,
            bytes("p1"),
            address(0),
            uint64(block.timestamp + 1 hours)
        );
        bytes32 d2 = ada.createSelectiveDisclosure(
            credId,
            keccak256("r2"),
            hidden,
            bytes("p2"),
            address(0),
            uint64(block.timestamp + 1 hours)
        );
        vm.stopPrank();

        bytes32[] memory dIds = new bytes32[](2);
        dIds[0] = d1;
        dIds[1] = d2;

        vm.prank(subject);
        bytes32 aggId = ada.createAggregateDisclosure(
            dIds,
            AggregateDisclosureAlgebra.AggregationType.AND,
            0
        );

        vm.prank(verifier_);
        bool valid = ada.verifyAggregateDisclosure(aggId);
        assertTrue(valid);
    }

    function test_verifyAggregateDisclosure_nonVerifierReverts() public {
        bytes32 credId = _registerAndIssue();

        bytes32[] memory hidden = new bytes32[](0);
        vm.prank(subject);
        bytes32 d1 = ada.createSelectiveDisclosure(
            credId,
            keccak256("r"),
            hidden,
            bytes("p"),
            address(0),
            uint64(block.timestamp + 1 hours)
        );

        bytes32[] memory dIds = new bytes32[](1);
        dIds[0] = d1;

        vm.prank(subject);
        bytes32 aggId = ada.createAggregateDisclosure(
            dIds,
            AggregateDisclosureAlgebra.AggregationType.AND,
            0
        );

        vm.prank(alice);
        vm.expectRevert();
        ada.verifyAggregateDisclosure(aggId);
    }

    // ──────── Time Conditions ────────

    function test_createTimeCondition() public {
        // Need a real disclosure first
        bytes32 credId = _registerAndIssue();

        bytes32[] memory hidden = new bytes32[](0);
        vm.prank(subject);
        bytes32 dId = ada.createSelectiveDisclosure(
            credId,
            keccak256("r"),
            hidden,
            bytes("p"),
            verifier_,
            uint64(block.timestamp + 1 hours)
        );

        vm.prank(subject);
        bytes32 condId = ada.createTimeCondition(
            dId,
            block.timestamp + 1 hours
        );
        assertTrue(condId != bytes32(0));
    }

    function test_checkCondition_timeAfter() public {
        bytes32 credId = _registerAndIssue();

        bytes32[] memory hidden = new bytes32[](0);
        vm.prank(subject);
        bytes32 dId = ada.createSelectiveDisclosure(
            credId,
            keccak256("r"),
            hidden,
            bytes("p"),
            verifier_,
            uint64(block.timestamp + 2 hours)
        );

        vm.prank(subject);
        bytes32 condId = ada.createTimeCondition(
            dId,
            block.timestamp + 1 hours
        );

        // Before unlock time
        assertFalse(ada.checkCondition(condId));

        // After unlock time
        vm.warp(block.timestamp + 2 hours);
        assertTrue(ada.checkCondition(condId));
    }

    // ──────── View Functions ────────

    function test_isCredentialValid_expired() public {
        vm.prank(admin);
        bytes32 attrHash = ada.registerAttribute("exp", true, false);

        vm.prank(issuer);
        bytes32 credId = ada.issueCredential(
            subject,
            attrHash,
            keccak256("v"),
            uint64(block.timestamp + 100) // Expires in 100s
        );

        assertTrue(ada.isCredentialValid(credId));

        vm.warp(block.timestamp + 200);
        assertFalse(ada.isCredentialValid(credId));
    }

    function test_getSubjectCredentials() public {
        _registerAndIssue();
        bytes32[] memory creds = ada.getSubjectCredentials(subject);
        assertEq(creds.length, 1);
    }

    function test_getSubjectDisclosures() public {
        bytes32 credId = _registerAndIssue();

        bytes32[] memory hidden = new bytes32[](0);
        vm.prank(subject);
        ada.createSelectiveDisclosure(
            credId,
            keccak256("r"),
            hidden,
            bytes("p"),
            verifier_,
            uint64(block.timestamp + 1 hours)
        );

        bytes32[] memory discs = ada.getSubjectDisclosures(subject);
        assertEq(discs.length, 1);
    }

    // ──────── Admin ────────

    function test_pause_unpause() public {
        vm.startPrank(admin);
        ada.pause();
        assertTrue(ada.paused());
        ada.unpause();
        assertFalse(ada.paused());
        vm.stopPrank();
    }

    function test_setDisclosureProofVerifier() public {
        vm.prank(admin);
        ada.setDisclosureProofVerifier(address(badVerifier));
        assertEq(ada.disclosureProofVerifier(), address(badVerifier));
    }

    // ──────── Fuzz ────────

    function testFuzz_issueCredential_anyExpiry(uint64 expiry) public {
        expiry = uint64(
            bound(uint256(expiry), block.timestamp + 1, type(uint64).max)
        );

        vm.prank(admin);
        bytes32 attrHash = ada.registerAttribute("fuzz_attr", false, false);

        vm.prank(issuer);
        bytes32 credId = ada.issueCredential(
            subject,
            attrHash,
            keccak256("fuzz"),
            expiry
        );
        assertTrue(credId != bytes32(0));
    }
}
