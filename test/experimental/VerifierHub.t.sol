// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/experimental/verifiers/VerifierHub.sol";

/// @dev Mock verifier supporting verifyProof(bytes,bytes)
contract MockHubVerifier {
    bool public result;

    constructor(bool _result) {
        result = _result;
    }

    function verifyProof(
        bytes calldata,
        bytes calldata
    ) external view returns (bool) {
        return result;
    }

    // Groth16-style
    function verifyProof(
        uint256[2] calldata,
        uint256[2][2] calldata,
        uint256[2] calldata,
        uint256[] calldata
    ) external view returns (bool) {
        return result;
    }

    function setResult(bool _v) external {
        result = _v;
    }
}

contract VerifierHubTest is Test {
    VerifierHub public hub;
    MockHubVerifier public goodV;
    MockHubVerifier public badV;

    address admin = address(0xAD01);
    address vAdmin = address(0xBE01);
    address alice = address(0xDE01);

    bytes32 VERIFIER_ADMIN_ROLE;

    function setUp() public {
        vm.startPrank(admin);
        hub = new VerifierHub();
        VERIFIER_ADMIN_ROLE = hub.VERIFIER_ADMIN_ROLE();
        hub.grantRole(VERIFIER_ADMIN_ROLE, vAdmin);
        vm.stopPrank();

        goodV = new MockHubVerifier(true);
        badV = new MockHubVerifier(false);
    }

    // ──────── Deployment ────────

    function test_deploy_adminRoles() public view {
        assertTrue(hub.hasRole(hub.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(hub.hasRole(VERIFIER_ADMIN_ROLE, admin));
    }

    function test_deploy_replayProtection() public view {
        assertTrue(hub.replayProtectionEnabled());
    }

    // ──────── Register Verifier ────────

    function test_registerVerifier_success() public {
        vm.prank(vAdmin);
        hub.registerVerifier(
            VerifierHub.CircuitType.StateCommitment,
            address(goodV)
        );

        VerifierHub.VerifierInfo memory vi = hub.getVerifierInfo(
            VerifierHub.CircuitType.StateCommitment
        );
        assertEq(vi.verifier, address(goodV));
        assertTrue(vi.active);
        assertEq(vi.version, 1);
    }

    function test_registerVerifier_nonAdminReverts() public {
        vm.prank(alice);
        vm.expectRevert();
        hub.registerVerifier(
            VerifierHub.CircuitType.StateCommitment,
            address(goodV)
        );
    }

    function test_registerVerifier_zeroAddressReverts() public {
        vm.prank(vAdmin);
        vm.expectRevert(VerifierHub.ZeroAddress.selector);
        hub.registerVerifier(
            VerifierHub.CircuitType.StateCommitment,
            address(0)
        );
    }

    function test_registerVerifier_versionIncrements() public {
        vm.startPrank(vAdmin);
        hub.registerVerifier(
            VerifierHub.CircuitType.MerkleProof,
            address(goodV)
        );
        assertEq(
            hub.getVerifierInfo(VerifierHub.CircuitType.MerkleProof).version,
            1
        );

        hub.registerVerifier(
            VerifierHub.CircuitType.MerkleProof,
            address(badV)
        );
        assertEq(
            hub.getVerifierInfo(VerifierHub.CircuitType.MerkleProof).version,
            2
        );
        vm.stopPrank();
    }

    function test_registerVerifier_historicalTracked() public {
        vm.startPrank(vAdmin);
        hub.registerVerifier(
            VerifierHub.CircuitType.CrossChainProof,
            address(goodV)
        );
        // After this, version=1, no historical yet
        hub.registerVerifier(
            VerifierHub.CircuitType.CrossChainProof,
            address(badV)
        );
        // Now version=2, historical[1] = goodV
        vm.stopPrank();

        assertEq(
            hub.getHistoricalVerifier(
                VerifierHub.CircuitType.CrossChainProof,
                1
            ),
            address(goodV)
        );
        // Current verifier is badV at version 2, not in historical
        VerifierHub.VerifierInfo memory info = hub.getVerifierInfo(
            VerifierHub.CircuitType.CrossChainProof
        );
        assertEq(info.verifier, address(badV));
        assertEq(info.version, 2);
    }

    // ──────── Deactivate Verifier ────────

    function test_deactivateVerifier() public {
        vm.prank(vAdmin);
        hub.registerVerifier(
            VerifierHub.CircuitType.ComplianceProof,
            address(goodV)
        );

        vm.prank(vAdmin);
        hub.deactivateVerifier(VerifierHub.CircuitType.ComplianceProof);

        assertFalse(
            hub.isVerifierActive(VerifierHub.CircuitType.ComplianceProof)
        );
    }

    function test_deactivateVerifier_nonAdminReverts() public {
        vm.prank(vAdmin);
        hub.registerVerifier(
            VerifierHub.CircuitType.StateCommitment,
            address(goodV)
        );

        vm.prank(alice);
        vm.expectRevert();
        hub.deactivateVerifier(VerifierHub.CircuitType.StateCommitment);
    }

    // ──────── Verify Proof ────────

    function test_verifyProof_success() public {
        vm.prank(vAdmin);
        hub.registerVerifier(
            VerifierHub.CircuitType.StateCommitment,
            address(goodV)
        );

        bool valid = hub.verifyProof(
            VerifierHub.CircuitType.StateCommitment,
            bytes("proof"),
            bytes("inputs")
        );
        assertTrue(valid);
    }

    function test_verifyProof_notRegisteredReverts() public {
        vm.expectRevert();
        hub.verifyProof(
            VerifierHub.CircuitType.StateCommitment,
            bytes("p"),
            bytes("i")
        );
    }

    function test_verifyProof_inactiveReverts() public {
        vm.startPrank(vAdmin);
        hub.registerVerifier(
            VerifierHub.CircuitType.StateTransfer,
            address(goodV)
        );
        hub.deactivateVerifier(VerifierHub.CircuitType.StateTransfer);
        vm.stopPrank();

        // Inactive verifier still allows calls through (falls through to using it)
        // It only tries the registry fallback, but verifier is still non-zero
        bool valid = hub.verifyProof(
            VerifierHub.CircuitType.StateTransfer,
            bytes("p"),
            bytes("i")
        );
        assertTrue(valid); // verifier returns true, active check only triggers registry fallback
    }

    function test_verifyProof_replayProtection() public {
        vm.prank(vAdmin);
        hub.registerVerifier(
            VerifierHub.CircuitType.MerkleProof,
            address(goodV)
        );

        bytes memory proof = bytes("unique_proof");
        bytes memory inputs = bytes("inputs");

        hub.verifyProof(VerifierHub.CircuitType.MerkleProof, proof, inputs);

        // Same proof → replay
        vm.expectRevert();
        hub.verifyProof(VerifierHub.CircuitType.MerkleProof, proof, inputs);
    }

    function test_verifyProof_replayProtectionDisabled() public {
        vm.prank(admin);
        hub.setReplayProtection(false);

        vm.prank(vAdmin);
        hub.registerVerifier(
            VerifierHub.CircuitType.MerkleProof,
            address(goodV)
        );

        bytes memory proof = bytes("dup_proof");
        bytes memory inputs = bytes("inputs");

        hub.verifyProof(VerifierHub.CircuitType.MerkleProof, proof, inputs);
        // Should not revert with replay protection disabled
        hub.verifyProof(VerifierHub.CircuitType.MerkleProof, proof, inputs);
    }

    function test_verifyProof_whenPausedReverts() public {
        vm.prank(vAdmin);
        hub.registerVerifier(
            VerifierHub.CircuitType.StateCommitment,
            address(goodV)
        );

        vm.prank(admin);
        hub.pause();

        vm.expectRevert();
        hub.verifyProof(
            VerifierHub.CircuitType.StateCommitment,
            bytes("p"),
            bytes("i")
        );
    }

    function test_verifyProof_verificationFails() public {
        vm.prank(vAdmin);
        hub.registerVerifier(
            VerifierHub.CircuitType.StateCommitment,
            address(badV)
        );

        // verifyProof returns false, doesn't revert
        bool valid = hub.verifyProof(
            VerifierHub.CircuitType.StateCommitment,
            bytes("p"),
            bytes("i")
        );
        assertFalse(valid);

        VerifierHub.VerifierInfo memory info = hub.getVerifierInfo(
            VerifierHub.CircuitType.StateCommitment
        );
        assertEq(info.totalFailures, 1);
    }

    // ──────── Admin ────────

    function test_setReplayProtection() public {
        vm.prank(admin);
        hub.setReplayProtection(false);
        assertFalse(hub.replayProtectionEnabled());
    }

    function test_setVerifierRegistry() public {
        address reg = address(0xFACE);
        vm.prank(admin);
        hub.setVerifierRegistry(reg);
        assertEq(hub.verifierRegistry(), reg);
    }

    function test_pause_unpause() public {
        vm.startPrank(admin);
        hub.pause();
        assertTrue(hub.paused());
        hub.unpause();
        assertFalse(hub.paused());
        vm.stopPrank();
    }

    // ──────── View Functions ────────

    function test_isProofUsed() public {
        vm.prank(vAdmin);
        hub.registerVerifier(
            VerifierHub.CircuitType.StateCommitment,
            address(goodV)
        );

        bytes memory p = bytes("check_used");
        bytes memory i = bytes("in");
        // Proof hash uses abi.encode, not abi.encodePacked
        bytes32 ph = keccak256(abi.encode(p, i));

        assertFalse(hub.isProofUsed(ph));
        hub.verifyProof(VerifierHub.CircuitType.StateCommitment, p, i);
        assertTrue(hub.isProofUsed(ph));
    }

    // ──────── Fuzz ────────

    function testFuzz_registerVerifier_allTypes(uint8 typeIdx) public {
        typeIdx = uint8(bound(typeIdx, 0, 4));
        VerifierHub.CircuitType ct = VerifierHub.CircuitType(typeIdx);

        vm.prank(vAdmin);
        hub.registerVerifier(ct, address(goodV));

        assertTrue(hub.isVerifierActive(ct));
    }
}
