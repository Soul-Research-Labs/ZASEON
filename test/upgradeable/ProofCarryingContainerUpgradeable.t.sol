// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "../../contracts/upgradeable/ProofCarryingContainerUpgradeable.sol";
import "../../contracts/verifiers/VerifierRegistryV2.sol";

contract ProofCarryingContainerUpgradeableTest is Test {
    ProofCarryingContainerUpgradeable pc3;
    address admin = address(0xA0A0);
    address verifier = address(0xB0B0);
    address user1 = address(0xC0C0);

    function setUp() public {
        ProofCarryingContainerUpgradeable impl = new ProofCarryingContainerUpgradeable();
        bytes memory initData = abi.encodeCall(
            ProofCarryingContainerUpgradeable.initialize,
            (admin)
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);
        pc3 = ProofCarryingContainerUpgradeable(address(proxy));

        // Grant verifier role — use startPrank to avoid prank being consumed by VERIFIER_ROLE() getter
        bytes32 verifierRole = pc3.VERIFIER_ROLE();
        vm.prank(admin);
        pc3.grantRole(verifierRole, verifier);
    }

    /* ══════════════════════════════════════════════════
              HELPER
       ══════════════════════════════════════════════════ */

    function _validProofBundle()
        internal
        view
        returns (ProofCarryingContainerUpgradeable.ProofBundle memory bundle)
    {
        bytes memory validityProof = new bytes(256);
        bytes memory policyProof = new bytes(32);
        bytes memory nullifierProof = new bytes(32);

        bundle = ProofCarryingContainerUpgradeable.ProofBundle({
            validityProof: validityProof,
            policyProof: policyProof,
            nullifierProof: nullifierProof,
            proofHash: keccak256(
                abi.encodePacked(validityProof, policyProof, nullifierProof)
            ),
            proofTimestamp: block.timestamp,
            proofExpiry: block.timestamp + 24 hours
        });
    }

    function _createTestContainer()
        internal
        returns (bytes32 containerId)
    {
        bytes memory payload = abi.encode("test payload");
        bytes32 stateCommitment = bytes32(uint256(1));
        bytes32 nullifier = bytes32(uint256(2));
        ProofCarryingContainerUpgradeable.ProofBundle memory bundle = _validProofBundle();

        vm.prank(user1);
        containerId = pc3.createContainer(
            payload,
            stateCommitment,
            nullifier,
            bundle,
            bytes32(0) // no policy
        );
    }

    /* ══════════════════════════════════════════════════
              INITIALIZATION
       ══════════════════════════════════════════════════ */

    function test_initialize_setsRoles() public view {
        assertTrue(pc3.hasRole(pc3.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(pc3.hasRole(pc3.CONTAINER_ADMIN_ROLE(), admin));
        assertTrue(pc3.hasRole(pc3.UPGRADER_ROLE(), admin));
    }

    function test_initialize_setsDefaults() public view {
        assertEq(pc3.proofValidityWindow(), 24 hours);
        assertEq(pc3.contractVersion(), 1);
        assertFalse(pc3.useRealVerification());
    }

    function test_initialize_cannotCallTwice() public {
        vm.expectRevert();
        pc3.initialize(admin);
    }

    /* ══════════════════════════════════════════════════
              CREATE CONTAINER
       ══════════════════════════════════════════════════ */

    function test_createContainer_success() public {
        bytes32 containerId = _createTestContainer();
        assertNotEq(containerId, bytes32(0));
        assertEq(pc3.totalContainers(), 1);
    }

    function test_createContainer_storesData() public {
        bytes32 containerId = _createTestContainer();
        ProofCarryingContainerUpgradeable.Container memory c = pc3.getContainer(containerId);
        assertEq(c.stateCommitment, bytes32(uint256(1)));
        assertEq(c.nullifier, bytes32(uint256(2)));
        assertFalse(c.isVerified);
        assertFalse(c.isConsumed);
        assertEq(c.version, 1);
    }

    function test_createContainer_revertsEmptyPayload() public {
        ProofCarryingContainerUpgradeable.ProofBundle memory bundle = _validProofBundle();
        vm.prank(user1);
        vm.expectRevert(ProofCarryingContainerUpgradeable.InvalidContainerData.selector);
        pc3.createContainer(
            "",
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            bundle,
            bytes32(0)
        );
    }

    function test_createContainer_revertsZeroCommitment() public {
        ProofCarryingContainerUpgradeable.ProofBundle memory bundle = _validProofBundle();
        vm.prank(user1);
        vm.expectRevert(ProofCarryingContainerUpgradeable.InvalidContainerData.selector);
        pc3.createContainer(
            abi.encode("data"),
            bytes32(0),
            bytes32(uint256(2)),
            bundle,
            bytes32(0)
        );
    }

    function test_createContainer_revertsZeroNullifier() public {
        ProofCarryingContainerUpgradeable.ProofBundle memory bundle = _validProofBundle();
        vm.prank(user1);
        vm.expectRevert(ProofCarryingContainerUpgradeable.InvalidContainerData.selector);
        pc3.createContainer(
            abi.encode("data"),
            bytes32(uint256(1)),
            bytes32(0),
            bundle,
            bytes32(0)
        );
    }

    function test_createContainer_revertsShortProof() public {
        bytes memory shortValid = new bytes(100);
        bytes memory pp = new bytes(32);
        bytes memory np = new bytes(32);

        ProofCarryingContainerUpgradeable.ProofBundle memory bundle = ProofCarryingContainerUpgradeable.ProofBundle({
            validityProof: shortValid,
            policyProof: pp,
            nullifierProof: np,
            proofHash: keccak256(abi.encodePacked(shortValid, pp, np)),
            proofTimestamp: block.timestamp,
            proofExpiry: 0
        });

        vm.prank(user1);
        vm.expectRevert(abi.encodeWithSelector(
            ProofCarryingContainerUpgradeable.ProofTooSmall.selector,
            100,
            256
        ));
        pc3.createContainer(
            abi.encode("data"),
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            bundle,
            bytes32(0)
        );
    }

    function test_createContainer_revertsInvalidProofHash() public {
        ProofCarryingContainerUpgradeable.ProofBundle memory bundle = _validProofBundle();
        bundle.proofHash = bytes32(uint256(0xDEAD)); // tampered

        vm.prank(user1);
        vm.expectRevert(ProofCarryingContainerUpgradeable.InvalidProofBundle.selector);
        pc3.createContainer(
            abi.encode("data"),
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            bundle,
            bytes32(0)
        );
    }

    function test_createContainer_revertsUnsupportedPolicy() public {
        ProofCarryingContainerUpgradeable.ProofBundle memory bundle = _validProofBundle();
        bytes32 policy = bytes32(uint256(0xABC));

        vm.prank(user1);
        vm.expectRevert(abi.encodeWithSelector(
            ProofCarryingContainerUpgradeable.UnsupportedPolicy.selector,
            policy
        ));
        pc3.createContainer(
            abi.encode("data"),
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            bundle,
            policy
        );
    }

    function test_createContainer_withSupportedPolicy() public {
        bytes32 policy = bytes32(uint256(0xABC));
        vm.prank(admin);
        pc3.addPolicy(policy);

        ProofCarryingContainerUpgradeable.ProofBundle memory bundle = _validProofBundle();
        vm.prank(user1);
        bytes32 id = pc3.createContainer(
            abi.encode("data"),
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            bundle,
            policy
        );
        assertNotEq(id, bytes32(0));
    }

    function test_createContainer_revertsConsumedNullifier() public {
        // Create and consume first container
        bytes32 id = _createTestContainer();
        vm.prank(verifier);
        pc3.consumeContainer(id);

        // Try to create with same nullifier
        ProofCarryingContainerUpgradeable.ProofBundle memory bundle = _validProofBundle();
        vm.prank(user1);
        vm.expectRevert(abi.encodeWithSelector(
            ProofCarryingContainerUpgradeable.NullifierAlreadyConsumed.selector,
            bytes32(uint256(2))
        ));
        pc3.createContainer(
            abi.encode("data"),
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            bundle,
            bytes32(0)
        );
    }

    function test_createContainer_revertsWhenPaused() public {
        vm.prank(admin);
        pc3.pause();

        ProofCarryingContainerUpgradeable.ProofBundle memory bundle = _validProofBundle();
        vm.prank(user1);
        vm.expectRevert();
        pc3.createContainer(
            abi.encode("x"),
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            bundle,
            bytes32(0)
        );
    }

    /* ══════════════════════════════════════════════════
              CONSUME CONTAINER
       ══════════════════════════════════════════════════ */

    function test_consumeContainer_success() public {
        bytes32 id = _createTestContainer();
        vm.prank(verifier);
        pc3.consumeContainer(id);

        ProofCarryingContainerUpgradeable.Container memory c = pc3.getContainer(id);
        assertTrue(c.isConsumed);
        assertTrue(pc3.isNullifierConsumed(bytes32(uint256(2))));
    }

    function test_consumeContainer_revertsNotFound() public {
        vm.prank(verifier);
        vm.expectRevert(abi.encodeWithSelector(
            ProofCarryingContainerUpgradeable.ContainerNotFound.selector,
            bytes32(uint256(999))
        ));
        pc3.consumeContainer(bytes32(uint256(999)));
    }

    function test_consumeContainer_revertsAlreadyConsumed() public {
        bytes32 id = _createTestContainer();
        vm.prank(verifier);
        pc3.consumeContainer(id);

        vm.prank(verifier);
        vm.expectRevert(abi.encodeWithSelector(
            ProofCarryingContainerUpgradeable.ContainerAlreadyConsumed.selector,
            id
        ));
        pc3.consumeContainer(id);
    }

    function test_consumeContainer_revertsNotVerifier() public {
        bytes32 id = _createTestContainer();
        vm.prank(user1);
        vm.expectRevert();
        pc3.consumeContainer(id);
    }

    /* ══════════════════════════════════════════════════
              VIEW FUNCTIONS
       ══════════════════════════════════════════════════ */

    function test_getContainerIds_pagination() public {
        // Create 3 containers with unique nullifiers
        bytes memory payload = abi.encode("data");
        for (uint256 i = 1; i <= 3; i++) {
            ProofCarryingContainerUpgradeable.ProofBundle memory bundle = _validProofBundle();
            vm.prank(user1);
            pc3.createContainer(
                payload,
                bytes32(i * 10),
                bytes32(i),
                bundle,
                bytes32(0)
            );
        }

        bytes32[] memory first2 = pc3.getContainerIds(0, 2);
        assertEq(first2.length, 2);

        bytes32[] memory last1 = pc3.getContainerIds(2, 5);
        assertEq(last1.length, 1);

        bytes32[] memory outOfRange = pc3.getContainerIds(10, 5);
        assertEq(outOfRange.length, 0);
    }

    function test_isNullifierConsumed_false() public view {
        assertFalse(pc3.isNullifierConsumed(bytes32(uint256(999))));
    }

    function test_getImplementationVersion() public view {
        assertEq(keccak256(bytes(pc3.getImplementationVersion())), keccak256("1.0.0"));
    }

    /* ══════════════════════════════════════════════════
              ADMIN FUNCTIONS
       ══════════════════════════════════════════════════ */

    function test_addRemovePolicy() public {
        bytes32 policy = bytes32(uint256(0x123));
        vm.prank(admin);
        pc3.addPolicy(policy);
        assertTrue(pc3.supportedPolicies(policy));

        vm.prank(admin);
        pc3.removePolicy(policy);
        assertFalse(pc3.supportedPolicies(policy));
    }

    function test_setProofValidityWindow() public {
        vm.prank(admin);
        pc3.setProofValidityWindow(48 hours);
        assertEq(pc3.proofValidityWindow(), 48 hours);
    }

    function test_setVerifierRegistry() public {
        address registry = address(0x99);
        vm.prank(admin);
        pc3.setVerifierRegistry(registry);
        assertEq(address(pc3.verifierRegistry()), registry);
    }

    function test_setRealVerification() public {
        vm.prank(admin);
        pc3.setRealVerification(true);
        assertTrue(pc3.useRealVerification());
    }

    /* ══════════════════════════════════════════════════
              PAUSE / UNPAUSE
       ══════════════════════════════════════════════════ */

    function test_pause_unpause() public {
        vm.prank(admin);
        pc3.pause();
        assertTrue(pc3.paused());

        vm.prank(admin);
        pc3.unpause();
        assertFalse(pc3.paused());
    }

    function test_pause_revertsNotAdmin() public {
        vm.prank(user1);
        vm.expectRevert();
        pc3.pause();
    }

    /* ══════════════════════════════════════════════════
              UPGRADE
       ══════════════════════════════════════════════════ */

    function test_upgrade_revertsNotUpgrader() public {
        ProofCarryingContainerUpgradeable newImpl = new ProofCarryingContainerUpgradeable();
        vm.prank(user1);
        vm.expectRevert();
        pc3.upgradeToAndCall(address(newImpl), "");
    }

    function test_upgrade_succeeds() public {
        ProofCarryingContainerUpgradeable newImpl = new ProofCarryingContainerUpgradeable();
        vm.prank(admin);
        pc3.upgradeToAndCall(address(newImpl), "");
        assertEq(pc3.contractVersion(), 2);
    }

    /* ══════════════════════════════════════════════════
              CONSTANTS
       ══════════════════════════════════════════════════ */

    function test_constants() public view {
        assertEq(pc3.MAX_PAYLOAD_SIZE(), 1 << 20);
        assertEq(pc3.MIN_PROOF_SIZE(), 256);
    }
}
