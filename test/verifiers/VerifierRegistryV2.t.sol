// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {VerifierRegistryV2} from "../../contracts/verifiers/VerifierRegistryV2.sol";
import {MockProofVerifier} from "../../contracts/mocks/MockProofVerifier.sol";

/**
 * @title VerifierRegistryV2Test
 * @notice Comprehensive tests for the VerifierRegistryV2 registry
 * @dev Covers registration, verification, deprecation, rollback, pause, batch ops, access control
 */
contract VerifierRegistryV2Test is Test {
    VerifierRegistryV2 public registry;
    MockProofVerifier public mockAdapter;
    MockProofVerifier public mockAdapter2;
    MockProofVerifier public falseAdapter;

    address public admin;
    address public guardian;
    address public unauthorized;

    bytes constant SAMPLE_PROOF = hex"aabbccdd";
    bytes constant SAMPLE_INPUTS = hex"11223344";

    function setUp() public {
        admin = makeAddr("admin");
        guardian = makeAddr("guardian");
        unauthorized = makeAddr("unauthorized");

        vm.startPrank(admin);
        registry = new VerifierRegistryV2();
        registry.grantRole(registry.GUARDIAN_ROLE(), guardian);
        vm.stopPrank();

        // Deploy mock adapters
        mockAdapter = new MockProofVerifier();
        mockAdapter.setVerificationResult(true);

        mockAdapter2 = new MockProofVerifier();
        mockAdapter2.setVerificationResult(true);

        falseAdapter = new MockProofVerifier();
        falseAdapter.setVerificationResult(false);
    }

    /*//////////////////////////////////////////////////////////////
                          INITIALIZATION
    //////////////////////////////////////////////////////////////*/

    function test_DeployedAt() public view {
        assertGt(registry.deployedAt(), 0);
    }

    function test_CircuitTypeCount() public view {
        assertEq(registry.CIRCUIT_TYPE_COUNT(), 20);
    }

    function test_CircuitNames() public view {
        assertEq(
            registry.circuitNames(
                VerifierRegistryV2.CircuitType.STATE_TRANSFER
            ),
            "state_transfer"
        );
        assertEq(
            registry.circuitNames(VerifierRegistryV2.CircuitType.NULLIFIER),
            "nullifier"
        );
        assertEq(
            registry.circuitNames(VerifierRegistryV2.CircuitType.AGGREGATOR),
            "aggregator"
        );
    }

    function test_InitialState() public view {
        assertEq(registry.totalRegistered(), 0);
        assertFalse(registry.paused());
    }

    function test_AdminHasRoles() public view {
        assertTrue(registry.hasRole(registry.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(registry.hasRole(registry.REGISTRY_ADMIN_ROLE(), admin));
        assertTrue(registry.hasRole(registry.GUARDIAN_ROLE(), admin));
    }

    /*//////////////////////////////////////////////////////////////
                          REGISTRATION
    //////////////////////////////////////////////////////////////*/

    function test_RegisterVerifier() public {
        bytes32 hash = keccak256("circuit_v1");

        vm.prank(admin);
        uint256 version = registry.registerVerifier(
            VerifierRegistryV2.CircuitType.STATE_TRANSFER,
            address(mockAdapter),
            address(mockAdapter),
            hash
        );

        assertEq(version, 1);
        assertEq(registry.totalRegistered(), 1);
        assertTrue(
            registry.isInitialized(
                VerifierRegistryV2.CircuitType.STATE_TRANSFER
            )
        );
        assertTrue(
            registry.isActive(VerifierRegistryV2.CircuitType.STATE_TRANSFER)
        );
        assertEq(
            registry.getAdapter(VerifierRegistryV2.CircuitType.STATE_TRANSFER),
            address(mockAdapter)
        );
    }

    function test_RegisterVerifierEmitsEvent() public {
        bytes32 hash = keccak256("circuit_v1");

        vm.expectEmit(true, true, true, true);
        emit VerifierRegistryV2.VerifierRegistered(
            VerifierRegistryV2.CircuitType.STATE_TRANSFER,
            address(mockAdapter),
            address(mockAdapter),
            1,
            hash
        );

        vm.prank(admin);
        registry.registerVerifier(
            VerifierRegistryV2.CircuitType.STATE_TRANSFER,
            address(mockAdapter),
            address(mockAdapter),
            hash
        );
    }

    function test_RegisterMultipleCircuitTypes() public {
        bytes32 hash = keccak256("hash");

        vm.startPrank(admin);
        registry.registerVerifier(
            VerifierRegistryV2.CircuitType.STATE_TRANSFER,
            address(mockAdapter),
            address(mockAdapter),
            hash
        );
        registry.registerVerifier(
            VerifierRegistryV2.CircuitType.NULLIFIER,
            address(mockAdapter2),
            address(mockAdapter2),
            hash
        );
        vm.stopPrank();

        assertEq(registry.totalRegistered(), 2);
    }

    function test_UpgradeVerifierBumpsVersion() public {
        bytes32 hash1 = keccak256("v1");
        bytes32 hash2 = keccak256("v2");

        vm.startPrank(admin);
        registry.registerVerifier(
            VerifierRegistryV2.CircuitType.STATE_TRANSFER,
            address(mockAdapter),
            address(mockAdapter),
            hash1
        );
        uint256 v2 = registry.registerVerifier(
            VerifierRegistryV2.CircuitType.STATE_TRANSFER,
            address(mockAdapter2),
            address(mockAdapter2),
            hash2
        );
        vm.stopPrank();

        assertEq(v2, 2);
        // totalRegistered should still be 1 (same circuit type)
        assertEq(registry.totalRegistered(), 1);
        assertEq(
            registry.getAdapter(VerifierRegistryV2.CircuitType.STATE_TRANSFER),
            address(mockAdapter2)
        );
    }

    function test_RevertRegisterZeroVerifier() public {
        vm.prank(admin);
        vm.expectRevert(VerifierRegistryV2.InvalidAddress.selector);
        registry.registerVerifier(
            VerifierRegistryV2.CircuitType.STATE_TRANSFER,
            address(0),
            address(mockAdapter),
            keccak256("h")
        );
    }

    function test_RevertRegisterZeroAdapter() public {
        vm.prank(admin);
        vm.expectRevert(VerifierRegistryV2.InvalidAddress.selector);
        registry.registerVerifier(
            VerifierRegistryV2.CircuitType.STATE_TRANSFER,
            address(mockAdapter),
            address(0),
            keccak256("h")
        );
    }

    function test_RevertRegisterUnauthorized() public {
        vm.prank(unauthorized);
        vm.expectRevert();
        registry.registerVerifier(
            VerifierRegistryV2.CircuitType.STATE_TRANSFER,
            address(mockAdapter),
            address(mockAdapter),
            keccak256("h")
        );
    }

    /*//////////////////////////////////////////////////////////////
                        BATCH REGISTRATION
    //////////////////////////////////////////////////////////////*/

    function test_BatchRegister() public {
        VerifierRegistryV2.CircuitType[]
            memory types = new VerifierRegistryV2.CircuitType[](3);
        types[0] = VerifierRegistryV2.CircuitType.STATE_TRANSFER;
        types[1] = VerifierRegistryV2.CircuitType.NULLIFIER;
        types[2] = VerifierRegistryV2.CircuitType.POLICY;

        address[] memory verifiers = new address[](3);
        verifiers[0] = address(mockAdapter);
        verifiers[1] = address(mockAdapter);
        verifiers[2] = address(mockAdapter);

        address[] memory adapters = new address[](3);
        adapters[0] = address(mockAdapter);
        adapters[1] = address(mockAdapter2);
        adapters[2] = address(falseAdapter);

        bytes32[] memory hashes = new bytes32[](3);
        hashes[0] = keccak256("a");
        hashes[1] = keccak256("b");
        hashes[2] = keccak256("c");

        vm.prank(admin);
        registry.batchRegisterVerifiers(types, verifiers, adapters, hashes);

        assertEq(registry.totalRegistered(), 3);
        assertTrue(
            registry.isActive(VerifierRegistryV2.CircuitType.STATE_TRANSFER)
        );
        assertTrue(registry.isActive(VerifierRegistryV2.CircuitType.NULLIFIER));
        assertTrue(registry.isActive(VerifierRegistryV2.CircuitType.POLICY));
    }

    /*//////////////////////////////////////////////////////////////
                          VERIFICATION
    //////////////////////////////////////////////////////////////*/

    function test_VerifyProof() public {
        _registerDefault();

        bool result = registry.verify(
            VerifierRegistryV2.CircuitType.STATE_TRANSFER,
            SAMPLE_PROOF,
            SAMPLE_INPUTS
        );
        assertTrue(result);
    }

    function test_VerifyProofFalse() public {
        vm.prank(admin);
        registry.registerVerifier(
            VerifierRegistryV2.CircuitType.STATE_TRANSFER,
            address(falseAdapter),
            address(falseAdapter),
            keccak256("h")
        );

        bool result = registry.verify(
            VerifierRegistryV2.CircuitType.STATE_TRANSFER,
            SAMPLE_PROOF,
            SAMPLE_INPUTS
        );
        assertFalse(result);
    }

    function test_RevertVerifyUnregistered() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                VerifierRegistryV2.VerifierNotRegistered.selector,
                VerifierRegistryV2.CircuitType.STATE_TRANSFER
            )
        );
        registry.verify(
            VerifierRegistryV2.CircuitType.STATE_TRANSFER,
            SAMPLE_PROOF,
            SAMPLE_INPUTS
        );
    }

    function test_RevertVerifyDeprecated() public {
        _registerDefault();

        vm.prank(admin);
        registry.deprecateVerifier(
            VerifierRegistryV2.CircuitType.STATE_TRANSFER,
            "deprecated"
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                VerifierRegistryV2.VerifierDeprecatedError.selector,
                VerifierRegistryV2.CircuitType.STATE_TRANSFER
            )
        );
        registry.verify(
            VerifierRegistryV2.CircuitType.STATE_TRANSFER,
            SAMPLE_PROOF,
            SAMPLE_INPUTS
        );
    }

    function test_RevertVerifyWhenPaused() public {
        _registerDefault();

        vm.prank(guardian);
        registry.pause();

        vm.expectRevert(VerifierRegistryV2.RegistryPausedError.selector);
        registry.verify(
            VerifierRegistryV2.CircuitType.STATE_TRANSFER,
            SAMPLE_PROOF,
            SAMPLE_INPUTS
        );
    }

    /*//////////////////////////////////////////////////////////////
                        BATCH VERIFICATION
    //////////////////////////////////////////////////////////////*/

    function test_BatchVerify() public {
        _registerDefault();

        bytes[] memory proofs = new bytes[](3);
        proofs[0] = SAMPLE_PROOF;
        proofs[1] = SAMPLE_PROOF;
        proofs[2] = SAMPLE_PROOF;

        bytes[] memory inputs = new bytes[](3);
        inputs[0] = SAMPLE_INPUTS;
        inputs[1] = SAMPLE_INPUTS;
        inputs[2] = SAMPLE_INPUTS;

        bool[] memory results = registry.batchVerify(
            VerifierRegistryV2.CircuitType.STATE_TRANSFER,
            proofs,
            inputs
        );

        assertEq(results.length, 3);
        for (uint256 i = 0; i < 3; i++) {
            assertTrue(results[i]);
        }
    }

    /*//////////////////////////////////////////////////////////////
                          DEPRECATION
    //////////////////////////////////////////////////////////////*/

    function test_DeprecateVerifier() public {
        _registerDefault();

        vm.prank(admin);
        registry.deprecateVerifier(
            VerifierRegistryV2.CircuitType.STATE_TRANSFER,
            "obsolete"
        );

        assertFalse(
            registry.isActive(VerifierRegistryV2.CircuitType.STATE_TRANSFER)
        );
    }

    function test_RevertDeprecateUnregistered() public {
        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(
                VerifierRegistryV2.VerifierNotRegistered.selector,
                VerifierRegistryV2.CircuitType.STATE_TRANSFER
            )
        );
        registry.deprecateVerifier(
            VerifierRegistryV2.CircuitType.STATE_TRANSFER,
            "no exist"
        );
    }

    /*//////////////////////////////////////////////////////////////
                        EMERGENCY ROLLBACK
    //////////////////////////////////////////////////////////////*/

    function test_EmergencyRollback() public {
        bytes32 hash1 = keccak256("v1");
        bytes32 hash2 = keccak256("v2");

        vm.startPrank(admin);
        registry.registerVerifier(
            VerifierRegistryV2.CircuitType.STATE_TRANSFER,
            address(mockAdapter),
            address(mockAdapter),
            hash1
        );
        registry.registerVerifier(
            VerifierRegistryV2.CircuitType.STATE_TRANSFER,
            address(mockAdapter2),
            address(mockAdapter2),
            hash2
        );
        vm.stopPrank();

        // Current should be mockAdapter2
        assertEq(
            registry.getAdapter(VerifierRegistryV2.CircuitType.STATE_TRANSFER),
            address(mockAdapter2)
        );

        // Rollback
        vm.prank(guardian);
        registry.emergencyRollback(
            VerifierRegistryV2.CircuitType.STATE_TRANSFER
        );

        // Should be back to mockAdapter
        assertEq(
            registry.getAdapter(VerifierRegistryV2.CircuitType.STATE_TRANSFER),
            address(mockAdapter)
        );
    }

    function test_RevertRollbackNoPreviousVersion() public {
        _registerDefault();

        vm.prank(guardian);
        vm.expectRevert(
            abi.encodeWithSelector(
                VerifierRegistryV2.NoPreviousVersion.selector,
                VerifierRegistryV2.CircuitType.STATE_TRANSFER
            )
        );
        registry.emergencyRollback(
            VerifierRegistryV2.CircuitType.STATE_TRANSFER
        );
    }

    function test_RevertRollbackUnauthorized() public {
        vm.prank(unauthorized);
        vm.expectRevert();
        registry.emergencyRollback(
            VerifierRegistryV2.CircuitType.STATE_TRANSFER
        );
    }

    /*//////////////////////////////////////////////////////////////
                          PAUSE / UNPAUSE
    //////////////////////////////////////////////////////////////*/

    function test_PauseUnpause() public {
        vm.prank(guardian);
        registry.pause();
        assertTrue(registry.paused());

        vm.prank(guardian);
        registry.unpause();
        assertFalse(registry.paused());
    }

    function test_RevertPauseUnauthorized() public {
        vm.prank(unauthorized);
        vm.expectRevert();
        registry.pause();
    }

    /*//////////////////////////////////////////////////////////////
                          QUERY FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function test_GetVerifierEntry() public {
        bytes32 hash = keccak256("circuit");

        vm.prank(admin);
        registry.registerVerifier(
            VerifierRegistryV2.CircuitType.STATE_TRANSFER,
            address(mockAdapter),
            address(mockAdapter2),
            hash
        );

        VerifierRegistryV2.VerifierEntry memory entry = registry
            .getVerifierEntry(VerifierRegistryV2.CircuitType.STATE_TRANSFER);

        assertEq(entry.verifier, address(mockAdapter));
        assertEq(entry.adapter, address(mockAdapter2));
        assertEq(entry.version, 1);
        assertFalse(entry.deprecated);
        assertEq(entry.circuitHash, hash);
    }

    function test_GetVersionHistory() public {
        bytes32 h1 = keccak256("v1");
        bytes32 h2 = keccak256("v2");
        bytes32 h3 = keccak256("v3");

        vm.startPrank(admin);
        registry.registerVerifier(
            VerifierRegistryV2.CircuitType.STATE_TRANSFER,
            address(mockAdapter),
            address(mockAdapter),
            h1
        );
        registry.registerVerifier(
            VerifierRegistryV2.CircuitType.STATE_TRANSFER,
            address(mockAdapter2),
            address(mockAdapter2),
            h2
        );
        registry.registerVerifier(
            VerifierRegistryV2.CircuitType.STATE_TRANSFER,
            address(falseAdapter),
            address(falseAdapter),
            h3
        );
        vm.stopPrank();

        VerifierRegistryV2.VerifierEntry[] memory history = registry
            .getVersionHistory(VerifierRegistryV2.CircuitType.STATE_TRANSFER);

        assertEq(history.length, 2); // v1 and v2 in history, v3 is current
        assertEq(history[0].circuitHash, h1);
        assertEq(history[1].circuitHash, h2);
    }

    function test_GetVersionCount() public {
        vm.startPrank(admin);
        registry.registerVerifier(
            VerifierRegistryV2.CircuitType.STATE_TRANSFER,
            address(mockAdapter),
            address(mockAdapter),
            keccak256("v1")
        );
        registry.registerVerifier(
            VerifierRegistryV2.CircuitType.STATE_TRANSFER,
            address(mockAdapter2),
            address(mockAdapter2),
            keccak256("v2")
        );
        vm.stopPrank();

        assertEq(
            registry.getVersionCount(
                VerifierRegistryV2.CircuitType.STATE_TRANSFER
            ),
            2
        );
    }

    function test_AdapterToCircuitReverseLookup() public {
        _registerDefault();

        assertEq(
            uint256(registry.adapterToCircuit(address(mockAdapter))),
            uint256(VerifierRegistryV2.CircuitType.STATE_TRANSFER)
        );
    }

    function test_IsActiveReturnsFalseForUnregistered() public view {
        assertFalse(
            registry.isActive(VerifierRegistryV2.CircuitType.NULLIFIER)
        );
    }

    /*//////////////////////////////////////////////////////////////
                          FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_RegisterAndVerify(
        uint8 circuitId,
        bytes calldata proof,
        bytes calldata inputs
    ) public {
        // Bound to valid circuit types (0-19)
        circuitId = uint8(bound(uint256(circuitId), 0, 19));
        VerifierRegistryV2.CircuitType ct = VerifierRegistryV2.CircuitType(
            circuitId
        );

        vm.prank(admin);
        registry.registerVerifier(
            ct,
            address(mockAdapter),
            address(mockAdapter),
            keccak256("fuzz")
        );

        bool result = registry.verify(ct, proof, inputs);
        assertTrue(result);
    }

    function testFuzz_RegisterDoesNotDecreaseTotal(
        uint8 ct1,
        uint8 ct2
    ) public {
        ct1 = uint8(bound(uint256(ct1), 0, 19));
        ct2 = uint8(bound(uint256(ct2), 0, 19));

        vm.startPrank(admin);
        registry.registerVerifier(
            VerifierRegistryV2.CircuitType(ct1),
            address(mockAdapter),
            address(mockAdapter),
            keccak256("a")
        );
        uint256 afterFirst = registry.totalRegistered();

        registry.registerVerifier(
            VerifierRegistryV2.CircuitType(ct2),
            address(mockAdapter2),
            address(mockAdapter2),
            keccak256("b")
        );
        uint256 afterSecond = registry.totalRegistered();
        vm.stopPrank();

        assertGe(afterSecond, afterFirst);
    }

    /*//////////////////////////////////////////////////////////////
                            HELPERS
    //////////////////////////////////////////////////////////////*/

    function _registerDefault() internal {
        vm.prank(admin);
        registry.registerVerifier(
            VerifierRegistryV2.CircuitType.STATE_TRANSFER,
            address(mockAdapter),
            address(mockAdapter),
            keccak256("default")
        );
    }
}
