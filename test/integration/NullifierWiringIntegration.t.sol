// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {ZKBoundStateLocks} from "../../contracts/primitives/ZKBoundStateLocks.sol";
import {NullifierRegistryV3} from "../../contracts/core/NullifierRegistryV3.sol";
import {IProofVerifier} from "../../contracts/interfaces/IProofVerifier.sol";

/// @notice Mock verifier that accepts all proofs
contract MockVerifierForWiring is IProofVerifier {
    function verify(
        bytes calldata,
        uint256[] calldata
    ) external pure returns (bool) {
        return true;
    }

    function verifyProof(
        bytes calldata,
        bytes calldata
    ) external pure returns (bool) {
        return true;
    }

    function verifySingle(
        bytes calldata,
        uint256
    ) external pure returns (bool) {
        return true;
    }

    function getPublicInputCount() external pure returns (uint256) {
        return 1;
    }

    function isReady() external pure returns (bool) {
        return true;
    }
}

/// @title NullifierWiringIntegration
/// @notice Tests that ZKBoundStateLocks properly propagates nullifiers to NullifierRegistryV3
contract NullifierWiringIntegrationTest is Test {
    ZKBoundStateLocks public zkSlocks;
    NullifierRegistryV3 public nullifierRegistry;
    MockVerifierForWiring public verifier;

    address admin = address(this);
    bytes32 ethDomain; // Ethereum Mainnet pre-registered domain

    function setUp() public {
        // Deploy verifier
        verifier = new MockVerifierForWiring();

        // Deploy NullifierRegistryV3
        nullifierRegistry = new NullifierRegistryV3();

        // Deploy ZKBoundStateLocks
        zkSlocks = new ZKBoundStateLocks(address(verifier));

        // Compute the Ethereum Mainnet domain separator (chainId=1, appId=0, epoch=0)
        // This is pre-registered in ZKBoundStateLocks constructor via _registerDefaultDomains()
        ethDomain = zkSlocks.generateDomainSeparator(1, 0, 0);

        // Wire: set nullifier registry on ZKBoundStateLocks
        zkSlocks.setNullifierRegistry(address(nullifierRegistry));

        // Wire: grant REGISTRAR_ROLE to ZKBoundStateLocks on NullifierRegistryV3
        nullifierRegistry.grantRole(
            nullifierRegistry.REGISTRAR_ROLE(),
            address(zkSlocks)
        );
    }

    /// @notice Test that nullifier registry is properly set
    function test_NullifierRegistryIsSet() public view {
        assertEq(zkSlocks.nullifierRegistry(), address(nullifierRegistry));
    }

    /// @notice Test that ZKBoundStateLocks has REGISTRAR_ROLE on registry
    function test_ZKSlocksHasRegistrarRole() public view {
        assertTrue(
            nullifierRegistry.hasRole(
                nullifierRegistry.REGISTRAR_ROLE(),
                address(zkSlocks)
            )
        );
    }

    /// @notice Test that creating a lock works
    function test_CreateLock() public {
        bytes32 oldState = keccak256("old_state");
        bytes32 predicate = keccak256("transition");
        bytes32 policy = bytes32(0);

        bytes32 lockId = zkSlocks.createLock(
            oldState,
            predicate,
            policy,
            ethDomain,
            0
        );
        assertTrue(lockId != bytes32(0));
    }

    /// @notice Test nullifier propagation on recovery unlock
    function test_NullifierPropagatedOnRecovery() public {
        // Create a lock using pre-registered Ethereum Mainnet domain
        bytes32 oldState = keccak256("state_for_recovery");
        bytes32 predicate = keccak256("transition");

        bytes32 lockId = zkSlocks.createLock(
            oldState,
            predicate,
            bytes32(0),
            ethDomain,
            0
        );

        // Compute the expected recovery nullifier
        bytes32 recoveryNullifier = keccak256(
            abi.encode(lockId, "RECOVERY", block.chainid)
        );

        // Before recovery: nullifier should NOT exist in registry
        assertFalse(nullifierRegistry.exists(recoveryNullifier));

        // Recover the lock
        zkSlocks.recoverLock(lockId, admin);

        // After recovery: nullifier should be marked locally
        assertTrue(zkSlocks.nullifierUsed(recoveryNullifier));

        // After recovery: nullifier should also be propagated to NullifierRegistryV3
        assertTrue(nullifierRegistry.exists(recoveryNullifier));
    }

    /// @notice Test that without registry set, propagation silently skips
    function test_NoPropagationWithoutRegistry() public {
        // Deploy a new ZKBoundStateLocks without registry
        ZKBoundStateLocks fresh = new ZKBoundStateLocks(address(verifier));
        // nullifierRegistry defaults to address(0)
        assertEq(fresh.nullifierRegistry(), address(0));

        // Create & recover lock using pre-registered Ethereum domain — should not revert
        bytes32 domain = fresh.generateDomainSeparator(1, 0, 0);
        bytes32 lockId = fresh.createLock(
            keccak256("s"),
            keccak256("t"),
            bytes32(0),
            domain,
            0
        );
        fresh.recoverLock(lockId, admin);

        // Nullifier marked locally
        bytes32 nullifier = keccak256(
            abi.encode(lockId, "RECOVERY", block.chainid)
        );
        assertTrue(fresh.nullifierUsed(nullifier));

        // But NOT in the external registry (since none is set)
        assertFalse(nullifierRegistry.exists(nullifier));
    }
}
