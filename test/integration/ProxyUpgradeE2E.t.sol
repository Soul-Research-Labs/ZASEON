// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console2} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {NullifierRegistryV3} from "../../contracts/core/NullifierRegistryV3.sol";
import {NullifierRegistryV3Upgradeable} from "../../contracts/upgradeable/NullifierRegistryV3Upgradeable.sol";

/**
 * @title ProxyUpgradeE2E
 * @notice End-to-end test for UUPS proxy upgrades: deploy → use → upgrade → verify storage
 * @dev Validates that:
 *      1. Proxy deployment + initialization works correctly
 *      2. State is written and readable through the proxy
 *      3. UUPS upgrade to a new implementation preserves all storage
 *      4. New implementation functions correctly with existing state
 *      5. Only authorized upgrader role can perform upgrades
 *      6. Re-initialization is blocked after upgrade
 */
contract ProxyUpgradeE2E is Test {
    NullifierRegistryV3Upgradeable public implementation;
    NullifierRegistryV3Upgradeable public implementationV2;
    ERC1967Proxy public proxy;
    NullifierRegistryV3Upgradeable public nullifierProxy;

    address public admin = makeAddr("admin");
    address public operator = makeAddr("operator");
    address public upgrader = makeAddr("upgrader");
    address public attacker = makeAddr("attacker");

    bytes32 public constant REGISTRAR_ROLE = keccak256("REGISTRAR_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    function setUp() public {
        // Deploy implementation
        implementation = new NullifierRegistryV3Upgradeable();

        // Deploy proxy pointing to implementation
        bytes memory initData = abi.encodeCall(
            NullifierRegistryV3Upgradeable.initialize,
            (admin)
        );
        proxy = new ERC1967Proxy(address(implementation), initData);

        // Wrap proxy with the contract interface
        nullifierProxy = NullifierRegistryV3Upgradeable(address(proxy));

        // Grant roles
        vm.startPrank(admin);
        nullifierProxy.grantRole(REGISTRAR_ROLE, operator);
        nullifierProxy.grantRole(UPGRADER_ROLE, upgrader);
        vm.stopPrank();
    }

    // ─────────────────────────────────────────────────────────────
    //  Phase 1: Verify initial deployment
    // ─────────────────────────────────────────────────────────────

    function test_E2E_InitialDeployment() public view {
        // Admin has DEFAULT_ADMIN_ROLE
        assertTrue(
            nullifierProxy.hasRole(nullifierProxy.DEFAULT_ADMIN_ROLE(), admin)
        );
        // Operator role is granted
        assertTrue(nullifierProxy.hasRole(REGISTRAR_ROLE, operator));
        // Upgrader role is granted
        assertTrue(nullifierProxy.hasRole(UPGRADER_ROLE, upgrader));
    }

    function test_E2E_ReinitializationBlocked() public {
        vm.expectRevert();
        nullifierProxy.initialize(attacker);
    }

    // ─────────────────────────────────────────────────────────────
    //  Phase 2: Use the proxy, write state
    // ─────────────────────────────────────────────────────────────

    function test_E2E_WriteStateThroughProxy() public {
        bytes32 nullifier = keccak256("test-nullifier-1");
        bytes32 commitment = bytes32(uint256(1));

        vm.prank(operator);
        nullifierProxy.registerNullifier(nullifier, commitment);

        assertTrue(nullifierProxy.exists(nullifier));
    }

    // ─────────────────────────────────────────────────────────────
    //  Phase 3: Full upgrade lifecycle
    // ─────────────────────────────────────────────────────────────

    function test_E2E_FullUpgradeLifecycle() public {
        // --- Step 1: Write state through V1 proxy ---
        bytes32 nullifier1 = keccak256("pre-upgrade-nullifier");
        bytes32 commitment = bytes32(uint256(1));

        vm.prank(operator);
        nullifierProxy.registerNullifier(nullifier1, commitment);
        assertTrue(nullifierProxy.exists(nullifier1));

        // --- Step 2: Deploy V2 implementation ---
        implementationV2 = new NullifierRegistryV3Upgradeable();

        // --- Step 3: Upgrade via authorized upgrader ---
        vm.prank(upgrader);
        nullifierProxy.upgradeToAndCall(address(implementationV2), "");

        // --- Step 4: Verify state preservation ---
        // Pre-upgrade nullifier still exists
        assertTrue(
            nullifierProxy.exists(nullifier1),
            "Pre-upgrade nullifier should still be spent after upgrade"
        );

        // Roles still intact
        assertTrue(
            nullifierProxy.hasRole(nullifierProxy.DEFAULT_ADMIN_ROLE(), admin)
        );
        assertTrue(nullifierProxy.hasRole(REGISTRAR_ROLE, operator));
        assertTrue(nullifierProxy.hasRole(UPGRADER_ROLE, upgrader));

        // --- Step 5: Write new state through upgraded proxy ---
        bytes32 nullifier2 = keccak256("post-upgrade-nullifier");

        vm.prank(operator);
        nullifierProxy.registerNullifier(nullifier2, commitment);
        assertTrue(
            nullifierProxy.exists(nullifier2),
            "Post-upgrade nullifier registration should work"
        );

        // --- Step 6: Both old and new state coexist ---
        assertTrue(nullifierProxy.exists(nullifier1));
        assertTrue(nullifierProxy.exists(nullifier2));
    }

    // ─────────────────────────────────────────────────────────────
    //  Phase 4: Access control on upgrades
    // ─────────────────────────────────────────────────────────────

    function test_E2E_UnauthorizedUpgradeReverts() public {
        implementationV2 = new NullifierRegistryV3Upgradeable();

        // Attacker cannot upgrade
        vm.prank(attacker);
        vm.expectRevert();
        nullifierProxy.upgradeToAndCall(address(implementationV2), "");

        // Operator cannot upgrade (only UPGRADER_ROLE can)
        vm.prank(operator);
        vm.expectRevert();
        nullifierProxy.upgradeToAndCall(address(implementationV2), "");
    }

    function test_E2E_ReinitializationBlockedAfterUpgrade() public {
        implementationV2 = new NullifierRegistryV3Upgradeable();

        vm.prank(upgrader);
        nullifierProxy.upgradeToAndCall(address(implementationV2), "");

        // Re-initialization must be blocked
        vm.expectRevert();
        nullifierProxy.initialize(attacker);
    }

    // ─────────────────────────────────────────────────────────────
    //  Phase 5: Multiple sequential upgrades
    // ─────────────────────────────────────────────────────────────

    function test_E2E_MultipleSequentialUpgrades() public {
        bytes32 nullifier1 = keccak256("v1-nullifier");
        bytes32 commitment = bytes32(uint256(1));

        // Write V1 state
        vm.prank(operator);
        nullifierProxy.registerNullifier(nullifier1, commitment);

        // Upgrade to V2
        NullifierRegistryV3Upgradeable v2 = new NullifierRegistryV3Upgradeable();
        vm.prank(upgrader);
        nullifierProxy.upgradeToAndCall(address(v2), "");

        // Write V2 state
        bytes32 nullifier2 = keccak256("v2-nullifier");
        vm.prank(operator);
        nullifierProxy.registerNullifier(nullifier2, commitment);

        // Upgrade to V3
        NullifierRegistryV3Upgradeable v3 = new NullifierRegistryV3Upgradeable();
        vm.prank(upgrader);
        nullifierProxy.upgradeToAndCall(address(v3), "");

        // Write V3 state
        bytes32 nullifier3 = keccak256("v3-nullifier");
        vm.prank(operator);
        nullifierProxy.registerNullifier(nullifier3, commitment);

        // All state from V1, V2, V3 is preserved
        assertTrue(nullifierProxy.exists(nullifier1), "V1 state lost");
        assertTrue(nullifierProxy.exists(nullifier2), "V2 state lost");
        assertTrue(nullifierProxy.exists(nullifier3), "V3 state lost");
    }
}
