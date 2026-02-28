// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {CrossChainProofHubV3} from "contracts/bridge/CrossChainProofHubV3.sol";

/**
 * @title HalmosAccessControl
 * @notice Symbolic tests for role-based access control on real contracts.
 * @dev Run: halmos --contract HalmosAccessControl --solver-timeout-assertion 60000
 */
contract HalmosAccessControl is SymTest, Test {
    CrossChainProofHubV3 internal hub;

    function setUp() public {
        hub = new CrossChainProofHubV3();
    }

    /// @notice Only DEFAULT_ADMIN_ROLE can grant roles.
    function check_onlyAdminCanGrantRole(
        address nonAdmin,
        bytes32 role,
        address target
    ) public {
        vm.assume(nonAdmin != address(this));
        vm.assume(target != address(0));

        vm.prank(nonAdmin);
        try hub.grantRole(role, target) {
            assert(false); // must revert for non-admin
        } catch {
            // expected
        }
    }

    /// @notice Admin can grant and then revoke a role.
    function check_grantRevokeRoundtrip(address target) public {
        vm.assume(target != address(0) && target != address(this));

        bytes32 role = hub.RELAYER_ROLE();

        // Grant
        hub.grantRole(role, target);
        assertTrue(hub.hasRole(role, target), "Role must be granted");

        // Revoke
        hub.revokeRole(role, target);
        assertFalse(hub.hasRole(role, target), "Role must be revoked");
    }

    /// @notice A non-admin cannot self-escalate to DEFAULT_ADMIN_ROLE.
    function check_noSelfEscalation(address attacker) public {
        vm.assume(attacker != address(this));

        bytes32 adminRole = hub.DEFAULT_ADMIN_ROLE();

        vm.prank(attacker);
        try hub.grantRole(adminRole, attacker) {
            assert(false);
        } catch {
            // expected
        }

        assertFalse(
            hub.hasRole(adminRole, attacker),
            "Attacker must not have admin role"
        );
    }

    /// @notice Renouncing own role removes it permanently.
    function check_renounceRemovesRole(address account) public {
        vm.assume(account != address(0) && account != address(this));

        bytes32 role = hub.OPERATOR_ROLE();
        hub.grantRole(role, account);
        assertTrue(hub.hasRole(role, account));

        vm.prank(account);
        hub.renounceRole(role, account);
        assertFalse(
            hub.hasRole(role, account),
            "Role must be removed after renounce"
        );
    }
}
