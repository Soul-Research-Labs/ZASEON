// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {PrivacyRouter} from "../../contracts/core/PrivacyRouter.sol";

/// @title Mock implementing NullifierRegistryV3 interface (exists)
contract MockNullifierRegistryV3Like {
    mapping(bytes32 => bool) public nullifiers;

    function exists(bytes32 nullifier) external view returns (bool) {
        return nullifiers[nullifier];
    }

    function setSpent(bytes32 nullifier) external {
        nullifiers[nullifier] = true;
    }
}

/// @title Mock implementing UnifiedNullifierManager interface (isNullifierSpent)
contract MockUnifiedNullifierManager {
    mapping(bytes32 => bool) public nullifiers;

    function isNullifierSpent(bytes32 nullifier) external view returns (bool) {
        return nullifiers[nullifier];
    }

    function setSpent(bytes32 nullifier) external {
        nullifiers[nullifier] = true;
    }
}

/// @title DummyContract — has neither interface
contract DummyContract {

}

/// @title PrivacyRouterCompatibilityTest
/// @notice Tests the dual-fallback nullifier check in PrivacyRouter.isNullifierSpent()
contract PrivacyRouterCompatibilityTest is Test {
    PrivacyRouter public routerWithV3;
    PrivacyRouter public routerWithUnified;
    PrivacyRouter public routerWithDummy;

    MockNullifierRegistryV3Like public v3Registry;
    MockUnifiedNullifierManager public unifiedMgr;
    DummyContract public dummy;

    // Placeholders for required constructor args
    address constant ADMIN = address(0xA);
    address constant SHIELDED = address(0xB);
    address constant CROSSCHAIN = address(0xC);
    address constant STEALTH = address(0xD);
    address constant COMPLIANCE = address(0xE);
    address constant TRANSLATOR = address(0xF);

    function setUp() public {
        v3Registry = new MockNullifierRegistryV3Like();
        unifiedMgr = new MockUnifiedNullifierManager();
        dummy = new DummyContract();

        // Router backed by NullifierRegistryV3 (only has exists())
        routerWithV3 = new PrivacyRouter(
            ADMIN,
            SHIELDED,
            CROSSCHAIN,
            STEALTH,
            address(v3Registry),
            address(COMPLIANCE),
            TRANSLATOR
        );

        // Router backed by UnifiedNullifierManager (has isNullifierSpent())
        routerWithUnified = new PrivacyRouter(
            ADMIN,
            SHIELDED,
            CROSSCHAIN,
            STEALTH,
            address(unifiedMgr),
            address(COMPLIANCE),
            TRANSLATOR
        );

        // Router backed by DummyContract (has neither)
        routerWithDummy = new PrivacyRouter(
            ADMIN,
            SHIELDED,
            CROSSCHAIN,
            STEALTH,
            address(dummy),
            address(COMPLIANCE),
            TRANSLATOR
        );
    }

    /// @notice isNullifierSpent works when backed by NullifierRegistryV3 (exists fallback)
    function test_NullifierSpentViaV3Registry() public {
        bytes32 nf = keccak256("test-nullifier-v3");

        assertFalse(routerWithV3.isNullifierSpent(nf));

        v3Registry.setSpent(nf);
        assertTrue(routerWithV3.isNullifierSpent(nf));
    }

    /// @notice isNullifierSpent works when backed by UnifiedNullifierManager
    function test_NullifierSpentViaUnifiedManager() public {
        bytes32 nf = keccak256("test-nullifier-unified");

        assertFalse(routerWithUnified.isNullifierSpent(nf));

        unifiedMgr.setSpent(nf);
        assertTrue(routerWithUnified.isNullifierSpent(nf));
    }

    /// @notice isNullifierSpent gracefully returns false when backend has neither interface
    function test_NullifierSpentFallsBackGracefully() public view {
        bytes32 nf = keccak256("test-nullifier-dummy");
        assertFalse(routerWithDummy.isNullifierSpent(nf));
    }

    /// @notice Unspent nullifiers return false for both backends
    function test_UnspentNullifierReturnsFalse() public view {
        bytes32 nf = keccak256("never-spent");
        assertFalse(routerWithV3.isNullifierSpent(nf));
        assertFalse(routerWithUnified.isNullifierSpent(nf));
    }
}
