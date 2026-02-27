// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/experimental/ExperimentalFeatureGated.sol";
import "../../contracts/security/ExperimentalFeatureRegistry.sol";

/// @dev Concrete child of the abstract ExperimentalFeatureGated for testing
contract MockGatedContract is ExperimentalFeatureGated {
    uint256 public counter;

    function initialize(address registry, bytes32 _featureId) external {
        _setFeatureRegistry(registry, _featureId);
    }

    function guardedIncrement() external onlyIfFeatureEnabled {
        counter++;
    }
}

contract ExperimentalFeatureGatedTest is Test {
    ExperimentalFeatureRegistry registry;
    MockGatedContract gated;

    address admin = makeAddr("admin");
    bytes32 featureId = keccak256("TEST_FEATURE");

    function setUp() public {
        vm.startPrank(admin);
        registry = new ExperimentalFeatureRegistry(admin);
        gated = new MockGatedContract();
        gated.initialize(address(registry), featureId);
        vm.stopPrank();
    }

    // ── State after initialization ──

    function test_registrySet() public view {
        assertEq(address(gated.featureRegistry()), address(registry));
    }

    function test_featureIdSet() public view {
        assertEq(gated.featureId(), featureId);
    }

    // ── Modifier blocks when feature not enabled ──

    function test_guardedFunction_reverts_whenNotEnabled() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                ExperimentalFeatureGated.FeatureNotEnabled.selector,
                featureId
            )
        );
        gated.guardedIncrement();
    }

    // ── Modifier allows when feature is enabled ──

    function test_guardedFunction_succeeds_whenEnabled() public {
        // Register and enable the feature
        vm.startPrank(admin);
        registry.registerFeature(featureId, "Test Feature", "test");
        registry.enableFeature(featureId);
        vm.stopPrank();

        gated.guardedIncrement();
        assertEq(gated.counter(), 1);
    }

    // ── Multiple guarded calls accumulate ──

    function test_guardedFunction_multipleCalls() public {
        vm.startPrank(admin);
        registry.registerFeature(featureId, "Test Feature", "test");
        registry.enableFeature(featureId);
        vm.stopPrank();

        gated.guardedIncrement();
        gated.guardedIncrement();
        gated.guardedIncrement();
        assertEq(gated.counter(), 3);
    }

    // ── Disabling feature blocks subsequent calls ──

    function test_guardedFunction_reverts_afterDisable() public {
        vm.startPrank(admin);
        registry.registerFeature(featureId, "Test Feature", "test");
        registry.enableFeature(featureId);
        vm.stopPrank();

        gated.guardedIncrement();
        assertEq(gated.counter(), 1);

        vm.prank(admin);
        registry.disableFeature(featureId);

        vm.expectRevert(
            abi.encodeWithSelector(
                ExperimentalFeatureGated.FeatureNotEnabled.selector,
                featureId
            )
        );
        gated.guardedIncrement();
    }

    // ── _setFeatureRegistry emits event ──

    function test_setFeatureRegistry_emitsEvent() public {
        MockGatedContract fresh = new MockGatedContract();
        vm.expectEmit(true, true, false, false);
        emit ExperimentalFeatureGated.FeatureRegistrySet(
            address(registry),
            featureId
        );
        fresh.initialize(address(registry), featureId);
    }
}
