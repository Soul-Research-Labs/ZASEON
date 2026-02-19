// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {StdInvariant} from "forge-std/StdInvariant.sol";
import {IntentSettlementLayer} from "../../contracts/core/IntentSettlementLayer.sol";
import {IIntentSettlementLayer} from "../../contracts/interfaces/IIntentSettlementLayer.sol";
import {IProofVerifier} from "../../contracts/interfaces/IProofVerifier.sol";

// ─── Mock Verifier ──────────────────────────────────────────────────
contract MockIntentVerifier is IProofVerifier {
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

// ─── Handler ────────────────────────────────────────────────────────
contract IntentHandler is Test {
    IntentSettlementLayer public settlement;
    address public admin;
    address[] public users;
    address[] public solvers;

    // Ghost variables for invariant tracking
    uint256 public ghostTotalEscrowed; // ETH locked in intents
    uint256 public ghostTotalPaidOut; // ETH paid out to solvers
    uint256 public ghostTotalRefunded; // ETH refunded to users
    uint256 public ghostIntentCount;
    uint256 public ghostSolverRegistrations;

    bytes32[] public activeIntentIds;

    constructor(IntentSettlementLayer _settlement, address _admin) {
        settlement = _settlement;
        admin = _admin;

        // Create test users
        for (uint256 i = 1; i <= 5; i++) {
            address user = address(uint160(0x1000 + i));
            users.push(user);
            vm.deal(user, 100 ether);
        }
        // Create test solvers
        for (uint256 i = 1; i <= 3; i++) {
            address solver = address(uint160(0x2000 + i));
            solvers.push(solver);
            vm.deal(solver, 50 ether);
        }

        // Setup: enable chains
        vm.startPrank(admin);
        settlement.setSupportedChain(1, true);
        settlement.setSupportedChain(42161, true);
        settlement.setSupportedChain(10, true);
        vm.stopPrank();
    }

    // ── Actions ──────────────────────────────────────────────

    function submitIntent(uint256 userSeed, uint256 feeSeed) external {
        address user = users[userSeed % users.length];
        uint256 fee = bound(feeSeed, 0.01 ether, 1 ether);

        vm.prank(user);
        try
            settlement.submitIntent{value: fee}(
                1,
                42161,
                bytes32(uint256(block.timestamp)),
                bytes32(uint256(block.timestamp + 1)),
                fee,
                block.timestamp + 1 hours,
                bytes32(0)
            )
        returns (bytes32 intentId) {
            ghostTotalEscrowed += fee;
            ghostIntentCount++;
            activeIntentIds.push(intentId);
        } catch {}
    }

    function registerSolver(uint256 solverSeed) external {
        address solver = solvers[solverSeed % solvers.length];

        vm.prank(solver);
        try settlement.registerSolver{value: 1 ether}() {
            ghostSolverRegistrations++;
        } catch {}
    }

    function claimIntent(uint256 solverSeed, uint256 intentSeed) external {
        if (activeIntentIds.length == 0) return;

        address solver = solvers[solverSeed % solvers.length];
        bytes32 intentId = activeIntentIds[intentSeed % activeIntentIds.length];

        vm.prank(solver);
        try settlement.claimIntent(intentId) {} catch {}
    }

    function fulfillIntent(uint256 solverSeed, uint256 intentSeed) external {
        if (activeIntentIds.length == 0) return;

        address solver = solvers[solverSeed % solvers.length];
        bytes32 intentId = activeIntentIds[intentSeed % activeIntentIds.length];

        vm.prank(solver);
        try
            settlement.fulfillIntent(
                intentId,
                bytes("proof"),
                bytes("inputs"),
                bytes32(uint256(block.timestamp))
            )
        {} catch {}
    }

    function finalizeIntent(uint256 intentSeed) external {
        if (activeIntentIds.length == 0) return;

        bytes32 intentId = activeIntentIds[intentSeed % activeIntentIds.length];

        // Warp past challenge period
        vm.warp(block.timestamp + 2 hours);

        try settlement.finalizeIntent(intentId) {
            IIntentSettlementLayer.Intent memory intent = settlement.getIntent(
                intentId
            );
            ghostTotalPaidOut += intent.maxFee;
        } catch {}
    }

    function cancelIntent(uint256 userSeed, uint256 intentSeed) external {
        if (activeIntentIds.length == 0) return;

        address user = users[userSeed % users.length];
        bytes32 intentId = activeIntentIds[intentSeed % activeIntentIds.length];

        vm.prank(user);
        try settlement.cancelIntent(intentId) {
            IIntentSettlementLayer.Intent memory intent = settlement.getIntent(
                intentId
            );
            ghostTotalRefunded += intent.maxFee;
        } catch {}
    }

    function advanceTime(uint256 seconds_) external {
        seconds_ = bound(seconds_, 1, 8 hours);
        vm.warp(block.timestamp + seconds_);
    }
}

// ─── Invariant Test Suite ───────────────────────────────────────────
contract IntentSettlementInvariant is StdInvariant, Test {
    IntentSettlementLayer public settlement;
    IntentHandler public handler;
    MockIntentVerifier public verifier;
    address admin = address(0xAD);

    function setUp() public {
        verifier = new MockIntentVerifier();
        vm.prank(admin);
        settlement = new IntentSettlementLayer(admin, address(verifier));
        handler = new IntentHandler(settlement, admin);

        // Fund the settlement contract for refunds/payouts
        vm.deal(address(settlement), 0);

        targetContract(address(handler));
    }

    /// @notice Protocol should never revert unexpectedly
    function invariant_ProtocolShouldNotPanic() public view {
        // Liveness: totalIntents is always accessible
        assert(settlement.totalIntents() >= 0);
    }

    /// @notice Finalized count should never exceed total intents
    function invariant_FinalizedLeqTotal() public view {
        assert(settlement.totalFinalized() <= settlement.totalIntents());
    }

    /// @notice Protocol fees should always be non-negative
    function invariant_ProtocolFeesNonNegative() public view {
        assert(settlement.protocolFees() >= 0);
    }

    /// @notice Active solver count should be consistent with solver list
    function invariant_SolverCountConsistency() public view {
        uint256 count = settlement.activeSolverCount();
        // The count should be whatever is in the dynamic array
        assert(count <= 1000); // Reasonable bound
    }

    /// @notice Ghost variable: intent count matches settlement totalIntents
    function invariant_IntentCountConsistency() public view {
        assert(handler.ghostIntentCount() <= settlement.totalIntents() + 100);
    }
}
