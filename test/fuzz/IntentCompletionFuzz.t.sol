// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/core/IntentCompletionLayer.sol";
import "../../contracts/interfaces/IIntentCompletionLayer.sol";
import "../../contracts/interfaces/IProofVerifier.sol";

// ─── Mock Verifier (always passes) ─────────────────────────────────
contract MockFuzzVerifier is IProofVerifier {
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

/**
 * @title IntentCompletionFuzz
 * @notice Fuzz tests for IntentCompletionLayer covering submit, register, lifecycle, and edge cases
 * @dev Run with: forge test --match-contract IntentCompletionFuzz --fuzz-runs 10000
 */
contract IntentCompletionFuzz is Test {
    IntentCompletionLayer public completion;
    MockFuzzVerifier public verifier;

    address public admin = address(0xAD);
    address public user1 = address(0xF1);
    address public user2 = address(0xF2);
    address public solver1 = address(0x51);
    address public solver2 = address(0x52);

    uint256 internal constant SOURCE_CHAIN = 1;
    uint256 internal constant DEST_CHAIN = 42161;

    function setUp() public {
        verifier = new MockFuzzVerifier();

        vm.prank(admin);
        completion = new IntentCompletionLayer(admin, address(verifier));

        // Enable chains
        vm.startPrank(admin);
        completion.setSupportedChain(SOURCE_CHAIN, true);
        completion.setSupportedChain(DEST_CHAIN, true);
        completion.setSupportedChain(10, true);
        completion.setSupportedChain(8453, true);
        vm.stopPrank();

        // Fund actors
        vm.deal(user1, 1000 ether);
        vm.deal(user2, 1000 ether);
        vm.deal(solver1, 100 ether);
        vm.deal(solver2, 100 ether);
    }

    /*//////////////////////////////////////////////////////////////
                    SECTION 1 — submitIntent FUZZ
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz sourceChainId and destChainId — only supported, distinct chains should succeed
    function testFuzz_submitIntent_chainIds(
        uint256 sourceChainId,
        uint256 destChainId
    ) public {
        uint256 fee = 0.1 ether;
        uint256 deadline = block.timestamp + 1 hours;

        vm.prank(user1);
        if (
            sourceChainId == 0 ||
            destChainId == 0 ||
            sourceChainId == destChainId ||
            !completion.supportedChains(sourceChainId) ||
            !completion.supportedChains(destChainId)
        ) {
            vm.expectRevert();
            completion.submitIntent{value: fee}(
                sourceChainId,
                destChainId,
                bytes32(uint256(1)),
                bytes32(uint256(2)),
                fee,
                deadline,
                bytes32(0)
            );
        } else {
            bytes32 intentId = completion.submitIntent{value: fee}(
                sourceChainId,
                destChainId,
                bytes32(uint256(1)),
                bytes32(uint256(2)),
                fee,
                deadline,
                bytes32(0)
            );
            IIntentCompletionLayer.Intent memory intent = completion.getIntent(
                intentId
            );
            assertEq(intent.sourceChainId, sourceChainId);
            assertEq(intent.destChainId, destChainId);
            assertEq(
                uint8(intent.status),
                uint8(IIntentCompletionLayer.IntentStatus.PENDING)
            );
        }
    }

    /// @notice Fuzz maxFee — must be > 0 and msg.value >= maxFee
    function testFuzz_submitIntent_maxFee(uint256 maxFee) public {
        maxFee = bound(maxFee, 1, 10 ether);
        uint256 deadline = block.timestamp + 1 hours;

        vm.prank(user1);
        bytes32 intentId = completion.submitIntent{value: maxFee}(
            SOURCE_CHAIN,
            DEST_CHAIN,
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            maxFee,
            deadline,
            bytes32(0)
        );

        IIntentCompletionLayer.Intent memory intent = completion.getIntent(
            intentId
        );
        assertEq(intent.maxFee, maxFee);
        assertEq(intent.user, user1);
    }

    /// @notice Fuzz deadline — must be within [MIN_DEADLINE_OFFSET, MAX_DEADLINE_OFFSET]
    function testFuzz_submitIntent_deadline(uint256 deadlineOffset) public {
        uint256 fee = 0.1 ether;

        uint256 minOffset = completion.MIN_DEADLINE_OFFSET();
        uint256 maxOffset = completion.MAX_DEADLINE_OFFSET();

        // Bound to avoid arithmetic overflow on block.timestamp + deadlineOffset
        deadlineOffset = bound(deadlineOffset, 0, maxOffset + 1 hours);
        uint256 deadline = block.timestamp + deadlineOffset;

        vm.prank(user1);
        if (deadlineOffset < minOffset || deadlineOffset > maxOffset) {
            vm.expectRevert();
            completion.submitIntent{value: fee}(
                SOURCE_CHAIN,
                DEST_CHAIN,
                bytes32(uint256(1)),
                bytes32(uint256(2)),
                fee,
                deadline,
                bytes32(0)
            );
        } else {
            bytes32 intentId = completion.submitIntent{value: fee}(
                SOURCE_CHAIN,
                DEST_CHAIN,
                bytes32(uint256(1)),
                bytes32(uint256(2)),
                fee,
                deadline,
                bytes32(0)
            );
            IIntentCompletionLayer.Intent memory intent = completion.getIntent(
                intentId
            );
            assertEq(intent.deadline, deadline);
        }
    }

    /// @notice Fuzz insufficient msg.value — should revert when value < maxFee
    function testFuzz_submitIntent_insufficientFee(
        uint256 maxFee,
        uint256 msgValue
    ) public {
        maxFee = bound(maxFee, 0.01 ether, 5 ether);
        msgValue = bound(msgValue, 0, maxFee - 1);
        uint256 deadline = block.timestamp + 1 hours;

        vm.prank(user1);
        vm.expectRevert();
        completion.submitIntent{value: msgValue}(
            SOURCE_CHAIN,
            DEST_CHAIN,
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            maxFee,
            deadline,
            bytes32(0)
        );
    }

    /// @notice Fuzz excess ETH — surplus should be refunded
    function testFuzz_submitIntent_refundExcess(
        uint128 maxFee,
        uint128 extra
    ) public {
        uint256 fee = bound(uint256(maxFee), 0.01 ether, 5 ether);
        uint256 surplus = bound(uint256(extra), 1, 5 ether);
        uint256 totalSent = fee + surplus;
        uint256 deadline = block.timestamp + 1 hours;

        uint256 balBefore = user1.balance;
        vm.prank(user1);
        completion.submitIntent{value: totalSent}(
            SOURCE_CHAIN,
            DEST_CHAIN,
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            fee,
            deadline,
            bytes32(0)
        );
        uint256 balAfter = user1.balance;

        // User should have been refunded the surplus; only `fee` was kept
        assertEq(balBefore - balAfter, fee, "Only maxFee should be escrowed");
    }

    /// @notice Fuzz zero sourceCommitment or desiredStateHash — should revert
    function testFuzz_submitIntent_zeroCommitments(
        bool zeroSource,
        bool zeroDest
    ) public {
        vm.assume(zeroSource || zeroDest);
        uint256 fee = 0.1 ether;
        uint256 deadline = block.timestamp + 1 hours;

        bytes32 src = zeroSource ? bytes32(0) : bytes32(uint256(1));
        bytes32 dst = zeroDest ? bytes32(0) : bytes32(uint256(2));

        vm.prank(user1);
        vm.expectRevert();
        completion.submitIntent{value: fee}(
            SOURCE_CHAIN,
            DEST_CHAIN,
            src,
            dst,
            fee,
            deadline,
            bytes32(0)
        );
    }

    /*//////////////////////////////////////////////////////////////
                  SECTION 2 — registerSolver FUZZ
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz stake amounts — must meet MIN_SOLVER_STAKE
    function testFuzz_registerSolver_stake(uint256 stake) public {
        stake = bound(stake, 0, 50 ether);
        uint256 minStake = completion.MIN_SOLVER_STAKE();

        address solver = address(uint160(0x3000 + stake));
        vm.deal(solver, stake + 1 ether);

        vm.prank(solver);
        if (stake < minStake) {
            vm.expectRevert();
            completion.registerSolver{value: stake}();
        } else {
            completion.registerSolver{value: stake}();
            IIntentCompletionLayer.Solver memory s = completion.getSolver(
                solver
            );
            assertEq(s.stake, stake);
            assertTrue(s.isActive);
        }
    }

    /// @notice Fuzz duplicate registration — second call should revert
    function testFuzz_registerSolver_duplicate(uint256 stake) public {
        stake = bound(stake, 1 ether, 10 ether);

        address solver = address(uint160(0x4000));
        vm.deal(solver, stake * 3);

        vm.prank(solver);
        completion.registerSolver{value: stake}();

        vm.prank(solver);
        vm.expectRevert();
        completion.registerSolver{value: stake}();
    }

    /*//////////////////////////////////////////////////////////////
            SECTION 3 — FULL LIFECYCLE FUZZ
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz full lifecycle: submit → claim → fulfill → finalize
    function testFuzz_fullLifecycle(
        uint128 feeRaw,
        uint128 stakeRaw,
        uint24 deadlineOffsetRaw
    ) public {
        uint256 fee = bound(uint256(feeRaw), 0.01 ether, 5 ether);
        uint256 stake = bound(uint256(stakeRaw), 1 ether, 10 ether);
        uint256 deadlineOffset = bound(
            uint256(deadlineOffsetRaw),
            10 minutes,
            7 days
        );
        uint256 deadline = block.timestamp + deadlineOffset;

        // Register solver
        vm.prank(solver1);
        completion.registerSolver{value: stake}();

        // Submit intent
        vm.prank(user1);
        bytes32 intentId = completion.submitIntent{value: fee}(
            SOURCE_CHAIN,
            DEST_CHAIN,
            bytes32(uint256(block.timestamp)),
            bytes32(uint256(block.timestamp + 1)),
            fee,
            deadline,
            bytes32(0)
        );

        // Claim intent
        vm.prank(solver1);
        completion.claimIntent(intentId);

        IIntentCompletionLayer.Intent memory intent = completion.getIntent(
            intentId
        );
        assertEq(
            uint8(intent.status),
            uint8(IIntentCompletionLayer.IntentStatus.CLAIMED)
        );
        assertEq(intent.solver, solver1);

        // Fulfill intent
        vm.prank(solver1);
        completion.fulfillIntent(
            intentId,
            bytes("proof"),
            bytes("inputs"),
            bytes32(uint256(block.timestamp))
        );

        intent = completion.getIntent(intentId);
        assertEq(
            uint8(intent.status),
            uint8(IIntentCompletionLayer.IntentStatus.FULFILLED)
        );

        // Warp past challenge period
        vm.warp(block.timestamp + completion.CHALLENGE_PERIOD() + 1);

        // Finalize intent
        uint256 solverBalBefore = solver1.balance;
        completion.finalizeIntent(intentId);

        intent = completion.getIntent(intentId);
        assertEq(
            uint8(intent.status),
            uint8(IIntentCompletionLayer.IntentStatus.FINALIZED)
        );

        // Solver should receive payout minus protocol fee
        uint256 protocolCut = (fee * completion.PROTOCOL_FEE_BPS()) / 10_000;
        uint256 expectedPayout = fee - protocolCut;
        assertEq(
            solver1.balance - solverBalBefore,
            expectedPayout,
            "Solver payout mismatch"
        );
    }

    /// @notice Fuzz submit → cancel lifecycle
    function testFuzz_submitAndCancel(uint128 feeRaw) public {
        uint256 fee = bound(uint256(feeRaw), 0.01 ether, 5 ether);
        uint256 deadline = block.timestamp + 1 hours;

        uint256 balBefore = user1.balance;
        vm.prank(user1);
        bytes32 intentId = completion.submitIntent{value: fee}(
            SOURCE_CHAIN,
            DEST_CHAIN,
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            fee,
            deadline,
            bytes32(0)
        );

        vm.prank(user1);
        completion.cancelIntent(intentId);

        IIntentCompletionLayer.Intent memory intent = completion.getIntent(
            intentId
        );
        assertEq(
            uint8(intent.status),
            uint8(IIntentCompletionLayer.IntentStatus.CANCELLED)
        );

        // Full refund
        assertEq(user1.balance, balBefore, "User should be fully refunded");
    }

    /*//////////////////////////////////////////////////////////////
                SECTION 4 — EDGE CASES & NEGATIVE FUZZ
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz expired intent — submit then warp past deadline, expireIntent should work
    function testFuzz_expireIntent(
        uint128 feeRaw,
        uint24 deadlineOffsetRaw
    ) public {
        uint256 fee = bound(uint256(feeRaw), 0.01 ether, 2 ether);
        uint256 deadlineOffset = bound(
            uint256(deadlineOffsetRaw),
            10 minutes,
            7 days
        );
        uint256 deadline = block.timestamp + deadlineOffset;

        vm.prank(user1);
        bytes32 intentId = completion.submitIntent{value: fee}(
            SOURCE_CHAIN,
            DEST_CHAIN,
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            fee,
            deadline,
            bytes32(0)
        );

        // Warp past deadline
        vm.warp(deadline + 1);

        uint256 balBefore = user1.balance;
        completion.expireIntent(intentId);

        IIntentCompletionLayer.Intent memory intent = completion.getIntent(
            intentId
        );
        assertEq(
            uint8(intent.status),
            uint8(IIntentCompletionLayer.IntentStatus.EXPIRED)
        );
        assertEq(
            user1.balance - balBefore,
            fee,
            "User should be refunded after expiry"
        );
    }

    /// @notice Fuzz: non-owner cannot cancel
    function testFuzz_cancelIntent_notOwner(address impersonator) public {
        vm.assume(impersonator != user1 && impersonator != address(0));
        uint256 fee = 0.1 ether;
        uint256 deadline = block.timestamp + 1 hours;

        vm.prank(user1);
        bytes32 intentId = completion.submitIntent{value: fee}(
            SOURCE_CHAIN,
            DEST_CHAIN,
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            fee,
            deadline,
            bytes32(0)
        );

        vm.prank(impersonator);
        vm.expectRevert();
        completion.cancelIntent(intentId);
    }

    /// @notice Fuzz: cannot claim after deadline
    function testFuzz_claimAfterDeadline(uint24 deadlineOffsetRaw) public {
        uint256 deadlineOffset = bound(
            uint256(deadlineOffsetRaw),
            10 minutes,
            7 days
        );
        uint256 deadline = block.timestamp + deadlineOffset;
        uint256 fee = 0.1 ether;

        // Register solver
        vm.prank(solver1);
        completion.registerSolver{value: 1 ether}();

        // Submit intent
        vm.prank(user1);
        bytes32 intentId = completion.submitIntent{value: fee}(
            SOURCE_CHAIN,
            DEST_CHAIN,
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            fee,
            deadline,
            bytes32(0)
        );

        // Warp past deadline
        vm.warp(deadline + 1);

        vm.prank(solver1);
        vm.expectRevert();
        completion.claimIntent(intentId);
    }

    /// @notice Fuzz: only assigned solver can fulfill
    function testFuzz_fulfillIntent_notAssignedSolver(
        address wrongSolver
    ) public {
        vm.assume(wrongSolver != solver1 && wrongSolver != address(0));

        uint256 fee = 0.1 ether;
        uint256 deadline = block.timestamp + 1 hours;

        // Register solvers
        vm.prank(solver1);
        completion.registerSolver{value: 1 ether}();

        vm.deal(wrongSolver, 10 ether);
        vm.prank(wrongSolver);
        try completion.registerSolver{value: 1 ether}() {} catch {}

        // Submit and claim
        vm.prank(user1);
        bytes32 intentId = completion.submitIntent{value: fee}(
            SOURCE_CHAIN,
            DEST_CHAIN,
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            fee,
            deadline,
            bytes32(0)
        );

        vm.prank(solver1);
        completion.claimIntent(intentId);

        // Wrong solver tries to fulfill
        vm.prank(wrongSolver);
        vm.expectRevert();
        completion.fulfillIntent(
            intentId,
            bytes("proof"),
            bytes("inputs"),
            bytes32(uint256(block.timestamp))
        );
    }

    /// @notice Fuzz: cannot finalize before challenge period elapses
    function testFuzz_finalizeBeforeChallengePeriod(uint256 warpTime) public {
        warpTime = bound(warpTime, 0, completion.CHALLENGE_PERIOD() - 1);
        uint256 fee = 0.1 ether;
        uint256 deadline = block.timestamp + 1 hours;

        // Setup
        vm.prank(solver1);
        completion.registerSolver{value: 1 ether}();

        vm.prank(user1);
        bytes32 intentId = completion.submitIntent{value: fee}(
            SOURCE_CHAIN,
            DEST_CHAIN,
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            fee,
            deadline,
            bytes32(0)
        );

        vm.prank(solver1);
        completion.claimIntent(intentId);

        vm.prank(solver1);
        completion.fulfillIntent(
            intentId,
            bytes("proof"),
            bytes("inputs"),
            bytes32(uint256(block.timestamp))
        );

        // Warp less than full challenge period
        vm.warp(block.timestamp + warpTime);

        vm.expectRevert();
        completion.finalizeIntent(intentId);
    }

    /// @notice Fuzz: protocol fee accumulation is correct
    function testFuzz_protocolFeeAccumulation(uint128 feeRaw) public {
        uint256 fee = bound(uint256(feeRaw), 0.01 ether, 5 ether);
        uint256 deadline = block.timestamp + 1 hours;

        vm.prank(solver1);
        completion.registerSolver{value: 1 ether}();

        vm.prank(user1);
        bytes32 intentId = completion.submitIntent{value: fee}(
            SOURCE_CHAIN,
            DEST_CHAIN,
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            fee,
            deadline,
            bytes32(0)
        );

        vm.prank(solver1);
        completion.claimIntent(intentId);

        vm.prank(solver1);
        completion.fulfillIntent(
            intentId,
            bytes("proof"),
            bytes("inputs"),
            bytes32(uint256(block.timestamp))
        );

        vm.warp(block.timestamp + completion.CHALLENGE_PERIOD() + 1);

        uint256 feesBefore = completion.protocolFees();
        completion.finalizeIntent(intentId);
        uint256 feesAfter = completion.protocolFees();

        uint256 expectedCut = (fee * completion.PROTOCOL_FEE_BPS()) / 10_000;
        assertEq(feesAfter - feesBefore, expectedCut, "Protocol fee mismatch");
    }

    /// @notice Fuzz: duplicate claim should revert (intent already claimed)
    function testFuzz_duplicateClaim(uint128 feeRaw) public {
        uint256 fee = bound(uint256(feeRaw), 0.01 ether, 2 ether);
        uint256 deadline = block.timestamp + 1 hours;

        vm.prank(solver1);
        completion.registerSolver{value: 1 ether}();
        vm.prank(solver2);
        completion.registerSolver{value: 1 ether}();

        vm.prank(user1);
        bytes32 intentId = completion.submitIntent{value: fee}(
            SOURCE_CHAIN,
            DEST_CHAIN,
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            fee,
            deadline,
            bytes32(0)
        );

        vm.prank(solver1);
        completion.claimIntent(intentId);

        // Second solver tries to claim same intent
        vm.prank(solver2);
        vm.expectRevert();
        completion.claimIntent(intentId);
    }

    /// @notice Fuzz: totalIntents monotonically increases
    function testFuzz_totalIntentsMonotonic(uint8 count) public {
        count = uint8(bound(count, 1, 10));

        uint256 fee = 0.01 ether;
        uint256 deadline = block.timestamp + 1 hours;

        for (uint8 i = 0; i < count; i++) {
            uint256 prevTotal = completion.totalIntents();
            vm.prank(user1);
            completion.submitIntent{value: fee}(
                SOURCE_CHAIN,
                DEST_CHAIN,
                bytes32(uint256(i + 1)),
                bytes32(uint256(i + 100)),
                fee,
                deadline,
                bytes32(0)
            );
            assertEq(
                completion.totalIntents(),
                prevTotal + 1,
                "totalIntents should increment by 1"
            );
        }
    }
}
