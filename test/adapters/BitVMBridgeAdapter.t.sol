// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/adapters/BitVMBridgeAdapter.sol";

contract BitVMBridgeAdapterTest is Test {
    BitVMBridgeAdapter adapter;

    address admin = makeAddr("admin");
    address operator = makeAddr("operator");
    address challenger = makeAddr("challenger");
    address user = makeAddr("user");

    function setUp() public {
        vm.prank(admin);
        adapter = new BitVMBridgeAdapter(admin, 0); // 0 → default 7 days
    }

    // ── Constructor & Roles ──

    function test_constructor_setsRoles() public view {
        assertTrue(adapter.hasRole(adapter.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(adapter.hasRole(adapter.OPERATOR_ROLE(), admin));
        assertTrue(adapter.hasRole(adapter.GUARDIAN_ROLE(), admin));
    }

    function test_constructor_defaultChallengePeriod() public view {
        assertEq(adapter.challengePeriod(), 7 days);
    }

    function test_constructor_customChallengePeriod() public {
        vm.prank(admin);
        BitVMBridgeAdapter custom = new BitVMBridgeAdapter(admin, 3 days);
        assertEq(custom.challengePeriod(), 3 days);
    }

    function test_constants() public view {
        assertEq(adapter.BITCOIN_CHAIN_ID(), 0);
        assertEq(adapter.MIN_OPERATOR_BOND(), 10 ether);
        assertEq(adapter.MIN_CHALLENGE_BOND(), 1 ether);
        assertEq(adapter.BTC_CONFIRMATIONS(), 6);
    }

    // ── bridgeMessage reverts NotImplemented ──

    function test_bridgeMessage_reverts() public {
        vm.expectRevert(BitVMBridgeAdapter.NotImplemented.selector);
        adapter.bridgeMessage{value: 0.1 ether}(
            address(0xBEEF),
            hex"01",
            address(0)
        );
    }

    // ── estimateFee ──

    function test_estimateFee_returnsZero() public view {
        uint256 fee = adapter.estimateFee(address(0), hex"01");
        assertEq(fee, 0);
    }

    // ── registerOperator ──

    function test_registerOperator_success() public {
        vm.deal(operator, 20 ether);
        vm.prank(operator);
        adapter.registerOperator{value: 10 ether}();

        BitVMBridgeAdapter.Operator memory op = adapter.getOperator(operator);
        assertEq(op.bond, 10 ether);
        assertTrue(op.active);
        assertFalse(op.slashed);
    }

    function test_registerOperator_insufficientBond() public {
        vm.deal(operator, 5 ether);
        vm.prank(operator);
        vm.expectRevert(
            abi.encodeWithSelector(
                BitVMBridgeAdapter.InsufficientBond.selector,
                5 ether,
                10 ether
            )
        );
        adapter.registerOperator{value: 5 ether}();
    }

    // ── submitDepositClaim ──

    function _registerAndGrantOperator() internal {
        vm.deal(operator, 20 ether);
        vm.prank(operator);
        adapter.registerOperator{value: 10 ether}();
        vm.prank(admin);
        adapter.grantRole(adapter.OPERATOR_ROLE(), operator);
    }

    function test_submitDepositClaim_success() public {
        _registerAndGrantOperator();
        BitVMBridgeAdapter.BitcoinSPVProof memory proof = BitVMBridgeAdapter
            .BitcoinSPVProof({
                txHash: keccak256("btcTx"),
                blockHash: keccak256("block"),
                blockHeight: 800000,
                merkleProof: hex"aabb",
                txIndex: 0
            });

        vm.prank(operator);
        bytes32 claimId = adapter.submitDepositClaim(
            keccak256("btcTx"),
            user,
            1_00000000,
            proof
        );
        assertTrue(claimId != bytes32(0));

        BitVMBridgeAdapter.DepositClaim memory claim = adapter.getDepositClaim(
            claimId
        );
        assertEq(claim.evmRecipient, user);
        assertEq(claim.amountSats, 1_00000000);
        assertEq(
            uint8(claim.status),
            uint8(BitVMBridgeAdapter.DepositStatus.PENDING)
        );
    }

    function test_submitDepositClaim_nonOperator_reverts() public {
        BitVMBridgeAdapter.BitcoinSPVProof memory proof = BitVMBridgeAdapter
            .BitcoinSPVProof({
                txHash: keccak256("btcTx"),
                blockHash: keccak256("block"),
                blockHeight: 800000,
                merkleProof: hex"aabb",
                txIndex: 0
            });

        vm.prank(user);
        vm.expectRevert();
        adapter.submitDepositClaim(keccak256("btcTx"), user, 1_00000000, proof);
    }

    // ── challengeDeposit ──

    function test_challengeDeposit_success() public {
        _registerAndGrantOperator();
        BitVMBridgeAdapter.BitcoinSPVProof memory proof = BitVMBridgeAdapter
            .BitcoinSPVProof({
                txHash: keccak256("btcTx"),
                blockHash: keccak256("block"),
                blockHeight: 800000,
                merkleProof: hex"aabb",
                txIndex: 0
            });

        vm.prank(operator);
        bytes32 claimId = adapter.submitDepositClaim(
            keccak256("btcTx"),
            user,
            1_00000000,
            proof
        );

        // Grant challenger role and challenge
        vm.prank(admin);
        adapter.grantRole(adapter.CHALLENGER_ROLE(), challenger);

        vm.deal(challenger, 2 ether);
        vm.prank(challenger);
        adapter.challengeDeposit{value: 1 ether}(claimId);

        BitVMBridgeAdapter.DepositClaim memory claim = adapter.getDepositClaim(
            claimId
        );
        assertEq(
            uint8(claim.status),
            uint8(BitVMBridgeAdapter.DepositStatus.CHALLENGED)
        );
    }

    // ── finalizeDeposit ──

    function test_finalizeDeposit_beforeChallengePeriod_reverts() public {
        _registerAndGrantOperator();
        BitVMBridgeAdapter.BitcoinSPVProof memory proof = BitVMBridgeAdapter
            .BitcoinSPVProof({
                txHash: keccak256("btcTx"),
                blockHash: keccak256("block"),
                blockHeight: 800000,
                merkleProof: hex"aabb",
                txIndex: 0
            });

        vm.prank(operator);
        bytes32 claimId = adapter.submitDepositClaim(
            keccak256("btcTx"),
            user,
            1_00000000,
            proof
        );

        // Try to finalize immediately — should fail
        vm.expectRevert();
        adapter.finalizeDeposit(claimId);
    }

    function test_finalizeDeposit_afterChallengePeriod() public {
        _registerAndGrantOperator();
        BitVMBridgeAdapter.BitcoinSPVProof memory proof = BitVMBridgeAdapter
            .BitcoinSPVProof({
                txHash: keccak256("btcTx"),
                blockHash: keccak256("block"),
                blockHeight: 800000,
                merkleProof: hex"aabb",
                txIndex: 0
            });

        vm.prank(operator);
        bytes32 claimId = adapter.submitDepositClaim(
            keccak256("btcTx"),
            user,
            1_00000000,
            proof
        );

        // Warp past challenge period
        vm.warp(block.timestamp + 7 days + 1);
        adapter.finalizeDeposit(claimId);

        assertTrue(adapter.isDepositFinalized(claimId));
    }

    // ── requestWithdrawal ──

    function test_requestWithdrawal() public {
        vm.prank(user);
        bytes32 reqId = adapter.requestWithdrawal(hex"0014aabbccdd", 50000000);
        assertTrue(reqId != bytes32(0));

        BitVMBridgeAdapter.WithdrawalRequest memory req = adapter
            .getWithdrawalRequest(reqId);
        assertEq(req.evmSender, user);
        assertEq(req.amountSats, 50000000);
        assertEq(
            uint8(req.status),
            uint8(BitVMBridgeAdapter.WithdrawalStatus.PENDING)
        );
    }

    // ── Pause / Unpause ──

    function test_pause_byGuardian() public {
        vm.prank(admin);
        adapter.pause();
        assertTrue(adapter.paused());
    }

    function test_unpause_byGuardian() public {
        vm.prank(admin);
        adapter.pause();
        vm.prank(admin);
        adapter.unpause();
        assertFalse(adapter.paused());
    }

    function test_pause_byNonGuardian_reverts() public {
        vm.prank(user);
        vm.expectRevert();
        adapter.pause();
    }

    function test_submitDepositClaim_whenPaused_reverts() public {
        _registerAndGrantOperator();
        vm.prank(admin);
        adapter.pause();

        BitVMBridgeAdapter.BitcoinSPVProof memory proof = BitVMBridgeAdapter
            .BitcoinSPVProof({
                txHash: keccak256("btcTx"),
                blockHash: keccak256("block"),
                blockHeight: 800000,
                merkleProof: hex"aabb",
                txIndex: 0
            });

        vm.prank(operator);
        vm.expectRevert();
        adapter.submitDepositClaim(keccak256("btcTx"), user, 1_00000000, proof);
    }

    // ── setChallengePeriod ──

    function test_setChallengePeriod_byAdmin() public {
        vm.prank(admin);
        adapter.setChallengePeriod(14 days);
        assertEq(adapter.challengePeriod(), 14 days);
    }

    function test_setChallengePeriod_byNonAdmin_reverts() public {
        vm.prank(user);
        vm.expectRevert();
        adapter.setChallengePeriod(14 days);
    }

    // ── receive() accepts ETH ──

    function test_receiveETH() public {
        vm.deal(user, 1 ether);
        vm.prank(user);
        (bool ok, ) = address(adapter).call{value: 1 ether}("");
        assertTrue(ok);
        assertEq(address(adapter).balance, 1 ether);
    }
}
