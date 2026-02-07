// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {CardanoBridgeAdapter} from "../../contracts/crosschain/CardanoBridgeAdapter.sol";
import {ICardanoBridgeAdapter} from "../../contracts/interfaces/ICardanoBridgeAdapter.sol";
import {MockWrappedADA} from "../../contracts/mocks/MockWrappedADA.sol";
import {MockCardanoLightClient} from "../../contracts/mocks/MockCardanoLightClient.sol";

/**
 * @title CardanoBridgeFuzz
 * @notice Foundry fuzz & invariant tests for the CardanoBridgeAdapter
 * @dev Tests Lovelace precision (6 decimals), Ouroboros Praos header verification,
 *      validator attestation, and Cardano-specific bridge parameters.
 */
contract CardanoBridgeFuzz is Test {
    CardanoBridgeAdapter public bridge;
    MockWrappedADA public wADA;
    MockCardanoLightClient public cardanoLC;

    address public admin = address(0xA);
    address public relayer = address(0xB);
    address public user = address(0xC);
    address public treasury = address(0xD);

    // Validator addresses (stake pool operators)
    address constant VALIDATOR_1 = address(0x2001);
    address constant VALIDATOR_2 = address(0x2002);
    address constant VALIDATOR_3 = address(0x2003);

    uint256 constant LOVELACE_PER_ADA = 1_000_000; // 1e6
    uint256 constant MIN_DEPOSIT = 100_000; // 0.1 ADA
    uint256 constant MAX_DEPOSIT = 10_000_000 * LOVELACE_PER_ADA;

    function setUp() public {
        vm.startPrank(admin);

        bridge = new CardanoBridgeAdapter(admin);
        wADA = new MockWrappedADA();
        cardanoLC = new MockCardanoLightClient();

        // Register validators with voting power
        cardanoLC.addValidator(VALIDATOR_1, 100);
        cardanoLC.addValidator(VALIDATOR_2, 100);
        cardanoLC.addValidator(VALIDATOR_3, 100);

        // Configure bridge
        bridge.configure(
            address(0x1), // cardanoBridgeContract
            address(wADA),
            address(cardanoLC),
            2, // minValidatorSignatures
            36 // requiredBlockConfirmations (~20 min finality)
        );

        bridge.setTreasury(treasury);
        bridge.grantRole(bridge.RELAYER_ROLE(), relayer);

        // Fund the bridge with wADA (100M ADA in Lovelace)
        wADA.mint(address(bridge), 100_000_000 * LOVELACE_PER_ADA);

        vm.stopPrank();
    }

    receive() external payable {}

    /*//////////////////////////////////////////////////////////////
                          HELPER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _buildValidatorAttestations()
        internal
        pure
        returns (ICardanoBridgeAdapter.ValidatorAttestation[] memory)
    {
        ICardanoBridgeAdapter.ValidatorAttestation[]
            memory attestations = new ICardanoBridgeAdapter.ValidatorAttestation[](
                3
            );

        attestations[0] = ICardanoBridgeAdapter.ValidatorAttestation({
            validator: VALIDATOR_1,
            signature: hex"01"
        });
        attestations[1] = ICardanoBridgeAdapter.ValidatorAttestation({
            validator: VALIDATOR_2,
            signature: hex"02"
        });
        attestations[2] = ICardanoBridgeAdapter.ValidatorAttestation({
            validator: VALIDATOR_3,
            signature: hex"03"
        });

        return attestations;
    }

    function _submitVerifiedHeader(uint256 slot) internal {
        ICardanoBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();

        // blockBodyHash = keccak256(hex"01") so our state proof can validate
        bytes32 blockBodyHash = keccak256(hex"01");

        vm.prank(relayer);
        bridge.submitOuroborosHeader(
            slot,
            1, // epoch
            keccak256(abi.encode("blockHash", slot)),
            keccak256(abi.encode("prevBlockHash", slot)),
            keccak256(abi.encode("vrfOutput", slot)),
            blockBodyHash,
            block.timestamp,
            attestations
        );
    }

    function _buildStateProof()
        internal
        pure
        returns (ICardanoBridgeAdapter.CardanoStateProof memory)
    {
        bytes32[] memory merklePath = new bytes32[](0);

        return
            ICardanoBridgeAdapter.CardanoStateProof({
                merklePath: merklePath,
                blockBodyHash: keccak256(hex"01"),
                value: hex"01"
            });
    }

    function _initiateDeposit(
        uint256 amount,
        bytes32 txHash
    ) internal returns (bytes32) {
        uint256 depositSlot = 1;
        uint256 confirmSlot = depositSlot + 36;

        // Submit header at deposit slot and confirmation slot
        _submitVerifiedHeader(depositSlot);
        _submitVerifiedHeader(confirmSlot);

        ICardanoBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        ICardanoBridgeAdapter.CardanoStateProof
            memory proof = _buildStateProof();

        vm.prank(relayer);
        return
            bridge.initiateADADeposit(
                txHash,
                keccak256("cardano_sender"),
                user,
                amount,
                depositSlot,
                proof,
                attestations
            );
    }

    /*//////////////////////////////////////////////////////////////
                         CONSTANTS TESTS
    //////////////////////////////////////////////////////////////*/

    function test_constantsAreCorrect() public view {
        assertEq(bridge.CARDANO_CHAIN_ID(), 764824073);
        assertEq(bridge.LOVELACE_PER_ADA(), 1_000_000);
        assertEq(bridge.BRIDGE_FEE_BPS(), 6);
        assertEq(bridge.WITHDRAWAL_REFUND_DELAY(), 48 hours);
        assertEq(bridge.MIN_ESCROW_TIMELOCK(), 2 hours);
        assertEq(bridge.MAX_ESCROW_TIMELOCK(), 30 days);
        assertEq(bridge.DEFAULT_BLOCK_CONFIRMATIONS(), 36);
    }

    function test_constructorRejectsZeroAdmin() public {
        vm.expectRevert(ICardanoBridgeAdapter.ZeroAddress.selector);
        new CardanoBridgeAdapter(address(0));
    }

    /*//////////////////////////////////////////////////////////////
                       LOVELACE PRECISION TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_lovelacePrecision(uint256 adaAmount) public pure {
        adaAmount = bound(adaAmount, 1, 1_000_000);
        uint256 lovelace = adaAmount * LOVELACE_PER_ADA;
        assertEq(lovelace / LOVELACE_PER_ADA, adaAmount);
        assertEq(lovelace % LOVELACE_PER_ADA, 0);
    }

    function testFuzz_lovelaceSubUnitDeposit(uint256 lovelace) public {
        lovelace = bound(lovelace, MIN_DEPOSIT, MAX_DEPOSIT);

        bytes32 txHash = keccak256(abi.encode("ada_tx_sub", lovelace));
        bytes32 depositId = _initiateDeposit(lovelace, txHash);

        ICardanoBridgeAdapter.ADADeposit memory dep = bridge.getDeposit(
            depositId
        );
        assertEq(dep.amountLovelace, lovelace);
        assertEq(dep.fee, (lovelace * 6) / 10_000);
        assertEq(dep.netAmountLovelace, lovelace - dep.fee);
    }

    /*//////////////////////////////////////////////////////////////
                        FEE CALCULATION TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_feeCalculation(uint256 amount) public pure {
        amount = bound(amount, MIN_DEPOSIT, MAX_DEPOSIT);
        uint256 fee = (amount * 6) / 10_000;
        uint256 net = amount - fee;

        // Fee should never exceed the amount
        assertLe(fee, amount);
        // Net + fee = amount
        assertEq(net + fee, amount);
        // 0.06% fee
        assertLe(fee, amount / 100);
    }

    /*//////////////////////////////////////////////////////////////
                  OUROBOROS HEADER VERIFICATION TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_headerChain(uint8 count) public {
        uint256 n = bound(uint256(count), 1, 20);

        for (uint256 i = 0; i < n; i++) {
            _submitVerifiedHeader(i);

            ICardanoBridgeAdapter.OuroborosHeader memory hdr = bridge
                .getOuroborosHeader(i);
            assertTrue(hdr.verified);
            assertEq(hdr.slot, i);
        }

        assertEq(bridge.latestVerifiedSlot(), n - 1);
    }

    function test_depositRequiresVerifiedHeader() public {
        // Don't submit any Ouroboros header — deposit should fail
        ICardanoBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        ICardanoBridgeAdapter.CardanoStateProof
            memory proof = _buildStateProof();

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                ICardanoBridgeAdapter.CardanoSlotNotVerified.selector,
                999
            )
        );
        bridge.initiateADADeposit(
            keccak256("unverified_tx"),
            keccak256("sender"),
            user,
            1 * LOVELACE_PER_ADA,
            999, // non-existent slot
            proof,
            attestations
        );
    }

    /*//////////////////////////////////////////////////////////////
                        DEPOSIT TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_depositRoundTrip(uint256 amount) public {
        amount = bound(amount, MIN_DEPOSIT, MAX_DEPOSIT);

        bytes32 txHash = keccak256(abi.encode("roundtrip_tx", amount));
        bytes32 depositId = _initiateDeposit(amount, txHash);

        ICardanoBridgeAdapter.ADADeposit memory dep = bridge.getDeposit(
            depositId
        );
        assertEq(
            uint256(dep.status),
            uint256(ICardanoBridgeAdapter.DepositStatus.VERIFIED)
        );

        // Complete the deposit (admin has OPERATOR_ROLE)
        vm.prank(admin);
        bridge.completeADADeposit(depositId);

        dep = bridge.getDeposit(depositId);
        assertEq(
            uint256(dep.status),
            uint256(ICardanoBridgeAdapter.DepositStatus.COMPLETED)
        );

        uint256 expectedFee = (amount * 6) / 10_000;
        uint256 expectedNet = amount - expectedFee;
        assertEq(dep.netAmountLovelace, expectedNet);
        assertEq(wADA.balanceOf(user), expectedNet);
    }

    function testFuzz_depositAmountBounds(uint256 amount) public {
        amount = bound(amount, MIN_DEPOSIT, MAX_DEPOSIT);

        bytes32 txHash = keccak256(abi.encode("bounds_tx", amount));
        bytes32 depositId = _initiateDeposit(amount, txHash);

        ICardanoBridgeAdapter.ADADeposit memory dep = bridge.getDeposit(
            depositId
        );
        assertGe(dep.amountLovelace, MIN_DEPOSIT);
        assertLe(dep.amountLovelace, MAX_DEPOSIT);
    }

    function testFuzz_depositRejectsAmountBelowMin(uint256 amount) public {
        amount = bound(amount, 1, MIN_DEPOSIT - 1);

        _submitVerifiedHeader(1);
        _submitVerifiedHeader(37);

        ICardanoBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        ICardanoBridgeAdapter.CardanoStateProof
            memory proof = _buildStateProof();

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                ICardanoBridgeAdapter.AmountBelowMinimum.selector,
                amount,
                MIN_DEPOSIT
            )
        );
        bridge.initiateADADeposit(
            keccak256(abi.encode("tx_low", amount)),
            keccak256("sender"),
            user,
            amount,
            1,
            proof,
            attestations
        );
    }

    function testFuzz_depositRejectsAmountAboveMax(uint256 amount) public {
        amount = bound(amount, MAX_DEPOSIT + 1, type(uint128).max);

        _submitVerifiedHeader(1);
        _submitVerifiedHeader(37);

        ICardanoBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        ICardanoBridgeAdapter.CardanoStateProof
            memory proof = _buildStateProof();

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                ICardanoBridgeAdapter.AmountAboveMaximum.selector,
                amount,
                MAX_DEPOSIT
            )
        );
        bridge.initiateADADeposit(
            keccak256(abi.encode("tx_high", amount)),
            keccak256("sender"),
            user,
            amount,
            1,
            proof,
            attestations
        );
    }

    function testFuzz_txHashReplayProtection(bytes32 txHash) public {
        vm.assume(txHash != bytes32(0));

        bytes32 depositId = _initiateDeposit(1 * LOVELACE_PER_ADA, txHash);
        assertTrue(depositId != bytes32(0));

        // Submit fresh confirmation slot for second attempt
        _submitVerifiedHeader(38);

        ICardanoBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        ICardanoBridgeAdapter.CardanoStateProof
            memory proof = _buildStateProof();

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                ICardanoBridgeAdapter.CardanoTxAlreadyUsed.selector,
                txHash
            )
        );
        bridge.initiateADADeposit(
            txHash,
            keccak256("sender"),
            user,
            1 * LOVELACE_PER_ADA,
            1,
            proof,
            attestations
        );
    }

    function testFuzz_depositNonceOnlyIncreases(uint8 count) public {
        uint256 n = bound(uint256(count), 1, 10);
        uint256 prevNonce = bridge.depositNonce();

        // Submit headers once — reusable for all deposits at slot 1
        _submitVerifiedHeader(1);
        _submitVerifiedHeader(37);

        for (uint256 i = 0; i < n; i++) {
            bytes32 txHash = keccak256(abi.encode("nonce_tx", i));

            ICardanoBridgeAdapter.ValidatorAttestation[]
                memory attestations = _buildValidatorAttestations();
            ICardanoBridgeAdapter.CardanoStateProof
                memory proof = _buildStateProof();

            vm.prank(relayer);
            bridge.initiateADADeposit(
                txHash,
                keccak256("sender"),
                user,
                1 * LOVELACE_PER_ADA,
                1,
                proof,
                attestations
            );

            assertGt(bridge.depositNonce(), prevNonce);
            prevNonce = bridge.depositNonce();
        }
    }

    function testFuzz_multipleDeposits(uint8 count) public {
        uint256 n = bound(uint256(count), 2, 10);

        // Submit headers once
        _submitVerifiedHeader(1);
        _submitVerifiedHeader(37);

        bytes32[] memory depositIds = new bytes32[](n);

        for (uint256 i = 0; i < n; i++) {
            bytes32 txHash = keccak256(abi.encode("multi_tx", i));

            ICardanoBridgeAdapter.ValidatorAttestation[]
                memory attestations = _buildValidatorAttestations();
            ICardanoBridgeAdapter.CardanoStateProof
                memory proof = _buildStateProof();

            vm.prank(relayer);
            depositIds[i] = bridge.initiateADADeposit(
                txHash,
                keccak256("sender"),
                user,
                1 * LOVELACE_PER_ADA,
                1,
                proof,
                attestations
            );
        }

        // All deposit IDs should be unique
        for (uint256 i = 0; i < n; i++) {
            for (uint256 j = i + 1; j < n; j++) {
                assertTrue(depositIds[i] != depositIds[j]);
            }
        }

        assertEq(bridge.depositNonce(), n);
    }

    function testFuzz_depositIdUniqueness(bytes32 txHash) public {
        vm.assume(txHash != bytes32(0));

        bytes32 depositId = _initiateDeposit(1 * LOVELACE_PER_ADA, txHash);
        assertTrue(depositId != bytes32(0));

        ICardanoBridgeAdapter.ADADeposit memory dep = bridge.getDeposit(
            depositId
        );
        assertEq(dep.cardanoTxHash, txHash);
        assertEq(dep.depositId, depositId);
    }

    /*//////////////////////////////////////////////////////////////
                       WITHDRAWAL TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_withdrawalRejectsAmountBelowMin(uint256 amount) public {
        amount = bound(amount, 1, MIN_DEPOSIT - 1);

        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                ICardanoBridgeAdapter.AmountBelowMinimum.selector,
                amount,
                MIN_DEPOSIT
            )
        );
        bridge.initiateWithdrawal(keccak256("cardano_recipient"), amount);
    }

    function testFuzz_withdrawalRejectsAmountAboveMax(uint256 amount) public {
        amount = bound(amount, MAX_DEPOSIT + 1, type(uint128).max);

        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                ICardanoBridgeAdapter.AmountAboveMaximum.selector,
                amount,
                MAX_DEPOSIT
            )
        );
        bridge.initiateWithdrawal(keccak256("cardano_recipient"), amount);
    }

    function testFuzz_withdrawalNonceOnlyIncreases(uint8 count) public {
        uint256 n = bound(uint256(count), 1, 10);
        uint256 amount = 1 * LOVELACE_PER_ADA;

        // Mint wADA to user for withdrawals
        vm.prank(admin);
        wADA.mint(user, amount * n);

        vm.startPrank(user);
        wADA.approve(address(bridge), amount * n);

        uint256 prevNonce = bridge.withdrawalNonce();
        for (uint256 i = 0; i < n; i++) {
            bridge.initiateWithdrawal(keccak256("cardano_recipient"), amount);
            assertGt(bridge.withdrawalNonce(), prevNonce);
            prevNonce = bridge.withdrawalNonce();
        }

        vm.stopPrank();
    }

    function test_withdrawalRefundAfterDelay() public {
        uint256 amount = 1 * LOVELACE_PER_ADA;

        vm.prank(admin);
        wADA.mint(user, amount);

        vm.startPrank(user);
        wADA.approve(address(bridge), amount);
        bytes32 wId = bridge.initiateWithdrawal(
            keccak256("cardano_recipient"),
            amount
        );
        vm.stopPrank();

        // Cannot refund before delay
        vm.expectRevert();
        bridge.refundWithdrawal(wId);

        // Warp past refund delay (48 hours for Cardano)
        vm.warp(block.timestamp + 48 hours + 1);

        uint256 balBefore = wADA.balanceOf(user);
        bridge.refundWithdrawal(wId);
        uint256 balAfter = wADA.balanceOf(user);

        assertEq(balAfter - balBefore, amount);

        ICardanoBridgeAdapter.ADAWithdrawal memory w = bridge.getWithdrawal(
            wId
        );
        assertEq(
            uint256(w.status),
            uint256(ICardanoBridgeAdapter.WithdrawalStatus.REFUNDED)
        );
    }

    function test_withdrawalRefundTooEarly() public {
        uint256 amount = 1 * LOVELACE_PER_ADA;

        vm.prank(admin);
        wADA.mint(user, amount);

        vm.startPrank(user);
        wADA.approve(address(bridge), amount);
        bytes32 wId = bridge.initiateWithdrawal(
            keccak256("cardano_recipient"),
            amount
        );
        vm.stopPrank();

        // Try immediately — should fail
        vm.expectRevert();
        bridge.refundWithdrawal(wId);

        // Warp to just before the 48-hour refund delay
        vm.warp(block.timestamp + 48 hours - 1);
        vm.expectRevert();
        bridge.refundWithdrawal(wId);
    }

    function test_withdrawalDoubleComplete() public {
        uint256 amount = 1 * LOVELACE_PER_ADA;

        vm.prank(admin);
        wADA.mint(user, amount);

        vm.startPrank(user);
        wADA.approve(address(bridge), amount);
        bytes32 wId = bridge.initiateWithdrawal(
            keccak256("cardano_recipient"),
            amount
        );
        vm.stopPrank();

        ICardanoBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        ICardanoBridgeAdapter.CardanoStateProof
            memory proof = _buildStateProof();

        vm.prank(relayer);
        bridge.completeWithdrawal(
            wId,
            keccak256("cardano_tx"),
            proof,
            attestations
        );

        // Second complete should fail
        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                ICardanoBridgeAdapter.WithdrawalNotPending.selector,
                wId
            )
        );
        bridge.completeWithdrawal(
            wId,
            keccak256("cardano_tx2"),
            proof,
            attestations
        );
    }

    /*//////////////////////////////////////////////////////////////
                        ESCROW LIFECYCLE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_escrowCreateFinishLifecycle() public {
        bytes32 preimage = keccak256("test_preimage_cardano");
        bytes32 hashlock = sha256(abi.encodePacked(preimage));

        uint256 finishAfter = block.timestamp + 2 hours;
        uint256 cancelAfter = finishAfter + 12 hours;

        vm.deal(user, 10 ether);
        vm.prank(user);
        bytes32 escrowId = bridge.createEscrow{value: 1 ether}(
            keccak256("cardano_party"),
            hashlock,
            finishAfter,
            cancelAfter
        );

        ICardanoBridgeAdapter.ADAEscrow memory e = bridge.getEscrow(escrowId);
        assertEq(
            uint256(e.status),
            uint256(ICardanoBridgeAdapter.EscrowStatus.ACTIVE)
        );
        assertEq(e.amountLovelace, 1 ether);

        // Finish after timelock
        vm.warp(finishAfter + 1);
        bridge.finishEscrow(escrowId, preimage);

        e = bridge.getEscrow(escrowId);
        assertEq(
            uint256(e.status),
            uint256(ICardanoBridgeAdapter.EscrowStatus.FINISHED)
        );
        assertEq(e.preimage, preimage);
    }

    function test_escrowCreateCancelLifecycle() public {
        bytes32 hashlock = sha256(
            abi.encodePacked(keccak256("cancel_cardano"))
        );

        uint256 finishAfter = block.timestamp + 2 hours;
        uint256 cancelAfter = finishAfter + 6 hours;

        vm.deal(user, 10 ether);
        vm.prank(user);
        bytes32 escrowId = bridge.createEscrow{value: 0.5 ether}(
            keccak256("cardano_party"),
            hashlock,
            finishAfter,
            cancelAfter
        );

        // Cannot cancel before cancelAfter
        vm.expectRevert(ICardanoBridgeAdapter.EscrowTimelockNotMet.selector);
        bridge.cancelEscrow(escrowId);

        // Warp past cancelAfter
        vm.warp(cancelAfter + 1);
        uint256 balBefore = user.balance;
        bridge.cancelEscrow(escrowId);
        uint256 balAfter = user.balance;

        assertEq(balAfter - balBefore, 0.5 ether);
    }

    function testFuzz_escrowTimelockBounds(
        uint256 finish,
        uint256 duration
    ) public {
        finish = bound(finish, block.timestamp + 1, block.timestamp + 365 days);
        duration = bound(duration, 2 hours, 30 days);
        uint256 cancel = finish + duration;

        bytes32 hashlock = sha256(
            abi.encodePacked(keccak256("timelock_cardano"))
        );

        vm.deal(user, 1 ether);
        vm.prank(user);
        bytes32 escrowId = bridge.createEscrow{value: 0.1 ether}(
            keccak256("cardano_party"),
            hashlock,
            finish,
            cancel
        );

        ICardanoBridgeAdapter.ADAEscrow memory e = bridge.getEscrow(escrowId);
        assertEq(e.finishAfter, finish);
        assertEq(e.cancelAfter, cancel);
    }

    function testFuzz_escrowTimelockTooLong(
        uint256 finish,
        uint256 excess
    ) public {
        finish = bound(finish, block.timestamp + 1, block.timestamp + 365 days);
        excess = bound(excess, 30 days + 1, 365 days);
        uint256 cancel = finish + excess;

        bytes32 hashlock = sha256(abi.encodePacked(keccak256("long_cardano")));

        vm.deal(user, 1 ether);
        vm.prank(user);
        vm.expectRevert(ICardanoBridgeAdapter.InvalidTimelockRange.selector);
        bridge.createEscrow{value: 0.1 ether}(
            keccak256("cardano_party"),
            hashlock,
            finish,
            cancel
        );
    }

    function test_escrowDoubleFinish() public {
        bytes32 preimage = keccak256("double_finish_cardano");
        bytes32 hashlock = sha256(abi.encodePacked(preimage));

        uint256 finishAfter = block.timestamp + 2 hours;
        uint256 cancelAfter = finishAfter + 12 hours;

        vm.deal(user, 10 ether);
        vm.prank(user);
        bytes32 escrowId = bridge.createEscrow{value: 1 ether}(
            keccak256("cardano_party"),
            hashlock,
            finishAfter,
            cancelAfter
        );

        vm.warp(finishAfter + 1);
        bridge.finishEscrow(escrowId, preimage);

        // Second finish should fail
        vm.expectRevert(
            abi.encodeWithSelector(
                ICardanoBridgeAdapter.EscrowNotActive.selector,
                escrowId
            )
        );
        bridge.finishEscrow(escrowId, preimage);
    }

    /*//////////////////////////////////////////////////////////////
                        ACCESS CONTROL TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_onlyRelayerCanInitiateDeposit(address caller) public {
        vm.assume(caller != relayer && caller != admin && caller != address(0));

        _submitVerifiedHeader(1);
        _submitVerifiedHeader(37);

        ICardanoBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        ICardanoBridgeAdapter.CardanoStateProof
            memory proof = _buildStateProof();

        vm.prank(caller);
        vm.expectRevert();
        bridge.initiateADADeposit(
            keccak256("ac_tx"),
            keccak256("sender"),
            user,
            1 * LOVELACE_PER_ADA,
            1,
            proof,
            attestations
        );
    }

    function testFuzz_onlyOperatorCanCompleteDeposit(address caller) public {
        vm.assume(caller != admin && caller != address(0));

        bytes32 depositId = _initiateDeposit(
            1 * LOVELACE_PER_ADA,
            keccak256("complete_test")
        );

        vm.prank(caller);
        vm.expectRevert();
        bridge.completeADADeposit(depositId);
    }

    function testFuzz_onlyGuardianCanPause(address caller) public {
        vm.assume(caller != admin && caller != address(0));

        vm.prank(caller);
        vm.expectRevert();
        bridge.pause();
    }

    /*//////////////////////////////////////////////////////////////
                        PAUSE TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_pauseBlocksDeposits() public {
        vm.prank(admin);
        bridge.pause();

        _submitVerifiedHeader(1);
        _submitVerifiedHeader(37);

        ICardanoBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        ICardanoBridgeAdapter.CardanoStateProof
            memory proof = _buildStateProof();

        vm.prank(relayer);
        vm.expectRevert();
        bridge.initiateADADeposit(
            keccak256("paused_tx"),
            keccak256("sender"),
            user,
            1 * LOVELACE_PER_ADA,
            1,
            proof,
            attestations
        );
    }

    function testFuzz_pauseBlocksWithdrawals() public {
        vm.prank(admin);
        bridge.pause();

        vm.prank(user);
        vm.expectRevert();
        bridge.initiateWithdrawal(
            keccak256("cardano_recipient"),
            1 * LOVELACE_PER_ADA
        );
    }

    function testFuzz_pauseBlocksEscrow() public {
        bytes32 hashlock = sha256(
            abi.encodePacked(keccak256("paused_cardano"))
        );

        vm.prank(admin);
        bridge.pause();

        vm.deal(user, 1 ether);
        vm.prank(user);
        vm.expectRevert();
        bridge.createEscrow{value: 0.1 ether}(
            keccak256("cardano_party"),
            hashlock,
            block.timestamp + 2 hours,
            block.timestamp + 8 hours
        );
    }

    function test_pauseUnpause() public {
        vm.startPrank(admin);
        bridge.pause();
        assertTrue(bridge.paused());

        bridge.unpause();
        assertFalse(bridge.paused());
        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                       NULLIFIER / PRIVACY TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_privateDeposit(bytes32 commitment) public {
        vm.assume(commitment != bytes32(0));

        bytes32 depositId = _initiateDeposit(
            1 * LOVELACE_PER_ADA,
            keccak256(abi.encode("priv_tx", commitment))
        );

        bytes32 nullifier = keccak256(abi.encode("nullifier", commitment));
        bridge.registerPrivateDeposit(
            depositId,
            commitment,
            nullifier,
            hex"00"
        );

        assertTrue(bridge.usedNullifiers(nullifier));
    }

    function testFuzz_nullifierCannotBeReused(bytes32 nullifier) public {
        vm.assume(nullifier != bytes32(0));

        bytes32 depositId = _initiateDeposit(
            1 * LOVELACE_PER_ADA,
            keccak256(abi.encode("null_tx", nullifier))
        );

        bridge.registerPrivateDeposit(
            depositId,
            keccak256("commitment"),
            nullifier,
            hex"00"
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                ICardanoBridgeAdapter.NullifierAlreadyUsed.selector,
                nullifier
            )
        );
        bridge.registerPrivateDeposit(
            depositId,
            keccak256("commitment2"),
            nullifier,
            hex"00"
        );
    }

    /*//////////////////////////////////////////////////////////////
                     CONFIGURATION TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_configCannotSetZeroAddresses(
        address a,
        address b,
        address c,
        uint256 sigs
    ) public {
        vm.prank(admin);
        vm.expectRevert(ICardanoBridgeAdapter.ZeroAddress.selector);
        bridge.configure(address(0), b, c, sigs, 36);

        vm.prank(admin);
        vm.expectRevert(ICardanoBridgeAdapter.ZeroAddress.selector);
        bridge.configure(
            a == address(0) ? address(1) : a,
            address(0),
            c,
            sigs,
            36
        );

        vm.prank(admin);
        vm.expectRevert(ICardanoBridgeAdapter.ZeroAddress.selector);
        bridge.configure(
            a == address(0) ? address(1) : a,
            b == address(0) ? address(1) : b,
            address(0),
            sigs,
            36
        );
    }

    function test_treasuryCanBeUpdated() public {
        address newTreasury = address(0xF1);
        vm.prank(admin);
        bridge.setTreasury(newTreasury);
        assertEq(bridge.treasury(), newTreasury);
    }

    function test_treasuryRejectsZeroAddress() public {
        vm.prank(admin);
        vm.expectRevert(ICardanoBridgeAdapter.ZeroAddress.selector);
        bridge.setTreasury(address(0));
    }

    /*//////////////////////////////////////////////////////////////
                       FEE WITHDRAWAL TESTS
    //////////////////////////////////////////////////////////////*/

    function test_feeWithdrawal() public {
        bytes32 depositId = _initiateDeposit(
            10 * LOVELACE_PER_ADA,
            keccak256("fee_tx")
        );

        uint256 expectedFees = (10 * LOVELACE_PER_ADA * 6) / 10_000;
        assertEq(bridge.accumulatedFees(), expectedFees);

        uint256 balBefore = wADA.balanceOf(treasury);
        vm.prank(admin);
        bridge.withdrawFees();
        uint256 balAfter = wADA.balanceOf(treasury);

        assertEq(balAfter - balBefore, expectedFees);
        assertEq(bridge.accumulatedFees(), 0);
    }

    /*//////////////////////////////////////////////////////////////
                       VIEW FUNCTION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_viewFunctionsReturnDefaults() public view {
        ICardanoBridgeAdapter.ADADeposit memory dep = bridge.getDeposit(
            bytes32(0)
        );
        assertEq(dep.amountLovelace, 0);

        ICardanoBridgeAdapter.ADAWithdrawal memory w = bridge.getWithdrawal(
            bytes32(0)
        );
        assertEq(w.amountLovelace, 0);

        ICardanoBridgeAdapter.ADAEscrow memory e = bridge.getEscrow(bytes32(0));
        assertEq(e.amountLovelace, 0);

        ICardanoBridgeAdapter.OuroborosHeader memory hdr = bridge
            .getOuroborosHeader(0);
        assertFalse(hdr.verified);
    }

    function test_statisticsTracking() public view {
        (
            uint256 deposited,
            uint256 withdrawn,
            uint256 escrowCount,
            ,
            ,
            uint256 fees,
            uint256 latestSlot
        ) = bridge.getBridgeStats();

        assertEq(deposited, 0);
        assertEq(withdrawn, 0);
        assertEq(escrowCount, 0);
        assertEq(fees, 0);
        assertEq(latestSlot, 0);
    }

    function test_userHistoryTracking() public view {
        bytes32[] memory deps = bridge.getUserDeposits(user);
        bytes32[] memory ws = bridge.getUserWithdrawals(user);
        bytes32[] memory es = bridge.getUserEscrows(user);

        assertEq(deps.length, 0);
        assertEq(ws.length, 0);
        assertEq(es.length, 0);
    }
}
