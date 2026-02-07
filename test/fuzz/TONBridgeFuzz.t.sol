// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {TONBridgeAdapter} from "../../contracts/crosschain/TONBridgeAdapter.sol";
import {ITONBridgeAdapter} from "../../contracts/interfaces/ITONBridgeAdapter.sol";
import {MockWrappedTON} from "../../contracts/mocks/MockWrappedTON.sol";
import {MockTONLightClient} from "../../contracts/mocks/MockTONLightClient.sol";

/**
 * @title TONBridgeFuzz
 * @notice Foundry fuzz & invariant tests for the TONBridgeAdapter
 * @dev Tests Nanoton precision (9 decimals), MasterchainBlock verification,
 *      Catchain BFT validator attestation, and TON-specific bridge parameters.
 */
contract TONBridgeFuzz is Test {
    TONBridgeAdapter public bridge;
    MockWrappedTON public wTON;
    MockTONLightClient public tonLC;

    address public admin = address(0xA);
    address public relayer = address(0xB);
    address public user = address(0xC);
    address public treasury = address(0xD);

    // Validator addresses
    address constant VALIDATOR_1 = address(0x2001);
    address constant VALIDATOR_2 = address(0x2002);
    address constant VALIDATOR_3 = address(0x2003);

    uint256 constant NANOTON_PER_TON = 1_000_000_000; // 1e9
    uint256 constant MIN_DEPOSIT = 100_000_000; // 0.1 TON
    uint256 constant MAX_DEPOSIT = 10_000_000 * NANOTON_PER_TON;

    function setUp() public {
        vm.startPrank(admin);

        bridge = new TONBridgeAdapter(admin);
        wTON = new MockWrappedTON();
        tonLC = new MockTONLightClient();

        // Register validators with voting power
        tonLC.addValidator(VALIDATOR_1, 100);
        tonLC.addValidator(VALIDATOR_2, 100);
        tonLC.addValidator(VALIDATOR_3, 100);

        // Configure bridge
        bridge.configure(
            address(0x1), // tonBridgeContract
            address(wTON),
            address(tonLC),
            2, // minValidatorSignatures
            1 // requiredConfirmations
        );

        bridge.setTreasury(treasury);
        bridge.grantRole(bridge.RELAYER_ROLE(), relayer);

        // Fund the bridge with wTON (100M TON in nanoton)
        wTON.mint(address(bridge), 100_000_000 * NANOTON_PER_TON);

        vm.stopPrank();
    }

    receive() external payable {}

    /*//////////////////////////////////////////////////////////////
                          HELPER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _buildValidatorAttestations()
        internal
        pure
        returns (ITONBridgeAdapter.ValidatorAttestation[] memory)
    {
        ITONBridgeAdapter.ValidatorAttestation[]
            memory attestations = new ITONBridgeAdapter.ValidatorAttestation[](
                3
            );

        attestations[0] = ITONBridgeAdapter.ValidatorAttestation({
            validator: VALIDATOR_1,
            signature: hex"01"
        });
        attestations[1] = ITONBridgeAdapter.ValidatorAttestation({
            validator: VALIDATOR_2,
            signature: hex"02"
        });
        attestations[2] = ITONBridgeAdapter.ValidatorAttestation({
            validator: VALIDATOR_3,
            signature: hex"03"
        });

        return attestations;
    }

    function _submitVerifiedBlock(uint256 seqno) internal {
        ITONBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();

        // Use a rootHash that matches _buildStateProof for Merkle verification
        bytes32 rootHash = keccak256("ton_proof_leaf");
        bytes32 fileHash = keccak256(abi.encode("fileHash", seqno));

        vm.prank(relayer);
        bridge.submitMasterchainBlock(
            seqno,
            rootHash,
            fileHash,
            -1, // workchain (masterchain)
            0, // shardId
            block.timestamp,
            attestations
        );
    }

    function _buildStateProof()
        internal
        pure
        returns (ITONBridgeAdapter.TONStateProof memory)
    {
        // Empty merkle proof: computedHash = keccak256(value) must equal rootHash
        bytes32[] memory merkleProof = new bytes32[](0);

        return
            ITONBridgeAdapter.TONStateProof({
                merkleProof: merkleProof,
                rootHash: keccak256("ton_proof_leaf"),
                value: "ton_proof_leaf"
            });
    }

    function _initiateDeposit(
        uint256 amount,
        bytes32 txHash
    ) internal returns (bytes32) {
        // Submit masterchain blocks to satisfy confirmation requirement
        // requiredBlockConfirmations=1 → latestVerifiedSeqno >= tonSeqno + 1
        _submitVerifiedBlock(1);
        _submitVerifiedBlock(2);

        ITONBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        ITONBridgeAdapter.TONStateProof memory proof = _buildStateProof();

        vm.prank(relayer);
        return
            bridge.initiateTONDeposit(
                txHash,
                keccak256("ton_sender"),
                user,
                amount,
                1, // tonSeqno
                proof,
                attestations
            );
    }

    /*//////////////////////////////////////////////////////////////
                         CONSTANTS TESTS
    //////////////////////////////////////////////////////////////*/

    function test_constantsAreCorrect() public view {
        assertEq(bridge.TON_CHAIN_ID(), 239);
        assertEq(bridge.NANOTON_PER_TON(), 1_000_000_000);
        assertEq(bridge.BRIDGE_FEE_BPS(), 5);
        assertEq(bridge.WITHDRAWAL_REFUND_DELAY(), 24 hours);
        assertEq(bridge.MIN_ESCROW_TIMELOCK(), 1 hours);
        assertEq(bridge.MAX_ESCROW_TIMELOCK(), 30 days);
        assertEq(bridge.DEFAULT_BLOCK_CONFIRMATIONS(), 1);
    }

    function test_constructorRejectsZeroAdmin() public {
        vm.expectRevert(ITONBridgeAdapter.ZeroAddress.selector);
        new TONBridgeAdapter(address(0));
    }

    /*//////////////////////////////////////////////////////////////
                       NANOTON PRECISION TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_nanotonPrecision(uint256 tonAmount) public pure {
        tonAmount = bound(tonAmount, 1, 1_000_000);
        uint256 nanoton = tonAmount * NANOTON_PER_TON;
        assertEq(nanoton / NANOTON_PER_TON, tonAmount);
        assertEq(nanoton % NANOTON_PER_TON, 0);
    }

    function testFuzz_nanotonSubUnitDeposit(uint256 nanoton) public {
        nanoton = bound(nanoton, MIN_DEPOSIT, MAX_DEPOSIT);

        bytes32 txHash = keccak256(abi.encode("ton_tx_sub", nanoton));
        bytes32 depositId = _initiateDeposit(nanoton, txHash);

        ITONBridgeAdapter.TONDeposit memory dep = bridge.getDeposit(depositId);
        assertEq(dep.amountNanoton, nanoton);
        assertEq(dep.fee, (nanoton * 5) / 10_000);
        assertEq(dep.netAmountNanoton, nanoton - dep.fee);
    }

    /*//////////////////////////////////////////////////////////////
                        FEE CALCULATION TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_feeCalculation(uint256 amount) public pure {
        amount = bound(amount, MIN_DEPOSIT, MAX_DEPOSIT);
        uint256 fee = (amount * 5) / 10_000;
        uint256 net = amount - fee;

        // Fee should never exceed the amount
        assertLe(fee, amount);
        // Net + fee = amount
        assertEq(net + fee, amount);
        // 0.05% fee
        assertLe(fee, amount / 100);
    }

    /*//////////////////////////////////////////////////////////////
                  MASTERCHAIN BLOCK VERIFICATION TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_masterchainBlockChain(uint8 count) public {
        uint256 n = bound(uint256(count), 1, 20);

        for (uint256 i = 0; i < n; i++) {
            _submitVerifiedBlock(i);

            ITONBridgeAdapter.MasterchainBlock memory blk = bridge
                .getMasterchainBlock(i);
            assertTrue(blk.verified);
            assertEq(blk.seqno, i);
            assertEq(blk.workchain, -1);
        }

        assertEq(bridge.latestVerifiedSeqno(), n - 1);
    }

    function test_depositRequiresVerifiedBlock() public {
        // Don't submit any masterchain block — deposit should fail
        ITONBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        ITONBridgeAdapter.TONStateProof memory proof = _buildStateProof();

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                ITONBridgeAdapter.TONBlockNotVerified.selector,
                999
            )
        );
        bridge.initiateTONDeposit(
            keccak256("unverified_tx"),
            keccak256("sender"),
            user,
            1 * NANOTON_PER_TON,
            999, // non-existent seqno
            proof,
            attestations
        );
    }

    /*//////////////////////////////////////////////////////////////
                        DEPOSIT TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_depositRoundTrip(uint256 amount) public {
        amount = bound(amount, MIN_DEPOSIT, MAX_DEPOSIT);

        bytes32 txHash = keccak256(abi.encode("round_trip", amount));
        bytes32 depositId = _initiateDeposit(amount, txHash);

        ITONBridgeAdapter.TONDeposit memory dep = bridge.getDeposit(depositId);
        assertEq(
            uint256(dep.status),
            uint256(ITONBridgeAdapter.DepositStatus.VERIFIED)
        );

        uint256 balBefore = wTON.balanceOf(user);

        // Complete deposit (admin has OPERATOR_ROLE)
        vm.prank(admin);
        bridge.completeTONDeposit(depositId);

        uint256 balAfter = wTON.balanceOf(user);
        assertEq(balAfter - balBefore, dep.netAmountNanoton);

        dep = bridge.getDeposit(depositId);
        assertEq(
            uint256(dep.status),
            uint256(ITONBridgeAdapter.DepositStatus.COMPLETED)
        );
    }

    function testFuzz_depositRejectsAmountBelowMin(uint256 amount) public {
        amount = bound(amount, 1, MIN_DEPOSIT - 1);

        _submitVerifiedBlock(1);
        _submitVerifiedBlock(2);

        ITONBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        ITONBridgeAdapter.TONStateProof memory proof = _buildStateProof();

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                ITONBridgeAdapter.AmountBelowMinimum.selector,
                amount,
                MIN_DEPOSIT
            )
        );
        bridge.initiateTONDeposit(
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

        _submitVerifiedBlock(1);
        _submitVerifiedBlock(2);

        ITONBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        ITONBridgeAdapter.TONStateProof memory proof = _buildStateProof();

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                ITONBridgeAdapter.AmountAboveMaximum.selector,
                amount,
                MAX_DEPOSIT
            )
        );
        bridge.initiateTONDeposit(
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

        bytes32 depositId = _initiateDeposit(1 * NANOTON_PER_TON, txHash);
        assertTrue(depositId != bytes32(0));

        // Submit additional blocks for second attempt
        _submitVerifiedBlock(3);
        _submitVerifiedBlock(4);

        ITONBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        ITONBridgeAdapter.TONStateProof memory proof = _buildStateProof();

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                ITONBridgeAdapter.TONTxAlreadyUsed.selector,
                txHash
            )
        );
        bridge.initiateTONDeposit(
            txHash,
            keccak256("sender"),
            user,
            1 * NANOTON_PER_TON,
            3,
            proof,
            attestations
        );
    }

    function testFuzz_depositNonceOnlyIncreases(uint8 count) public {
        uint256 n = bound(uint256(count), 1, 10);
        uint256 prevNonce = bridge.depositNonce();

        for (uint256 i = 0; i < n; i++) {
            bytes32 txHash = keccak256(abi.encode("nonce_tx", i));

            // Submit blocks for each iteration
            uint256 baseSeqno = (i * 2) + 1;
            _submitVerifiedBlock(baseSeqno);
            _submitVerifiedBlock(baseSeqno + 1);

            ITONBridgeAdapter.ValidatorAttestation[]
                memory attestations = _buildValidatorAttestations();
            ITONBridgeAdapter.TONStateProof memory proof = _buildStateProof();

            vm.prank(relayer);
            bridge.initiateTONDeposit(
                txHash,
                keccak256("sender"),
                user,
                1 * NANOTON_PER_TON,
                baseSeqno,
                proof,
                attestations
            );

            assertGt(bridge.depositNonce(), prevNonce);
            prevNonce = bridge.depositNonce();
        }
    }

    function testFuzz_depositIdUniqueness(uint8 count) public {
        uint256 n = bound(uint256(count), 2, 10);
        bytes32[] memory ids = new bytes32[](n);

        for (uint256 i = 0; i < n; i++) {
            bytes32 txHash = keccak256(abi.encode("unique_tx", i));

            uint256 baseSeqno = (i * 2) + 1;
            _submitVerifiedBlock(baseSeqno);
            _submitVerifiedBlock(baseSeqno + 1);

            ITONBridgeAdapter.ValidatorAttestation[]
                memory attestations = _buildValidatorAttestations();
            ITONBridgeAdapter.TONStateProof memory proof = _buildStateProof();

            vm.prank(relayer);
            ids[i] = bridge.initiateTONDeposit(
                txHash,
                keccak256("sender"),
                user,
                1 * NANOTON_PER_TON,
                baseSeqno,
                proof,
                attestations
            );
        }

        // Verify all deposit IDs are unique
        for (uint256 i = 0; i < n; i++) {
            for (uint256 j = i + 1; j < n; j++) {
                assertTrue(ids[i] != ids[j]);
            }
        }
    }

    function testFuzz_multipleDeposits(uint8 count) public {
        uint256 n = bound(uint256(count), 1, 10);

        for (uint256 i = 0; i < n; i++) {
            bytes32 txHash = keccak256(abi.encode("multi_tx", i));

            uint256 baseSeqno = (i * 2) + 1;
            _submitVerifiedBlock(baseSeqno);
            _submitVerifiedBlock(baseSeqno + 1);

            ITONBridgeAdapter.ValidatorAttestation[]
                memory attestations = _buildValidatorAttestations();
            ITONBridgeAdapter.TONStateProof memory proof = _buildStateProof();

            vm.prank(relayer);
            bytes32 depositId = bridge.initiateTONDeposit(
                txHash,
                keccak256("sender"),
                user,
                1 * NANOTON_PER_TON,
                baseSeqno,
                proof,
                attestations
            );

            ITONBridgeAdapter.TONDeposit memory dep = bridge.getDeposit(
                depositId
            );
            assertEq(dep.amountNanoton, 1 * NANOTON_PER_TON);
        }

        assertEq(bridge.depositNonce(), n);
    }

    /*//////////////////////////////////////////////////////////////
                       WITHDRAWAL TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_withdrawalRejectsAmountBelowMin(uint256 amount) public {
        amount = bound(amount, 1, MIN_DEPOSIT - 1);

        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                ITONBridgeAdapter.AmountBelowMinimum.selector,
                amount,
                MIN_DEPOSIT
            )
        );
        bridge.initiateWithdrawal(keccak256("ton_recipient"), amount);
    }

    function testFuzz_withdrawalRejectsAmountAboveMax(uint256 amount) public {
        amount = bound(amount, MAX_DEPOSIT + 1, type(uint128).max);

        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                ITONBridgeAdapter.AmountAboveMaximum.selector,
                amount,
                MAX_DEPOSIT
            )
        );
        bridge.initiateWithdrawal(keccak256("ton_recipient"), amount);
    }

    function testFuzz_withdrawalNonceOnlyIncreases(uint8 count) public {
        uint256 n = bound(uint256(count), 1, 10);
        uint256 amount = 1 * NANOTON_PER_TON;

        // Mint wTON to user for withdrawals
        vm.prank(admin);
        wTON.mint(user, amount * n);

        vm.startPrank(user);
        wTON.approve(address(bridge), amount * n);

        uint256 prevNonce = bridge.withdrawalNonce();
        for (uint256 i = 0; i < n; i++) {
            bridge.initiateWithdrawal(keccak256("ton_recipient"), amount);
            assertGt(bridge.withdrawalNonce(), prevNonce);
            prevNonce = bridge.withdrawalNonce();
        }

        vm.stopPrank();
    }

    function test_withdrawalRefundAfterDelay() public {
        uint256 amount = 1 * NANOTON_PER_TON;

        vm.prank(admin);
        wTON.mint(user, amount);

        vm.startPrank(user);
        wTON.approve(address(bridge), amount);
        bytes32 wId = bridge.initiateWithdrawal(
            keccak256("ton_recipient"),
            amount
        );
        vm.stopPrank();

        // Cannot refund before delay
        vm.expectRevert();
        bridge.refundWithdrawal(wId);

        // Warp past refund delay (24 hours)
        vm.warp(block.timestamp + 24 hours + 1);

        uint256 balBefore = wTON.balanceOf(user);
        bridge.refundWithdrawal(wId);
        uint256 balAfter = wTON.balanceOf(user);

        assertEq(balAfter - balBefore, amount);

        ITONBridgeAdapter.TONWithdrawal memory w = bridge.getWithdrawal(wId);
        assertEq(
            uint256(w.status),
            uint256(ITONBridgeAdapter.WithdrawalStatus.REFUNDED)
        );
    }

    function test_refundTooEarly() public {
        uint256 amount = 1 * NANOTON_PER_TON;

        vm.prank(admin);
        wTON.mint(user, amount);

        vm.startPrank(user);
        wTON.approve(address(bridge), amount);
        bytes32 wId = bridge.initiateWithdrawal(
            keccak256("ton_recipient"),
            amount
        );
        vm.stopPrank();

        uint256 earliest = block.timestamp + 24 hours;

        vm.expectRevert(
            abi.encodeWithSelector(
                ITONBridgeAdapter.RefundTooEarly.selector,
                block.timestamp,
                earliest
            )
        );
        bridge.refundWithdrawal(wId);
    }

    function test_withdrawalDoubleComplete() public {
        uint256 amount = 1 * NANOTON_PER_TON;

        vm.prank(admin);
        wTON.mint(user, amount);

        vm.startPrank(user);
        wTON.approve(address(bridge), amount);
        bytes32 wId = bridge.initiateWithdrawal(
            keccak256("ton_recipient"),
            amount
        );
        vm.stopPrank();

        ITONBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        ITONBridgeAdapter.TONStateProof memory proof = _buildStateProof();

        // Complete withdrawal
        vm.prank(relayer);
        bridge.completeWithdrawal(
            wId,
            keccak256("ton_tx_complete"),
            proof,
            attestations
        );

        ITONBridgeAdapter.TONWithdrawal memory w = bridge.getWithdrawal(wId);
        assertEq(
            uint256(w.status),
            uint256(ITONBridgeAdapter.WithdrawalStatus.COMPLETED)
        );

        // Second completion should revert
        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                ITONBridgeAdapter.WithdrawalNotPending.selector,
                wId
            )
        );
        bridge.completeWithdrawal(
            wId,
            keccak256("ton_tx_complete_2"),
            proof,
            attestations
        );
    }

    /*//////////////////////////////////////////////////////////////
                        ESCROW LIFECYCLE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_escrowCreateFinishLifecycle() public {
        bytes32 preimage = keccak256("test_preimage_ton");
        bytes32 hashlock = sha256(abi.encodePacked(preimage));

        uint256 finishAfter = block.timestamp + 1 hours;
        uint256 cancelAfter = finishAfter + 12 hours;

        vm.deal(user, 10 ether);
        vm.prank(user);
        bytes32 escrowId = bridge.createEscrow{value: 1 ether}(
            keccak256("ton_party"),
            hashlock,
            finishAfter,
            cancelAfter
        );

        ITONBridgeAdapter.TONEscrow memory e = bridge.getEscrow(escrowId);
        assertEq(
            uint256(e.status),
            uint256(ITONBridgeAdapter.EscrowStatus.ACTIVE)
        );
        assertEq(e.amountNanoton, 1 ether);

        // Finish after timelock
        vm.warp(finishAfter + 1);
        bridge.finishEscrow(escrowId, preimage);

        e = bridge.getEscrow(escrowId);
        assertEq(
            uint256(e.status),
            uint256(ITONBridgeAdapter.EscrowStatus.FINISHED)
        );
        assertEq(e.preimage, preimage);
    }

    function test_escrowCreateCancelLifecycle() public {
        bytes32 hashlock = sha256(abi.encodePacked(keccak256("cancel_ton")));

        uint256 finishAfter = block.timestamp + 2 hours;
        uint256 cancelAfter = finishAfter + 6 hours;

        vm.deal(user, 10 ether);
        vm.prank(user);
        bytes32 escrowId = bridge.createEscrow{value: 0.5 ether}(
            keccak256("ton_party"),
            hashlock,
            finishAfter,
            cancelAfter
        );

        // Cannot cancel before cancelAfter
        vm.expectRevert(ITONBridgeAdapter.EscrowTimelockNotMet.selector);
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
        duration = bound(duration, 1 hours, 30 days);
        uint256 cancel = finish + duration;

        bytes32 hashlock = sha256(abi.encodePacked(keccak256("timelock_ton")));

        vm.deal(user, 1 ether);
        vm.prank(user);
        bytes32 escrowId = bridge.createEscrow{value: 0.1 ether}(
            keccak256("ton_party"),
            hashlock,
            finish,
            cancel
        );

        ITONBridgeAdapter.TONEscrow memory e = bridge.getEscrow(escrowId);
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

        bytes32 hashlock = sha256(abi.encodePacked(keccak256("long_ton")));

        vm.deal(user, 1 ether);
        vm.prank(user);
        vm.expectRevert(ITONBridgeAdapter.InvalidTimelockRange.selector);
        bridge.createEscrow{value: 0.1 ether}(
            keccak256("ton_party"),
            hashlock,
            finish,
            cancel
        );
    }

    function test_escrowDoubleFinish() public {
        bytes32 preimage = keccak256("double_finish_ton");
        bytes32 hashlock = sha256(abi.encodePacked(preimage));

        uint256 finishAfter = block.timestamp + 1 hours;
        uint256 cancelAfter = finishAfter + 12 hours;

        vm.deal(user, 10 ether);
        vm.prank(user);
        bytes32 escrowId = bridge.createEscrow{value: 1 ether}(
            keccak256("ton_party"),
            hashlock,
            finishAfter,
            cancelAfter
        );

        vm.warp(finishAfter + 1);
        bridge.finishEscrow(escrowId, preimage);

        // Second finish should revert
        vm.expectRevert(
            abi.encodeWithSelector(
                ITONBridgeAdapter.EscrowNotActive.selector,
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

        _submitVerifiedBlock(1);
        _submitVerifiedBlock(2);

        ITONBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        ITONBridgeAdapter.TONStateProof memory proof = _buildStateProof();

        vm.prank(caller);
        vm.expectRevert();
        bridge.initiateTONDeposit(
            keccak256("ac_tx"),
            keccak256("sender"),
            user,
            1 * NANOTON_PER_TON,
            1,
            proof,
            attestations
        );
    }

    function testFuzz_onlyOperatorCanCompleteDeposit(address caller) public {
        vm.assume(caller != admin && caller != address(0));

        bytes32 depositId = _initiateDeposit(
            1 * NANOTON_PER_TON,
            keccak256("complete_test")
        );

        vm.prank(caller);
        vm.expectRevert();
        bridge.completeTONDeposit(depositId);
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

        _submitVerifiedBlock(1);
        _submitVerifiedBlock(2);

        ITONBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        ITONBridgeAdapter.TONStateProof memory proof = _buildStateProof();

        vm.prank(relayer);
        vm.expectRevert();
        bridge.initiateTONDeposit(
            keccak256("paused_tx"),
            keccak256("sender"),
            user,
            1 * NANOTON_PER_TON,
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
            keccak256("ton_recipient"),
            1 * NANOTON_PER_TON
        );
    }

    function testFuzz_pauseBlocksEscrow() public {
        bytes32 hashlock = sha256(abi.encodePacked(keccak256("paused_ton")));

        vm.prank(admin);
        bridge.pause();

        vm.deal(user, 1 ether);
        vm.prank(user);
        vm.expectRevert();
        bridge.createEscrow{value: 0.1 ether}(
            keccak256("ton_party"),
            hashlock,
            block.timestamp + 1 hours,
            block.timestamp + 5 hours
        );
    }

    function test_unpauseRestoresDeposits() public {
        vm.prank(admin);
        bridge.pause();

        vm.prank(admin);
        bridge.unpause();

        // Should succeed after unpause
        bytes32 depositId = _initiateDeposit(
            1 * NANOTON_PER_TON,
            keccak256("unpause_tx")
        );

        ITONBridgeAdapter.TONDeposit memory dep = bridge.getDeposit(depositId);
        assertEq(
            uint256(dep.status),
            uint256(ITONBridgeAdapter.DepositStatus.VERIFIED)
        );
    }

    /*//////////////////////////////////////////////////////////////
                       NULLIFIER / PRIVACY TESTS
    //////////////////////////////////////////////////////////////*/

    function test_privateDeposit() public {
        bytes32 depositId = _initiateDeposit(
            1 * NANOTON_PER_TON,
            keccak256("private_tx")
        );

        bytes32 commitment = keccak256("commitment");
        bytes32 nullifier = keccak256("nullifier_1");

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
            1 * NANOTON_PER_TON,
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
                ITONBridgeAdapter.NullifierAlreadyUsed.selector,
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
                      FEE WITHDRAWAL TESTS
    //////////////////////////////////////////////////////////////*/

    function test_feeWithdrawal() public {
        uint256 amount = 10 * NANOTON_PER_TON;
        bytes32 depositId = _initiateDeposit(amount, keccak256("fee_tx"));

        uint256 expectedFee = (amount * 5) / 10_000;
        assertEq(bridge.accumulatedFees(), expectedFee);

        uint256 treasuryBalBefore = wTON.balanceOf(treasury);

        vm.prank(admin);
        bridge.withdrawFees();

        uint256 treasuryBalAfter = wTON.balanceOf(treasury);
        assertEq(treasuryBalAfter - treasuryBalBefore, expectedFee);
        assertEq(bridge.accumulatedFees(), 0);
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
        vm.expectRevert(ITONBridgeAdapter.ZeroAddress.selector);
        bridge.configure(address(0), b, c, sigs, 1);

        vm.prank(admin);
        vm.expectRevert(ITONBridgeAdapter.ZeroAddress.selector);
        bridge.configure(
            a == address(0) ? address(1) : a,
            address(0),
            c,
            sigs,
            1
        );

        vm.prank(admin);
        vm.expectRevert(ITONBridgeAdapter.ZeroAddress.selector);
        bridge.configure(
            a == address(0) ? address(1) : a,
            b == address(0) ? address(1) : b,
            address(0),
            sigs,
            1
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
        vm.expectRevert(ITONBridgeAdapter.ZeroAddress.selector);
        bridge.setTreasury(address(0));
    }

    /*//////////////////////////////////////////////////////////////
                       VIEW FUNCTION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_viewFunctionsReturnDefaults() public view {
        ITONBridgeAdapter.TONDeposit memory dep = bridge.getDeposit(bytes32(0));
        assertEq(dep.amountNanoton, 0);

        ITONBridgeAdapter.TONWithdrawal memory w = bridge.getWithdrawal(
            bytes32(0)
        );
        assertEq(w.amountNanoton, 0);

        ITONBridgeAdapter.TONEscrow memory e = bridge.getEscrow(bytes32(0));
        assertEq(e.amountNanoton, 0);

        ITONBridgeAdapter.MasterchainBlock memory blk = bridge
            .getMasterchainBlock(0);
        assertFalse(blk.verified);
    }

    function test_bridgeStats() public view {
        (
            uint256 deposited,
            uint256 withdrawn,
            uint256 escrowCount,
            ,
            ,
            uint256 fees,
            uint256 latestSeqno
        ) = bridge.getBridgeStats();

        assertEq(deposited, 0);
        assertEq(withdrawn, 0);
        assertEq(escrowCount, 0);
        assertEq(fees, 0);
        assertEq(latestSeqno, 0);
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
