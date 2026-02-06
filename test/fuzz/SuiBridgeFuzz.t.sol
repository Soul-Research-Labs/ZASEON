// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {SuiBridgeAdapter} from "../../contracts/crosschain/SuiBridgeAdapter.sol";
import {ISuiBridgeAdapter} from "../../contracts/interfaces/ISuiBridgeAdapter.sol";
import {MockWrappedSUI} from "../../contracts/mocks/MockWrappedSUI.sol";
import {MockSuiValidatorOracle} from "../../contracts/mocks/MockSuiValidatorOracle.sol";

/**
 * @title SuiBridgeFuzz
 * @notice Foundry fuzz & invariant tests for the SuiBridgeAdapter
 * @dev Tests MIST precision (9 decimals), checkpoint verification,
 *      validator committee attestation, and Sui-specific bridge parameters.
 */
contract SuiBridgeFuzz is Test {
    SuiBridgeAdapter public bridge;
    MockWrappedSUI public wSUI;
    MockSuiValidatorOracle public oracle;

    address public admin = address(0xA);
    address public relayer = address(0xB);
    address public user = address(0xC);
    address public treasury = address(0xD);

    // Validator BLS public key hashes (mock)
    bytes32 constant VALIDATOR_1 = keccak256("sui_validator_1");
    bytes32 constant VALIDATOR_2 = keccak256("sui_validator_2");
    bytes32 constant VALIDATOR_3 = keccak256("sui_validator_3");

    uint256 constant MIST_PER_SUI = 1_000_000_000; // 1e9
    uint256 constant MIN_DEPOSIT = MIST_PER_SUI / 10; // 0.1 SUI
    uint256 constant MAX_DEPOSIT = 10_000_000 * MIST_PER_SUI;

    function setUp() public {
        vm.startPrank(admin);

        bridge = new SuiBridgeAdapter(admin);
        wSUI = new MockWrappedSUI();
        oracle = new MockSuiValidatorOracle();

        // Register validators
        oracle.addValidator(VALIDATOR_1);
        oracle.addValidator(VALIDATOR_2);
        oracle.addValidator(VALIDATOR_3);

        // Configure bridge
        bridge.configure(
            address(0x1), // suiBridgeContract
            address(wSUI),
            address(oracle),
            2, // minCommitteeSignatures
            10 // requiredCheckpointConfirmations
        );

        bridge.setTreasury(treasury);
        bridge.grantRole(bridge.RELAYER_ROLE(), relayer);

        // Fund the bridge with wSUI
        wSUI.mint(address(bridge), 100_000_000 * MIST_PER_SUI);

        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                          HELPER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _buildValidatorAttestations()
        internal
        pure
        returns (ISuiBridgeAdapter.ValidatorAttestation[] memory)
    {
        ISuiBridgeAdapter.ValidatorAttestation[]
            memory attestations = new ISuiBridgeAdapter.ValidatorAttestation[](3);

        attestations[0] = ISuiBridgeAdapter.ValidatorAttestation({
            validatorPublicKey: VALIDATOR_1,
            signature: hex"01"
        });
        attestations[1] = ISuiBridgeAdapter.ValidatorAttestation({
            validatorPublicKey: VALIDATOR_2,
            signature: hex"02"
        });
        attestations[2] = ISuiBridgeAdapter.ValidatorAttestation({
            validatorPublicKey: VALIDATOR_3,
            signature: hex"03"
        });

        return attestations;
    }

    function _submitVerifiedCheckpoint(
        uint256 seq,
        bytes32 digest,
        bytes32 prevDigest,
        uint256 epoch
    ) internal {
        ISuiBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();

        vm.prank(relayer);
        bridge.submitCheckpoint(
            seq,
            digest,
            prevDigest,
            keccak256(abi.encode("txRoot", seq)),
            keccak256(abi.encode("effectsRoot", seq)),
            epoch,
            keccak256(abi.encode("validatorSet", epoch)),
            block.timestamp * 1000, // timestampMs
            attestations
        );
    }

    function _buildObjectProof()
        internal
        pure
        returns (ISuiBridgeAdapter.SuiObjectProof memory)
    {
        bytes32[] memory proof = new bytes32[](2);
        proof[0] = keccak256("proof_node_0");
        proof[1] = keccak256("proof_node_1");

        return
            ISuiBridgeAdapter.SuiObjectProof({
                objectId: keccak256("objectId"),
                version: 1,
                objectDigest: keccak256("objectDigest"),
                proof: proof,
                proofIndex: 0
            });
    }

    function _initiateDeposit(
        uint256 amount,
        bytes32 txDigest
    ) internal returns (bytes32) {
        // Submit checkpoint first
        _submitVerifiedCheckpoint(1, keccak256("cp1"), bytes32(0), 1);

        ISuiBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        ISuiBridgeAdapter.SuiObjectProof memory proof = _buildObjectProof();

        vm.prank(relayer);
        return
            bridge.initiateSUIDeposit(
                txDigest,
                keccak256("sui_sender"),
                user,
                amount,
                1, // checkpointSequence
                proof,
                attestations
            );
    }

    /*//////////////////////////////////////////////////////////////
                         CONSTANTS TESTS
    //////////////////////////////////////////////////////////////*/

    function test_constantsAreCorrect() public view {
        assertEq(bridge.SUI_CHAIN_ID(), 784);
        assertEq(bridge.MIST_PER_SUI(), 1_000_000_000);
        assertEq(bridge.BRIDGE_FEE_BPS(), 6);
        assertEq(bridge.WITHDRAWAL_REFUND_DELAY(), 48 hours);
        assertEq(bridge.MIN_ESCROW_TIMELOCK(), 1 hours);
        assertEq(bridge.MAX_ESCROW_TIMELOCK(), 30 days);
        assertEq(bridge.DEFAULT_CHECKPOINT_CONFIRMATIONS(), 10);
    }

    function test_constructorRejectsZeroAdmin() public {
        vm.expectRevert(ISuiBridgeAdapter.ZeroAddress.selector);
        new SuiBridgeAdapter(address(0));
    }

    /*//////////////////////////////////////////////////////////////
                         MIST PRECISION TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_mistPrecision(uint256 suiAmount) public pure {
        suiAmount = bound(suiAmount, 1, 1_000_000);
        uint256 mist = suiAmount * MIST_PER_SUI;
        assertEq(mist / MIST_PER_SUI, suiAmount);
        assertEq(mist % MIST_PER_SUI, 0);
    }

    function testFuzz_mistSubUnitDeposit(uint256 mist) public {
        mist = bound(mist, MIN_DEPOSIT, MAX_DEPOSIT);

        bytes32 txDigest = keccak256(abi.encode("sui_tx_sub", mist));
        bytes32 depositId = _initiateDeposit(mist, txDigest);

        ISuiBridgeAdapter.SUIDeposit memory dep = bridge.getDeposit(depositId);
        assertEq(dep.amountMist, mist);
        assertEq(dep.fee, (mist * 6) / 10_000);
        assertEq(dep.netAmountMist, mist - dep.fee);
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
                      CHECKPOINT VERIFICATION TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_checkpointChain(uint8 count) public {
        uint256 n = bound(uint256(count), 1, 20);
        bytes32 prevDigest = bytes32(0);

        for (uint256 i = 0; i < n; i++) {
            bytes32 digest = keccak256(abi.encode("checkpoint", i));
            _submitVerifiedCheckpoint(i, digest, prevDigest, 1);

            ISuiBridgeAdapter.SuiCheckpoint memory cp = bridge.getCheckpoint(i);
            assertTrue(cp.verified);
            assertEq(cp.digest, digest);
            assertEq(cp.previousDigest, prevDigest);
            assertEq(cp.epoch, 1);

            prevDigest = digest;
        }

        assertEq(bridge.latestCheckpointSequence(), n - 1);
    }

    function test_depositRequiresVerifiedCheckpoint() public {
        // Don't submit any checkpoint — deposit should fail
        ISuiBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        ISuiBridgeAdapter.SuiObjectProof memory proof = _buildObjectProof();

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                ISuiBridgeAdapter.CheckpointNotVerified.selector,
                999
            )
        );
        bridge.initiateSUIDeposit(
            keccak256("unverified_tx"),
            keccak256("sender"),
            user,
            1 * MIST_PER_SUI,
            999, // non-existent checkpoint
            proof,
            attestations
        );
    }

    function test_epochTracking() public {
        // Submit checkpoints across epochs
        _submitVerifiedCheckpoint(0, keccak256("cp0"), bytes32(0), 1);
        assertEq(bridge.currentEpoch(), 1);

        _submitVerifiedCheckpoint(1, keccak256("cp1"), keccak256("cp0"), 2);
        assertEq(bridge.currentEpoch(), 2);

        _submitVerifiedCheckpoint(2, keccak256("cp2"), keccak256("cp1"), 5);
        assertEq(bridge.currentEpoch(), 5);
    }

    /*//////////////////////////////////////////////////////////////
                        DEPOSIT TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_depositRejectsAmountBelowMin(uint256 amount) public {
        amount = bound(amount, 1, MIN_DEPOSIT - 1);

        _submitVerifiedCheckpoint(1, keccak256("cp1"), bytes32(0), 1);

        ISuiBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        ISuiBridgeAdapter.SuiObjectProof memory proof = _buildObjectProof();

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                ISuiBridgeAdapter.AmountBelowMinimum.selector,
                amount,
                MIN_DEPOSIT
            )
        );
        bridge.initiateSUIDeposit(
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

        _submitVerifiedCheckpoint(1, keccak256("cp1"), bytes32(0), 1);

        ISuiBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        ISuiBridgeAdapter.SuiObjectProof memory proof = _buildObjectProof();

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                ISuiBridgeAdapter.AmountAboveMaximum.selector,
                amount,
                MAX_DEPOSIT
            )
        );
        bridge.initiateSUIDeposit(
            keccak256(abi.encode("tx_high", amount)),
            keccak256("sender"),
            user,
            amount,
            1,
            proof,
            attestations
        );
    }

    function testFuzz_txDigestReplayProtection(bytes32 txDigest) public {
        vm.assume(txDigest != bytes32(0));

        bytes32 depositId = _initiateDeposit(1 * MIST_PER_SUI, txDigest);
        assertTrue(depositId != bytes32(0));

        // Re-submit same checkpoint for second attempt
        _submitVerifiedCheckpoint(2, keccak256("cp2"), keccak256("cp1"), 1);

        ISuiBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        ISuiBridgeAdapter.SuiObjectProof memory proof = _buildObjectProof();

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                ISuiBridgeAdapter.SuiTxAlreadyUsed.selector,
                txDigest
            )
        );
        bridge.initiateSUIDeposit(
            txDigest,
            keccak256("sender"),
            user,
            1 * MIST_PER_SUI,
            2,
            proof,
            attestations
        );
    }

    function testFuzz_depositNonceOnlyIncreases(uint8 count) public {
        uint256 n = bound(uint256(count), 1, 10);
        uint256 prevNonce = bridge.depositNonce();

        for (uint256 i = 0; i < n; i++) {
            bytes32 txDigest = keccak256(abi.encode("nonce_tx", i));
            _submitVerifiedCheckpoint(
                i + 1,
                keccak256(abi.encode("nonce_cp", i)),
                i == 0
                    ? bytes32(0)
                    : keccak256(abi.encode("nonce_cp", i - 1)),
                1
            );

            ISuiBridgeAdapter.ValidatorAttestation[]
                memory attestations = _buildValidatorAttestations();
            ISuiBridgeAdapter.SuiObjectProof memory proof = _buildObjectProof();

            vm.prank(relayer);
            bridge.initiateSUIDeposit(
                txDigest,
                keccak256("sender"),
                user,
                1 * MIST_PER_SUI,
                i + 1,
                proof,
                attestations
            );

            assertGt(bridge.depositNonce(), prevNonce);
            prevNonce = bridge.depositNonce();
        }
    }

    /*//////////////////////////////////////////////////////////////
                       WITHDRAWAL TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_withdrawalRejectsAmountBelowMin(uint256 amount) public {
        amount = bound(amount, 1, MIN_DEPOSIT - 1);

        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                ISuiBridgeAdapter.AmountBelowMinimum.selector,
                amount,
                MIN_DEPOSIT
            )
        );
        bridge.initiateWithdrawal(keccak256("sui_recipient"), amount);
    }

    function testFuzz_withdrawalRejectsAmountAboveMax(uint256 amount) public {
        amount = bound(amount, MAX_DEPOSIT + 1, type(uint128).max);

        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                ISuiBridgeAdapter.AmountAboveMaximum.selector,
                amount,
                MAX_DEPOSIT
            )
        );
        bridge.initiateWithdrawal(keccak256("sui_recipient"), amount);
    }

    function testFuzz_withdrawalNonceOnlyIncreases(uint8 count) public {
        uint256 n = bound(uint256(count), 1, 10);
        uint256 amount = 1 * MIST_PER_SUI;

        // Mint wSUI to user for withdrawals
        vm.prank(admin);
        wSUI.mint(user, amount * n);

        vm.startPrank(user);
        wSUI.approve(address(bridge), amount * n);

        uint256 prevNonce = bridge.withdrawalNonce();
        for (uint256 i = 0; i < n; i++) {
            bridge.initiateWithdrawal(keccak256("sui_recipient"), amount);
            assertGt(bridge.withdrawalNonce(), prevNonce);
            prevNonce = bridge.withdrawalNonce();
        }

        vm.stopPrank();
    }

    function test_withdrawalRefundAfterDelay() public {
        uint256 amount = 1 * MIST_PER_SUI;

        vm.prank(admin);
        wSUI.mint(user, amount);

        vm.startPrank(user);
        wSUI.approve(address(bridge), amount);
        bytes32 wId = bridge.initiateWithdrawal(
            keccak256("sui_recipient"),
            amount
        );
        vm.stopPrank();

        // Cannot refund before delay
        vm.expectRevert();
        bridge.refundWithdrawal(wId);

        // Warp past refund delay (48 hours)
        vm.warp(block.timestamp + 48 hours + 1);

        uint256 balBefore = wSUI.balanceOf(user);
        bridge.refundWithdrawal(wId);
        uint256 balAfter = wSUI.balanceOf(user);

        assertEq(balAfter - balBefore, amount);

        ISuiBridgeAdapter.SUIWithdrawal memory w = bridge.getWithdrawal(wId);
        assertEq(
            uint256(w.status),
            uint256(ISuiBridgeAdapter.WithdrawalStatus.REFUNDED)
        );
    }

    /*//////////////////////////////////////////////////////////////
                        ESCROW LIFECYCLE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_escrowCreateFinishLifecycle() public {
        bytes32 preimage = keccak256("test_preimage_sui");
        bytes32 hashlock = sha256(abi.encodePacked(preimage));

        uint256 finishAfter = block.timestamp + 1 hours;
        uint256 cancelAfter = finishAfter + 12 hours;

        vm.deal(user, 10 ether);
        vm.prank(user);
        bytes32 escrowId = bridge.createEscrow{value: 1 ether}(
            keccak256("sui_party"),
            hashlock,
            finishAfter,
            cancelAfter
        );

        ISuiBridgeAdapter.SUIEscrow memory e = bridge.getEscrow(escrowId);
        assertEq(
            uint256(e.status),
            uint256(ISuiBridgeAdapter.EscrowStatus.ACTIVE)
        );
        assertEq(e.amountMist, 1 ether);

        // Finish after timelock
        vm.warp(finishAfter + 1);
        bridge.finishEscrow(escrowId, preimage);

        e = bridge.getEscrow(escrowId);
        assertEq(
            uint256(e.status),
            uint256(ISuiBridgeAdapter.EscrowStatus.FINISHED)
        );
        assertEq(e.preimage, preimage);
    }

    function test_escrowCreateCancelLifecycle() public {
        bytes32 hashlock = sha256(abi.encodePacked(keccak256("cancel_sui")));

        uint256 finishAfter = block.timestamp + 2 hours;
        uint256 cancelAfter = finishAfter + 6 hours;

        vm.deal(user, 10 ether);
        vm.prank(user);
        bytes32 escrowId = bridge.createEscrow{value: 0.5 ether}(
            keccak256("sui_party"),
            hashlock,
            finishAfter,
            cancelAfter
        );

        // Cannot cancel before cancelAfter
        vm.expectRevert(ISuiBridgeAdapter.EscrowTimelockNotMet.selector);
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

        bytes32 hashlock = sha256(abi.encodePacked(keccak256("timelock_sui")));

        vm.deal(user, 1 ether);
        vm.prank(user);
        bytes32 escrowId = bridge.createEscrow{value: 0.1 ether}(
            keccak256("sui_party"),
            hashlock,
            finish,
            cancel
        );

        ISuiBridgeAdapter.SUIEscrow memory e = bridge.getEscrow(escrowId);
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

        bytes32 hashlock = sha256(abi.encodePacked(keccak256("long_sui")));

        vm.deal(user, 1 ether);
        vm.prank(user);
        vm.expectRevert(ISuiBridgeAdapter.InvalidTimelockRange.selector);
        bridge.createEscrow{value: 0.1 ether}(
            keccak256("sui_party"),
            hashlock,
            finish,
            cancel
        );
    }

    /*//////////////////////////////////////////////////////////////
                        ACCESS CONTROL TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_onlyRelayerCanInitiateDeposit(address caller) public {
        vm.assume(caller != relayer && caller != admin && caller != address(0));

        _submitVerifiedCheckpoint(1, keccak256("cp_ac"), bytes32(0), 1);

        ISuiBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        ISuiBridgeAdapter.SuiObjectProof memory proof = _buildObjectProof();

        vm.prank(caller);
        vm.expectRevert();
        bridge.initiateSUIDeposit(
            keccak256("ac_tx"),
            keccak256("sender"),
            user,
            1 * MIST_PER_SUI,
            1,
            proof,
            attestations
        );
    }

    function testFuzz_onlyOperatorCanCompleteDeposit(address caller) public {
        vm.assume(caller != admin && caller != address(0));

        bytes32 depositId = _initiateDeposit(
            1 * MIST_PER_SUI,
            keccak256("complete_test")
        );

        vm.prank(caller);
        vm.expectRevert();
        bridge.completeSUIDeposit(depositId);
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

        _submitVerifiedCheckpoint(1, keccak256("cp_pause"), bytes32(0), 1);

        ISuiBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        ISuiBridgeAdapter.SuiObjectProof memory proof = _buildObjectProof();

        vm.prank(relayer);
        vm.expectRevert();
        bridge.initiateSUIDeposit(
            keccak256("paused_tx"),
            keccak256("sender"),
            user,
            1 * MIST_PER_SUI,
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
        bridge.initiateWithdrawal(keccak256("sui_recipient"), 1 * MIST_PER_SUI);
    }

    function testFuzz_pauseBlocksEscrow() public {
        bytes32 hashlock = sha256(abi.encodePacked(keccak256("paused_sui")));

        vm.prank(admin);
        bridge.pause();

        vm.deal(user, 1 ether);
        vm.prank(user);
        vm.expectRevert();
        bridge.createEscrow{value: 0.1 ether}(
            keccak256("sui_party"),
            hashlock,
            block.timestamp + 1 hours,
            block.timestamp + 5 hours
        );
    }

    /*//////////////////////////////////////////////////////////////
                       NULLIFIER / PRIVACY TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_nullifierCannotBeReused(bytes32 nullifier) public {
        vm.assume(nullifier != bytes32(0));

        bytes32 depositId = _initiateDeposit(
            1 * MIST_PER_SUI,
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
                ISuiBridgeAdapter.NullifierAlreadyUsed.selector,
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
        // At least one address is zero
        vm.prank(admin);
        vm.expectRevert(ISuiBridgeAdapter.ZeroAddress.selector);
        bridge.configure(address(0), b, c, sigs, 10);

        vm.prank(admin);
        vm.expectRevert(ISuiBridgeAdapter.ZeroAddress.selector);
        bridge.configure(a == address(0) ? address(1) : a, address(0), c, sigs, 10);
    }

    function test_treasuryCanBeUpdated() public {
        address newTreasury = address(0xF1);
        vm.prank(admin);
        bridge.setTreasury(newTreasury);
        assertEq(bridge.treasury(), newTreasury);
    }

    function test_treasuryRejectsZeroAddress() public {
        vm.prank(admin);
        vm.expectRevert(ISuiBridgeAdapter.ZeroAddress.selector);
        bridge.setTreasury(address(0));
    }

    /*//////////////////////////////////////////////////////////////
                       VIEW FUNCTION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_viewFunctionsReturnDefaults() public view {
        ISuiBridgeAdapter.SUIDeposit memory dep = bridge.getDeposit(
            bytes32(0)
        );
        assertEq(dep.amountMist, 0);

        ISuiBridgeAdapter.SUIWithdrawal memory w = bridge.getWithdrawal(
            bytes32(0)
        );
        assertEq(w.amountMist, 0);

        ISuiBridgeAdapter.SUIEscrow memory e = bridge.getEscrow(bytes32(0));
        assertEq(e.amountMist, 0);

        ISuiBridgeAdapter.SuiCheckpoint memory cp = bridge.getCheckpoint(0);
        assertFalse(cp.verified);
    }

    function test_statisticsTracking() public view {
        (
            uint256 deposited,
            uint256 withdrawn,
            uint256 escrowCount,
            ,
            ,
            uint256 fees,
            uint256 latestCp
        ) = bridge.getBridgeStats();

        assertEq(deposited, 0);
        assertEq(withdrawn, 0);
        assertEq(escrowCount, 0);
        assertEq(fees, 0);
        assertEq(latestCp, 0);
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
