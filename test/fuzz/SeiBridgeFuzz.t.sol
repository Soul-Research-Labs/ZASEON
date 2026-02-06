// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {SeiBridgeAdapter} from "../../contracts/crosschain/SeiBridgeAdapter.sol";
import {ISeiBridgeAdapter} from "../../contracts/interfaces/ISeiBridgeAdapter.sol";
import {MockWrappedSEI} from "../../contracts/mocks/MockWrappedSEI.sol";
import {MockSeiValidatorOracle} from "../../contracts/mocks/MockSeiValidatorOracle.sol";

/**
 * @title SeiBridgeFuzz
 * @notice Foundry fuzz & invariant tests for the SeiBridgeAdapter
 * @dev Tests usei precision (6 decimals), Twin-Turbo block verification,
 *      Tendermint BFT validator attestation, and Sei-specific bridge parameters.
 */
contract SeiBridgeFuzz is Test {
    SeiBridgeAdapter public bridge;
    MockWrappedSEI public wSEI;
    MockSeiValidatorOracle public oracle;

    address public admin = address(0xA);
    address public relayer = address(0xB);
    address public user = address(0xC);
    address public treasury = address(0xD);

    // Validator addresses
    address constant VALIDATOR_1 = address(0x1001);
    address constant VALIDATOR_2 = address(0x1002);
    address constant VALIDATOR_3 = address(0x1003);

    uint256 constant USEI_PER_SEI = 1_000_000; // 1e6
    uint256 constant MIN_DEPOSIT = USEI_PER_SEI / 10; // 0.1 SEI
    uint256 constant MAX_DEPOSIT = 10_000_000 * USEI_PER_SEI;

    function setUp() public {
        vm.startPrank(admin);

        bridge = new SeiBridgeAdapter(admin);
        wSEI = new MockWrappedSEI();
        oracle = new MockSeiValidatorOracle();

        // Register validators with voting power
        oracle.addValidator(VALIDATOR_1, 100);
        oracle.addValidator(VALIDATOR_2, 100);
        oracle.addValidator(VALIDATOR_3, 100);

        // Configure bridge
        bridge.configure(
            address(0x1), // seiBridgeContract
            address(wSEI),
            address(oracle),
            2, // minValidatorSignatures
            8 // requiredBlockConfirmations
        );

        bridge.setTreasury(treasury);
        bridge.grantRole(bridge.RELAYER_ROLE(), relayer);

        // Fund the bridge with wSEI
        wSEI.mint(address(bridge), 100_000_000 * USEI_PER_SEI);

        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                          HELPER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _buildValidatorAttestations()
        internal
        pure
        returns (ISeiBridgeAdapter.ValidatorAttestation[] memory)
    {
        ISeiBridgeAdapter.ValidatorAttestation[]
            memory attestations = new ISeiBridgeAdapter.ValidatorAttestation[](3);

        attestations[0] = ISeiBridgeAdapter.ValidatorAttestation({
            validator: VALIDATOR_1,
            signature: hex"01"
        });
        attestations[1] = ISeiBridgeAdapter.ValidatorAttestation({
            validator: VALIDATOR_2,
            signature: hex"02"
        });
        attestations[2] = ISeiBridgeAdapter.ValidatorAttestation({
            validator: VALIDATOR_3,
            signature: hex"03"
        });

        return attestations;
    }

    function _submitVerifiedBlock(
        uint256 height,
        bytes32 blockHash,
        bytes32 parentHash
    ) internal {
        ISeiBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();

        vm.prank(relayer);
        bridge.submitBlockHeader(
            height,
            blockHash,
            parentHash,
            keccak256(abi.encode("stateRoot", height)),
            keccak256(abi.encode("txRoot", height)),
            keccak256(abi.encode("validatorSet")),
            block.timestamp,
            10, // numTxs
            attestations
        );
    }

    function _buildMerkleProof()
        internal
        pure
        returns (ISeiBridgeAdapter.SeiMerkleProof memory)
    {
        bytes32[] memory proof = new bytes32[](2);
        proof[0] = keccak256("proof_node_0");
        proof[1] = keccak256("proof_node_1");

        return
            ISeiBridgeAdapter.SeiMerkleProof({
                leafHash: keccak256("leaf"),
                proof: proof,
                index: 0
            });
    }

    function _initiateDeposit(
        uint256 amount,
        bytes32 txHash
    ) internal returns (bytes32) {
        // Submit block header first
        _submitVerifiedBlock(1, keccak256("block1"), bytes32(0));

        ISeiBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        ISeiBridgeAdapter.SeiMerkleProof memory proof = _buildMerkleProof();

        vm.prank(relayer);
        return
            bridge.initiateSEIDeposit(
                txHash,
                keccak256("sei_sender"),
                user,
                amount,
                1, // blockHeight
                proof,
                attestations
            );
    }

    /*//////////////////////////////////////////////////////////////
                         CONSTANTS TESTS
    //////////////////////////////////////////////////////////////*/

    function test_constantsAreCorrect() public view {
        assertEq(bridge.SEI_CHAIN_ID(), 1329);
        assertEq(bridge.USEI_PER_SEI(), 1_000_000);
        assertEq(bridge.BRIDGE_FEE_BPS(), 5);
        assertEq(bridge.WITHDRAWAL_REFUND_DELAY(), 36 hours);
        assertEq(bridge.MIN_ESCROW_TIMELOCK(), 1 hours);
        assertEq(bridge.MAX_ESCROW_TIMELOCK(), 30 days);
        assertEq(bridge.DEFAULT_BLOCK_CONFIRMATIONS(), 8);
    }

    function test_constructorRejectsZeroAdmin() public {
        vm.expectRevert(ISeiBridgeAdapter.ZeroAddress.selector);
        new SeiBridgeAdapter(address(0));
    }

    /*//////////////////////////////////////////////////////////////
                         USEI PRECISION TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_useiPrecision(uint256 seiAmount) public pure {
        seiAmount = bound(seiAmount, 1, 1_000_000);
        uint256 usei = seiAmount * USEI_PER_SEI;
        assertEq(usei / USEI_PER_SEI, seiAmount);
        assertEq(usei % USEI_PER_SEI, 0);
    }

    function testFuzz_useiSubUnitDeposit(uint256 usei) public {
        usei = bound(usei, MIN_DEPOSIT, MAX_DEPOSIT);

        bytes32 txHash = keccak256(abi.encode("sei_tx_sub", usei));
        bytes32 depositId = _initiateDeposit(usei, txHash);

        ISeiBridgeAdapter.SEIDeposit memory dep = bridge.getDeposit(depositId);
        assertEq(dep.amountUsei, usei);
        assertEq(dep.fee, (usei * 5) / 10_000);
        assertEq(dep.netAmountUsei, usei - dep.fee);
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
                      BLOCK HEADER VERIFICATION TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_blockHeaderChain(uint8 count) public {
        uint256 n = bound(uint256(count), 1, 20);
        bytes32 prevHash = bytes32(0);

        for (uint256 i = 0; i < n; i++) {
            bytes32 blockHash = keccak256(abi.encode("block", i));
            _submitVerifiedBlock(i, blockHash, prevHash);

            ISeiBridgeAdapter.SeiBlockHeader memory bh = bridge.getBlockHeader(i);
            assertTrue(bh.verified);
            assertEq(bh.blockHash, blockHash);
            assertEq(bh.parentHash, prevHash);

            prevHash = blockHash;
        }

        assertEq(bridge.latestBlockHeight(), n - 1);
    }

    function test_depositRequiresVerifiedBlock() public {
        // Don't submit any block — deposit should fail
        ISeiBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        ISeiBridgeAdapter.SeiMerkleProof memory proof = _buildMerkleProof();

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                ISeiBridgeAdapter.BlockNotVerified.selector,
                999
            )
        );
        bridge.initiateSEIDeposit(
            keccak256("unverified_tx"),
            keccak256("sender"),
            user,
            1 * USEI_PER_SEI,
            999, // non-existent block
            proof,
            attestations
        );
    }

    /*//////////////////////////////////////////////////////////////
                        DEPOSIT TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_depositRejectsAmountBelowMin(uint256 amount) public {
        amount = bound(amount, 1, MIN_DEPOSIT - 1);

        _submitVerifiedBlock(1, keccak256("block_low"), bytes32(0));

        ISeiBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        ISeiBridgeAdapter.SeiMerkleProof memory proof = _buildMerkleProof();

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                ISeiBridgeAdapter.AmountBelowMinimum.selector,
                amount,
                MIN_DEPOSIT
            )
        );
        bridge.initiateSEIDeposit(
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

        _submitVerifiedBlock(1, keccak256("block_high"), bytes32(0));

        ISeiBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        ISeiBridgeAdapter.SeiMerkleProof memory proof = _buildMerkleProof();

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                ISeiBridgeAdapter.AmountAboveMaximum.selector,
                amount,
                MAX_DEPOSIT
            )
        );
        bridge.initiateSEIDeposit(
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

        bytes32 depositId = _initiateDeposit(1 * USEI_PER_SEI, txHash);
        assertTrue(depositId != bytes32(0));

        // Submit another block for second attempt
        _submitVerifiedBlock(2, keccak256("block2"), keccak256("block1"));

        ISeiBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        ISeiBridgeAdapter.SeiMerkleProof memory proof = _buildMerkleProof();

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                ISeiBridgeAdapter.SeiTxAlreadyUsed.selector,
                txHash
            )
        );
        bridge.initiateSEIDeposit(
            txHash,
            keccak256("sender"),
            user,
            1 * USEI_PER_SEI,
            2,
            proof,
            attestations
        );
    }

    function testFuzz_depositNonceOnlyIncreases(uint8 count) public {
        uint256 n = bound(uint256(count), 1, 10);
        uint256 prevNonce = bridge.depositNonce();

        for (uint256 i = 0; i < n; i++) {
            bytes32 txHash = keccak256(abi.encode("nonce_tx", i));
            _submitVerifiedBlock(
                i + 1,
                keccak256(abi.encode("nonce_block", i)),
                i == 0
                    ? bytes32(0)
                    : keccak256(abi.encode("nonce_block", i - 1))
            );

            ISeiBridgeAdapter.ValidatorAttestation[]
                memory attestations = _buildValidatorAttestations();
            ISeiBridgeAdapter.SeiMerkleProof memory proof = _buildMerkleProof();

            vm.prank(relayer);
            bridge.initiateSEIDeposit(
                txHash,
                keccak256("sender"),
                user,
                1 * USEI_PER_SEI,
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
                ISeiBridgeAdapter.AmountBelowMinimum.selector,
                amount,
                MIN_DEPOSIT
            )
        );
        bridge.initiateWithdrawal(keccak256("sei_recipient"), amount);
    }

    function testFuzz_withdrawalRejectsAmountAboveMax(uint256 amount) public {
        amount = bound(amount, MAX_DEPOSIT + 1, type(uint128).max);

        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                ISeiBridgeAdapter.AmountAboveMaximum.selector,
                amount,
                MAX_DEPOSIT
            )
        );
        bridge.initiateWithdrawal(keccak256("sei_recipient"), amount);
    }

    function testFuzz_withdrawalNonceOnlyIncreases(uint8 count) public {
        uint256 n = bound(uint256(count), 1, 10);
        uint256 amount = 1 * USEI_PER_SEI;

        // Mint wSEI to user for withdrawals
        vm.prank(admin);
        wSEI.mint(user, amount * n);

        vm.startPrank(user);
        wSEI.approve(address(bridge), amount * n);

        uint256 prevNonce = bridge.withdrawalNonce();
        for (uint256 i = 0; i < n; i++) {
            bridge.initiateWithdrawal(keccak256("sei_recipient"), amount);
            assertGt(bridge.withdrawalNonce(), prevNonce);
            prevNonce = bridge.withdrawalNonce();
        }

        vm.stopPrank();
    }

    function test_withdrawalRefundAfterDelay() public {
        uint256 amount = 1 * USEI_PER_SEI;

        vm.prank(admin);
        wSEI.mint(user, amount);

        vm.startPrank(user);
        wSEI.approve(address(bridge), amount);
        bytes32 wId = bridge.initiateWithdrawal(
            keccak256("sei_recipient"),
            amount
        );
        vm.stopPrank();

        // Cannot refund before delay
        vm.expectRevert();
        bridge.refundWithdrawal(wId);

        // Warp past refund delay (36 hours)
        vm.warp(block.timestamp + 36 hours + 1);

        uint256 balBefore = wSEI.balanceOf(user);
        bridge.refundWithdrawal(wId);
        uint256 balAfter = wSEI.balanceOf(user);

        assertEq(balAfter - balBefore, amount);

        ISeiBridgeAdapter.SEIWithdrawal memory w = bridge.getWithdrawal(wId);
        assertEq(
            uint256(w.status),
            uint256(ISeiBridgeAdapter.WithdrawalStatus.REFUNDED)
        );
    }

    /*//////////////////////////////////////////////////////////////
                        ESCROW LIFECYCLE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_escrowCreateFinishLifecycle() public {
        bytes32 preimage = keccak256("test_preimage_sei");
        bytes32 hashlock = sha256(abi.encodePacked(preimage));

        uint256 finishAfter = block.timestamp + 1 hours;
        uint256 cancelAfter = finishAfter + 12 hours;

        vm.deal(user, 10 ether);
        vm.prank(user);
        bytes32 escrowId = bridge.createEscrow{value: 1 ether}(
            keccak256("sei_party"),
            hashlock,
            finishAfter,
            cancelAfter
        );

        ISeiBridgeAdapter.SEIEscrow memory e = bridge.getEscrow(escrowId);
        assertEq(
            uint256(e.status),
            uint256(ISeiBridgeAdapter.EscrowStatus.ACTIVE)
        );
        assertEq(e.amountUsei, 1 ether);

        // Finish after timelock
        vm.warp(finishAfter + 1);
        bridge.finishEscrow(escrowId, preimage);

        e = bridge.getEscrow(escrowId);
        assertEq(
            uint256(e.status),
            uint256(ISeiBridgeAdapter.EscrowStatus.FINISHED)
        );
        assertEq(e.preimage, preimage);
    }

    function test_escrowCreateCancelLifecycle() public {
        bytes32 hashlock = sha256(abi.encodePacked(keccak256("cancel_sei")));

        uint256 finishAfter = block.timestamp + 2 hours;
        uint256 cancelAfter = finishAfter + 6 hours;

        vm.deal(user, 10 ether);
        vm.prank(user);
        bytes32 escrowId = bridge.createEscrow{value: 0.5 ether}(
            keccak256("sei_party"),
            hashlock,
            finishAfter,
            cancelAfter
        );

        // Cannot cancel before cancelAfter
        vm.expectRevert(ISeiBridgeAdapter.EscrowTimelockNotMet.selector);
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

        bytes32 hashlock = sha256(abi.encodePacked(keccak256("timelock_sei")));

        vm.deal(user, 1 ether);
        vm.prank(user);
        bytes32 escrowId = bridge.createEscrow{value: 0.1 ether}(
            keccak256("sei_party"),
            hashlock,
            finish,
            cancel
        );

        ISeiBridgeAdapter.SEIEscrow memory e = bridge.getEscrow(escrowId);
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

        bytes32 hashlock = sha256(abi.encodePacked(keccak256("long_sei")));

        vm.deal(user, 1 ether);
        vm.prank(user);
        vm.expectRevert(ISeiBridgeAdapter.InvalidTimelockRange.selector);
        bridge.createEscrow{value: 0.1 ether}(
            keccak256("sei_party"),
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

        _submitVerifiedBlock(1, keccak256("block_ac"), bytes32(0));

        ISeiBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        ISeiBridgeAdapter.SeiMerkleProof memory proof = _buildMerkleProof();

        vm.prank(caller);
        vm.expectRevert();
        bridge.initiateSEIDeposit(
            keccak256("ac_tx"),
            keccak256("sender"),
            user,
            1 * USEI_PER_SEI,
            1,
            proof,
            attestations
        );
    }

    function testFuzz_onlyOperatorCanCompleteDeposit(address caller) public {
        vm.assume(caller != admin && caller != address(0));

        bytes32 depositId = _initiateDeposit(
            1 * USEI_PER_SEI,
            keccak256("complete_test")
        );

        vm.prank(caller);
        vm.expectRevert();
        bridge.completeSEIDeposit(depositId);
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

        _submitVerifiedBlock(1, keccak256("block_pause"), bytes32(0));

        ISeiBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        ISeiBridgeAdapter.SeiMerkleProof memory proof = _buildMerkleProof();

        vm.prank(relayer);
        vm.expectRevert();
        bridge.initiateSEIDeposit(
            keccak256("paused_tx"),
            keccak256("sender"),
            user,
            1 * USEI_PER_SEI,
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
        bridge.initiateWithdrawal(keccak256("sei_recipient"), 1 * USEI_PER_SEI);
    }

    function testFuzz_pauseBlocksEscrow() public {
        bytes32 hashlock = sha256(abi.encodePacked(keccak256("paused_sei")));

        vm.prank(admin);
        bridge.pause();

        vm.deal(user, 1 ether);
        vm.prank(user);
        vm.expectRevert();
        bridge.createEscrow{value: 0.1 ether}(
            keccak256("sei_party"),
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
            1 * USEI_PER_SEI,
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
                ISeiBridgeAdapter.NullifierAlreadyUsed.selector,
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
        vm.expectRevert(ISeiBridgeAdapter.ZeroAddress.selector);
        bridge.configure(address(0), b, c, sigs, 8);

        vm.prank(admin);
        vm.expectRevert(ISeiBridgeAdapter.ZeroAddress.selector);
        bridge.configure(a == address(0) ? address(1) : a, address(0), c, sigs, 8);
    }

    function test_treasuryCanBeUpdated() public {
        address newTreasury = address(0xF1);
        vm.prank(admin);
        bridge.setTreasury(newTreasury);
        assertEq(bridge.treasury(), newTreasury);
    }

    function test_treasuryRejectsZeroAddress() public {
        vm.prank(admin);
        vm.expectRevert(ISeiBridgeAdapter.ZeroAddress.selector);
        bridge.setTreasury(address(0));
    }

    /*//////////////////////////////////////////////////////////////
                       VIEW FUNCTION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_viewFunctionsReturnDefaults() public view {
        ISeiBridgeAdapter.SEIDeposit memory dep = bridge.getDeposit(
            bytes32(0)
        );
        assertEq(dep.amountUsei, 0);

        ISeiBridgeAdapter.SEIWithdrawal memory w = bridge.getWithdrawal(
            bytes32(0)
        );
        assertEq(w.amountUsei, 0);

        ISeiBridgeAdapter.SEIEscrow memory e = bridge.getEscrow(bytes32(0));
        assertEq(e.amountUsei, 0);

        ISeiBridgeAdapter.SeiBlockHeader memory bh = bridge.getBlockHeader(0);
        assertFalse(bh.verified);
    }

    function test_statisticsTracking() public view {
        (
            uint256 deposited,
            uint256 withdrawn,
            uint256 escrowCount,
            ,
            ,
            uint256 fees,
            uint256 latestHeight
        ) = bridge.getBridgeStats();

        assertEq(deposited, 0);
        assertEq(withdrawn, 0);
        assertEq(escrowCount, 0);
        assertEq(fees, 0);
        assertEq(latestHeight, 0);
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
