// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {PolkadotBridgeAdapter} from "../../contracts/crosschain/PolkadotBridgeAdapter.sol";
import {IPolkadotBridgeAdapter} from "../../contracts/interfaces/IPolkadotBridgeAdapter.sol";
import {MockWrappedDOT} from "../../contracts/mocks/MockWrappedDOT.sol";
import {MockPolkadotGrandpaOracle} from "../../contracts/mocks/MockPolkadotGrandpaOracle.sol";

/**
 * @title PolkadotBridgeFuzz
 * @notice Foundry fuzz & invariant tests for the PolkadotBridgeAdapter
 * @dev Tests Planck precision (10 decimals), GRANDPA header verification,
 *      validator attestation, and Polkadot-specific bridge parameters.
 */
contract PolkadotBridgeFuzz is Test {
    PolkadotBridgeAdapter public bridge;
    MockWrappedDOT public wDOT;
    MockPolkadotGrandpaOracle public oracle;

    address public admin = address(0xA);
    address public relayer = address(0xB);
    address public user = address(0xC);
    address public treasury = address(0xD);

    // Validator addresses
    address constant VALIDATOR_1 = address(0x2001);
    address constant VALIDATOR_2 = address(0x2002);
    address constant VALIDATOR_3 = address(0x2003);

    uint256 constant PLANCK_PER_DOT = 10_000_000_000; // 1e10
    uint256 constant MIN_DEPOSIT = PLANCK_PER_DOT / 10; // 0.1 DOT
    uint256 constant MAX_DEPOSIT = 10_000_000 * PLANCK_PER_DOT;

    function setUp() public {
        vm.startPrank(admin);

        bridge = new PolkadotBridgeAdapter(admin);
        wDOT = new MockWrappedDOT();
        oracle = new MockPolkadotGrandpaOracle();

        // Register validators with voting power
        oracle.addValidator(VALIDATOR_1, 100);
        oracle.addValidator(VALIDATOR_2, 100);
        oracle.addValidator(VALIDATOR_3, 100);

        // Configure bridge
        bridge.configure(
            address(0x1), // polkadotBridgeContract
            address(wDOT),
            address(oracle),
            2, // minValidatorSignatures
            2 // requiredConfirmations
        );

        bridge.setTreasury(treasury);
        bridge.grantRole(bridge.RELAYER_ROLE(), relayer);

        // Fund the bridge with wDOT (100M DOT in Planck)
        wDOT.mint(address(bridge), 100_000_000 * PLANCK_PER_DOT);

        vm.stopPrank();
    }

    // Needed for escrow cancel refunds
    receive() external payable {}

    /*//////////////////////////////////////////////////////////////
                          HELPER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _buildValidatorAttestations()
        internal
        pure
        returns (IPolkadotBridgeAdapter.ValidatorAttestation[] memory)
    {
        IPolkadotBridgeAdapter.ValidatorAttestation[]
            memory attestations = new IPolkadotBridgeAdapter.ValidatorAttestation[](
                3
            );

        attestations[0] = IPolkadotBridgeAdapter.ValidatorAttestation({
            validator: VALIDATOR_1,
            signature: hex"01"
        });
        attestations[1] = IPolkadotBridgeAdapter.ValidatorAttestation({
            validator: VALIDATOR_2,
            signature: hex"02"
        });
        attestations[2] = IPolkadotBridgeAdapter.ValidatorAttestation({
            validator: VALIDATOR_3,
            signature: hex"03"
        });

        return attestations;
    }

    function _submitVerifiedHeader(
        uint256 blockNumber,
        bytes32 blockHash
    ) internal {
        IPolkadotBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();

        vm.prank(relayer);
        bridge.submitGrandpaHeader(
            blockNumber,
            blockHash,
            keccak256(abi.encode("parentHash", blockNumber)),
            keccak256(abi.encode("stateRoot", blockNumber)),
            keccak256(abi.encode("extrinsicsRoot", blockNumber)),
            1, // setId
            block.timestamp,
            attestations
        );
    }

    function _buildStateProof()
        internal
        pure
        returns (IPolkadotBridgeAdapter.SubstrateStateProof memory)
    {
        bytes32[] memory proof = new bytes32[](2);
        proof[0] = keccak256("proof_node_0");
        proof[1] = keccak256("proof_node_1");

        return
            IPolkadotBridgeAdapter.SubstrateStateProof({
                merkleProof: proof,
                storageKey: keccak256("storage_key"),
                value: hex"01"
            });
    }

    function _initiateDeposit(
        uint256 amount,
        bytes32 txHash
    ) internal returns (bytes32) {
        // Submit GRANDPA header first
        _submitVerifiedHeader(1, keccak256("header1"));

        IPolkadotBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        IPolkadotBridgeAdapter.SubstrateStateProof
            memory proof = _buildStateProof();

        vm.prank(relayer);
        return
            bridge.initiateDOTDeposit(
                txHash,
                keccak256("substrate_sender"),
                user,
                amount,
                1, // relayBlockNumber
                proof,
                attestations
            );
    }

    /*//////////////////////////////////////////////////////////////
                         CONSTANTS TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice 1. Verify all bridge constants are correctly set
    function test_constantsAreCorrect() public view {
        assertEq(bridge.POLKADOT_CHAIN_ID(), 0);
        assertEq(bridge.PLANCK_PER_DOT(), 10_000_000_000);
        assertEq(bridge.BRIDGE_FEE_BPS(), 6);
        assertEq(bridge.WITHDRAWAL_REFUND_DELAY(), 24 hours);
        assertEq(bridge.MIN_ESCROW_TIMELOCK(), 1 hours);
        assertEq(bridge.MAX_ESCROW_TIMELOCK(), 30 days);
        assertEq(bridge.DEFAULT_FINALITY_CONFIRMATIONS(), 2);
        assertEq(bridge.MIN_DEPOSIT_PLANCK(), PLANCK_PER_DOT / 10);
        assertEq(bridge.MAX_DEPOSIT_PLANCK(), 10_000_000 * PLANCK_PER_DOT);
        assertEq(bridge.BPS_DENOMINATOR(), 10_000);
    }

    /// @notice 2. Constructor rejects zero admin address
    function test_constructorRejectsZeroAdmin() public {
        vm.expectRevert(IPolkadotBridgeAdapter.ZeroAddress.selector);
        new PolkadotBridgeAdapter(address(0));
    }

    /*//////////////////////////////////////////////////////////////
                       PLANCK PRECISION TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice 3. DOT <-> Planck conversion is lossless
    function testFuzz_planckPrecision(uint256 dotAmount) public pure {
        dotAmount = bound(dotAmount, 1, 1_000_000);
        uint256 planck = dotAmount * PLANCK_PER_DOT;
        assertEq(planck / PLANCK_PER_DOT, dotAmount);
        assertEq(planck % PLANCK_PER_DOT, 0);
    }

    /// @notice 4. Deposits with sub-DOT Planck precision are tracked exactly
    function testFuzz_planckSubUnitDeposit(uint256 planck) public {
        planck = bound(planck, MIN_DEPOSIT, MAX_DEPOSIT);

        bytes32 txHash = keccak256(abi.encode("dot_tx_sub", planck));
        bytes32 depositId = _initiateDeposit(planck, txHash);

        IPolkadotBridgeAdapter.DOTDeposit memory dep = bridge.getDeposit(
            depositId
        );
        assertEq(dep.amountPlanck, planck);
        assertEq(dep.fee, (planck * 6) / 10_000);
        assertEq(dep.netAmountPlanck, planck - dep.fee);
    }

    /*//////////////////////////////////////////////////////////////
                        FEE CALCULATION TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice 5. Fee calculation uses 6 BPS correctly
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
                   GRANDPA HEADER VERIFICATION TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice 6. Chained GRANDPA headers are all verified and latest block tracked
    function testFuzz_grandpaHeaderChain(uint8 count) public {
        uint256 n = bound(uint256(count), 1, 20);

        for (uint256 i = 0; i < n; i++) {
            bytes32 blockHash = keccak256(abi.encode("header", i));
            _submitVerifiedHeader(i + 1, blockHash);

            IPolkadotBridgeAdapter.GrandpaHeader memory hdr = bridge
                .getGrandpaHeader(i + 1);
            assertTrue(hdr.verified);
            assertEq(hdr.blockHash, blockHash);
        }

        assertEq(bridge.latestRelayBlock(), n);
    }

    /// @notice 7. Deposit requires a verified GRANDPA header at the relay block
    function test_depositRequiresVerifiedHeader() public {
        // Don't submit any GRANDPA header — deposit should fail
        IPolkadotBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        IPolkadotBridgeAdapter.SubstrateStateProof
            memory proof = _buildStateProof();

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                IPolkadotBridgeAdapter.RelayBlockNotVerified.selector,
                999
            )
        );
        bridge.initiateDOTDeposit(
            keccak256("unverified_tx"),
            keccak256("sender"),
            user,
            1 * PLANCK_PER_DOT,
            999, // non-existent relay block
            proof,
            attestations
        );
    }

    /*//////////////////////////////////////////////////////////////
                          DEPOSIT TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice 8. Full deposit round-trip: initiate + complete
    function testFuzz_depositRoundTrip(uint256 amount) public {
        amount = bound(amount, MIN_DEPOSIT, MAX_DEPOSIT);

        bytes32 txHash = keccak256(abi.encode("roundtrip_tx", amount));
        bytes32 depositId = _initiateDeposit(amount, txHash);

        IPolkadotBridgeAdapter.DOTDeposit memory dep = bridge.getDeposit(
            depositId
        );
        assertEq(
            uint256(dep.status),
            uint256(IPolkadotBridgeAdapter.DepositStatus.VERIFIED)
        );

        uint256 balBefore = wDOT.balanceOf(user);

        // Complete the deposit (admin has OPERATOR_ROLE)
        vm.prank(admin);
        bridge.completeDOTDeposit(depositId);

        uint256 balAfter = wDOT.balanceOf(user);
        assertEq(balAfter - balBefore, dep.netAmountPlanck);

        dep = bridge.getDeposit(depositId);
        assertEq(
            uint256(dep.status),
            uint256(IPolkadotBridgeAdapter.DepositStatus.COMPLETED)
        );
    }

    /// @notice 9. Deposit amount bounds are enforced
    function testFuzz_depositAmountBounds(uint256 amount) public {
        amount = bound(amount, MIN_DEPOSIT, MAX_DEPOSIT);

        bytes32 txHash = keccak256(abi.encode("bounds_tx", amount));
        bytes32 depositId = _initiateDeposit(amount, txHash);

        IPolkadotBridgeAdapter.DOTDeposit memory dep = bridge.getDeposit(
            depositId
        );
        assertGe(dep.amountPlanck, MIN_DEPOSIT);
        assertLe(dep.amountPlanck, MAX_DEPOSIT);
    }

    /// @notice 10. Deposit below minimum reverts
    function test_depositBelowMinimum() public {
        uint256 amount = MIN_DEPOSIT - 1;

        _submitVerifiedHeader(1, keccak256("header_low"));

        IPolkadotBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        IPolkadotBridgeAdapter.SubstrateStateProof
            memory proof = _buildStateProof();

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                IPolkadotBridgeAdapter.AmountBelowMinimum.selector,
                amount,
                MIN_DEPOSIT
            )
        );
        bridge.initiateDOTDeposit(
            keccak256("tx_low"),
            keccak256("sender"),
            user,
            amount,
            1,
            proof,
            attestations
        );
    }

    /// @notice 11. Deposit above maximum reverts
    function test_depositAboveMaximum() public {
        uint256 amount = MAX_DEPOSIT + 1;

        _submitVerifiedHeader(1, keccak256("header_high"));

        IPolkadotBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        IPolkadotBridgeAdapter.SubstrateStateProof
            memory proof = _buildStateProof();

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                IPolkadotBridgeAdapter.AmountAboveMaximum.selector,
                amount,
                MAX_DEPOSIT
            )
        );
        bridge.initiateDOTDeposit(
            keccak256("tx_high"),
            keccak256("sender"),
            user,
            amount,
            1,
            proof,
            attestations
        );
    }

    /*//////////////////////////////////////////////////////////////
                        WITHDRAWAL TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice 12. Full withdrawal lifecycle: initiate + complete
    function testFuzz_withdrawalLifecycle(uint256 amount) public {
        amount = bound(amount, MIN_DEPOSIT, MAX_DEPOSIT);

        // Mint wDOT to user for withdrawal
        vm.prank(admin);
        wDOT.mint(user, amount);

        vm.startPrank(user);
        wDOT.approve(address(bridge), amount);
        bytes32 wId = bridge.initiateWithdrawal(
            keccak256("substrate_recipient"),
            amount
        );
        vm.stopPrank();

        IPolkadotBridgeAdapter.DOTWithdrawal memory w = bridge.getWithdrawal(
            wId
        );
        assertEq(
            uint256(w.status),
            uint256(IPolkadotBridgeAdapter.WithdrawalStatus.PENDING)
        );
        assertEq(w.amountPlanck, amount);

        // Complete withdrawal as relayer
        IPolkadotBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        IPolkadotBridgeAdapter.SubstrateStateProof
            memory proof = _buildStateProof();

        vm.prank(relayer);
        bridge.completeWithdrawal(
            wId,
            keccak256("substrate_tx"),
            proof,
            attestations
        );

        w = bridge.getWithdrawal(wId);
        assertEq(
            uint256(w.status),
            uint256(IPolkadotBridgeAdapter.WithdrawalStatus.COMPLETED)
        );
    }

    /// @notice 13. Withdrawal can be refunded after delay
    function testFuzz_withdrawalRefund(uint256 amount) public {
        amount = bound(amount, MIN_DEPOSIT, MAX_DEPOSIT);

        vm.prank(admin);
        wDOT.mint(user, amount);

        vm.startPrank(user);
        wDOT.approve(address(bridge), amount);
        bytes32 wId = bridge.initiateWithdrawal(
            keccak256("substrate_recipient"),
            amount
        );
        vm.stopPrank();

        // Warp past refund delay (24 hours)
        vm.warp(block.timestamp + 24 hours + 1);

        uint256 balBefore = wDOT.balanceOf(user);
        bridge.refundWithdrawal(wId);
        uint256 balAfter = wDOT.balanceOf(user);

        assertEq(balAfter - balBefore, amount);

        IPolkadotBridgeAdapter.DOTWithdrawal memory w = bridge.getWithdrawal(
            wId
        );
        assertEq(
            uint256(w.status),
            uint256(IPolkadotBridgeAdapter.WithdrawalStatus.REFUNDED)
        );
    }

    /// @notice 14. Withdrawal refund before delay reverts
    function test_withdrawalRefundTooEarly() public {
        uint256 amount = 1 * PLANCK_PER_DOT;

        vm.prank(admin);
        wDOT.mint(user, amount);

        vm.startPrank(user);
        wDOT.approve(address(bridge), amount);
        bytes32 wId = bridge.initiateWithdrawal(
            keccak256("substrate_recipient"),
            amount
        );
        vm.stopPrank();

        // Attempt refund immediately (before 24h delay)
        vm.expectRevert();
        bridge.refundWithdrawal(wId);
    }

    /*//////////////////////////////////////////////////////////////
                       ESCROW LIFECYCLE TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice 15. HTLC escrow create + finish lifecycle
    function testFuzz_escrowCreateFinish(uint256 amount) public {
        amount = bound(amount, 0.01 ether, 10 ether);

        bytes32 preimage = keccak256("test_preimage_dot");
        bytes32 hashlock = sha256(abi.encodePacked(preimage));

        uint256 finishAfter = block.timestamp + 1 hours;
        uint256 cancelAfter = finishAfter + 12 hours;

        vm.deal(user, amount + 1 ether);
        vm.prank(user);
        bytes32 escrowId = bridge.createEscrow{value: amount}(
            keccak256("substrate_party"),
            hashlock,
            finishAfter,
            cancelAfter
        );

        IPolkadotBridgeAdapter.DOTEscrow memory e = bridge.getEscrow(escrowId);
        assertEq(
            uint256(e.status),
            uint256(IPolkadotBridgeAdapter.EscrowStatus.ACTIVE)
        );
        assertEq(e.amountPlanck, amount);

        // Finish after timelock
        vm.warp(finishAfter + 1);
        bridge.finishEscrow(escrowId, preimage);

        e = bridge.getEscrow(escrowId);
        assertEq(
            uint256(e.status),
            uint256(IPolkadotBridgeAdapter.EscrowStatus.FINISHED)
        );
        assertEq(e.preimage, preimage);
    }

    /// @notice 16. HTLC escrow cancel after expiry refunds ETH
    function testFuzz_escrowCancel(uint256 amount) public {
        amount = bound(amount, 0.01 ether, 10 ether);

        bytes32 hashlock = sha256(abi.encodePacked(keccak256("cancel_dot")));

        uint256 finishAfter = block.timestamp + 2 hours;
        uint256 cancelAfter = finishAfter + 6 hours;

        vm.deal(user, amount + 1 ether);
        vm.prank(user);
        bytes32 escrowId = bridge.createEscrow{value: amount}(
            keccak256("substrate_party"),
            hashlock,
            finishAfter,
            cancelAfter
        );

        // Cannot cancel before cancelAfter
        vm.expectRevert(IPolkadotBridgeAdapter.EscrowTimelockNotMet.selector);
        bridge.cancelEscrow(escrowId);

        // Warp past cancelAfter
        vm.warp(cancelAfter + 1);
        uint256 balBefore = user.balance;
        bridge.cancelEscrow(escrowId);
        uint256 balAfter = user.balance;

        assertEq(balAfter - balBefore, amount);

        IPolkadotBridgeAdapter.DOTEscrow memory e = bridge.getEscrow(escrowId);
        assertEq(
            uint256(e.status),
            uint256(IPolkadotBridgeAdapter.EscrowStatus.CANCELLED)
        );
    }

    /// @notice 17. Escrow timelock bounds: too short and too long both revert
    function test_escrowTimelockBounds() public {
        bytes32 hashlock = sha256(abi.encodePacked(keccak256("timelock_dot")));

        // Too short (< 1 hour duration)
        vm.deal(user, 10 ether);
        vm.prank(user);
        vm.expectRevert(IPolkadotBridgeAdapter.InvalidTimelockRange.selector);
        bridge.createEscrow{value: 0.1 ether}(
            keccak256("substrate_party"),
            hashlock,
            block.timestamp + 1 hours,
            block.timestamp + 1 hours + 30 minutes // duration = 30 min < MIN_ESCROW_TIMELOCK
        );

        // Too long (> 30 days duration)
        vm.prank(user);
        vm.expectRevert(IPolkadotBridgeAdapter.InvalidTimelockRange.selector);
        bridge.createEscrow{value: 0.1 ether}(
            keccak256("substrate_party"),
            hashlock,
            block.timestamp + 1 hours,
            block.timestamp + 1 hours + 31 days // duration = 31 days > MAX_ESCROW_TIMELOCK
        );
    }

    /*//////////////////////////////////////////////////////////////
                      PRIVACY / NULLIFIER TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice 18. Private deposit registers nullifier and commitment
    function testFuzz_privateDeposit(uint256 amount) public {
        amount = bound(amount, MIN_DEPOSIT, MAX_DEPOSIT);

        bytes32 txHash = keccak256(abi.encode("priv_tx", amount));
        bytes32 depositId = _initiateDeposit(amount, txHash);

        bytes32 nullifier = keccak256(abi.encode("nullifier", amount));
        bytes32 commitment = keccak256(abi.encode("commitment", amount));

        bridge.registerPrivateDeposit(
            depositId,
            commitment,
            nullifier,
            hex"00"
        );

        assertTrue(bridge.usedNullifiers(nullifier));
    }

    /// @notice 19. Duplicate nullifier reverts
    function test_duplicateNullifier() public {
        bytes32 depositId = _initiateDeposit(
            1 * PLANCK_PER_DOT,
            keccak256("dup_null_tx")
        );

        bytes32 nullifier = keccak256("same_nullifier");

        bridge.registerPrivateDeposit(
            depositId,
            keccak256("commitment1"),
            nullifier,
            hex"00"
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                IPolkadotBridgeAdapter.NullifierAlreadyUsed.selector,
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
                       ACCESS CONTROL TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice 20. Only relayer can initiate deposits
    function test_onlyRelayerCanDeposit() public {
        _submitVerifiedHeader(1, keccak256("header_ac"));

        IPolkadotBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        IPolkadotBridgeAdapter.SubstrateStateProof
            memory proof = _buildStateProof();

        vm.prank(user);
        vm.expectRevert();
        bridge.initiateDOTDeposit(
            keccak256("ac_tx"),
            keccak256("sender"),
            user,
            1 * PLANCK_PER_DOT,
            1,
            proof,
            attestations
        );
    }

    /// @notice 21. Only relayer can complete withdrawals
    function test_onlyRelayerCanWithdraw() public {
        uint256 amount = 1 * PLANCK_PER_DOT;

        vm.prank(admin);
        wDOT.mint(user, amount);

        vm.startPrank(user);
        wDOT.approve(address(bridge), amount);
        bytes32 wId = bridge.initiateWithdrawal(
            keccak256("substrate_recipient"),
            amount
        );
        vm.stopPrank();

        IPolkadotBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        IPolkadotBridgeAdapter.SubstrateStateProof
            memory proof = _buildStateProof();

        vm.prank(user); // user is not relayer
        vm.expectRevert();
        bridge.completeWithdrawal(
            wId,
            keccak256("substrate_tx"),
            proof,
            attestations
        );
    }

    /*//////////////////////////////////////////////////////////////
                          PAUSE TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice 22. Pause blocks deposits, withdrawals, and escrows; unpause restores
    function test_pauseUnpause() public {
        vm.prank(admin);
        bridge.pause();

        // Deposits blocked
        _submitVerifiedHeader(1, keccak256("header_pause"));

        IPolkadotBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        IPolkadotBridgeAdapter.SubstrateStateProof
            memory proof = _buildStateProof();

        vm.prank(relayer);
        vm.expectRevert();
        bridge.initiateDOTDeposit(
            keccak256("paused_tx"),
            keccak256("sender"),
            user,
            1 * PLANCK_PER_DOT,
            1,
            proof,
            attestations
        );

        // Withdrawals blocked
        vm.prank(user);
        vm.expectRevert();
        bridge.initiateWithdrawal(
            keccak256("substrate_recipient"),
            1 * PLANCK_PER_DOT
        );

        // Escrows blocked
        bytes32 hashlock = sha256(abi.encodePacked(keccak256("paused_dot")));
        vm.deal(user, 1 ether);
        vm.prank(user);
        vm.expectRevert();
        bridge.createEscrow{value: 0.1 ether}(
            keccak256("substrate_party"),
            hashlock,
            block.timestamp + 1 hours,
            block.timestamp + 5 hours
        );

        // Unpause restores operations
        vm.prank(admin);
        bridge.unpause();

        // Withdrawal should now work
        vm.prank(admin);
        wDOT.mint(user, 1 * PLANCK_PER_DOT);

        vm.startPrank(user);
        wDOT.approve(address(bridge), 1 * PLANCK_PER_DOT);
        bytes32 wId = bridge.initiateWithdrawal(
            keccak256("substrate_recipient_2"),
            1 * PLANCK_PER_DOT
        );
        vm.stopPrank();

        IPolkadotBridgeAdapter.DOTWithdrawal memory w = bridge.getWithdrawal(
            wId
        );
        assertEq(
            uint256(w.status),
            uint256(IPolkadotBridgeAdapter.WithdrawalStatus.PENDING)
        );
    }

    /*//////////////////////////////////////////////////////////////
                       FEE WITHDRAWAL TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice 23. Accumulated fees can be withdrawn to treasury
    function testFuzz_feeWithdrawal(uint256 amount) public {
        amount = bound(amount, MIN_DEPOSIT, MAX_DEPOSIT);

        bytes32 txHash = keccak256(abi.encode("fee_tx", amount));
        _initiateDeposit(amount, txHash);

        uint256 expectedFee = (amount * 6) / 10_000;
        assertEq(bridge.accumulatedFees(), expectedFee);

        uint256 treasuryBefore = wDOT.balanceOf(treasury);

        vm.prank(admin);
        bridge.withdrawFees();

        uint256 treasuryAfter = wDOT.balanceOf(treasury);
        assertEq(treasuryAfter - treasuryBefore, expectedFee);
        assertEq(bridge.accumulatedFees(), 0);
    }

    /*//////////////////////////////////////////////////////////////
                      BATCH / MULTIPLE OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice 24. Multiple deposits accumulate correctly
    function testFuzz_multipleDeposits(uint8 count) public {
        uint256 n = bound(uint256(count), 1, 10);
        uint256 amount = 1 * PLANCK_PER_DOT;
        uint256 prevNonce = bridge.depositNonce();

        for (uint256 i = 0; i < n; i++) {
            bytes32 txHash = keccak256(abi.encode("multi_tx", i));
            _submitVerifiedHeader(
                i + 2,
                keccak256(abi.encode("multi_header", i))
            );

            IPolkadotBridgeAdapter.ValidatorAttestation[]
                memory attestations = _buildValidatorAttestations();
            IPolkadotBridgeAdapter.SubstrateStateProof
                memory proof = _buildStateProof();

            vm.prank(relayer);
            bridge.initiateDOTDeposit(
                txHash,
                keccak256("sender"),
                user,
                amount,
                i + 2,
                proof,
                attestations
            );

            assertGt(bridge.depositNonce(), prevNonce);
            prevNonce = bridge.depositNonce();
        }

        assertEq(bridge.totalDeposited(), amount * (n + 0));
        // The _initiateDeposit helper already does one deposit at block 1,
        // but here we're creating n deposits directly, so total = n * amount
        // However _initiateDeposit is NOT called here, so total = n * amount
    }

    /*//////////////////////////////////////////////////////////////
                     CONFIGURATION TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice 25. Configure rejects zero address for token or oracle
    function test_configureRejectsZeroAddress() public {
        vm.prank(admin);
        vm.expectRevert(IPolkadotBridgeAdapter.ZeroAddress.selector);
        bridge.configure(address(0), address(wDOT), address(oracle), 2, 2);

        vm.prank(admin);
        vm.expectRevert(IPolkadotBridgeAdapter.ZeroAddress.selector);
        bridge.configure(address(0x1), address(0), address(oracle), 2, 2);

        vm.prank(admin);
        vm.expectRevert(IPolkadotBridgeAdapter.ZeroAddress.selector);
        bridge.configure(address(0x1), address(wDOT), address(0), 2, 2);
    }

    /*//////////////////////////////////////////////////////////////
                    USER TRACKING VIEW FUNCTION TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice 26. User deposit tracking returns correct deposit IDs
    function testFuzz_getUserDeposits(uint8 count) public {
        uint256 n = bound(uint256(count), 1, 5);

        for (uint256 i = 0; i < n; i++) {
            bytes32 txHash = keccak256(abi.encode("user_dep_tx", i));
            _submitVerifiedHeader(
                i + 2,
                keccak256(abi.encode("user_dep_header", i))
            );

            IPolkadotBridgeAdapter.ValidatorAttestation[]
                memory attestations = _buildValidatorAttestations();
            IPolkadotBridgeAdapter.SubstrateStateProof
                memory proof = _buildStateProof();

            vm.prank(relayer);
            bridge.initiateDOTDeposit(
                txHash,
                keccak256("sender"),
                user,
                1 * PLANCK_PER_DOT,
                i + 2,
                proof,
                attestations
            );
        }

        bytes32[] memory deps = bridge.getUserDeposits(user);
        // _initiateDeposit in loop uses relayBlock i+2, each unique
        assertEq(deps.length, n);
    }

    /// @notice 27. User withdrawal tracking returns correct withdrawal IDs
    function testFuzz_getUserWithdrawals(uint8 count) public {
        uint256 n = bound(uint256(count), 1, 5);
        uint256 amount = 1 * PLANCK_PER_DOT;

        vm.prank(admin);
        wDOT.mint(user, amount * n);

        vm.startPrank(user);
        wDOT.approve(address(bridge), amount * n);

        for (uint256 i = 0; i < n; i++) {
            bridge.initiateWithdrawal(
                keccak256(abi.encode("sub_recip", i)),
                amount
            );
        }
        vm.stopPrank();

        bytes32[] memory ws = bridge.getUserWithdrawals(user);
        assertEq(ws.length, n);
    }

    /// @notice 28. User escrow tracking returns correct escrow IDs
    function testFuzz_getUserEscrows(uint8 count) public {
        uint256 n = bound(uint256(count), 1, 5);

        vm.deal(user, n * 1 ether);

        for (uint256 i = 0; i < n; i++) {
            bytes32 hashlock = sha256(
                abi.encodePacked(keccak256(abi.encode("escrow", i)))
            );

            vm.prank(user);
            bridge.createEscrow{value: 0.1 ether}(
                keccak256(abi.encode("substrate_party", i)),
                hashlock,
                block.timestamp + 1 hours,
                block.timestamp + 5 hours
            );
        }

        bytes32[] memory es = bridge.getUserEscrows(user);
        assertEq(es.length, n);
    }

    /*//////////////////////////////////////////////////////////////
                      STATISTICS / STATS TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice 29. Bridge stats counters are accurate
    function test_bridgeStats() public {
        // Initial state: all zeros
        (
            uint256 deposited,
            uint256 withdrawn,
            uint256 escrowCount,
            uint256 escrowsFinished,
            uint256 escrowsCancelled,
            uint256 fees,
            uint256 latestBlock
        ) = bridge.getBridgeStats();

        assertEq(deposited, 0);
        assertEq(withdrawn, 0);
        assertEq(escrowCount, 0);
        assertEq(escrowsFinished, 0);
        assertEq(escrowsCancelled, 0);
        assertEq(fees, 0);
        assertEq(latestBlock, 0);

        // Make a deposit
        uint256 amount = 5 * PLANCK_PER_DOT;
        _initiateDeposit(amount, keccak256("stats_tx"));

        (deposited, , , , , fees, latestBlock) = bridge.getBridgeStats();
        assertEq(deposited, amount);
        assertEq(fees, (amount * 6) / 10_000);
        assertEq(latestBlock, 1);

        // Make a withdrawal
        vm.prank(admin);
        wDOT.mint(user, amount);
        vm.startPrank(user);
        wDOT.approve(address(bridge), amount);
        bridge.initiateWithdrawal(keccak256("sub_recip_stats"), amount);
        vm.stopPrank();

        (, withdrawn, , , , , ) = bridge.getBridgeStats();
        assertEq(withdrawn, amount);

        // Create and finish an escrow
        bytes32 preimage = keccak256("stats_preimage");
        bytes32 hashlock = sha256(abi.encodePacked(preimage));

        vm.deal(user, 1 ether);
        vm.prank(user);
        bytes32 escrowId = bridge.createEscrow{value: 0.5 ether}(
            keccak256("substrate_party"),
            hashlock,
            block.timestamp + 1 hours,
            block.timestamp + 5 hours
        );

        (, , escrowCount, , , , ) = bridge.getBridgeStats();
        assertEq(escrowCount, 1);

        vm.warp(block.timestamp + 1 hours + 1);
        bridge.finishEscrow(escrowId, preimage);

        (, , , escrowsFinished, , , ) = bridge.getBridgeStats();
        assertEq(escrowsFinished, 1);
    }

    /*//////////////////////////////////////////////////////////////
                     UNIQUENESS / IDEMPOTENCY TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice 30. Deposit IDs are unique for different inputs
    function testFuzz_depositIdUniqueness(uint256 a, uint256 b) public {
        a = bound(a, MIN_DEPOSIT, MAX_DEPOSIT);
        b = bound(b, MIN_DEPOSIT, MAX_DEPOSIT);
        vm.assume(a != b);

        bytes32 txHashA = keccak256(abi.encode("uniq_tx_a", a));
        bytes32 depositIdA = _initiateDeposit(a, txHashA);

        // Submit a fresh header for the second deposit
        _submitVerifiedHeader(2, keccak256("header_uniq_b"));

        IPolkadotBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        IPolkadotBridgeAdapter.SubstrateStateProof
            memory proof = _buildStateProof();

        bytes32 txHashB = keccak256(abi.encode("uniq_tx_b", b));

        vm.prank(relayer);
        bytes32 depositIdB = bridge.initiateDOTDeposit(
            txHashB,
            keccak256("sender"),
            user,
            b,
            2,
            proof,
            attestations
        );

        assertTrue(depositIdA != depositIdB);
    }

    /// @notice 31. Double-finishing an escrow reverts
    function test_escrowDoubleFinish() public {
        bytes32 preimage = keccak256("double_finish_preimage");
        bytes32 hashlock = sha256(abi.encodePacked(preimage));

        uint256 finishAfter = block.timestamp + 1 hours;
        uint256 cancelAfter = finishAfter + 12 hours;

        vm.deal(user, 10 ether);
        vm.prank(user);
        bytes32 escrowId = bridge.createEscrow{value: 1 ether}(
            keccak256("substrate_party"),
            hashlock,
            finishAfter,
            cancelAfter
        );

        vm.warp(finishAfter + 1);
        bridge.finishEscrow(escrowId, preimage);

        // Second finish should revert
        vm.expectRevert(
            abi.encodeWithSelector(
                IPolkadotBridgeAdapter.EscrowNotActive.selector,
                escrowId
            )
        );
        bridge.finishEscrow(escrowId, preimage);
    }

    /// @notice 32. Double-completing a withdrawal reverts
    function test_withdrawalDoubleComplete() public {
        uint256 amount = 1 * PLANCK_PER_DOT;

        vm.prank(admin);
        wDOT.mint(user, amount);

        vm.startPrank(user);
        wDOT.approve(address(bridge), amount);
        bytes32 wId = bridge.initiateWithdrawal(
            keccak256("substrate_recipient"),
            amount
        );
        vm.stopPrank();

        IPolkadotBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        IPolkadotBridgeAdapter.SubstrateStateProof
            memory proof = _buildStateProof();

        // Complete once
        vm.prank(relayer);
        bridge.completeWithdrawal(
            wId,
            keccak256("substrate_tx_1"),
            proof,
            attestations
        );

        // Second complete should revert
        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                IPolkadotBridgeAdapter.WithdrawalNotPending.selector,
                wId
            )
        );
        bridge.completeWithdrawal(
            wId,
            keccak256("substrate_tx_2"),
            proof,
            attestations
        );
    }
}
