// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {CosmosBridgeAdapter} from "../../contracts/crosschain/CosmosBridgeAdapter.sol";
import {ICosmosBridgeAdapter} from "../../contracts/interfaces/ICosmosBridgeAdapter.sol";
import {MockWrappedATOM} from "../../contracts/mocks/MockWrappedATOM.sol";
import {MockCosmosIBCLightClient} from "../../contracts/mocks/MockCosmosIBCLightClient.sol";

/**
 * @title CosmosBridgeFuzz
 * @notice Foundry fuzz & invariant tests for the CosmosBridgeAdapter
 * @dev Tests uatom precision (6 decimals), Tendermint header verification,
 *      IBC light client validator attestation, and Cosmos-specific bridge parameters.
 */
contract CosmosBridgeFuzz is Test {
    CosmosBridgeAdapter public bridge;
    MockWrappedATOM public wATOM;
    MockCosmosIBCLightClient public oracle;

    address public admin = address(0xA);
    address public relayer = address(0xB);
    address public user = address(0xC);
    address public treasury = address(0xD);

    // Validator addresses
    address constant VALIDATOR_1 = address(0x2001);
    address constant VALIDATOR_2 = address(0x2002);
    address constant VALIDATOR_3 = address(0x2003);

    uint256 constant UATOM_PER_ATOM = 1_000_000; // 1e6
    uint256 constant MIN_DEPOSIT = 100_000; // 0.1 ATOM
    uint256 constant MAX_DEPOSIT = 10_000_000 * UATOM_PER_ATOM;

    function setUp() public {
        vm.startPrank(admin);

        bridge = new CosmosBridgeAdapter(admin);
        wATOM = new MockWrappedATOM();
        oracle = new MockCosmosIBCLightClient();

        // Register validators with voting power
        oracle.addValidator(VALIDATOR_1, 100);
        oracle.addValidator(VALIDATOR_2, 100);
        oracle.addValidator(VALIDATOR_3, 100);

        // Configure bridge
        bridge.configure(
            address(0x1), // cosmosBridgeContract
            address(wATOM),
            address(oracle),
            2, // minValidatorSignatures
            1 // requiredConfirmations
        );

        bridge.setTreasury(treasury);
        bridge.grantRole(bridge.RELAYER_ROLE(), relayer);

        // Fund the bridge with wATOM (100M ATOM in uatom)
        wATOM.mint(address(bridge), 100_000_000 * UATOM_PER_ATOM);

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
        returns (ICosmosBridgeAdapter.ValidatorAttestation[] memory)
    {
        ICosmosBridgeAdapter.ValidatorAttestation[]
            memory attestations = new ICosmosBridgeAdapter.ValidatorAttestation[](
                3
            );

        attestations[0] = ICosmosBridgeAdapter.ValidatorAttestation({
            validator: VALIDATOR_1,
            signature: hex"01"
        });
        attestations[1] = ICosmosBridgeAdapter.ValidatorAttestation({
            validator: VALIDATOR_2,
            signature: hex"02"
        });
        attestations[2] = ICosmosBridgeAdapter.ValidatorAttestation({
            validator: VALIDATOR_3,
            signature: hex"03"
        });

        return attestations;
    }

    function _submitVerifiedHeader(uint256 height, bytes32 blockHash) internal {
        ICosmosBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();

        vm.prank(relayer);
        bridge.submitTendermintHeader(
            height,
            blockHash,
            keccak256(abi.encode("appHash", height)),
            keccak256(abi.encode("validatorsHash", height)),
            block.timestamp,
            attestations
        );
    }

    function _buildStateProof()
        internal
        pure
        returns (ICosmosBridgeAdapter.IBCProof memory)
    {
        bytes32[] memory proof = new bytes32[](2);
        proof[0] = keccak256("proof_node_0");
        proof[1] = keccak256("proof_node_1");

        return
            ICosmosBridgeAdapter.IBCProof({
                merklePath: proof,
                commitmentRoot: keccak256("commitment_root"),
                value: hex"01"
            });
    }

    function _initiateDeposit(
        uint256 amount,
        bytes32 txHash
    ) internal returns (bytes32) {
        // Submit Tendermint header first
        _submitVerifiedHeader(1, keccak256("header1"));

        ICosmosBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        ICosmosBridgeAdapter.IBCProof memory proof = _buildStateProof();

        vm.prank(relayer);
        return
            bridge.initiateATOMDeposit(
                txHash,
                keccak256("cosmos_sender"),
                user,
                amount,
                1, // cosmosHeight
                proof,
                attestations
            );
    }

    /*//////////////////////////////////////////////////////////////
                         CONSTANTS TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice 1. Verify all bridge constants are correctly set
    function test_constantsAreCorrect() public view {
        assertEq(bridge.COSMOS_CHAIN_ID(), 118);
        assertEq(bridge.UATOM_PER_ATOM(), 1_000_000);
        assertEq(bridge.BRIDGE_FEE_BPS(), 5);
        assertEq(bridge.WITHDRAWAL_REFUND_DELAY(), 24 hours);
        assertEq(bridge.MIN_ESCROW_TIMELOCK(), 1 hours);
        assertEq(bridge.MAX_ESCROW_TIMELOCK(), 30 days);
        assertEq(bridge.DEFAULT_BLOCK_CONFIRMATIONS(), 1);
        assertEq(bridge.MIN_DEPOSIT_UATOM(), UATOM_PER_ATOM / 10);
        assertEq(bridge.MAX_DEPOSIT_UATOM(), 10_000_000 * UATOM_PER_ATOM);
        assertEq(bridge.BPS_DENOMINATOR(), 10_000);
    }

    /// @notice 2. Constructor rejects zero admin address
    function test_constructorRejectsZeroAdmin() public {
        vm.expectRevert(ICosmosBridgeAdapter.ZeroAddress.selector);
        new CosmosBridgeAdapter(address(0));
    }

    /*//////////////////////////////////////////////////////////////
                       UATOM PRECISION TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice 3. ATOM <-> uatom conversion is lossless
    function testFuzz_uatomPrecision(uint256 atomAmount) public pure {
        atomAmount = bound(atomAmount, 1, 1_000_000);
        uint256 uatom = atomAmount * UATOM_PER_ATOM;
        assertEq(uatom / UATOM_PER_ATOM, atomAmount);
        assertEq(uatom % UATOM_PER_ATOM, 0);
    }

    /// @notice 4. Deposits with sub-ATOM uatom precision are tracked exactly
    function testFuzz_uatomSubUnitDeposit(uint256 uatom) public {
        uatom = bound(uatom, MIN_DEPOSIT, MAX_DEPOSIT);

        bytes32 txHash = keccak256(abi.encode("atom_tx_sub", uatom));
        bytes32 depositId = _initiateDeposit(uatom, txHash);

        ICosmosBridgeAdapter.ATOMDeposit memory dep = bridge.getDeposit(
            depositId
        );
        assertEq(dep.amountUatom, uatom);
        assertEq(dep.fee, (uatom * 5) / 10_000);
        assertEq(dep.netAmountUatom, uatom - dep.fee);
    }

    /*//////////////////////////////////////////////////////////////
                         DEPOSIT FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice 5. Fuzz deposit amounts within valid range
    function testFuzz_deposit(uint256 amount) public {
        amount = bound(amount, MIN_DEPOSIT, MAX_DEPOSIT);

        bytes32 txHash = keccak256(abi.encode("fuzz_dep_tx", amount));
        bytes32 depositId = _initiateDeposit(amount, txHash);

        ICosmosBridgeAdapter.ATOMDeposit memory dep = bridge.getDeposit(
            depositId
        );
        assertEq(dep.amountUatom, amount);
        assertEq(
            uint256(dep.status),
            uint256(ICosmosBridgeAdapter.DepositStatus.VERIFIED)
        );
    }

    /*//////////////////////////////////////////////////////////////
                        FEE CALCULATION TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice 6. Fee calculation uses 5 BPS correctly
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
                 TENDERMINT HEADER VERIFICATION TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice 7. Chained Tendermint headers are all verified and latest height tracked
    function testFuzz_headerChain(uint8 count) public {
        uint256 n = bound(uint256(count), 1, 20);

        for (uint256 i = 0; i < n; i++) {
            bytes32 blockHash = keccak256(abi.encode("header", i));
            _submitVerifiedHeader(i + 1, blockHash);

            ICosmosBridgeAdapter.TendermintHeader memory hdr = bridge
                .getTendermintHeader(i + 1);
            assertTrue(hdr.verified);
            assertEq(hdr.blockHash, blockHash);
        }

        assertEq(bridge.latestCosmosHeight(), n);
    }

    /// @notice 8. Deposit requires a verified Tendermint header at the cosmos height
    function test_depositRequiresVerifiedHeader() public {
        // Don't submit any Tendermint header — deposit should fail
        ICosmosBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        ICosmosBridgeAdapter.IBCProof memory proof = _buildStateProof();

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                ICosmosBridgeAdapter.CosmosHeightNotVerified.selector,
                999
            )
        );
        bridge.initiateATOMDeposit(
            keccak256("unverified_tx"),
            keccak256("sender"),
            user,
            1 * UATOM_PER_ATOM,
            999, // non-existent cosmos height
            proof,
            attestations
        );
    }

    /*//////////////////////////////////////////////////////////////
                          DEPOSIT TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice 9. Full deposit round-trip: initiate + complete
    function testFuzz_depositRoundTrip(uint256 amount) public {
        amount = bound(amount, MIN_DEPOSIT, MAX_DEPOSIT);

        bytes32 txHash = keccak256(abi.encode("roundtrip_tx", amount));
        bytes32 depositId = _initiateDeposit(amount, txHash);

        ICosmosBridgeAdapter.ATOMDeposit memory dep = bridge.getDeposit(
            depositId
        );
        assertEq(
            uint256(dep.status),
            uint256(ICosmosBridgeAdapter.DepositStatus.VERIFIED)
        );

        uint256 balBefore = wATOM.balanceOf(user);

        // Complete the deposit (admin has OPERATOR_ROLE)
        vm.prank(admin);
        bridge.completeATOMDeposit(depositId);

        uint256 balAfter = wATOM.balanceOf(user);
        assertEq(balAfter - balBefore, dep.netAmountUatom);

        dep = bridge.getDeposit(depositId);
        assertEq(
            uint256(dep.status),
            uint256(ICosmosBridgeAdapter.DepositStatus.COMPLETED)
        );
    }

    /// @notice 10. Deposit amount bounds are enforced
    function testFuzz_depositAmountBounds(uint256 amount) public {
        amount = bound(amount, MIN_DEPOSIT, MAX_DEPOSIT);

        bytes32 txHash = keccak256(abi.encode("bounds_tx", amount));
        bytes32 depositId = _initiateDeposit(amount, txHash);

        ICosmosBridgeAdapter.ATOMDeposit memory dep = bridge.getDeposit(
            depositId
        );
        assertGe(dep.amountUatom, MIN_DEPOSIT);
        assertLe(dep.amountUatom, MAX_DEPOSIT);
    }

    /// @notice 11. Deposit below minimum reverts
    function test_depositBelowMinimum() public {
        uint256 amount = MIN_DEPOSIT - 1;

        _submitVerifiedHeader(1, keccak256("header_low"));

        ICosmosBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        ICosmosBridgeAdapter.IBCProof memory proof = _buildStateProof();

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                ICosmosBridgeAdapter.AmountBelowMinimum.selector,
                amount,
                MIN_DEPOSIT
            )
        );
        bridge.initiateATOMDeposit(
            keccak256("tx_low"),
            keccak256("sender"),
            user,
            amount,
            1,
            proof,
            attestations
        );
    }

    /// @notice 12. Deposit above maximum reverts
    function test_depositAboveMaximum() public {
        uint256 amount = MAX_DEPOSIT + 1;

        _submitVerifiedHeader(1, keccak256("header_high"));

        ICosmosBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        ICosmosBridgeAdapter.IBCProof memory proof = _buildStateProof();

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                ICosmosBridgeAdapter.AmountAboveMaximum.selector,
                amount,
                MAX_DEPOSIT
            )
        );
        bridge.initiateATOMDeposit(
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

    /// @notice 13. Full withdrawal lifecycle: initiate + complete
    function testFuzz_withdrawalLifecycle(uint256 amount) public {
        amount = bound(amount, MIN_DEPOSIT, MAX_DEPOSIT);

        // Mint wATOM to user for withdrawal
        vm.prank(admin);
        wATOM.mint(user, amount);

        vm.startPrank(user);
        wATOM.approve(address(bridge), amount);
        bytes32 wId = bridge.initiateWithdrawal(
            keccak256("cosmos_recipient"),
            amount
        );
        vm.stopPrank();

        ICosmosBridgeAdapter.ATOMWithdrawal memory w = bridge.getWithdrawal(
            wId
        );
        assertEq(
            uint256(w.status),
            uint256(ICosmosBridgeAdapter.WithdrawalStatus.PENDING)
        );
        assertEq(w.amountUatom, amount);

        // Complete withdrawal as relayer
        ICosmosBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        ICosmosBridgeAdapter.IBCProof memory proof = _buildStateProof();

        vm.prank(relayer);
        bridge.completeWithdrawal(
            wId,
            keccak256("cosmos_tx"),
            proof,
            attestations
        );

        w = bridge.getWithdrawal(wId);
        assertEq(
            uint256(w.status),
            uint256(ICosmosBridgeAdapter.WithdrawalStatus.COMPLETED)
        );
    }

    /// @notice 14. Withdrawal can be refunded after delay
    function testFuzz_withdrawalRefund(uint256 amount) public {
        amount = bound(amount, MIN_DEPOSIT, MAX_DEPOSIT);

        vm.prank(admin);
        wATOM.mint(user, amount);

        vm.startPrank(user);
        wATOM.approve(address(bridge), amount);
        bytes32 wId = bridge.initiateWithdrawal(
            keccak256("cosmos_recipient"),
            amount
        );
        vm.stopPrank();

        // Warp past refund delay (24 hours)
        vm.warp(block.timestamp + 24 hours + 1);

        uint256 balBefore = wATOM.balanceOf(user);
        bridge.refundWithdrawal(wId);
        uint256 balAfter = wATOM.balanceOf(user);

        assertEq(balAfter - balBefore, amount);

        ICosmosBridgeAdapter.ATOMWithdrawal memory w = bridge.getWithdrawal(
            wId
        );
        assertEq(
            uint256(w.status),
            uint256(ICosmosBridgeAdapter.WithdrawalStatus.REFUNDED)
        );
    }

    /// @notice 15. Withdrawal refund before delay reverts
    function test_withdrawalRefundTooEarly() public {
        uint256 amount = 1 * UATOM_PER_ATOM;

        vm.prank(admin);
        wATOM.mint(user, amount);

        vm.startPrank(user);
        wATOM.approve(address(bridge), amount);
        bytes32 wId = bridge.initiateWithdrawal(
            keccak256("cosmos_recipient"),
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

    /// @notice 16. HTLC escrow create + finish lifecycle
    function testFuzz_escrowCreateFinish(uint256 amount) public {
        amount = bound(amount, 0.01 ether, 10 ether);

        bytes32 preimage = keccak256("test_preimage_atom");
        bytes32 hashlock = sha256(abi.encodePacked(preimage));

        uint256 finishAfter = block.timestamp + 1 hours;
        uint256 cancelAfter = finishAfter + 12 hours;

        vm.deal(user, amount + 1 ether);
        vm.prank(user);
        bytes32 escrowId = bridge.createEscrow{value: amount}(
            keccak256("cosmos_party"),
            hashlock,
            finishAfter,
            cancelAfter
        );

        ICosmosBridgeAdapter.ATOMEscrow memory e = bridge.getEscrow(escrowId);
        assertEq(
            uint256(e.status),
            uint256(ICosmosBridgeAdapter.EscrowStatus.ACTIVE)
        );
        assertEq(e.amountUatom, amount);

        // Finish after timelock
        vm.warp(finishAfter + 1);
        bridge.finishEscrow(escrowId, preimage);

        e = bridge.getEscrow(escrowId);
        assertEq(
            uint256(e.status),
            uint256(ICosmosBridgeAdapter.EscrowStatus.FINISHED)
        );
        assertEq(e.preimage, preimage);
    }

    /// @notice 17. HTLC escrow cancel after expiry refunds ETH
    function testFuzz_escrowCancel(uint256 amount) public {
        amount = bound(amount, 0.01 ether, 10 ether);

        bytes32 hashlock = sha256(abi.encodePacked(keccak256("cancel_atom")));

        uint256 finishAfter = block.timestamp + 2 hours;
        uint256 cancelAfter = finishAfter + 6 hours;

        vm.deal(user, amount + 1 ether);
        vm.prank(user);
        bytes32 escrowId = bridge.createEscrow{value: amount}(
            keccak256("cosmos_party"),
            hashlock,
            finishAfter,
            cancelAfter
        );

        // Cannot cancel before cancelAfter
        vm.expectRevert(ICosmosBridgeAdapter.EscrowTimelockNotMet.selector);
        bridge.cancelEscrow(escrowId);

        // Warp past cancelAfter
        vm.warp(cancelAfter + 1);
        uint256 balBefore = user.balance;
        bridge.cancelEscrow(escrowId);
        uint256 balAfter = user.balance;

        assertEq(balAfter - balBefore, amount);

        ICosmosBridgeAdapter.ATOMEscrow memory e = bridge.getEscrow(escrowId);
        assertEq(
            uint256(e.status),
            uint256(ICosmosBridgeAdapter.EscrowStatus.CANCELLED)
        );
    }

    /// @notice 18. Escrow timelock bounds: too short and too long both revert
    function test_escrowTimelockBounds() public {
        bytes32 hashlock = sha256(abi.encodePacked(keccak256("timelock_atom")));

        // Too short (< 1 hour duration)
        vm.deal(user, 10 ether);
        vm.prank(user);
        vm.expectRevert(ICosmosBridgeAdapter.InvalidTimelockRange.selector);
        bridge.createEscrow{value: 0.1 ether}(
            keccak256("cosmos_party"),
            hashlock,
            block.timestamp + 1 hours,
            block.timestamp + 1 hours + 30 minutes // duration = 30 min < MIN_ESCROW_TIMELOCK
        );

        // Too long (> 30 days duration)
        vm.prank(user);
        vm.expectRevert(ICosmosBridgeAdapter.InvalidTimelockRange.selector);
        bridge.createEscrow{value: 0.1 ether}(
            keccak256("cosmos_party"),
            hashlock,
            block.timestamp + 1 hours,
            block.timestamp + 1 hours + 31 days // duration = 31 days > MAX_ESCROW_TIMELOCK
        );
    }

    /*//////////////////////////////////////////////////////////////
                      PRIVACY / NULLIFIER TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice 19. Private deposit registers nullifier and commitment
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

    /// @notice 20. Duplicate nullifier reverts
    function test_duplicateNullifier() public {
        bytes32 depositId = _initiateDeposit(
            1 * UATOM_PER_ATOM,
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
                ICosmosBridgeAdapter.NullifierAlreadyUsed.selector,
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

    /// @notice 21. Only relayer can initiate deposits
    function test_onlyRelayerCanDeposit() public {
        _submitVerifiedHeader(1, keccak256("header_ac"));

        ICosmosBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        ICosmosBridgeAdapter.IBCProof memory proof = _buildStateProof();

        vm.prank(user);
        vm.expectRevert();
        bridge.initiateATOMDeposit(
            keccak256("ac_tx"),
            keccak256("sender"),
            user,
            1 * UATOM_PER_ATOM,
            1,
            proof,
            attestations
        );
    }

    /// @notice 22. Only relayer can complete withdrawals
    function test_onlyRelayerCanCompleteWithdrawal() public {
        uint256 amount = 1 * UATOM_PER_ATOM;

        vm.prank(admin);
        wATOM.mint(user, amount);

        vm.startPrank(user);
        wATOM.approve(address(bridge), amount);
        bytes32 wId = bridge.initiateWithdrawal(
            keccak256("cosmos_recipient"),
            amount
        );
        vm.stopPrank();

        ICosmosBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        ICosmosBridgeAdapter.IBCProof memory proof = _buildStateProof();

        vm.prank(user); // user is not relayer
        vm.expectRevert();
        bridge.completeWithdrawal(
            wId,
            keccak256("cosmos_tx"),
            proof,
            attestations
        );
    }

    /*//////////////////////////////////////////////////////////////
                          PAUSE TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice 23. Pause blocks deposits, withdrawals, and escrows; unpause restores
    function test_pauseUnpause() public {
        vm.prank(admin);
        bridge.pause();

        // Deposits blocked
        _submitVerifiedHeader(1, keccak256("header_pause"));

        ICosmosBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        ICosmosBridgeAdapter.IBCProof memory proof = _buildStateProof();

        vm.prank(relayer);
        vm.expectRevert();
        bridge.initiateATOMDeposit(
            keccak256("paused_tx"),
            keccak256("sender"),
            user,
            1 * UATOM_PER_ATOM,
            1,
            proof,
            attestations
        );

        // Withdrawals blocked
        vm.prank(user);
        vm.expectRevert();
        bridge.initiateWithdrawal(
            keccak256("cosmos_recipient"),
            1 * UATOM_PER_ATOM
        );

        // Escrows blocked
        bytes32 hashlock = sha256(abi.encodePacked(keccak256("paused_atom")));
        vm.deal(user, 1 ether);
        vm.prank(user);
        vm.expectRevert();
        bridge.createEscrow{value: 0.1 ether}(
            keccak256("cosmos_party"),
            hashlock,
            block.timestamp + 1 hours,
            block.timestamp + 5 hours
        );

        // Unpause restores operations
        vm.prank(admin);
        bridge.unpause();

        // Withdrawal should now work
        vm.prank(admin);
        wATOM.mint(user, 1 * UATOM_PER_ATOM);

        vm.startPrank(user);
        wATOM.approve(address(bridge), 1 * UATOM_PER_ATOM);
        bytes32 wId = bridge.initiateWithdrawal(
            keccak256("cosmos_recipient_2"),
            1 * UATOM_PER_ATOM
        );
        vm.stopPrank();

        ICosmosBridgeAdapter.ATOMWithdrawal memory w = bridge.getWithdrawal(
            wId
        );
        assertEq(
            uint256(w.status),
            uint256(ICosmosBridgeAdapter.WithdrawalStatus.PENDING)
        );
    }

    /*//////////////////////////////////////////////////////////////
                       FEE WITHDRAWAL TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice 24. Accumulated fees can be withdrawn to treasury
    function testFuzz_feeWithdrawal(uint256 amount) public {
        amount = bound(amount, MIN_DEPOSIT, MAX_DEPOSIT);

        bytes32 txHash = keccak256(abi.encode("fee_tx", amount));
        _initiateDeposit(amount, txHash);

        uint256 expectedFee = (amount * 5) / 10_000;
        assertEq(bridge.accumulatedFees(), expectedFee);

        uint256 treasuryBefore = wATOM.balanceOf(treasury);

        vm.prank(admin);
        bridge.withdrawFees();

        uint256 treasuryAfter = wATOM.balanceOf(treasury);
        assertEq(treasuryAfter - treasuryBefore, expectedFee);
        assertEq(bridge.accumulatedFees(), 0);
    }

    /*//////////////////////////////////////////////////////////////
                      BATCH / MULTIPLE OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice 25. Multiple deposits accumulate correctly
    function testFuzz_multipleDeposits(uint8 count) public {
        uint256 n = bound(uint256(count), 1, 10);
        uint256 amount = 1 * UATOM_PER_ATOM;
        uint256 prevNonce = bridge.depositNonce();

        for (uint256 i = 0; i < n; i++) {
            bytes32 txHash = keccak256(abi.encode("multi_tx", i));
            _submitVerifiedHeader(
                i + 2,
                keccak256(abi.encode("multi_header", i))
            );

            ICosmosBridgeAdapter.ValidatorAttestation[]
                memory attestations = _buildValidatorAttestations();
            ICosmosBridgeAdapter.IBCProof memory proof = _buildStateProof();

            vm.prank(relayer);
            bridge.initiateATOMDeposit(
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

        assertEq(bridge.totalDeposited(), amount * n);
    }

    /*//////////////////////////////////////////////////////////////
                     CONFIGURATION TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice 26. Configure rejects zero address for token or oracle
    function test_configureRejectsZeroAddress() public {
        vm.prank(admin);
        vm.expectRevert(ICosmosBridgeAdapter.ZeroAddress.selector);
        bridge.configure(address(0), address(wATOM), address(oracle), 2, 1);

        vm.prank(admin);
        vm.expectRevert(ICosmosBridgeAdapter.ZeroAddress.selector);
        bridge.configure(address(0x1), address(0), address(oracle), 2, 1);

        vm.prank(admin);
        vm.expectRevert(ICosmosBridgeAdapter.ZeroAddress.selector);
        bridge.configure(address(0x1), address(wATOM), address(0), 2, 1);
    }

    /*//////////////////////////////////////////////////////////////
                    USER TRACKING VIEW FUNCTION TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice 27. User deposit tracking returns correct deposit IDs
    function testFuzz_getUserDeposits(uint8 count) public {
        uint256 n = bound(uint256(count), 1, 5);

        for (uint256 i = 0; i < n; i++) {
            bytes32 txHash = keccak256(abi.encode("user_dep_tx", i));
            _submitVerifiedHeader(
                i + 2,
                keccak256(abi.encode("user_dep_header", i))
            );

            ICosmosBridgeAdapter.ValidatorAttestation[]
                memory attestations = _buildValidatorAttestations();
            ICosmosBridgeAdapter.IBCProof memory proof = _buildStateProof();

            vm.prank(relayer);
            bridge.initiateATOMDeposit(
                txHash,
                keccak256("sender"),
                user,
                1 * UATOM_PER_ATOM,
                i + 2,
                proof,
                attestations
            );
        }

        bytes32[] memory deps = bridge.getUserDeposits(user);
        assertEq(deps.length, n);
    }

    /// @notice 28. User withdrawal tracking returns correct withdrawal IDs
    function testFuzz_getUserWithdrawals(uint8 count) public {
        uint256 n = bound(uint256(count), 1, 5);
        uint256 amount = 1 * UATOM_PER_ATOM;

        vm.prank(admin);
        wATOM.mint(user, amount * n);

        vm.startPrank(user);
        wATOM.approve(address(bridge), amount * n);

        for (uint256 i = 0; i < n; i++) {
            bridge.initiateWithdrawal(
                keccak256(abi.encode("cosmos_recip", i)),
                amount
            );
        }
        vm.stopPrank();

        bytes32[] memory ws = bridge.getUserWithdrawals(user);
        assertEq(ws.length, n);
    }

    /// @notice 29. User escrow tracking returns correct escrow IDs
    function testFuzz_getUserEscrows(uint8 count) public {
        uint256 n = bound(uint256(count), 1, 5);

        vm.deal(user, n * 1 ether);

        for (uint256 i = 0; i < n; i++) {
            bytes32 hashlock = sha256(
                abi.encodePacked(keccak256(abi.encode("escrow", i)))
            );

            vm.prank(user);
            bridge.createEscrow{value: 0.1 ether}(
                keccak256(abi.encode("cosmos_party", i)),
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

    /// @notice 30. Bridge stats counters are accurate
    function test_bridgeStats() public {
        // Initial state: all zeros
        (
            uint256 deposited,
            uint256 withdrawn,
            uint256 escrowCount,
            uint256 escrowsFinished,
            uint256 escrowsCancelled,
            uint256 fees,
            uint256 latestHeight
        ) = bridge.getBridgeStats();

        assertEq(deposited, 0);
        assertEq(withdrawn, 0);
        assertEq(escrowCount, 0);
        assertEq(escrowsFinished, 0);
        assertEq(escrowsCancelled, 0);
        assertEq(fees, 0);
        assertEq(latestHeight, 0);

        // Make a deposit
        uint256 amount = 5 * UATOM_PER_ATOM;
        _initiateDeposit(amount, keccak256("stats_tx"));

        (deposited, , , , , fees, latestHeight) = bridge.getBridgeStats();
        assertEq(deposited, amount);
        assertEq(fees, (amount * 5) / 10_000);
        assertEq(latestHeight, 1);

        // Make a withdrawal
        vm.prank(admin);
        wATOM.mint(user, amount);
        vm.startPrank(user);
        wATOM.approve(address(bridge), amount);
        bridge.initiateWithdrawal(keccak256("cosmos_recip_stats"), amount);
        vm.stopPrank();

        (, withdrawn, , , , , ) = bridge.getBridgeStats();
        assertEq(withdrawn, amount);

        // Create and finish an escrow
        bytes32 preimage = keccak256("stats_preimage");
        bytes32 hashlock = sha256(abi.encodePacked(preimage));

        vm.deal(user, 1 ether);
        vm.prank(user);
        bytes32 escrowId = bridge.createEscrow{value: 0.5 ether}(
            keccak256("cosmos_party"),
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

    /// @notice 31. Deposit IDs are unique for different inputs
    function testFuzz_depositIdUniqueness(uint256 a, uint256 b) public {
        a = bound(a, MIN_DEPOSIT, MAX_DEPOSIT);
        b = bound(b, MIN_DEPOSIT, MAX_DEPOSIT);
        vm.assume(a != b);

        bytes32 txHashA = keccak256(abi.encode("uniq_tx_a", a));
        bytes32 depositIdA = _initiateDeposit(a, txHashA);

        // Submit a fresh header for the second deposit
        _submitVerifiedHeader(2, keccak256("header_uniq_b"));

        ICosmosBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        ICosmosBridgeAdapter.IBCProof memory proof = _buildStateProof();

        bytes32 txHashB = keccak256(abi.encode("uniq_tx_b", b));

        vm.prank(relayer);
        bytes32 depositIdB = bridge.initiateATOMDeposit(
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

    /// @notice 32. Double-finishing an escrow reverts
    function test_escrowDoubleFinish() public {
        bytes32 preimage = keccak256("double_finish_preimage");
        bytes32 hashlock = sha256(abi.encodePacked(preimage));

        uint256 finishAfter = block.timestamp + 1 hours;
        uint256 cancelAfter = finishAfter + 12 hours;

        vm.deal(user, 10 ether);
        vm.prank(user);
        bytes32 escrowId = bridge.createEscrow{value: 1 ether}(
            keccak256("cosmos_party"),
            hashlock,
            finishAfter,
            cancelAfter
        );

        vm.warp(finishAfter + 1);
        bridge.finishEscrow(escrowId, preimage);

        // Second finish should revert
        vm.expectRevert(
            abi.encodeWithSelector(
                ICosmosBridgeAdapter.EscrowNotActive.selector,
                escrowId
            )
        );
        bridge.finishEscrow(escrowId, preimage);
    }

    /// @notice 33. Double-completing a withdrawal reverts
    function test_withdrawalDoubleComplete() public {
        uint256 amount = 1 * UATOM_PER_ATOM;

        vm.prank(admin);
        wATOM.mint(user, amount);

        vm.startPrank(user);
        wATOM.approve(address(bridge), amount);
        bytes32 wId = bridge.initiateWithdrawal(
            keccak256("cosmos_recipient"),
            amount
        );
        vm.stopPrank();

        ICosmosBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        ICosmosBridgeAdapter.IBCProof memory proof = _buildStateProof();

        // Complete once
        vm.prank(relayer);
        bridge.completeWithdrawal(
            wId,
            keccak256("cosmos_tx_1"),
            proof,
            attestations
        );

        // Second complete should revert
        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                ICosmosBridgeAdapter.WithdrawalNotPending.selector,
                wId
            )
        );
        bridge.completeWithdrawal(
            wId,
            keccak256("cosmos_tx_2"),
            proof,
            attestations
        );
    }
}
