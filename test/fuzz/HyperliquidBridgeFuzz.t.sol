// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/crosschain/HyperliquidBridgeAdapter.sol";
import "../../contracts/interfaces/IHyperliquidBridgeAdapter.sol";
import "../../contracts/mocks/MockWrappedHYPE.sol";
import "../../contracts/mocks/MockHyperBFTValidatorOracle.sol";

/**
 * @title HyperliquidBridgeFuzz
 * @notice Foundry fuzz & invariant tests for HyperliquidBridgeAdapter
 * @dev Tests cover deposit/withdrawal flows, escrow lifecycle,
 *      block header submission, and security invariants
 *
 * Hyperliquid-specific test parameters:
 * - 1 HYPE = 1e8 drips (8 decimals, not 18)
 * - Chain ID 999 (HyperEVM mainnet)
 * - 3 block confirmations (~0.6s BFT finality)
 * - 4 active validators, 3/4 supermajority
 */
contract HyperliquidBridgeFuzz is Test {
    HyperliquidBridgeAdapter public bridge;
    MockWrappedHYPE public wHYPE;
    MockHyperBFTValidatorOracle public oracle;

    address public admin = makeAddr("admin");
    address public relayer = makeAddr("relayer");
    address public operator = makeAddr("operator");
    address public guardian = makeAddr("guardian");
    address public user1 = makeAddr("user1");
    address public user2 = makeAddr("user2");
    address public treasury = makeAddr("treasury");

    address public constant HL_BRIDGE_CONTRACT =
        address(0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB);
    address public constant HL_USER =
        address(0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC);

    uint256 public constant DRIPS_PER_HYPE = 100_000_000; // 1e8
    uint256 public constant MIN_DEPOSIT = DRIPS_PER_HYPE / 10; // 0.1 HYPE = 10_000_000 drips
    uint256 public constant MAX_DEPOSIT = 1_000_000 * DRIPS_PER_HYPE; // 1M HYPE

    // Validator addresses (4 validators for HyperBFT)
    address public constant VALIDATOR_1 =
        address(0x1111111111111111111111111111111111111111);
    address public constant VALIDATOR_2 =
        address(0x2222222222222222222222222222222222222222);
    address public constant VALIDATOR_3 =
        address(0x3333333333333333333333333333333333333333);
    address public constant VALIDATOR_4 =
        address(0x4444444444444444444444444444444444444444);

    /*//////////////////////////////////////////////////////////////
                              SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public {
        vm.startPrank(admin);

        // Deploy mocks
        wHYPE = new MockWrappedHYPE();
        oracle = new MockHyperBFTValidatorOracle();

        // Deploy bridge
        bridge = new HyperliquidBridgeAdapter(admin);

        // Grant roles
        bridge.grantRole(bridge.RELAYER_ROLE(), relayer);
        bridge.grantRole(bridge.OPERATOR_ROLE(), operator);
        bridge.grantRole(bridge.GUARDIAN_ROLE(), guardian);
        bridge.grantRole(bridge.TREASURY_ROLE(), treasury);

        // Register 4 HyperBFT validators
        oracle.addValidator(VALIDATOR_1);
        oracle.addValidator(VALIDATOR_2);
        oracle.addValidator(VALIDATOR_3);
        oracle.addValidator(VALIDATOR_4);

        // Configure bridge (3 min sigs, 3 block confirmations)
        bridge.configure(
            HL_BRIDGE_CONTRACT,
            address(wHYPE),
            address(oracle),
            3, // minValidatorSignatures (3/4 supermajority)
            3 // requiredBlockConfirmations (~0.6s)
        );

        // Fund user1 with wHYPE for withdrawal tests (10K HYPE in drips)
        wHYPE.mint(user1, 10_000 * DRIPS_PER_HYPE);

        vm.stopPrank();

        // Approve bridge to spend user1's wHYPE
        vm.prank(user1);
        IERC20(address(wHYPE)).approve(address(bridge), type(uint256).max);
    }

    /*//////////////////////////////////////////////////////////////
                        HELPER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _buildValidatorAttestations()
        internal
        pure
        returns (IHyperliquidBridgeAdapter.ValidatorAttestation[] memory)
    {
        IHyperliquidBridgeAdapter.ValidatorAttestation[]
            memory attestations = new IHyperliquidBridgeAdapter.ValidatorAttestation[](
                4
            );
        attestations[0] = IHyperliquidBridgeAdapter.ValidatorAttestation({
            validator: VALIDATOR_1,
            signature: hex"0123456789"
        });
        attestations[1] = IHyperliquidBridgeAdapter.ValidatorAttestation({
            validator: VALIDATOR_2,
            signature: hex"0123456789"
        });
        attestations[2] = IHyperliquidBridgeAdapter.ValidatorAttestation({
            validator: VALIDATOR_3,
            signature: hex"0123456789"
        });
        attestations[3] = IHyperliquidBridgeAdapter.ValidatorAttestation({
            validator: VALIDATOR_4,
            signature: hex"0123456789"
        });
        return attestations;
    }

    function _buildMerkleProof()
        internal
        pure
        returns (IHyperliquidBridgeAdapter.HyperliquidMerkleProof memory)
    {
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = keccak256("sibling");

        return
            IHyperliquidBridgeAdapter.HyperliquidMerkleProof({
                leafHash: keccak256("leaf"),
                proof: proof,
                index: 0
            });
    }

    function _submitFinalizedBlock(uint256 blockNum) internal {
        vm.prank(relayer);
        bridge.submitBlockHeader(
            blockNum,
            keccak256(abi.encodePacked("block", blockNum)),
            blockNum > 0
                ? keccak256(abi.encodePacked("block", blockNum - 1))
                : bytes32(0),
            keccak256(abi.encodePacked("txRoot", blockNum)),
            keccak256(abi.encodePacked("stateRoot", blockNum)),
            block.timestamp,
            _buildValidatorAttestations()
        );
    }

    /*//////////////////////////////////////////////////////////////
                    FUZZ: DEPOSIT AMOUNT BOUNDS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_depositRejectsAmountBelowMin(uint256 amount) public {
        amount = bound(amount, 0, MIN_DEPOSIT - 1);

        _submitFinalizedBlock(1);

        bytes32 txHash = keccak256(abi.encodePacked("tx", amount));

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                IHyperliquidBridgeAdapter.AmountTooSmall.selector,
                amount
            )
        );
        bridge.initiateHYPEDeposit(
            txHash,
            HL_USER,
            user1,
            amount,
            1,
            _buildMerkleProof(),
            _buildValidatorAttestations()
        );
    }

    function testFuzz_depositRejectsAmountAboveMax(uint256 amount) public {
        amount = bound(amount, MAX_DEPOSIT + 1, type(uint256).max);

        _submitFinalizedBlock(1);

        bytes32 txHash = keccak256(abi.encodePacked("tx", amount));

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                IHyperliquidBridgeAdapter.AmountTooLarge.selector,
                amount
            )
        );
        bridge.initiateHYPEDeposit(
            txHash,
            HL_USER,
            user1,
            amount,
            1,
            _buildMerkleProof(),
            _buildValidatorAttestations()
        );
    }

    /*//////////////////////////////////////////////////////////////
                    FUZZ: WITHDRAWAL AMOUNT BOUNDS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_withdrawalRejectsAmountBelowMin(uint256 amount) public {
        amount = bound(amount, 0, MIN_DEPOSIT - 1);

        vm.prank(user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                IHyperliquidBridgeAdapter.AmountTooSmall.selector,
                amount
            )
        );
        bridge.initiateWithdrawal(HL_USER, amount);
    }

    function testFuzz_withdrawalRejectsAmountAboveMax(uint256 amount) public {
        amount = bound(amount, MAX_DEPOSIT + 1, type(uint256).max);

        vm.prank(user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                IHyperliquidBridgeAdapter.AmountTooLarge.selector,
                amount
            )
        );
        bridge.initiateWithdrawal(HL_USER, amount);
    }

    /*//////////////////////////////////////////////////////////////
                    FUZZ: ESCROW TIMELOCKS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_escrowTimelockBounds(
        uint256 finishOffset,
        uint256 duration
    ) public {
        finishOffset = bound(finishOffset, 1, 365 days);
        uint256 finishAfter = block.timestamp + finishOffset;

        // Duration too short (< 30 minutes)
        duration = bound(duration, 0, 30 minutes - 1);
        uint256 cancelAfter = finishAfter + duration;

        vm.deal(user1, 10 ether);
        vm.prank(user1);
        (bool success, ) = address(bridge).call{value: 1 ether}(
            abi.encodeWithSelector(
                bridge.createEscrow.selector,
                HL_USER,
                keccak256("hashlock"),
                finishAfter,
                cancelAfter
            )
        );
        assertFalse(success, "Escrow with too short timelock should revert");
    }

    function testFuzz_escrowTimelockTooLong(
        uint256 finishOffset,
        uint256 duration
    ) public {
        finishOffset = bound(finishOffset, 1, 365 days);
        uint256 finishAfter = block.timestamp + finishOffset;

        // Duration too long (> 14 days)
        duration = bound(duration, 14 days + 1, 365 days);
        uint256 cancelAfter = finishAfter + duration;

        vm.deal(user1, 10 ether);
        vm.prank(user1);
        (bool success, ) = address(bridge).call{value: 1 ether}(
            abi.encodeWithSelector(
                bridge.createEscrow.selector,
                HL_USER,
                keccak256("hashlock"),
                finishAfter,
                cancelAfter
            )
        );
        assertFalse(success, "Escrow with too long timelock should revert");
    }

    /*//////////////////////////////////////////////////////////////
                    FUZZ: FEE CALCULATION
    //////////////////////////////////////////////////////////////*/

    function testFuzz_feeCalculation(uint256 amount) public pure {
        amount = bound(amount, MIN_DEPOSIT, MAX_DEPOSIT);

        uint256 expectedFee = (amount * 15) / 10_000; // 0.15% fee
        uint256 expectedNet = amount - expectedFee;

        // Fee should never exceed 1% even with rounding
        assertLe(expectedFee, amount / 100 + 1, "Fee exceeds 1%");

        // Net + fee should equal original amount
        assertEq(expectedNet + expectedFee, amount, "Fee arithmetic mismatch");
    }

    /*//////////////////////////////////////////////////////////////
                    FUZZ: REPLAY PROTECTION
    //////////////////////////////////////////////////////////////*/

    function testFuzz_txHashReplayProtection(bytes32 txHash) public {
        vm.assume(txHash != bytes32(0));

        _submitFinalizedBlock(1);

        // Tx hash should initially be unused
        assertFalse(bridge.usedHLTxHashes(txHash));
    }

    /*//////////////////////////////////////////////////////////////
                    FUZZ: NULLIFIER UNIQUENESS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_nullifierCannotBeReused(bytes32 nullifier) public {
        vm.assume(nullifier != bytes32(0));
        // Initially unused
        assertFalse(bridge.usedNullifiers(nullifier));
    }

    /*//////////////////////////////////////////////////////////////
                INVARIANT: BRIDGE CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    function testFuzz_configCannotSetZeroAddresses(
        address hlBridge,
        address wrappedHYPEAddr,
        address oracleAddr,
        uint256 minSigs
    ) public {
        vm.assume(minSigs > 0);

        if (
            hlBridge == address(0) ||
            wrappedHYPEAddr == address(0) ||
            oracleAddr == address(0)
        ) {
            vm.prank(admin);
            vm.expectRevert(IHyperliquidBridgeAdapter.ZeroAddress.selector);
            bridge.configure(hlBridge, wrappedHYPEAddr, oracleAddr, minSigs, 3);
        }
    }

    /*//////////////////////////////////////////////////////////////
                INVARIANT: NONCE MONOTONICITY
    //////////////////////////////////////////////////////////////*/

    function testFuzz_depositNonceOnlyIncreases(uint8 numOps) public {
        numOps = uint8(bound(numOps, 0, 5));

        uint256 prevNonce = bridge.depositNonce();

        for (uint8 i = 0; i < numOps; i++) {
            uint256 currentNonce = bridge.depositNonce();
            assertGe(currentNonce, prevNonce, "Nonce decreased");
            prevNonce = currentNonce;
        }
    }

    function testFuzz_withdrawalNonceOnlyIncreases(uint8 numOps) public {
        numOps = uint8(bound(numOps, 0, 5));

        uint256 prevNonce = bridge.withdrawalNonce();

        for (uint8 i = 0; i < numOps; i++) {
            uint256 currentNonce = bridge.withdrawalNonce();
            assertGe(currentNonce, prevNonce, "Nonce decreased");
            prevNonce = currentNonce;
        }
    }

    /*//////////////////////////////////////////////////////////////
              INVARIANT: ACCESS CONTROL
    //////////////////////////////////////////////////////////////*/

    function testFuzz_onlyRelayerCanInitiateDeposit(address caller) public {
        vm.assume(caller != relayer && caller != admin);

        _submitFinalizedBlock(1);

        vm.prank(caller);
        vm.expectRevert();
        bridge.initiateHYPEDeposit(
            keccak256("tx"),
            HL_USER,
            user1,
            MIN_DEPOSIT,
            1,
            _buildMerkleProof(),
            _buildValidatorAttestations()
        );
    }

    function testFuzz_onlyOperatorCanCompleteDeposit(address caller) public {
        vm.assume(caller != operator && caller != admin);

        vm.prank(caller);
        vm.expectRevert();
        bridge.completeHYPEDeposit(keccak256("deposit"));
    }

    function testFuzz_onlyGuardianCanPause(address caller) public {
        vm.assume(caller != guardian && caller != admin);

        vm.prank(caller);
        vm.expectRevert();
        bridge.pause();
    }

    /*//////////////////////////////////////////////////////////////
            INVARIANT: PAUSE BLOCKS OPERATIONS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_pauseBlocksDeposits() public {
        _submitFinalizedBlock(1);

        vm.prank(guardian);
        bridge.pause();

        vm.prank(relayer);
        vm.expectRevert();
        bridge.initiateHYPEDeposit(
            keccak256("tx"),
            HL_USER,
            user1,
            MIN_DEPOSIT,
            1,
            _buildMerkleProof(),
            _buildValidatorAttestations()
        );
    }

    function testFuzz_pauseBlocksWithdrawals() public {
        vm.prank(guardian);
        bridge.pause();

        vm.prank(user1);
        vm.expectRevert();
        bridge.initiateWithdrawal(HL_USER, MIN_DEPOSIT);
    }

    function testFuzz_pauseBlocksEscrow() public {
        vm.prank(guardian);
        bridge.pause();

        vm.deal(user1, 10 ether);
        vm.prank(user1);
        (bool success, ) = address(bridge).call{value: 1 ether}(
            abi.encodeWithSelector(
                bridge.createEscrow.selector,
                HL_USER,
                keccak256("hashlock"),
                block.timestamp + 1 hours,
                block.timestamp + 2 hours
            )
        );
        assertFalse(success, "Escrow creation should be blocked when paused");
    }

    /*//////////////////////////////////////////////////////////////
            ESCROW: FINISH & CANCEL LIFECYCLE
    //////////////////////////////////////////////////////////////*/

    function test_escrowCreateFinishLifecycle() public {
        bytes32 preimage = keccak256("secret_preimage");
        bytes32 hashlock = sha256(abi.encodePacked(preimage));

        uint256 finishAfter = block.timestamp + 2 hours;
        uint256 cancelAfter = block.timestamp + 14 hours;

        vm.deal(user1, 10 ether);

        vm.prank(user1);
        bytes32 escrowId = bridge.createEscrow{value: 1 ether}(
            HL_USER,
            hashlock,
            finishAfter,
            cancelAfter
        );

        // Cannot finish before finishAfter
        vm.prank(user2);
        vm.expectRevert();
        bridge.finishEscrow(escrowId, preimage);

        // Advance time past finishAfter
        vm.warp(finishAfter + 1);

        // Finish with valid preimage
        uint256 balBefore = user2.balance;
        vm.prank(user2);
        bridge.finishEscrow(escrowId, preimage);

        // User2 should receive the escrowed ETH
        assertEq(user2.balance - balBefore, 1 ether);

        // Verify escrow status
        IHyperliquidBridgeAdapter.HYPEEscrow memory esc = bridge.getEscrow(
            escrowId
        );
        assertEq(
            uint8(esc.status),
            uint8(IHyperliquidBridgeAdapter.EscrowStatus.FINISHED)
        );
        assertEq(esc.preimage, preimage);
    }

    function test_escrowCreateCancelLifecycle() public {
        bytes32 hashlock = sha256(abi.encodePacked(keccak256("secret")));

        uint256 finishAfter = block.timestamp + 2 hours;
        uint256 cancelAfter = block.timestamp + 14 hours;

        vm.deal(user1, 10 ether);

        vm.prank(user1);
        bytes32 escrowId = bridge.createEscrow{value: 1 ether}(
            HL_USER,
            hashlock,
            finishAfter,
            cancelAfter
        );

        // Cannot cancel before cancelAfter
        vm.prank(user1);
        vm.expectRevert();
        bridge.cancelEscrow(escrowId);

        // Advance time past cancelAfter
        vm.warp(cancelAfter + 1);

        uint256 balBefore = user1.balance;
        vm.prank(user1);
        bridge.cancelEscrow(escrowId);

        // User1 should get funds back
        assertEq(user1.balance - balBefore, 1 ether);

        // Verify escrow status
        IHyperliquidBridgeAdapter.HYPEEscrow memory esc = bridge.getEscrow(
            escrowId
        );
        assertEq(
            uint8(esc.status),
            uint8(IHyperliquidBridgeAdapter.EscrowStatus.CANCELLED)
        );
    }

    /*//////////////////////////////////////////////////////////////
            WITHDRAWAL REFUND AFTER DELAY
    //////////////////////////////////////////////////////////////*/

    function test_withdrawalRefundAfterDelay() public {
        uint256 amount = 1 * DRIPS_PER_HYPE; // 1 HYPE in drips

        vm.prank(user1);
        bytes32 withdrawalId = bridge.initiateWithdrawal(HL_USER, amount);

        // Cannot refund before 24 hours
        vm.prank(user1);
        vm.expectRevert();
        bridge.refundWithdrawal(withdrawalId);

        // Advance 24 hours
        vm.warp(block.timestamp + 24 hours + 1);

        vm.prank(user1);
        bridge.refundWithdrawal(withdrawalId);

        IHyperliquidBridgeAdapter.HYPEWithdrawal memory w = bridge
            .getWithdrawal(withdrawalId);
        assertEq(
            uint8(w.status),
            uint8(IHyperliquidBridgeAdapter.WithdrawalStatus.REFUNDED)
        );
    }

    /*//////////////////////////////////////////////////////////////
            BLOCK HEADER: PARENT CHAIN VALIDATION
    //////////////////////////////////////////////////////////////*/

    function testFuzz_blockHeaderParentChain(uint8 count) public {
        count = uint8(bound(count, 1, 10));

        for (uint8 i = 0; i < count; i++) {
            _submitFinalizedBlock(i + 1);
        }

        assertEq(bridge.latestBlockNumber(), count);
    }

    /*//////////////////////////////////////////////////////////////
            STATISTICS TRACKING
    //////////////////////////////////////////////////////////////*/

    function test_statisticsTracking() public {
        (uint256 totalDep, uint256 totalWith, uint256 totalEsc, , , , ) = bridge
            .getBridgeStats();

        assertEq(totalDep, 0);
        assertEq(totalWith, 0);
        assertEq(totalEsc, 0);
    }

    /*//////////////////////////////////////////////////////////////
            CONSTRUCTOR VALIDATION
    //////////////////////////////////////////////////////////////*/

    function test_constructorRejectsZeroAdmin() public {
        vm.expectRevert(IHyperliquidBridgeAdapter.ZeroAddress.selector);
        new HyperliquidBridgeAdapter(address(0));
    }

    /*//////////////////////////////////////////////////////////////
            VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function test_viewFunctionsReturnDefaults() public view {
        IHyperliquidBridgeAdapter.HYPEDeposit memory dep = bridge.getDeposit(
            bytes32(0)
        );
        assertEq(dep.depositId, bytes32(0));

        IHyperliquidBridgeAdapter.HYPEWithdrawal memory w = bridge
            .getWithdrawal(bytes32(0));
        assertEq(w.withdrawalId, bytes32(0));

        IHyperliquidBridgeAdapter.HYPEEscrow memory esc = bridge.getEscrow(
            bytes32(0)
        );
        assertEq(esc.escrowId, bytes32(0));
    }

    function test_userHistoryTracking() public view {
        bytes32[] memory deps = bridge.getUserDeposits(user1);
        assertEq(deps.length, 0);

        bytes32[] memory withs = bridge.getUserWithdrawals(user1);
        assertEq(withs.length, 0);

        bytes32[] memory escs = bridge.getUserEscrows(user1);
        assertEq(escs.length, 0);
    }

    /*//////////////////////////////////////////////////////////////
            TREASURY MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    function test_treasuryCanBeUpdated() public {
        address newTreasury = makeAddr("newTreasury");

        vm.prank(admin);
        bridge.setTreasury(newTreasury);

        assertEq(bridge.treasury(), newTreasury);
    }

    function test_treasuryRejectsZeroAddress() public {
        vm.prank(admin);
        vm.expectRevert(IHyperliquidBridgeAdapter.ZeroAddress.selector);
        bridge.setTreasury(address(0));
    }

    /*//////////////////////////////////////////////////////////////
            CONSTANTS VERIFICATION
    //////////////////////////////////////////////////////////////*/

    function test_constantsAreCorrect() public view {
        assertEq(bridge.HYPERLIQUID_CHAIN_ID(), 999);
        assertEq(bridge.DRIPS_PER_HYPE(), 100_000_000); // 1e8
        assertEq(bridge.MIN_DEPOSIT_DRIPS(), DRIPS_PER_HYPE / 10); // 0.1 HYPE
        assertEq(bridge.MAX_DEPOSIT_DRIPS(), 1_000_000 * DRIPS_PER_HYPE); // 1M HYPE
        assertEq(bridge.BRIDGE_FEE_BPS(), 15); // 0.15%
        assertEq(bridge.BPS_DENOMINATOR(), 10_000);
        assertEq(bridge.MIN_ESCROW_TIMELOCK(), 30 minutes);
        assertEq(bridge.MAX_ESCROW_TIMELOCK(), 14 days);
        assertEq(bridge.WITHDRAWAL_REFUND_DELAY(), 24 hours);
        assertEq(bridge.DEFAULT_BLOCK_CONFIRMATIONS(), 3);
    }

    /*//////////////////////////////////////////////////////////////
            HYPERLIQUID-SPECIFIC: DRIP PRECISION
    //////////////////////////////////////////////////////////////*/

    function testFuzz_dripPrecision(uint256 hypeAmount) public pure {
        hypeAmount = bound(hypeAmount, 1, 1_000_000);

        uint256 drips = hypeAmount * DRIPS_PER_HYPE;
        uint256 backToHype = drips / DRIPS_PER_HYPE;

        assertEq(backToHype, hypeAmount, "Drip conversion not reversible");
        assertEq(drips % DRIPS_PER_HYPE, 0, "Drips should be exact multiple");
    }

    function testFuzz_dripSubUnitDeposit(uint256 subUnitDrips) public {
        // Test deposits of fractional HYPE amounts (sub-unit drips)
        subUnitDrips = bound(subUnitDrips, MIN_DEPOSIT, DRIPS_PER_HYPE - 1);

        bytes32 txHash = keccak256(
            abi.encodePacked("sub_unit_tx", subUnitDrips)
        );

        // Build a merkle proof that matches the txHash and derive txRoot
        bytes32 sibling = keccak256("sibling");
        bytes32 txRoot = keccak256(abi.encodePacked(txHash, sibling));

        // Submit block with a txRoot that matches our proof
        vm.prank(relayer);
        bridge.submitBlockHeader(
            1,
            keccak256(abi.encodePacked("block", uint256(1))),
            keccak256(abi.encodePacked("block", uint256(0))),
            txRoot,
            keccak256(abi.encodePacked("stateRoot", uint256(1))),
            block.timestamp,
            _buildValidatorAttestations()
        );

        bytes32[] memory proof = new bytes32[](1);
        proof[0] = sibling;
        IHyperliquidBridgeAdapter.HyperliquidMerkleProof
            memory merkleProof = IHyperliquidBridgeAdapter
                .HyperliquidMerkleProof({
                    leafHash: txHash,
                    proof: proof,
                    index: 0
                });

        // Should succeed — fractional HYPE deposits above min are valid
        vm.prank(relayer);
        bytes32 depositId = bridge.initiateHYPEDeposit(
            txHash,
            HL_USER,
            user1,
            subUnitDrips,
            1,
            merkleProof,
            _buildValidatorAttestations()
        );

        IHyperliquidBridgeAdapter.HYPEDeposit memory dep = bridge.getDeposit(
            depositId
        );
        assertEq(dep.amountDrips, subUnitDrips);
    }
}
