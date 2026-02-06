// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/crosschain/CantonBridgeAdapter.sol";
import "../../contracts/interfaces/ICantonBridgeAdapter.sol";
import "../../contracts/mocks/MockWrappedCANTON.sol";
import "../../contracts/mocks/MockCantonMediatorOracle.sol";

/**
 * @title CantonBridgeFuzz
 * @notice Foundry fuzz & invariant tests for CantonBridgeAdapter
 * @dev Tests cover deposit/withdrawal flows, escrow lifecycle,
 *      round header submission, and security invariants
 *
 * Canton-specific test parameters:
 * - 1 CANTON = 1e6 microcanton (6 decimals)
 * - Chain ID 510 (canton-global-1 EVM mapping)
 * - 5 round confirmations (~10s synchronizer finality)
 * - 6 active mediators (test set), 5/6 supermajority
 */
contract CantonBridgeFuzz is Test {
    CantonBridgeAdapter public bridge;
    MockWrappedCANTON public wCANTON;
    MockCantonMediatorOracle public oracle;

    address public admin = makeAddr("admin");
    address public relayer = makeAddr("relayer");
    address public operator = makeAddr("operator");
    address public guardian = makeAddr("guardian");
    address public user1 = makeAddr("user1");
    address public user2 = makeAddr("user2");
    address public treasury = makeAddr("treasury");

    address public constant CANTON_BRIDGE_CONTRACT =
        address(0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB);
    address public constant CANTON_USER =
        address(0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC);

    uint256 public constant MICROCANTON_PER_CANTON = 1_000_000; // 1e6
    uint256 public constant MIN_DEPOSIT = MICROCANTON_PER_CANTON / 10; // 0.1 CANTON = 100_000 microcanton
    uint256 public constant MAX_DEPOSIT = 10_000_000 * MICROCANTON_PER_CANTON; // 10M CANTON

    // Mediator addresses (6 mediators for Canton test set)
    address public constant MEDIATOR_1 =
        address(0x1111111111111111111111111111111111111111);
    address public constant MEDIATOR_2 =
        address(0x2222222222222222222222222222222222222222);
    address public constant MEDIATOR_3 =
        address(0x3333333333333333333333333333333333333333);
    address public constant MEDIATOR_4 =
        address(0x4444444444444444444444444444444444444444);
    address public constant MEDIATOR_5 =
        address(0x5555555555555555555555555555555555555555);
    address public constant MEDIATOR_6 =
        address(0x6666666666666666666666666666666666666666);

    /*//////////////////////////////////////////////////////////////
                              SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public {
        vm.startPrank(admin);

        // Deploy mocks
        wCANTON = new MockWrappedCANTON();
        oracle = new MockCantonMediatorOracle();

        // Deploy bridge
        bridge = new CantonBridgeAdapter(admin);

        // Grant roles
        bridge.grantRole(bridge.RELAYER_ROLE(), relayer);
        bridge.grantRole(bridge.OPERATOR_ROLE(), operator);
        bridge.grantRole(bridge.GUARDIAN_ROLE(), guardian);
        bridge.grantRole(bridge.TREASURY_ROLE(), treasury);

        // Register 6 Canton mediators
        oracle.addMediator(MEDIATOR_1);
        oracle.addMediator(MEDIATOR_2);
        oracle.addMediator(MEDIATOR_3);
        oracle.addMediator(MEDIATOR_4);
        oracle.addMediator(MEDIATOR_5);
        oracle.addMediator(MEDIATOR_6);

        // Configure bridge (5 min sigs, 5 round confirmations)
        bridge.configure(
            CANTON_BRIDGE_CONTRACT,
            address(wCANTON),
            address(oracle),
            5, // minMediatorSignatures (5/6 supermajority)
            5 // requiredRoundConfirmations (~10s)
        );

        // Fund user1 with wCANTON for withdrawal tests (10K CANTON in microcanton)
        wCANTON.mint(user1, 10_000 * MICROCANTON_PER_CANTON);

        vm.stopPrank();

        // Approve bridge to spend user1's wCANTON
        vm.prank(user1);
        IERC20(address(wCANTON)).approve(address(bridge), type(uint256).max);
    }

    /*//////////////////////////////////////////////////////////////
                        HELPER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _buildMediatorAttestations()
        internal
        pure
        returns (ICantonBridgeAdapter.MediatorAttestation[] memory)
    {
        ICantonBridgeAdapter.MediatorAttestation[]
            memory attestations = new ICantonBridgeAdapter.MediatorAttestation[](
                6
            );
        attestations[0] = ICantonBridgeAdapter.MediatorAttestation({
            mediator: MEDIATOR_1,
            signature: hex"0123456789"
        });
        attestations[1] = ICantonBridgeAdapter.MediatorAttestation({
            mediator: MEDIATOR_2,
            signature: hex"0123456789"
        });
        attestations[2] = ICantonBridgeAdapter.MediatorAttestation({
            mediator: MEDIATOR_3,
            signature: hex"0123456789"
        });
        attestations[3] = ICantonBridgeAdapter.MediatorAttestation({
            mediator: MEDIATOR_4,
            signature: hex"0123456789"
        });
        attestations[4] = ICantonBridgeAdapter.MediatorAttestation({
            mediator: MEDIATOR_5,
            signature: hex"0123456789"
        });
        attestations[5] = ICantonBridgeAdapter.MediatorAttestation({
            mediator: MEDIATOR_6,
            signature: hex"0123456789"
        });
        return attestations;
    }

    function _buildMerkleProof()
        internal
        pure
        returns (ICantonBridgeAdapter.CantonMerkleProof memory)
    {
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = keccak256("sibling");

        return
            ICantonBridgeAdapter.CantonMerkleProof({
                leafHash: keccak256("leaf"),
                proof: proof,
                index: 0
            });
    }

    function _submitFinalizedRound(uint256 roundNum) internal {
        vm.prank(relayer);
        bridge.submitRoundHeader(
            roundNum,
            keccak256(abi.encodePacked("round", roundNum)),
            roundNum > 0
                ? keccak256(abi.encodePacked("round", roundNum - 1))
                : bytes32(0),
            keccak256(abi.encodePacked("txRoot", roundNum)),
            keccak256(abi.encodePacked("stateRoot", roundNum)),
            keccak256(abi.encodePacked("mediatorSet", roundNum)),
            keccak256(abi.encodePacked("domainTopology", roundNum)),
            block.timestamp,
            _buildMediatorAttestations()
        );
    }

    /*//////////////////////////////////////////////////////////////
                    FUZZ: DEPOSIT AMOUNT BOUNDS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_depositRejectsAmountBelowMin(uint256 amount) public {
        amount = bound(amount, 0, MIN_DEPOSIT - 1);

        _submitFinalizedRound(1);

        bytes32 txHash = keccak256(abi.encodePacked("tx", amount));

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                ICantonBridgeAdapter.AmountTooSmall.selector,
                amount
            )
        );
        bridge.initiateCANTONDeposit(
            txHash,
            CANTON_USER,
            user1,
            amount,
            1,
            _buildMerkleProof(),
            _buildMediatorAttestations()
        );
    }

    function testFuzz_depositRejectsAmountAboveMax(uint256 amount) public {
        amount = bound(amount, MAX_DEPOSIT + 1, type(uint256).max);

        _submitFinalizedRound(1);

        bytes32 txHash = keccak256(abi.encodePacked("tx", amount));

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                ICantonBridgeAdapter.AmountTooLarge.selector,
                amount
            )
        );
        bridge.initiateCANTONDeposit(
            txHash,
            CANTON_USER,
            user1,
            amount,
            1,
            _buildMerkleProof(),
            _buildMediatorAttestations()
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
                ICantonBridgeAdapter.AmountTooSmall.selector,
                amount
            )
        );
        bridge.initiateWithdrawal(CANTON_USER, amount);
    }

    function testFuzz_withdrawalRejectsAmountAboveMax(uint256 amount) public {
        amount = bound(amount, MAX_DEPOSIT + 1, type(uint256).max);

        vm.prank(user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                ICantonBridgeAdapter.AmountTooLarge.selector,
                amount
            )
        );
        bridge.initiateWithdrawal(CANTON_USER, amount);
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

        // Duration too short (< 2 hours)
        duration = bound(duration, 0, 2 hours - 1);
        uint256 cancelAfter = finishAfter + duration;

        vm.deal(user1, 10 ether);
        vm.prank(user1);
        (bool success, ) = address(bridge).call{value: 1 ether}(
            abi.encodeWithSelector(
                bridge.createEscrow.selector,
                CANTON_USER,
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

        // Duration too long (> 60 days)
        duration = bound(duration, 60 days + 1, 365 days);
        uint256 cancelAfter = finishAfter + duration;

        vm.deal(user1, 10 ether);
        vm.prank(user1);
        (bool success, ) = address(bridge).call{value: 1 ether}(
            abi.encodeWithSelector(
                bridge.createEscrow.selector,
                CANTON_USER,
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

        uint256 expectedFee = (amount * 5) / 10_000; // 0.05% fee
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

        _submitFinalizedRound(1);

        // Tx hash should initially be unused
        assertFalse(bridge.usedCantonTxHashes(txHash));
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
        address cantonBridge,
        address wrappedCANTONAddr,
        address oracleAddr,
        uint256 minSigs
    ) public {
        vm.assume(minSigs > 0);

        if (
            cantonBridge == address(0) ||
            wrappedCANTONAddr == address(0) ||
            oracleAddr == address(0)
        ) {
            vm.prank(admin);
            vm.expectRevert(ICantonBridgeAdapter.ZeroAddress.selector);
            bridge.configure(cantonBridge, wrappedCANTONAddr, oracleAddr, minSigs, 5);
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

        _submitFinalizedRound(1);

        vm.prank(caller);
        vm.expectRevert();
        bridge.initiateCANTONDeposit(
            keccak256("tx"),
            CANTON_USER,
            user1,
            MIN_DEPOSIT,
            1,
            _buildMerkleProof(),
            _buildMediatorAttestations()
        );
    }

    function testFuzz_onlyOperatorCanCompleteDeposit(address caller) public {
        vm.assume(caller != operator && caller != admin);

        vm.prank(caller);
        vm.expectRevert();
        bridge.completeCANTONDeposit(keccak256("deposit"));
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
        _submitFinalizedRound(1);

        vm.prank(guardian);
        bridge.pause();

        vm.prank(relayer);
        vm.expectRevert();
        bridge.initiateCANTONDeposit(
            keccak256("tx"),
            CANTON_USER,
            user1,
            MIN_DEPOSIT,
            1,
            _buildMerkleProof(),
            _buildMediatorAttestations()
        );
    }

    function testFuzz_pauseBlocksWithdrawals() public {
        vm.prank(guardian);
        bridge.pause();

        vm.prank(user1);
        vm.expectRevert();
        bridge.initiateWithdrawal(CANTON_USER, MIN_DEPOSIT);
    }

    function testFuzz_pauseBlocksEscrow() public {
        vm.prank(guardian);
        bridge.pause();

        vm.deal(user1, 10 ether);
        vm.prank(user1);
        (bool success, ) = address(bridge).call{value: 1 ether}(
            abi.encodeWithSelector(
                bridge.createEscrow.selector,
                CANTON_USER,
                keccak256("hashlock"),
                block.timestamp + 3 hours,
                block.timestamp + 26 hours
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

        uint256 finishAfter = block.timestamp + 3 hours;
        uint256 cancelAfter = block.timestamp + 48 hours;

        vm.deal(user1, 10 ether);

        vm.prank(user1);
        bytes32 escrowId = bridge.createEscrow{value: 1 ether}(
            CANTON_USER,
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
        ICantonBridgeAdapter.CANTONEscrow memory esc = bridge.getEscrow(
            escrowId
        );
        assertEq(
            uint8(esc.status),
            uint8(ICantonBridgeAdapter.EscrowStatus.FINISHED)
        );
        assertEq(esc.preimage, preimage);
    }

    function test_escrowCreateCancelLifecycle() public {
        bytes32 hashlock = sha256(abi.encodePacked(keccak256("secret")));

        uint256 finishAfter = block.timestamp + 3 hours;
        uint256 cancelAfter = block.timestamp + 48 hours;

        vm.deal(user1, 10 ether);

        vm.prank(user1);
        bytes32 escrowId = bridge.createEscrow{value: 1 ether}(
            CANTON_USER,
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
        ICantonBridgeAdapter.CANTONEscrow memory esc = bridge.getEscrow(
            escrowId
        );
        assertEq(
            uint8(esc.status),
            uint8(ICantonBridgeAdapter.EscrowStatus.CANCELLED)
        );
    }

    /*//////////////////////////////////////////////////////////////
            WITHDRAWAL REFUND AFTER DELAY
    //////////////////////////////////////////////////////////////*/

    function test_withdrawalRefundAfterDelay() public {
        uint256 amount = 1 * MICROCANTON_PER_CANTON; // 1 CANTON in microcanton

        vm.prank(user1);
        bytes32 withdrawalId = bridge.initiateWithdrawal(CANTON_USER, amount);

        // Cannot refund before 72 hours
        vm.prank(user1);
        vm.expectRevert();
        bridge.refundWithdrawal(withdrawalId);

        // Advance 72 hours
        vm.warp(block.timestamp + 72 hours + 1);

        vm.prank(user1);
        bridge.refundWithdrawal(withdrawalId);

        ICantonBridgeAdapter.CANTONWithdrawal memory w = bridge
            .getWithdrawal(withdrawalId);
        assertEq(
            uint8(w.status),
            uint8(ICantonBridgeAdapter.WithdrawalStatus.REFUNDED)
        );
    }

    /*//////////////////////////////////////////////////////////////
            ROUND HEADER: PARENT CHAIN VALIDATION
    //////////////////////////////////////////////////////////////*/

    function testFuzz_roundHeaderParentChain(uint8 count) public {
        count = uint8(bound(count, 1, 10));

        for (uint8 i = 0; i < count; i++) {
            _submitFinalizedRound(i + 1);
        }

        assertEq(bridge.latestRoundNumber(), count);
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
        vm.expectRevert(ICantonBridgeAdapter.ZeroAddress.selector);
        new CantonBridgeAdapter(address(0));
    }

    /*//////////////////////////////////////////////////////////////
            VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function test_viewFunctionsReturnDefaults() public view {
        ICantonBridgeAdapter.CANTONDeposit memory dep = bridge.getDeposit(
            bytes32(0)
        );
        assertEq(dep.depositId, bytes32(0));

        ICantonBridgeAdapter.CANTONWithdrawal memory w = bridge
            .getWithdrawal(bytes32(0));
        assertEq(w.withdrawalId, bytes32(0));

        ICantonBridgeAdapter.CANTONEscrow memory esc = bridge.getEscrow(
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
        vm.expectRevert(ICantonBridgeAdapter.ZeroAddress.selector);
        bridge.setTreasury(address(0));
    }

    /*//////////////////////////////////////////////////////////////
            CONSTANTS VERIFICATION
    //////////////////////////////////////////////////////////////*/

    function test_constantsAreCorrect() public view {
        assertEq(bridge.CANTON_CHAIN_ID(), 510);
        assertEq(bridge.MICROCANTON_PER_CANTON(), 1_000_000); // 1e6
        assertEq(bridge.MIN_DEPOSIT_MICROCANTON(), MICROCANTON_PER_CANTON / 10); // 0.1 CANTON
        assertEq(bridge.MAX_DEPOSIT_MICROCANTON(), 10_000_000 * MICROCANTON_PER_CANTON); // 10M CANTON
        assertEq(bridge.BRIDGE_FEE_BPS(), 5); // 0.05%
        assertEq(bridge.BPS_DENOMINATOR(), 10_000);
        assertEq(bridge.MIN_ESCROW_TIMELOCK(), 2 hours);
        assertEq(bridge.MAX_ESCROW_TIMELOCK(), 60 days);
        assertEq(bridge.WITHDRAWAL_REFUND_DELAY(), 72 hours);
        assertEq(bridge.DEFAULT_ROUND_CONFIRMATIONS(), 5);
    }

    /*//////////////////////////////////////////////////////////////
            CANTON-SPECIFIC: MICROCANTON PRECISION
    //////////////////////////////////////////////////////////////*/

    function testFuzz_microcantonPrecision(uint256 cantonAmount) public pure {
        cantonAmount = bound(cantonAmount, 1, 10_000_000);

        uint256 microcanton = cantonAmount * MICROCANTON_PER_CANTON;
        uint256 backToCanton = microcanton / MICROCANTON_PER_CANTON;

        assertEq(backToCanton, cantonAmount, "Microcanton conversion not reversible");
        assertEq(microcanton % MICROCANTON_PER_CANTON, 0, "Microcanton should be exact multiple");
    }

    function testFuzz_microcantonSubUnitDeposit(uint256 subUnitMicrocanton) public {
        // Test deposits of fractional CANTON amounts (sub-unit microcanton)
        subUnitMicrocanton = bound(subUnitMicrocanton, MIN_DEPOSIT, MICROCANTON_PER_CANTON - 1);

        bytes32 txHash = keccak256(
            abi.encodePacked("sub_unit_tx", subUnitMicrocanton)
        );

        // Build a merkle proof that matches the txHash and derive txRoot
        bytes32 sibling = keccak256("sibling");
        bytes32 txRoot = keccak256(abi.encodePacked(txHash, sibling));

        // Submit round with a txRoot that matches our proof
        vm.prank(relayer);
        bridge.submitRoundHeader(
            1,
            keccak256(abi.encodePacked("round", uint256(1))),
            keccak256(abi.encodePacked("round", uint256(0))),
            txRoot,
            keccak256(abi.encodePacked("stateRoot", uint256(1))),
            keccak256(abi.encodePacked("mediatorSet", uint256(1))),
            keccak256(abi.encodePacked("domainTopology", uint256(1))),
            block.timestamp,
            _buildMediatorAttestations()
        );

        bytes32[] memory proof = new bytes32[](1);
        proof[0] = sibling;
        ICantonBridgeAdapter.CantonMerkleProof
            memory merkleProof = ICantonBridgeAdapter
                .CantonMerkleProof({
                    leafHash: txHash,
                    proof: proof,
                    index: 0
                });

        // Should succeed — fractional CANTON deposits above min are valid
        vm.prank(relayer);
        bytes32 depositId = bridge.initiateCANTONDeposit(
            txHash,
            CANTON_USER,
            user1,
            subUnitMicrocanton,
            1,
            merkleProof,
            _buildMediatorAttestations()
        );

        ICantonBridgeAdapter.CANTONDeposit memory dep = bridge.getDeposit(
            depositId
        );
        assertEq(dep.amountMicrocanton, subUnitMicrocanton);
    }
}
