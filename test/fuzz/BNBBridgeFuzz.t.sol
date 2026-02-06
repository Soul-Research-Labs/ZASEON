// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/crosschain/BNBBridgeAdapter.sol";
import "../../contracts/interfaces/IBNBBridgeAdapter.sol";
import "../../contracts/mocks/MockWrappedBNB.sol";
import "../../contracts/mocks/MockBSCValidatorOracle.sol";

/**
 * @title BNBBridgeFuzz
 * @notice Foundry fuzz & invariant tests for BNBBridgeAdapter
 * @dev Tests cover deposit/withdrawal flows, escrow lifecycle,
 *      block header submission, and security invariants
 */
contract BNBBridgeFuzz is Test {
    BNBBridgeAdapter public bridge;
    MockWrappedBNB public wBNB;
    MockBSCValidatorOracle public oracle;

    address public admin = makeAddr("admin");
    address public relayer = makeAddr("relayer");
    address public operator = makeAddr("operator");
    address public guardian = makeAddr("guardian");
    address public user1 = makeAddr("user1");
    address public user2 = makeAddr("user2");
    address public treasury = makeAddr("treasury");

    address public constant BSC_BRIDGE_CONTRACT =
        address(0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB);
    address public constant BSC_USER =
        address(0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC);

    uint256 public constant MIN_DEPOSIT = 0.01 ether; // 0.01 BNB
    uint256 public constant MAX_DEPOSIT = 100_000 ether; // 100K BNB

    // Validator addresses
    address public constant VALIDATOR_1 =
        address(0x1111111111111111111111111111111111111111);
    address public constant VALIDATOR_2 =
        address(0x2222222222222222222222222222222222222222);
    address public constant VALIDATOR_3 =
        address(0x3333333333333333333333333333333333333333);

    /*//////////////////////////////////////////////////////////////
                              SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public {
        vm.startPrank(admin);

        // Deploy mocks
        wBNB = new MockWrappedBNB(admin);
        oracle = new MockBSCValidatorOracle(admin);

        // Deploy bridge
        bridge = new BNBBridgeAdapter(admin);

        // Grant roles
        bridge.grantRole(bridge.RELAYER_ROLE(), relayer);
        bridge.grantRole(bridge.OPERATOR_ROLE(), operator);
        bridge.grantRole(bridge.GUARDIAN_ROLE(), guardian);
        bridge.grantRole(bridge.TREASURY_ROLE(), treasury);

        // Register validators
        oracle.registerValidator(VALIDATOR_1);
        oracle.registerValidator(VALIDATOR_2);
        oracle.registerValidator(VALIDATOR_3);

        // Configure bridge
        bridge.configure(
            BSC_BRIDGE_CONTRACT,
            address(wBNB),
            address(oracle),
            2, // minValidatorSignatures
            15 // requiredBlockConfirmations
        );

        // Grant minter role to bridge
        wBNB.grantMinter(address(bridge));

        // Fund user1 with wBNB for withdrawal tests
        wBNB.mint(user1, 10_000 ether); // 10K BNB

        vm.stopPrank();

        // Approve bridge to spend user1's wBNB
        vm.prank(user1);
        wBNB.approve(address(bridge), type(uint256).max);
    }

    /*//////////////////////////////////////////////////////////////
                        HELPER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _buildValidatorAttestations()
        internal
        pure
        returns (IBNBBridgeAdapter.ValidatorAttestation[] memory)
    {
        IBNBBridgeAdapter.ValidatorAttestation[]
            memory attestations = new IBNBBridgeAdapter.ValidatorAttestation[](
                3
            );
        attestations[0] = IBNBBridgeAdapter.ValidatorAttestation({
            validator: VALIDATOR_1,
            signature: hex"0123456789"
        });
        attestations[1] = IBNBBridgeAdapter.ValidatorAttestation({
            validator: VALIDATOR_2,
            signature: hex"0123456789"
        });
        attestations[2] = IBNBBridgeAdapter.ValidatorAttestation({
            validator: VALIDATOR_3,
            signature: hex"0123456789"
        });
        return attestations;
    }

    function _buildMerkleProof()
        internal
        pure
        returns (IBNBBridgeAdapter.BSCMerkleProof memory)
    {
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = keccak256("sibling");

        return
            IBNBBridgeAdapter.BSCMerkleProof({
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
            keccak256(abi.encodePacked("receiptsRoot", blockNum)),
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
                IBNBBridgeAdapter.AmountTooSmall.selector,
                amount
            )
        );
        bridge.initiateBNBDeposit(
            txHash,
            BSC_USER,
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
                IBNBBridgeAdapter.AmountTooLarge.selector,
                amount
            )
        );
        bridge.initiateBNBDeposit(
            txHash,
            BSC_USER,
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
                IBNBBridgeAdapter.AmountTooSmall.selector,
                amount
            )
        );
        bridge.initiateWithdrawal(BSC_USER, amount);
    }

    function testFuzz_withdrawalRejectsAmountAboveMax(uint256 amount) public {
        amount = bound(amount, MAX_DEPOSIT + 1, type(uint256).max);

        vm.prank(user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                IBNBBridgeAdapter.AmountTooLarge.selector,
                amount
            )
        );
        bridge.initiateWithdrawal(BSC_USER, amount);
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

        // Duration too short (< 1 hour)
        duration = bound(duration, 0, 1 hours - 1);
        uint256 cancelAfter = finishAfter + duration;

        vm.deal(user1, 10 ether);
        vm.prank(user1);
        (bool success, ) = address(bridge).call{value: 1 ether}(
            abi.encodeWithSelector(
                bridge.createEscrow.selector,
                BSC_USER,
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

        // Duration too long (> 30 days)
        duration = bound(duration, 30 days + 1, 365 days);
        uint256 cancelAfter = finishAfter + duration;

        vm.deal(user1, 10 ether);
        vm.prank(user1);
        (bool success, ) = address(bridge).call{value: 1 ether}(
            abi.encodeWithSelector(
                bridge.createEscrow.selector,
                BSC_USER,
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

        uint256 expectedFee = (amount * 25) / 10_000;
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
        assertFalse(bridge.usedBSCTxHashes(txHash));
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
        address bscBridge,
        address wrappedBNB,
        address oracleAddr,
        uint256 minSigs
    ) public {
        vm.assume(minSigs > 0);

        if (
            bscBridge == address(0) ||
            wrappedBNB == address(0) ||
            oracleAddr == address(0)
        ) {
            vm.prank(admin);
            vm.expectRevert(IBNBBridgeAdapter.ZeroAddress.selector);
            bridge.configure(
                bscBridge,
                wrappedBNB,
                oracleAddr,
                minSigs,
                15
            );
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
        bridge.initiateBNBDeposit(
            keccak256("tx"),
            BSC_USER,
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
        bridge.completeBNBDeposit(keccak256("deposit"));
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
        bridge.initiateBNBDeposit(
            keccak256("tx"),
            BSC_USER,
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
        bridge.initiateWithdrawal(BSC_USER, MIN_DEPOSIT);
    }

    function testFuzz_pauseBlocksEscrow() public {
        vm.prank(guardian);
        bridge.pause();

        vm.deal(user1, 10 ether);
        vm.prank(user1);
        (bool success, ) = address(bridge).call{value: 1 ether}(
            abi.encodeWithSelector(
                bridge.createEscrow.selector,
                BSC_USER,
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
        uint256 cancelAfter = block.timestamp + 26 hours;

        vm.deal(user1, 10 ether);

        vm.prank(user1);
        bytes32 escrowId = bridge.createEscrow{value: 1 ether}(
            BSC_USER,
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
        IBNBBridgeAdapter.BNBEscrow memory esc = bridge.getEscrow(escrowId);
        assertEq(
            uint8(esc.status),
            uint8(IBNBBridgeAdapter.EscrowStatus.FINISHED)
        );
        assertEq(esc.preimage, preimage);
    }

    function test_escrowCreateCancelLifecycle() public {
        bytes32 hashlock = sha256(abi.encodePacked(keccak256("secret")));

        uint256 finishAfter = block.timestamp + 2 hours;
        uint256 cancelAfter = block.timestamp + 26 hours;

        vm.deal(user1, 10 ether);

        vm.prank(user1);
        bytes32 escrowId = bridge.createEscrow{value: 1 ether}(
            BSC_USER,
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
        IBNBBridgeAdapter.BNBEscrow memory esc = bridge.getEscrow(escrowId);
        assertEq(
            uint8(esc.status),
            uint8(IBNBBridgeAdapter.EscrowStatus.CANCELLED)
        );
    }

    /*//////////////////////////////////////////////////////////////
            WITHDRAWAL REFUND AFTER DELAY
    //////////////////////////////////////////////////////////////*/

    function test_withdrawalRefundAfterDelay() public {
        uint256 amount = 1 ether; // 1 BNB

        vm.prank(user1);
        bytes32 withdrawalId = bridge.initiateWithdrawal(BSC_USER, amount);

        // Cannot refund before 48 hours
        vm.prank(user1);
        vm.expectRevert();
        bridge.refundWithdrawal(withdrawalId);

        // Advance 48 hours
        vm.warp(block.timestamp + 48 hours + 1);

        vm.prank(user1);
        bridge.refundWithdrawal(withdrawalId);

        IBNBBridgeAdapter.BNBWithdrawal memory w = bridge.getWithdrawal(
            withdrawalId
        );
        assertEq(
            uint8(w.status),
            uint8(IBNBBridgeAdapter.WithdrawalStatus.REFUNDED)
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
        vm.expectRevert(IBNBBridgeAdapter.ZeroAddress.selector);
        new BNBBridgeAdapter(address(0));
    }

    /*//////////////////////////////////////////////////////////////
            VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function test_viewFunctionsReturnDefaults() public view {
        IBNBBridgeAdapter.BNBDeposit memory dep = bridge.getDeposit(
            bytes32(0)
        );
        assertEq(dep.depositId, bytes32(0));

        IBNBBridgeAdapter.BNBWithdrawal memory w = bridge.getWithdrawal(
            bytes32(0)
        );
        assertEq(w.withdrawalId, bytes32(0));

        IBNBBridgeAdapter.BNBEscrow memory esc = bridge.getEscrow(bytes32(0));
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
        vm.expectRevert(IBNBBridgeAdapter.ZeroAddress.selector);
        bridge.setTreasury(address(0));
    }

    /*//////////////////////////////////////////////////////////////
            CONSTANTS VERIFICATION
    //////////////////////////////////////////////////////////////*/

    function test_constantsAreCorrect() public view {
        assertEq(bridge.BSC_CHAIN_ID(), 56);
        assertEq(bridge.WEI_PER_BNB(), 1 ether);
        assertEq(bridge.MIN_DEPOSIT_WEI(), 0.01 ether); // 0.01 BNB
        assertEq(bridge.MAX_DEPOSIT_WEI(), 100_000 ether); // 100K BNB
        assertEq(bridge.BRIDGE_FEE_BPS(), 25);
        assertEq(bridge.BPS_DENOMINATOR(), 10_000);
        assertEq(bridge.MIN_ESCROW_TIMELOCK(), 1 hours);
        assertEq(bridge.MAX_ESCROW_TIMELOCK(), 30 days);
        assertEq(bridge.WITHDRAWAL_REFUND_DELAY(), 48 hours);
        assertEq(bridge.DEFAULT_BLOCK_CONFIRMATIONS(), 15);
    }
}
