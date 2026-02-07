// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {AvalancheBridgeAdapter} from "../../contracts/crosschain/AvalancheBridgeAdapter.sol";
import {IAvalancheBridgeAdapter} from "../../contracts/interfaces/IAvalancheBridgeAdapter.sol";
import {MockWrappedAVAX} from "../../contracts/mocks/MockWrappedAVAX.sol";
import {MockAvalancheWarpVerifier} from "../../contracts/mocks/MockAvalancheWarpVerifier.sol";

/**
 * @title AvalancheBridgeFuzz
 * @notice Foundry fuzz & invariant tests for the AvalancheBridgeAdapter
 * @dev Tests Wei precision (18 decimals), Snowman block verification,
 *      P-Chain validator BLS attestation, and Avalanche-specific bridge parameters.
 */
contract AvalancheBridgeFuzz is Test {
    AvalancheBridgeAdapter public bridge;
    MockWrappedAVAX public wAVAX;
    MockAvalancheWarpVerifier public warpVerifier;

    address public admin = address(0xA);
    address public relayer = address(0xB);
    address public user = address(0xC);
    address public treasury = address(0xD);

    // Validator addresses
    address constant VALIDATOR_1 = address(0x2001);
    address constant VALIDATOR_2 = address(0x2002);
    address constant VALIDATOR_3 = address(0x2003);

    uint256 constant MIN_DEPOSIT = 0.01 ether; // 0.01 AVAX (18 decimals)
    uint256 constant MAX_DEPOSIT = 10_000_000 ether; // 10M AVAX

    function setUp() public {
        vm.startPrank(admin);

        bridge = new AvalancheBridgeAdapter(admin);
        wAVAX = new MockWrappedAVAX();
        warpVerifier = new MockAvalancheWarpVerifier();

        // Register validators with voting power
        warpVerifier.addValidator(VALIDATOR_1, 100);
        warpVerifier.addValidator(VALIDATOR_2, 100);
        warpVerifier.addValidator(VALIDATOR_3, 100);

        // Configure bridge
        bridge.configure(
            address(0x1), // avalancheBridgeContract
            address(wAVAX),
            address(warpVerifier),
            2, // minValidatorSignatures
            1 // requiredConfirmations (sub-second Snowman finality)
        );

        bridge.setTreasury(treasury);
        bridge.grantRole(bridge.RELAYER_ROLE(), relayer);

        // Fund the bridge with wAVAX (100M AVAX in wei)
        wAVAX.mint(address(bridge), 100_000_000 ether);

        vm.stopPrank();
    }

    receive() external payable {}

    /*//////////////////////////////////////////////////////////////
                          HELPER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _buildValidatorAttestations()
        internal
        pure
        returns (IAvalancheBridgeAdapter.ValidatorAttestation[] memory)
    {
        IAvalancheBridgeAdapter.ValidatorAttestation[]
            memory attestations = new IAvalancheBridgeAdapter.ValidatorAttestation[](
                3
            );

        attestations[0] = IAvalancheBridgeAdapter.ValidatorAttestation({
            validator: VALIDATOR_1,
            signature: hex"01"
        });
        attestations[1] = IAvalancheBridgeAdapter.ValidatorAttestation({
            validator: VALIDATOR_2,
            signature: hex"02"
        });
        attestations[2] = IAvalancheBridgeAdapter.ValidatorAttestation({
            validator: VALIDATOR_3,
            signature: hex"03"
        });

        return attestations;
    }

    function _submitVerifiedBlock(
        uint256 blockNumber,
        bytes32 blockHash
    ) internal {
        IAvalancheBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();

        // Compute parent hash: use actual parent blockHash if parent is verified
        bytes32 parentHash;
        if (blockNumber > 0) {
            IAvalancheBridgeAdapter.SnowmanBlock memory parent = bridge
                .getSnowmanBlock(blockNumber - 1);
            if (parent.verified) {
                parentHash = parent.blockHash;
            } else {
                parentHash = keccak256(abi.encode("parentHash", blockNumber));
            }
        } else {
            parentHash = bytes32(0);
        }

        vm.prank(relayer);
        bridge.submitSnowmanBlock(
            blockNumber,
            blockHash,
            parentHash,
            keccak256(abi.encode("stateRoot", blockNumber)),
            block.timestamp,
            attestations
        );
    }

    function _buildStateProof()
        internal
        pure
        returns (IAvalancheBridgeAdapter.WarpStateProof memory)
    {
        bytes32[] memory proof = new bytes32[](2);
        proof[0] = keccak256("proof_node_0");
        proof[1] = keccak256("proof_node_1");

        return
            IAvalancheBridgeAdapter.WarpStateProof({
                merkleProof: proof,
                storageRoot: keccak256("storageRoot"),
                value: hex"01"
            });
    }

    function _initiateDeposit(
        uint256 amount,
        bytes32 txHash
    ) internal returns (bytes32) {
        // Submit snowman block first
        _submitVerifiedBlock(1, keccak256("block1"));

        IAvalancheBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        IAvalancheBridgeAdapter.WarpStateProof
            memory proof = _buildStateProof();

        vm.prank(relayer);
        return
            bridge.initiateAVAXDeposit(
                txHash,
                address(0xDEAD), // cChainSender (address — Avalanche is EVM-compatible)
                user,
                amount,
                1, // cChainBlockNumber
                proof,
                attestations
            );
    }

    function _buildZKProof(
        bytes32 depositId,
        bytes32 commitment,
        bytes32 nullifier
    ) internal pure returns (bytes memory) {
        bytes memory zkProof = new bytes(256);
        bytes32 proofBinding = keccak256(
            abi.encodePacked(depositId, commitment, nullifier)
        );
        // Place proof binding at bytes 32-64
        assembly {
            mstore(add(zkProof, 64), proofBinding)
        }
        return zkProof;
    }

    /*//////////////////////////////////////////////////////////////
                         CONSTANTS TESTS
    //////////////////////////////////////////////////////////////*/

    function test_constantsAreCorrect() public view {
        assertEq(bridge.AVALANCHE_CHAIN_ID(), 43114);
        assertEq(bridge.WEI_PER_AVAX(), 1 ether);
        assertEq(bridge.BRIDGE_FEE_BPS(), 4);
        assertEq(bridge.WITHDRAWAL_REFUND_DELAY(), 24 hours);
        assertEq(bridge.MIN_ESCROW_TIMELOCK(), 1 hours);
        assertEq(bridge.MAX_ESCROW_TIMELOCK(), 30 days);
        assertEq(bridge.DEFAULT_BLOCK_CONFIRMATIONS(), 1);
    }

    function test_constructorRejectsZeroAdmin() public {
        vm.expectRevert(IAvalancheBridgeAdapter.ZeroAddress.selector);
        new AvalancheBridgeAdapter(address(0));
    }

    /*//////////////////////////////////////////////////////////////
                         WEI PRECISION TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_weiPrecision(uint256 avaxAmount) public pure {
        avaxAmount = bound(avaxAmount, 1, 1_000_000);
        uint256 weiAmount = avaxAmount * 1 ether;
        assertEq(weiAmount / 1 ether, avaxAmount);
        assertEq(weiAmount % 1 ether, 0);
    }

    function testFuzz_weiSubUnitDeposit(uint256 amountWei) public {
        amountWei = bound(amountWei, MIN_DEPOSIT, MAX_DEPOSIT);

        bytes32 txHash = keccak256(abi.encode("avax_tx_sub", amountWei));
        bytes32 depositId = _initiateDeposit(amountWei, txHash);

        IAvalancheBridgeAdapter.AVAXDeposit memory dep = bridge.getDeposit(
            depositId
        );
        assertEq(dep.amountWei, amountWei);
        assertEq(dep.fee, (amountWei * 4) / 10_000);
        assertEq(dep.netAmountWei, amountWei - dep.fee);
    }

    /*//////////////////////////////////////////////////////////////
                        FEE CALCULATION TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_feeCalculation(uint256 amount) public pure {
        amount = bound(amount, MIN_DEPOSIT, MAX_DEPOSIT);
        uint256 fee = (amount * 4) / 10_000;
        uint256 net = amount - fee;

        // Fee should never exceed the amount
        assertLe(fee, amount);
        // Net + fee = amount
        assertEq(net + fee, amount);
        // 0.04% fee
        assertLe(fee, amount / 100);
    }

    /*//////////////////////////////////////////////////////////////
                    SNOWMAN BLOCK VERIFICATION TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_snowmanBlockChain(uint8 count) public {
        uint256 n = bound(uint256(count), 1, 20);

        for (uint256 i = 0; i < n; i++) {
            bytes32 blockHash = keccak256(abi.encode("block", i));
            _submitVerifiedBlock(i, blockHash);

            IAvalancheBridgeAdapter.SnowmanBlock memory blk = bridge
                .getSnowmanBlock(i);
            assertTrue(blk.verified);
            assertEq(blk.blockHash, blockHash);
        }

        assertEq(bridge.latestBlockNumber(), n - 1);
    }

    function test_depositRequiresVerifiedBlock() public {
        // Don't submit any block — deposit should fail
        IAvalancheBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        IAvalancheBridgeAdapter.WarpStateProof
            memory proof = _buildStateProof();

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAvalancheBridgeAdapter.CChainBlockNotVerified.selector,
                999
            )
        );
        bridge.initiateAVAXDeposit(
            keccak256("unverified_tx"),
            address(0xDEAD),
            user,
            1 ether,
            999, // non-existent block
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

        IAvalancheBridgeAdapter.AVAXDeposit memory dep = bridge.getDeposit(
            depositId
        );
        assertEq(dep.amountWei, amount);
        assertEq(dep.cChainTxHash, txHash);
        assertEq(dep.evmRecipient, user);
        assertEq(
            uint256(dep.status),
            uint256(IAvalancheBridgeAdapter.DepositStatus.VERIFIED)
        );
        assertGt(dep.initiatedAt, 0);
    }

    function testFuzz_depositAmountBounds(uint256 amount) public {
        amount = bound(amount, MIN_DEPOSIT, MAX_DEPOSIT);

        bytes32 txHash = keccak256(abi.encode("bounds_tx", amount));
        bytes32 depositId = _initiateDeposit(amount, txHash);

        IAvalancheBridgeAdapter.AVAXDeposit memory dep = bridge.getDeposit(
            depositId
        );
        assertGe(dep.amountWei, MIN_DEPOSIT);
        assertLe(dep.amountWei, MAX_DEPOSIT);
    }

    function testFuzz_depositRejectsAmountBelowMin(uint256 amount) public {
        amount = bound(amount, 1, MIN_DEPOSIT - 1);

        _submitVerifiedBlock(1, keccak256("block_low"));

        IAvalancheBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        IAvalancheBridgeAdapter.WarpStateProof
            memory proof = _buildStateProof();

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAvalancheBridgeAdapter.AmountBelowMinimum.selector,
                amount,
                MIN_DEPOSIT
            )
        );
        bridge.initiateAVAXDeposit(
            keccak256(abi.encode("tx_low", amount)),
            address(0xDEAD),
            user,
            amount,
            1,
            proof,
            attestations
        );
    }

    function testFuzz_depositRejectsAmountAboveMax(uint256 amount) public {
        amount = bound(amount, MAX_DEPOSIT + 1, type(uint128).max);

        _submitVerifiedBlock(1, keccak256("block_high"));

        IAvalancheBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        IAvalancheBridgeAdapter.WarpStateProof
            memory proof = _buildStateProof();

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAvalancheBridgeAdapter.AmountAboveMaximum.selector,
                amount,
                MAX_DEPOSIT
            )
        );
        bridge.initiateAVAXDeposit(
            keccak256(abi.encode("tx_high", amount)),
            address(0xDEAD),
            user,
            amount,
            1,
            proof,
            attestations
        );
    }

    function testFuzz_txHashReplayProtection(bytes32 txHash) public {
        vm.assume(txHash != bytes32(0));

        bytes32 depositId = _initiateDeposit(1 ether, txHash);
        assertTrue(depositId != bytes32(0));

        // Submit another block for second attempt
        _submitVerifiedBlock(2, keccak256("block2"));

        IAvalancheBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        IAvalancheBridgeAdapter.WarpStateProof
            memory proof = _buildStateProof();

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAvalancheBridgeAdapter.CChainTxAlreadyUsed.selector,
                txHash
            )
        );
        bridge.initiateAVAXDeposit(
            txHash,
            address(0xDEAD),
            user,
            1 ether,
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
                keccak256(abi.encode("nonce_block", i))
            );

            IAvalancheBridgeAdapter.ValidatorAttestation[]
                memory attestations = _buildValidatorAttestations();
            IAvalancheBridgeAdapter.WarpStateProof
                memory proof = _buildStateProof();

            vm.prank(relayer);
            bridge.initiateAVAXDeposit(
                txHash,
                address(0xDEAD),
                user,
                1 ether,
                i + 1,
                proof,
                attestations
            );

            assertGt(bridge.depositNonce(), prevNonce);
            prevNonce = bridge.depositNonce();
        }
    }

    function testFuzz_multipleDeposits(uint8 count) public {
        uint256 n = bound(uint256(count), 2, 8);

        for (uint256 i = 0; i < n; i++) {
            bytes32 txHash = keccak256(abi.encode("multi_tx", i));
            _submitVerifiedBlock(
                i + 1,
                keccak256(abi.encode("multi_block", i))
            );

            IAvalancheBridgeAdapter.ValidatorAttestation[]
                memory attestations = _buildValidatorAttestations();
            IAvalancheBridgeAdapter.WarpStateProof
                memory proof = _buildStateProof();

            vm.prank(relayer);
            bridge.initiateAVAXDeposit(
                txHash,
                address(0xDEAD),
                user,
                1 ether,
                i + 1,
                proof,
                attestations
            );
        }

        bytes32[] memory ids = bridge.getUserDeposits(user);
        assertEq(ids.length, n);
    }

    function testFuzz_depositIdUniqueness(uint8 count) public {
        uint256 n = bound(uint256(count), 2, 10);
        bytes32[] memory depositIds = new bytes32[](n);

        for (uint256 i = 0; i < n; i++) {
            bytes32 txHash = keccak256(abi.encode("unique_tx", i));
            _submitVerifiedBlock(
                i + 1,
                keccak256(abi.encode("unique_block", i))
            );

            IAvalancheBridgeAdapter.ValidatorAttestation[]
                memory attestations = _buildValidatorAttestations();
            IAvalancheBridgeAdapter.WarpStateProof
                memory proof = _buildStateProof();

            vm.prank(relayer);
            depositIds[i] = bridge.initiateAVAXDeposit(
                txHash,
                address(0xDEAD),
                user,
                1 ether,
                i + 1,
                proof,
                attestations
            );
        }

        // Verify all IDs are unique
        for (uint256 i = 0; i < n; i++) {
            for (uint256 j = i + 1; j < n; j++) {
                assertTrue(depositIds[i] != depositIds[j]);
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                       WITHDRAWAL TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_withdrawalLifecycle(uint256 amount) public {
        amount = bound(amount, MIN_DEPOSIT, 1000 ether);
        address cChainRecipient = address(0xCAFE);

        // Mint wAVAX to user
        vm.prank(admin);
        wAVAX.mint(user, amount);

        vm.startPrank(user);
        wAVAX.approve(address(bridge), amount);
        bytes32 wId = bridge.initiateWithdrawal(cChainRecipient, amount);
        vm.stopPrank();

        IAvalancheBridgeAdapter.AVAXWithdrawal memory w = bridge.getWithdrawal(
            wId
        );
        assertEq(w.amountWei, amount);
        assertEq(w.evmSender, user);
        assertEq(w.cChainRecipient, cChainRecipient);
        assertEq(
            uint256(w.status),
            uint256(IAvalancheBridgeAdapter.WithdrawalStatus.PENDING)
        );
    }

    function testFuzz_withdrawalRejectsAmountBelowMin(uint256 amount) public {
        amount = bound(amount, 1, MIN_DEPOSIT - 1);

        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAvalancheBridgeAdapter.AmountBelowMinimum.selector,
                amount,
                MIN_DEPOSIT
            )
        );
        bridge.initiateWithdrawal(address(0xCAFE), amount);
    }

    function testFuzz_withdrawalRejectsAmountAboveMax(uint256 amount) public {
        amount = bound(amount, MAX_DEPOSIT + 1, type(uint128).max);

        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAvalancheBridgeAdapter.AmountAboveMaximum.selector,
                amount,
                MAX_DEPOSIT
            )
        );
        bridge.initiateWithdrawal(address(0xCAFE), amount);
    }

    function test_withdrawalRefundAfterDelay() public {
        uint256 amount = 1 ether;

        vm.prank(admin);
        wAVAX.mint(user, amount);

        vm.startPrank(user);
        wAVAX.approve(address(bridge), amount);
        bytes32 wId = bridge.initiateWithdrawal(address(0xCAFE), amount);
        vm.stopPrank();

        // Cannot refund before delay
        vm.expectRevert();
        bridge.refundWithdrawal(wId);

        // Warp past refund delay (24 hours)
        vm.warp(block.timestamp + 24 hours + 1);

        uint256 balBefore = wAVAX.balanceOf(user);
        bridge.refundWithdrawal(wId);
        uint256 balAfter = wAVAX.balanceOf(user);

        assertEq(balAfter - balBefore, amount);

        IAvalancheBridgeAdapter.AVAXWithdrawal memory w = bridge.getWithdrawal(
            wId
        );
        assertEq(
            uint256(w.status),
            uint256(IAvalancheBridgeAdapter.WithdrawalStatus.REFUNDED)
        );
    }

    function test_refundTooEarly() public {
        uint256 amount = 1 ether;

        vm.prank(admin);
        wAVAX.mint(user, amount);

        vm.startPrank(user);
        wAVAX.approve(address(bridge), amount);
        bytes32 wId = bridge.initiateWithdrawal(address(0xCAFE), amount);
        vm.stopPrank();

        // Attempt refund immediately (too early)
        vm.expectRevert(
            abi.encodeWithSelector(
                IAvalancheBridgeAdapter.RefundTooEarly.selector,
                block.timestamp,
                block.timestamp + 24 hours
            )
        );
        bridge.refundWithdrawal(wId);
    }

    function testFuzz_withdrawalNonceOnlyIncreases(uint8 count) public {
        uint256 n = bound(uint256(count), 1, 10);
        uint256 amount = 1 ether;

        // Mint wAVAX to user for withdrawals
        vm.prank(admin);
        wAVAX.mint(user, amount * n);

        vm.startPrank(user);
        wAVAX.approve(address(bridge), amount * n);

        uint256 prevNonce = bridge.withdrawalNonce();
        for (uint256 i = 0; i < n; i++) {
            bridge.initiateWithdrawal(address(0xCAFE), amount);
            assertGt(bridge.withdrawalNonce(), prevNonce);
            prevNonce = bridge.withdrawalNonce();
        }

        vm.stopPrank();
    }

    function test_withdrawalDoubleComplete() public {
        uint256 amount = 1 ether;

        vm.prank(admin);
        wAVAX.mint(user, amount);

        vm.startPrank(user);
        wAVAX.approve(address(bridge), amount);
        bytes32 wId = bridge.initiateWithdrawal(address(0xCAFE), amount);
        vm.stopPrank();

        // Warp past delay and refund (changes status to REFUNDED)
        vm.warp(block.timestamp + 24 hours + 1);
        bridge.refundWithdrawal(wId);

        // Attempting to refund again should revert (not PENDING anymore)
        vm.expectRevert(
            abi.encodeWithSelector(
                IAvalancheBridgeAdapter.WithdrawalNotPending.selector,
                wId
            )
        );
        bridge.refundWithdrawal(wId);
    }

    /*//////////////////////////////////////////////////////////////
                        ESCROW LIFECYCLE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_escrowCreateFinishLifecycle() public {
        bytes32 preimage = keccak256("test_preimage_avax");
        bytes32 hashlock = sha256(abi.encodePacked(preimage));
        address cChainParty = address(0xBEEF);

        uint256 finishAfter = block.timestamp + 1 hours;
        uint256 cancelAfter = finishAfter + 12 hours;

        vm.deal(user, 10 ether);
        vm.prank(user);
        bytes32 escrowId = bridge.createEscrow{value: 1 ether}(
            cChainParty,
            hashlock,
            finishAfter,
            cancelAfter
        );

        IAvalancheBridgeAdapter.AVAXEscrow memory e = bridge.getEscrow(
            escrowId
        );
        assertEq(
            uint256(e.status),
            uint256(IAvalancheBridgeAdapter.EscrowStatus.ACTIVE)
        );
        assertEq(e.amountWei, 1 ether);
        assertEq(e.cChainParty, cChainParty);

        // Finish after timelock
        vm.warp(finishAfter + 1);
        bridge.finishEscrow(escrowId, preimage);

        e = bridge.getEscrow(escrowId);
        assertEq(
            uint256(e.status),
            uint256(IAvalancheBridgeAdapter.EscrowStatus.FINISHED)
        );
        assertEq(e.preimage, preimage);
    }

    function test_escrowCreateCancelLifecycle() public {
        bytes32 hashlock = sha256(abi.encodePacked(keccak256("cancel_avax")));
        address cChainParty = address(0xBEEF);

        uint256 finishAfter = block.timestamp + 2 hours;
        uint256 cancelAfter = finishAfter + 6 hours;

        vm.deal(user, 10 ether);
        vm.prank(user);
        bytes32 escrowId = bridge.createEscrow{value: 0.5 ether}(
            cChainParty,
            hashlock,
            finishAfter,
            cancelAfter
        );

        // Cannot cancel before cancelAfter
        vm.expectRevert(IAvalancheBridgeAdapter.EscrowTimelockNotMet.selector);
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
        address cChainParty = address(0xBEEF);

        bytes32 hashlock = sha256(abi.encodePacked(keccak256("timelock_avax")));

        vm.deal(user, 1 ether);
        vm.prank(user);
        bytes32 escrowId = bridge.createEscrow{value: 0.1 ether}(
            cChainParty,
            hashlock,
            finish,
            cancel
        );

        IAvalancheBridgeAdapter.AVAXEscrow memory e = bridge.getEscrow(
            escrowId
        );
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
        address cChainParty = address(0xBEEF);

        bytes32 hashlock = sha256(abi.encodePacked(keccak256("long_avax")));

        vm.deal(user, 1 ether);
        vm.prank(user);
        vm.expectRevert(IAvalancheBridgeAdapter.InvalidTimelockRange.selector);
        bridge.createEscrow{value: 0.1 ether}(
            cChainParty,
            hashlock,
            finish,
            cancel
        );
    }

    function test_escrowDoubleFinish() public {
        bytes32 preimage = keccak256("double_finish_avax");
        bytes32 hashlock = sha256(abi.encodePacked(preimage));
        address cChainParty = address(0xBEEF);

        uint256 finishAfter = block.timestamp + 1 hours;
        uint256 cancelAfter = finishAfter + 12 hours;

        vm.deal(user, 10 ether);
        vm.prank(user);
        bytes32 escrowId = bridge.createEscrow{value: 1 ether}(
            cChainParty,
            hashlock,
            finishAfter,
            cancelAfter
        );

        vm.warp(finishAfter + 1);
        bridge.finishEscrow(escrowId, preimage);

        // Second finish should revert (not ACTIVE anymore)
        vm.expectRevert(
            abi.encodeWithSelector(
                IAvalancheBridgeAdapter.EscrowNotActive.selector,
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

        _submitVerifiedBlock(1, keccak256("block_ac"));

        IAvalancheBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        IAvalancheBridgeAdapter.WarpStateProof
            memory proof = _buildStateProof();

        vm.prank(caller);
        vm.expectRevert();
        bridge.initiateAVAXDeposit(
            keccak256("ac_tx"),
            address(0xDEAD),
            user,
            1 ether,
            1,
            proof,
            attestations
        );
    }

    function testFuzz_onlyOperatorCanCompleteDeposit(address caller) public {
        vm.assume(caller != admin && caller != address(0));

        bytes32 depositId = _initiateDeposit(
            1 ether,
            keccak256("complete_test")
        );

        vm.prank(caller);
        vm.expectRevert();
        bridge.completeAVAXDeposit(depositId);
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
        // Submit block BEFORE pausing (submitSnowmanBlock is also whenNotPaused)
        _submitVerifiedBlock(1, keccak256("block_pause"));

        vm.prank(admin);
        bridge.pause();

        IAvalancheBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        IAvalancheBridgeAdapter.WarpStateProof
            memory proof = _buildStateProof();

        vm.prank(relayer);
        vm.expectRevert();
        bridge.initiateAVAXDeposit(
            keccak256("paused_tx"),
            address(0xDEAD),
            user,
            1 ether,
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
        bridge.initiateWithdrawal(address(0xCAFE), 1 ether);
    }

    function testFuzz_pauseBlocksEscrow() public {
        bytes32 hashlock = sha256(abi.encodePacked(keccak256("paused_avax")));
        address cChainParty = address(0xBEEF);

        vm.prank(admin);
        bridge.pause();

        vm.deal(user, 1 ether);
        vm.prank(user);
        vm.expectRevert();
        bridge.createEscrow{value: 0.1 ether}(
            cChainParty,
            hashlock,
            block.timestamp + 1 hours,
            block.timestamp + 5 hours
        );
    }

    function test_unpauseRestoresOperations() public {
        vm.prank(admin);
        bridge.pause();

        vm.prank(admin);
        bridge.unpause();

        // Should work again after unpause
        address cChainParty = address(0xBEEF);
        bytes32 hashlock = sha256(abi.encodePacked(keccak256("unpause_avax")));

        vm.deal(user, 1 ether);
        vm.prank(user);
        bytes32 escrowId = bridge.createEscrow{value: 0.1 ether}(
            cChainParty,
            hashlock,
            block.timestamp + 1 hours,
            block.timestamp + 5 hours
        );
        assertTrue(escrowId != bytes32(0));
    }

    /*//////////////////////////////////////////////////////////////
                       NULLIFIER / PRIVACY TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_privateDeposit(uint256 amount) public {
        amount = bound(amount, MIN_DEPOSIT, 100 ether);

        bytes32 txHash = keccak256(abi.encode("priv_tx", amount));
        bytes32 depositId = _initiateDeposit(amount, txHash);

        // Complete the deposit (Avalanche requires COMPLETED status for privacy registration)
        vm.prank(admin);
        bridge.completeAVAXDeposit(depositId);

        bytes32 commitment = keccak256("commitment");
        bytes32 nullifier = keccak256(abi.encode("nullifier", amount));

        // Build valid ZK proof (>= 256 bytes, proof binding at bytes 32-64)
        bytes memory zkProof = _buildZKProof(depositId, commitment, nullifier);

        vm.prank(admin);
        bridge.registerPrivateDeposit(
            depositId,
            commitment,
            nullifier,
            zkProof
        );

        assertTrue(bridge.usedNullifiers(nullifier));
    }

    function testFuzz_nullifierCannotBeReused(bytes32 nullifier) public {
        vm.assume(nullifier != bytes32(0));

        bytes32 depositId = _initiateDeposit(
            1 ether,
            keccak256(abi.encode("null_tx", nullifier))
        );

        // Complete the deposit first
        vm.prank(admin);
        bridge.completeAVAXDeposit(depositId);

        bytes32 commitment = keccak256("commitment");
        bytes memory zkProof = _buildZKProof(depositId, commitment, nullifier);

        vm.prank(admin);
        bridge.registerPrivateDeposit(
            depositId,
            commitment,
            nullifier,
            zkProof
        );

        bytes32 commitment2 = keccak256("commitment2");
        bytes memory zkProof2 = _buildZKProof(
            depositId,
            commitment2,
            nullifier
        );

        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAvalancheBridgeAdapter.NullifierAlreadyUsed.selector,
                nullifier
            )
        );
        bridge.registerPrivateDeposit(
            depositId,
            commitment2,
            nullifier,
            zkProof2
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
        sigs = bound(sigs, 1, 100);

        vm.prank(admin);
        vm.expectRevert(IAvalancheBridgeAdapter.ZeroAddress.selector);
        bridge.configure(address(0), b, c, sigs, 1);

        vm.prank(admin);
        vm.expectRevert(IAvalancheBridgeAdapter.ZeroAddress.selector);
        bridge.configure(
            a == address(0) ? address(1) : a,
            address(0),
            c,
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
        vm.expectRevert(IAvalancheBridgeAdapter.ZeroAddress.selector);
        bridge.setTreasury(address(0));
    }

    /*//////////////////////////////////////////////////////////////
                       FEE WITHDRAWAL TESTS
    //////////////////////////////////////////////////////////////*/

    function test_feeWithdrawal() public {
        // Initiate a deposit to generate fees
        bytes32 depositId = _initiateDeposit(100 ether, keccak256("fee_tx"));
        assertTrue(depositId != bytes32(0));

        uint256 expectedFee = (100 ether * 4) / 10_000;
        assertEq(bridge.accumulatedFees(), expectedFee);

        // Withdraw fees
        vm.prank(admin);
        bridge.withdrawFees();

        assertEq(bridge.accumulatedFees(), 0);
    }

    /*//////////////////////////////////////////////////////////////
                       VIEW FUNCTION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_viewFunctionsReturnDefaults() public view {
        IAvalancheBridgeAdapter.AVAXDeposit memory dep = bridge.getDeposit(
            bytes32(0)
        );
        assertEq(dep.amountWei, 0);

        IAvalancheBridgeAdapter.AVAXWithdrawal memory w = bridge.getWithdrawal(
            bytes32(0)
        );
        assertEq(w.amountWei, 0);

        IAvalancheBridgeAdapter.AVAXEscrow memory e = bridge.getEscrow(
            bytes32(0)
        );
        assertEq(e.amountWei, 0);

        IAvalancheBridgeAdapter.SnowmanBlock memory blk = bridge
            .getSnowmanBlock(0);
        assertFalse(blk.verified);
    }

    function test_statisticsTracking() public view {
        (
            uint256 deposited,
            uint256 withdrawn,
            uint256 escrowCount,
            ,
            ,
            uint256 fees,
            uint256 lastBlock
        ) = bridge.getBridgeStats();

        assertEq(deposited, 0);
        assertEq(withdrawn, 0);
        assertEq(escrowCount, 0);
        assertEq(fees, 0);
        assertEq(lastBlock, 0);
    }

    function test_userHistoryTracking() public view {
        bytes32[] memory deps = bridge.getUserDeposits(user);
        bytes32[] memory ws = bridge.getUserWithdrawals(user);
        bytes32[] memory es = bridge.getUserEscrows(user);

        assertEq(deps.length, 0);
        assertEq(ws.length, 0);
        assertEq(es.length, 0);
    }

    function test_bridgeStatsAfterDeposits() public {
        bytes32 depositId = _initiateDeposit(10 ether, keccak256("stats_tx"));
        assertTrue(depositId != bytes32(0));

        (uint256 deposited, , , , , uint256 fees, ) = bridge.getBridgeStats();

        assertEq(deposited, 10 ether);
        assertEq(fees, (10 ether * 4) / 10_000);
    }

    function test_userTrackingAfterOperations() public {
        bytes32 depositId = _initiateDeposit(1 ether, keccak256("track_tx"));
        assertTrue(depositId != bytes32(0));

        bytes32[] memory deps = bridge.getUserDeposits(user);
        assertEq(deps.length, 1);
        assertEq(deps[0], depositId);
    }
}
