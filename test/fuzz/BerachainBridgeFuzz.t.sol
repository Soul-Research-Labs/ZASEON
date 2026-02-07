// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {BerachainBridgeAdapter} from "../../contracts/crosschain/BerachainBridgeAdapter.sol";
import {IBerachainBridgeAdapter} from "../../contracts/interfaces/IBerachainBridgeAdapter.sol";
import {MockWrappedBERA} from "../../contracts/mocks/MockWrappedBERA.sol";
import {MockCometBFTVerifier} from "../../contracts/mocks/MockCometBFTVerifier.sol";

/**
 * @title BerachainBridgeFuzz
 * @notice Foundry fuzz & invariant tests for the BerachainBridgeAdapter
 * @dev Tests Wei precision (18 decimals), CometBFT block verification,
 *      Merkle inclusion proofs, and Berachain-specific bridge parameters.
 */
contract BerachainBridgeFuzz is Test {
    BerachainBridgeAdapter public bridge;
    MockWrappedBERA public wBERA;
    MockCometBFTVerifier public cometBFTVerifier;

    address public admin = address(0xA);
    address public relayer = address(0xB);
    address public user = address(0xC);
    address public treasury = address(0xD);

    // Validator addresses
    address constant VALIDATOR_1 = address(0x2001);
    address constant VALIDATOR_2 = address(0x2002);
    address constant VALIDATOR_3 = address(0x2003);

    uint256 constant MIN_DEPOSIT = 0.01 ether;
    uint256 constant MAX_DEPOSIT = 10_000_000 ether;

    function setUp() public {
        vm.startPrank(admin);

        bridge = new BerachainBridgeAdapter(admin);
        wBERA = new MockWrappedBERA();
        cometBFTVerifier = new MockCometBFTVerifier();

        // Register validators with voting power (PoL-backed)
        cometBFTVerifier.addValidator(VALIDATOR_1, 100);
        cometBFTVerifier.addValidator(VALIDATOR_2, 100);
        cometBFTVerifier.addValidator(VALIDATOR_3, 100);

        // Configure bridge
        bridge.configure(
            address(0x1), // berachainBridgeContract
            address(wBERA),
            address(cometBFTVerifier),
            2, // minValidatorSignatures
            1 // requiredBlockConfirmations (CometBFT instant finality)
        );

        bridge.setTreasury(treasury);
        bridge.grantRole(bridge.RELAYER_ROLE(), relayer);

        // Fund the bridge with wBERA
        wBERA.mint(address(bridge), 100_000_000 ether);

        // Transfer wBERA ownership to bridge so completeBERADeposit can mint
        wBERA.transferOwnership(address(bridge));

        vm.stopPrank();

        // Wildcard mock: accept any verifyAttestation(bytes32,address,bytes) call
        vm.mockCall(
            address(cometBFTVerifier),
            abi.encodeWithSelector(
                bytes4(keccak256("verifyAttestation(bytes32,address,bytes)"))
            ),
            abi.encode(true)
        );
    }

    /// @notice Accept ETH for escrow operations
    receive() external payable {}

    /*//////////////////////////////////////////////////////////////
                          HELPER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _buildValidatorAttestations()
        internal
        pure
        returns (IBerachainBridgeAdapter.ValidatorAttestation[] memory)
    {
        IBerachainBridgeAdapter.ValidatorAttestation[]
            memory attestations = new IBerachainBridgeAdapter.ValidatorAttestation[](
                3
            );

        attestations[0] = IBerachainBridgeAdapter.ValidatorAttestation({
            validator: VALIDATOR_1,
            signature: hex"01"
        });
        attestations[1] = IBerachainBridgeAdapter.ValidatorAttestation({
            validator: VALIDATOR_2,
            signature: hex"02"
        });
        attestations[2] = IBerachainBridgeAdapter.ValidatorAttestation({
            validator: VALIDATOR_3,
            signature: hex"03"
        });

        return attestations;
    }

    /**
     * @dev Build a CometBFT Merkle inclusion proof and the matching block appHash.
     *      Constructs a single-sibling Merkle proof such that:
     *        computedHash = keccak256(beraTxHash || proof.appHash || proof.value)
     *        root = keccak256(sort(computedHash, sibling))
     *      The returned `blockAppHash` must be used as the CometBFTBlock.appHash
     *      when submitting the verified block header.
     */
    function _buildCometBFTProof(
        bytes32 beraTxHash
    )
        internal
        pure
        returns (
            IBerachainBridgeAdapter.CometBFTProof memory proof,
            bytes32 blockAppHash
        )
    {
        bytes32 proofAppHash = keccak256("proofAppHash");
        bytes memory proofValue = hex"01";

        bytes32 computedHash = keccak256(
            abi.encodePacked(beraTxHash, proofAppHash, proofValue)
        );

        bytes32 sibling = keccak256("sibling");

        bytes32[] memory merkleProof = new bytes32[](1);
        merkleProof[0] = sibling;

        if (computedHash <= sibling) {
            blockAppHash = keccak256(
                abi.encodePacked(computedHash, sibling)
            );
        } else {
            blockAppHash = keccak256(
                abi.encodePacked(sibling, computedHash)
            );
        }

        proof = IBerachainBridgeAdapter.CometBFTProof({
            merkleProof: merkleProof,
            appHash: proofAppHash,
            value: proofValue
        });
    }

    function _submitVerifiedBlock(
        uint256 blockNumber,
        bytes32 beraTxHash
    ) internal returns (bytes32 blockAppHash) {
        (, bytes32 appHash) = _buildCometBFTProof(beraTxHash);
        blockAppHash = appHash;

        IBerachainBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();

        vm.prank(relayer);
        bridge.submitCometBFTBlock(
            blockNumber,
            keccak256(abi.encode("blockHash", blockNumber)),
            appHash,
            keccak256(abi.encode("validatorsHash", blockNumber)),
            0, // round
            block.timestamp,
            attestations
        );
    }

    function _initiateDeposit(
        uint256 amount,
        bytes32 txHash
    ) internal returns (bytes32) {
        // Build proof and submit verified block first
        (
            IBerachainBridgeAdapter.CometBFTProof memory proof,
            bytes32 blockAppHash
        ) = _buildCometBFTProof(txHash);

        IBerachainBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();

        vm.prank(relayer);
        bridge.submitCometBFTBlock(
            1,
            keccak256(abi.encode("blockHash", uint256(1))),
            blockAppHash,
            keccak256(abi.encode("validatorsHash", uint256(1))),
            0,
            block.timestamp,
            attestations
        );

        vm.prank(relayer);
        return
            bridge.initiateBERADeposit(
                txHash,
                address(0x1234), // beraSender (EVM-compatible address)
                user,
                amount,
                1, // beraBlockNumber
                proof,
                attestations
            );
    }

    /**
     * @dev Initiates a deposit at a specific block number to avoid
     *      CometBFT block collisions in multi-deposit tests.
     */
    function _initiateDepositAtBlock(
        uint256 amount,
        bytes32 txHash,
        uint256 blockNumber
    ) internal returns (bytes32) {
        (
            IBerachainBridgeAdapter.CometBFTProof memory proof,
            bytes32 blockAppHash
        ) = _buildCometBFTProof(txHash);

        IBerachainBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();

        vm.prank(relayer);
        bridge.submitCometBFTBlock(
            blockNumber,
            keccak256(abi.encode("blockHash", blockNumber)),
            blockAppHash,
            keccak256(abi.encode("validatorsHash", blockNumber)),
            0,
            block.timestamp,
            attestations
        );

        vm.prank(relayer);
        return
            bridge.initiateBERADeposit(
                txHash,
                address(0x1234),
                user,
                amount,
                blockNumber,
                proof,
                attestations
            );
    }

    /*//////////////////////////////////////////////////////////////
                         CONSTANTS TESTS
    //////////////////////////////////////////////////////////////*/

    function test_constantsAreCorrect() public view {
        assertEq(bridge.BERACHAIN_CHAIN_ID(), 80094);
        assertEq(bridge.BRIDGE_FEE_BPS(), 4);
        assertEq(bridge.BPS_DENOMINATOR(), 10_000);
        assertEq(bridge.WITHDRAWAL_REFUND_DELAY(), 24 hours);
        assertEq(bridge.MIN_ESCROW_TIMELOCK(), 1 hours);
        assertEq(bridge.MAX_ESCROW_TIMELOCK(), 30 days);
        assertEq(bridge.DEFAULT_BLOCK_CONFIRMATIONS(), 1);
        assertEq(bridge.MIN_DEPOSIT(), 0.01 ether);
        assertEq(bridge.MAX_DEPOSIT(), 10_000_000 ether);
    }

    function test_constructorRejectsZeroAdmin() public {
        vm.expectRevert(IBerachainBridgeAdapter.ZeroAddress.selector);
        new BerachainBridgeAdapter(address(0));
    }

    /*//////////////////////////////////////////////////////////////
                         DEPOSIT FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_depositAmount(uint256 amount) public {
        amount = bound(amount, MIN_DEPOSIT, MAX_DEPOSIT);

        bytes32 txHash = keccak256(abi.encode("bera_tx_fuzz", amount));
        bytes32 depositId = _initiateDeposit(amount, txHash);

        IBerachainBridgeAdapter.BERADeposit memory dep = bridge.getDeposit(
            depositId
        );
        assertEq(dep.amountWei, amount);
        assertEq(dep.fee, (amount * 4) / 10_000);
        assertEq(dep.netAmountWei, amount - dep.fee);
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
                COMETBFT BLOCK CHAIN VERIFICATION TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_cometBFTBlockChain(uint8 count) public {
        uint256 n = bound(uint256(count), 1, 20);

        for (uint256 i = 0; i < n; i++) {
            bytes32 txHash = keccak256(abi.encode("chain_tx", i));
            _submitVerifiedBlock(i + 1, txHash);

            IBerachainBridgeAdapter.CometBFTBlock memory blk = bridge
                .getCometBFTBlock(i + 1);
            assertTrue(blk.verified);
        }

        assertEq(bridge.latestBlockNumber(), n);
    }

    function test_depositRequiresVerifiedBlock() public {
        // Don't submit any CometBFT block — deposit should fail
        IBerachainBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();

        bytes32 txHash = keccak256("unverified_tx");
        (IBerachainBridgeAdapter.CometBFTProof memory proof, ) = _buildCometBFTProof(txHash);

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                IBerachainBridgeAdapter.BeraBlockNotVerified.selector,
                999
            )
        );
        bridge.initiateBERADeposit(
            txHash,
            address(0x1234),
            user,
            1 ether,
            999, // non-existent block number
            proof,
            attestations
        );
    }

    /*//////////////////////////////////////////////////////////////
                       DEPOSIT ROUND TRIP TEST
    //////////////////////////////////////////////////////////////*/

    function testFuzz_depositRoundTrip(uint256 amount) public {
        amount = bound(amount, MIN_DEPOSIT, MAX_DEPOSIT);

        bytes32 txHash = keccak256(abi.encode("roundtrip_tx", amount));
        bytes32 depositId = _initiateDeposit(amount, txHash);

        IBerachainBridgeAdapter.BERADeposit memory dep = bridge.getDeposit(
            depositId
        );
        assertEq(
            uint256(dep.status),
            uint256(IBerachainBridgeAdapter.DepositStatus.VERIFIED)
        );
        assertEq(dep.evmRecipient, user);
        assertEq(dep.beraSender, address(0x1234));
        assertEq(dep.beraTxHash, txHash);
        assertGt(dep.initiatedAt, 0);
    }

    /*//////////////////////////////////////////////////////////////
                       AMOUNT BOUNDS TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_depositAmountBounds(uint256 amount) public {
        amount = bound(amount, MIN_DEPOSIT, MAX_DEPOSIT);

        bytes32 txHash = keccak256(abi.encode("bounds_tx", amount));
        bytes32 depositId = _initiateDeposit(amount, txHash);

        IBerachainBridgeAdapter.BERADeposit memory dep = bridge.getDeposit(
            depositId
        );
        assertGe(dep.amountWei, MIN_DEPOSIT);
        assertLe(dep.amountWei, MAX_DEPOSIT);
    }

    function testFuzz_depositRejectsAmountBelowMin(uint256 amount) public {
        amount = bound(amount, 1, MIN_DEPOSIT - 1);

        bytes32 txHash = keccak256(abi.encode("tx_low", amount));

        // Submit a verified block first
        (
            IBerachainBridgeAdapter.CometBFTProof memory proof,
            bytes32 blockAppHash
        ) = _buildCometBFTProof(txHash);

        IBerachainBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();

        vm.prank(relayer);
        bridge.submitCometBFTBlock(
            1,
            keccak256(abi.encode("blockHash", uint256(1))),
            blockAppHash,
            keccak256(abi.encode("validatorsHash", uint256(1))),
            0,
            block.timestamp,
            attestations
        );

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                IBerachainBridgeAdapter.AmountBelowMinimum.selector,
                amount,
                MIN_DEPOSIT
            )
        );
        bridge.initiateBERADeposit(
            txHash,
            address(0x1234),
            user,
            amount,
            1,
            proof,
            attestations
        );
    }

    function testFuzz_depositRejectsAmountAboveMax(uint256 amount) public {
        amount = bound(amount, MAX_DEPOSIT + 1, type(uint128).max);

        bytes32 txHash = keccak256(abi.encode("tx_high", amount));

        (
            IBerachainBridgeAdapter.CometBFTProof memory proof,
            bytes32 blockAppHash
        ) = _buildCometBFTProof(txHash);

        IBerachainBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();

        vm.prank(relayer);
        bridge.submitCometBFTBlock(
            1,
            keccak256(abi.encode("blockHash", uint256(1))),
            blockAppHash,
            keccak256(abi.encode("validatorsHash", uint256(1))),
            0,
            block.timestamp,
            attestations
        );

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                IBerachainBridgeAdapter.AmountAboveMaximum.selector,
                amount,
                MAX_DEPOSIT
            )
        );
        bridge.initiateBERADeposit(
            txHash,
            address(0x1234),
            user,
            amount,
            1,
            proof,
            attestations
        );
    }

    /*//////////////////////////////////////////////////////////////
                     COMPLETE DEPOSIT TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_completeDeposit(uint256 amount) public {
        amount = bound(amount, MIN_DEPOSIT, MAX_DEPOSIT);

        bytes32 txHash = keccak256(abi.encode("complete_tx", amount));
        bytes32 depositId = _initiateDeposit(amount, txHash);

        uint256 recipientBalBefore = wBERA.balanceOf(user);

        vm.prank(admin);
        bridge.completeBERADeposit(depositId);

        IBerachainBridgeAdapter.BERADeposit memory dep = bridge.getDeposit(
            depositId
        );
        assertEq(
            uint256(dep.status),
            uint256(IBerachainBridgeAdapter.DepositStatus.COMPLETED)
        );
        assertGt(dep.completedAt, 0);

        uint256 recipientBalAfter = wBERA.balanceOf(user);
        assertEq(recipientBalAfter - recipientBalBefore, dep.netAmountWei);
    }

    function test_completeDepositRejectsUnknown() public {
        bytes32 fakeId = keccak256("nonexistent");

        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(
                IBerachainBridgeAdapter.DepositNotFound.selector,
                fakeId
            )
        );
        bridge.completeBERADeposit(fakeId);
    }

    /*//////////////////////////////////////////////////////////////
                    WITHDRAWAL LIFECYCLE TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_withdrawalLifecycle(uint256 amount) public {
        amount = bound(amount, MIN_DEPOSIT, MAX_DEPOSIT);

        // Mint wBERA to user for withdrawal (bridge owns wBERA)
        vm.prank(address(bridge));
        wBERA.mint(user, amount);

        vm.startPrank(user);
        wBERA.approve(address(bridge), amount);
        bytes32 wId = bridge.initiateWithdrawal(
            address(0x5678), // beraRecipient (EVM-compatible address)
            amount
        );
        vm.stopPrank();

        IBerachainBridgeAdapter.BERAWithdrawal memory w = bridge.getWithdrawal(
            wId
        );
        assertEq(
            uint256(w.status),
            uint256(IBerachainBridgeAdapter.WithdrawalStatus.PENDING)
        );
        assertEq(w.evmSender, user);
        assertEq(w.beraRecipient, address(0x5678));
        assertEq(w.amountWei, amount);
    }

    function test_withdrawalRefundAfterDelay() public {
        uint256 amount = 1 ether;

        vm.prank(address(bridge));
        wBERA.mint(user, amount);

        vm.startPrank(user);
        wBERA.approve(address(bridge), amount);
        bytes32 wId = bridge.initiateWithdrawal(address(0x5678), amount);
        vm.stopPrank();

        // Cannot refund before delay
        vm.expectRevert();
        bridge.refundWithdrawal(wId);

        // Warp past refund delay (24 hours)
        vm.warp(block.timestamp + 24 hours + 1);

        uint256 balBefore = wBERA.balanceOf(user);
        bridge.refundWithdrawal(wId);
        uint256 balAfter = wBERA.balanceOf(user);

        assertEq(balAfter - balBefore, amount);

        IBerachainBridgeAdapter.BERAWithdrawal memory w = bridge.getWithdrawal(
            wId
        );
        assertEq(
            uint256(w.status),
            uint256(IBerachainBridgeAdapter.WithdrawalStatus.REFUNDED)
        );
    }

    function test_refundTooEarly() public {
        uint256 amount = 1 ether;

        vm.prank(address(bridge));
        wBERA.mint(user, amount);

        vm.startPrank(user);
        wBERA.approve(address(bridge), amount);
        bytes32 wId = bridge.initiateWithdrawal(address(0x5678), amount);
        vm.stopPrank();

        uint256 initiatedAt = block.timestamp;

        vm.expectRevert(
            abi.encodeWithSelector(
                IBerachainBridgeAdapter.RefundTooEarly.selector,
                block.timestamp,
                initiatedAt + 24 hours
            )
        );
        bridge.refundWithdrawal(wId);
    }

    function testFuzz_withdrawalRejectsAmountBelowMin(uint256 amount) public {
        amount = bound(amount, 1, MIN_DEPOSIT - 1);

        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                IBerachainBridgeAdapter.AmountBelowMinimum.selector,
                amount,
                MIN_DEPOSIT
            )
        );
        bridge.initiateWithdrawal(address(0x5678), amount);
    }

    function testFuzz_withdrawalRejectsAmountAboveMax(uint256 amount) public {
        amount = bound(amount, MAX_DEPOSIT + 1, type(uint128).max);

        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                IBerachainBridgeAdapter.AmountAboveMaximum.selector,
                amount,
                MAX_DEPOSIT
            )
        );
        bridge.initiateWithdrawal(address(0x5678), amount);
    }

    /*//////////////////////////////////////////////////////////////
                    WITHDRAWAL COMPLETE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_withdrawalComplete() public {
        uint256 amount = 1 ether;

        vm.prank(address(bridge));
        wBERA.mint(user, amount);

        vm.startPrank(user);
        wBERA.approve(address(bridge), amount);
        bytes32 wId = bridge.initiateWithdrawal(address(0x5678), amount);
        vm.stopPrank();

        // Submit a CometBFT block so completeWithdrawal can verify
        bytes32 beraTxHash = keccak256("complete_bera_tx");
        (
            IBerachainBridgeAdapter.CometBFTProof memory proof,
            bytes32 blockAppHash
        ) = _buildCometBFTProof(beraTxHash);

        IBerachainBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();

        vm.prank(relayer);
        bridge.submitCometBFTBlock(
            100,
            keccak256(abi.encode("blockHash", uint256(100))),
            blockAppHash,
            keccak256(abi.encode("validatorsHash", uint256(100))),
            0,
            block.timestamp,
            attestations
        );

        vm.prank(relayer);
        bridge.completeWithdrawal(wId, beraTxHash, proof, attestations);

        IBerachainBridgeAdapter.BERAWithdrawal memory w = bridge.getWithdrawal(
            wId
        );
        assertEq(
            uint256(w.status),
            uint256(IBerachainBridgeAdapter.WithdrawalStatus.COMPLETED)
        );
        assertEq(w.beraTxHash, beraTxHash);
        assertGt(w.completedAt, 0);
    }

    /*//////////////////////////////////////////////////////////////
                        ESCROW LIFECYCLE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_escrowCreateFinishLifecycle() public {
        bytes32 preimage = keccak256("test_preimage_bera");
        bytes32 hashlock = sha256(abi.encodePacked(preimage));

        uint256 finishAfter = block.timestamp + 1 hours;
        uint256 cancelAfter = finishAfter + 12 hours;

        vm.deal(user, 10 ether);
        vm.prank(user);
        bytes32 escrowId = bridge.createEscrow{value: 1 ether}(
            address(0x5678), // beraParty (EVM-compatible address)
            hashlock,
            finishAfter,
            cancelAfter
        );

        IBerachainBridgeAdapter.BERAEscrow memory e = bridge.getEscrow(
            escrowId
        );
        assertEq(
            uint256(e.status),
            uint256(IBerachainBridgeAdapter.EscrowStatus.ACTIVE)
        );
        assertEq(e.amountWei, 1 ether);
        assertEq(e.beraParty, address(0x5678));

        // Finish after timelock
        vm.warp(finishAfter + 1);
        bridge.finishEscrow(escrowId, preimage);

        e = bridge.getEscrow(escrowId);
        assertEq(
            uint256(e.status),
            uint256(IBerachainBridgeAdapter.EscrowStatus.FINISHED)
        );
        assertEq(e.preimage, preimage);
    }

    function test_escrowCreateCancelLifecycle() public {
        bytes32 hashlock = sha256(
            abi.encodePacked(keccak256("cancel_bera"))
        );

        uint256 finishAfter = block.timestamp + 2 hours;
        uint256 cancelAfter = finishAfter + 6 hours;

        vm.deal(user, 10 ether);
        vm.prank(user);
        bytes32 escrowId = bridge.createEscrow{value: 0.5 ether}(
            address(0x5678),
            hashlock,
            finishAfter,
            cancelAfter
        );

        // Cannot cancel before cancelAfter
        vm.expectRevert(IBerachainBridgeAdapter.EscrowTimelockNotMet.selector);
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

        bytes32 hashlock = sha256(
            abi.encodePacked(keccak256("timelock_bera"))
        );

        vm.deal(user, 1 ether);
        vm.prank(user);
        bytes32 escrowId = bridge.createEscrow{value: 0.1 ether}(
            address(0x5678),
            hashlock,
            finish,
            cancel
        );

        IBerachainBridgeAdapter.BERAEscrow memory e = bridge.getEscrow(
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

        bytes32 hashlock = sha256(
            abi.encodePacked(keccak256("long_bera"))
        );

        vm.deal(user, 1 ether);
        vm.prank(user);
        vm.expectRevert(IBerachainBridgeAdapter.InvalidTimelockRange.selector);
        bridge.createEscrow{value: 0.1 ether}(
            address(0x5678),
            hashlock,
            finish,
            cancel
        );
    }

    function testFuzz_escrowRejectsZeroValue() public {
        bytes32 hashlock = sha256(
            abi.encodePacked(keccak256("zero_bera"))
        );

        vm.prank(user);
        vm.expectRevert(IBerachainBridgeAdapter.InvalidAmount.selector);
        bridge.createEscrow{value: 0}(
            address(0x5678),
            hashlock,
            block.timestamp + 1 hours,
            block.timestamp + 5 hours
        );
    }

    function testFuzz_escrowRejectsZeroHashlock() public {
        vm.deal(user, 1 ether);
        vm.prank(user);
        vm.expectRevert(IBerachainBridgeAdapter.InvalidAmount.selector);
        bridge.createEscrow{value: 0.1 ether}(
            address(0x5678),
            bytes32(0), // zero hashlock
            block.timestamp + 1 hours,
            block.timestamp + 5 hours
        );
    }

    function test_escrowFinishBeforeTimelock() public {
        bytes32 preimage = keccak256("early_finish_bera");
        bytes32 hashlock = sha256(abi.encodePacked(preimage));

        uint256 finishAfter = block.timestamp + 2 hours;
        uint256 cancelAfter = finishAfter + 12 hours;

        vm.deal(user, 10 ether);
        vm.prank(user);
        bytes32 escrowId = bridge.createEscrow{value: 1 ether}(
            address(0x5678),
            hashlock,
            finishAfter,
            cancelAfter
        );

        // Try to finish before finishAfter — should revert
        vm.expectRevert(IBerachainBridgeAdapter.EscrowTimelockNotMet.selector);
        bridge.finishEscrow(escrowId, preimage);
    }

    function test_escrowInvalidPreimage() public {
        bytes32 preimage = keccak256("real_preimage_bera");
        bytes32 hashlock = sha256(abi.encodePacked(preimage));

        uint256 finishAfter = block.timestamp + 1 hours;
        uint256 cancelAfter = finishAfter + 12 hours;

        vm.deal(user, 10 ether);
        vm.prank(user);
        bytes32 escrowId = bridge.createEscrow{value: 1 ether}(
            address(0x5678),
            hashlock,
            finishAfter,
            cancelAfter
        );

        vm.warp(finishAfter + 1);

        bytes32 wrongPreimage = keccak256("wrong_preimage");
        bytes32 computedHash = sha256(abi.encodePacked(wrongPreimage));

        vm.expectRevert(
            abi.encodeWithSelector(
                IBerachainBridgeAdapter.InvalidPreimage.selector,
                hashlock,
                computedHash
            )
        );
        bridge.finishEscrow(escrowId, wrongPreimage);
    }

    /*//////////////////////////////////////////////////////////////
                     PRIVATE DEPOSIT / NULLIFIER TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_privateDeposit(bytes32 commitment) public {
        vm.assume(commitment != bytes32(0));

        bytes32 txHash = keccak256(abi.encode("priv_tx", commitment));
        bytes32 depositId = _initiateDeposit(1 ether, txHash);

        // Complete the deposit so status is COMPLETED
        vm.prank(admin);
        bridge.completeBERADeposit(depositId);

        // Build a valid ZK proof
        bytes32 nullifier = keccak256(abi.encode("nullifier", commitment));
        bytes32 proofBinding = keccak256(
            abi.encodePacked(depositId, commitment, nullifier)
        );
        // Proof must be >= 256 bytes, with proofBind at bytes [32:64]
        bytes memory zkProof = new bytes(256);
        assembly {
            mstore(add(zkProof, 64), proofBinding)
        }

        vm.prank(admin);
        bridge.registerPrivateDeposit(
            depositId,
            commitment,
            nullifier,
            zkProof
        );

        assertTrue(bridge.usedNullifiers(nullifier));
    }

    function testFuzz_duplicateNullifier(bytes32 nullifier) public {
        vm.assume(nullifier != bytes32(0));

        // First deposit
        bytes32 txHash1 = keccak256(abi.encode("null_tx1", nullifier));
        bytes32 depositId1 = _initiateDeposit(1 ether, txHash1);

        vm.prank(admin);
        bridge.completeBERADeposit(depositId1);

        bytes32 commitment1 = keccak256("commitment1");
        bytes32 proofBinding1 = keccak256(
            abi.encodePacked(depositId1, commitment1, nullifier)
        );
        bytes memory zkProof1 = new bytes(256);
        assembly {
            mstore(add(zkProof1, 64), proofBinding1)
        }

        vm.prank(admin);
        bridge.registerPrivateDeposit(
            depositId1,
            commitment1,
            nullifier,
            zkProof1
        );

        // Second deposit with same nullifier should fail
        bytes32 txHash2 = keccak256(abi.encode("null_tx2", nullifier));
        bytes32 depositId2 = _initiateDepositAtBlock(1 ether, txHash2, 2);

        vm.prank(admin);
        bridge.completeBERADeposit(depositId2);

        bytes32 commitment2 = keccak256("commitment2");
        bytes32 proofBinding2 = keccak256(
            abi.encodePacked(depositId2, commitment2, nullifier)
        );
        bytes memory zkProof2 = new bytes(256);
        assembly {
            mstore(add(zkProof2, 64), proofBinding2)
        }

        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(
                IBerachainBridgeAdapter.NullifierAlreadyUsed.selector,
                nullifier
            )
        );
        bridge.registerPrivateDeposit(
            depositId2,
            commitment2,
            nullifier,
            zkProof2
        );
    }

    /*//////////////////////////////////////////////////////////////
                        ACCESS CONTROL TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_onlyRelayerCanInitiateDeposit(address caller) public {
        vm.assume(caller != relayer && caller != admin && caller != address(0));

        bytes32 txHash = keccak256("ac_tx");

        (
            IBerachainBridgeAdapter.CometBFTProof memory proof,
            bytes32 blockAppHash
        ) = _buildCometBFTProof(txHash);

        IBerachainBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();

        // Submit block as relayer first
        vm.prank(relayer);
        bridge.submitCometBFTBlock(
            1,
            keccak256(abi.encode("blockHash", uint256(1))),
            blockAppHash,
            keccak256(abi.encode("validatorsHash", uint256(1))),
            0,
            block.timestamp,
            attestations
        );

        vm.prank(caller);
        vm.expectRevert();
        bridge.initiateBERADeposit(
            txHash,
            address(0x1234),
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
        bridge.completeBERADeposit(depositId);
    }

    function testFuzz_onlyGuardianCanPause(address caller) public {
        vm.assume(caller != admin && caller != address(0));

        vm.prank(caller);
        vm.expectRevert();
        bridge.pause();
    }

    function testFuzz_onlyRelayerCanSubmitBlock(address caller) public {
        vm.assume(caller != relayer && caller != admin && caller != address(0));

        IBerachainBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();

        vm.prank(caller);
        vm.expectRevert();
        bridge.submitCometBFTBlock(
            1,
            keccak256("blockHash"),
            keccak256("appHash"),
            keccak256("validatorsHash"),
            0,
            block.timestamp,
            attestations
        );
    }

    /*//////////////////////////////////////////////////////////////
                        PAUSE / UNPAUSE TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_pauseBlocksDeposits() public {
        vm.prank(admin);
        bridge.pause();

        IBerachainBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();

        // Cannot submit CometBFT block while paused
        vm.prank(relayer);
        vm.expectRevert();
        bridge.submitCometBFTBlock(
            1,
            keccak256("blockHash"),
            keccak256("appHash"),
            keccak256("validatorsHash"),
            0,
            block.timestamp,
            attestations
        );
    }

    function testFuzz_pauseBlocksWithdrawals() public {
        vm.prank(admin);
        bridge.pause();

        vm.prank(user);
        vm.expectRevert();
        bridge.initiateWithdrawal(address(0x5678), 1 ether);
    }

    function testFuzz_pauseBlocksEscrow() public {
        bytes32 hashlock = sha256(
            abi.encodePacked(keccak256("paused_bera"))
        );

        vm.prank(admin);
        bridge.pause();

        vm.deal(user, 1 ether);
        vm.prank(user);
        vm.expectRevert();
        bridge.createEscrow{value: 0.1 ether}(
            address(0x5678),
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
        bytes32 txHash = keccak256("unpause_tx");
        bytes32 depositId = _initiateDeposit(1 ether, txHash);
        assertTrue(depositId != bytes32(0));
    }

    function test_pauseBlocksRefund() public {
        uint256 amount = 1 ether;

        vm.prank(address(bridge));
        wBERA.mint(user, amount);

        vm.startPrank(user);
        wBERA.approve(address(bridge), amount);
        bytes32 wId = bridge.initiateWithdrawal(address(0x5678), amount);
        vm.stopPrank();

        vm.warp(block.timestamp + 24 hours + 1);

        vm.prank(admin);
        bridge.pause();

        vm.expectRevert();
        bridge.refundWithdrawal(wId);
    }

    /*//////////////////////////////////////////////////////////////
                       FEE WITHDRAWAL TESTS
    //////////////////////////////////////////////////////////////*/

    function test_feeWithdrawal() public {
        // Create a deposit to accumulate fees
        bytes32 depositId = _initiateDeposit(
            100 ether,
            keccak256("fee_test_tx")
        );

        uint256 expectedFee = (100 ether * 4) / 10_000;
        assertEq(bridge.accumulatedFees(), expectedFee);

        // Withdraw fees
        uint256 treasuryBalBefore = wBERA.balanceOf(treasury);
        vm.prank(admin);
        bridge.withdrawFees();

        assertEq(bridge.accumulatedFees(), 0);
        // Treasury should have received fees (up to bridge balance)
        uint256 treasuryBalAfter = wBERA.balanceOf(treasury);
        assertGe(treasuryBalAfter, treasuryBalBefore);
    }

    function test_feeWithdrawalRejectsZeroFees() public {
        // No deposits → no fees
        vm.prank(admin);
        vm.expectRevert(IBerachainBridgeAdapter.InvalidAmount.selector);
        bridge.withdrawFees();
    }

    /*//////////////////////////////////////////////////////////////
                     MULTIPLE DEPOSITS TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_multipleDeposits(uint8 count) public {
        uint256 n = bound(uint256(count), 1, 10);
        uint256 prevNonce = bridge.depositNonce();

        for (uint256 i = 0; i < n; i++) {
            bytes32 txHash = keccak256(abi.encode("multi_tx", i));
            bytes32 depositId = _initiateDepositAtBlock(1 ether, txHash, i + 1);

            assertTrue(depositId != bytes32(0));
            assertGt(bridge.depositNonce(), prevNonce);
            prevNonce = bridge.depositNonce();
        }
    }

    /*//////////////////////////////////////////////////////////////
                     TX HASH REPLAY PROTECTION
    //////////////////////////////////////////////////////////////*/

    function testFuzz_txHashReplayProtection(bytes32 txHash) public {
        vm.assume(txHash != bytes32(0));

        bytes32 depositId = _initiateDeposit(1 ether, txHash);
        assertTrue(depositId != bytes32(0));

        // Submit another verified block for second attempt
        (
            IBerachainBridgeAdapter.CometBFTProof memory proof,
            bytes32 blockAppHash
        ) = _buildCometBFTProof(txHash);

        IBerachainBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();

        vm.prank(relayer);
        bridge.submitCometBFTBlock(
            2,
            keccak256(abi.encode("blockHash", uint256(2))),
            blockAppHash,
            keccak256(abi.encode("validatorsHash", uint256(2))),
            0,
            block.timestamp,
            attestations
        );

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                IBerachainBridgeAdapter.BeraTxAlreadyUsed.selector,
                txHash
            )
        );
        bridge.initiateBERADeposit(
            txHash,
            address(0x1234),
            user,
            1 ether,
            2,
            proof,
            attestations
        );
    }

    /*//////////////////////////////////////////////////////////////
                     CONFIGURATION TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_configRejectsZeroAddresses(
        address a,
        address b,
        address c,
        uint256 sigs
    ) public {
        sigs = bound(sigs, 1, 100);

        vm.prank(admin);
        vm.expectRevert(IBerachainBridgeAdapter.ZeroAddress.selector);
        bridge.configure(address(0), b, c, sigs, 1);

        vm.prank(admin);
        vm.expectRevert(IBerachainBridgeAdapter.ZeroAddress.selector);
        bridge.configure(
            a == address(0) ? address(1) : a,
            address(0),
            c,
            sigs,
            1
        );

        vm.prank(admin);
        vm.expectRevert(IBerachainBridgeAdapter.ZeroAddress.selector);
        bridge.configure(
            a == address(0) ? address(1) : a,
            b == address(0) ? address(1) : b,
            address(0),
            sigs,
            1
        );
    }

    function test_configRejectsZeroSignatures() public {
        vm.prank(admin);
        vm.expectRevert(IBerachainBridgeAdapter.InvalidAmount.selector);
        bridge.configure(address(0x1), address(0x2), address(0x3), 0, 1);
    }

    function test_treasuryCanBeUpdated() public {
        address newTreasury = address(0xF1);
        vm.prank(admin);
        bridge.setTreasury(newTreasury);
        assertEq(bridge.treasury(), newTreasury);
    }

    function test_treasuryRejectsZeroAddress() public {
        vm.prank(admin);
        vm.expectRevert(IBerachainBridgeAdapter.ZeroAddress.selector);
        bridge.setTreasury(address(0));
    }

    /*//////////////////////////////////////////////////////////////
                       USER TRACKING TESTS
    //////////////////////////////////////////////////////////////*/

    function test_userTracking() public {
        // Deposit tracking
        bytes32 depositId = _initiateDeposit(
            1 ether,
            keccak256("track_deposit")
        );
        bytes32[] memory userDeps = bridge.getUserDeposits(user);
        assertEq(userDeps.length, 1);
        assertEq(userDeps[0], depositId);

        // Withdrawal tracking
        vm.prank(address(bridge));
        wBERA.mint(user, 1 ether);

        vm.startPrank(user);
        wBERA.approve(address(bridge), 1 ether);
        bytes32 wId = bridge.initiateWithdrawal(address(0x5678), 1 ether);
        vm.stopPrank();

        bytes32[] memory userWithds = bridge.getUserWithdrawals(user);
        assertEq(userWithds.length, 1);
        assertEq(userWithds[0], wId);

        // Escrow tracking
        vm.deal(user, 1 ether);
        bytes32 hashlock = sha256(
            abi.encodePacked(keccak256("track_escrow"))
        );
        vm.prank(user);
        bytes32 eId = bridge.createEscrow{value: 0.1 ether}(
            address(0x5678),
            hashlock,
            block.timestamp + 1 hours,
            block.timestamp + 5 hours
        );

        bytes32[] memory userEscs = bridge.getUserEscrows(user);
        assertEq(userEscs.length, 1);
        assertEq(userEscs[0], eId);
    }

    /*//////////////////////////////////////////////////////////////
                       BRIDGE STATS TESTS
    //////////////////////////////////////////////////////////////*/

    function test_bridgeStats() public {
        // Initial stats
        (
            uint256 deposited,
            uint256 withdrawn,
            uint256 escrowCount,
            ,
            ,
            uint256 fees,
            uint256 latestBlock
        ) = bridge.getBridgeStats();

        assertEq(deposited, 0);
        assertEq(withdrawn, 0);
        assertEq(escrowCount, 0);
        assertEq(fees, 0);
        assertEq(latestBlock, 0);

        // After deposit
        _initiateDeposit(10 ether, keccak256("stats_deposit"));
        (deposited, , , , , fees, ) = bridge.getBridgeStats();
        assertEq(deposited, 10 ether);
        assertEq(fees, (10 ether * 4) / 10_000);

        // After withdrawal
        vm.prank(address(bridge));
        wBERA.mint(user, 1 ether);
        vm.startPrank(user);
        wBERA.approve(address(bridge), 1 ether);
        bridge.initiateWithdrawal(address(0x5678), 1 ether);
        vm.stopPrank();

        (, withdrawn, , , , , ) = bridge.getBridgeStats();
        assertEq(withdrawn, 1 ether);

        // After escrow
        vm.deal(user, 1 ether);
        bytes32 hashlock = sha256(
            abi.encodePacked(keccak256("stats_escrow"))
        );
        vm.prank(user);
        bridge.createEscrow{value: 0.5 ether}(
            address(0x5678),
            hashlock,
            block.timestamp + 1 hours,
            block.timestamp + 5 hours
        );

        (, , escrowCount, , , , ) = bridge.getBridgeStats();
        assertEq(escrowCount, 1);
    }

    function test_bridgeStatsEscrowCounters() public {
        bytes32 preimage = keccak256("stats_preimage_bera");
        bytes32 hashlock = sha256(abi.encodePacked(preimage));

        uint256 finishAfter = block.timestamp + 1 hours;
        uint256 cancelAfter = finishAfter + 12 hours;

        // Create and finish one escrow
        vm.deal(user, 10 ether);
        vm.prank(user);
        bytes32 escrowId1 = bridge.createEscrow{value: 1 ether}(
            address(0x5678),
            hashlock,
            finishAfter,
            cancelAfter
        );

        vm.warp(finishAfter + 1);
        bridge.finishEscrow(escrowId1, preimage);

        (, , uint256 total, uint256 finished, uint256 cancelled, , ) = bridge
            .getBridgeStats();
        assertEq(total, 1);
        assertEq(finished, 1);
        assertEq(cancelled, 0);

        // Create and cancel another escrow
        bytes32 hashlock2 = sha256(
            abi.encodePacked(keccak256("cancel_stats_bera"))
        );
        uint256 finishAfter2 = block.timestamp + 1 hours;
        uint256 cancelAfter2 = finishAfter2 + 6 hours;

        vm.prank(user);
        bytes32 escrowId2 = bridge.createEscrow{value: 0.5 ether}(
            address(0x5678),
            hashlock2,
            finishAfter2,
            cancelAfter2
        );

        vm.warp(cancelAfter2 + 1);
        bridge.cancelEscrow(escrowId2);

        (, , total, finished, cancelled, , ) = bridge.getBridgeStats();
        assertEq(total, 2);
        assertEq(finished, 1);
        assertEq(cancelled, 1);
    }

    /*//////////////////////////////////////////////////////////////
                    DEPOSIT ID UNIQUENESS TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_depositIdUniqueness(uint8 count) public {
        uint256 n = bound(uint256(count), 2, 10);
        bytes32[] memory ids = new bytes32[](n);

        for (uint256 i = 0; i < n; i++) {
            bytes32 txHash = keccak256(abi.encode("unique_tx", i));
            ids[i] = _initiateDepositAtBlock(1 ether, txHash, i + 1);
        }

        // Verify all IDs are unique
        for (uint256 i = 0; i < n; i++) {
            for (uint256 j = i + 1; j < n; j++) {
                assertTrue(ids[i] != ids[j], "Deposit IDs must be unique");
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                    ESCROW DOUBLE FINISH / CANCEL TESTS
    //////////////////////////////////////////////////////////////*/

    function test_escrowDoubleFinish() public {
        bytes32 preimage = keccak256("double_finish_bera");
        bytes32 hashlock = sha256(abi.encodePacked(preimage));

        uint256 finishAfter = block.timestamp + 1 hours;
        uint256 cancelAfter = finishAfter + 12 hours;

        vm.deal(user, 10 ether);
        vm.prank(user);
        bytes32 escrowId = bridge.createEscrow{value: 1 ether}(
            address(0x5678),
            hashlock,
            finishAfter,
            cancelAfter
        );

        // Finish the escrow
        vm.warp(finishAfter + 1);
        bridge.finishEscrow(escrowId, preimage);

        // Attempt to finish again — should revert
        vm.expectRevert(
            abi.encodeWithSelector(
                IBerachainBridgeAdapter.EscrowNotActive.selector,
                escrowId
            )
        );
        bridge.finishEscrow(escrowId, preimage);
    }

    function test_escrowDoubleCancel() public {
        bytes32 hashlock = sha256(
            abi.encodePacked(keccak256("double_cancel_bera"))
        );

        uint256 finishAfter = block.timestamp + 2 hours;
        uint256 cancelAfter = finishAfter + 6 hours;

        vm.deal(user, 10 ether);
        vm.prank(user);
        bytes32 escrowId = bridge.createEscrow{value: 0.5 ether}(
            address(0x5678),
            hashlock,
            finishAfter,
            cancelAfter
        );

        vm.warp(cancelAfter + 1);
        bridge.cancelEscrow(escrowId);

        // Attempt to cancel again — should revert
        vm.expectRevert(
            abi.encodeWithSelector(
                IBerachainBridgeAdapter.EscrowNotActive.selector,
                escrowId
            )
        );
        bridge.cancelEscrow(escrowId);
    }

    /*//////////////////////////////////////////////////////////////
                  WITHDRAWAL DOUBLE COMPLETE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_withdrawalDoubleComplete() public {
        uint256 amount = 1 ether;

        vm.prank(address(bridge));
        wBERA.mint(user, amount);

        vm.startPrank(user);
        wBERA.approve(address(bridge), amount);
        bytes32 wId = bridge.initiateWithdrawal(address(0x5678), amount);
        vm.stopPrank();

        // Complete the withdrawal — use block >= 100 to avoid underflow in the contract's loop
        bytes32 beraTxHash = keccak256("complete_bera_tx_dc");
        (
            IBerachainBridgeAdapter.CometBFTProof memory proof,
            bytes32 blockAppHash
        ) = _buildCometBFTProof(beraTxHash);

        IBerachainBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();

        vm.prank(relayer);
        bridge.submitCometBFTBlock(
            100,
            keccak256(abi.encode("blockHash", uint256(100))),
            blockAppHash,
            keccak256(abi.encode("validatorsHash", uint256(100))),
            0,
            block.timestamp,
            attestations
        );

        vm.prank(relayer);
        bridge.completeWithdrawal(wId, beraTxHash, proof, attestations);

        // Attempt to complete again — should revert
        bytes32 beraTxHash2 = keccak256("complete_bera_tx_dc_2");
        (
            IBerachainBridgeAdapter.CometBFTProof memory proof2,
            bytes32 blockAppHash2
        ) = _buildCometBFTProof(beraTxHash2);

        vm.prank(relayer);
        bridge.submitCometBFTBlock(
            101,
            keccak256(abi.encode("blockHash", uint256(101))),
            blockAppHash2,
            keccak256(abi.encode("validatorsHash", uint256(101))),
            0,
            block.timestamp,
            attestations
        );

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                IBerachainBridgeAdapter.WithdrawalNotPending.selector,
                wId
            )
        );
        bridge.completeWithdrawal(wId, beraTxHash2, proof2, attestations);
    }

    /*//////////////////////////////////////////////////////////////
                       WITHDRAWAL NONCE TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_withdrawalNonceOnlyIncreases(uint8 count) public {
        uint256 n = bound(uint256(count), 1, 10);
        uint256 amount = 1 ether;

        // Mint wBERA to user for withdrawals (bridge owns wBERA)
        vm.prank(address(bridge));
        wBERA.mint(user, amount * n);

        vm.startPrank(user);
        wBERA.approve(address(bridge), amount * n);

        uint256 prevNonce = bridge.withdrawalNonce();
        for (uint256 i = 0; i < n; i++) {
            bridge.initiateWithdrawal(address(0x5678), amount);
            assertGt(bridge.withdrawalNonce(), prevNonce);
            prevNonce = bridge.withdrawalNonce();
        }

        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                    DEPOSIT ZERO RECIPIENT TEST
    //////////////////////////////////////////////////////////////*/

    function test_depositRejectsZeroRecipient() public {
        bytes32 txHash = keccak256("zero_recipient_tx");
        (
            IBerachainBridgeAdapter.CometBFTProof memory proof,
            bytes32 blockAppHash
        ) = _buildCometBFTProof(txHash);

        IBerachainBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();

        vm.prank(relayer);
        bridge.submitCometBFTBlock(
            1,
            keccak256(abi.encode("blockHash", uint256(1))),
            blockAppHash,
            keccak256(abi.encode("validatorsHash", uint256(1))),
            0,
            block.timestamp,
            attestations
        );

        vm.prank(relayer);
        vm.expectRevert(IBerachainBridgeAdapter.ZeroAddress.selector);
        bridge.initiateBERADeposit(
            txHash,
            address(0x1234),
            address(0), // zero recipient
            1 ether,
            1,
            proof,
            attestations
        );
    }

    /*//////////////////////////////////////////////////////////////
                    WITHDRAWAL ZERO RECIPIENT TEST
    //////////////////////////////////////////////////////////////*/

    function test_withdrawalRejectsZeroRecipient() public {
        vm.prank(user);
        vm.expectRevert(IBerachainBridgeAdapter.ZeroAddress.selector);
        bridge.initiateWithdrawal(address(0), 1 ether);
    }

    /*//////////////////////////////////////////////////////////////
                       VIEW FUNCTION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_viewFunctionsReturnDefaults() public view {
        IBerachainBridgeAdapter.BERADeposit memory dep = bridge.getDeposit(
            bytes32(0)
        );
        assertEq(dep.amountWei, 0);

        IBerachainBridgeAdapter.BERAWithdrawal memory w = bridge.getWithdrawal(
            bytes32(0)
        );
        assertEq(w.amountWei, 0);

        IBerachainBridgeAdapter.BERAEscrow memory e = bridge.getEscrow(
            bytes32(0)
        );
        assertEq(e.amountWei, 0);

        IBerachainBridgeAdapter.CometBFTBlock memory blk = bridge
            .getCometBFTBlock(0);
        assertFalse(blk.verified);
    }

    function test_userHistoryTracking() public view {
        bytes32[] memory deps = bridge.getUserDeposits(user);
        bytes32[] memory ws = bridge.getUserWithdrawals(user);
        bytes32[] memory es = bridge.getUserEscrows(user);

        assertEq(deps.length, 0);
        assertEq(ws.length, 0);
        assertEq(es.length, 0);
    }

    /*//////////////////////////////////////////////////////////////
                    COMETBFT BLOCK HEADER FIELDS TEST
    //////////////////////////////////////////////////////////////*/

    function testFuzz_cometBFTBlockFields(
        uint256 blockNumber,
        bytes32 blockHash,
        bytes32 appHash,
        bytes32 validatorsHash,
        uint256 round
    ) public {
        blockNumber = bound(blockNumber, 1, 1_000_000);
        round = bound(round, 0, 100);

        IBerachainBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();

        vm.prank(relayer);
        bridge.submitCometBFTBlock(
            blockNumber,
            blockHash,
            appHash,
            validatorsHash,
            round,
            block.timestamp,
            attestations
        );

        IBerachainBridgeAdapter.CometBFTBlock memory blk = bridge
            .getCometBFTBlock(blockNumber);
        assertTrue(blk.verified);
        assertEq(blk.blockNumber, blockNumber);
        assertEq(blk.blockHash, blockHash);
        assertEq(blk.appHash, appHash);
        assertEq(blk.validatorsHash, validatorsHash);
        assertEq(blk.round, round);
        assertEq(blk.timestamp, block.timestamp);
    }

    /*//////////////////////////////////////////////////////////////
              ESCROW BERACHAIN ADDRESS PARTY TEST
    //////////////////////////////////////////////////////////////*/

    function testFuzz_escrowBeraPartyAddress(address beraParty) public {
        vm.assume(beraParty != address(0));

        bytes32 hashlock = sha256(
            abi.encodePacked(keccak256("party_test"))
        );

        vm.deal(user, 1 ether);
        vm.prank(user);
        bytes32 escrowId = bridge.createEscrow{value: 0.1 ether}(
            beraParty,
            hashlock,
            block.timestamp + 1 hours,
            block.timestamp + 5 hours
        );

        IBerachainBridgeAdapter.BERAEscrow memory e = bridge.getEscrow(
            escrowId
        );
        assertEq(e.beraParty, beraParty);
        assertEq(e.evmParty, user);
    }

    function test_escrowRejectsZeroBeraParty() public {
        bytes32 hashlock = sha256(
            abi.encodePacked(keccak256("zero_party"))
        );

        vm.deal(user, 1 ether);
        vm.prank(user);
        vm.expectRevert(IBerachainBridgeAdapter.ZeroAddress.selector);
        bridge.createEscrow{value: 0.1 ether}(
            address(0),
            hashlock,
            block.timestamp + 1 hours,
            block.timestamp + 5 hours
        );
    }

    /*//////////////////////////////////////////////////////////////
                 DEPOSIT FEE ACCUMULATION INVARIANT
    //////////////////////////////////////////////////////////////*/

    function testFuzz_feeAccumulationInvariant(uint8 count) public {
        uint256 n = bound(uint256(count), 1, 8);
        uint256 expectedFees = 0;

        for (uint256 i = 0; i < n; i++) {
            uint256 amount = bound(
                uint256(keccak256(abi.encode("inv", i))),
                MIN_DEPOSIT,
                1000 ether
            );
            bytes32 txHash = keccak256(abi.encode("fee_inv_tx", i));
            _initiateDepositAtBlock(amount, txHash, i + 1);
            expectedFees += (amount * 4) / 10_000;
        }

        assertEq(bridge.accumulatedFees(), expectedFees);
    }

    /*//////////////////////////////////////////////////////////////
                   LATEST BLOCK TRACKING TEST
    //////////////////////////////////////////////////////////////*/

    function test_latestBlockTracking() public {
        assertEq(bridge.latestBlockNumber(), 0);

        bytes32 txHash1 = keccak256("block_track_1");
        _submitVerifiedBlock(5, txHash1);
        assertEq(bridge.latestBlockNumber(), 5);

        bytes32 txHash2 = keccak256("block_track_2");
        _submitVerifiedBlock(3, txHash2);
        // latestBlockNumber should stay at 5 (only increases)
        assertEq(bridge.latestBlockNumber(), 5);

        bytes32 txHash3 = keccak256("block_track_3");
        _submitVerifiedBlock(10, txHash3);
        assertEq(bridge.latestBlockNumber(), 10);
    }
}
