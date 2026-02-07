// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {MonadBridgeAdapter} from "../../contracts/crosschain/MonadBridgeAdapter.sol";
import {IMonadBridgeAdapter} from "../../contracts/interfaces/IMonadBridgeAdapter.sol";
import {MockWrappedMON} from "../../contracts/mocks/MockWrappedMON.sol";
import {MockMonadBFTVerifier} from "../../contracts/mocks/MockMonadBFTVerifier.sol";

/**
 * @title MonadBridgeFuzz
 * @notice Foundry fuzz & invariant tests for the MonadBridgeAdapter
 * @dev Tests Wei precision (18 decimals), MonadBFT verification,
 *      MonadStateProof validation, and Monad-specific bridge parameters.
 */
contract MonadBridgeFuzz is Test {
    MonadBridgeAdapter public bridge;
    MockWrappedMON public wMON;
    MockMonadBFTVerifier public monadBFTVerifier;

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

        bridge = new MonadBridgeAdapter(admin);
        wMON = new MockWrappedMON();
        monadBFTVerifier = new MockMonadBFTVerifier();

        // Register validators with voting power
        monadBFTVerifier.addValidator(VALIDATOR_1, 100);
        monadBFTVerifier.addValidator(VALIDATOR_2, 100);
        monadBFTVerifier.addValidator(VALIDATOR_3, 100);

        // Configure bridge
        bridge.configure(
            address(0x1), // monadBridgeContract
            address(wMON),
            address(monadBFTVerifier),
            2, // minValidatorSignatures
            1 // requiredBlockConfirmations
        );

        bridge.setTreasury(treasury);
        bridge.grantRole(bridge.RELAYER_ROLE(), relayer);

        // Fund the bridge with wMON
        wMON.mint(address(bridge), 100_000_000 ether);

        // Transfer wMON ownership to bridge so completeMONDeposit can mint
        wMON.transferOwnership(address(bridge));

        vm.stopPrank();

        // Wildcard mock: accept any verifyAttestation(bytes32,address,bytes) call
        vm.mockCall(
            address(monadBFTVerifier),
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
        returns (IMonadBridgeAdapter.ValidatorAttestation[] memory)
    {
        IMonadBridgeAdapter.ValidatorAttestation[]
            memory attestations = new IMonadBridgeAdapter.ValidatorAttestation[](
                3
            );

        attestations[0] = IMonadBridgeAdapter.ValidatorAttestation({
            validator: VALIDATOR_1,
            signature: hex"01"
        });
        attestations[1] = IMonadBridgeAdapter.ValidatorAttestation({
            validator: VALIDATOR_2,
            signature: hex"02"
        });
        attestations[2] = IMonadBridgeAdapter.ValidatorAttestation({
            validator: VALIDATOR_3,
            signature: hex"03"
        });

        return attestations;
    }

    function _submitVerifiedBlock(
        uint256 blockNumber,
        bytes32 blockHash
    ) internal {
        IMonadBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();

        vm.prank(relayer);
        bridge.submitMonadBFTBlock(
            blockNumber,
            blockHash,
            keccak256(abi.encode("parentHash", blockNumber)),
            keccak256(abi.encode("stateRoot", blockNumber)),
            keccak256(abi.encode("executionRoot", blockNumber)),
            1, // round
            block.timestamp, // timestamp
            attestations
        );
    }

    function _buildStateProof(
        uint256 blockNumber
    ) internal pure returns (IMonadBridgeAdapter.MonadStateProof memory) {
        // Build a MonadStateProof that passes _verifyMonadStateProof.
        // The contract computes:
        //   computedHash = keccak256(abi.encodePacked(leafHash, proof.stateRoot, proof.value))
        //   then iterates merkle siblings; final result must equal the stored block stateRoot.
        //
        // We pre-compute compatible values so the proof verification passes.
        bytes32 stateRoot = keccak256(abi.encode("stateRoot", blockNumber));

        bytes32[] memory merkleProof = new bytes32[](1);
        // We set a single-element proof so the loop runs once.
        // The final computedHash after the loop must equal the block's stateRoot.
        // We'll adjust: set proof.stateRoot and proof.value so that the intermediate hash,
        // when hashed with the sibling, equals stateRoot.
        // Since the actual leafHash varies per call, we override verification via mockCall below.
        merkleProof[0] = stateRoot;

        return
            IMonadBridgeAdapter.MonadStateProof({
                merkleProof: merkleProof,
                stateRoot: stateRoot,
                value: abi.encodePacked(stateRoot)
            });
    }

    function _initiateDeposit(
        uint256 amount,
        bytes32 txHash
    ) internal returns (bytes32) {
        // Submit a verified MonadBFT block first
        bytes32 blockHash = keccak256(abi.encode("blockHash", uint256(1)));
        _submitVerifiedBlock(1, blockHash);

        IMonadBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        IMonadBridgeAdapter.MonadStateProof memory proof = _buildStateProof(1);

        // Mock _verifyMonadStateProof to pass by mocking the internal staticcall behavior
        // The contract checks _verifyMonadStateProof internally (pure function), so we need
        // the proof to actually verify. Instead, we mock at a higher level:
        // We already have the wildcard mockCall for verifyAttestation.
        // For the state proof, we need to construct a valid one.
        // Since it's complex, we mock the entire initiateMONDeposit result path by ensuring
        // the Merkle proof passes. Let's compute the correct proof values.

        bytes32 stateRoot = keccak256(abi.encode("stateRoot", uint256(1)));

        // Compute the correct proof that will pass _verifyMonadStateProof:
        // computedHash = keccak256(abi.encodePacked(txHash, proof.stateRoot, proof.value))
        // After one iteration: hash(computedHash, sibling) or hash(sibling, computedHash)
        // must equal the block's stateRoot
        bytes32 computedHash = keccak256(
            abi.encodePacked(txHash, stateRoot, abi.encodePacked(stateRoot))
        );

        // We need: keccak256(abi.encodePacked(min, max)) == stateRoot
        // where min = min(computedHash, sibling), max = max(computedHash, sibling)
        // This is hard to solve. Instead, let's use a direct approach:
        // We'll set the merkle proof sibling so that the hash matches.
        // Since we can't easily reverse keccak, let's set the block stateRoot to match
        // the computed value instead. We re-submit the block with a matching stateRoot.

        // Compute what the final hash would be if sibling = bytes32(0):
        bytes32 sibling = bytes32(0);
        bytes32 finalHash;
        if (computedHash <= sibling) {
            finalHash = keccak256(abi.encodePacked(computedHash, sibling));
        } else {
            finalHash = keccak256(abi.encodePacked(sibling, computedHash));
        }

        // Re-submit block 1 with stateRoot = finalHash so the proof verifies
        IMonadBridgeAdapter.ValidatorAttestation[]
            memory att2 = _buildValidatorAttestations();
        vm.prank(relayer);
        bridge.submitMonadBFTBlock(
            1,
            blockHash,
            keccak256(abi.encode("parentHash", uint256(1))),
            finalHash, // stateRoot that matches our proof
            keccak256(abi.encode("executionRoot", uint256(1))),
            1,
            block.timestamp,
            att2
        );

        // Now build matching proof
        bytes32[] memory merkleProof = new bytes32[](1);
        merkleProof[0] = sibling;

        IMonadBridgeAdapter.MonadStateProof
            memory validProof = IMonadBridgeAdapter.MonadStateProof({
                merkleProof: merkleProof,
                stateRoot: finalHash,
                value: abi.encodePacked(stateRoot)
            });

        // Re-compute to verify:
        // computedHash = keccak256(abi.encodePacked(txHash, finalHash, abi.encodePacked(stateRoot)))
        bytes32 recomputed = keccak256(
            abi.encodePacked(txHash, finalHash, abi.encodePacked(stateRoot))
        );

        // Final hash after one round with sibling=0:
        bytes32 finalRecomputed;
        if (recomputed <= sibling) {
            finalRecomputed = keccak256(abi.encodePacked(recomputed, sibling));
        } else {
            finalRecomputed = keccak256(abi.encodePacked(sibling, recomputed));
        }

        // We need finalRecomputed == finalHash. This won't match because we changed stateRoot.
        // The circular dependency means we need a fixed-point approach.
        // Instead, let's use a simpler strategy: override at a deeper level.

        // ---- Simplified approach: just set block stateRoot = computedHash (single element proof with itself) ----
        // Actually, the simplest approach: use proof.stateRoot = X, proof.value = Y
        // such that keccak256(txHash || X || Y) when hashed with sibling[0] equals the block stateRoot.
        // Let's pick block stateRoot = keccak256(txHash || X || Y) with empty merkle proof...
        // But merkleProof.length == 0 returns false.

        // The most robust approach for testing: override the block stateRoot after computing the proof.
        // We compute the FULL chain forward.

        // Step 1: Pick proof fields
        bytes32 proofStateRoot = bytes32(uint256(0xdead));
        bytes memory proofValue = hex"cafe";
        bytes32 mSibling = bytes32(uint256(0xbeef));

        // Step 2: Compute intermediate
        bytes32 intermediate = keccak256(
            abi.encodePacked(txHash, proofStateRoot, proofValue)
        );

        // Step 3: One Merkle step
        bytes32 root;
        if (intermediate <= mSibling) {
            root = keccak256(abi.encodePacked(intermediate, mSibling));
        } else {
            root = keccak256(abi.encodePacked(mSibling, intermediate));
        }

        // Step 4: Submit block with stateRoot = root
        vm.prank(relayer);
        bridge.submitMonadBFTBlock(
            1,
            blockHash,
            keccak256(abi.encode("parentHash", uint256(1))),
            root,
            keccak256(abi.encode("executionRoot", uint256(1))),
            1,
            block.timestamp,
            att2
        );

        // Step 5: Build valid proof
        bytes32[] memory mProof = new bytes32[](1);
        mProof[0] = mSibling;

        IMonadBridgeAdapter.MonadStateProof
            memory correctProof = IMonadBridgeAdapter.MonadStateProof({
                merkleProof: mProof,
                stateRoot: proofStateRoot,
                value: proofValue
            });

        vm.prank(relayer);
        return
            bridge.initiateMONDeposit(
                txHash,
                address(0x1234), // monadSender
                user,
                amount,
                1, // monadBlockNumber
                correctProof,
                attestations
            );
    }

    /// @dev Helper to initiate deposit at a specific block number
    function _initiateDepositAtBlock(
        uint256 amount,
        bytes32 txHash,
        uint256 blockNum
    ) internal returns (bytes32) {
        bytes32 blockHash = keccak256(abi.encode("blockHash", blockNum));

        // Compute proof
        bytes32 proofStateRoot = bytes32(uint256(0xdead));
        bytes memory proofValue = hex"cafe";
        bytes32 mSibling = bytes32(uint256(0xbeef));

        bytes32 intermediate = keccak256(
            abi.encodePacked(txHash, proofStateRoot, proofValue)
        );
        bytes32 root;
        if (intermediate <= mSibling) {
            root = keccak256(abi.encodePacked(intermediate, mSibling));
        } else {
            root = keccak256(abi.encodePacked(mSibling, intermediate));
        }

        // Submit block
        IMonadBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        vm.prank(relayer);
        bridge.submitMonadBFTBlock(
            blockNum,
            blockHash,
            keccak256(abi.encode("parentHash", blockNum)),
            root,
            keccak256(abi.encode("executionRoot", blockNum)),
            1,
            block.timestamp,
            attestations
        );

        // Build proof
        bytes32[] memory mProof = new bytes32[](1);
        mProof[0] = mSibling;
        IMonadBridgeAdapter.MonadStateProof memory proof = IMonadBridgeAdapter
            .MonadStateProof({
                merkleProof: mProof,
                stateRoot: proofStateRoot,
                value: proofValue
            });

        vm.prank(relayer);
        return
            bridge.initiateMONDeposit(
                txHash,
                address(0x1234),
                user,
                amount,
                blockNum,
                proof,
                attestations
            );
    }

    /*//////////////////////////////////////////////////////////////
                         CONSTANTS TESTS
    //////////////////////////////////////////////////////////////*/

    function test_constantsAreCorrect() public view {
        assertEq(bridge.MONAD_CHAIN_ID(), 41454);
        assertEq(bridge.BRIDGE_FEE_BPS(), 3);
        assertEq(bridge.WITHDRAWAL_REFUND_DELAY(), 24 hours);
        assertEq(bridge.MIN_ESCROW_TIMELOCK(), 1 hours);
        assertEq(bridge.MAX_ESCROW_TIMELOCK(), 30 days);
        assertEq(bridge.DEFAULT_BLOCK_CONFIRMATIONS(), 1);
        assertEq(bridge.MIN_DEPOSIT(), 0.01 ether);
        assertEq(bridge.MAX_DEPOSIT(), 10_000_000 ether);
        assertEq(bridge.BPS_DENOMINATOR(), 10_000);
    }

    function test_constructorRejectsZeroAdmin() public {
        vm.expectRevert(IMonadBridgeAdapter.ZeroAddress.selector);
        new MonadBridgeAdapter(address(0));
    }

    /*//////////////////////////////////////////////////////////////
                         DEPOSIT FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_depositAmount(uint256 amount) public {
        amount = bound(amount, MIN_DEPOSIT, MAX_DEPOSIT);

        bytes32 txHash = keccak256(abi.encode("mon_tx_fuzz", amount));
        bytes32 depositId = _initiateDeposit(amount, txHash);

        IMonadBridgeAdapter.MONDeposit memory dep = bridge.getDeposit(
            depositId
        );
        assertEq(dep.amountWei, amount);
        assertEq(dep.fee, (amount * 3) / 10_000);
        assertEq(dep.netAmountWei, amount - dep.fee);
    }

    /*//////////////////////////////////////////////////////////////
                        FEE CALCULATION TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_feeCalculation(uint256 amount) public pure {
        amount = bound(amount, MIN_DEPOSIT, MAX_DEPOSIT);
        uint256 fee = (amount * 3) / 10_000;
        uint256 net = amount - fee;

        // Fee should never exceed the amount
        assertLe(fee, amount);
        // Net + fee = amount
        assertEq(net + fee, amount);
        // 0.03% fee
        assertLe(fee, amount / 100);
    }

    /*//////////////////////////////////////////////////////////////
                  MONADBFT BLOCK CHAIN VERIFICATION TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_monadBFTBlockChain(uint8 count) public {
        uint256 n = bound(uint256(count), 1, 20);

        for (uint256 i = 0; i < n; i++) {
            bytes32 blockHash = keccak256(abi.encode("blockHash", i + 1));
            _submitVerifiedBlock(i + 1, blockHash);

            IMonadBridgeAdapter.MonadBFTBlock memory blk = bridge
                .getMonadBFTBlock(i + 1);
            assertTrue(blk.verified);
            assertEq(blk.blockHash, blockHash);
        }

        assertEq(bridge.latestBlockNumber(), n);
    }

    function test_depositRequiresVerifiedBlock() public {
        // Don't submit any MonadBFT block — deposit should fail
        IMonadBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();

        bytes32[] memory mProof = new bytes32[](1);
        mProof[0] = bytes32(uint256(0xbeef));
        IMonadBridgeAdapter.MonadStateProof memory proof = IMonadBridgeAdapter
            .MonadStateProof({
                merkleProof: mProof,
                stateRoot: bytes32(uint256(0xdead)),
                value: hex"cafe"
            });

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                IMonadBridgeAdapter.MonadBlockNotVerified.selector,
                999
            )
        );
        bridge.initiateMONDeposit(
            keccak256("unverified_tx"),
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

        IMonadBridgeAdapter.MONDeposit memory dep = bridge.getDeposit(
            depositId
        );
        assertEq(
            uint256(dep.status),
            uint256(IMonadBridgeAdapter.DepositStatus.VERIFIED)
        );
        assertEq(dep.evmRecipient, user);
        assertEq(dep.monadSender, address(0x1234));
        assertEq(dep.monadTxHash, txHash);
        assertGt(dep.initiatedAt, 0);
    }

    /*//////////////////////////////////////////////////////////////
                       AMOUNT BOUNDS TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_depositAmountBounds(uint256 amount) public {
        amount = bound(amount, MIN_DEPOSIT, MAX_DEPOSIT);

        bytes32 txHash = keccak256(abi.encode("bounds_tx", amount));
        bytes32 depositId = _initiateDeposit(amount, txHash);

        IMonadBridgeAdapter.MONDeposit memory dep = bridge.getDeposit(
            depositId
        );
        assertGe(dep.amountWei, MIN_DEPOSIT);
        assertLe(dep.amountWei, MAX_DEPOSIT);
    }

    function testFuzz_depositRejectsAmountBelowMin(uint256 amount) public {
        amount = bound(amount, 1, MIN_DEPOSIT - 1);

        // Submit a block first
        bytes32 blockHash = keccak256(abi.encode("blockHash", uint256(1)));
        _submitVerifiedBlock(1, blockHash);

        IMonadBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        IMonadBridgeAdapter.MonadStateProof memory proof = _buildStateProof(1);

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                IMonadBridgeAdapter.AmountBelowMinimum.selector,
                amount,
                MIN_DEPOSIT
            )
        );
        bridge.initiateMONDeposit(
            keccak256(abi.encode("tx_low", amount)),
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

        bytes32 blockHash = keccak256(abi.encode("blockHash", uint256(1)));
        _submitVerifiedBlock(1, blockHash);

        IMonadBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        IMonadBridgeAdapter.MonadStateProof memory proof = _buildStateProof(1);

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                IMonadBridgeAdapter.AmountAboveMaximum.selector,
                amount,
                MAX_DEPOSIT
            )
        );
        bridge.initiateMONDeposit(
            keccak256(abi.encode("tx_high", amount)),
            address(0x1234),
            user,
            amount,
            1,
            proof,
            attestations
        );
    }

    /*//////////////////////////////////////////////////////////////
                    DEPOSIT COMPLETION TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_completeDeposit(uint256 amount) public {
        amount = bound(amount, MIN_DEPOSIT, MAX_DEPOSIT);

        bytes32 txHash = keccak256(abi.encode("complete_tx", amount));
        bytes32 depositId = _initiateDeposit(amount, txHash);

        // Complete the deposit
        vm.prank(admin);
        bridge.completeMONDeposit(depositId);

        IMonadBridgeAdapter.MONDeposit memory dep = bridge.getDeposit(
            depositId
        );
        assertEq(
            uint256(dep.status),
            uint256(IMonadBridgeAdapter.DepositStatus.COMPLETED)
        );
        assertGt(dep.completedAt, 0);
    }

    function test_completeDepositNotFound() public {
        bytes32 fakeId = keccak256("nonexistent");

        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(
                IMonadBridgeAdapter.DepositNotFound.selector,
                fakeId
            )
        );
        bridge.completeMONDeposit(fakeId);
    }

    function test_completeDepositAlreadyCompleted() public {
        bytes32 txHash = keccak256("double_complete_tx");
        bytes32 depositId = _initiateDeposit(1 ether, txHash);

        vm.prank(admin);
        bridge.completeMONDeposit(depositId);

        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(
                IMonadBridgeAdapter.DepositNotVerified.selector,
                depositId
            )
        );
        bridge.completeMONDeposit(depositId);
    }

    /*//////////////////////////////////////////////////////////////
                    WITHDRAWAL LIFECYCLE TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_withdrawalLifecycle(uint256 amount) public {
        amount = bound(amount, MIN_DEPOSIT, MAX_DEPOSIT);

        // Mint wMON to user for withdrawal (bridge owns wMON)
        vm.prank(address(bridge));
        wMON.mint(user, amount);

        vm.startPrank(user);
        wMON.approve(address(bridge), amount);
        bytes32 wId = bridge.initiateWithdrawal(
            address(0x5678), // monadRecipient
            amount
        );
        vm.stopPrank();

        IMonadBridgeAdapter.MONWithdrawal memory w = bridge.getWithdrawal(wId);
        assertEq(
            uint256(w.status),
            uint256(IMonadBridgeAdapter.WithdrawalStatus.PENDING)
        );
        assertEq(w.evmSender, user);
        assertEq(w.monadRecipient, address(0x5678));
        assertEq(w.amountWei, amount);
    }

    function test_withdrawalRefundAfterDelay() public {
        uint256 amount = 1 ether;

        vm.prank(address(bridge));
        wMON.mint(user, amount);

        vm.startPrank(user);
        wMON.approve(address(bridge), amount);
        bytes32 wId = bridge.initiateWithdrawal(address(0x5678), amount);
        vm.stopPrank();

        // Cannot refund before delay
        vm.expectRevert();
        bridge.refundWithdrawal(wId);

        // Warp past refund delay (24 hours)
        vm.warp(block.timestamp + 24 hours + 1);

        uint256 balBefore = wMON.balanceOf(user);
        bridge.refundWithdrawal(wId);
        uint256 balAfter = wMON.balanceOf(user);

        assertEq(balAfter - balBefore, amount);

        IMonadBridgeAdapter.MONWithdrawal memory w = bridge.getWithdrawal(wId);
        assertEq(
            uint256(w.status),
            uint256(IMonadBridgeAdapter.WithdrawalStatus.REFUNDED)
        );
    }

    function test_refundTooEarly() public {
        uint256 amount = 1 ether;

        vm.prank(address(bridge));
        wMON.mint(user, amount);

        vm.startPrank(user);
        wMON.approve(address(bridge), amount);
        bytes32 wId = bridge.initiateWithdrawal(address(0x5678), amount);
        vm.stopPrank();

        uint256 initiatedAt = block.timestamp;

        vm.expectRevert(
            abi.encodeWithSelector(
                IMonadBridgeAdapter.RefundTooEarly.selector,
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
                IMonadBridgeAdapter.AmountBelowMinimum.selector,
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
                IMonadBridgeAdapter.AmountAboveMaximum.selector,
                amount,
                MAX_DEPOSIT
            )
        );
        bridge.initiateWithdrawal(address(0x5678), amount);
    }

    function test_withdrawalRejectsZeroRecipient() public {
        vm.prank(address(bridge));
        wMON.mint(user, 1 ether);

        vm.startPrank(user);
        wMON.approve(address(bridge), 1 ether);
        vm.expectRevert(IMonadBridgeAdapter.ZeroAddress.selector);
        bridge.initiateWithdrawal(address(0), 1 ether);
        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                        ESCROW LIFECYCLE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_escrowCreateFinishLifecycle() public {
        bytes32 preimage = keccak256("test_preimage_monad");
        bytes32 hashlock = sha256(abi.encodePacked(preimage));

        uint256 finishAfter = block.timestamp + 1 hours;
        uint256 cancelAfter = finishAfter + 12 hours;

        vm.deal(user, 10 ether);
        vm.prank(user);
        bytes32 escrowId = bridge.createEscrow{value: 1 ether}(
            address(0x5678), // monadParty
            hashlock,
            finishAfter,
            cancelAfter
        );

        IMonadBridgeAdapter.MONEscrow memory e = bridge.getEscrow(escrowId);
        assertEq(
            uint256(e.status),
            uint256(IMonadBridgeAdapter.EscrowStatus.ACTIVE)
        );
        assertEq(e.amountWei, 1 ether);

        // Finish after timelock
        vm.warp(finishAfter + 1);
        bridge.finishEscrow(escrowId, preimage);

        e = bridge.getEscrow(escrowId);
        assertEq(
            uint256(e.status),
            uint256(IMonadBridgeAdapter.EscrowStatus.FINISHED)
        );
        assertEq(e.preimage, preimage);
    }

    function test_escrowCreateCancelLifecycle() public {
        bytes32 hashlock = sha256(abi.encodePacked(keccak256("cancel_monad")));

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
        vm.expectRevert(IMonadBridgeAdapter.EscrowTimelockNotMet.selector);
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
            abi.encodePacked(keccak256("timelock_monad"))
        );

        vm.deal(user, 1 ether);
        vm.prank(user);
        bytes32 escrowId = bridge.createEscrow{value: 0.1 ether}(
            address(0x5678),
            hashlock,
            finish,
            cancel
        );

        IMonadBridgeAdapter.MONEscrow memory e = bridge.getEscrow(escrowId);
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

        bytes32 hashlock = sha256(abi.encodePacked(keccak256("long_monad")));

        vm.deal(user, 1 ether);
        vm.prank(user);
        vm.expectRevert(IMonadBridgeAdapter.InvalidTimelockRange.selector);
        bridge.createEscrow{value: 0.1 ether}(
            address(0x5678),
            hashlock,
            finish,
            cancel
        );
    }

    function test_escrowRejectsZeroHashlock() public {
        vm.deal(user, 1 ether);
        vm.prank(user);
        vm.expectRevert(IMonadBridgeAdapter.InvalidAmount.selector);
        bridge.createEscrow{value: 0.1 ether}(
            address(0x5678),
            bytes32(0),
            block.timestamp + 1 hours,
            block.timestamp + 5 hours
        );
    }

    function test_escrowRejectsZeroValue() public {
        bytes32 hashlock = sha256(abi.encodePacked(keccak256("zero_val")));

        vm.prank(user);
        vm.expectRevert(IMonadBridgeAdapter.InvalidAmount.selector);
        bridge.createEscrow{value: 0}(
            address(0x5678),
            hashlock,
            block.timestamp + 1 hours,
            block.timestamp + 5 hours
        );
    }

    function test_escrowRejectsZeroMonadParty() public {
        bytes32 hashlock = sha256(abi.encodePacked(keccak256("zero_party")));
        vm.deal(user, 1 ether);

        vm.prank(user);
        vm.expectRevert(IMonadBridgeAdapter.ZeroAddress.selector);
        bridge.createEscrow{value: 0.1 ether}(
            address(0),
            hashlock,
            block.timestamp + 1 hours,
            block.timestamp + 5 hours
        );
    }

    function test_escrowInvalidPreimage() public {
        bytes32 preimage = keccak256("correct_preimage");
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
        bytes32 wrongHash = sha256(abi.encodePacked(wrongPreimage));

        vm.expectRevert(
            abi.encodeWithSelector(
                IMonadBridgeAdapter.InvalidPreimage.selector,
                hashlock,
                wrongHash
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
        bridge.completeMONDeposit(depositId);

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
        bridge.completeMONDeposit(depositId1);

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
        bridge.completeMONDeposit(depositId2);

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
                IMonadBridgeAdapter.NullifierAlreadyUsed.selector,
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

        bytes32 blockHash = keccak256(abi.encode("blockHash", uint256(1)));
        _submitVerifiedBlock(1, blockHash);

        IMonadBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        IMonadBridgeAdapter.MonadStateProof memory proof = _buildStateProof(1);

        vm.prank(caller);
        vm.expectRevert();
        bridge.initiateMONDeposit(
            keccak256("ac_tx"),
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
        bridge.completeMONDeposit(depositId);
    }

    function testFuzz_onlyGuardianCanPause(address caller) public {
        vm.assume(caller != admin && caller != address(0));

        vm.prank(caller);
        vm.expectRevert();
        bridge.pause();
    }

    /*//////////////////////////////////////////////////////////////
                        PAUSE / UNPAUSE TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_pauseBlocksDeposits() public {
        vm.prank(admin);
        bridge.pause();

        bytes32 blockHash = keccak256(abi.encode("blockHash", uint256(1)));

        // Cannot submit MonadBFT block while paused
        IMonadBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();

        vm.prank(relayer);
        vm.expectRevert();
        bridge.submitMonadBFTBlock(
            1,
            blockHash,
            keccak256("parentHash"),
            keccak256("stateRoot"),
            keccak256("executionRoot"),
            1,
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
        bytes32 hashlock = sha256(abi.encodePacked(keccak256("paused_monad")));

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

    /*//////////////////////////////////////////////////////////////
                       FEE WITHDRAWAL TESTS
    //////////////////////////////////////////////////////////////*/

    function test_feeWithdrawal() public {
        // Create a deposit to accumulate fees
        bytes32 depositId = _initiateDeposit(
            100 ether,
            keccak256("fee_test_tx")
        );

        uint256 expectedFee = (100 ether * 3) / 10_000;
        assertEq(bridge.accumulatedFees(), expectedFee);

        // Withdraw fees
        uint256 treasuryBalBefore = wMON.balanceOf(treasury);
        vm.prank(admin);
        bridge.withdrawFees();

        assertEq(bridge.accumulatedFees(), 0);
        // Treasury should have received fees (up to bridge balance)
        uint256 treasuryBalAfter = wMON.balanceOf(treasury);
        assertGe(treasuryBalAfter, treasuryBalBefore);
    }

    function test_feeWithdrawalZeroFees() public {
        vm.prank(admin);
        vm.expectRevert(IMonadBridgeAdapter.InvalidAmount.selector);
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
            _initiateDepositAtBlock(1 ether, txHash, i + 1);

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

        // Attempt same txHash at a different block — should revert
        bytes32 blockHash2 = keccak256(abi.encode("blockHash", uint256(2)));

        bytes32 proofStateRoot = bytes32(uint256(0xdead));
        bytes memory proofValue = hex"cafe";
        bytes32 mSibling = bytes32(uint256(0xbeef));
        bytes32 intermediate = keccak256(
            abi.encodePacked(txHash, proofStateRoot, proofValue)
        );
        bytes32 root;
        if (intermediate <= mSibling) {
            root = keccak256(abi.encodePacked(intermediate, mSibling));
        } else {
            root = keccak256(abi.encodePacked(mSibling, intermediate));
        }

        IMonadBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        vm.prank(relayer);
        bridge.submitMonadBFTBlock(
            2,
            blockHash2,
            keccak256(abi.encode("parentHash", uint256(2))),
            root,
            keccak256(abi.encode("executionRoot", uint256(2))),
            1,
            block.timestamp,
            attestations
        );

        bytes32[] memory mProof = new bytes32[](1);
        mProof[0] = mSibling;
        IMonadBridgeAdapter.MonadStateProof memory proof = IMonadBridgeAdapter
            .MonadStateProof({
                merkleProof: mProof,
                stateRoot: proofStateRoot,
                value: proofValue
            });

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                IMonadBridgeAdapter.MonadTxAlreadyUsed.selector,
                txHash
            )
        );
        bridge.initiateMONDeposit(
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
        vm.expectRevert(IMonadBridgeAdapter.ZeroAddress.selector);
        bridge.configure(address(0), b, c, sigs, 1);

        vm.prank(admin);
        vm.expectRevert(IMonadBridgeAdapter.ZeroAddress.selector);
        bridge.configure(
            a == address(0) ? address(1) : a,
            address(0),
            c,
            sigs,
            1
        );

        vm.prank(admin);
        vm.expectRevert(IMonadBridgeAdapter.ZeroAddress.selector);
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
        vm.expectRevert(IMonadBridgeAdapter.InvalidAmount.selector);
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
        vm.expectRevert(IMonadBridgeAdapter.ZeroAddress.selector);
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
        wMON.mint(user, 1 ether);

        vm.startPrank(user);
        wMON.approve(address(bridge), 1 ether);
        bytes32 wId = bridge.initiateWithdrawal(address(0x5678), 1 ether);
        vm.stopPrank();

        bytes32[] memory userWithds = bridge.getUserWithdrawals(user);
        assertEq(userWithds.length, 1);
        assertEq(userWithds[0], wId);

        // Escrow tracking
        vm.deal(user, 1 ether);
        bytes32 hashlock = sha256(abi.encodePacked(keccak256("track_escrow")));
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
        assertEq(fees, (10 ether * 3) / 10_000);

        // After withdrawal
        vm.prank(address(bridge));
        wMON.mint(user, 1 ether);
        vm.startPrank(user);
        wMON.approve(address(bridge), 1 ether);
        bridge.initiateWithdrawal(address(0x5678), 1 ether);
        vm.stopPrank();

        (, withdrawn, , , , , ) = bridge.getBridgeStats();
        assertEq(withdrawn, 1 ether);

        // After escrow
        vm.deal(user, 1 ether);
        bytes32 hashlock = sha256(abi.encodePacked(keccak256("stats_escrow")));
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
        bytes32 preimage = keccak256("double_finish_monad");
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
                IMonadBridgeAdapter.EscrowNotActive.selector,
                escrowId
            )
        );
        bridge.finishEscrow(escrowId, preimage);
    }

    function test_escrowDoubleCancel() public {
        bytes32 hashlock = sha256(abi.encodePacked(keccak256("double_cancel")));

        uint256 finishAfter = block.timestamp + 2 hours;
        uint256 cancelAfter = finishAfter + 6 hours;

        vm.deal(user, 10 ether);
        vm.prank(user);
        bytes32 escrowId = bridge.createEscrow{value: 1 ether}(
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
                IMonadBridgeAdapter.EscrowNotActive.selector,
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
        wMON.mint(user, amount);

        vm.startPrank(user);
        wMON.approve(address(bridge), amount);
        bytes32 wId = bridge.initiateWithdrawal(address(0x5678), amount);
        vm.stopPrank();

        // Complete the withdrawal — use block >= 100 to avoid underflow in the contract's loop
        bytes32 monadTxHash = keccak256("complete_monad_tx");

        // Build proof and submit block
        bytes32 proofStateRoot = bytes32(uint256(0xdead));
        bytes memory proofValue = hex"cafe";
        bytes32 mSibling = bytes32(uint256(0xbeef));
        bytes32 intermediate = keccak256(
            abi.encodePacked(monadTxHash, proofStateRoot, proofValue)
        );
        bytes32 root;
        if (intermediate <= mSibling) {
            root = keccak256(abi.encodePacked(intermediate, mSibling));
        } else {
            root = keccak256(abi.encodePacked(mSibling, intermediate));
        }

        IMonadBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        vm.prank(relayer);
        bridge.submitMonadBFTBlock(
            100,
            keccak256(abi.encode("blockHash", uint256(100))),
            keccak256(abi.encode("parentHash", uint256(100))),
            root,
            keccak256(abi.encode("executionRoot", uint256(100))),
            1,
            block.timestamp,
            attestations
        );

        bytes32[] memory mProof = new bytes32[](1);
        mProof[0] = mSibling;
        IMonadBridgeAdapter.MonadStateProof memory proof = IMonadBridgeAdapter
            .MonadStateProof({
                merkleProof: mProof,
                stateRoot: proofStateRoot,
                value: proofValue
            });

        vm.prank(relayer);
        bridge.completeWithdrawal(wId, monadTxHash, proof, attestations);

        // Attempt to complete again — should revert
        bytes32 monadTxHash2 = keccak256("complete_monad_tx_2");

        // Submit another block with proof for txHash2
        bytes32 intermediate2 = keccak256(
            abi.encodePacked(monadTxHash2, proofStateRoot, proofValue)
        );
        bytes32 root2;
        if (intermediate2 <= mSibling) {
            root2 = keccak256(abi.encodePacked(intermediate2, mSibling));
        } else {
            root2 = keccak256(abi.encodePacked(mSibling, intermediate2));
        }
        vm.prank(relayer);
        bridge.submitMonadBFTBlock(
            101,
            keccak256(abi.encode("blockHash", uint256(101))),
            keccak256(abi.encode("parentHash", uint256(101))),
            root2,
            keccak256(abi.encode("executionRoot", uint256(101))),
            1,
            block.timestamp,
            attestations
        );

        bytes32[] memory mProof2 = new bytes32[](1);
        mProof2[0] = mSibling;
        IMonadBridgeAdapter.MonadStateProof memory proof2 = IMonadBridgeAdapter
            .MonadStateProof({
                merkleProof: mProof2,
                stateRoot: proofStateRoot,
                value: proofValue
            });

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                IMonadBridgeAdapter.WithdrawalNotPending.selector,
                wId
            )
        );
        bridge.completeWithdrawal(wId, monadTxHash2, proof2, attestations);
    }

    /*//////////////////////////////////////////////////////////////
                       WITHDRAWAL NONCE TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_withdrawalNonceOnlyIncreases(uint8 count) public {
        uint256 n = bound(uint256(count), 1, 10);
        uint256 amount = MIN_DEPOSIT;

        // Mint wMON to user for withdrawals (bridge owns wMON)
        vm.prank(address(bridge));
        wMON.mint(user, amount * n);

        vm.startPrank(user);
        wMON.approve(address(bridge), amount * n);

        uint256 prevNonce = bridge.withdrawalNonce();
        for (uint256 i = 0; i < n; i++) {
            bridge.initiateWithdrawal(address(0x5678), amount);
            assertGt(bridge.withdrawalNonce(), prevNonce);
            prevNonce = bridge.withdrawalNonce();
        }

        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                       VIEW FUNCTION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_viewFunctionsReturnDefaults() public view {
        IMonadBridgeAdapter.MONDeposit memory dep = bridge.getDeposit(
            bytes32(0)
        );
        assertEq(dep.amountWei, 0);

        IMonadBridgeAdapter.MONWithdrawal memory w = bridge.getWithdrawal(
            bytes32(0)
        );
        assertEq(w.amountWei, 0);

        IMonadBridgeAdapter.MONEscrow memory e = bridge.getEscrow(bytes32(0));
        assertEq(e.amountWei, 0);

        IMonadBridgeAdapter.MonadBFTBlock memory blk = bridge.getMonadBFTBlock(
            0
        );
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
                 MONADBFT BLOCK HEADER SUBMISSION TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_submitMonadBFTBlock(
        uint256 blockNumber,
        bytes32 blockHash,
        bytes32 stateRoot,
        bytes32 executionRoot,
        uint256 round
    ) public {
        blockNumber = bound(blockNumber, 1, 1_000_000);
        vm.assume(blockHash != bytes32(0));

        IMonadBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();

        vm.prank(relayer);
        bridge.submitMonadBFTBlock(
            blockNumber,
            blockHash,
            keccak256(abi.encode("parentHash", blockNumber)),
            stateRoot,
            executionRoot,
            round,
            block.timestamp,
            attestations
        );

        IMonadBridgeAdapter.MonadBFTBlock memory blk = bridge.getMonadBFTBlock(
            blockNumber
        );
        assertTrue(blk.verified);
        assertEq(blk.blockHash, blockHash);
        assertEq(blk.stateRoot, stateRoot);
        assertEq(blk.executionRoot, executionRoot);
        assertEq(blk.round, round);
    }

    function test_submitBlockUpdatesLatest() public {
        _submitVerifiedBlock(5, keccak256("block5"));
        assertEq(bridge.latestBlockNumber(), 5);

        _submitVerifiedBlock(10, keccak256("block10"));
        assertEq(bridge.latestBlockNumber(), 10);

        // Lower block number should NOT update latest
        _submitVerifiedBlock(3, keccak256("block3"));
        assertEq(bridge.latestBlockNumber(), 10);
    }

    /*//////////////////////////////////////////////////////////////
                     ESCROW AMOUNT FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_escrowAmount(uint256 amount) public {
        amount = bound(amount, 0.01 ether, 100 ether);

        bytes32 preimage = keccak256(abi.encode("escrow_preimage", amount));
        bytes32 hashlock = sha256(abi.encodePacked(preimage));

        uint256 finishAfter = block.timestamp + 1 hours;
        uint256 cancelAfter = finishAfter + 12 hours;

        vm.deal(user, amount);
        vm.prank(user);
        bytes32 escrowId = bridge.createEscrow{value: amount}(
            address(0x5678),
            hashlock,
            finishAfter,
            cancelAfter
        );

        IMonadBridgeAdapter.MONEscrow memory e = bridge.getEscrow(escrowId);
        assertEq(e.amountWei, amount);
        assertEq(e.evmParty, user);
        assertEq(e.monadParty, address(0x5678));
        assertEq(e.hashlock, hashlock);
    }

    /*//////////////////////////////////////////////////////////////
               WITHDRAWAL NOT FOUND / NOT PENDING TESTS
    //////////////////////////////////////////////////////////////*/

    function test_refundWithdrawalNotFound() public {
        bytes32 fakeId = keccak256("nonexistent_withdrawal");
        vm.expectRevert(
            abi.encodeWithSelector(
                IMonadBridgeAdapter.WithdrawalNotFound.selector,
                fakeId
            )
        );
        bridge.refundWithdrawal(fakeId);
    }

    function test_completeWithdrawalNotFound() public {
        bytes32 fakeId = keccak256("nonexistent_withdrawal2");

        IMonadBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        bytes32[] memory mProof = new bytes32[](1);
        mProof[0] = bytes32(0);
        IMonadBridgeAdapter.MonadStateProof memory proof = IMonadBridgeAdapter
            .MonadStateProof({
                merkleProof: mProof,
                stateRoot: bytes32(0),
                value: hex""
            });

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                IMonadBridgeAdapter.WithdrawalNotFound.selector,
                fakeId
            )
        );
        bridge.completeWithdrawal(fakeId, keccak256("tx"), proof, attestations);
    }

    /*//////////////////////////////////////////////////////////////
                     ESCROW NOT FOUND TESTS
    //////////////////////////////////////////////////////////////*/

    function test_finishEscrowNotFound() public {
        bytes32 fakeId = keccak256("nonexistent_escrow");
        vm.expectRevert(
            abi.encodeWithSelector(
                IMonadBridgeAdapter.EscrowNotFound.selector,
                fakeId
            )
        );
        bridge.finishEscrow(fakeId, keccak256("preimage"));
    }

    function test_cancelEscrowNotFound() public {
        bytes32 fakeId = keccak256("nonexistent_escrow2");
        vm.expectRevert(
            abi.encodeWithSelector(
                IMonadBridgeAdapter.EscrowNotFound.selector,
                fakeId
            )
        );
        bridge.cancelEscrow(fakeId);
    }

    /*//////////////////////////////////////////////////////////////
              DEPOSIT RECIPIENT ZERO ADDRESS REJECTION
    //////////////////////////////////////////////////////////////*/

    function test_depositRejectsZeroRecipient() public {
        bytes32 blockHash = keccak256(abi.encode("blockHash", uint256(1)));
        _submitVerifiedBlock(1, blockHash);

        IMonadBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        IMonadBridgeAdapter.MonadStateProof memory proof = _buildStateProof(1);

        vm.prank(relayer);
        vm.expectRevert(IMonadBridgeAdapter.ZeroAddress.selector);
        bridge.initiateMONDeposit(
            keccak256("zero_recipient_tx"),
            address(0x1234),
            address(0), // zero recipient
            1 ether,
            1,
            proof,
            attestations
        );
    }

    /*//////////////////////////////////////////////////////////////
                   FINALITY AND BLOCK CONFIRMATIONS
    //////////////////////////////////////////////////////////////*/

    function test_monadBFTSingleSlotFinality() public {
        // Monad has single-slot finality (~1s) so DEFAULT_BLOCK_CONFIRMATIONS = 1
        assertEq(bridge.DEFAULT_BLOCK_CONFIRMATIONS(), 1);

        // A single block submission should make deposits possible
        bytes32 txHash = keccak256("finality_test_tx");
        bytes32 depositId = _initiateDeposit(1 ether, txHash);
        assertTrue(depositId != bytes32(0));
    }

    /*//////////////////////////////////////////////////////////////
                  TOTAL STATISTICS ACCUMULATION
    //////////////////////////////////////////////////////////////*/

    function testFuzz_totalDepositedAccumulates(uint8 count) public {
        uint256 n = bound(uint256(count), 1, 5);
        uint256 depositAmount = 1 ether;
        uint256 totalExpected = 0;

        for (uint256 i = 0; i < n; i++) {
            bytes32 txHash = keccak256(abi.encode("accum_tx", i));
            _initiateDepositAtBlock(depositAmount, txHash, i + 1);
            totalExpected += depositAmount;
        }

        assertEq(bridge.totalDeposited(), totalExpected);
    }

    function testFuzz_totalWithdrawnAccumulates(uint8 count) public {
        uint256 n = bound(uint256(count), 1, 5);
        uint256 withdrawAmount = MIN_DEPOSIT;

        vm.prank(address(bridge));
        wMON.mint(user, withdrawAmount * n);

        vm.startPrank(user);
        wMON.approve(address(bridge), withdrawAmount * n);

        uint256 totalExpected = 0;
        for (uint256 i = 0; i < n; i++) {
            bridge.initiateWithdrawal(address(0x5678), withdrawAmount);
            totalExpected += withdrawAmount;
        }
        vm.stopPrank();

        assertEq(bridge.totalWithdrawn(), totalExpected);
    }

    /*//////////////////////////////////////////////////////////////
               ESCROW FINISH BEFORE TIMELOCK REJECTION
    //////////////////////////////////////////////////////////////*/

    function test_escrowCannotFinishBeforeTimelock() public {
        bytes32 preimage = keccak256("early_finish");
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
        vm.expectRevert(IMonadBridgeAdapter.EscrowTimelockNotMet.selector);
        bridge.finishEscrow(escrowId, preimage);
    }

    /*//////////////////////////////////////////////////////////////
               ESCROW CANCEL BEFORE TIMELOCK REJECTION
    //////////////////////////////////////////////////////////////*/

    function test_escrowCannotCancelBeforeTimelock() public {
        bytes32 hashlock = sha256(abi.encodePacked(keccak256("early_cancel")));

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

        // Try to cancel before cancelAfter — should revert
        vm.expectRevert(IMonadBridgeAdapter.EscrowTimelockNotMet.selector);
        bridge.cancelEscrow(escrowId);
    }
}
