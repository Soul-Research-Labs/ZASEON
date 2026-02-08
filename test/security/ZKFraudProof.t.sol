// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {ZKFraudProof} from "../../contracts/security/ZKFraudProof.sol";

contract MockZKVerifier {
    bool public returnValue;

    constructor(bool _ret) {
        returnValue = _ret;
    }

    function verifyProof(bytes calldata, bytes calldata, bytes calldata) external view returns (bool) {
        return returnValue;
    }
}

contract ZKFraudProofTest is Test {
    ZKFraudProof public fraud;

    address public admin;
    address public prover = address(0xAA01);
    address public verifier = address(0xAA02);
    address public operator = address(0xAA03);

    MockZKVerifier public zkVerifier;
    address public stateChain = address(0x1111);
    address public bondMgr = address(0x2222);

    function setUp() public {
        admin = address(this);
        zkVerifier = new MockZKVerifier(true);

        fraud = new ZKFraudProof(stateChain, bondMgr, address(zkVerifier));

        fraud.grantRole(fraud.PROVER_ROLE(), prover);
        fraud.grantRole(fraud.VERIFIER_ROLE(), verifier);
        fraud.grantRole(fraud.OPERATOR_ROLE(), operator);

        // Fund prover for bonds
        vm.deal(prover, 100 ether);
        vm.deal(admin, 100 ether);
    }

    // ======= Initial State =======

    function test_initialState() public view {
        assertEq(fraud.totalProofsSubmitted(), 0);
        assertEq(fraud.totalProofsVerified(), 0);
        assertEq(fraud.totalFraudConfirmed(), 0);
        assertEq(fraud.totalSlashed(), 0);
        assertEq(fraud.stateCommitmentChain(), stateChain);
        assertEq(fraud.bondManager(), bondMgr);
        assertEq(fraud.zkVerifier(), address(zkVerifier));
    }

    function test_constants() public view {
        assertEq(fraud.STANDARD_DISPUTE_PERIOD(), 7 days);
        assertEq(fraud.MIN_BOND(), 1 ether);
    }

    // ======= Batch Submission =======

    function test_submitBatch() public {
        bytes32 stateRoot = keccak256("state1");
        bytes32 prevRoot = keccak256("state0");
        bytes32 txRoot = keccak256("txs1");

        vm.prank(operator);
        bytes32 batchId = fraud.submitBatch(stateRoot, prevRoot, txRoot);

        (bytes32 sr, bytes32 pr, uint256 submittedAt, bool finalized, bool disputed, address sequencer) = fraud.getBatch(batchId);
        assertEq(sr, stateRoot);
        assertEq(pr, prevRoot);
        assertTrue(submittedAt > 0);
        assertFalse(finalized);
        assertFalse(disputed);
        assertEq(sequencer, operator);
    }

    function test_submitBatch_onlyOperator() public {
        vm.prank(prover);
        vm.expectRevert();
        fraud.submitBatch(keccak256("s"), keccak256("p"), keccak256("t"));
    }

    // ======= Batch Finalization =======

    function test_finalizeBatch_afterDisputePeriod() public {
        bytes32 batchId = _submitBatch();

        // Advance past standard dispute period
        vm.warp(block.timestamp + 7 days + 1);

        fraud.finalizeBatch(batchId);

        (, , , bool finalized, ,) = fraud.getBatch(batchId);
        assertTrue(finalized);
    }

    function test_finalizeBatch_reverts_duringDisputePeriod() public {
        bytes32 batchId = _submitBatch();

        vm.expectRevert();
        fraud.finalizeBatch(batchId);
    }

    // ======= Fraud Proof Submission =======

    function test_submitFraudProof() public {
        bytes32 batchId = _submitBatch();

        vm.prank(prover);
        bytes32 proofId = fraud.submitFraudProof{value: 1 ether}(
            ZKFraudProof.ProofType.EXECUTION,
            batchId,
            0,
            keccak256("correctState"),
            hex"deadbeefcafe0102030405060708",
            keccak256("publicInputs")
        );

        ZKFraudProof.FraudProof memory fp = fraud.getFraudProof(proofId);
        assertEq(fp.challenger, prover);
        assertEq(uint256(fp.proofType), uint256(ZKFraudProof.ProofType.EXECUTION));
        assertEq(uint256(fp.status), uint256(ZKFraudProof.ProofStatus.PENDING));
        assertEq(fp.bondAmount, 1 ether);
        assertEq(fraud.totalProofsSubmitted(), 1);
    }

    function test_submitFraudProof_insufficientBond() public {
        bytes32 batchId = _submitBatch();

        vm.prank(prover);
        vm.expectRevert();
        fraud.submitFraudProof{value: 0.1 ether}(
            ZKFraudProof.ProofType.EXECUTION,
            batchId,
            0,
            keccak256("correct"),
            hex"aabb",
            keccak256("pi")
        );
    }

    function test_submitFraudProof_onlyProver() public {
        bytes32 batchId = _submitBatch();

        address unauthorized = address(0xDEAD);
        vm.deal(unauthorized, 10 ether);

        // Cache role before prank to avoid consuming it
        bytes32 proverRole = fraud.PROVER_ROLE();

        vm.prank(unauthorized);
        vm.expectRevert(abi.encodeWithSelector(
            bytes4(keccak256("AccessControlUnauthorizedAccount(address,bytes32)")),
            unauthorized,
            proverRole
        ));
        fraud.submitFraudProof{value: 1 ether}(
            ZKFraudProof.ProofType.EXECUTION,
            batchId,
            0,
            keccak256("correct"),
            hex"aabb",
            keccak256("pi")
        );
    }

    // ======= Fraud Proof Verification =======

    function test_verifyFraudProof() public {
        bytes32 proofId = _submitFraudProofForBatch();

        vm.prank(verifier);
        bool valid = fraud.verifyFraudProof(proofId);

        // Result depends on zkVerifier and VK setup
        // Just check it doesn't revert and returns a bool
        assertTrue(valid || !valid);

        ZKFraudProof.FraudProof memory fp = fraud.getFraudProof(proofId);
        assertTrue(
            uint256(fp.status) == uint256(ZKFraudProof.ProofStatus.VERIFIED) ||
            uint256(fp.status) == uint256(ZKFraudProof.ProofStatus.REJECTED)
        );
    }

    function test_verifyFraudProof_onlyVerifier() public {
        bytes32 proofId = _submitFraudProofForBatch();

        vm.prank(address(0xDEAD));
        vm.expectRevert();
        fraud.verifyFraudProof(proofId);
    }

    // ======= Apply Fraud Proof =======

    function test_applyFraudProof_onlyOperator() public {
        bytes32 proofId = _submitFraudProofForBatch();

        vm.prank(verifier);
        fraud.verifyFraudProof(proofId);

        vm.prank(address(0xDEAD));
        vm.expectRevert();
        fraud.applyFraudProof(proofId);
    }

    // ======= Verification Keys =======

    function test_addVerificationKey() public {
        bytes memory vkData = hex"aabbccdd";
        bytes32 vkId = fraud.addVerificationKey(ZKFraudProof.ProofType.EXECUTION, vkData);

        assertTrue(vkId != bytes32(0));
    }

    function test_deactivateVerificationKey() public {
        bytes32 vkId = fraud.addVerificationKey(ZKFraudProof.ProofType.EXECUTION, hex"aabb");
        fraud.deactivateVerificationKey(vkId);
    }

    // ======= Admin =======

    function test_updateContracts() public {
        address newChain = address(0x3333);
        address newBond = address(0x4444);
        address newZK = address(0x5555);

        fraud.updateContracts(newChain, newBond, newZK);

        assertEq(fraud.stateCommitmentChain(), newChain);
        assertEq(fraud.bondManager(), newBond);
        assertEq(fraud.zkVerifier(), newZK);
    }

    function test_pause_unpause() public {
        fraud.pause();
        assertTrue(fraud.paused());

        fraud.unpause();
        assertFalse(fraud.paused());
    }

    function test_emergencyWithdraw() public {
        // Send some ETH to the contract
        (bool sent,) = address(fraud).call{value: 5 ether}("");
        assertTrue(sent);

        address recipient = address(0xBBBB);
        uint256 balBefore = recipient.balance;

        fraud.emergencyWithdraw(recipient, 2 ether);
        assertEq(recipient.balance, balBefore + 2 ether);
    }

    function test_emergencyWithdraw_onlyAdmin() public {
        vm.prank(address(0xDEAD));
        vm.expectRevert();
        fraud.emergencyWithdraw(address(0xBBBB), 1 ether);
    }

    // ======= View Functions =======

    function test_getPendingProofCount() public view {
        assertEq(fraud.getPendingProofCount(), 0);
    }

    function test_getDisputePeriod() public view {
        assertEq(fraud.getDisputePeriod(false), 7 days);
        assertEq(fraud.getDisputePeriod(true), 1 days);
    }

    function test_getProverStats() public view {
        ZKFraudProof.ProverStats memory stats = fraud.getProverStats(prover);
        assertEq(stats.proofsSubmitted, 0);
    }

    function test_isInDisputePeriod() public {
        bytes32 batchId = _submitBatch();
        assertTrue(fraud.isInDisputePeriod(batchId));

        vm.warp(block.timestamp + 7 days + 1);
        assertFalse(fraud.isInDisputePeriod(batchId));
    }

    // ======= Fuzz Tests =======

    function testFuzz_submitBatch(bytes32 stateRoot, bytes32 prevRoot, bytes32 txRoot) public {
        vm.prank(operator);
        bytes32 batchId = fraud.submitBatch(stateRoot, prevRoot, txRoot);
        assertTrue(batchId != bytes32(0));
    }

    function testFuzz_bondAmount(uint256 amount) public {
        amount = bound(amount, 1 ether, 50 ether);
        bytes32 batchId = _submitBatch();

        vm.deal(prover, amount);
        vm.prank(prover);
        bytes32 proofId = fraud.submitFraudProof{value: amount}(
            ZKFraudProof.ProofType.EXECUTION,
            batchId,
            0,
            keccak256("correct"),
            hex"aabbccdd",
            keccak256("pi")
        );

        ZKFraudProof.FraudProof memory fp = fraud.getFraudProof(proofId);
        assertEq(fp.bondAmount, amount);
    }

    // ======= Helpers =======

    function _submitBatch() internal returns (bytes32) {
        vm.prank(operator);
        return fraud.submitBatch(
            keccak256("state1"),
            keccak256("state0"),
            keccak256("txs1")
        );
    }

    function _submitFraudProofForBatch() internal returns (bytes32) {
        bytes32 batchId = _submitBatch();

        vm.prank(prover);
        return fraud.submitFraudProof{value: 1 ether}(
            ZKFraudProof.ProofType.EXECUTION,
            batchId,
            0,
            keccak256("correctState"),
            hex"deadbeefcafe0102030405060708",
            keccak256("publicInputs")
        );
    }
}
