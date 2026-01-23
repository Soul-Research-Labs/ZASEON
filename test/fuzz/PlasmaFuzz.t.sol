// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/plasma/PlasmaPrimitives.sol";
import "../../contracts/crosschain/PlasmaBridgeAdapter.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/**
 * @title PlasmaFuzz
 * @notice Comprehensive fuzz tests for Plasma Layer 2 integration
 * @dev Tests UTXO model, Merkle proofs, exit games, and cross-domain nullifiers
 */
contract PlasmaFuzz is Test {
    using PlasmaPrimitives for *;

    PlasmaBridgeAdapter public bridge;

    address public admin = address(0x1);
    address public operator = address(0x2);
    address public user1 = address(0x3);
    address public user2 = address(0x4);
    address public emergencyCouncil = address(0x911);

    uint256 public userPrivateKey = 0xBEEF;
    address public userWithKey;

    function setUp() public {
        userWithKey = vm.addr(userPrivateKey);

        vm.startPrank(admin);

        // Deploy implementation
        PlasmaBridgeAdapter implementation = new PlasmaBridgeAdapter();

        // Deploy proxy
        bytes memory initData = abi.encodeWithSelector(
            PlasmaBridgeAdapter.initialize.selector,
            admin,
            emergencyCouncil
        );
        ERC1967Proxy proxy = new ERC1967Proxy(
            address(implementation),
            initData
        );
        bridge = PlasmaBridgeAdapter(payable(address(proxy)));

        // Setup roles
        bridge.grantRole(bridge.OPERATOR_ROLE(), operator);

        vm.stopPrank();

        // Fund accounts
        vm.deal(user1, 1000 ether);
        vm.deal(user2, 1000 ether);
        vm.deal(userWithKey, 1000 ether);
        vm.deal(address(bridge), 10000 ether);
    }

    // =========================================================================
    // PRIMITIVE FUZZ TESTS - HASH FUNCTIONS
    // =========================================================================

    function testFuzz_KeccakHashDeterminism(bytes memory data) public pure {
        bytes32 hash1 = PlasmaPrimitives.keccakHash(data);
        bytes32 hash2 = PlasmaPrimitives.keccakHash(data);
        assertEq(hash1, hash2, "Keccak hash not deterministic");
    }

    function testFuzz_KeccakHashUniqueness(
        bytes memory data1,
        bytes memory data2
    ) public pure {
        vm.assume(keccak256(data1) != keccak256(data2));
        bytes32 hash1 = PlasmaPrimitives.keccakHash(data1);
        bytes32 hash2 = PlasmaPrimitives.keccakHash(data2);
        assertNotEq(hash1, hash2, "Different data produced same hash");
    }

    function testFuzz_Hash2Determinism(
        bytes32 left,
        bytes32 right
    ) public pure {
        bytes32 hash1 = PlasmaPrimitives.hash2(left, right);
        bytes32 hash2 = PlasmaPrimitives.hash2(left, right);
        assertEq(hash1, hash2, "Hash2 not deterministic");
    }

    function testFuzz_Hash2NonCommutative(
        bytes32 left,
        bytes32 right
    ) public pure {
        vm.assume(left != right);
        bytes32 hash1 = PlasmaPrimitives.hash2(left, right);
        bytes32 hash2 = PlasmaPrimitives.hash2(right, left);
        assertNotEq(hash1, hash2, "Hash2 should not be commutative");
    }

    function testFuzz_HashNDeterminism(bytes32[] memory inputs) public pure {
        vm.assume(inputs.length > 0 && inputs.length <= 10);
        bytes32 hash1 = PlasmaPrimitives.hashN(inputs);
        bytes32 hash2 = PlasmaPrimitives.hashN(inputs);
        assertEq(hash1, hash2, "HashN not deterministic");
    }

    function testFuzz_HashNSingle(bytes32 input) public pure {
        bytes32[] memory inputs = new bytes32[](1);
        inputs[0] = input;
        bytes32 result = PlasmaPrimitives.hashN(inputs);
        assertEq(result, input, "Single element should return itself");
    }

    function test_HashNEmpty() public pure {
        bytes32[] memory empty = new bytes32[](0);
        bytes32 result = PlasmaPrimitives.hashN(empty);
        assertEq(result, bytes32(0), "Empty hash should be zero");
    }

    // =========================================================================
    // PRIMITIVE FUZZ TESTS - UTXO POSITION
    // =========================================================================

    function testFuzz_UTXOPositionEncoding(
        uint256 blockNum,
        uint256 txIndex,
        uint256 outputIndex
    ) public pure {
        blockNum = bound(blockNum, 1, type(uint64).max);
        txIndex = bound(
            txIndex,
            0,
            PlasmaPrimitives.MAX_TRANSACTIONS_PER_BLOCK - 1
        );
        outputIndex = bound(outputIndex, 0, PlasmaPrimitives.MAX_OUTPUTS - 1);

        uint256 encoded = PlasmaPrimitives.encodeUTXOPosition(
            blockNum,
            txIndex,
            outputIndex
        );
        (
            uint256 decodedBlock,
            uint256 decodedTx,
            uint256 decodedOutput
        ) = PlasmaPrimitives.decodeUTXOPosition(encoded);

        assertEq(decodedBlock, blockNum, "Block number mismatch");
        assertEq(decodedTx, txIndex, "Tx index mismatch");
        assertEq(decodedOutput, outputIndex, "Output index mismatch");
    }

    function testFuzz_UTXOPositionStruct(uint256 pos) public pure {
        pos = bound(pos, 1, type(uint128).max);

        PlasmaPrimitives.UTXOPosition memory utxo = PlasmaPrimitives
            .toUTXOPosition(pos);
        (
            uint256 blockNum,
            uint256 txIndex,
            uint256 outputIndex
        ) = PlasmaPrimitives.decodeUTXOPosition(pos);

        assertEq(utxo.blockNum, blockNum, "Block number mismatch");
        assertEq(utxo.txIndex, txIndex, "Tx index mismatch");
        assertEq(utxo.outputIndex, outputIndex, "Output index mismatch");
    }

    function testFuzz_UTXOPositionValidation(
        uint256 blockNum,
        uint256 txIndex,
        uint256 outputIndex
    ) public pure {
        blockNum = bound(blockNum, 0, type(uint64).max);
        txIndex = bound(txIndex, 0, type(uint32).max);
        outputIndex = bound(outputIndex, 0, type(uint16).max);

        uint256 encoded = blockNum * 10 ** 9 + txIndex * 10 ** 4 + outputIndex;
        bool valid = PlasmaPrimitives.isValidUTXOPosition(encoded);

        bool expected = blockNum > 0 &&
            txIndex < PlasmaPrimitives.MAX_TRANSACTIONS_PER_BLOCK &&
            outputIndex < PlasmaPrimitives.MAX_OUTPUTS;

        assertEq(valid, expected, "UTXO validation mismatch");
    }

    // =========================================================================
    // PRIMITIVE FUZZ TESTS - MERKLE TREE
    // =========================================================================

    function testFuzz_MerkleRootSingleLeaf(bytes32 leaf) public pure {
        bytes32[] memory leaves = new bytes32[](1);
        leaves[0] = leaf;
        bytes32 root = PlasmaPrimitives.computeMerkleRoot(leaves);
        assertEq(root, leaf, "Single leaf should be root");
    }

    function testFuzz_MerkleRootTwoLeaves(
        bytes32 leaf1,
        bytes32 leaf2
    ) public pure {
        bytes32[] memory leaves = new bytes32[](2);
        leaves[0] = leaf1;
        leaves[1] = leaf2;

        bytes32 root = PlasmaPrimitives.computeMerkleRoot(leaves);
        bytes32 expected = PlasmaPrimitives.hash2(leaf1, leaf2);

        assertEq(root, expected, "Two leaves should hash together");
    }

    function testFuzz_MerkleRootDeterminism(
        bytes32 leaf1,
        bytes32 leaf2,
        bytes32 leaf3,
        bytes32 leaf4
    ) public pure {
        bytes32[] memory leaves = new bytes32[](4);
        leaves[0] = leaf1;
        leaves[1] = leaf2;
        leaves[2] = leaf3;
        leaves[3] = leaf4;

        bytes32 root1 = PlasmaPrimitives.computeMerkleRoot(leaves);
        bytes32 root2 = PlasmaPrimitives.computeMerkleRoot(leaves);

        assertEq(root1, root2, "Merkle root not deterministic");
    }

    function testFuzz_MerkleProofVerification(
        bytes32 leaf,
        bytes32[16] memory siblings,
        uint256 index
    ) public pure {
        index = bound(index, 0, (1 << 16) - 1);

        bytes32[] memory siblingArray = new bytes32[](16);
        for (uint256 i = 0; i < 16; i++) {
            siblingArray[i] = siblings[i];
        }

        PlasmaPrimitives.MerkleProof memory proof = PlasmaPrimitives
            .MerkleProof({siblings: siblingArray, index: index});

        bytes32 computedRoot = PlasmaPrimitives.computeMerkleRootFromProof(
            leaf,
            proof
        );
        bool verified = PlasmaPrimitives.verifyMerkleProof(
            leaf,
            proof,
            computedRoot
        );

        assertTrue(verified, "Proof should verify against computed root");
    }

    function test_EmptyMerkleRoot() public pure {
        bytes32[] memory empty = new bytes32[](0);
        bytes32 root = PlasmaPrimitives.computeMerkleRoot(empty);
        assertEq(root, bytes32(0), "Empty tree should have zero root");
    }

    // =========================================================================
    // PRIMITIVE FUZZ TESTS - EXIT PRIORITY
    // =========================================================================

    function testFuzz_ExitPriorityEncoding(
        uint256 exitableAt,
        uint256 utxoPos
    ) public pure {
        exitableAt = bound(exitableAt, 0, type(uint128).max);
        utxoPos = bound(
            utxoPos,
            0,
            PlasmaPrimitives.EXIT_PRIORITY_DENOMINATOR - 1
        );

        uint256 priority = PlasmaPrimitives.computeExitPriority(
            exitableAt,
            utxoPos
        );
        (uint256 decodedExitableAt, uint256 decodedUtxoPos) = PlasmaPrimitives
            .decodeExitPriority(priority);

        assertEq(decodedExitableAt, exitableAt, "ExitableAt mismatch");
        assertEq(decodedUtxoPos, utxoPos, "UTXO position mismatch");
    }

    function testFuzz_ExitPriorityOrdering(
        uint256 time1,
        uint256 time2,
        uint256 pos1,
        uint256 pos2
    ) public pure {
        time1 = bound(time1, 0, type(uint64).max);
        time2 = bound(time2, 0, type(uint64).max);
        pos1 = bound(pos1, 0, 10 ** 18 - 1);
        pos2 = bound(pos2, 0, 10 ** 18 - 1);

        uint256 priority1 = PlasmaPrimitives.computeExitPriority(time1, pos1);
        uint256 priority2 = PlasmaPrimitives.computeExitPriority(time2, pos2);

        if (time1 < time2) {
            assertTrue(
                priority1 < priority2,
                "Earlier time should have lower priority"
            );
        } else if (time1 > time2) {
            assertTrue(
                priority1 > priority2,
                "Later time should have higher priority"
            );
        }
    }

    function testFuzz_ExitableAtComputation(
        uint256 submissionTime
    ) public pure {
        submissionTime = bound(submissionTime, 0, type(uint128).max);

        uint256 exitableAt = PlasmaPrimitives.computeExitableAt(submissionTime);
        assertEq(
            exitableAt,
            submissionTime + PlasmaPrimitives.CHALLENGE_PERIOD,
            "ExitableAt calculation wrong"
        );
    }

    // =========================================================================
    // PRIMITIVE FUZZ TESTS - NULLIFIER
    // =========================================================================

    function testFuzz_NullifierDerivation(
        bytes32 txHash,
        uint256 blockNumber,
        uint256 outputIndex
    ) public pure {
        blockNumber = bound(blockNumber, 1, type(uint64).max);
        outputIndex = bound(outputIndex, 0, PlasmaPrimitives.MAX_OUTPUTS - 1);

        bytes32 nf1 = PlasmaPrimitives.deriveNullifier(
            txHash,
            blockNumber,
            outputIndex
        );
        bytes32 nf2 = PlasmaPrimitives.deriveNullifier(
            txHash,
            blockNumber,
            outputIndex
        );

        assertEq(nf1, nf2, "Nullifier derivation not deterministic");
    }

    function testFuzz_NullifierUniqueness(
        bytes32 txHash1,
        bytes32 txHash2,
        uint256 blockNumber
    ) public pure {
        vm.assume(txHash1 != txHash2);
        blockNumber = bound(blockNumber, 1, type(uint64).max);

        bytes32 nf1 = PlasmaPrimitives.deriveNullifier(txHash1, blockNumber, 0);
        bytes32 nf2 = PlasmaPrimitives.deriveNullifier(txHash2, blockNumber, 0);

        assertNotEq(
            nf1,
            nf2,
            "Different txHash should produce different nullifiers"
        );
    }

    function testFuzz_CrossDomainNullifier(
        bytes32 plasmaNullifier,
        uint256 sourceChain,
        uint256 targetChain
    ) public pure {
        vm.assume(sourceChain != targetChain);

        bytes32 crossNf1 = PlasmaPrimitives.deriveCrossDomainNullifier(
            plasmaNullifier,
            sourceChain,
            targetChain
        );
        bytes32 crossNf2 = PlasmaPrimitives.deriveCrossDomainNullifier(
            plasmaNullifier,
            sourceChain,
            targetChain
        );

        assertEq(
            crossNf1,
            crossNf2,
            "Cross-domain nullifier not deterministic"
        );
    }

    function testFuzz_CrossDomainNullifierDirectionMatters(
        bytes32 plasmaNullifier,
        uint256 sourceChain,
        uint256 targetChain
    ) public pure {
        vm.assume(sourceChain != targetChain);
        vm.assume(sourceChain > 0 && targetChain > 0);

        bytes32 forward = PlasmaPrimitives.deriveCrossDomainNullifier(
            plasmaNullifier,
            sourceChain,
            targetChain
        );
        bytes32 backward = PlasmaPrimitives.deriveCrossDomainNullifier(
            plasmaNullifier,
            targetChain,
            sourceChain
        );

        assertNotEq(forward, backward, "Direction should matter");
    }

    function testFuzz_PILBinding(bytes32 plasmaNullifier) public pure {
        bytes32 binding1 = PlasmaPrimitives.derivePILBinding(plasmaNullifier);
        bytes32 binding2 = PlasmaPrimitives.derivePILBinding(plasmaNullifier);

        assertEq(binding1, binding2, "PIL binding not deterministic");
    }

    function testFuzz_PILBindingUniqueness(
        bytes32 nf1,
        bytes32 nf2
    ) public pure {
        vm.assume(nf1 != nf2);

        bytes32 binding1 = PlasmaPrimitives.derivePILBinding(nf1);
        bytes32 binding2 = PlasmaPrimitives.derivePILBinding(nf2);

        assertNotEq(
            binding1,
            binding2,
            "Different nullifiers should have different bindings"
        );
    }

    // =========================================================================
    // PRIMITIVE FUZZ TESTS - SIGNATURES
    // =========================================================================

    function testFuzz_SignatureRecovery(bytes32 messageHash) public view {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(userPrivateKey, messageHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        address recovered = PlasmaPrimitives.recoverSigner(
            messageHash,
            signature
        );
        assertEq(recovered, userWithKey, "Signature recovery failed");
    }

    function testFuzz_SignatureVerification(bytes32 messageHash) public view {
        bytes32 prefixedHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(userPrivateKey, prefixedHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        bool valid = PlasmaPrimitives.verifySignature(
            messageHash,
            signature,
            userWithKey
        );
        assertTrue(valid, "Signature verification failed");
    }

    function testFuzz_InvalidSignatureLength(
        bytes memory signature
    ) public pure {
        vm.assume(signature.length != 65);

        address recovered = PlasmaPrimitives.recoverSigner(
            bytes32(0),
            signature
        );
        assertEq(
            recovered,
            address(0),
            "Invalid signature should return zero address"
        );
    }

    // =========================================================================
    // PRIMITIVE FUZZ TESTS - VALIDATION
    // =========================================================================

    function testFuzz_ExitValidation(
        address owner,
        uint256 amount,
        uint256 utxoPos,
        uint256 bondAmount
    ) public view {
        amount = bound(amount, 0, type(uint128).max);
        bondAmount = bound(bondAmount, 0, type(uint128).max);

        PlasmaPrimitives.Exit memory exit = PlasmaPrimitives.Exit({
            owner: owner,
            token: address(0),
            amount: amount,
            utxoPos: utxoPos,
            exitableAt: block.timestamp + 7 days,
            bondAmount: bondAmount,
            status: PlasmaPrimitives.ExitStatus.IN_PROGRESS
        });

        bool valid = PlasmaPrimitives.isValidExit(exit);
        bool expected = owner != address(0) &&
            amount > 0 &&
            utxoPos > 0 &&
            bondAmount >= PlasmaPrimitives.MIN_EXIT_BOND;

        assertEq(valid, expected, "Exit validation mismatch");
    }

    function testFuzz_ExitFinalization(
        uint256 exitableAt,
        uint256 currentTime
    ) public pure {
        exitableAt = bound(exitableAt, 0, type(uint128).max);
        currentTime = bound(currentTime, 0, type(uint128).max);

        PlasmaPrimitives.Exit memory exit = PlasmaPrimitives.Exit({
            owner: address(0x1),
            token: address(0),
            amount: 1 ether,
            utxoPos: 1,
            exitableAt: exitableAt,
            bondAmount: 0.1 ether,
            status: PlasmaPrimitives.ExitStatus.IN_PROGRESS
        });

        bool finalized = PlasmaPrimitives.isExitFinalized(exit, currentTime);
        bool expected = currentTime >= exitableAt;

        assertEq(finalized, expected, "Exit finalization check mismatch");
    }

    function testFuzz_ExitChallengeable(
        uint256 exitableAt,
        uint256 currentTime
    ) public pure {
        exitableAt = bound(exitableAt, 1, type(uint128).max);
        currentTime = bound(currentTime, 0, type(uint128).max);

        PlasmaPrimitives.Exit memory exit = PlasmaPrimitives.Exit({
            owner: address(0x1),
            token: address(0),
            amount: 1 ether,
            utxoPos: 1,
            exitableAt: exitableAt,
            bondAmount: 0.1 ether,
            status: PlasmaPrimitives.ExitStatus.IN_PROGRESS
        });

        bool challengeable = PlasmaPrimitives.isExitChallengeable(
            exit,
            currentTime
        );
        bool expected = currentTime < exitableAt;

        assertEq(challengeable, expected, "Exit challengeable check mismatch");
    }

    function testFuzz_BlockValidation(
        bytes32 root,
        uint256 timestamp,
        uint256 blockNumber,
        address operatorAddr
    ) public pure {
        PlasmaPrimitives.PlasmaBlock memory plasmaBlock = PlasmaPrimitives
            .PlasmaBlock({
                root: root,
                timestamp: timestamp,
                blockNumber: blockNumber,
                operator: operatorAddr,
                numTransactions: 1
            });

        bool valid = PlasmaPrimitives.isValidBlock(plasmaBlock);
        bool expected = root != bytes32(0) &&
            timestamp > 0 &&
            blockNumber > 0 &&
            operatorAddr != address(0);

        assertEq(valid, expected, "Block validation mismatch");
    }

    // =========================================================================
    // PRIMITIVE FUZZ TESTS - CHAIN DETECTION
    // =========================================================================

    function testFuzz_PlasmaChainDetection(uint256 chainId) public pure {
        bool isPlasma = PlasmaPrimitives.isPlasmaChain(chainId);
        bool expected = chainId == 1 || chainId == 137 || chainId == 80001;
        assertEq(isPlasma, expected, "Chain detection mismatch");
    }

    function test_KnownPlasmaChains() public pure {
        assertTrue(PlasmaPrimitives.isPlasmaChain(1), "Ethereum mainnet");
        assertTrue(PlasmaPrimitives.isPlasmaChain(137), "Polygon mainnet");
        assertTrue(PlasmaPrimitives.isPlasmaChain(80001), "Polygon testnet");
        assertFalse(PlasmaPrimitives.isPlasmaChain(56), "BSC is not Plasma");
    }

    // =========================================================================
    // BRIDGE ADAPTER FUZZ TESTS - DEPOSITS
    // =========================================================================

    function testFuzz_Deposit(uint256 amount) public {
        amount = bound(amount, 1, bridge.MAX_TRANSFER());

        bytes32 commitment = keccak256(
            abi.encodePacked("commitment", amount, block.timestamp)
        );

        vm.prank(user1);
        bridge.deposit{value: amount}(commitment);

        PlasmaPrimitives.Deposit memory dep = bridge.getDeposit(commitment);
        assertEq(dep.depositor, user1, "Depositor mismatch");
        assertEq(dep.amount, amount, "Amount mismatch");
    }

    function testFuzz_DepositRevertsZeroAmount() public {
        bytes32 commitment = keccak256("test");

        vm.prank(user1);
        vm.expectRevert(PlasmaBridgeAdapter.InvalidAmount.selector);
        bridge.deposit{value: 0}(commitment);
    }

    function testFuzz_DepositRevertsExceedsMax(uint256 seed) public {
        uint256 amount = bound(
            seed,
            bridge.MAX_TRANSFER() + 1,
            bridge.MAX_TRANSFER() + 100 ether
        );

        bytes32 commitment = keccak256(abi.encodePacked("commitment", amount));

        vm.deal(user1, amount);
        vm.prank(user1);
        vm.expectRevert(PlasmaBridgeAdapter.ExceedsMaxTransfer.selector);
        bridge.deposit{value: amount}(commitment);
    }

    function testFuzz_DepositRevertsZeroCommitment() public {
        vm.prank(user1);
        vm.expectRevert(PlasmaBridgeAdapter.InvalidTransaction.selector);
        bridge.deposit{value: 1 ether}(bytes32(0));
    }

    // =========================================================================
    // BRIDGE ADAPTER FUZZ TESTS - BLOCK SUBMISSION
    // =========================================================================

    function testFuzz_BlockSubmission(bytes32 root, uint256 numTx) public {
        vm.assume(root != bytes32(0));
        numTx = bound(numTx, 1, 1000);

        uint256 blockNumBefore = bridge.currentBlockNumber();

        vm.prank(operator);
        bridge.submitBlock(root, numTx);

        assertEq(
            bridge.currentBlockNumber(),
            blockNumBefore + 1,
            "Block number should increment"
        );
        assertEq(
            bridge.blockRoots(blockNumBefore),
            root,
            "Root should be stored"
        );
    }

    function testFuzz_BlockSubmissionRevertsZeroRoot() public {
        vm.prank(operator);
        vm.expectRevert(PlasmaBridgeAdapter.InvalidBlock.selector);
        bridge.submitBlock(bytes32(0), 1);
    }

    function testFuzz_BlockSubmissionRevertsNonOperator(
        address attacker
    ) public {
        vm.assume(attacker != operator && attacker != admin);
        vm.assume(!bridge.hasRole(bridge.OPERATOR_ROLE(), attacker));

        vm.prank(attacker);
        vm.expectRevert();
        bridge.submitBlock(keccak256("root"), 1);
    }

    // =========================================================================
    // BRIDGE ADAPTER FUZZ TESTS - CROSS-DOMAIN NULLIFIER
    // =========================================================================

    function testFuzz_CrossDomainNullifierRegistration(
        bytes32 plasmaNullifier,
        uint256 targetChain
    ) public {
        vm.assume(plasmaNullifier != bytes32(0));
        targetChain = bound(targetChain, 1, type(uint64).max);

        vm.prank(user1);
        bridge.registerCrossDomainNullifier(plasmaNullifier, targetChain);

        bytes32 pilNullifier = bridge.crossDomainNullifiers(plasmaNullifier);
        assertNotEq(pilNullifier, bytes32(0), "PIL nullifier should be set");

        bytes32 reverse = bridge.pilBindings(pilNullifier);
        assertEq(reverse, plasmaNullifier, "Reverse mapping should match");
    }

    function testFuzz_CrossDomainNullifierIdempotent(
        bytes32 plasmaNullifier,
        uint256 targetChain
    ) public {
        vm.assume(plasmaNullifier != bytes32(0));
        targetChain = bound(targetChain, 1, type(uint64).max);

        vm.prank(user1);
        bridge.registerCrossDomainNullifier(plasmaNullifier, targetChain);
        bytes32 pilNf1 = bridge.crossDomainNullifiers(plasmaNullifier);

        vm.prank(user1);
        bridge.registerCrossDomainNullifier(plasmaNullifier, targetChain);
        bytes32 pilNf2 = bridge.crossDomainNullifiers(plasmaNullifier);

        assertEq(pilNf1, pilNf2, "Should be idempotent");
    }

    // =========================================================================
    // BRIDGE ADAPTER FUZZ TESTS - CIRCUIT BREAKER
    // =========================================================================

    function test_CircuitBreakerBlocksDeposits() public {
        vm.prank(admin);
        bridge.triggerCircuitBreaker("Test");

        assertTrue(
            bridge.circuitBreakerActive(),
            "Circuit breaker should be active"
        );

        vm.prank(user1);
        vm.expectRevert(PlasmaBridgeAdapter.CircuitBreakerOn.selector);
        bridge.deposit{value: 1 ether}(keccak256("test"));
    }

    function test_CircuitBreakerReset() public {
        vm.prank(admin);
        bridge.triggerCircuitBreaker("Test");

        vm.prank(admin);
        bridge.resetCircuitBreaker();

        assertFalse(
            bridge.circuitBreakerActive(),
            "Circuit breaker should be reset"
        );

        vm.prank(user1);
        bridge.deposit{value: 1 ether}(keccak256("test"));
    }

    // =========================================================================
    // BRIDGE ADAPTER FUZZ TESTS - PAUSE
    // =========================================================================

    function test_PauseBlocksDeposits() public {
        vm.prank(admin);
        bridge.pause();

        vm.prank(user1);
        vm.expectRevert();
        bridge.deposit{value: 1 ether}(keccak256("test"));
    }

    function test_UnpauseAllowsDeposits() public {
        vm.prank(admin);
        bridge.pause();

        vm.prank(admin);
        bridge.unpause();

        vm.prank(user1);
        bridge.deposit{value: 1 ether}(keccak256("test"));
    }

    // =========================================================================
    // BRIDGE ADAPTER FUZZ TESTS - RELAYER
    // =========================================================================

    function testFuzz_RelayerRegistration(address relayer) public {
        vm.assume(relayer != address(0));

        vm.prank(relayer);
        bridge.registerRelayer();

        assertTrue(
            bridge.registeredRelayers(relayer),
            "Relayer should be registered"
        );
    }

    function testFuzz_RelayerUnregistration(address relayer) public {
        vm.assume(relayer != address(0));

        vm.startPrank(relayer);
        bridge.registerRelayer();
        assertTrue(bridge.registeredRelayers(relayer), "Should be registered");

        bridge.unregisterRelayer();
        assertFalse(
            bridge.registeredRelayers(relayer),
            "Should be unregistered"
        );
        vm.stopPrank();
    }

    function testFuzz_RelayerFeeUpdate(uint256 newFee) public {
        if (newFee <= bridge.MAX_RELAYER_FEE_BPS()) {
            vm.prank(admin);
            bridge.updateRelayerFee(newFee);
            assertEq(bridge.relayerFeeBps(), newFee, "Fee should be updated");
        } else {
            vm.prank(admin);
            vm.expectRevert("Fee too high");
            bridge.updateRelayerFee(newFee);
        }
    }

    // =========================================================================
    // BRIDGE ADAPTER FUZZ TESTS - ACCESS CONTROL
    // =========================================================================

    function testFuzz_OnlyGuardianCanTriggerBreaker(address attacker) public {
        vm.assume(attacker != admin && attacker != emergencyCouncil);
        vm.assume(!bridge.hasRole(bridge.GUARDIAN_ROLE(), attacker));

        vm.prank(attacker);
        vm.expectRevert();
        bridge.triggerCircuitBreaker("Attack");
    }

    function testFuzz_OnlyAdminCanResetBreaker(address attacker) public {
        vm.assume(attacker != admin);
        vm.assume(!bridge.hasRole(bridge.DEFAULT_ADMIN_ROLE(), attacker));

        vm.prank(admin);
        bridge.triggerCircuitBreaker("Test");

        vm.prank(attacker);
        vm.expectRevert();
        bridge.resetCircuitBreaker();
    }

    // =========================================================================
    // BRIDGE ADAPTER FUZZ TESTS - STATS
    // =========================================================================

    function test_GetStats() public {
        (
            uint256 blockNum,
            uint256 tvl,
            uint256 queueLen,
            bool circuitBreaker
        ) = bridge.getStats();

        assertEq(blockNum, 1, "Initial block number");
        assertEq(tvl, 0, "Initial TVL");
        assertEq(queueLen, 0, "Initial queue length");
        assertFalse(circuitBreaker, "Circuit breaker should be off");
    }

    function testFuzz_TotalValueLockedTracking(uint256 amount) public {
        amount = bound(amount, 1 ether, 10 ether);

        bytes32 commitment = keccak256(abi.encodePacked("commitment", amount));

        vm.prank(user1);
        bridge.deposit{value: amount}(commitment);

        (, uint256 tvl, , ) = bridge.getStats();
        assertEq(tvl, amount, "TVL should equal deposit");
    }

    // =========================================================================
    // CONSTANTS TESTS
    // =========================================================================

    function test_Constants() public pure {
        assertEq(PlasmaPrimitives.MAX_INPUTS, 4);
        assertEq(PlasmaPrimitives.MAX_OUTPUTS, 4);
        assertEq(PlasmaPrimitives.MERKLE_TREE_DEPTH, 16);
        assertEq(PlasmaPrimitives.MAX_TRANSACTIONS_PER_BLOCK, 65536);
        assertEq(PlasmaPrimitives.CHALLENGE_PERIOD, 7 days);
        assertEq(PlasmaPrimitives.MIN_EXIT_BOND, 0.1 ether);
        assertEq(PlasmaPrimitives.SIGNATURE_LENGTH, 65);
    }
}
