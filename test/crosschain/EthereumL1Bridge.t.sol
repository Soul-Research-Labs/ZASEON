// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/crosschain/EthereumL1Bridge.sol";

/// @title EthereumL1Bridge Unit Tests
/// @notice Comprehensive tests for state commitment relay, deposits, withdrawals, challenges, and admin functions
contract EthereumL1BridgeTest is Test {
    EthereumL1Bridge public bridge;

    address public admin = address(this);
    address public relayer = makeAddr("relayer");
    address public guardian = makeAddr("guardian");
    address public operator = makeAddr("operator");
    address public alice = makeAddr("alice");
    address public bob = makeAddr("bob");

    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");

    // Default L2 chain IDs from _initializeL2Chains
    uint256 constant ARBITRUM = 42161;
    uint256 constant OPTIMISM = 10;
    uint256 constant BASE = 8453;
    uint256 constant ZKSYNC = 324;
    uint256 constant SCROLL = 534352;

    function setUp() public {
        bridge = new EthereumL1Bridge();

        // Grant roles
        bridge.grantRole(RELAYER_ROLE, relayer);
        bridge.grantRole(GUARDIAN_ROLE, guardian);
        bridge.grantRole(OPERATOR_ROLE, operator);

        // Fund accounts
        vm.deal(relayer, 100 ether);
        vm.deal(alice, 100 ether);
        vm.deal(bob, 100 ether);
        vm.deal(guardian, 10 ether);
    }

    // ============ Constructor / Initialization Tests ============

    function test_constructor_grantsAdminRoles() public view {
        assertTrue(bridge.hasRole(bridge.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(bridge.hasRole(OPERATOR_ROLE, admin));
        assertTrue(bridge.hasRole(GUARDIAN_ROLE, admin));
    }

    function test_constructor_initializesDefaultChains() public view {
        uint256[] memory chainIds = bridge.getSupportedChainIds();
        assertGe(chainIds.length, 7); // At least 7 chains configured
    }

    function test_constructor_arbitrumConfig() public view {
        EthereumL1Bridge.L2Config memory config = bridge.getL2Config(ARBITRUM);
        assertEq(config.chainId, ARBITRUM);
        assertTrue(config.enabled);
        assertEq(config.challengePeriod, 7 days);
    }

    function test_constructor_zkSyncConfigFinalizesImmediately() public view {
        EthereumL1Bridge.L2Config memory config = bridge.getL2Config(ZKSYNC);
        assertEq(config.chainId, ZKSYNC);
        assertTrue(config.enabled);
        assertEq(config.challengePeriod, 0); // ZK rollups finalize immediately
    }

    function test_isChainSupported_true() public view {
        assertTrue(bridge.isChainSupported(ARBITRUM));
        assertTrue(bridge.isChainSupported(OPTIMISM));
        assertTrue(bridge.isChainSupported(ZKSYNC));
    }

    function test_isChainSupported_unknownChain() public view {
        assertFalse(bridge.isChainSupported(999999));
    }

    // ============ L2 Chain Management Tests ============

    function test_configureL2Chain_success() public {
        EthereumL1Bridge.L2Config memory config = EthereumL1Bridge.L2Config({
            chainId: 7777777,
            name: "TestChain",
            rollupType: EthereumL1Bridge.RollupType.ZK_ROLLUP,
            canonicalBridge: address(0),
            messenger: address(0),
            stateCommitmentChain: address(0),
            challengePeriod: 0,
            confirmationBlocks: 1,
            enabled: true,
            gasLimit: 500000,
            lastSyncedBlock: 0
        });

        vm.prank(operator);
        bridge.configureL2Chain(config);

        assertTrue(bridge.isChainSupported(7777777));
    }

    function test_configureL2Chain_revertsNotOperator() public {
        EthereumL1Bridge.L2Config memory config = EthereumL1Bridge.L2Config({
            chainId: 7777777,
            name: "TestChain",
            rollupType: EthereumL1Bridge.RollupType.ZK_ROLLUP,
            canonicalBridge: address(0),
            messenger: address(0),
            stateCommitmentChain: address(0),
            challengePeriod: 0,
            confirmationBlocks: 1,
            enabled: true,
            gasLimit: 500000,
            lastSyncedBlock: 0
        });

        vm.prank(alice);
        vm.expectRevert();
        bridge.configureL2Chain(config);
    }

    function test_setCanonicalBridge_success() public {
        address newBridge = makeAddr("newBridge");
        vm.prank(operator);
        bridge.setCanonicalBridge(ARBITRUM, newBridge);

        EthereumL1Bridge.L2Config memory config = bridge.getL2Config(ARBITRUM);
        assertEq(config.canonicalBridge, newBridge);
    }

    function test_setCanonicalBridge_revertsZeroAddress() public {
        vm.prank(operator);
        vm.expectRevert(EthereumL1Bridge.ZeroAddress.selector);
        bridge.setCanonicalBridge(ARBITRUM, address(0));
    }

    function test_setCanonicalBridge_revertsUnsupportedChain() public {
        vm.prank(operator);
        vm.expectRevert(
            abi.encodeWithSelector(
                EthereumL1Bridge.ChainNotSupported.selector,
                999
            )
        );
        bridge.setCanonicalBridge(999, makeAddr("bridge"));
    }

    function test_setChainEnabled_toggle() public {
        vm.startPrank(operator);
        bridge.setChainEnabled(ARBITRUM, false);
        assertFalse(bridge.isChainSupported(ARBITRUM));

        bridge.setChainEnabled(ARBITRUM, true);
        assertTrue(bridge.isChainSupported(ARBITRUM));
        vm.stopPrank();
    }

    // ============ State Commitment Submission Tests ============

    function test_submitStateCommitment_optimistic() public {
        bytes32 stateRoot = keccak256("stateRoot");
        bytes32 proofRoot = keccak256("proofRoot");

        vm.prank(relayer);
        bridge.submitStateCommitment{value: 0.1 ether}(
            ARBITRUM,
            stateRoot,
            proofRoot,
            12345
        );

        assertEq(bridge.totalCommitments(), 1);
        // Optimistic rollup: state root not finalized yet
        assertEq(bridge.getLatestStateRoot(ARBITRUM), bytes32(0));
    }

    function test_submitStateCommitment_zkRollup_immediateFinalization()
        public
    {
        bytes32 stateRoot = keccak256("zkStateRoot");
        bytes32 proofRoot = keccak256("zkProofRoot");

        vm.prank(relayer);
        bridge.submitStateCommitment{value: 0.1 ether}(
            ZKSYNC,
            stateRoot,
            proofRoot,
            100
        );

        // ZK rollup: state root finalized immediately
        assertEq(bridge.getLatestStateRoot(ZKSYNC), stateRoot);
    }

    function test_submitStateCommitment_revertsInsufficientBond() public {
        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                EthereumL1Bridge.InsufficientBond.selector,
                0.01 ether,
                0.1 ether
            )
        );
        bridge.submitStateCommitment{value: 0.01 ether}(
            ARBITRUM,
            keccak256("root"),
            keccak256("proof"),
            1
        );
    }

    function test_submitStateCommitment_revertsChainNotEnabled() public {
        vm.prank(operator);
        bridge.setChainEnabled(ARBITRUM, false);

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                EthereumL1Bridge.ChainNotEnabled.selector,
                ARBITRUM
            )
        );
        bridge.submitStateCommitment{value: 0.1 ether}(
            ARBITRUM,
            keccak256("root"),
            keccak256("proof"),
            1
        );
    }

    function test_submitStateCommitment_revertsNotRelayer() public {
        vm.prank(alice);
        vm.expectRevert();
        bridge.submitStateCommitment{value: 0.1 ether}(
            ARBITRUM,
            keccak256("root"),
            keccak256("proof"),
            1
        );
    }

    function test_submitStateCommitment_revertsWhenPaused() public {
        vm.prank(guardian);
        bridge.pause();

        vm.prank(relayer);
        vm.expectRevert();
        bridge.submitStateCommitment{value: 0.1 ether}(
            ARBITRUM,
            keccak256("root"),
            keccak256("proof"),
            1
        );
    }

    // ============ Challenge Tests ============

    function _submitOptimisticCommitment()
        internal
        returns (bytes32 commitmentId)
    {
        bytes32 stateRoot = keccak256("stateRoot");
        bytes32 proofRoot = keccak256("proofRoot");

        vm.prank(relayer);
        bridge.submitStateCommitment{value: 0.1 ether}(
            OPTIMISM,
            stateRoot,
            proofRoot,
            100
        );

        // Compute the commitment ID
        commitmentId = keccak256(
            abi.encodePacked(
                uint256(OPTIMISM),
                stateRoot,
                proofRoot,
                uint256(100),
                block.timestamp,
                bytes32(0) // no blob
            )
        );
    }

    function test_challengeCommitment_success() public {
        bytes32 commitmentId = _submitOptimisticCommitment();

        vm.prank(alice);
        bridge.challengeCommitment{value: 0.05 ether}(
            commitmentId,
            keccak256("reason")
        );

        (, , , , , , EthereumL1Bridge.CommitmentStatus status, , , ) = bridge
            .stateCommitments(commitmentId);
        assertEq(
            uint256(status),
            uint256(EthereumL1Bridge.CommitmentStatus.CHALLENGED)
        );
    }

    function test_challengeCommitment_revertsInsufficientBond() public {
        bytes32 commitmentId = _submitOptimisticCommitment();

        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(
                EthereumL1Bridge.InsufficientChallengeBond.selector,
                0.01 ether,
                0.05 ether
            )
        );
        bridge.challengeCommitment{value: 0.01 ether}(
            commitmentId,
            keccak256("reason")
        );
    }

    function test_challengeCommitment_revertsAfterDeadline() public {
        bytes32 commitmentId = _submitOptimisticCommitment();

        // Warp past challenge period
        vm.warp(block.timestamp + 7 days + 1);

        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(
                EthereumL1Bridge.ChallengePeriodOver.selector,
                commitmentId
            )
        );
        bridge.challengeCommitment{value: 0.05 ether}(
            commitmentId,
            keccak256("reason")
        );
    }

    // ============ Finalize Commitment Tests ============

    function test_finalizeCommitment_afterChallengePeriod() public {
        bytes32 commitmentId = _submitOptimisticCommitment();

        // Warp past challenge period
        vm.warp(block.timestamp + 7 days + 1);

        uint256 relayerBalBefore = relayer.balance;
        bridge.finalizeCommitment(commitmentId);

        // State root should be updated
        assertEq(bridge.getLatestStateRoot(OPTIMISM), keccak256("stateRoot"));

        // Bond returned to relayer
        assertGt(relayer.balance, relayerBalBefore);
    }

    function test_finalizeCommitment_revertsTooEarly() public {
        bytes32 commitmentId = _submitOptimisticCommitment();

        vm.expectRevert();
        bridge.finalizeCommitment(commitmentId);
    }

    function test_finalizeCommitment_revertsNotPending() public {
        bytes32 commitmentId = _submitOptimisticCommitment();

        // Challenge it first
        vm.prank(alice);
        bridge.challengeCommitment{value: 0.05 ether}(
            commitmentId,
            keccak256("reason")
        );

        vm.warp(block.timestamp + 7 days + 1);

        vm.expectRevert(
            abi.encodeWithSelector(
                EthereumL1Bridge.CommitmentNotPending.selector,
                commitmentId
            )
        );
        bridge.finalizeCommitment(commitmentId);
    }

    // ============ Resolve Challenge Tests ============

    function test_resolveChallenge_reject() public {
        bytes32 commitmentId = _submitOptimisticCommitment();

        vm.prank(alice);
        bridge.challengeCommitment{value: 0.05 ether}(
            commitmentId,
            keccak256("reason")
        );

        uint256 aliceBalBefore = alice.balance;

        vm.prank(guardian);
        bridge.resolveChallenge(commitmentId, true);

        // Challenger gets submitter bond + challenge bond
        assertGt(alice.balance, aliceBalBefore);

        (, , , , , , EthereumL1Bridge.CommitmentStatus status, , , ) = bridge
            .stateCommitments(commitmentId);
        assertEq(
            uint256(status),
            uint256(EthereumL1Bridge.CommitmentStatus.REJECTED)
        );
    }

    function test_resolveChallenge_submitterWins() public {
        bytes32 commitmentId = _submitOptimisticCommitment();

        vm.prank(alice);
        bridge.challengeCommitment{value: 0.05 ether}(
            commitmentId,
            keccak256("reason")
        );

        uint256 relayerBalBefore = relayer.balance;

        vm.prank(guardian);
        bridge.resolveChallenge(commitmentId, false);

        // Submitter gets challenger's bond
        assertGt(relayer.balance, relayerBalBefore);

        // Status reset to PENDING for finalization
        (, , , , , , EthereumL1Bridge.CommitmentStatus status, , , ) = bridge
            .stateCommitments(commitmentId);
        assertEq(
            uint256(status),
            uint256(EthereumL1Bridge.CommitmentStatus.PENDING)
        );
    }

    function test_resolveChallenge_revertsNotGuardian() public {
        bytes32 commitmentId = _submitOptimisticCommitment();

        vm.prank(alice);
        bridge.challengeCommitment{value: 0.05 ether}(
            commitmentId,
            keccak256("reason")
        );

        vm.prank(alice);
        vm.expectRevert();
        bridge.resolveChallenge(commitmentId, true);
    }

    // ============ Deposit Tests ============

    function test_depositETH_success() public {
        bytes32 commitment = keccak256("commitment");

        vm.prank(alice);
        bridge.depositETH{value: 1 ether}(ARBITRUM, commitment);

        assertEq(bridge.totalDeposits(), 1);
    }

    function test_depositETH_revertsZeroAmount() public {
        vm.prank(alice);
        vm.expectRevert(EthereumL1Bridge.ZeroAmount.selector);
        bridge.depositETH{value: 0}(ARBITRUM, keccak256("c"));
    }

    function test_depositETH_revertsUnsupportedChain() public {
        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(
                EthereumL1Bridge.ChainNotSupported.selector,
                999
            )
        );
        bridge.depositETH{value: 1 ether}(999, keccak256("c"));
    }

    function test_depositETH_revertsZeroCommitment() public {
        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(
                EthereumL1Bridge.InvalidCommitment.selector,
                bytes32(0)
            )
        );
        bridge.depositETH{value: 1 ether}(ARBITRUM, bytes32(0));
    }

    function test_depositETH_revertsWhenPaused() public {
        vm.prank(guardian);
        bridge.pause();

        vm.prank(alice);
        vm.expectRevert();
        bridge.depositETH{value: 1 ether}(ARBITRUM, keccak256("c"));
    }

    function test_depositETH_revertsChainDisabled() public {
        vm.prank(operator);
        bridge.setChainEnabled(ARBITRUM, false);

        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(
                EthereumL1Bridge.ChainNotEnabled.selector,
                ARBITRUM
            )
        );
        bridge.depositETH{value: 1 ether}(ARBITRUM, keccak256("c"));
    }

    // ============ Withdrawal Tests ============

    function _setupWithdrawal() internal returns (bytes32) {
        // First submit and finalize a ZK state root with a valid Merkle tree
        bytes32 nullifier = keccak256("nullifier1");
        uint256 amount = 1 ether;
        bytes32 leaf = keccak256(abi.encodePacked(nullifier, amount));
        // Single-node tree: proof is empty, state root = leaf
        // But we need at least 1 proof element, so build a 2-leaf tree
        bytes32 sibling = keccak256("sibling");
        bytes32 stateRoot;
        if (leaf <= sibling) {
            stateRoot = keccak256(abi.encodePacked(leaf, sibling));
        } else {
            stateRoot = keccak256(abi.encodePacked(sibling, leaf));
        }

        // Submit ZK state root (finalizes immediately)
        vm.prank(relayer);
        bridge.submitStateCommitment{value: 0.1 ether}(
            ZKSYNC,
            stateRoot,
            keccak256("proofRoot"),
            100
        );

        // Fund bridge for withdrawal
        vm.deal(address(bridge), 10 ether);

        // Initiate withdrawal
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = sibling;

        vm.prank(alice);
        bridge.initiateWithdrawal(ZKSYNC, amount, nullifier, proof);

        // Compute withdrawal ID
        bytes32 withdrawalId = keccak256(
            abi.encodePacked(alice, ZKSYNC, amount, nullifier, block.timestamp)
        );
        return withdrawalId;
    }

    function test_initiateWithdrawal_zkRollup() public {
        bytes32 withdrawalId = _setupWithdrawal();
        assertEq(bridge.totalWithdrawals(), 1);

        // ZK withdrawal should be immediately finalized
        (, , , , , , , bool finalized, ) = bridge.withdrawals(withdrawalId);
        assertTrue(finalized);
    }

    function test_initiateWithdrawal_revertsNullifierReuse() public {
        _setupWithdrawal();

        bytes32 nullifier = keccak256("nullifier1");
        assertTrue(bridge.isNullifierUsed(nullifier));

        // Try again with same nullifier
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = keccak256("any");

        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(
                EthereumL1Bridge.NullifierAlreadyUsed.selector,
                nullifier
            )
        );
        bridge.initiateWithdrawal(ZKSYNC, 1 ether, nullifier, proof);
    }

    function test_initiateWithdrawal_revertsZeroAmount() public {
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = keccak256("any");

        vm.prank(alice);
        vm.expectRevert(EthereumL1Bridge.ZeroAmount.selector);
        bridge.initiateWithdrawal(ZKSYNC, 0, keccak256("n"), proof);
    }

    function test_claimWithdrawal_success() public {
        bytes32 withdrawalId = _setupWithdrawal();

        uint256 aliceBalBefore = alice.balance;
        vm.prank(alice);
        bridge.claimWithdrawal(withdrawalId);

        assertEq(alice.balance, aliceBalBefore + 1 ether);
    }

    function test_claimWithdrawal_revertsDoubleClaim() public {
        bytes32 withdrawalId = _setupWithdrawal();

        vm.prank(alice);
        bridge.claimWithdrawal(withdrawalId);

        vm.prank(alice);
        vm.expectRevert(EthereumL1Bridge.AlreadyClaimed.selector);
        bridge.claimWithdrawal(withdrawalId);
    }

    function test_claimWithdrawal_revertsNotFinalized() public {
        // Setup an optimistic withdrawal that is NOT finalized
        bytes32 nullifier = keccak256("optNullifier");
        uint256 amount = 1 ether;
        bytes32 leaf = keccak256(abi.encodePacked(nullifier, amount));
        bytes32 sibling = keccak256("optSibling");
        bytes32 stateRoot;
        if (leaf <= sibling) {
            stateRoot = keccak256(abi.encodePacked(leaf, sibling));
        } else {
            stateRoot = keccak256(abi.encodePacked(sibling, leaf));
        }

        // Submit and immediately finalize a commitment on an optimistic chain
        // First we need a finalized state root on OPTIMISM
        vm.prank(relayer);
        bridge.submitStateCommitment{value: 0.1 ether}(
            OPTIMISM,
            stateRoot,
            keccak256("p"),
            200
        );
        vm.warp(block.timestamp + 7 days + 1);
        // Compute commitment ID and finalize
        bytes32 commitmentId = keccak256(
            abi.encodePacked(
                uint256(OPTIMISM),
                stateRoot,
                keccak256("p"),
                uint256(200),
                block.timestamp - 7 days - 1,
                bytes32(0)
            )
        );
        bridge.finalizeCommitment(commitmentId);

        vm.deal(address(bridge), 10 ether);
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = sibling;

        vm.prank(alice);
        bridge.initiateWithdrawal(OPTIMISM, amount, nullifier, proof);

        bytes32 withdrawalId = keccak256(
            abi.encodePacked(
                alice,
                OPTIMISM,
                amount,
                nullifier,
                block.timestamp
            )
        );

        // Withdrawal from optimistic rollup is NOT finalized yet
        (, , , , , , , bool finalized, ) = bridge.withdrawals(withdrawalId);
        assertFalse(finalized);

        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(
                EthereumL1Bridge.WithdrawalNotFinalized.selector,
                withdrawalId
            )
        );
        bridge.claimWithdrawal(withdrawalId);
    }

    function test_finalizeWithdrawal_optimistic() public {
        // Same setup as above but with time warp to finalize
        bytes32 nullifier = keccak256("optNullifier2");
        uint256 amount = 0.5 ether;
        bytes32 leaf = keccak256(abi.encodePacked(nullifier, amount));
        bytes32 sibling = keccak256("optSibling2");
        bytes32 stateRoot;
        if (leaf <= sibling) {
            stateRoot = keccak256(abi.encodePacked(leaf, sibling));
        } else {
            stateRoot = keccak256(abi.encodePacked(sibling, leaf));
        }

        // Submit optimistic commitment and capture the commitmentId from event
        vm.prank(relayer);
        vm.recordLogs();
        bridge.submitStateCommitment{value: 0.1 ether}(
            OPTIMISM,
            stateRoot,
            keccak256("p2"),
            300
        );

        Vm.Log[] memory entries = vm.getRecordedLogs();
        bytes32 commitmentId = entries[0].topics[1]; // commitmentId is first indexed topic

        vm.warp(block.timestamp + 7 days + 1);
        bridge.finalizeCommitment(commitmentId);

        vm.deal(address(bridge), 10 ether);
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = sibling;

        vm.prank(alice);
        bridge.initiateWithdrawal(OPTIMISM, amount, nullifier, proof);

        bytes32 withdrawalId = keccak256(
            abi.encodePacked(
                alice,
                OPTIMISM,
                amount,
                nullifier,
                block.timestamp
            )
        );

        // Wait for challenge period
        vm.warp(block.timestamp + 7 days + 1);
        bridge.finalizeWithdrawal(withdrawalId);

        (, , , , , , , bool finalizedAfter, ) = bridge.withdrawals(
            withdrawalId
        );
        assertTrue(finalizedAfter);
    }

    // ============ Proof Relay Tests ============

    function test_relayProof_success() public {
        // First submit and finalize a ZK state root
        bytes32 stateRoot = keccak256("proofRelayRoot");
        vm.prank(relayer);
        bridge.submitStateCommitment{value: 0.1 ether}(
            ZKSYNC,
            stateRoot,
            keccak256("pr"),
            50
        );

        bytes32 proofHash = keccak256("proof1");
        vm.prank(relayer);
        bridge.relayProof(ZKSYNC, proofHash, stateRoot, "proofData");

        assertTrue(bridge.relayedProofs(proofHash));
    }

    function test_relayProof_revertsInvalidStateRoot() public {
        vm.prank(relayer);
        vm.expectRevert(EthereumL1Bridge.InvalidProof.selector);
        bridge.relayProof(
            ZKSYNC,
            keccak256("p"),
            keccak256("wrongRoot"),
            "data"
        );
    }

    function test_relayProof_revertsDuplicate() public {
        bytes32 stateRoot = keccak256("dup");
        vm.prank(relayer);
        bridge.submitStateCommitment{value: 0.1 ether}(
            ZKSYNC,
            stateRoot,
            keccak256("pr"),
            60
        );

        bytes32 proofHash = keccak256("dupp");
        vm.prank(relayer);
        bridge.relayProof(ZKSYNC, proofHash, stateRoot, "");

        vm.prank(relayer);
        vm.expectRevert(EthereumL1Bridge.InvalidProof.selector);
        bridge.relayProof(ZKSYNC, proofHash, stateRoot, "");
    }

    // ============ Admin Tests ============

    function test_setRateLimits() public {
        vm.prank(operator);
        bridge.setRateLimits(50);
        assertEq(bridge.maxCommitmentsPerHour(), 50);
    }

    function test_setMinSubmissionBond() public {
        vm.prank(operator);
        bridge.setMinSubmissionBond(0.5 ether);
        assertEq(bridge.minSubmissionBond(), 0.5 ether);
    }

    function test_pause_unpause() public {
        vm.prank(guardian);
        bridge.pause();

        vm.prank(operator);
        bridge.unpause();
    }

    function test_pause_revertsNotGuardian() public {
        vm.prank(alice);
        vm.expectRevert();
        bridge.pause();
    }

    // ============ View Function Tests ============

    function test_getSupportedChainIds() public view {
        uint256[] memory ids = bridge.getSupportedChainIds();
        assertGe(ids.length, 7);
    }

    function test_getLatestStateRoot_default() public view {
        assertEq(bridge.getLatestStateRoot(ARBITRUM), bytes32(0));
    }

    function test_isNullifierUsed_default() public view {
        assertFalse(bridge.isNullifierUsed(keccak256("any")));
    }

    // ============ Rate Limiting Tests ============

    function test_rateLimit_blocksExcessiveCommitments() public {
        vm.prank(operator);
        bridge.setMaxCommitmentsPerHour(3);

        vm.startPrank(relayer);
        for (uint256 i = 0; i < 3; i++) {
            bridge.submitStateCommitment{value: 0.1 ether}(
                ZKSYNC,
                keccak256(abi.encodePacked("root", i)),
                keccak256(abi.encodePacked("proof", i)),
                i + 1
            );
        }

        // 4th should fail
        vm.expectRevert(EthereumL1Bridge.RateLimitExceeded.selector);
        bridge.submitStateCommitment{value: 0.1 ether}(
            ZKSYNC,
            keccak256("root4"),
            keccak256("proof4"),
            4
        );
        vm.stopPrank();
    }

    function test_rateLimit_resetsAfterHour() public {
        vm.prank(operator);
        bridge.setMaxCommitmentsPerHour(1);

        vm.prank(relayer);
        bridge.submitStateCommitment{value: 0.1 ether}(
            ZKSYNC,
            keccak256("r1"),
            keccak256("p1"),
            1
        );

        // Warp past 1 hour
        vm.warp(block.timestamp + 1 hours + 1);

        // Should succeed after reset
        vm.prank(relayer);
        bridge.submitStateCommitment{value: 0.1 ether}(
            ZKSYNC,
            keccak256("r2"),
            keccak256("p2"),
            2
        );
    }

    // ============ Fuzz Tests ============

    function testFuzz_depositPreservesAmount(uint96 amount) public {
        vm.assume(amount > 0);
        vm.deal(alice, uint256(amount) + 1 ether);

        vm.prank(alice);
        bridge.depositETH{value: amount}(ARBITRUM, keccak256("c"));

        assertEq(bridge.totalDeposits(), 1);
        assertEq(address(bridge).balance, amount);
    }

    function testFuzz_submissionBondRequired(uint96 bond) public {
        vm.assume(bond < 0.1 ether && bond > 0);

        vm.prank(relayer);
        vm.expectRevert();
        bridge.submitStateCommitment{value: bond}(
            ZKSYNC,
            keccak256("r"),
            keccak256("p"),
            1
        );
    }

    // ============ Receive ETH Test ============

    function test_receiveETH() public {
        vm.prank(alice);
        (bool success, ) = address(bridge).call{value: 1 ether}("");
        assertTrue(success);
    }
}
