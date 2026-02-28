// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/security/CrossChainMEVShield.sol";

contract CrossChainMEVShieldTest is Test {
    CrossChainMEVShield public shield;
    address public admin = address(this);
    address public user1 = makeAddr("user1");
    address public user2 = makeAddr("user2");

    uint32 constant SRC_CHAIN = 1;
    uint32 constant DST_CHAIN = 42161;

    function setUp() public {
        shield = new CrossChainMEVShield(admin);
    }

    /*//////////////////////////////////////////////////////////////
                       COMMIT TESTS
    //////////////////////////////////////////////////////////////*/

    function test_Commit() public {
        bytes memory preimage = abi.encode(
            "secret_operation",
            user1,
            100 ether
        );
        bytes32 commitHash = keccak256(preimage);

        vm.prank(user1);
        bytes32 commitId = shield.commit(commitHash, SRC_CHAIN, DST_CHAIN);

        ICrossChainMEVShield.Commitment memory c = shield.getCommitment(
            commitId
        );
        assertEq(c.commitHash, commitHash);
        assertEq(c.committer, user1);
        assertEq(c.commitBlock, block.number);
        assertFalse(c.revealed);
        assertFalse(c.expired);
        assertEq(shield.totalCommits(), 1);
    }

    /*//////////////////////////////////////////////////////////////
                       REVEAL TESTS
    //////////////////////////////////////////////////////////////*/

    function test_Reveal_Success() public {
        bytes memory preimage = abi.encode(
            "secret_operation",
            user1,
            100 ether
        );
        bytes32 commitHash = keccak256(preimage);

        vm.prank(user1);
        bytes32 commitId = shield.commit(commitHash, SRC_CHAIN, DST_CHAIN);

        // Advance past commitment delay (default: 2 blocks)
        vm.roll(block.number + 3);

        vm.prank(user1);
        bytes32 opHash = shield.reveal(commitId, preimage);

        assertEq(opHash, commitHash);
        ICrossChainMEVShield.Commitment memory c = shield.getCommitment(
            commitId
        );
        assertTrue(c.revealed);
        assertEq(shield.successfulReveals(), 1);
    }

    function test_Reveal_TooEarlyReverts() public {
        bytes memory preimage = abi.encode("secret");
        bytes32 commitHash = keccak256(preimage);

        vm.prank(user1);
        bytes32 commitId = shield.commit(commitHash, SRC_CHAIN, DST_CHAIN);

        // Don't advance blocks — try to reveal immediately
        vm.prank(user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                ICrossChainMEVShield.RevealTooEarly.selector,
                commitId,
                block.number,
                block.number + 2 // readyBlock
            )
        );
        shield.reveal(commitId, preimage);
    }

    function test_Reveal_TooLateReverts() public {
        bytes memory preimage = abi.encode("secret");
        bytes32 commitHash = keccak256(preimage);

        vm.prank(user1);
        bytes32 commitId = shield.commit(commitHash, SRC_CHAIN, DST_CHAIN);

        ICrossChainMEVShield.Commitment memory c = shield.getCommitment(
            commitId
        );

        // Advance past reveal window
        vm.roll(c.revealDeadlineBlock + 1);

        vm.prank(user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                ICrossChainMEVShield.RevealTooLate.selector,
                commitId,
                block.number,
                c.revealDeadlineBlock
            )
        );
        shield.reveal(commitId, preimage);
    }

    function test_Reveal_WrongPreimageReverts() public {
        bytes memory preimage = abi.encode("secret");
        bytes32 commitHash = keccak256(preimage);

        vm.prank(user1);
        bytes32 commitId = shield.commit(commitHash, SRC_CHAIN, DST_CHAIN);

        vm.roll(block.number + 3);

        bytes memory wrongPreimage = abi.encode("wrong_secret");
        bytes32 wrongHash = keccak256(wrongPreimage);

        vm.prank(user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                ICrossChainMEVShield.InvalidReveal.selector,
                commitId,
                commitHash,
                wrongHash
            )
        );
        shield.reveal(commitId, wrongPreimage);
    }

    function test_Reveal_NotCommitterReverts() public {
        bytes memory preimage = abi.encode("secret");
        bytes32 commitHash = keccak256(preimage);

        vm.prank(user1);
        bytes32 commitId = shield.commit(commitHash, SRC_CHAIN, DST_CHAIN);

        vm.roll(block.number + 3);

        vm.prank(user2);
        vm.expectRevert(
            abi.encodeWithSelector(
                ICrossChainMEVShield.NotCommitter.selector,
                commitId,
                user2
            )
        );
        shield.reveal(commitId, preimage);
    }

    function test_Reveal_DoubleRevealReverts() public {
        bytes memory preimage = abi.encode("secret");
        bytes32 commitHash = keccak256(preimage);

        vm.prank(user1);
        bytes32 commitId = shield.commit(commitHash, SRC_CHAIN, DST_CHAIN);

        vm.roll(block.number + 3);

        vm.prank(user1);
        shield.reveal(commitId, preimage);

        vm.prank(user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                ICrossChainMEVShield.CommitmentAlreadyRevealed.selector,
                commitId
            )
        );
        shield.reveal(commitId, preimage);
    }

    /*//////////////////////////////////////////////////////////////
                       EXPIRY TESTS
    //////////////////////////////////////////////////////////////*/

    function test_ExpireCommitment() public {
        bytes memory preimage = abi.encode("secret");
        bytes32 commitHash = keccak256(preimage);

        vm.prank(user1);
        bytes32 commitId = shield.commit(commitHash, SRC_CHAIN, DST_CHAIN);

        ICrossChainMEVShield.Commitment memory c = shield.getCommitment(
            commitId
        );
        vm.roll(c.revealDeadlineBlock + 1);

        shield.expireCommitment(commitId);

        c = shield.getCommitment(commitId);
        assertTrue(c.expired);
        assertEq(shield.totalExpiredCommits(), 1);
    }

    function test_BatchExpire() public {
        bytes32[] memory commitIds = new bytes32[](3);

        for (uint256 i; i < 3; i++) {
            bytes memory preimage = abi.encode("secret", i);
            bytes32 commitHash = keccak256(preimage);

            vm.prank(user1);
            commitIds[i] = shield.commit(commitHash, SRC_CHAIN, DST_CHAIN);
        }

        // Advance past all deadlines
        vm.roll(block.number + 200);

        uint256 expired = shield.batchExpire(commitIds);
        assertEq(expired, 3);
    }

    /*//////////////////////////////////////////////////////////////
                       CONFIG TESTS
    //////////////////////////////////////////////////////////////*/

    function test_ConfigureShield() public {
        shield.configureShield(SRC_CHAIN, DST_CHAIN, 5, 300);

        (uint256 delay, uint256 window, bool configured) = shield
            .getShieldConfig(SRC_CHAIN, DST_CHAIN);

        assertEq(delay, 5);
        assertEq(window, 300);
        assertTrue(configured);
    }

    function test_ConfigureShield_InvalidReverts() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                ICrossChainMEVShield.InvalidShieldConfig.selector,
                0,
                150
            )
        );
        shield.configureShield(SRC_CHAIN, DST_CHAIN, 0, 150); // below MIN_COMMITMENT_DELAY
    }

    function test_DefaultShieldConfig() public view {
        (uint256 delay, uint256 window, bool configured) = shield
            .getShieldConfig(SRC_CHAIN, DST_CHAIN);

        assertEq(delay, 2);
        assertEq(window, 150);
        assertFalse(configured); // using defaults
    }

    /*//////////////////////////////////////////////////////////////
                       READY-TO-REVEAL VIEW
    //////////////////////////////////////////////////////////////*/

    function test_IsReadyToReveal() public {
        bytes memory preimage = abi.encode("secret");
        bytes32 commitHash = keccak256(preimage);

        vm.prank(user1);
        bytes32 commitId = shield.commit(commitHash, SRC_CHAIN, DST_CHAIN);

        // Not ready yet (same block)
        assertFalse(shield.isReadyToReveal(commitId));

        // Advance past delay
        vm.roll(block.number + 3);
        assertTrue(shield.isReadyToReveal(commitId));

        // Advance past window
        vm.roll(block.number + 200);
        assertFalse(shield.isReadyToReveal(commitId));
    }

    /*//////////////////////////////////////////////////////////////
                       EFFECTIVENESS TRACKING
    //////////////////////////////////////////////////////////////*/

    function test_EffectivenessRate() public {
        // Make 3 commits, reveal 2
        for (uint256 i; i < 3; i++) {
            bytes memory preimage = abi.encode("secret", i);
            bytes32 commitHash = keccak256(preimage);
            vm.prank(user1);
            shield.commit(commitHash, SRC_CHAIN, DST_CHAIN);
        }

        (uint256 total, uint256 reveals) = shield.getEffectivenessRate();
        assertEq(total, 3);
        assertEq(reveals, 0);
    }

    /*//////////////////////////////////////////////////////////////
                       FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_CommitRevealIntegrity(bytes memory preimage) public {
        vm.assume(preimage.length > 0 && preimage.length < 10000);

        bytes32 commitHash = keccak256(preimage);

        vm.prank(user1);
        bytes32 commitId = shield.commit(commitHash, SRC_CHAIN, DST_CHAIN);

        vm.roll(block.number + 3);

        vm.prank(user1);
        bytes32 opHash = shield.reveal(commitId, preimage);

        assertEq(opHash, commitHash);
    }
}
