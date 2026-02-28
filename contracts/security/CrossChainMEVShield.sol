// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {ICrossChainMEVShield} from "../interfaces/ICrossChainMEVShield.sol";

/**
 * @title CrossChainMEVShield
 * @author ZASEON
 * @notice Source-chain commit-reveal for cross-chain privacy operations
 * @dev Inspired by Arcium's single mempool MEV protection. Implements a 2-phase
 *      commit-reveal flow to prevent MEV extraction on cross-chain privacy ops:
 *
 *      1. COMMIT: User submits hash(preimage) — encrypted intent is hidden
 *      2. WAIT:   commitmentDelay blocks must pass (prevents front-running)
 *      3. REVEAL: User reveals preimage — if hash matches, operation proceeds
 *
 * ARCHITECTURE:
 * ┌─────────────────────────────────────────────────────────────────────┐
 * │                    MEV SHIELD (COMMIT-REVEAL)                       │
 * ├─────────────────────────────────────────────────────────────────────┤
 * │                                                                     │
 * │  Block N:   commit(hash)                                           │
 * │             ↓                                                       │
 * │  Block N+D: reveal possible (D = commitmentDelay)                  │
 * │             ↓                                                       │
 * │  Block N+D+W: reveal expired (W = revealWindow)                    │
 * │                                                                     │
 * │  ┌──────┐   D blocks   ┌─────────┐   W blocks   ┌─────────┐      │
 * │  │COMMIT├─────────────►│ REVEAL  ├──────────────►│ EXPIRED │      │
 * │  │      │  "dark pool" │ WINDOW  │  if no reveal │         │      │
 * │  └──────┘              └─────────┘               └─────────┘      │
 * │                                                                     │
 * │  CONFIG: Per chain pair — different L2s have different block times  │
 * │          Defaults: commitmentDelay=2, revealWindow=150             │
 * └─────────────────────────────────────────────────────────────────────┘
 *
 * SECURITY:
 * - Commit hash cannot be decoded by searchers/builders
 * - Delay ensures commit is finalized before reveal is possible
 * - Reveal window prevents indefinite resource holding
 * - Per chain pair config for L2 block-time differences
 * - Effectiveness tracking for monitoring
 */
contract CrossChainMEVShield is
    ICrossChainMEVShield,
    AccessControl,
    ReentrancyGuard
{
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    /// @notice Role for shield configuration (governance)
    bytes32 public constant GOVERNANCE_ROLE = keccak256("GOVERNANCE_ROLE");

    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Default commitment delay: 2 blocks
    uint256 public constant DEFAULT_COMMITMENT_DELAY = 2;

    /// @notice Default reveal window: 150 blocks
    uint256 public constant DEFAULT_REVEAL_WINDOW = 150;

    /// @notice Minimum commitment delay: 1 block
    uint256 public constant MIN_COMMITMENT_DELAY = 1;

    /// @notice Maximum commitment delay: 100 blocks
    uint256 public constant MAX_COMMITMENT_DELAY = 100;

    /// @notice Minimum reveal window: 10 blocks
    uint256 public constant MIN_REVEAL_WINDOW = 10;

    /// @notice Maximum reveal window: 1000 blocks
    uint256 public constant MAX_REVEAL_WINDOW = 1000;

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Commitments by ID
    mapping(bytes32 => Commitment) private _commitments;

    /// @notice Shield configs per chain pair
    mapping(bytes32 => ShieldConfig) private _shieldConfigs;

    /// @notice Whether a chain pair has been explicitly configured
    mapping(bytes32 => bool) private _configured;

    /// @notice Nonce for unique commitment IDs
    uint256 private _commitNonce;

    /// @notice Total commitments made
    uint256 public totalCommits;

    /// @notice Total successful reveals
    uint256 public successfulReveals;

    /// @notice Total expired commitments
    uint256 public totalExpiredCommits;

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @param admin Address granted DEFAULT_ADMIN_ROLE
    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(GOVERNANCE_ROLE, admin);
    }

    /*//////////////////////////////////////////////////////////////
                         EXTERNAL — WRITE
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc ICrossChainMEVShield
    function commit(
        bytes32 commitHash,
        uint32 sourceChainId,
        uint32 destChainId
    ) external nonReentrant returns (bytes32 commitId) {
        commitId = keccak256(
            abi.encodePacked(msg.sender, commitHash, _commitNonce++)
        );

        (uint256 delay, uint256 window, ) = _getEffectiveConfig(
            sourceChainId,
            destChainId
        );

        uint256 revealDeadline = block.number + delay + window;

        _commitments[commitId] = Commitment({
            commitHash: commitHash,
            committer: msg.sender,
            commitBlock: block.number,
            revealDeadlineBlock: revealDeadline,
            sourceChainId: sourceChainId,
            destChainId: destChainId,
            revealed: false,
            expired: false
        });

        totalCommits++;

        emit CommitmentMade(commitId, msg.sender, block.number, revealDeadline);
    }

    /// @inheritdoc ICrossChainMEVShield
    function reveal(
        bytes32 commitId,
        bytes calldata preimage
    ) external nonReentrant returns (bytes32 operationHash) {
        Commitment storage c = _commitments[commitId];
        if (c.committer == address(0)) revert CommitmentDoesNotExist(commitId);
        if (c.revealed) revert CommitmentAlreadyRevealed(commitId);
        if (c.expired) revert CommitmentExpiredError(commitId);
        if (c.committer != msg.sender)
            revert NotCommitter(commitId, msg.sender);

        // Check timing: must be past commitment delay
        (uint256 delay, , ) = _getEffectiveConfig(
            c.sourceChainId,
            c.destChainId
        );
        uint256 readyBlock = c.commitBlock + delay;

        if (block.number < readyBlock) {
            revert RevealTooEarly(commitId, block.number, readyBlock);
        }
        if (block.number > c.revealDeadlineBlock) {
            revert RevealTooLate(commitId, block.number, c.revealDeadlineBlock);
        }

        // Verify hash match
        operationHash = keccak256(preimage);
        if (operationHash != c.commitHash) {
            revert InvalidReveal(commitId, c.commitHash, operationHash);
        }

        c.revealed = true;
        successfulReveals++;

        emit CommitmentRevealed(commitId, msg.sender, operationHash);
    }

    /// @inheritdoc ICrossChainMEVShield
    function expireCommitment(bytes32 commitId) external {
        Commitment storage c = _commitments[commitId];
        if (c.committer == address(0)) revert CommitmentDoesNotExist(commitId);
        if (c.revealed) revert CommitmentAlreadyRevealed(commitId);
        if (c.expired) revert CommitmentExpiredError(commitId);

        if (block.number <= c.revealDeadlineBlock) {
            revert RevealTooEarly(
                commitId,
                block.number,
                c.revealDeadlineBlock
            );
        }

        c.expired = true;
        totalExpiredCommits++;

        emit CommitmentExpired(commitId);
    }

    /// @inheritdoc ICrossChainMEVShield
    function batchExpire(
        bytes32[] calldata commitIds
    ) external returns (uint256 expiredCount) {
        for (uint256 i; i < commitIds.length; i++) {
            Commitment storage c = _commitments[commitIds[i]];
            if (
                c.committer != address(0) &&
                !c.revealed &&
                !c.expired &&
                block.number > c.revealDeadlineBlock
            ) {
                c.expired = true;
                totalExpiredCommits++;
                expiredCount++;
                emit CommitmentExpired(commitIds[i]);
            }
        }

        if (expiredCount > 0) {
            emit BatchExpired(expiredCount);
        }
    }

    /// @inheritdoc ICrossChainMEVShield
    function configureShield(
        uint32 sourceChainId,
        uint32 destChainId,
        uint256 commitmentDelay,
        uint256 revealWindow
    ) external onlyRole(GOVERNANCE_ROLE) {
        if (
            commitmentDelay < MIN_COMMITMENT_DELAY ||
            commitmentDelay > MAX_COMMITMENT_DELAY
        ) {
            revert InvalidShieldConfig(commitmentDelay, revealWindow);
        }
        if (
            revealWindow < MIN_REVEAL_WINDOW || revealWindow > MAX_REVEAL_WINDOW
        ) {
            revert InvalidShieldConfig(commitmentDelay, revealWindow);
        }

        bytes32 key = _chainPairKey(sourceChainId, destChainId);
        _shieldConfigs[key] = ShieldConfig({
            commitmentDelay: commitmentDelay,
            revealWindow: revealWindow
        });
        _configured[key] = true;

        emit ShieldConfigUpdated(
            sourceChainId,
            destChainId,
            commitmentDelay,
            revealWindow
        );
    }

    /*//////////////////////////////////////////////////////////////
                          EXTERNAL — VIEW
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc ICrossChainMEVShield
    function getCommitment(
        bytes32 commitId
    ) external view returns (Commitment memory) {
        if (_commitments[commitId].committer == address(0)) {
            revert CommitmentDoesNotExist(commitId);
        }
        return _commitments[commitId];
    }

    /// @inheritdoc ICrossChainMEVShield
    function getShieldConfig(
        uint32 sourceChainId,
        uint32 destChainId
    )
        external
        view
        returns (uint256 commitmentDelay, uint256 revealWindow, bool configured)
    {
        bytes32 key = _chainPairKey(sourceChainId, destChainId);
        if (_configured[key]) {
            ShieldConfig storage cfg = _shieldConfigs[key];
            return (cfg.commitmentDelay, cfg.revealWindow, true);
        }
        return (DEFAULT_COMMITMENT_DELAY, DEFAULT_REVEAL_WINDOW, false);
    }

    /// @inheritdoc ICrossChainMEVShield
    function isReadyToReveal(bytes32 commitId) external view returns (bool) {
        Commitment storage c = _commitments[commitId];
        if (c.committer == address(0) || c.revealed || c.expired) return false;

        (uint256 delay, , ) = _getEffectiveConfig(
            c.sourceChainId,
            c.destChainId
        );
        uint256 readyBlock = c.commitBlock + delay;

        return
            block.number >= readyBlock && block.number <= c.revealDeadlineBlock;
    }

    /// @inheritdoc ICrossChainMEVShield
    function getEffectivenessRate()
        external
        view
        returns (uint256 _totalCommits, uint256 _successfulReveals)
    {
        return (totalCommits, successfulReveals);
    }

    /*//////////////////////////////////////////////////////////////
                            INTERNAL
    //////////////////////////////////////////////////////////////*/

    /// @dev Key for chain pair lookups
    function _chainPairKey(
        uint32 src,
        uint32 dst
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(src, dst));
    }

    /// @dev Get effective config for a chain pair (falls back to defaults)
    function _getEffectiveConfig(
        uint32 sourceChainId,
        uint32 destChainId
    )
        internal
        view
        returns (uint256 commitmentDelay, uint256 revealWindow, bool configured)
    {
        bytes32 key = _chainPairKey(sourceChainId, destChainId);
        if (_configured[key]) {
            ShieldConfig storage cfg = _shieldConfigs[key];
            return (cfg.commitmentDelay, cfg.revealWindow, true);
        }
        return (DEFAULT_COMMITMENT_DELAY, DEFAULT_REVEAL_WINDOW, false);
    }
}
