// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title ICrossChainMEVShield
 * @notice Interface for source-chain commit-reveal MEV protection
 * @dev Inspired by Arcium's single mempool MEV protection — uses a 2-phase
 *      commit-reveal scheme to prevent MEV extraction on cross-chain privacy ops
 */
interface ICrossChainMEVShield {
    /*//////////////////////////////////////////////////////////////
                                STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Commitment record for a cross-chain operation
    struct Commitment {
        bytes32 commitHash;
        address committer;
        uint256 commitBlock;
        uint256 revealDeadlineBlock;
        uint32 sourceChainId;
        uint32 destChainId;
        bool revealed;
        bool expired;
    }

    /// @notice MEV shield configuration per chain pair
    struct ShieldConfig {
        uint256 commitmentDelay; // blocks to wait between commit and reveal
        uint256 revealWindow; // blocks after delay before commitment expires
    }

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event CommitmentMade(
        bytes32 indexed commitId,
        address indexed committer,
        uint256 commitBlock,
        uint256 revealDeadlineBlock
    );

    event CommitmentRevealed(
        bytes32 indexed commitId,
        address indexed committer,
        bytes32 operationHash
    );

    event CommitmentExpired(bytes32 indexed commitId);

    event ShieldConfigUpdated(
        uint32 indexed sourceChainId,
        uint32 indexed destChainId,
        uint256 commitmentDelay,
        uint256 revealWindow
    );

    event BatchExpired(uint256 count);

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    error CommitmentAlreadyExists(bytes32 commitId);
    error CommitmentDoesNotExist(bytes32 commitId);
    error CommitmentAlreadyRevealed(bytes32 commitId);
    error CommitmentExpiredError(bytes32 commitId);
    error RevealTooEarly(
        bytes32 commitId,
        uint256 currentBlock,
        uint256 readyBlock
    );
    error RevealTooLate(
        bytes32 commitId,
        uint256 currentBlock,
        uint256 deadline
    );
    error InvalidReveal(
        bytes32 commitId,
        bytes32 expectedHash,
        bytes32 actualHash
    );
    error NotCommitter(bytes32 commitId, address caller);
    error InvalidShieldConfig(uint256 commitmentDelay, uint256 revealWindow);

    /*//////////////////////////////////////////////////////////////
                            EXTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function commit(
        bytes32 commitHash,
        uint32 sourceChainId,
        uint32 destChainId
    ) external returns (bytes32 commitId);

    function reveal(
        bytes32 commitId,
        bytes calldata preimage
    ) external returns (bytes32 operationHash);

    function expireCommitment(bytes32 commitId) external;

    function batchExpire(
        bytes32[] calldata commitIds
    ) external returns (uint256 expiredCount);

    function configureShield(
        uint32 sourceChainId,
        uint32 destChainId,
        uint256 commitmentDelay,
        uint256 revealWindow
    ) external;

    function getCommitment(
        bytes32 commitId
    ) external view returns (Commitment memory);

    function getShieldConfig(
        uint32 sourceChainId,
        uint32 destChainId
    )
        external
        view
        returns (
            uint256 commitmentDelay,
            uint256 revealWindow,
            bool configured
        );

    function isReadyToReveal(bytes32 commitId) external view returns (bool);

    function getEffectivenessRate()
        external
        view
        returns (uint256 totalCommits, uint256 successfulReveals);
}
