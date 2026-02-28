// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title IEpochExpiryManager
 * @notice Interface for epoch-based automatic expiry of ZKBoundStateLocks
 * @dev Inspired by Arcium's single-epoch computation finality — prevents "stuck locks"
 *      by auto-expiring state locks after a configurable number of epochs
 */
interface IEpochExpiryManager {
    /*//////////////////////////////////////////////////////////////
                                STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Epoch configuration per chain pair
    struct EpochConfig {
        uint256 epochDuration; // seconds per epoch
        uint256 epochsToExpiry; // number of epochs before auto-expiry
        uint64 genesisTimestamp; // epoch counting starts here
    }

    /// @notice A lock tracked by the expiry manager
    struct ManagedLock {
        bytes32 lockId;
        address locker;
        uint32 sourceChainId;
        uint32 destChainId;
        uint256 createdEpoch;
        uint256 expiryEpoch;
        bool expired;
        bool reclaimed;
    }

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event LockRegistered(
        bytes32 indexed lockId,
        address indexed locker,
        uint256 createdEpoch,
        uint256 expiryEpoch
    );

    event LockExpired(
        bytes32 indexed lockId,
        uint256 currentEpoch,
        uint256 expiryEpoch
    );

    event LockReclaimed(bytes32 indexed lockId, address indexed locker);

    event EpochConfigUpdated(
        uint32 indexed sourceChainId,
        uint32 indexed destChainId,
        uint256 epochDuration,
        uint256 epochsToExpiry
    );

    event BatchExpired(uint256 count, uint256 epoch);

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    error LockAlreadyManaged(bytes32 lockId);
    error LockNotManaged(bytes32 lockId);
    error LockNotExpired(
        bytes32 lockId,
        uint256 currentEpoch,
        uint256 expiryEpoch
    );
    error LockAlreadyReclaimed(bytes32 lockId);
    error NotLockOwner(bytes32 lockId, address caller);
    error InvalidEpochDuration(uint256 duration);
    error InvalidEpochsToExpiry(uint256 epochs);

    /*//////////////////////////////////////////////////////////////
                            EXTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function registerLock(
        bytes32 lockId,
        uint32 sourceChainId,
        uint32 destChainId
    ) external;

    function checkAndExpire(bytes32 lockId) external returns (bool expired);

    function reclaimExpired(bytes32 lockId) external;

    function batchExpire(
        bytes32[] calldata lockIds
    ) external returns (uint256 expiredCount);

    function configureEpoch(
        uint32 sourceChainId,
        uint32 destChainId,
        uint256 epochDuration,
        uint256 epochsToExpiry
    ) external;

    function getCurrentEpoch(
        uint32 sourceChainId,
        uint32 destChainId
    ) external view returns (uint256);

    function getLock(bytes32 lockId) external view returns (ManagedLock memory);

    function isExpired(bytes32 lockId) external view returns (bool);

    function getEpochConfig(
        uint32 sourceChainId,
        uint32 destChainId
    )
        external
        view
        returns (
            uint256 epochDuration,
            uint256 epochsToExpiry,
            uint64 genesisTimestamp,
            bool configured
        );
}
