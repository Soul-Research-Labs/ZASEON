// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IEpochExpiryManager} from "../interfaces/IEpochExpiryManager.sol";

/**
 * @title EpochExpiryManager
 * @author ZASEON
 * @notice Epoch-based automatic expiry for ZKBoundStateLocks
 * @dev Inspired by Arcium's single-epoch computation finality. Prevents "stuck locks"
 *      by dividing time into configurable epochs and auto-expiring locks that exceed
 *      a configurable number of epochs.
 *
 * ARCHITECTURE:
 * ┌─────────────────────────────────────────────────────────────────────┐
 * │                    EPOCH EXPIRY MANAGER                             │
 * ├─────────────────────────────────────────────────────────────────────┤
 * │                                                                     │
 * │  TIME:  ──┬──────┬──────┬──────┬──────┬──────┬──────┬──→          │
 * │           E0     E1     E2     E3     E4     E5     E6             │
 * │                                                                     │
 * │  Lock created at E1, epochsToExpiry=3:                             │
 * │           ╠══════╬══════╬══════╣                                    │
 * │           E1     E2     E3     E4 ← expires here                   │
 * │                                                                     │
 * │  registerLock() → checkAndExpire() → reclaimExpired()              │
 * │                                                                     │
 * │  CONFIG: Per chain pair — different L2s may need different epochs   │
 * │          Default: 1 hour epochs, 24 epochs to expiry (= 24 hours) │
 * └─────────────────────────────────────────────────────────────────────┘
 *
 * SECURITY:
 * - Only lock owner can reclaim expired locks
 * - Epoch configs set by GOVERNANCE_ROLE
 * - Lock registration by LOCK_MANAGER_ROLE (held by ZKBoundStateLocks)
 * - ReentrancyGuard on reclaim operations
 * - Batch expiry for gas-efficient cleanup
 */
contract EpochExpiryManager is
    IEpochExpiryManager,
    AccessControl,
    ReentrancyGuard
{
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    /// @notice Role for governance epoch configuration
    bytes32 public constant GOVERNANCE_ROLE = keccak256("GOVERNANCE_ROLE");

    /// @notice Role for lock registration (held by ZKBoundStateLocks)
    bytes32 public constant LOCK_MANAGER_ROLE = keccak256("LOCK_MANAGER_ROLE");

    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Default epoch duration: 1 hour
    uint256 public constant DEFAULT_EPOCH_DURATION = 1 hours;

    /// @notice Default epochs to expiry: 24 (= 24 hours with default duration)
    uint256 public constant DEFAULT_EPOCHS_TO_EXPIRY = 24;

    /// @notice Minimum allowed epoch duration: 5 minutes
    uint256 public constant MIN_EPOCH_DURATION = 5 minutes;

    /// @notice Maximum allowed epoch duration: 7 days
    uint256 public constant MAX_EPOCH_DURATION = 7 days;

    /// @notice Minimum epochs to expiry
    uint256 public constant MIN_EPOCHS_TO_EXPIRY = 1;

    /// @notice Maximum epochs to expiry
    uint256 public constant MAX_EPOCHS_TO_EXPIRY = 1000;

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Epoch config per chain pair
    mapping(bytes32 => EpochConfig) private _epochConfigs;

    /// @notice Whether a chain pair has been configured
    mapping(bytes32 => bool) private _configured;

    /// @notice Managed locks
    mapping(bytes32 => ManagedLock) private _locks;

    /// @notice Default genesis timestamp (set at deploy)
    uint64 public immutable defaultGenesis;

    /// @notice Total locks registered
    uint256 public totalLocks;

    /// @notice Total locks expired
    uint256 public totalExpired;

    /// @notice Total locks reclaimed
    uint256 public totalReclaimed;

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @param admin Address granted DEFAULT_ADMIN_ROLE
    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(GOVERNANCE_ROLE, admin);
        defaultGenesis = uint64(block.timestamp);
    }

    /*//////////////////////////////////////////////////////////////
                         EXTERNAL — WRITE
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IEpochExpiryManager
    function registerLock(
        bytes32 lockId,
        uint32 sourceChainId,
        uint32 destChainId
    ) external onlyRole(LOCK_MANAGER_ROLE) {
        if (_locks[lockId].locker != address(0)) {
            revert LockAlreadyManaged(lockId);
        }

        (
            uint256 epochDuration,
            uint256 epochsToExpiry,
            uint64 genesis,

        ) = _getEffectiveConfig(sourceChainId, destChainId);

        uint256 currentEpoch = _computeEpoch(
            block.timestamp,
            genesis,
            epochDuration
        );
        uint256 expiryEpoch = currentEpoch + epochsToExpiry;

        _locks[lockId] = ManagedLock({
            lockId: lockId,
            locker: msg.sender,
            sourceChainId: sourceChainId,
            destChainId: destChainId,
            createdEpoch: currentEpoch,
            expiryEpoch: expiryEpoch,
            expired: false,
            reclaimed: false
        });

        totalLocks++;

        emit LockRegistered(lockId, msg.sender, currentEpoch, expiryEpoch);
    }

    /// @inheritdoc IEpochExpiryManager
    function checkAndExpire(bytes32 lockId) external returns (bool expired) {
        ManagedLock storage lock = _locks[lockId];
        if (lock.locker == address(0)) revert LockNotManaged(lockId);
        if (lock.expired) return true; // already expired

        (uint256 epochDuration, , uint64 genesis, ) = _getEffectiveConfig(
            lock.sourceChainId,
            lock.destChainId
        );
        uint256 currentEpoch = _computeEpoch(
            block.timestamp,
            genesis,
            epochDuration
        );

        if (currentEpoch >= lock.expiryEpoch) {
            lock.expired = true;
            totalExpired++;
            emit LockExpired(lockId, currentEpoch, lock.expiryEpoch);
            return true;
        }

        return false;
    }

    /// @inheritdoc IEpochExpiryManager
    function reclaimExpired(bytes32 lockId) external nonReentrant {
        ManagedLock storage lock = _locks[lockId];
        if (lock.locker == address(0)) revert LockNotManaged(lockId);
        if (lock.reclaimed) revert LockAlreadyReclaimed(lockId);

        // Check expiry
        (uint256 epochDuration, , uint64 genesis, ) = _getEffectiveConfig(
            lock.sourceChainId,
            lock.destChainId
        );
        uint256 currentEpoch = _computeEpoch(
            block.timestamp,
            genesis,
            epochDuration
        );

        if (!lock.expired && currentEpoch < lock.expiryEpoch) {
            revert LockNotExpired(lockId, currentEpoch, lock.expiryEpoch);
        }

        // Mark as expired if not already
        if (!lock.expired) {
            lock.expired = true;
            totalExpired++;
            emit LockExpired(lockId, currentEpoch, lock.expiryEpoch);
        }

        // Only original locker can reclaim
        if (lock.locker != msg.sender) {
            revert NotLockOwner(lockId, msg.sender);
        }

        lock.reclaimed = true;
        totalReclaimed++;

        emit LockReclaimed(lockId, msg.sender);
    }

    /// @inheritdoc IEpochExpiryManager
    function batchExpire(
        bytes32[] calldata lockIds
    ) external returns (uint256 expiredCount) {
        for (uint256 i; i < lockIds.length; i++) {
            ManagedLock storage lock = _locks[lockIds[i]];
            if (lock.locker == address(0) || lock.expired) continue;

            (uint256 epochDuration, , uint64 genesis, ) = _getEffectiveConfig(
                lock.sourceChainId,
                lock.destChainId
            );
            uint256 currentEpoch = _computeEpoch(
                block.timestamp,
                genesis,
                epochDuration
            );

            if (currentEpoch >= lock.expiryEpoch) {
                lock.expired = true;
                totalExpired++;
                expiredCount++;
                emit LockExpired(lockIds[i], currentEpoch, lock.expiryEpoch);
            }
        }

        if (expiredCount > 0) {
            (uint256 ed, , uint64 gen, ) = _getEffectiveConfig(0, 0);
            uint256 currentEpoch = _computeEpoch(block.timestamp, gen, ed);
            emit BatchExpired(expiredCount, currentEpoch);
        }
    }

    /// @inheritdoc IEpochExpiryManager
    function configureEpoch(
        uint32 sourceChainId,
        uint32 destChainId,
        uint256 epochDuration,
        uint256 epochsToExpiry
    ) external onlyRole(GOVERNANCE_ROLE) {
        if (
            epochDuration < MIN_EPOCH_DURATION ||
            epochDuration > MAX_EPOCH_DURATION
        ) {
            revert InvalidEpochDuration(epochDuration);
        }
        if (
            epochsToExpiry < MIN_EPOCHS_TO_EXPIRY ||
            epochsToExpiry > MAX_EPOCHS_TO_EXPIRY
        ) {
            revert InvalidEpochsToExpiry(epochsToExpiry);
        }

        bytes32 key = _chainPairKey(sourceChainId, destChainId);

        // If first time configuring, set genesis to now
        if (!_configured[key]) {
            _epochConfigs[key] = EpochConfig({
                epochDuration: epochDuration,
                epochsToExpiry: epochsToExpiry,
                genesisTimestamp: uint64(block.timestamp)
            });
            _configured[key] = true;
        } else {
            _epochConfigs[key].epochDuration = epochDuration;
            _epochConfigs[key].epochsToExpiry = epochsToExpiry;
        }

        emit EpochConfigUpdated(
            sourceChainId,
            destChainId,
            epochDuration,
            epochsToExpiry
        );
    }

    /*//////////////////////////////////////////////////////////////
                          EXTERNAL — VIEW
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IEpochExpiryManager
    function getCurrentEpoch(
        uint32 sourceChainId,
        uint32 destChainId
    ) external view returns (uint256) {
        (uint256 epochDuration, , uint64 genesis, ) = _getEffectiveConfig(
            sourceChainId,
            destChainId
        );
        return _computeEpoch(block.timestamp, genesis, epochDuration);
    }

    /// @inheritdoc IEpochExpiryManager
    function getLock(
        bytes32 lockId
    ) external view returns (ManagedLock memory) {
        if (_locks[lockId].locker == address(0)) revert LockNotManaged(lockId);
        return _locks[lockId];
    }

    /// @inheritdoc IEpochExpiryManager
    function isExpired(bytes32 lockId) external view returns (bool) {
        ManagedLock storage lock = _locks[lockId];
        if (lock.locker == address(0)) revert LockNotManaged(lockId);
        if (lock.expired) return true;

        (uint256 epochDuration, , uint64 genesis, ) = _getEffectiveConfig(
            lock.sourceChainId,
            lock.destChainId
        );
        uint256 currentEpoch = _computeEpoch(
            block.timestamp,
            genesis,
            epochDuration
        );
        return currentEpoch >= lock.expiryEpoch;
    }

    /// @inheritdoc IEpochExpiryManager
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
        )
    {
        bytes32 key = _chainPairKey(sourceChainId, destChainId);
        if (_configured[key]) {
            EpochConfig storage cfg = _epochConfigs[key];
            return (
                cfg.epochDuration,
                cfg.epochsToExpiry,
                cfg.genesisTimestamp,
                true
            );
        }
        return (
            DEFAULT_EPOCH_DURATION,
            DEFAULT_EPOCHS_TO_EXPIRY,
            defaultGenesis,
            false
        );
    }

    /*//////////////////////////////////////////////////////////////
                            INTERNAL
    //////////////////////////////////////////////////////////////*/

    /// @dev Key for chain-pair lookups
    function _chainPairKey(
        uint32 src,
        uint32 dst
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(src, dst));
    }

    /// @dev Compute current epoch from timestamp, genesis, and duration
    function _computeEpoch(
        uint256 timestamp,
        uint64 genesis,
        uint256 epochDuration
    ) internal pure returns (uint256) {
        if (timestamp < genesis) return 0;
        return (timestamp - genesis) / epochDuration;
    }

    /// @dev Get effective config for a chain pair (falls back to defaults)
    function _getEffectiveConfig(
        uint32 sourceChainId,
        uint32 destChainId
    )
        internal
        view
        returns (
            uint256 epochDuration,
            uint256 epochsToExpiry,
            uint64 genesisTimestamp,
            bool configured
        )
    {
        bytes32 key = _chainPairKey(sourceChainId, destChainId);
        if (_configured[key]) {
            EpochConfig storage cfg = _epochConfigs[key];
            return (
                cfg.epochDuration,
                cfg.epochsToExpiry,
                cfg.genesisTimestamp,
                true
            );
        }
        return (
            DEFAULT_EPOCH_DURATION,
            DEFAULT_EPOCHS_TO_EXPIRY,
            defaultGenesis,
            false
        );
    }
}
