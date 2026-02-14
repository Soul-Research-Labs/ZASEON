// SPDX-License-Identifier: AGPL-3.0-only
// Coverage stub – assembly-free ZKBoundStateLocks
pragma solidity ^0.8.20;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {IProofVerifier} from "../interfaces/IProofVerifier.sol";

contract ZKBoundStateLocks is AccessControl, ReentrancyGuard, Pausable {
    bytes32 public constant LOCK_ADMIN_ROLE = keccak256("LOCK_ADMIN_ROLE");
    bytes32 public constant VERIFIER_ADMIN_ROLE =
        keccak256("VERIFIER_ADMIN_ROLE");
    bytes32 public constant DOMAIN_ADMIN_ROLE = keccak256("DOMAIN_ADMIN_ROLE");
    bytes32 public constant DISPUTE_RESOLVER_ROLE =
        keccak256("DISPUTE_RESOLVER_ROLE");
    bytes32 public constant OPERATOR_ROLE =
        0x97667070c54ef182b0f5858b034beac1b6f3089aa2d3188bb1e8929f4fa9b929;
    bytes32 public constant RECOVERY_ROLE = keccak256("RECOVERY_ROLE");

    enum LockStatus {
        Active,
        PendingUnlock,
        Unlocked,
        Disputed,
        Recovered,
        Expired
    }

    struct ZKSLock {
        bytes32 lockId;
        bytes32 commitment;
        bytes32 nullifier;
        bytes32 domainSeparator;
        address creator;
        uint256 sourceChainId;
        uint256 destChainId;
        uint64 createdAt;
        uint64 expiresAt;
        uint64 unlockedAt;
        LockStatus status;
        bytes32 proofVerifierType;
        bool optimistic;
        bytes32 optimisticProofHash;
        uint64 optimisticSubmittedAt;
    }

    struct DomainConfig {
        bytes32 domainSeparator;
        string name;
        uint256 chainId;
        bool active;
        uint256 defaultExpiry;
    }

    IProofVerifier public proofVerifier;
    mapping(bytes32 => ZKSLock) private _locks;
    mapping(bytes32 => IProofVerifier) private _verifiers;
    mapping(bytes32 => DomainConfig) private _domains;
    mapping(bytes32 => bytes32[]) private _commitmentChains;
    bytes32[] private _activeLockIds;
    mapping(bytes32 => uint256) private _activeLockIndex;

    uint256 private _totalLocksCreated;
    uint256 private _totalLocksUnlocked;
    uint256 private _totalOptimisticUnlocks;
    uint256 private _totalDisputes;
    uint256 public constant CHALLENGE_WINDOW = 1 hours;
    uint256 public constant DEFAULT_LOCK_EXPIRY = 24 hours;

    event LockCreated(
        bytes32 indexed lockId,
        bytes32 indexed commitment,
        address indexed creator,
        uint256 sourceChainId,
        uint256 destChainId
    );
    event LockUnlocked(
        bytes32 indexed lockId,
        bytes32 indexed nullifier,
        address indexed unlocker
    );
    event OptimisticUnlockSubmitted(
        bytes32 indexed lockId,
        bytes32 proofHash,
        address indexed submitter
    );
    event OptimisticUnlockFinalized(bytes32 indexed lockId);
    event OptimisticUnlockChallenged(
        bytes32 indexed lockId,
        address indexed challenger
    );
    event LockRecovered(bytes32 indexed lockId, address indexed recoverer);
    event VerifierRegistered(
        bytes32 indexed proofType,
        address indexed verifierAddr
    );
    event DomainRegistered(
        bytes32 indexed domainSeparator,
        string name,
        uint256 chainId
    );

    error LockNotFound(bytes32 lockId);
    error LockNotActive(bytes32 lockId);
    error LockExpired(bytes32 lockId);
    error InvalidProof();
    error NullifierAlreadyUsed(bytes32 nullifier);
    error CommitmentAlreadyLocked(bytes32 commitment);
    error ChallengeWindowNotPassed(bytes32 lockId);
    error ChallengeWindowPassed(bytes32 lockId);
    error InvalidDomain(bytes32 domain);
    error ZeroAddress();

    mapping(bytes32 => bool) private _usedNullifiers;
    mapping(bytes32 => bool) private _lockedCommitments;
    bool private _roleSeparationConfirmed;

    constructor(address _proofVerifier) {
        if (_proofVerifier == address(0)) revert ZeroAddress();
        proofVerifier = IProofVerifier(_proofVerifier);
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(LOCK_ADMIN_ROLE, msg.sender);
        _grantRole(VERIFIER_ADMIN_ROLE, msg.sender);
        _grantRole(DOMAIN_ADMIN_ROLE, msg.sender);
        _grantRole(OPERATOR_ROLE, msg.sender);
        _grantRole(RECOVERY_ROLE, msg.sender);
    }

    function totalLocksCreated() external view returns (uint256) {
        return _totalLocksCreated;
    }

    function totalLocksUnlocked() external view returns (uint256) {
        return _totalLocksUnlocked;
    }

    function totalOptimisticUnlocks() external view returns (uint256) {
        return _totalOptimisticUnlocks;
    }

    function totalDisputes() external view returns (uint256) {
        return _totalDisputes;
    }

    function createLock(
        bytes32 commitment,
        bytes32 domainSeparator,
        uint256 destChainId,
        uint256 expiry,
        bytes32 proofVerifierType
    ) external whenNotPaused returns (bytes32 lockId) {
        if (_lockedCommitments[commitment])
            revert CommitmentAlreadyLocked(commitment);
        lockId = keccak256(
            abi.encodePacked(
                commitment,
                msg.sender,
                block.timestamp,
                _totalLocksCreated
            )
        );
        _locks[lockId] = ZKSLock({
            lockId: lockId,
            commitment: commitment,
            nullifier: bytes32(0),
            domainSeparator: domainSeparator,
            creator: msg.sender,
            sourceChainId: block.chainid,
            destChainId: destChainId,
            createdAt: uint64(block.timestamp),
            expiresAt: uint64(
                block.timestamp + (expiry > 0 ? expiry : DEFAULT_LOCK_EXPIRY)
            ),
            unlockedAt: 0,
            status: LockStatus.Active,
            proofVerifierType: proofVerifierType,
            optimistic: false,
            optimisticProofHash: bytes32(0),
            optimisticSubmittedAt: 0
        });
        _lockedCommitments[commitment] = true;
        _activeLockIds.push(lockId);
        _activeLockIndex[lockId] = _activeLockIds.length - 1;
        _totalLocksCreated++;
        emit LockCreated(
            lockId,
            commitment,
            msg.sender,
            block.chainid,
            destChainId
        );
    }

    function unlock(
        bytes32 lockId,
        bytes32 nullifier,
        bytes calldata proof,
        uint256[] calldata publicInputs
    ) external nonReentrant whenNotPaused {
        ZKSLock storage lock = _locks[lockId];
        if (lock.createdAt == 0) revert LockNotFound(lockId);
        if (lock.status != LockStatus.Active) revert LockNotActive(lockId);
        if (_usedNullifiers[nullifier]) revert NullifierAlreadyUsed(nullifier);
        // Stub: skip actual proof verification
        if (proof.length == 0 && publicInputs.length == 0)
            revert InvalidProof();
        _usedNullifiers[nullifier] = true;
        lock.nullifier = nullifier;
        lock.status = LockStatus.Unlocked;
        lock.unlockedAt = uint64(block.timestamp);
        _totalLocksUnlocked++;
        _removeActiveLock(lockId);
        emit LockUnlocked(lockId, nullifier, msg.sender);
    }

    function optimisticUnlock(
        bytes32 lockId,
        bytes32 proofHash
    ) external whenNotPaused {
        ZKSLock storage lock = _locks[lockId];
        if (lock.createdAt == 0) revert LockNotFound(lockId);
        if (lock.status != LockStatus.Active) revert LockNotActive(lockId);
        lock.optimistic = true;
        lock.optimisticProofHash = proofHash;
        lock.optimisticSubmittedAt = uint64(block.timestamp);
        lock.status = LockStatus.PendingUnlock;
        _totalOptimisticUnlocks++;
        emit OptimisticUnlockSubmitted(lockId, proofHash, msg.sender);
    }

    function finalizeOptimisticUnlock(bytes32 lockId) external nonReentrant {
        ZKSLock storage lock = _locks[lockId];
        if (lock.createdAt == 0) revert LockNotFound(lockId);
        if (lock.status != LockStatus.PendingUnlock)
            revert LockNotActive(lockId);
        if (block.timestamp < lock.optimisticSubmittedAt + CHALLENGE_WINDOW)
            revert ChallengeWindowNotPassed(lockId);
        lock.status = LockStatus.Unlocked;
        lock.unlockedAt = uint64(block.timestamp);
        _totalLocksUnlocked++;
        _removeActiveLock(lockId);
        emit OptimisticUnlockFinalized(lockId);
    }

    function challengeOptimisticUnlock(
        bytes32 lockId,
        bytes calldata,
        uint256[] calldata
    ) external whenNotPaused {
        ZKSLock storage lock = _locks[lockId];
        if (lock.createdAt == 0) revert LockNotFound(lockId);
        if (lock.status != LockStatus.PendingUnlock)
            revert LockNotActive(lockId);
        if (block.timestamp >= lock.optimisticSubmittedAt + CHALLENGE_WINDOW)
            revert ChallengeWindowPassed(lockId);
        lock.status = LockStatus.Disputed;
        _totalDisputes++;
        emit OptimisticUnlockChallenged(lockId, msg.sender);
    }

    function registerVerifier(
        bytes32 proofType,
        address _verifierAddr
    ) external onlyRole(VERIFIER_ADMIN_ROLE) {
        _verifiers[proofType] = IProofVerifier(_verifierAddr);
        emit VerifierRegistered(proofType, _verifierAddr);
    }

    function registerDomain(
        bytes32 domainSeparator,
        string calldata name,
        uint256 chainId,
        uint256 defaultExpiry
    ) external onlyRole(DOMAIN_ADMIN_ROLE) {
        _domains[domainSeparator] = DomainConfig(
            domainSeparator,
            name,
            chainId,
            true,
            defaultExpiry
        );
        emit DomainRegistered(domainSeparator, name, chainId);
    }

    function recoverLock(bytes32 lockId) external onlyRole(RECOVERY_ROLE) {
        ZKSLock storage lock = _locks[lockId];
        if (lock.createdAt == 0) revert LockNotFound(lockId);
        lock.status = LockStatus.Recovered;
        _removeActiveLock(lockId);
        emit LockRecovered(lockId, msg.sender);
    }

    function _removeActiveLock(bytes32 lockId) internal {
        uint256 idx = _activeLockIndex[lockId];
        uint256 lastIdx = _activeLockIds.length - 1;
        if (idx != lastIdx) {
            bytes32 lastLock = _activeLockIds[lastIdx];
            _activeLockIds[idx] = lastLock;
            _activeLockIndex[lastLock] = idx;
        }
        _activeLockIds.pop();
        delete _activeLockIndex[lockId];
    }

    function generateDomainSeparator(
        uint256 chainId,
        string calldata name
    ) external pure returns (bytes32) {
        return keccak256(abi.encodePacked("SOUL_DOMAIN_V1", chainId, name));
    }

    function generateDomainSeparatorExtended(
        uint256 chainId,
        string calldata name,
        uint256 version
    ) external pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked("SOUL_DOMAIN_V1", chainId, name, version)
            );
    }

    function generateNullifier(
        bytes32 commitment,
        bytes32 secret
    ) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(commitment, secret));
    }

    function getActiveLockIds(
        uint256 offset,
        uint256 limit
    ) external view returns (bytes32[] memory result) {
        uint256 total = _activeLockIds.length;
        if (offset >= total) return new bytes32[](0);
        uint256 end = offset + limit > total ? total : offset + limit;
        result = new bytes32[](end - offset);
        for (uint256 i = offset; i < end; i++) {
            result[i - offset] = _activeLockIds[i];
        }
    }

    function getActiveLockCount() external view returns (uint256) {
        return _activeLockIds.length;
    }

    function getActiveLockIds() external view returns (bytes32[] memory) {
        return _activeLockIds;
    }

    function getLock(bytes32 lockId) external view returns (ZKSLock memory) {
        return _locks[lockId];
    }

    function canUnlock(bytes32 lockId) external view returns (bool) {
        ZKSLock storage lock = _locks[lockId];
        return
            lock.status == LockStatus.Active &&
            block.timestamp <= lock.expiresAt;
    }

    function getCommitmentChain(
        bytes32 commitment
    ) external view returns (bytes32[] memory) {
        return _commitmentChains[commitment];
    }

    function getStats()
        external
        view
        returns (
            uint256 created,
            uint256 unlocked,
            uint256 optimistic,
            uint256 disputes,
            uint256 active
        )
    {
        return (
            _totalLocksCreated,
            _totalLocksUnlocked,
            _totalOptimisticUnlocks,
            _totalDisputes,
            _activeLockIds.length
        );
    }

    function confirmRoleSeparation() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _roleSeparationConfirmed = true;
    }

    function pause() external onlyRole(LOCK_ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(LOCK_ADMIN_ROLE) {
        _unpause();
    }
}
