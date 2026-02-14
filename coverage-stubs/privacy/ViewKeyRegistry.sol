// SPDX-License-Identifier: MIT
// Coverage stub – assembly-free ViewKeyRegistry
pragma solidity ^0.8.24;

import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

contract ViewKeyRegistry is
    AccessControlUpgradeable,
    PausableUpgradeable,
    ReentrancyGuardUpgradeable,
    UUPSUpgradeable
{
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant REGISTRAR_ROLE = keccak256("REGISTRAR_ROLE");
    uint256 public constant MAX_GRANTS_PER_ACCOUNT = 100;
    uint256 public constant MIN_GRANT_DURATION = 1 hours;
    uint256 public constant MAX_GRANT_DURATION = 365 days;
    uint256 public constant REVOCATION_DELAY = 1 hours;

    enum ViewKeyType {
        INCOMING,
        OUTGOING,
        FULL,
        BALANCE,
        AUDIT
    }
    enum GrantStatus {
        ACTIVE,
        REVOKED,
        EXPIRED,
        PENDING_REVOCATION
    }

    struct ViewKey {
        bytes32 publicKey;
        ViewKeyType keyType;
        bytes32 commitment;
        uint256 registrationTime;
        bool isActive;
    }
    struct ViewGrant {
        bytes32 grantId;
        address granter;
        address grantee;
        bytes32 viewKeyHash;
        ViewKeyType keyType;
        uint256 startTime;
        uint256 endTime;
        GrantStatus status;
        bytes32 scope;
    }
    struct AuditEntry {
        bytes32 grantId;
        address accessor;
        uint256 accessTime;
        bytes32 accessProof;
    }

    mapping(address => mapping(ViewKeyType => ViewKey)) public viewKeys;
    mapping(address => uint256) public activeKeyCount;
    mapping(bytes32 => ViewGrant) public grants;
    mapping(address => bytes32[]) public receivedGrants;
    mapping(address => bytes32[]) public issuedGrants;
    mapping(bytes32 => AuditEntry[]) public auditTrail;
    mapping(address => uint256) public grantNonce;
    uint256 public totalKeysRegistered;
    uint256 public totalGrantsIssued;
    uint256 public totalActiveGrants;

    event ViewKeyRegistered(
        address indexed account,
        ViewKeyType keyType,
        bytes32 publicKey
    );
    event ViewKeyRevoked(address indexed account, ViewKeyType keyType);
    event ViewKeyRotated(
        address indexed account,
        ViewKeyType keyType,
        bytes32 oldKey,
        bytes32 newKey
    );
    event ViewGrantIssued(
        bytes32 indexed grantId,
        address indexed granter,
        address indexed grantee,
        ViewKeyType keyType,
        uint256 endTime
    );
    event ViewGrantRevoked(bytes32 indexed grantId, address indexed revoker);
    event ViewGrantExpired(bytes32 indexed grantId);
    event ViewGrantAccessed(
        bytes32 indexed grantId,
        address indexed accessor,
        bytes32 accessProof
    );

    error KeyAlreadyRegistered();
    error KeyNotRegistered();
    error KeyNotActive();
    error InvalidKeyType();
    error InvalidDuration();
    error MaxGrantsReached();
    error GrantNotFound();
    error GrantNotActive();
    error GrantExpired();
    error UnauthorizedAccess();
    error RevocationPending();
    error InvalidScope();
    error ZeroAddress();

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address admin) external initializer {
        __AccessControl_init();
        __Pausable_init();
        __ReentrancyGuard_init();
        __UUPSUpgradeable_init();
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(ADMIN_ROLE, admin);
    }

    function _authorizeUpgrade(
        address
    ) internal override onlyRole(ADMIN_ROLE) {}

    function registerViewKey(
        bytes32 publicKey,
        ViewKeyType keyType,
        bytes32 commitment
    ) external whenNotPaused {
        if (viewKeys[msg.sender][keyType].isActive)
            revert KeyAlreadyRegistered();
        viewKeys[msg.sender][keyType] = ViewKey(
            publicKey,
            keyType,
            commitment,
            block.timestamp,
            true
        );
        activeKeyCount[msg.sender]++;
        totalKeysRegistered++;
        emit ViewKeyRegistered(msg.sender, keyType, publicKey);
    }

    function revokeViewKey(ViewKeyType keyType) external {
        if (!viewKeys[msg.sender][keyType].isActive) revert KeyNotRegistered();
        viewKeys[msg.sender][keyType].isActive = false;
        activeKeyCount[msg.sender]--;
        emit ViewKeyRevoked(msg.sender, keyType);
    }

    function rotateViewKey(
        ViewKeyType keyType,
        bytes32 newPublicKey,
        bytes32 newCommitment
    ) external whenNotPaused {
        ViewKey storage key = viewKeys[msg.sender][keyType];
        if (!key.isActive) revert KeyNotRegistered();
        bytes32 oldKey = key.publicKey;
        key.publicKey = newPublicKey;
        key.commitment = newCommitment;
        key.registrationTime = block.timestamp;
        emit ViewKeyRotated(msg.sender, keyType, oldKey, newPublicKey);
    }

    function issueGrant(
        address grantee,
        ViewKeyType keyType,
        uint256 duration,
        bytes32 scope
    ) external whenNotPaused returns (bytes32 grantId) {
        if (grantee == address(0)) revert ZeroAddress();
        if (duration < MIN_GRANT_DURATION || duration > MAX_GRANT_DURATION)
            revert InvalidDuration();
        if (receivedGrants[grantee].length >= MAX_GRANTS_PER_ACCOUNT)
            revert MaxGrantsReached();
        grantId = keccak256(
            abi.encodePacked(msg.sender, grantee, grantNonce[msg.sender]++)
        );
        grants[grantId] = ViewGrant(
            grantId,
            msg.sender,
            grantee,
            viewKeys[msg.sender][keyType].publicKey,
            keyType,
            block.timestamp,
            block.timestamp + duration,
            GrantStatus.ACTIVE,
            scope
        );
        receivedGrants[grantee].push(grantId);
        issuedGrants[msg.sender].push(grantId);
        totalGrantsIssued++;
        totalActiveGrants++;
        emit ViewGrantIssued(
            grantId,
            msg.sender,
            grantee,
            keyType,
            block.timestamp + duration
        );
    }

    function issueAuditGrant(
        address auditor,
        uint256 duration,
        bytes32 scope
    ) external returns (bytes32 grantId) {
        return this.issueGrant(auditor, ViewKeyType.AUDIT, duration, scope);
    }

    function revokeGrant(bytes32 grantId) external {
        ViewGrant storage g = grants[grantId];
        if (g.startTime == 0) revert GrantNotFound();
        if (g.granter != msg.sender) revert UnauthorizedAccess();
        g.status = GrantStatus.PENDING_REVOCATION;
        emit ViewGrantRevoked(grantId, msg.sender);
    }

    function finalizeRevocation(bytes32 grantId) external {
        ViewGrant storage g = grants[grantId];
        if (g.status != GrantStatus.PENDING_REVOCATION) revert GrantNotActive();
        g.status = GrantStatus.REVOKED;
        totalActiveGrants--;
    }

    function recordAccess(bytes32 grantId, bytes32 accessProof) external {
        ViewGrant storage g = grants[grantId];
        if (g.startTime == 0) revert GrantNotFound();
        if (g.grantee != msg.sender) revert UnauthorizedAccess();
        auditTrail[grantId].push(
            AuditEntry(grantId, msg.sender, block.timestamp, accessProof)
        );
        emit ViewGrantAccessed(grantId, msg.sender, accessProof);
    }

    function verifyKeyOwnership(
        address account,
        ViewKeyType keyType,
        bytes32 commitment
    ) external view returns (bool) {
        ViewKey storage key = viewKeys[account][keyType];
        return key.isActive && key.commitment == commitment;
    }

    function isGrantValid(bytes32 grantId) external view returns (bool) {
        ViewGrant storage g = grants[grantId];
        return g.status == GrantStatus.ACTIVE && block.timestamp <= g.endTime;
    }

    function getGrantDetails(
        bytes32 grantId
    ) external view returns (ViewGrant memory) {
        return grants[grantId];
    }

    function getActiveGrantsReceived(
        address grantee
    ) external view returns (bytes32[] memory activeGrantIds) {
        bytes32[] storage all = receivedGrants[grantee];
        uint256 count;
        for (uint256 i = 0; i < all.length; i++) {
            if (
                grants[all[i]].status == GrantStatus.ACTIVE &&
                block.timestamp <= grants[all[i]].endTime
            ) count++;
        }
        activeGrantIds = new bytes32[](count);
        uint256 idx;
        for (uint256 i = 0; i < all.length; i++) {
            if (
                grants[all[i]].status == GrantStatus.ACTIVE &&
                block.timestamp <= grants[all[i]].endTime
            ) {
                activeGrantIds[idx++] = all[i];
            }
        }
    }

    function getAuditTrail(
        bytes32 grantId
    ) external view returns (AuditEntry[] memory) {
        return auditTrail[grantId];
    }

    function pause() external onlyRole(ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(ADMIN_ROLE) {
        _unpause();
    }
}
