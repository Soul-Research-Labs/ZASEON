// SPDX-License-Identifier: MIT
// Coverage stub – assembly-free StealthAddressRegistry
pragma solidity ^0.8.24;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

interface IDerivationVerifier {
    function verifyProof(
        bytes calldata proof,
        uint256[] calldata publicInputs
    ) external view returns (bool valid);
}

contract StealthAddressRegistry is
    Initializable,
    UUPSUpgradeable,
    AccessControlUpgradeable,
    ReentrancyGuardUpgradeable
{
    bytes32 public constant OPERATOR_ROLE =
        0x97667070c54ef182b0f5858b034beac1b6f3089aa2d3188bb1e8929f4fa9b929;
    bytes32 public constant ANNOUNCER_ROLE =
        0x28bf751bc1d0e1ce1e07469dfe6d05c5c0e65f1e92e0f41bfd3cc6c120c1ec3c;
    bytes32 public constant UPGRADER_ROLE =
        0x189ab7a9244df0848122154315af71fe140f3db0fe014031783b0946b8c9d2e3;
    uint256 public constant SECP256K1_N =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    uint256 public constant ED25519_L =
        0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED;
    uint256 public constant BLS12_381_R =
        0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001;
    bytes32 public constant STEALTH_DOMAIN =
        keccak256("Soul_STEALTH_ADDRESS_V1");
    uint256 public constant MAX_ANNOUNCEMENTS = 1000;
    uint256 public constant ANNOUNCEMENT_EXPIRY = 90 days;
    uint256 public constant MIN_DERIVATION_PROOF_LENGTH = 192;

    enum CurveType {
        SECP256K1,
        ED25519,
        BLS12_381,
        PALLAS,
        VESTA,
        BN254
    }
    enum KeyStatus {
        INACTIVE,
        ACTIVE,
        REVOKED
    }

    struct StealthMetaAddress {
        bytes spendingPubKey;
        bytes viewingPubKey;
        CurveType curveType;
        KeyStatus status;
        uint256 registeredAt;
        uint256 schemeId;
    }
    struct Announcement {
        bytes32 schemeId;
        address stealthAddress;
        bytes ephemeralPubKey;
        bytes viewTag;
        bytes metadata;
        uint256 timestamp;
        uint256 chainId;
    }
    struct CrossChainStealth {
        bytes32 sourceStealthKey;
        bytes32 destStealthKey;
        uint256 sourceChainId;
        uint256 destChainId;
        bytes derivationProof;
        uint256 timestamp;
    }
    struct DualKeyStealth {
        bytes32 spendingPubKeyHash;
        bytes32 viewingPubKeyHash;
        bytes32 stealthAddressHash;
        bytes32 ephemeralPubKeyHash;
        bytes32 sharedSecretHash;
        address derivedAddress;
        uint256 chainId;
    }

    mapping(address => StealthMetaAddress) public metaAddresses;
    address[] public registeredAddresses;
    mapping(address => Announcement) public announcements;
    mapping(address => Announcement[]) public recipientAnnouncements;
    mapping(bytes32 => CrossChainStealth) public crossChainBindings;
    mapping(bytes32 => DualKeyStealth) public dualKeyRecords;
    mapping(bytes1 => address[]) public viewTagIndex;
    uint256 public totalAnnouncements;
    uint256 public totalCrossChainDerivations;
    IDerivationVerifier public derivationVerifier;

    event MetaAddressRegistered(
        address indexed owner,
        bytes spendingPubKey,
        bytes viewingPubKey,
        CurveType curveType,
        uint256 schemeId
    );
    event MetaAddressUpdated(address indexed owner, KeyStatus newStatus);
    event StealthAnnouncement(
        bytes32 indexed schemeId,
        address indexed stealthAddress,
        address indexed caller,
        bytes ephemeralPubKey,
        bytes viewTag,
        bytes metadata
    );
    event CrossChainStealthDerived(
        bytes32 indexed sourceKey,
        bytes32 indexed destKey,
        uint256 sourceChainId,
        uint256 destChainId
    );
    event DualKeyStealthGenerated(
        bytes32 indexed stealthHash,
        address indexed derivedAddress,
        uint256 chainId
    );
    event DerivationVerifierUpdated(
        address indexed oldVerifier,
        address indexed newVerifier
    );

    error InvalidPubKey();
    error MetaAddressAlreadyExists();
    error MetaAddressNotFound();
    error MetaAddressRevoked();
    error InvalidCurveType();
    error InvalidSchemeId();
    error AnnouncementNotFound();
    error CrossChainBindingExists();
    error InvalidProof();
    error ZeroAddress();
    error InsufficientFee();
    error InvalidSecp256k1Key();
    error InvalidEd25519Key();
    error InvalidBLSKey();
    error InvalidBN254Key();

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address admin) external initializer {
        __AccessControl_init();
        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(OPERATOR_ROLE, admin);
        _grantRole(UPGRADER_ROLE, admin);
    }

    function _authorizeUpgrade(
        address
    ) internal override onlyRole(UPGRADER_ROLE) {}

    function setDerivationVerifier(
        address _verifier
    ) external onlyRole(OPERATOR_ROLE) {
        emit DerivationVerifierUpdated(address(derivationVerifier), _verifier);
        derivationVerifier = IDerivationVerifier(_verifier);
    }

    function registerMetaAddress(
        bytes calldata spendingPubKey,
        bytes calldata viewingPubKey,
        CurveType curveType,
        uint256 schemeId
    ) external {
        if (metaAddresses[msg.sender].registeredAt != 0)
            revert MetaAddressAlreadyExists();
        if (spendingPubKey.length == 0) revert InvalidPubKey();
        metaAddresses[msg.sender] = StealthMetaAddress(
            spendingPubKey,
            viewingPubKey,
            curveType,
            KeyStatus.ACTIVE,
            block.timestamp,
            schemeId
        );
        registeredAddresses.push(msg.sender);
        emit MetaAddressRegistered(
            msg.sender,
            spendingPubKey,
            viewingPubKey,
            curveType,
            schemeId
        );
    }

    function updateMetaAddressStatus(KeyStatus newStatus) external {
        if (metaAddresses[msg.sender].registeredAt == 0)
            revert MetaAddressNotFound();
        metaAddresses[msg.sender].status = newStatus;
        emit MetaAddressUpdated(msg.sender, newStatus);
    }

    function revokeMetaAddress() external {
        if (metaAddresses[msg.sender].registeredAt == 0)
            revert MetaAddressNotFound();
        metaAddresses[msg.sender].status = KeyStatus.REVOKED;
        emit MetaAddressUpdated(msg.sender, KeyStatus.REVOKED);
    }

    function deriveStealthAddress(
        address,
        bytes calldata ephemeralPubKey,
        bytes calldata viewTag,
        bytes calldata metadata
    ) external returns (address stealthAddress) {
        stealthAddress = address(
            uint160(
                uint256(
                    keccak256(
                        abi.encodePacked(
                            ephemeralPubKey,
                            msg.sender,
                            block.timestamp
                        )
                    )
                )
            )
        );
        announcements[stealthAddress] = Announcement(
            bytes32(0),
            stealthAddress,
            ephemeralPubKey,
            viewTag,
            metadata,
            block.timestamp,
            block.chainid
        );
        totalAnnouncements++;
    }

    function computeDualKeyStealth(
        bytes32 spendingPubKeyHash,
        bytes32 viewingPubKeyHash,
        bytes32 ephemeralPubKeyHash,
        bytes32 sharedSecretHash,
        address derivedAddress
    ) external returns (bytes32 recordId) {
        recordId = keccak256(
            abi.encodePacked(
                spendingPubKeyHash,
                viewingPubKeyHash,
                derivedAddress
            )
        );
        dualKeyRecords[recordId] = DualKeyStealth(
            spendingPubKeyHash,
            viewingPubKeyHash,
            keccak256(abi.encodePacked(derivedAddress)),
            ephemeralPubKeyHash,
            sharedSecretHash,
            derivedAddress,
            block.chainid
        );
        emit DualKeyStealthGenerated(recordId, derivedAddress, block.chainid);
    }

    function announce(
        bytes32 schemeId,
        address stealthAddress,
        bytes calldata ephemeralPubKey,
        bytes calldata viewTag,
        bytes calldata metadata
    ) external {
        announcements[stealthAddress] = Announcement(
            schemeId,
            stealthAddress,
            ephemeralPubKey,
            viewTag,
            metadata,
            block.timestamp,
            block.chainid
        );
        if (viewTag.length > 0) viewTagIndex[viewTag[0]].push(stealthAddress);
        totalAnnouncements++;
        emit StealthAnnouncement(
            schemeId,
            stealthAddress,
            msg.sender,
            ephemeralPubKey,
            viewTag,
            metadata
        );
    }

    function announcePrivate(
        bytes32 schemeId,
        address stealthAddress,
        bytes calldata ephemeralPubKey,
        bytes calldata viewTag,
        bytes calldata metadata,
        bytes calldata
    ) external {
        announcements[stealthAddress] = Announcement(
            schemeId,
            stealthAddress,
            ephemeralPubKey,
            viewTag,
            metadata,
            block.timestamp,
            block.chainid
        );
        totalAnnouncements++;
        emit StealthAnnouncement(
            schemeId,
            stealthAddress,
            msg.sender,
            ephemeralPubKey,
            viewTag,
            metadata
        );
    }

    function getAnnouncementsByViewTag(
        bytes1 viewTag
    ) external view returns (address[] memory) {
        return viewTagIndex[viewTag];
    }

    function checkStealthOwnership(
        address,
        bytes calldata,
        uint256
    ) external pure returns (bool) {
        return true;
    }

    function batchScan(
        bytes1[] calldata viewTags
    ) external view returns (address[][] memory results) {
        results = new address[][](viewTags.length);
        for (uint256 i = 0; i < viewTags.length; i++) {
            results[i] = viewTagIndex[viewTags[i]];
        }
    }

    function deriveCrossChainStealth(
        bytes32 sourceStealthKey,
        uint256 destChainId,
        bytes calldata derivationProof
    ) external returns (bytes32 destStealthKey) {
        destStealthKey = keccak256(
            abi.encodePacked(sourceStealthKey, destChainId)
        );
        crossChainBindings[destStealthKey] = CrossChainStealth(
            sourceStealthKey,
            destStealthKey,
            block.chainid,
            destChainId,
            derivationProof,
            block.timestamp
        );
        totalCrossChainDerivations++;
        emit CrossChainStealthDerived(
            sourceStealthKey,
            destStealthKey,
            block.chainid,
            destChainId
        );
    }

    function getMetaAddress(
        address owner
    ) external view returns (StealthMetaAddress memory) {
        return metaAddresses[owner];
    }

    function getAnnouncement(
        address stealthAddress
    ) external view returns (Announcement memory) {
        return announcements[stealthAddress];
    }

    function getDualKeyRecord(
        bytes32 recordId
    ) external view returns (DualKeyStealth memory) {
        return dualKeyRecords[recordId];
    }

    function getCrossChainBinding(
        bytes32 bindingId
    ) external view returns (CrossChainStealth memory) {
        return crossChainBindings[bindingId];
    }

    function getRegisteredAddressCount() external view returns (uint256) {
        return registeredAddresses.length;
    }

    function getStats()
        external
        view
        returns (
            uint256 totalRegistered,
            uint256 totalAnnouncementCount,
            uint256 totalCrossChain
        )
    {
        return (
            registeredAddresses.length,
            totalAnnouncements,
            totalCrossChainDerivations
        );
    }

    function withdrawFees(
        address payable recipient
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        (bool ok, ) = recipient.call{value: address(this).balance}("");
        require(ok);
    }
}
