// SPDX-License-Identifier: MIT
// Coverage stub – assembly-free GasOptimizedPrivacy (3 contracts)
pragma solidity ^0.8.24;

contract GasOptimizedStealthRegistry {
    error InvalidViewTag();
    error InvalidEphemeralKey();
    error InvalidPublicKey();
    error BatchSizeExceeded();
    error StealthAddressAlreadyRegistered();
    error Unauthorized();

    event StealthAddressGenerated(
        bytes32 indexed ephemeralKey,
        address indexed stealthAddress,
        uint8 viewTag
    );
    event BatchStealthGenerated(uint256 indexed batchId, uint256 count);

    struct StealthData {
        uint8 viewTag;
        uint32 timestamp;
        bytes27 reserved;
    }

    mapping(bytes32 => address) public stealthAddresses;
    mapping(address => StealthData) public stealthData;
    uint256 public batchCounter;
    uint256 public constant MAX_BATCH_SIZE = 100;

    function generateStealthAddress(
        uint256 ephemeralKeyX,
        uint256 ephemeralKeyY,
        uint256,
        uint256,
        uint256,
        uint256
    ) external returns (address stealthAddress, uint8 viewTag) {
        bytes32 ephKey = keccak256(
            abi.encodePacked(ephemeralKeyX, ephemeralKeyY)
        );
        stealthAddress = address(
            uint160(uint256(keccak256(abi.encodePacked(ephKey, msg.sender))))
        );
        viewTag = uint8(uint256(ephKey));
        stealthAddresses[ephKey] = stealthAddress;
        stealthData[stealthAddress] = StealthData(
            viewTag,
            uint32(block.timestamp),
            bytes27(0)
        );
        emit StealthAddressGenerated(ephKey, stealthAddress, viewTag);
    }

    function batchGenerateStealthAddresses(
        uint256[2][] calldata ephemeralKeys,
        uint256[4][] calldata
    ) external returns (address[] memory addresses, uint8[] memory viewTags) {
        if (ephemeralKeys.length > MAX_BATCH_SIZE) revert BatchSizeExceeded();
        addresses = new address[](ephemeralKeys.length);
        viewTags = new uint8[](ephemeralKeys.length);
        batchCounter++;
        emit BatchStealthGenerated(batchCounter, ephemeralKeys.length);
    }

    function computeViewTag(
        uint256,
        uint256,
        uint256 ephemeralKeyX,
        uint256 ephemeralKeyY
    ) external pure returns (uint8 viewTag) {
        viewTag = uint8(
            uint256(keccak256(abi.encodePacked(ephemeralKeyX, ephemeralKeyY)))
        );
    }

    function scanByViewTag(
        address[] calldata candidates,
        uint8 targetViewTag
    ) external view returns (address[] memory matches) {
        uint256 count;
        for (uint256 i = 0; i < candidates.length; i++) {
            if (stealthData[candidates[i]].viewTag == targetViewTag) count++;
        }
        matches = new address[](count);
        uint256 idx;
        for (uint256 i = 0; i < candidates.length; i++) {
            if (stealthData[candidates[i]].viewTag == targetViewTag) {
                matches[idx++] = candidates[i];
            }
        }
    }
}

contract GasOptimizedNullifierManager {
    error NullifierAlreadyConsumed();
    error InvalidNullifier();
    error InvalidDomain();
    error BatchSizeExceeded();
    error Unauthorized();

    event NullifierConsumed(
        bytes32 indexed nullifier,
        bytes32 indexed domain,
        uint256 timestamp
    );
    event BatchNullifiersConsumed(bytes32 indexed batchId, uint256 count);

    address public owner;
    mapping(bytes32 => mapping(bytes32 => bool)) public consumed;
    mapping(bytes32 => bool) public registeredDomains;
    uint256 public constant MAX_BATCH_SIZE = 256;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert Unauthorized();
        _;
    }

    function registerDomain(bytes32 domain) external onlyOwner {
        registeredDomains[domain] = true;
    }

    function consumeNullifier(bytes32 nullifier, bytes32 domain) external {
        if (nullifier == bytes32(0)) revert InvalidNullifier();
        if (!registeredDomains[domain]) revert InvalidDomain();
        if (consumed[domain][nullifier]) revert NullifierAlreadyConsumed();
        consumed[domain][nullifier] = true;
        emit NullifierConsumed(nullifier, domain, block.timestamp);
    }

    function batchConsumeNullifiers(
        bytes32[] calldata nullifiers,
        bytes32 domain
    ) external {
        if (nullifiers.length > MAX_BATCH_SIZE) revert BatchSizeExceeded();
        for (uint256 i = 0; i < nullifiers.length; i++) {
            if (consumed[domain][nullifiers[i]])
                revert NullifierAlreadyConsumed();
            consumed[domain][nullifiers[i]] = true;
        }
        emit BatchNullifiersConsumed(
            keccak256(abi.encodePacked(nullifiers)),
            nullifiers.length
        );
    }

    function deriveCrossDomainNullifier(
        bytes32 sourceNullifier,
        bytes32 sourceDomain,
        bytes32 targetDomain
    ) external pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(sourceNullifier, sourceDomain, targetDomain)
            );
    }

    function checkNullifiersBatch(
        bytes32[] calldata nullifiers,
        bytes32 domain
    ) external view returns (uint256 consumedBitmap) {
        for (uint256 i = 0; i < nullifiers.length && i < 256; i++) {
            if (consumed[domain][nullifiers[i]]) {
                consumedBitmap |= (1 << i);
            }
        }
    }
}

contract GasOptimizedRingCT {
    error InvalidRingSize();
    error KeyImageAlreadyUsed();
    error InvalidCommitment();
    error BalanceNotPreserved();
    error InvalidSignature();
    error RingSignatureVerificationNotImplemented();
    error Unauthorized();

    event RingCTTransaction(
        bytes32 indexed txHash,
        bytes32 indexed keyImage,
        uint256 ringSize
    );

    mapping(bytes32 => bool) public usedKeyImages;
    mapping(bytes32 => bool) public commitmentSet;
    address public ringSignatureVerifier;
    address public owner;
    uint256 public constant MIN_RING_SIZE = 2;
    uint256 public constant MAX_RING_SIZE = 16;

    constructor() {
        owner = msg.sender;
    }

    function setRingSignatureVerifier(address verifier) external {
        if (msg.sender != owner) revert Unauthorized();
        ringSignatureVerifier = verifier;
    }

    function processRingCT(
        bytes32[] calldata,
        bytes32[] calldata outputCommitments,
        bytes32[] calldata keyImages,
        bytes calldata,
        bytes32
    ) external {
        for (uint256 i = 0; i < keyImages.length; i++) {
            if (usedKeyImages[keyImages[i]]) revert KeyImageAlreadyUsed();
            usedKeyImages[keyImages[i]] = true;
        }
        for (uint256 i = 0; i < outputCommitments.length; i++) {
            commitmentSet[outputCommitments[i]] = true;
        }
    }

    function batchVerifyRingCT(
        bytes32[][] calldata allKeyImages
    ) external view returns (bool[] memory valid) {
        valid = new bool[](allKeyImages.length);
        for (uint256 i = 0; i < allKeyImages.length; i++) {
            bool isValid = true;
            for (uint256 j = 0; j < allKeyImages[i].length; j++) {
                if (usedKeyImages[allKeyImages[i][j]]) {
                    isValid = false;
                    break;
                }
            }
            valid[i] = isValid;
        }
    }
}
