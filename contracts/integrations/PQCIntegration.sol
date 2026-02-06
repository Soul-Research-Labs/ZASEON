// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/**
 * @title PQCIntegration
 * @author Soul Protocol
 * @notice Unified Post-Quantum Cryptography integration for Soul Protocol
 * @dev Integrates Dilithium, Kyber, SPHINCS+ verifiers with hybrid signature support
 *
 * ARCHITECTURE:
 * ┌─────────────────────────────────────────────────────────────────────────────────┐
 * │                           PQCIntegration                                         │
 * │                                                                                  │
 * │   ┌───────────────────────────────────────────────────────────────────────────┐ │
 * │   │  SIGNATURE VERIFICATION                                                    │ │
 * │   │  ├─ Dilithium (CRYSTALS-Dilithium2/3/5)                                   │ │
 * │   │  ├─ SPHINCS+ (SHA2/SHAKE variants)                                        │ │
 * │   │  ├─ Falcon-512/1024                                                       │ │
 * │   │  └─ Hybrid ECDSA + PQC                                                    │ │
 * │   └───────────────────────────────────────────────────────────────────────────┘ │
 * │                                                                                  │
 * │   ┌───────────────────────────────────────────────────────────────────────────┐ │
 * │   │  KEY ENCAPSULATION (Kyber KEM)                                            │ │
 * │   │  ├─ Kyber512 (NIST Level 1)                                               │ │
 * │   │  ├─ Kyber768 (NIST Level 3)                                               │ │
 * │   │  └─ Kyber1024 (NIST Level 5)                                              │ │
 * │   └───────────────────────────────────────────────────────────────────────────┘ │
 * │                                                                                  │
 * │   ┌───────────────────────────────────────────────────────────────────────────┐ │
 * │   │  MODE TRANSITIONS                                                          │ │
 * │   │  MOCK → PURE_SOLIDITY → OFFCHAIN_ZK → PRECOMPILE                          │ │
 * │   │  (timelock protected, no regression to MOCK)                              │ │
 * │   └───────────────────────────────────────────────────────────────────────────┘ │
 * │                                                                                  │
 * │   ┌───────────────────────────────────────────────────────────────────────────┐ │
 * │   │  INTEGRATION POINTS                                                        │ │
 * │   │  ├─ CrossChainProofHub: PQC-secured proofs                                │ │
 * │   │  ├─ ZKBoundStateLocks: Quantum-resistant unlocks                          │ │
 * │   │  ├─ AtomicSwaps: PQC-protected HTLCs                                      │ │
 * │   │  └─ PrivateBridge: Quantum-safe transfers                                 │ │
 * │   └───────────────────────────────────────────────────────────────────────────┘ │
 * │                                                                                  │
 * └─────────────────────────────────────────────────────────────────────────────────┘
 *
 * @custom:security-contact security@soulprotocol.io
 */
contract PQCIntegration is ReentrancyGuard, AccessControl, Pausable {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    error ZeroAddress();
    error InvalidSignature();
    error InvalidPublicKey();
    error InvalidAlgorithm();
    error PublicKeyExpired();
    error PublicKeyNotRegistered();
    error UnsupportedAlgorithm();
    error VerificationFailed();
    error ModeTransitionNotAllowed();
    error MockModeDisabled();
    error TimelockNotPassed();
    error InvalidKEMCiphertext();
    error KeyDecapsulationFailed();
    error HybridVerificationFailed();

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    event PQCSignatureVerified(
        bytes32 indexed messageHash,
        bytes32 indexed publicKeyHash,
        PQSignatureAlgorithm algorithm,
        bool valid
    );

    event HybridSignatureVerified(
        bytes32 indexed messageHash,
        address indexed ecdsaSigner,
        bytes32 indexed pqcKeyHash,
        bool valid
    );

    event PublicKeyRegistered(
        bytes32 indexed keyHash,
        PQSignatureAlgorithm algorithm,
        address indexed owner,
        uint64 expiresAt
    );

    event KEMKeyRegistered(
        bytes32 indexed keyHash,
        PQKEMAlgorithm algorithm,
        address indexed owner
    );

    event ModeTransitionRequested(
        VerificationMode from,
        VerificationMode to,
        uint256 effectiveAt
    );

    event ModeTransitionExecuted(VerificationMode from, VerificationMode to);

    event MockModePermanentlyDisabled();

    /*//////////////////////////////////////////////////////////////
                                 ENUMS
    //////////////////////////////////////////////////////////////*/

    enum PQSignatureAlgorithm {
        DILITHIUM2,
        DILITHIUM3,
        DILITHIUM5,
        SPHINCS_SHA2_128F,
        SPHINCS_SHA2_128S,
        SPHINCS_SHA2_256F,
        SPHINCS_SHAKE_128F,
        FALCON512,
        FALCON1024
    }

    enum PQKEMAlgorithm {
        KYBER512,
        KYBER768,
        KYBER1024,
        MCELIECE348864
    }

    enum VerificationMode {
        MOCK, // For testing only
        PURE_SOLIDITY, // Full on-chain (expensive)
        OFFCHAIN_ZK, // ZK proof of verification
        PRECOMPILE // Future EIP
    }

    /*//////////////////////////////////////////////////////////////
                                 STRUCTS
    //////////////////////////////////////////////////////////////*/

    struct PQSignature {
        PQSignatureAlgorithm algorithm;
        bytes signature;
        bytes32 publicKeyHash;
        uint256 timestamp;
    }

    struct PQPublicKey {
        PQSignatureAlgorithm algorithm;
        bytes keyData;
        bytes32 keyHash;
        address owner;
        uint64 createdAt;
        uint64 expiresAt;
    }

    struct HybridSignature {
        bytes ecdsaSignature;
        PQSignature pqcSignature;
    }

    struct KEMPublicKey {
        PQKEMAlgorithm algorithm;
        bytes keyData;
        bytes32 keyHash;
        address owner;
    }

    struct KEMCiphertext {
        PQKEMAlgorithm algorithm;
        bytes ciphertext;
        bytes32 sharedSecretHash;
    }

    struct ModeTransitionRequest {
        VerificationMode targetMode;
        uint256 requestedAt;
        uint256 effectiveAt;
        bool executed;
    }

    /*//////////////////////////////////////////////////////////////
                                 CONSTANTS
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant MODE_ADMIN_ROLE = keccak256("MODE_ADMIN_ROLE");
    bytes32 public constant KEY_REGISTRAR_ROLE =
        keccak256("KEY_REGISTRAR_ROLE");

    bytes32 public constant PQC_DOMAIN = keccak256("Soul_PQC_INTEGRATION_V1");

    /// @notice Mode transition timelock (72 hours)
    uint256 public constant MODE_TRANSITION_DELAY = 72 hours;

    /// @notice Default key validity period (1 year)
    uint64 public constant DEFAULT_KEY_VALIDITY = 365 days;

    /*//////////////////////////////////////////////////////////////
                                 STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Current verification mode
    VerificationMode public currentMode;

    /// @notice Fallback mode if primary fails
    VerificationMode public fallbackMode;

    /// @notice Whether mock mode is permanently disabled
    bool public mockModePermanentlyDisabled;

    /// @notice Pending mode transition
    ModeTransitionRequest public pendingTransition;

    /// @notice Registered PQC public keys
    mapping(bytes32 => PQPublicKey) public pqcPublicKeys;

    /// @notice Registered KEM public keys
    mapping(bytes32 => KEMPublicKey) public kemPublicKeys;

    /// @notice User to their PQC key hashes
    mapping(address => bytes32[]) public userPQCKeys;

    /// @notice User to their KEM key hashes
    mapping(address => bytes32[]) public userKEMKeys;

    /// @notice Verification cache (for gas optimization)
    mapping(bytes32 => bool) public verificationCache;

    /// @notice Cache timestamps
    mapping(bytes32 => uint256) public cacheTimestamps;

    /// @notice Cache TTL
    uint256 public cacheTTL = 1 hours;

    /// @notice External verifier contracts
    address public dilithiumVerifier;
    address public sphincsVerifier;
    address public kyberVerifier;
    address public zkProofVerifier;

    /// @notice Verification statistics
    mapping(VerificationMode => uint256) public verificationCount;
    mapping(PQSignatureAlgorithm => uint256) public algorithmUsage;

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(
        address _dilithiumVerifier,
        address _sphincsVerifier,
        address _kyberVerifier,
        address _zkProofVerifier,
        VerificationMode _initialMode
    ) {
        if (_dilithiumVerifier == address(0)) revert ZeroAddress();
        if (_sphincsVerifier == address(0)) revert ZeroAddress();
        if (_kyberVerifier == address(0)) revert ZeroAddress();
        if (_zkProofVerifier == address(0)) revert ZeroAddress();

        dilithiumVerifier = _dilithiumVerifier;
        sphincsVerifier = _sphincsVerifier;
        kyberVerifier = _kyberVerifier;
        zkProofVerifier = _zkProofVerifier;
        currentMode = _initialMode;
        fallbackMode = VerificationMode.PURE_SOLIDITY;

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(OPERATOR_ROLE, msg.sender);
        _grantRole(MODE_ADMIN_ROLE, msg.sender);
        _grantRole(KEY_REGISTRAR_ROLE, msg.sender);
    }

    /*//////////////////////////////////////////////////////////////
                        PUBLIC KEY REGISTRATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Register a PQC public key
     * @param algorithm Signature algorithm
     * @param keyData Public key data
     * @param expiresAt Key expiration timestamp
     */
    function registerPQCPublicKey(
        PQSignatureAlgorithm algorithm,
        bytes calldata keyData,
        uint64 expiresAt
    ) external whenNotPaused returns (bytes32 keyHash) {
        if (keyData.length == 0) revert InvalidPublicKey();
        if (expiresAt <= block.timestamp) revert InvalidPublicKey();

        keyHash = keccak256(
            abi.encodePacked(PQC_DOMAIN, algorithm, keyData, msg.sender)
        );

        pqcPublicKeys[keyHash] = PQPublicKey({
            algorithm: algorithm,
            keyData: keyData,
            keyHash: keyHash,
            owner: msg.sender,
            createdAt: uint64(block.timestamp),
            expiresAt: expiresAt
        });

        userPQCKeys[msg.sender].push(keyHash);

        emit PublicKeyRegistered(keyHash, algorithm, msg.sender, expiresAt);
    }

    /**
     * @notice Register a KEM public key
     * @param algorithm KEM algorithm
     * @param keyData Public key data
     */
    function registerKEMPublicKey(
        PQKEMAlgorithm algorithm,
        bytes calldata keyData
    ) external whenNotPaused returns (bytes32 keyHash) {
        if (keyData.length == 0) revert InvalidPublicKey();

        keyHash = keccak256(
            abi.encodePacked(PQC_DOMAIN, "KEM", algorithm, keyData, msg.sender)
        );

        kemPublicKeys[keyHash] = KEMPublicKey({
            algorithm: algorithm,
            keyData: keyData,
            keyHash: keyHash,
            owner: msg.sender
        });

        userKEMKeys[msg.sender].push(keyHash);

        emit KEMKeyRegistered(keyHash, algorithm, msg.sender);
    }

    /*//////////////////////////////////////////////////////////////
                       SIGNATURE VERIFICATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Verify a PQC signature
     * @param message Message that was signed
     * @param signature PQC signature struct
     * @return valid Whether signature is valid
     */
    function verifyPQCSignature(
        bytes32 message,
        PQSignature calldata signature
    ) external returns (bool valid) {
        // Check public key registration
        PQPublicKey storage pubKey = pqcPublicKeys[signature.publicKeyHash];
        if (pubKey.keyHash == bytes32(0)) revert PublicKeyNotRegistered();
        if (pubKey.expiresAt < block.timestamp) revert PublicKeyExpired();

        // Check cache
        bytes32 cacheKey = _computeCacheKey(message, signature);
        if (_isCacheValid(cacheKey)) {
            return verificationCache[cacheKey];
        }

        // Verify based on mode
        if (currentMode == VerificationMode.MOCK) {
            if (mockModePermanentlyDisabled) revert MockModeDisabled();
            valid = true;
        } else if (currentMode == VerificationMode.OFFCHAIN_ZK) {
            valid = _verifyViaZKProof(message, signature);
        } else {
            valid = _verifyPQCDirect(message, signature, pubKey);
        }

        // Fallback if verification failed
        if (!valid && fallbackMode != currentMode) {
            valid = _verifyWithFallback(message, signature, pubKey);
        }

        // Cache result
        verificationCache[cacheKey] = valid;
        cacheTimestamps[cacheKey] = block.timestamp;

        verificationCount[currentMode]++;
        algorithmUsage[signature.algorithm]++;

        emit PQCSignatureVerified(
            message,
            signature.publicKeyHash,
            signature.algorithm,
            valid
        );

        return valid;
    }

    /**
     * @notice Verify a hybrid ECDSA + PQC signature
     * @param message Message that was signed
     * @param hybridSig Hybrid signature struct
     * @return valid Whether both signatures are valid
     */
    function verifyHybridSignature(
        bytes32 message,
        HybridSignature calldata hybridSig
    ) external returns (bool valid) {
        // Verify ECDSA signature
        address ecdsaSigner = message.toEthSignedMessageHash().recover(
            hybridSig.ecdsaSignature
        );
        if (ecdsaSigner == address(0)) revert InvalidSignature();

        // Verify PQC signature
        PQPublicKey storage pubKey = pqcPublicKeys[
            hybridSig.pqcSignature.publicKeyHash
        ];
        if (pubKey.keyHash == bytes32(0)) revert PublicKeyNotRegistered();
        if (pubKey.expiresAt < block.timestamp) revert PublicKeyExpired();

        // Ensure ECDSA signer owns the PQC key
        if (pubKey.owner != ecdsaSigner) revert HybridVerificationFailed();

        bool pqcValid;
        if (currentMode == VerificationMode.MOCK) {
            if (mockModePermanentlyDisabled) revert MockModeDisabled();
            pqcValid = true;
        } else {
            pqcValid = _verifyPQCDirect(
                message,
                hybridSig.pqcSignature,
                pubKey
            );
        }

        valid = pqcValid;

        emit HybridSignatureVerified(
            message,
            ecdsaSigner,
            hybridSig.pqcSignature.publicKeyHash,
            valid
        );

        return valid;
    }

    /*//////////////////////////////////////////////////////////////
                        KEM OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Verify KEM encapsulation
     * @param keyHash Public key hash
     * @param ciphertext KEM ciphertext
     * @param expectedSharedSecretHash Expected hash of shared secret
     * @return valid Whether encapsulation is valid
     */
    function verifyKEMEncapsulation(
        bytes32 keyHash,
        bytes calldata ciphertext,
        bytes32 expectedSharedSecretHash
    ) external view returns (bool valid) {
        KEMPublicKey storage pubKey = kemPublicKeys[keyHash];
        if (pubKey.keyHash == bytes32(0)) revert InvalidPublicKey();

        return _verifyKEM(pubKey, ciphertext, expectedSharedSecretHash);
    }

    /*//////////////////////////////////////////////////////////////
                        MODE TRANSITIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Request mode transition (timelocked)
     * @param newMode Target verification mode
     */
    function requestModeTransition(
        VerificationMode newMode
    ) external onlyRole(MODE_ADMIN_ROLE) {
        if (newMode == VerificationMode.MOCK && mockModePermanentlyDisabled) {
            revert MockModeDisabled();
        }

        // Cannot transition back to MOCK from higher modes
        if (
            currentMode > VerificationMode.MOCK &&
            newMode == VerificationMode.MOCK
        ) {
            revert ModeTransitionNotAllowed();
        }

        uint256 effectiveAt = block.timestamp + MODE_TRANSITION_DELAY;

        pendingTransition = ModeTransitionRequest({
            targetMode: newMode,
            requestedAt: block.timestamp,
            effectiveAt: effectiveAt,
            executed: false
        });

        emit ModeTransitionRequested(currentMode, newMode, effectiveAt);
    }

    /**
     * @notice Execute pending mode transition
     */
    function executeModeTransition() external onlyRole(MODE_ADMIN_ROLE) {
        if (pendingTransition.executed) revert ModeTransitionNotAllowed();
        if (block.timestamp < pendingTransition.effectiveAt)
            revert TimelockNotPassed();

        VerificationMode previousMode = currentMode;
        currentMode = pendingTransition.targetMode;
        pendingTransition.executed = true;

        emit ModeTransitionExecuted(previousMode, currentMode);
    }

    /**
     * @notice Permanently disable mock mode (irreversible)
     */
    function disableMockModePermanently()
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        mockModePermanentlyDisabled = true;
        if (currentMode == VerificationMode.MOCK) {
            currentMode = VerificationMode.PURE_SOLIDITY;
        }
        emit MockModePermanentlyDisabled();
    }

    /*//////////////////////////////////////////////////////////////
                       INTERNAL VERIFICATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Direct PQC verification (pure Solidity or precompile)
     */
    function _verifyPQCDirect(
        bytes32 message,
        PQSignature calldata signature,
        PQPublicKey storage pubKey
    ) internal view returns (bool) {
        address verifier;

        if (signature.algorithm <= PQSignatureAlgorithm.DILITHIUM5) {
            verifier = dilithiumVerifier;
        } else if (
            signature.algorithm <= PQSignatureAlgorithm.SPHINCS_SHAKE_128F
        ) {
            verifier = sphincsVerifier;
        } else {
            revert UnsupportedAlgorithm();
        }

        (bool success, bytes memory result) = verifier.staticcall(
            abi.encodeWithSignature(
                "verify(bytes32,bytes,bytes,uint8)",
                message,
                signature.signature,
                pubKey.keyData,
                uint8(signature.algorithm)
            )
        );

        if (success && result.length >= 32) {
            return abi.decode(result, (bool));
        }
        return false;
    }

    /**
     * @notice Verify via ZK proof (off-chain computation)
     */
    function _verifyViaZKProof(
        bytes32 message,
        PQSignature calldata signature
    ) internal view returns (bool) {
        // ZK proof verification - the signature field contains the ZK proof
        (bool success, bytes memory result) = zkProofVerifier.staticcall(
            abi.encodeWithSignature(
                "verifyPQCProof(bytes32,bytes32,bytes)",
                message,
                signature.publicKeyHash,
                signature.signature
            )
        );

        if (success && result.length >= 32) {
            return abi.decode(result, (bool));
        }
        return false;
    }

    /**
     * @notice Fallback verification
     */
    function _verifyWithFallback(
        bytes32 message,
        PQSignature calldata signature,
        PQPublicKey storage pubKey
    ) internal view returns (bool) {
        if (fallbackMode == VerificationMode.PURE_SOLIDITY) {
            return _verifyPQCDirect(message, signature, pubKey);
        }
        return false;
    }

    /**
     * @notice Verify KEM
     */
    function _verifyKEM(
        KEMPublicKey storage pubKey,
        bytes calldata ciphertext,
        bytes32 expectedSharedSecretHash
    ) internal view returns (bool) {
        (bool success, bytes memory result) = kyberVerifier.staticcall(
            abi.encodeWithSignature(
                "verifyEncapsulation(bytes,bytes,bytes32,uint8)",
                pubKey.keyData,
                ciphertext,
                expectedSharedSecretHash,
                uint8(pubKey.algorithm)
            )
        );

        if (success && result.length >= 32) {
            return abi.decode(result, (bool));
        }
        return false;
    }

    /**
     * @notice Compute cache key
     */
    function _computeCacheKey(
        bytes32 message,
        PQSignature calldata signature
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(
                    message,
                    signature.publicKeyHash,
                    keccak256(signature.signature)
                )
            );
    }

    /**
     * @notice Check if cache is valid
     */
    function _isCacheValid(bytes32 cacheKey) internal view returns (bool) {
        return
            cacheTimestamps[cacheKey] > 0 &&
            block.timestamp - cacheTimestamps[cacheKey] < cacheTTL;
    }

    /*//////////////////////////////////////////////////////////////
                            VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get PQC public key
     */
    function getPQCPublicKey(
        bytes32 keyHash
    ) external view returns (PQPublicKey memory) {
        return pqcPublicKeys[keyHash];
    }

    /**
     * @notice Get KEM public key
     */
    function getKEMPublicKey(
        bytes32 keyHash
    ) external view returns (KEMPublicKey memory) {
        return kemPublicKeys[keyHash];
    }

    /**
     * @notice Get user's PQC keys
     */
    function getUserPQCKeys(
        address user
    ) external view returns (bytes32[] memory) {
        return userPQCKeys[user];
    }

    /**
     * @notice Get user's KEM keys
     */
    function getUserKEMKeys(
        address user
    ) external view returns (bytes32[] memory) {
        return userKEMKeys[user];
    }

    /**
     * @notice Check if key is valid
     */
    function isKeyValid(bytes32 keyHash) external view returns (bool) {
        PQPublicKey storage key = pqcPublicKeys[keyHash];
        return key.keyHash != bytes32(0) && key.expiresAt > block.timestamp;
    }

    /**
     * @notice Get pending transition
     */
    function getPendingTransition()
        external
        view
        returns (ModeTransitionRequest memory)
    {
        return pendingTransition;
    }

    /**
     * @notice Get verification stats
     */
    function getVerificationStats(
        VerificationMode mode
    ) external view returns (uint256) {
        return verificationCount[mode];
    }

    /**
     * @notice Get algorithm usage
     */
    function getAlgorithmUsage(
        PQSignatureAlgorithm algorithm
    ) external view returns (uint256) {
        return algorithmUsage[algorithm];
    }

    /*//////////////////////////////////////////////////////////////
                         ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Update verifier contracts
     */
    function setVerifiers(
        address _dilithiumVerifier,
        address _sphincsVerifier,
        address _kyberVerifier,
        address _zkProofVerifier
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_dilithiumVerifier == address(0)) revert ZeroAddress();
        if (_sphincsVerifier == address(0)) revert ZeroAddress();
        if (_kyberVerifier == address(0)) revert ZeroAddress();
        if (_zkProofVerifier == address(0)) revert ZeroAddress();

        dilithiumVerifier = _dilithiumVerifier;
        sphincsVerifier = _sphincsVerifier;
        kyberVerifier = _kyberVerifier;
        zkProofVerifier = _zkProofVerifier;
    }

    /**
     * @notice Update fallback mode
     */
    function setFallbackMode(
        VerificationMode mode
    ) external onlyRole(MODE_ADMIN_ROLE) {
        if (mode == VerificationMode.MOCK && mockModePermanentlyDisabled) {
            revert MockModeDisabled();
        }
        fallbackMode = mode;
    }

    /**
     * @notice Update cache TTL
     */
    function setCacheTTL(uint256 _cacheTTL) external onlyRole(OPERATOR_ROLE) {
        cacheTTL = _cacheTTL;
    }

    /**
     * @notice Pause contract
     */
    function pause() external onlyRole(OPERATOR_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause contract
     */
    function unpause() external onlyRole(OPERATOR_ROLE) {
        _unpause();
    }
}
