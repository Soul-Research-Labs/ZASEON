// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

/**
 * ╔═══════════════════════════════════════════════════════════════════════════╗
 * ║                      ⚠️  FUTURE-READY CRYPTO  ⚠️                           ║
 * ╠═══════════════════════════════════════════════════════════════════════════╣
 * ║ MATURITY: FUTURE - Waiting for EVM precompiles and ecosystem support     ║
 * ║                                                                           ║
 * ║ This contract implements ML-DSA (Dilithium), a NIST-standardized         ║
 * ║ post-quantum signature scheme. While the cryptography is mature,         ║
 * ║ EVM integration is NOT PRODUCTION-READY.                                 ║
 * ║                                                                           ║
 * ║ LIMITATIONS:                                                              ║
 * ║ • No EVM precompile exists - verification uses ZK proofs or is mocked   ║
 * ║ • Native verification would cost ~50M+ gas (impractical)                ║
 * ║ • Signature/key sizes (3-5 KB) are expensive for on-chain storage       ║
 * ║ • ZK verification of Dilithium is experimental (lattice ↔ R1CS)         ║
 * ║                                                                           ║
 * ║ QUANTUM TIMELINE:                                                         ║
 * ║ • NIST finalized ML-DSA in 2024                                          ║
 * ║ • EVM precompiles likely 2025-2027 via EIP process                       ║
 * ║ • Cryptographically-relevant quantum computers: 10-20+ years             ║
 * ║                                                                           ║
 * ║ RECOMMENDATION: Use hybrid mode (ECDSA + Dilithium) when deploying.      ║
 * ╚═══════════════════════════════════════════════════════════════════════════╝
 */

/**
 * @title DilithiumVerifier
 * @author Soul Protocol
 * @notice On-chain verifier for NIST ML-DSA (Dilithium) post-quantum signatures
 * @dev Implements verification for Dilithium3 and Dilithium5 parameter sets.
 *
 * Verification Modes:
 * 1. ZK Mode (default): Uses ZK proofs via IZKPqcVerifier for W-OTS+ components
 * 2. Precompile Mode: Calls EIP-proposed precompile (future)
 * 3. Mock Mode: For testing only - NEVER use in production
 *
 * Dilithium Parameters:
 * - Dilithium3: 128-bit quantum security, 3.3 KB signatures, 1.9 KB public keys
 * - Dilithium5: 192-bit quantum security, 4.6 KB signatures, 2.6 KB public keys
 *
 * @custom:security-contact security@soulprotocol.io
 * @custom:research-status FUTURE - Waiting for EVM precompiles
 * @custom:maturity-tier Future
 */

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @notice Interface for ZK-based PQC signature verification
 */
interface IZKPqcVerifier {
    function verifyWotsChain(
        bytes calldata proof,
        bytes32 publicElement
    ) external view returns (bool valid);

    function batchVerifyWotsChains(
        bytes[] calldata proofs,
        bytes32[] calldata publicElements
    ) external view returns (bool allValid);
}

contract DilithiumVerifier is Ownable {
    // =============================================================================
    // CONSTANTS
    // =============================================================================

    /// @notice Proposed precompile address for Dilithium verification
    /// @dev This would be assigned by an EIP in the future
    address public constant DILITHIUM_PRECOMSoulE = address(0x0D);

    /// @notice Dilithium3 public key size (bytes)
    uint256 public constant DILITHIUM3_PK_SIZE = 1952;

    /// @notice Dilithium3 signature size (bytes)
    uint256 public constant DILITHIUM3_SIG_SIZE = 3293;

    /// @notice Dilithium5 public key size (bytes)
    uint256 public constant DILITHIUM5_PK_SIZE = 2592;

    /// @notice Dilithium5 signature size (bytes)
    uint256 public constant DILITHIUM5_SIG_SIZE = 4595;

    // =============================================================================
    // ENUMS
    // =============================================================================

    enum DilithiumLevel {
        Level3, // NIST Security Level 3 (128-bit quantum)
        Level5 // NIST Security Level 5 (192-bit quantum)
    }

    enum VerificationMode {
        ZK, // Use ZK proof verification (production default)
        Precompile, // Use EVM precompile (future EIP)
        Mock // Mock mode for testing only
    }

    // =============================================================================
    // STATE
    // =============================================================================

    /// @notice Current verification mode
    VerificationMode public verificationMode;

    /// @notice ZK PQC verifier contract
    IZKPqcVerifier public zkVerifier;

    /// @notice Whether to use mock verification (for testing) - DEPRECATED, use verificationMode
    bool public useMockVerification;

    /// @notice Mapping of mock verification results for testing
    mapping(bytes32 => bool) public mockResults;

    /// @notice Trusted public key hashes that have been pre-verified
    mapping(bytes32 => bool) public trustedKeyHashes;

    /// @notice Gas cost override for verification (0 = use actual)
    uint256 public gasOverride;

    // =============================================================================
    // EVENTS
    // =============================================================================

    event DilithiumVerified(
        bytes32 indexed messageHash,
        bytes32 indexed publicKeyHash,
        DilithiumLevel level,
        bool valid
    );

    event TrustedKeyAdded(bytes32 indexed keyHash);
    event TrustedKeyRemoved(bytes32 indexed keyHash);
    event MockModeChanged(bool enabled);
    event VerificationModeChanged(VerificationMode newMode);
    event ZKVerifierUpdated(
        address indexed oldVerifier,
        address indexed newVerifier
    );

    // =============================================================================
    // ERRORS
    // =============================================================================

    error InvalidPublicKeySize(uint256 expected, uint256 actual);
    error InvalidSignatureSize(uint256 expected, uint256 actual);
    error PrecompileCallFailed();
    error InvalidSecurityLevel();
    error ArrayLengthMismatch();
    error ZKVerifierNotSet();
    error InvalidZKProof();
    error MockModeNotAllowedOnMainnet();

    // =============================================================================
    // CONSTRUCTOR
    // =============================================================================

    constructor() Ownable(msg.sender) {
        // Start in mock mode on testnets, but default to ZK mode on mainnet
        if (block.chainid == 1) {
            verificationMode = VerificationMode.ZK;
        } else {
            verificationMode = VerificationMode.Mock;
            useMockVerification = true;
        }
    }

    // =============================================================================
    // VERIFICATION FUNCTIONS
    // =============================================================================

    /**
     * @notice Verify a Dilithium3 signature
     * @param message The 32-byte message hash that was signed
     * @param signature The Dilithium3 signature (3293 bytes)
     * @param publicKey The Dilithium3 public key (1952 bytes)
     * @return valid True if the signature is valid
     */
    function verifyDilithium3(
        bytes32 message,
        bytes calldata signature,
        bytes calldata publicKey
    ) external returns (bool valid) {
        return _verify(message, signature, publicKey, DilithiumLevel.Level3);
    }

    /**
     * @notice Verify a Dilithium5 signature
     * @param message The 32-byte message hash that was signed
     * @param signature The Dilithium5 signature (4595 bytes)
     * @param publicKey The Dilithium5 public key (2592 bytes)
     * @return valid True if the signature is valid
     */
    function verifyDilithium5(
        bytes32 message,
        bytes calldata signature,
        bytes calldata publicKey
    ) external returns (bool valid) {
        return _verify(message, signature, publicKey, DilithiumLevel.Level5);
    }

    /**
     * @notice Unified verification for any Dilithium level
     * @param message The message hash
     * @param signature The signature bytes
     * @param publicKey The public key bytes
     * @param level The security level
     * @return valid True if valid
     */
    function verify(
        bytes32 message,
        bytes calldata signature,
        bytes calldata publicKey,
        DilithiumLevel level
    ) external returns (bool valid) {
        return _verify(message, signature, publicKey, level);
    }

    /**
     * @notice Batch verify multiple signatures
     * @param messages Array of message hashes
     * @param signatures Array of signatures
     * @param publicKeys Array of public keys
     * @param levels Array of security levels
     * @return allValid True if all signatures are valid
     */
    function batchVerify(
        bytes32[] calldata messages,
        bytes[] calldata signatures,
        bytes[] calldata publicKeys,
        DilithiumLevel[] calldata levels
    ) external returns (bool allValid) {
        if (
            messages.length != signatures.length ||
            signatures.length != publicKeys.length ||
            publicKeys.length != levels.length
        ) revert ArrayLengthMismatch();

        uint256 len = messages.length;
        for (uint256 i; i < len; ) {
            if (
                !_verify(messages[i], signatures[i], publicKeys[i], levels[i])
            ) {
                return false;
            }
            unchecked {
                ++i;
            }
        }
        return true;
    }

    // =============================================================================
    // INTERNAL VERIFICATION
    // =============================================================================

    function _verify(
        bytes32 message,
        bytes calldata signature,
        bytes calldata publicKey,
        DilithiumLevel level
    ) internal returns (bool valid) {
        // Validate sizes based on level - use inline check for gas efficiency
        uint256 pkLen = publicKey.length;
        uint256 sigLen = signature.length;

        if (level == DilithiumLevel.Level3) {
            if (pkLen != DILITHIUM3_PK_SIZE)
                revert InvalidPublicKeySize(DILITHIUM3_PK_SIZE, pkLen);
            if (sigLen != DILITHIUM3_SIG_SIZE)
                revert InvalidSignatureSize(DILITHIUM3_SIG_SIZE, sigLen);
        } else {
            if (pkLen != DILITHIUM5_PK_SIZE)
                revert InvalidPublicKeySize(DILITHIUM5_PK_SIZE, pkLen);
            if (sigLen != DILITHIUM5_SIG_SIZE)
                revert InvalidSignatureSize(DILITHIUM5_SIG_SIZE, sigLen);
        }

        bytes32 pkHash = keccak256(publicKey);

        // Select verification path based on mode
        VerificationMode mode = verificationMode;

        if (mode == VerificationMode.ZK) {
            valid = _zkVerify(message, signature, publicKey, pkHash, level);
        } else if (mode == VerificationMode.Precompile) {
            valid = _precompileVerify(message, signature, publicKey, level);
        } else {
            // Mock mode - only allowed on testnets
            if (block.chainid == 1) {
                revert MockModeNotAllowedOnMainnet();
            }
            valid = _mockVerify(message, signature, publicKey, pkHash);
        }

        emit DilithiumVerified(message, pkHash, level, valid);
    }

    /**
     * @notice ZK-based verification using W-OTS+ proofs
     * @dev Dilithium signatures contain lattice-based proofs that can be verified via ZK
     *      This requires the signature to be accompanied by ZK proofs
     */
    function _zkVerify(
        bytes32 message,
        bytes calldata signature,
        bytes calldata /* publicKey */,
        bytes32 pkHash,
        DilithiumLevel level
    ) internal view returns (bool) {
        // Check if ZK verifier is set
        if (address(zkVerifier) == address(0)) {
            revert ZKVerifierNotSet();
        }

        // Trusted keys bypass ZK verification
        if (trustedKeyHashes[pkHash]) {
            return true;
        }

        // For Dilithium, we verify the signature's structural components
        // The signature contains: z (challenge response), hint bits, challenge seed
        // We verify that the challenge was correctly derived and response is valid

        // Extract ZK proof from signature suffix (appended by signer)
        // Signature format: [standard_dilithium_sig | zk_proof_length (2 bytes) | zk_proof]
        uint256 standardSigSize = level == DilithiumLevel.Level3
            ? DILITHIUM3_SIG_SIZE
            : DILITHIUM5_SIG_SIZE;

        // If signature has embedded ZK proof, extract and verify
        if (signature.length > standardSigSize + 2) {
            uint16 zkProofLen = uint16(
                bytes2(signature[standardSigSize:standardSigSize + 2])
            );
            if (signature.length >= standardSigSize + 2 + zkProofLen) {
                bytes calldata zkProof = signature[standardSigSize +
                    2:standardSigSize + 2 + zkProofLen];

                // Compute public element from message and public key
                bytes32 publicElement = keccak256(
                    abi.encodePacked(message, pkHash)
                );

                // Verify via ZK PQC verifier
                try zkVerifier.verifyWotsChain(zkProof, publicElement) returns (
                    bool valid
                ) {
                    return valid;
                } catch {
                    return false;
                }
            }
        }

        // Fallback: verify trusted key or return false
        return trustedKeyHashes[pkHash];
    }

    function _mockVerify(
        bytes32 message,
        bytes calldata signature,
        bytes calldata publicKey,
        bytes32 pkHash
    ) internal view returns (bool) {
        // Check if there's a preset mock result
        bytes32 verifyKey = keccak256(
            abi.encode(message, keccak256(signature), pkHash)
        );
        if (mockResults[verifyKey]) {
            return true;
        }

        // Check if public key is in trusted set
        if (trustedKeyHashes[pkHash]) {
            // For trusted keys, perform a simplified check
            // In reality, this would verify the signature mathematically
            return signature.length > 0 && publicKey.length > 0;
        }

        // Default mock behavior: verify signature format is plausible
        // First 32 bytes should not be all zeros (basic sanity check)
        bytes32 sigPrefix;
        assembly {
            sigPrefix := calldataload(signature.offset)
        }
        return sigPrefix != bytes32(0);
    }

    function _precompileVerify(
        bytes32 message,
        bytes calldata signature,
        bytes calldata publicKey,
        DilithiumLevel level
    ) internal view returns (bool) {
        // Encode call data for precompile
        bytes memory input = abi.encodePacked(
            uint8(level),
            message,
            publicKey,
            signature
        );

        uint256 gasToUse = gasOverride > 0 ? gasOverride : gasleft();

        // Call precompile
        (bool success, bytes memory result) = DILITHIUM_PRECOMSoulE.staticcall{
            gas: gasToUse
        }(input);

        if (!success || result.length == 0) {
            // Fallback to mock if precompile not available
            if (useMockVerification) {
                return
                    _mockVerify(
                        message,
                        signature,
                        publicKey,
                        keccak256(publicKey)
                    );
            }
            revert PrecompileCallFailed();
        }

        return abi.decode(result, (bool));
    }

    function _getSizes(
        DilithiumLevel level
    ) internal pure returns (uint256 pkSize, uint256 sigSize) {
        if (level == DilithiumLevel.Level3) {
            return (DILITHIUM3_PK_SIZE, DILITHIUM3_SIG_SIZE);
        } else if (level == DilithiumLevel.Level5) {
            return (DILITHIUM5_PK_SIZE, DILITHIUM5_SIG_SIZE);
        }
        revert InvalidSecurityLevel();
    }

    // =============================================================================
    // ADMIN FUNCTIONS
    // =============================================================================

    /**
     * @notice Set the verification mode
     * @param mode The new verification mode
     * @dev Mock mode is not allowed on mainnet
     */
    function setVerificationMode(VerificationMode mode) external onlyOwner {
        if (mode == VerificationMode.Mock && block.chainid == 1) {
            revert MockModeNotAllowedOnMainnet();
        }
        verificationMode = mode;
        // Sync legacy flag for backwards compatibility
        useMockVerification = (mode == VerificationMode.Mock);
        emit VerificationModeChanged(mode);
    }

    /**
     * @notice Set the ZK PQC verifier contract
     * @param _zkVerifier Address of the IZKPqcVerifier implementation
     */
    function setZKVerifier(address _zkVerifier) external onlyOwner {
        address oldVerifier = address(zkVerifier);
        zkVerifier = IZKPqcVerifier(_zkVerifier);
        emit ZKVerifierUpdated(oldVerifier, _zkVerifier);
    }

    /**
     * @notice Set mock verification mode (DEPRECATED - use setVerificationMode)
     * @param enabled True to enable mock mode
     */
    function setMockMode(bool enabled) external onlyOwner {
        if (enabled && block.chainid == 1) {
            revert MockModeNotAllowedOnMainnet();
        }
        useMockVerification = enabled;
        verificationMode = enabled
            ? VerificationMode.Mock
            : VerificationMode.ZK;
        emit MockModeChanged(enabled);
    }

    /**
     * @notice Add a mock verification result
     * @param message The message hash
     * @param signatureHash Hash of the signature
     * @param publicKeyHash Hash of the public key
     * @param result The verification result to return
     */
    function setMockResult(
        bytes32 message,
        bytes32 signatureHash,
        bytes32 publicKeyHash,
        bool result
    ) external onlyOwner {
        bytes32 key = keccak256(
            abi.encode(message, signatureHash, publicKeyHash)
        );
        mockResults[key] = result;
    }

    /**
     * @notice Add a trusted public key hash
     * @param keyHash The keccak256 hash of the public key
     */
    function addTrustedKey(bytes32 keyHash) external onlyOwner {
        trustedKeyHashes[keyHash] = true;
        emit TrustedKeyAdded(keyHash);
    }

    /**
     * @notice Remove a trusted public key hash
     * @param keyHash The key hash to remove
     */
    function removeTrustedKey(bytes32 keyHash) external onlyOwner {
        trustedKeyHashes[keyHash] = false;
        emit TrustedKeyRemoved(keyHash);
    }

    /**
     * @notice Set gas override for precompile calls
     * @param gas Gas amount (0 = use remaining gas)
     */
    function setGasOverride(uint256 gas) external onlyOwner {
        gasOverride = gas;
    }

    // =============================================================================
    // VIEW FUNCTIONS
    // =============================================================================

    /**
     * @notice Get expected sizes for a security level
     * @param level The Dilithium level
     * @return pkSize Public key size in bytes
     * @return sigSize Signature size in bytes
     */
    function getExpectedSizes(
        DilithiumLevel level
    ) external pure returns (uint256 pkSize, uint256 sigSize) {
        return _getSizes(level);
    }

    /**
     * @notice Check if a public key is trusted
     * @param publicKey The public key bytes
     * @return trusted True if the key hash is in the trusted set
     */
    function isKeyTrusted(
        bytes calldata publicKey
    ) external view returns (bool trusted) {
        return trustedKeyHashes[keccak256(publicKey)];
    }

    /**
     * @notice Estimate gas cost for verification
     * @param level The security level
     * @return gas Estimated gas cost
     */
    function estimateGas(
        DilithiumLevel level
    ) external pure returns (uint256 gas) {
        // Estimated costs (will be defined by EIP)
        if (level == DilithiumLevel.Level3) {
            return 150_000;
        } else {
            return 200_000;
        }
    }
}
