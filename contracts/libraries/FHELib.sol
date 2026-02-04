// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title FHELib
 * @author Soul Protocol
 * @notice Common types and utilities for FHE operations across Soul Protocol
 * @dev Provides type-safe abstractions for working with encrypted values
 *
 * Architecture:
 * ┌─────────────────────────────────────────────────────────────────────┐
 * │                     FHE Type System                                  │
 * ├─────────────────────────────────────────────────────────────────────┤
 * │                                                                      │
 * │  ┌──────────────┐      ┌──────────────┐      ┌──────────────┐      │
 * │  │   Handle     │      │  ValueType   │      │   Scheme     │      │
 * │  │  (bytes32)   │─────▶│  (euintN)    │─────▶│  (TFHE/BFV)  │      │
 * │  └──────────────┘      └──────────────┘      └──────────────┘      │
 * │         │                                                           │
 * │         ▼                                                           │
 * │  ┌──────────────────────────────────────────────────────────┐      │
 * │  │                    Coprocessor                            │      │
 * │  │  • Homomorphic operations (add, mul, compare)             │      │
 * │  │  • Threshold decryption                                   │      │
 * │  │  • Reencryption                                           │      │
 * │  └──────────────────────────────────────────────────────────┘      │
 * └─────────────────────────────────────────────────────────────────────┘
 */
library FHELib {
    // ============================================
    // CONSTANTS
    // ============================================

    /// @notice Maximum number of inputs for batch operations
    uint256 public constant MAX_INPUTS = 16;

    /// @notice Maximum request TTL (1 hour)
    uint256 public constant MAX_REQUEST_TTL = 3600;

    /// @notice FHE gas multiplier (FHE ops are ~1000x more expensive)
    uint256 public constant FHE_GAS_MULTIPLIER = 1000;

    /// @notice Domain separator for handles
    bytes32 public constant HANDLE_DOMAIN = keccak256("SOUL_FHE_HANDLE_V1");

    // ============================================
    // VALUE TYPES (fhEVM compatible)
    // ============================================

    /// @notice Encrypted value types compatible with fhEVM
    enum ValueType {
        ebool, // 0: Encrypted boolean
        euint4, // 1: Encrypted 4-bit unsigned integer
        euint8, // 2: Encrypted 8-bit unsigned integer
        euint16, // 3: Encrypted 16-bit unsigned integer
        euint32, // 4: Encrypted 32-bit unsigned integer
        euint64, // 5: Encrypted 64-bit unsigned integer
        euint128, // 6: Encrypted 128-bit unsigned integer
        euint256, // 7: Encrypted 256-bit unsigned integer
        eaddress, // 8: Encrypted address (160-bit)
        ebytes64, // 9: Encrypted 64-byte value
        ebytes128, // 10: Encrypted 128-byte value
        ebytes256 // 11: Encrypted 256-byte value
    }

    // ============================================
    // FHE SCHEMES
    // ============================================

    /// @notice Supported FHE schemes
    enum FHEScheme {
        TFHE, // Torus FHE (best for binary/small integers)
        BFV, // Brakerski-Fan-Vercauteren (exact arithmetic)
        BGV, // Brakerski-Gentry-Vaikuntanathan (modular arithmetic)
        CKKS // Cheon-Kim-Kim-Song (approximate/floating-point)
    }

    // ============================================
    // OPERATION CODES
    // ============================================

    /// @notice FHE operation codes for coprocessor
    enum Opcode {
        // Arithmetic (0-5)
        ADD, // ct + ct or ct + pt
        SUB, // ct - ct or ct - pt
        MUL, // ct * ct or ct * pt
        DIV, // ct / pt (integer division)
        REM, // ct % pt (remainder)
        NEG, // -ct (negation)
        // Comparison (6-11)
        EQ, // ct == ct
        NE, // ct != ct
        GE, // ct >= ct
        GT, // ct > ct
        LE, // ct <= ct
        LT, // ct < ct
        // Bitwise (12-19)
        AND, // ct & ct
        OR, // ct | ct
        XOR, // ct ^ ct
        NOT, // ~ct
        SHL, // ct << n
        SHR, // ct >> n
        ROTL, // rotate left
        ROTR, // rotate right
        // Min/Max (20-21)
        MIN, // min(ct, ct)
        MAX, // max(ct, ct)
        // Conditional (22-23)
        SELECT, // condition ? ct1 : ct2
        CMUX, // encrypted multiplexer
        // Special (24-27)
        RAND, // generate random encrypted value
        TRIVIAL, // encrypt plaintext to ciphertext
        DECRYPT, // request async decryption
        REENCRYPT // reencrypt to new public key
    }

    // ============================================
    // REQUEST STATUS
    // ============================================

    /// @notice Status of FHE computation/decryption requests
    enum RequestStatus {
        Pending,
        Processing,
        Completed,
        Failed,
        Expired
    }

    // ============================================
    // CORE STRUCTURES
    // ============================================

    /// @notice Handle to an encrypted ciphertext
    /// @dev Handles are opaque references to off-chain ciphertexts
    struct Handle {
        bytes32 id; // Unique identifier
        uint8 valueType; // ValueType enum value
        bytes32 securityZone; // Security domain for ACL
        bool verified; // Whether ciphertext is verified
        uint64 createdAt; // Creation timestamp
    }

    /// @notice FHE computation request
    struct ComputeRequest {
        bytes32 requestId;
        uint8 opcode; // Opcode enum value
        bytes32[] inputs; // Input handle IDs
        bytes32 output; // Output handle ID
        address requester;
        uint256 gasEstimate; // Estimated FHE gas units
        uint64 timestamp;
        uint64 deadline;
        RequestStatus status;
    }

    /// @notice Decryption request (async)
    struct DecryptionRequest {
        bytes32 requestId;
        bytes32 handle;
        address requester;
        address callbackContract;
        bytes4 callbackSelector;
        uint64 maxTimestamp;
        bool fulfilled;
        bytes32 result; // Decrypted value (when fulfilled)
    }

    /// @notice Reencryption request
    struct ReencryptionRequest {
        bytes32 requestId;
        bytes32 handle;
        address requester;
        bytes32 targetPublicKey;
        uint64 maxTimestamp;
        bool fulfilled;
        bytes reencryptedCiphertext;
    }

    /// @notice Batch operation for gas efficiency
    struct BatchOperation {
        uint8 opcode;
        bytes32[] inputs;
        bytes32 output;
    }

    // ============================================
    // SECURITY STRUCTURES
    // ============================================

    /// @notice Security parameters for encryption
    struct SecurityParams {
        uint16 securityLevel; // Security bits (e.g., 128)
        uint16 noiseLevel; // Noise budget
        FHEScheme scheme; // FHE scheme used
        bytes32 publicKeyHash; // Hash of public key
    }

    /// @notice Access control for encrypted values
    struct ACLEntry {
        address grantee;
        bytes32 handle;
        bool canRead; // Can request decryption
        bool canCompute; // Can use in computations
        bool canDelegate; // Can grant access to others
        uint64 expiresAt; // 0 = no expiration
    }

    // ============================================
    // UTILITY FUNCTIONS
    // ============================================

    /**
     * @notice Compute a deterministic handle ID
     * @param creator The address creating the handle
     * @param valueType The type of encrypted value
     * @param securityZone The security domain
     * @param nonce Unique nonce
     * @return handleId The computed handle ID
     */
    function computeHandleId(
        address creator,
        uint8 valueType,
        bytes32 securityZone,
        uint256 nonce
    ) internal view returns (bytes32 handleId) {
        handleId = keccak256(
            abi.encode(
                HANDLE_DOMAIN,
                creator,
                valueType,
                securityZone,
                nonce,
                block.timestamp,
                block.chainid
            )
        );
    }

    /**
     * @notice Check if a value type is valid
     * @param valueType The type to check
     * @return valid Whether the type is valid
     */
    function isValidValueType(
        uint8 valueType
    ) internal pure returns (bool valid) {
        return valueType <= uint8(ValueType.ebytes256);
    }

    /**
     * @notice Get the byte size for a value type
     * @param valueType The type to check
     * @return size Size in bytes
     */
    function getValueTypeSize(
        uint8 valueType
    ) internal pure returns (uint256 size) {
        if (valueType == uint8(ValueType.ebool)) return 1;
        if (valueType == uint8(ValueType.euint4)) return 1;
        if (valueType == uint8(ValueType.euint8)) return 1;
        if (valueType == uint8(ValueType.euint16)) return 2;
        if (valueType == uint8(ValueType.euint32)) return 4;
        if (valueType == uint8(ValueType.euint64)) return 8;
        if (valueType == uint8(ValueType.euint128)) return 16;
        if (valueType == uint8(ValueType.euint256)) return 32;
        if (valueType == uint8(ValueType.eaddress)) return 20;
        if (valueType == uint8(ValueType.ebytes64)) return 64;
        if (valueType == uint8(ValueType.ebytes128)) return 128;
        if (valueType == uint8(ValueType.ebytes256)) return 256;
        return 0;
    }

    /**
     * @notice Estimate FHE gas for an operation
     * @param opcode The operation type
     * @param inputCount Number of inputs
     * @return gasEstimate Estimated gas units
     */
    function estimateFHEGas(
        uint8 opcode,
        uint256 inputCount
    ) internal pure returns (uint256 gasEstimate) {
        // Base costs for different operation types
        if (opcode <= uint8(Opcode.NEG)) {
            // Arithmetic: moderate cost
            gasEstimate = 50_000 * inputCount;
        } else if (opcode <= uint8(Opcode.LT)) {
            // Comparison: higher cost due to bootstrapping
            gasEstimate = 100_000 * inputCount;
        } else if (opcode <= uint8(Opcode.ROTR)) {
            // Bitwise: lower cost
            gasEstimate = 30_000 * inputCount;
        } else if (opcode <= uint8(Opcode.MAX)) {
            // Min/Max: requires comparison
            gasEstimate = 120_000 * inputCount;
        } else if (opcode <= uint8(Opcode.CMUX)) {
            // Conditional: most expensive
            gasEstimate = 150_000 * inputCount;
        } else {
            // Special operations
            gasEstimate = 200_000;
        }

        return gasEstimate * FHE_GAS_MULTIPLIER;
    }

    /**
     * @notice Validate that inputs are compatible for an operation
     * @param opcode The operation
     * @param inputCount Number of inputs
     * @return valid Whether inputs are valid for the operation
     */
    function validateInputCount(
        uint8 opcode,
        uint256 inputCount
    ) internal pure returns (bool valid) {
        // Unary operations
        if (
            opcode == uint8(Opcode.NEG) ||
            opcode == uint8(Opcode.NOT) ||
            opcode == uint8(Opcode.DECRYPT) ||
            opcode == uint8(Opcode.REENCRYPT)
        ) {
            return inputCount == 1;
        }

        // Binary operations
        if (opcode <= uint8(Opcode.MAX)) {
            return inputCount == 2;
        }

        // Ternary (SELECT, CMUX)
        if (opcode == uint8(Opcode.SELECT) || opcode == uint8(Opcode.CMUX)) {
            return inputCount == 3;
        }

        // Special operations
        if (opcode == uint8(Opcode.RAND) || opcode == uint8(Opcode.TRIVIAL)) {
            return inputCount <= 1;
        }

        return false;
    }

    /**
     * @notice Compute request ID for idempotency
     * @param requester The requesting address
     * @param opcode Operation type
     * @param inputs Input handles
     * @param nonce Request nonce
     * @return requestId Unique request ID
     */
    function computeRequestId(
        address requester,
        uint8 opcode,
        bytes32[] memory inputs,
        uint256 nonce
    ) internal view returns (bytes32 requestId) {
        requestId = keccak256(
            abi.encode(requester, opcode, inputs, nonce, block.chainid)
        );
    }
}
