// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title FHEUtils
 * @author Soul Protocol
 * @notice Common types and utilities for FHE operations
 */
library FHEUtils {
    // ============================================
    // TYPES
    // ============================================

    /// @notice FHE encrypted handle (reference to ciphertext)
    /// Handles are 256-bit references to off-chain ciphertexts
    struct Handle {
        bytes32 id; // Unique identifier
        uint8 valueType; // Type of encrypted value (see FHETypes)
        bytes32 securityZone; // Security domain
        bool verified; // Whether ciphertext is verified
        uint64 createdAt; // Creation timestamp
    }

    /// @notice Decryption request for async decryption
    struct DecryptionRequest {
        bytes32 requestId;
        bytes32 handle;
        address requester;
        address callbackContract;
        bytes4 callbackSelector;
        uint256 maxTimestamp;
        bool fulfilled;
        bytes32 result; // Decrypted value (as bytes32)
    }

    /// @notice Reencryption request for sharing encrypted data
    struct ReencryptionRequest {
        bytes32 requestId;
        bytes32 handle;
        address requester;
        bytes32 targetPublicKey;
        uint256 maxTimestamp;
        bool fulfilled;
        bytes reencryptedCiphertext;
    }

    /// @notice FHE computation request
    struct ComputeRequest {
        bytes32 requestId;
        uint8 opcode; // Operation code
        bytes32[] inputs; // Input handles
        bytes32 output; // Output handle
        address requester;
        uint256 gasUsed; // Estimated FHE gas
        uint256 timestamp;
        RequestStatus status;
    }

    /// @notice Request status
    enum RequestStatus {
        Pending,
        Processing,
        Completed,
        Failed,
        Expired
    }

    /// @notice Supported FHE schemes
    enum FHEScheme {
        TFHE,
        BFV,
        BGV,
        CKKS
    }

    /// @notice Value types for encrypted handles
    /// Compatible with fhEVM type system
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

    /// @notice FHE Operation codes
    enum Opcode {
        // Arithmetic
        ADD, // 0: ct + ct
        SUB, // 1: ct - ct
        MUL, // 2: ct * ct
        DIV, // 3: ct / ct (integer division)
        REM, // 4: ct % ct (remainder)
        NEG, // 5: -ct
        // Comparison
        EQ, // 6: ct == ct
        NE, // 7: ct != ct
        GE, // 8: ct >= ct
        GT, // 9: ct > ct
        LE, // 10: ct <= ct
        LT, // 11: ct < ct
        // Bitwise
        AND, // 12: ct & ct
        OR, // 13: ct | ct
        XOR, // 14: ct ^ ct
        NOT, // 15: ~ct
        SHL, // 16: ct << n
        SHR, // 17: ct >> n
        ROTL, // 18: rotate left
        ROTR, // 19: rotate right
        // Min/Max
        MIN, // 20: min(ct, ct)
        MAX, // 21: max(ct, ct)
        // Conditional
        SELECT, // 22: condition ? ct1 : ct2
        CMUX, // 23: encrypted mux
        // Special
        RAND, // 24: random encrypted value
        TRIVIAL, // 25: encrypt plaintext to ciphertext
        DECRYPT, // 26: request decryption
        REENCRYPT // 27: reencrypt to new key
    }
}
