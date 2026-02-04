// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../libraries/FHELib.sol";

/**
 * @title FHETypes
 * @author Soul Protocol
 * @notice Type definitions for FHE operations across Soul Protocol
 * @dev Provides encrypted value types compatible with fhEVM and TFHE
 *
 * Type Hierarchy:
 * ┌─────────────────────────────────────────────────────────────────────┐
 * │                    Encrypted Type System                            │
 * ├─────────────────────────────────────────────────────────────────────┤
 * │                                                                      │
 * │  Primitive Types:                                                    │
 * │  ┌────────┬────────┬────────┬────────┬────────┬─────────┐          │
 * │  │ ebool  │ euint8 │euint16 │euint32 │euint64 │euint128 │          │
 * │  └────────┴────────┴────────┴────────┴────────┴─────────┘          │
 * │                      └──────────┬──────────┘                        │
 * │                                 ▼                                   │
 * │  Composite Types:  ┌────────────────────────────┐                  │
 * │                    │ euint256 | eaddress | ebytesN                 │
 * │                    └────────────────────────────┘                  │
 * │                                 │                                   │
 * │                                 ▼                                   │
 * │  Container Types:  ┌────────────────────────────┐                  │
 * │                    │ EncryptedBalance | EncryptedTransfer          │
 * │                    └────────────────────────────┘                  │
 * └─────────────────────────────────────────────────────────────────────┘
 */

/// @notice FHE type constants (legacy compatibility)
library FHETypeConstants {
    uint8 public constant TYPE_EBOOL = 0;
    uint8 public constant TYPE_EUINT4 = 1;
    uint8 public constant TYPE_EUINT8 = 2;
    uint8 public constant TYPE_EUINT16 = 3;
    uint8 public constant TYPE_EUINT32 = 4;
    uint8 public constant TYPE_EUINT64 = 5;
    uint8 public constant TYPE_EUINT128 = 6;
    uint8 public constant TYPE_EUINT256 = 7;
    uint8 public constant TYPE_EADDRESS = 8;
    uint8 public constant TYPE_EBYTES64 = 9;
    uint8 public constant TYPE_EBYTES128 = 10;
    uint8 public constant TYPE_EBYTES256 = 11;
}

// ============================================
// PRIMITIVE ENCRYPTED TYPES
// ============================================

/// @notice Encrypted boolean type
/// @dev 1-bit encrypted value, result of comparisons
struct ebool {
    bytes32 handle; // Reference to ciphertext
    bytes32 ctHash; // Hash of ciphertext for verification
}

/// @notice Encrypted 4-bit unsigned integer
struct euint4 {
    bytes32 handle;
    bytes32 ctHash;
}

/// @notice Encrypted 8-bit unsigned integer
struct euint8 {
    bytes32 handle;
    bytes32 ctHash;
}

/// @notice Encrypted 16-bit unsigned integer
struct euint16 {
    bytes32 handle;
    bytes32 ctHash;
}

/// @notice Encrypted 32-bit unsigned integer
struct euint32 {
    bytes32 handle;
    bytes32 ctHash;
}

/// @notice Encrypted 64-bit unsigned integer
struct euint64 {
    bytes32 handle;
    bytes32 ctHash;
}

/// @notice Encrypted 128-bit unsigned integer
struct euint128 {
    bytes32 handle;
    bytes32 ctHash;
}

/// @notice Encrypted 256-bit unsigned integer
struct euint256 {
    bytes32 handle;
    bytes32 ctHash;
}

/// @notice Encrypted Ethereum address (160-bit)
struct eaddress {
    bytes32 handle;
    bytes32 ctHash;
}

/// @notice Encrypted 64-byte value
struct ebytes64 {
    bytes32 handle;
    bytes32 ctHash;
}

/// @notice Encrypted 128-byte value
struct ebytes128 {
    bytes32 handle;
    bytes32 ctHash;
}

/// @notice Encrypted 256-byte value
struct ebytes256 {
    bytes32 handle;
    bytes32 ctHash;
}

// ============================================
// KEY MANAGEMENT TYPES
// ============================================

/// @notice FHE public key for encryption
struct FHEPublicKey {
    bytes32 keyId; // Unique key identifier
    bytes32 keyHash; // Hash of full public key
    bytes publicKeyData; // Serialized public key (for off-chain use)
    FHELib.FHEScheme scheme; // TFHE, BFV, BGV, or CKKS
    uint64 createdAt;
    uint64 expiresAt; // 0 = no expiration
    bool revoked;
}

/// @notice Key share for threshold FHE
struct KeyShare {
    bytes32 shareId;
    bytes32 publicKeyId; // Associated public key
    address holder; // Share holder address
    uint8 threshold; // t-of-n threshold
    uint8 totalShares; // Total shares (n)
    bytes32 shareCommitment; // Commitment to share
    bool verified;
}

// ============================================
// REQUEST TYPES
// ============================================

/// @notice Re-encryption request for sharing encrypted data
struct ReencryptionRequest {
    bytes32 requestId;
    bytes32 sourceHandle; // Handle to reencrypt
    bytes32 targetPublicKey; // Target's public key
    address requester;
    address target; // Who can use reencrypted value
    uint64 timestamp;
    uint64 expiresAt;
    bool completed;
    bytes reencryptedCiphertext; // Result (filled by coprocessor)
}

/// @notice Decryption request for revealing encrypted values
struct DecryptionRequest {
    bytes32 requestId;
    bytes32 handle;
    address requester;
    address callbackContract; // Contract to receive result
    bytes4 callbackSelector; // Function selector for callback
    bytes callbackData; // Additional callback data
    uint64 timestamp;
    uint64 maxTimestamp; // Deadline
    bool fulfilled;
    bytes32 plaintextResult; // Decrypted value (when fulfilled)
}

/// @notice Batch decryption for gas efficiency
struct BatchDecryptionRequest {
    bytes32 requestId;
    bytes32[] handles; // Multiple handles to decrypt
    address requester;
    address callbackContract;
    bytes4 callbackSelector;
    uint64 timestamp;
    uint64 maxTimestamp;
    bool fulfilled;
    bytes32[] plaintextResults; // Results array
}

// ============================================
// CROSS-CHAIN TYPES
// ============================================

/// @notice Cross-chain FHE transfer
struct FHETransfer {
    bytes32 transferId;
    bytes32 encryptedAmount; // Encrypted transfer amount
    bytes32 senderCommitment; // Commitment to sender's new balance
    bytes32 recipientHandle; // Recipient's encrypted balance handle
    bytes32 recipientPublicKey; // For reencryption on destination
    address sender;
    address recipient;
    uint256 sourceChainId;
    uint256 destChainId;
    uint64 nonce;
    uint64 timestamp;
    FHETransferStatus status;
}

/// @notice Transfer status
enum FHETransferStatus {
    Pending,
    Locked, // Funds locked on source chain
    InTransit, // Cross-chain message sent
    Reencrypting, // Being reencrypted for destination
    Completed,
    Failed,
    Refunded
}

// ============================================
// BALANCE & STATE TYPES
// ============================================

/// @notice Encrypted balance for confidential tokens
struct EncryptedBalance {
    euint256 balance; // Encrypted token balance
    bytes32 lastUpdateCommitment; // Commitment to last update
    uint64 lastUpdated;
    uint32 updateCount; // Number of updates (for ordering)
}

/// @notice Encrypted allowance for token approvals
struct EncryptedAllowance {
    euint256 amount; // Encrypted allowance amount
    address owner;
    address spender;
    uint64 expiresAt; // 0 = no expiration
    bool unlimited; // If true, ignore amount
}

/// @notice Encrypted state slot for general storage
struct EncryptedSlot {
    bytes32 handle;
    uint8 valueType; // FHELib.ValueType
    bytes32 securityZone;
    bytes32 accessPolicyHash; // Hash of access control policy
    uint64 createdAt;
    uint64 lastAccessed;
}

// ============================================
// COMPUTATION TYPES
// ============================================

/// @notice FHE computation request
struct ComputeRequest {
    bytes32 requestId;
    FHELib.Opcode opcode; // Operation type
    bytes32[] inputHandles; // Input encrypted values
    bytes32 outputHandle; // Expected output handle
    bytes additionalData; // Plaintext inputs if needed
    address requester;
    uint256 gasReward; // Payment for computation
    uint64 timestamp;
    uint64 deadline;
    ComputeStatus status;
}

/// @notice Computation status
enum ComputeStatus {
    Pending,
    Assigned, // Assigned to coprocessor
    Computing, // In progress
    Verifying, // Result being verified
    Completed,
    Failed,
    Timeout
}

/// @notice Proof of correct FHE computation
struct ComputeProof {
    bytes32 requestId;
    bytes32 outputHandle;
    bytes zkProof; // ZK proof of correct computation
    bytes32 proofHash; // Hash for quick verification
    address prover;
    uint64 timestamp;
    bool verified;
}

// ============================================
// ORACLE / COPROCESSOR TYPES
// ============================================

/// @notice FHE Coprocessor node information
struct CoprocessorNode {
    address nodeAddress;
    bytes32 publicKeyHash; // Hash of node's FHE key share
    uint256 stake; // Staked collateral
    uint256 reputation; // Performance score (basis points)
    uint64 registeredAt;
    uint64 lastActiveAt;
    uint256 successfulOps;
    uint256 failedOps;
    bool isActive;
    bool isSlashed;
}

/// @notice Coprocessor response to computation request
struct CoprocessorResponse {
    bytes32 requestId;
    bytes32 outputHandle;
    bytes proof; // ZK proof of computation
    address responder;
    uint64 timestamp;
    bool accepted;
}

// ============================================
// COMPLIANCE TYPES
// ============================================

/// @notice Encrypted compliance proof
struct EncryptedComplianceProof {
    bytes32 proofId;
    bytes32 subjectHandle; // Handle to value being proven
    bytes32 policyHash; // Policy being satisfied
    bytes zkProof; // ZK proof of compliance
    uint64 timestamp;
    uint64 validUntil;
    bool verified;
}

/// @notice Range proof for encrypted values
struct EncryptedRangeProof {
    bytes32 proofId;
    bytes32 handle; // Handle to value
    uint256 minBound; // Plaintext min (public)
    uint256 maxBound; // Plaintext max (public)
    bytes zkProof; // ZK proof that min <= value <= max
    uint64 timestamp;
    bool verified;
}
