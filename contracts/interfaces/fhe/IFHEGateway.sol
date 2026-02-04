// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../../libraries/FHELib.sol";

/**
 * @title IFHEGateway
 * @author Soul Protocol
 * @notice Interface for the FHE Gateway contract
 */
interface IFHEGateway {
    // ============================================
    // EVENTS
    // ============================================

    event HandleCreated(
        bytes32 indexed handleId,
        uint8 valueType,
        address indexed creator
    );

    event HandleVerified(bytes32 indexed handleId, address indexed verifier);

    event AccessGranted(
        bytes32 indexed handleId,
        address indexed grantee,
        address indexed grantor
    );

    event AccessRevoked(
        bytes32 indexed handleId,
        address indexed revokee,
        address indexed revoker
    );

    event ComputeRequested(
        bytes32 indexed requestId,
        uint8 opcode,
        address indexed requester
    );

    event ComputeCompleted(
        bytes32 indexed requestId,
        bytes32 indexed outputHandle,
        address indexed coprocessor
    );

    event DecryptionRequested(
        bytes32 indexed requestId,
        bytes32 indexed handleId,
        address indexed requester
    );

    event DecryptionCompleted(bytes32 indexed requestId, bytes32 result);

    event ReencryptionRequested(
        bytes32 indexed requestId,
        bytes32 indexed handleId,
        address indexed requester
    );

    event ReencryptionCompleted(bytes32 indexed requestId);

    // ============================================
    // ERRORS
    // ============================================

    error InvalidHandle();
    error HandleAlreadyExists();
    error HandleNotVerified();
    error UnauthorizedAccess();
    error SecurityZoneMismatch();
    error RequestExpired();
    error RequestAlreadyFulfilled();
    error InvalidRequestStatus();
    error TooManyInputs();
    error InvalidOpcode();
    error ZeroAddress();

    // ============================================
    // HANDLE MANAGEMENT
    // ============================================

    /**
     * @notice Create a new encrypted handle
     * @param valueType The type of encrypted value
     * @param securityZone The security domain
     * @return handleId The new handle ID
     */
    function createHandle(
        uint8 valueType,
        bytes32 securityZone
    ) external returns (bytes32 handleId);

    /**
     * @notice Verify a handle
     * @param handleId The handle to verify
     */
    function verifyHandle(bytes32 handleId) external;

    /**
     * @notice Check if a handle is valid and verified
     * @param handleId The handle to check
     * @return valid Whether the handle exists
     * @return verified Whether the handle is verified
     */
    function checkHandle(
        bytes32 handleId
    ) external view returns (bool valid, bool verified);

    /**
     * @notice Get handle information
     * @param handleId The handle ID
     * @return info The handle info
     */
    function getHandleInfo(
        bytes32 handleId
    ) external view returns (FHELib.Handle memory info);

    // ============================================
    // ACCESS CONTROL
    // ============================================

    /**
     * @notice Grant access to an encrypted value
     * @param handleId The handle
     * @param grantee The address to grant access
     */
    function grantAccess(bytes32 handleId, address grantee) external;

    /**
     * @notice Revoke access to an encrypted value
     * @param handleId The handle
     * @param revokee The address to revoke access
     */
    function revokeAccess(bytes32 handleId, address revokee) external;

    /**
     * @notice Check if an address has access to a handle
     * @param handleId The handle
     * @param account The address to check
     * @return hasAccess Whether the address has access
     */
    function hasAccess(
        bytes32 handleId,
        address account
    ) external view returns (bool);

    // ============================================
    // COMPUTATION
    // ============================================

    /**
     * @notice Request an FHE computation
     * @param opcode The operation code
     * @param inputHandles Array of input handle IDs
     * @param deadline Maximum timestamp for completion
     * @return requestId The request ID
     * @return outputHandle The expected output handle
     */
    function requestCompute(
        uint8 opcode,
        bytes32[] calldata inputHandles,
        uint64 deadline
    ) external returns (bytes32 requestId, bytes32 outputHandle);

    /**
     * @notice Complete a computation request
     * @param requestId The request ID
     * @param proof ZK proof of correct computation
     */
    function completeCompute(bytes32 requestId, bytes calldata proof) external;

    // ============================================
    // DECRYPTION
    // ============================================

    /**
     * @notice Request decryption of an encrypted value
     * @param handleId The handle to decrypt
     * @param callbackContract Contract to receive the result
     * @param callbackSelector Function selector for callback
     * @param maxTimestamp Deadline for decryption
     * @return requestId The request ID
     */
    function requestDecryption(
        bytes32 handleId,
        address callbackContract,
        bytes4 callbackSelector,
        uint64 maxTimestamp
    ) external returns (bytes32 requestId);

    /**
     * @notice Complete a decryption request
     * @param requestId The request ID
     * @param plaintextResult The decrypted value
     */
    function completeDecryption(
        bytes32 requestId,
        bytes32 plaintextResult
    ) external;

    // ============================================
    // REENCRYPTION
    // ============================================

    /**
     * @notice Request reencryption to a different public key
     * @param handleId The handle to reencrypt
     * @param targetPublicKey The target's public key
     * @return requestId The request ID
     */
    function requestReencryption(
        bytes32 handleId,
        bytes32 targetPublicKey
    ) external returns (bytes32 requestId);

    /**
     * @notice Complete a reencryption request
     * @param requestId The request ID
     * @param reencryptedValue The reencrypted ciphertext
     */
    function completeReencryption(
        bytes32 requestId,
        bytes calldata reencryptedValue
    ) external;

    // ============================================
    // VIEW FUNCTIONS
    // ============================================

    /**
     * @notice Get the coprocessor address
     * @return The coprocessor address
     */
    function coprocessor() external view returns (address);

    /**
     * @notice Get the KMS address
     * @return The KMS address
     */
    function kms() external view returns (address);

    /**
     * @notice Get the active FHE scheme
     * @return The active scheme
     */
    function activeScheme() external view returns (FHELib.FHEScheme);

    /**
     * @notice Get the request queue length
     * @return length Queue length
     */
    function getQueueLength() external view returns (uint256 length);

    /**
     * @notice Get pending requests for an address
     * @param account The address
     * @return requests Array of request IDs
     */
    function getPendingRequests(
        address account
    ) external view returns (bytes32[] memory requests);
}
