// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IFHECoprocessor
 * @author Soul Protocol
 * @notice Interface for the FHE Coprocessor oracle network
 */
interface IFHECoprocessor {
    // ============================================
    // TYPES
    // ============================================

    /// @notice Node information
    struct NodeInfo {
        address nodeAddress;
        bytes32 publicKeyHash;
        uint256 stake;
        uint256 reputation;
        uint64 registeredAt;
        uint64 lastActiveAt;
        uint256 successfulOps;
        uint256 failedOps;
        bool isActive;
        bool isSlashed;
    }

    /// @notice Task status
    enum TaskStatus {
        Pending,
        Assigned,
        Computing,
        Consensus,
        Completed,
        Failed,
        Expired
    }

    // ============================================
    // EVENTS
    // ============================================

    event NodeRegistered(
        address indexed node,
        uint256 stake,
        bytes32 publicKeyHash
    );

    event NodeDeregistered(address indexed node, uint256 stakeReturned);

    event NodeSlashed(
        address indexed node,
        uint256 amount,
        bytes32 indexed taskId
    );

    event TaskCreated(
        bytes32 indexed taskId,
        uint8 opcode,
        address indexed requester
    );

    event ResponseSubmitted(
        bytes32 indexed taskId,
        address indexed node,
        bytes32 outputHandle
    );

    event ConsensusReached(
        bytes32 indexed taskId,
        bytes32 indexed outputHandle,
        uint256 votes
    );

    event TaskCompleted(bytes32 indexed taskId, bytes32 indexed outputHandle);

    event DecryptionTaskCreated(bytes32 indexed taskId, bytes32 indexed handle);

    event DecryptionShareSubmitted(
        bytes32 indexed taskId,
        address indexed node
    );

    event DecryptionCompleted(bytes32 indexed taskId, bytes32 result);

    // ============================================
    // ERRORS
    // ============================================

    error InsufficientStake();
    error ExcessiveStake();
    error NodeAlreadyRegistered();
    error NodeNotRegistered();
    error NodeNotActive();
    error NodeIsSlashed();
    error InvalidTask();
    error TaskExpired();
    error AlreadyResponded();
    error InvalidSignature();
    error InsufficientQuorum();

    // ============================================
    // NODE MANAGEMENT
    // ============================================

    /**
     * @notice Register as a coprocessor node
     * @param publicKeyHash Hash of FHE key share
     */
    function registerNode(bytes32 publicKeyHash) external payable;

    /**
     * @notice Deregister and withdraw stake
     */
    function deregisterNode() external;

    /**
     * @notice Add additional stake
     */
    function addStake() external payable;

    /**
     * @notice Get node info
     * @param nodeAddr The node address
     * @return node The node info
     */
    function getNode(
        address nodeAddr
    ) external view returns (NodeInfo memory node);

    // ============================================
    // TASK MANAGEMENT
    // ============================================

    /**
     * @notice Create a new computation task
     * @param gatewayRequestId The FHEGateway request ID
     * @param opcode Operation code
     * @param inputHandles Input handle IDs
     * @param expectedOutputHandle Expected output handle
     * @param deadline Task deadline
     * @return taskId The new task ID
     */
    function createTask(
        bytes32 gatewayRequestId,
        uint8 opcode,
        bytes32[] calldata inputHandles,
        bytes32 expectedOutputHandle,
        uint64 deadline
    ) external payable returns (bytes32 taskId);

    /**
     * @notice Submit response for a task
     * @param taskId The task ID
     * @param outputHandle Computed output handle
     * @param proofHash Hash of ZK proof
     * @param signature Node signature over response
     */
    function submitResponse(
        bytes32 taskId,
        bytes32 outputHandle,
        bytes32 proofHash,
        bytes calldata signature
    ) external;

    /**
     * @notice Claim accumulated rewards
     */
    function claimRewards() external;

    // ============================================
    // THRESHOLD DECRYPTION
    // ============================================

    /**
     * @notice Create a threshold decryption task
     * @param handle The handle to decrypt
     * @param callbackContract Contract to receive result
     * @param callbackSelector Callback function selector
     * @param deadline Decryption deadline
     * @return taskId The decryption task ID
     */
    function requestDecryption(
        bytes32 handle,
        address callbackContract,
        bytes4 callbackSelector,
        uint64 deadline
    ) external returns (bytes32 taskId);

    /**
     * @notice Submit partial decryption share
     * @param taskId The decryption task ID
     * @param share The partial decryption share
     */
    function submitDecryptionShare(bytes32 taskId, bytes32 share) external;

    // ============================================
    // SLASHING
    // ============================================

    /**
     * @notice Slash a node for misbehavior
     * @param nodeAddr The node to slash
     * @param taskId The task where misbehavior occurred
     * @param proof Evidence of misbehavior
     */
    function slashNode(
        address nodeAddr,
        bytes32 taskId,
        bytes calldata proof
    ) external;

    // ============================================
    // VIEW FUNCTIONS
    // ============================================

    /**
     * @notice Get total node count
     */
    function nodeCount() external view returns (uint256);

    /**
     * @notice Get active node count
     */
    function activeNodeCount() external view returns (uint256);

    /**
     * @notice Get decryption threshold
     */
    function decryptionThreshold() external view returns (uint256);

    /**
     * @notice Get queue length
     */
    function getQueueLength() external view returns (uint256);

    /**
     * @notice Check if consensus was reached for a task
     * @param taskId The task ID
     * @return reached Whether consensus was reached
     * @return outputHandle The consensus output
     */
    function getConsensusResult(
        bytes32 taskId
    ) external view returns (bool reached, bytes32 outputHandle);
}
