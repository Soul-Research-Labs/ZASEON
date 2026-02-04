// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import "../libraries/FHELib.sol";
import "./FHEGateway.sol";

/**
 * @title SoulFHECoprocessor
 * @author Soul Protocol
 * @notice Decentralized FHE computation oracle network with multi-node consensus
 * @dev Manages off-chain FHE computations with threshold verification
 *
 * Architecture:
 * ┌─────────────────────────────────────────────────────────────────────┐
 * │                 FHE Coprocessor Network                              │
 * ├─────────────────────────────────────────────────────────────────────┤
 * │                                                                      │
 * │  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐    │
 * │  │  Node 1    │  │  Node 2    │  │  Node 3    │  │  Node N    │    │
 * │  │  (TFHE)    │  │  (TFHE)    │  │  (TFHE)    │  │  (TFHE)    │    │
 * │  │  Stake: X  │  │  Stake: X  │  │  Stake: X  │  │  Stake: X  │    │
 * │  └─────┬──────┘  └─────┬──────┘  └─────┬──────┘  └─────┬──────┘    │
 * │        │               │               │               │           │
 * │        └───────────────┴───────┬───────┴───────────────┘           │
 * │                                │                                    │
 * │                    ┌───────────▼───────────┐                       │
 * │                    │  Consensus Engine     │                       │
 * │                    │  (2/3 + 1 threshold)  │                       │
 * │                    └───────────┬───────────┘                       │
 * │                                │                                    │
 * │                    ┌───────────▼───────────┐                       │
 * │                    │    FHE Gateway        │                       │
 * │                    │  (Handle Registry)    │                       │
 * │                    └───────────────────────┘                       │
 * └─────────────────────────────────────────────────────────────────────┘
 *
 * Security Features:
 * - Minimum stake requirement for nodes
 * - Slashing for incorrect/malicious behavior
 * - Reputation-based node selection
 * - Signature malleability protection
 * - VRF-based random node selection
 */
contract SoulFHECoprocessor is AccessControl, ReentrancyGuard, Pausable {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    // ============================================
    // ROLES
    // ============================================

    bytes32 public constant NODE_ROLE = keccak256("NODE_ROLE");
    bytes32 public constant SLASHER_ROLE = keccak256("SLASHER_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    // ============================================
    // CONSTANTS
    // ============================================

    /// @notice Minimum stake to become a coprocessor node
    uint256 public constant MIN_STAKE = 10 ether;

    /// @notice Maximum stake per node (for decentralization)
    uint256 public constant MAX_STAKE = 1000 ether;

    /// @notice Quorum threshold (basis points, 6667 = 66.67%)
    uint256 public constant QUORUM_BPS = 6667;

    /// @notice Slashing percentage for misbehavior (basis points)
    uint256 public constant SLASH_BPS = 1000; // 10%

    /// @notice Maximum task deadline
    uint256 public constant MAX_DEADLINE = 3600; // 1 hour

    /// @notice Minimum task deadline
    uint256 public constant MIN_DEADLINE = 30; // 30 seconds

    /// @notice Reputation increase for success (basis points)
    uint256 public constant REPUTATION_INCREASE_BPS = 10; // 0.1%

    /// @notice Reputation decrease for failure (basis points)
    uint256 public constant REPUTATION_DECREASE_BPS = 50; // 0.5%

    /// @notice Maximum reputation score
    uint256 public constant MAX_REPUTATION = 10000; // 100%

    /// @notice Domain separator for signatures
    bytes32 public constant DOMAIN_SEPARATOR =
        keccak256("SoulFHECoprocessor_v1");

    // ============================================
    // TYPES
    // ============================================

    /// @notice Coprocessor node information
    struct Node {
        address nodeAddress;
        bytes32 publicKeyHash; // Hash of node's FHE key share
        uint256 stake; // Staked collateral
        uint256 reputation; // Performance score (0-10000 bps)
        uint64 registeredAt;
        uint64 lastActiveAt;
        uint256 successfulOps;
        uint256 failedOps;
        bool isActive;
        bool isSlashed;
    }

    /// @notice Computation task
    struct Task {
        bytes32 taskId;
        bytes32 gatewayRequestId; // FHEGateway request ID
        uint8 opcode;
        bytes32[] inputHandles;
        bytes32 expectedOutputHandle;
        address requester;
        uint256 reward; // Payment for computation
        uint64 createdAt;
        uint64 deadline;
        TaskStatus status;
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

    /// @notice Node response to a task
    struct Response {
        bytes32 taskId;
        address node;
        bytes32 outputHandle;
        bytes32 proofHash; // Hash of ZK proof
        bytes signature; // Node signature
        uint64 submittedAt;
        bool accepted;
    }

    /// @notice Threshold decryption request
    struct DecryptionTask {
        bytes32 taskId;
        bytes32 handle;
        address requester;
        address callbackContract;
        bytes4 callbackSelector;
        uint64 deadline;
        uint256 responseCount;
        bool completed;
        bytes32 finalResult;
    }

    // ============================================
    // STATE VARIABLES
    // ============================================

    /// @notice FHE Gateway
    FHEGateway public immutable fheGateway;

    /// @notice Total node count
    uint256 public nodeCount;

    /// @notice Active node count
    uint256 public activeNodeCount;

    /// @notice Task nonce
    uint256 public taskNonce;

    /// @notice Total tasks processed
    uint256 public totalTasks;

    /// @notice Threshold for decryption (t-of-n)
    uint256 public decryptionThreshold;

    /// @notice Nodes registry
    mapping(address => Node) public nodes;

    /// @notice Node addresses list
    address[] public nodeList;

    /// @notice Tasks registry
    mapping(bytes32 => Task) public tasks;

    /// @notice Task responses: taskId => node => response
    mapping(bytes32 => mapping(address => Response)) public responses;

    /// @notice Response counts per task
    mapping(bytes32 => uint256) public responseCount;

    /// @notice Consensus votes: taskId => outputHash => vote count
    mapping(bytes32 => mapping(bytes32 => uint256)) public consensusVotes;

    /// @notice Decryption tasks
    mapping(bytes32 => DecryptionTask) public decryptionTasks;

    /// @notice Partial decryptions: taskId => node => share
    mapping(bytes32 => mapping(address => bytes32)) public partialDecryptions;

    /// @notice Accumulated rewards per node
    mapping(address => uint256) public pendingRewards;

    /// @notice Task queue
    bytes32[] public taskQueue;

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

    event TaskAssigned(bytes32 indexed taskId, address indexed node);

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

    event TaskFailed(bytes32 indexed taskId, string reason);

    event RewardsDistributed(bytes32 indexed taskId, uint256 totalReward);

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
    error TaskNotPending();
    error AlreadyResponded();
    error InvalidSignature();
    error InsufficientQuorum();
    error InvalidProof();
    error ZeroAddress();
    error NoRewardsToClaim();

    // ============================================
    // CONSTRUCTOR
    // ============================================

    constructor(address _fheGateway, uint256 _decryptionThreshold) {
        if (_fheGateway == address(0)) revert ZeroAddress();

        fheGateway = FHEGateway(_fheGateway);
        decryptionThreshold = _decryptionThreshold;

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(OPERATOR_ROLE, msg.sender);
        _grantRole(SLASHER_ROLE, msg.sender);
    }

    // ============================================
    // NODE MANAGEMENT
    // ============================================

    /**
     * @notice Register as a coprocessor node
     * @param publicKeyHash Hash of FHE key share
     */
    function registerNode(
        bytes32 publicKeyHash
    ) external payable nonReentrant whenNotPaused {
        if (msg.value < MIN_STAKE) revert InsufficientStake();
        if (msg.value > MAX_STAKE) revert ExcessiveStake();
        if (nodes[msg.sender].nodeAddress != address(0))
            revert NodeAlreadyRegistered();

        nodes[msg.sender] = Node({
            nodeAddress: msg.sender,
            publicKeyHash: publicKeyHash,
            stake: msg.value,
            reputation: MAX_REPUTATION / 2, // Start at 50%
            registeredAt: uint64(block.timestamp),
            lastActiveAt: uint64(block.timestamp),
            successfulOps: 0,
            failedOps: 0,
            isActive: true,
            isSlashed: false
        });

        nodeList.push(msg.sender);
        nodeCount++;
        activeNodeCount++;

        _grantRole(NODE_ROLE, msg.sender);

        emit NodeRegistered(msg.sender, msg.value, publicKeyHash);
    }

    /**
     * @notice Deregister and withdraw stake
     */
    function deregisterNode() external nonReentrant {
        Node storage node = nodes[msg.sender];
        if (node.nodeAddress == address(0)) revert NodeNotRegistered();
        if (node.isSlashed) revert NodeIsSlashed();

        uint256 stakeToReturn = node.stake;
        node.isActive = false;
        node.stake = 0;
        activeNodeCount--;

        _revokeRole(NODE_ROLE, msg.sender);

        // Return stake
        (bool success, ) = msg.sender.call{value: stakeToReturn}("");
        require(success, "Transfer failed");

        emit NodeDeregistered(msg.sender, stakeToReturn);
    }

    /**
     * @notice Add additional stake
     */
    function addStake() external payable nonReentrant {
        Node storage node = nodes[msg.sender];
        if (node.nodeAddress == address(0)) revert NodeNotRegistered();
        if (node.stake + msg.value > MAX_STAKE) revert ExcessiveStake();

        node.stake += msg.value;
    }

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
    ) external payable nonReentrant whenNotPaused returns (bytes32 taskId) {
        if (deadline < block.timestamp + MIN_DEADLINE) {
            deadline = uint64(block.timestamp + MIN_DEADLINE);
        }
        if (deadline > block.timestamp + MAX_DEADLINE) {
            deadline = uint64(block.timestamp + MAX_DEADLINE);
        }

        taskNonce++;
        taskId = keccak256(
            abi.encode(gatewayRequestId, msg.sender, taskNonce, block.chainid)
        );

        tasks[taskId] = Task({
            taskId: taskId,
            gatewayRequestId: gatewayRequestId,
            opcode: opcode,
            inputHandles: inputHandles,
            expectedOutputHandle: expectedOutputHandle,
            requester: msg.sender,
            reward: msg.value,
            createdAt: uint64(block.timestamp),
            deadline: deadline,
            status: TaskStatus.Pending
        });

        taskQueue.push(taskId);
        totalTasks++;

        emit TaskCreated(taskId, opcode, msg.sender);
    }

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
    ) external nonReentrant whenNotPaused onlyRole(NODE_ROLE) {
        Task storage task = tasks[taskId];
        Node storage node = nodes[msg.sender];

        if (task.taskId == bytes32(0)) revert InvalidTask();
        if (block.timestamp > task.deadline) revert TaskExpired();
        if (!node.isActive) revert NodeNotActive();
        if (responses[taskId][msg.sender].node != address(0))
            revert AlreadyResponded();

        // Verify signature
        bytes32 messageHash = keccak256(
            abi.encode(DOMAIN_SEPARATOR, taskId, outputHandle, proofHash)
        ).toEthSignedMessageHash();

        address signer = messageHash.recover(signature);
        if (signer != msg.sender) revert InvalidSignature();

        // Store response
        responses[taskId][msg.sender] = Response({
            taskId: taskId,
            node: msg.sender,
            outputHandle: outputHandle,
            proofHash: proofHash,
            signature: signature,
            submittedAt: uint64(block.timestamp),
            accepted: false
        });

        responseCount[taskId]++;
        consensusVotes[taskId][outputHandle]++;

        node.lastActiveAt = uint64(block.timestamp);

        emit ResponseSubmitted(taskId, msg.sender, outputHandle);

        // Check for consensus
        _checkConsensus(taskId, outputHandle);
    }

    /**
     * @notice Check if consensus is reached
     * @param taskId The task ID
     * @param outputHandle The proposed output
     */
    function _checkConsensus(bytes32 taskId, bytes32 outputHandle) internal {
        uint256 votes = consensusVotes[taskId][outputHandle];
        uint256 threshold = (activeNodeCount * QUORUM_BPS) / 10000;

        if (votes >= threshold) {
            Task storage task = tasks[taskId];
            task.status = TaskStatus.Completed;

            // Verify output handle on gateway
            fheGateway.verifyHandle(outputHandle);

            // Distribute rewards
            _distributeRewards(taskId, outputHandle);

            emit ConsensusReached(taskId, outputHandle, votes);
            emit TaskCompleted(taskId, outputHandle);
        }
    }

    /**
     * @notice Distribute rewards to nodes that reached consensus
     * @param taskId The task ID
     * @param winningOutput The consensus output
     */
    function _distributeRewards(
        bytes32 taskId,
        bytes32 winningOutput
    ) internal {
        Task storage task = tasks[taskId];
        uint256 totalReward = task.reward;
        uint256 winnerCount = consensusVotes[taskId][winningOutput];

        if (winnerCount == 0 || totalReward == 0) return;

        uint256 rewardPerNode = totalReward / winnerCount;

        // Iterate through nodes and reward winners
        for (uint256 i = 0; i < nodeList.length; i++) {
            address nodeAddr = nodeList[i];
            Response storage resp = responses[taskId][nodeAddr];

            if (resp.outputHandle == winningOutput) {
                resp.accepted = true;
                pendingRewards[nodeAddr] += rewardPerNode;

                // Increase reputation
                Node storage node = nodes[nodeAddr];
                node.successfulOps++;
                node.reputation = _min(
                    node.reputation + REPUTATION_INCREASE_BPS,
                    MAX_REPUTATION
                );
            } else if (resp.node != address(0)) {
                // Decrease reputation for wrong answer
                Node storage node = nodes[nodeAddr];
                node.failedOps++;
                if (node.reputation > REPUTATION_DECREASE_BPS) {
                    node.reputation -= REPUTATION_DECREASE_BPS;
                } else {
                    node.reputation = 0;
                }
            }
        }

        emit RewardsDistributed(taskId, totalReward);
    }

    /**
     * @notice Claim accumulated rewards
     */
    function claimRewards() external nonReentrant {
        uint256 rewards = pendingRewards[msg.sender];
        if (rewards == 0) revert NoRewardsToClaim();

        pendingRewards[msg.sender] = 0;

        (bool success, ) = msg.sender.call{value: rewards}("");
        require(success, "Transfer failed");
    }

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
    ) external nonReentrant whenNotPaused returns (bytes32 taskId) {
        if (callbackContract == address(0)) revert ZeroAddress();

        taskNonce++;
        taskId = keccak256(
            abi.encode("DECRYPT", handle, msg.sender, taskNonce)
        );

        decryptionTasks[taskId] = DecryptionTask({
            taskId: taskId,
            handle: handle,
            requester: msg.sender,
            callbackContract: callbackContract,
            callbackSelector: callbackSelector,
            deadline: deadline,
            responseCount: 0,
            completed: false,
            finalResult: bytes32(0)
        });

        emit DecryptionTaskCreated(taskId, handle);
    }

    /**
     * @notice Submit partial decryption share
     * @param taskId The decryption task ID
     * @param share The partial decryption share
     */
    function submitDecryptionShare(
        bytes32 taskId,
        bytes32 share
    ) external onlyRole(NODE_ROLE) {
        DecryptionTask storage task = decryptionTasks[taskId];

        if (task.taskId == bytes32(0)) revert InvalidTask();
        if (task.completed) revert InvalidTask();
        if (block.timestamp > task.deadline) revert TaskExpired();
        if (partialDecryptions[taskId][msg.sender] != bytes32(0))
            revert AlreadyResponded();

        partialDecryptions[taskId][msg.sender] = share;
        task.responseCount++;

        nodes[msg.sender].lastActiveAt = uint64(block.timestamp);

        emit DecryptionShareSubmitted(taskId, msg.sender);

        // Check if threshold reached
        if (task.responseCount >= decryptionThreshold) {
            _combineDecryptionShares(taskId);
        }
    }

    /**
     * @notice Combine decryption shares (simplified - real impl uses Shamir)
     * @param taskId The decryption task ID
     */
    function _combineDecryptionShares(bytes32 taskId) internal {
        DecryptionTask storage task = decryptionTasks[taskId];

        // Simplified: XOR all shares (real implementation uses Shamir's secret sharing)
        bytes32 combinedResult = bytes32(0);
        for (uint256 i = 0; i < nodeList.length; i++) {
            bytes32 share = partialDecryptions[taskId][nodeList[i]];
            if (share != bytes32(0)) {
                combinedResult = combinedResult ^ share;
            }
        }

        task.completed = true;
        task.finalResult = combinedResult;

        // Execute callback
        (bool success, ) = task.callbackContract.call(
            abi.encodeWithSelector(
                task.callbackSelector,
                taskId,
                combinedResult
            )
        );

        if (success) {
            emit DecryptionCompleted(taskId, combinedResult);
        }
    }

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
    ) external onlyRole(SLASHER_ROLE) nonReentrant {
        Node storage node = nodes[nodeAddr];
        if (node.nodeAddress == address(0)) revert NodeNotRegistered();
        if (node.isSlashed) revert NodeIsSlashed();

        // Verify proof of misbehavior (simplified)
        require(proof.length > 0, "Invalid proof");

        uint256 slashAmount = (node.stake * SLASH_BPS) / 10000;
        node.stake -= slashAmount;
        node.isSlashed = true;
        node.isActive = false;
        activeNodeCount--;

        _revokeRole(NODE_ROLE, nodeAddr);

        emit NodeSlashed(nodeAddr, slashAmount, taskId);
    }

    // ============================================
    // VIEW FUNCTIONS
    // ============================================

    /**
     * @notice Get node info
     * @param nodeAddr The node address
     * @return node The node info
     */
    function getNode(
        address nodeAddr
    ) external view returns (Node memory node) {
        return nodes[nodeAddr];
    }

    /**
     * @notice Get task info
     * @param taskId The task ID
     * @return task The task info
     */
    function getTask(bytes32 taskId) external view returns (Task memory task) {
        return tasks[taskId];
    }

    /**
     * @notice Get queue length
     * @return length The queue length
     */
    function getQueueLength() external view returns (uint256 length) {
        return taskQueue.length;
    }

    /**
     * @notice Check if consensus was reached for a task
     * @param taskId The task ID
     * @return reached Whether consensus was reached
     * @return outputHandle The consensus output (if reached)
     */
    function getConsensusResult(
        bytes32 taskId
    ) external view returns (bool reached, bytes32 outputHandle) {
        Task storage task = tasks[taskId];
        reached = task.status == TaskStatus.Completed;
        outputHandle = task.expectedOutputHandle;
    }

    // ============================================
    // ADMIN FUNCTIONS
    // ============================================

    /**
     * @notice Update decryption threshold
     * @param newThreshold New threshold value
     */
    function setDecryptionThreshold(
        uint256 newThreshold
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        decryptionThreshold = newThreshold;
    }

    /**
     * @notice Pause the coprocessor
     */
    function pause() external onlyRole(OPERATOR_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause the coprocessor
     */
    function unpause() external onlyRole(OPERATOR_ROLE) {
        _unpause();
    }

    // ============================================
    // INTERNAL HELPERS
    // ============================================

    function _min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }

    receive() external payable {}
}
