// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";

/**
 * @title MixnetNodeRegistry
 * @author Soul Protocol
 * @notice Registry for mixnet nodes with staking and reputation
 * @dev Phase 3 of Metadata Resistance - enables multi-hop onion routing
 *
 * PRIVACY GUARANTEE:
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │                    MIXNET ROUTING                                        │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │                                                                          │
 * │  WITHOUT MIXNET (Single Hop):                                           │
 * │  User ──────────────────────────────────────────────────► Destination   │
 * │         Relayer sees: source AND destination                            │
 * │                                                                          │
 * │  WITH MIXNET (3-Hop Onion Routing):                                     │
 * │  User ─► Node A ─► Node B ─► Node C ─► Destination                      │
 * │          │         │         │                                           │
 * │          │         │         └─ Sees: Node B → Destination              │
 * │          │         └─ Sees: Node A → Node C                              │
 * │          └─ Sees: User → Node B                                          │
 * │                                                                          │
 * │  No single node knows both source AND destination                       │
 * │  Requires n-1 collusion to break privacy (for n hops)                   │
 * │                                                                          │
 * └─────────────────────────────────────────────────────────────────────────┘
 */
contract MixnetNodeRegistry is
    Initializable,
    UUPSUpgradeable,
    AccessControlUpgradeable,
    ReentrancyGuardUpgradeable,
    PausableUpgradeable
{
    // =========================================================================
    // ROLES
    // =========================================================================

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant SLASHER_ROLE = keccak256("SLASHER_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    // =========================================================================
    // CONSTANTS
    // =========================================================================

    /// @notice Minimum stake to become a mix node
    uint256 public constant MIN_STAKE = 10 ether;

    /// @notice Maximum stake considered for selection
    uint256 public constant MAX_STAKE = 1000 ether;

    /// @notice Default number of hops in a path
    uint256 public constant DEFAULT_HOPS = 3;

    /// @notice Maximum hops allowed
    uint256 public constant MAX_HOPS = 5;

    /// @notice Minimum nodes required for operation
    uint256 public constant MIN_ACTIVE_NODES = 9; // 3 hops × 3 choices each

    /// @notice Unbonding period after exit request
    uint256 public constant UNBONDING_PERIOD = 7 days;

    /// @notice Slash percentage for misbehavior (basis points)
    uint256 public constant SLASH_PERCENTAGE = 2000; // 20%

    /// @notice Cooldown after being slashed
    uint256 public constant SLASH_COOLDOWN = 30 days;

    // =========================================================================
    // ENUMS
    // =========================================================================

    enum NodeStatus {
        PENDING, // Registered, awaiting activation
        ACTIVE, // Processing messages
        SUSPENDED, // Temporarily suspended
        SLASHED, // Penalized for misbehavior
        EXITING, // Exit requested, in unbonding
        EXITED // Stake withdrawn
    }

    enum SlashReason {
        MIXING_FAILURE, // Failed to correctly mix/forward
        TIMING_LEAK, // Exposed timing information
        DOUBLE_PROCESSING, // Processed same message twice
        PATH_DEVIATION, // Deviated from declared path
        KEY_COMPROMISE, // Private key compromised
        CENSORSHIP, // Refused to process valid messages
        COLLABORATION_BREACH // Colluded with other nodes
    }

    // =========================================================================
    // STRUCTS
    // =========================================================================

    /**
     * @notice Mix node registration
     */
    struct MixNode {
        address operator;
        bytes publicKey; // X25519 public key for onion encryption
        bytes32 publicKeyHash; // Hash for quick lookup
        uint256 stake;
        uint256 reputation; // 0-10000 (basis points)
        uint256 totalProcessed; // Messages processed
        uint256 successfulMixes; // Successful mix operations
        uint256 failedMixes; // Failed mix operations
        NodeStatus status;
        uint256 registeredAt;
        uint256 lastActiveAt;
        uint256 exitRequestedAt;
        uint256 slashedAt;
        uint256 slashedAmount;
        string endpoint; // Network endpoint (IP:port or DNS)
    }

    /**
     * @notice Node capabilities
     */
    struct NodeCapabilities {
        bool supportsThresholdDecryption;
        bool supportsZKMixing;
        bool supportsTimingObfuscation;
        bool supportsBatchProcessing;
        uint256 maxBatchSize;
        uint256 minBatchSize;
        uint256 maxLatencyMs;
    }

    /**
     * @notice Path selection result
     */
    struct MixPath {
        bytes32 pathId;
        address[] nodes;
        bytes[] publicKeys;
        uint256 createdAt;
        uint256 expiresAt;
    }

    // =========================================================================
    // STATE
    // =========================================================================

    /// @notice All nodes: operator address => node
    mapping(address => MixNode) public nodes;

    /// @notice Node capabilities: operator => capabilities
    mapping(address => NodeCapabilities) public nodeCapabilities;

    /// @notice Active node operators (for path selection)
    address[] public activeNodes;

    /// @notice Index in activeNodes array: operator => index
    mapping(address => uint256) public activeNodeIndex;

    /// @notice Public key hash to operator: pkHash => operator
    mapping(bytes32 => address) public publicKeyToOperator;

    /// @notice Generated paths: pathId => path
    mapping(bytes32 => MixPath) public paths;

    /// @notice Total active stake
    uint256 public totalActiveStake;

    /// @notice Total nodes registered
    uint256 public totalNodes;

    /// @notice Path validity duration
    uint256 public pathValidityPeriod;

    /// @notice VRF seed for path selection
    bytes32 public vrfSeed;

    /// @notice Path selection nonce
    uint256 public pathNonce;

    // =========================================================================
    // EVENTS
    // =========================================================================

    event NodeRegistered(
        address indexed operator,
        bytes32 publicKeyHash,
        uint256 stake,
        string endpoint
    );

    event NodeActivated(address indexed operator, uint256 timestamp);

    event NodeDeactivated(address indexed operator, string reason);

    event NodeSlashed(
        address indexed operator,
        uint256 amount,
        SlashReason reason,
        bytes evidence
    );

    event NodeExitRequested(address indexed operator, uint256 exitableAt);

    event NodeExited(address indexed operator, uint256 stakeReturned);

    event PathGenerated(
        bytes32 indexed pathId,
        address[] nodes,
        uint256 hops,
        uint256 expiresAt
    );

    event MixProcessed(
        address indexed node,
        bytes32 indexed inputCommitment,
        bytes32 indexed outputCommitment,
        uint256 timestamp
    );

    event ReputationUpdated(
        address indexed operator,
        uint256 oldReputation,
        uint256 newReputation
    );

    // =========================================================================
    // ERRORS
    // =========================================================================

    error InsufficientStake();
    error NodeAlreadyExists();
    error NodeNotFound();
    error NodeNotActive();
    error InvalidPublicKey();
    error InvalidEndpoint();
    error NotEnoughActiveNodes();
    error InvalidHopCount();
    error PathExpired();
    error PathNotFound();
    error UnbondingNotComplete();
    error AlreadyExiting();
    error InvalidEvidence();
    error ZeroAddress();

    // =========================================================================
    // INITIALIZER
    // =========================================================================

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address admin) external initializer {
        if (admin == address(0)) revert ZeroAddress();

        __UUPSUpgradeable_init();
        __AccessControl_init();
        __ReentrancyGuard_init();
        __Pausable_init();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(OPERATOR_ROLE, admin);
        _grantRole(SLASHER_ROLE, admin);
        _grantRole(UPGRADER_ROLE, admin);

        pathValidityPeriod = 1 hours;
        vrfSeed = keccak256(
            abi.encodePacked(block.timestamp, block.prevrandao, admin)
        );
    }

    // =========================================================================
    // NODE REGISTRATION
    // =========================================================================

    /**
     * @notice Register as a mix node
     * @param publicKey X25519 public key for onion encryption
     * @param endpoint Network endpoint (IP:port or DNS)
     * @param capabilities Node capabilities
     */
    function registerNode(
        bytes calldata publicKey,
        string calldata endpoint,
        NodeCapabilities calldata capabilities
    ) external payable nonReentrant whenNotPaused {
        if (msg.value < MIN_STAKE) revert InsufficientStake();
        if (nodes[msg.sender].registeredAt != 0) revert NodeAlreadyExists();
        if (publicKey.length != 32) revert InvalidPublicKey();
        if (bytes(endpoint).length == 0) revert InvalidEndpoint();

        bytes32 pkHash = keccak256(publicKey);
        if (publicKeyToOperator[pkHash] != address(0))
            revert InvalidPublicKey();

        nodes[msg.sender] = MixNode({
            operator: msg.sender,
            publicKey: publicKey,
            publicKeyHash: pkHash,
            stake: msg.value,
            reputation: 5000, // Start at 50%
            totalProcessed: 0,
            successfulMixes: 0,
            failedMixes: 0,
            status: NodeStatus.PENDING,
            registeredAt: block.timestamp,
            lastActiveAt: 0,
            exitRequestedAt: 0,
            slashedAt: 0,
            slashedAmount: 0,
            endpoint: endpoint
        });

        nodeCapabilities[msg.sender] = capabilities;
        publicKeyToOperator[pkHash] = msg.sender;
        totalNodes++;

        emit NodeRegistered(msg.sender, pkHash, msg.value, endpoint);
    }

    /**
     * @notice Activate a pending node
     */
    function activateNode(address operator) external onlyRole(OPERATOR_ROLE) {
        MixNode storage node = nodes[operator];
        if (node.registeredAt == 0) revert NodeNotFound();
        if (node.status != NodeStatus.PENDING) revert NodeNotActive();

        node.status = NodeStatus.ACTIVE;
        node.lastActiveAt = block.timestamp;

        // Add to active nodes
        activeNodeIndex[operator] = activeNodes.length;
        activeNodes.push(operator);
        totalActiveStake += node.stake > MAX_STAKE ? MAX_STAKE : node.stake;

        emit NodeActivated(operator, block.timestamp);
    }

    /**
     * @notice Self-activate after verification period (if auto-activation enabled)
     */
    function selfActivate() external nonReentrant {
        MixNode storage node = nodes[msg.sender];
        if (node.registeredAt == 0) revert NodeNotFound();
        if (node.status != NodeStatus.PENDING) revert NodeNotActive();

        // Require 24 hours waiting period for self-activation
        require(
            block.timestamp >= node.registeredAt + 24 hours,
            "Waiting period not complete"
        );

        node.status = NodeStatus.ACTIVE;
        node.lastActiveAt = block.timestamp;

        activeNodeIndex[msg.sender] = activeNodes.length;
        activeNodes.push(msg.sender);
        totalActiveStake += node.stake > MAX_STAKE ? MAX_STAKE : node.stake;

        emit NodeActivated(msg.sender, block.timestamp);
    }

    // =========================================================================
    // PATH SELECTION
    // =========================================================================

    /**
     * @notice Select a random path through the mixnet
     * @param hops Number of hops (default 3)
     * @return pathId Unique path identifier
     * @return selectedNodes Array of node addresses
     * @return publicKeys Array of node public keys
     */
    function selectPath(
        uint256 hops
    )
        external
        returns (
            bytes32 pathId,
            address[] memory selectedNodes,
            bytes[] memory publicKeys
        )
    {
        if (hops == 0) hops = DEFAULT_HOPS;
        if (hops > MAX_HOPS) revert InvalidHopCount();
        if (activeNodes.length < hops) revert NotEnoughActiveNodes();

        selectedNodes = new address[](hops);
        publicKeys = new bytes[](hops);

        // Use VRF-like selection
        bytes32 seed = keccak256(
            abi.encodePacked(vrfSeed, pathNonce, block.timestamp, msg.sender)
        );
        pathNonce++;

        // Select unique nodes for each hop
        bool[] memory selected = new bool[](activeNodes.length);

        for (uint256 i = 0; i < hops; ) {
            // Generate random index
            uint256 randomIndex = uint256(
                keccak256(abi.encodePacked(seed, i))
            ) % activeNodes.length;

            // Find next unselected node (linear probe)
            uint256 probes = 0;
            while (selected[randomIndex] && probes < activeNodes.length) {
                randomIndex = (randomIndex + 1) % activeNodes.length;
                probes++;
            }

            if (probes >= activeNodes.length) revert NotEnoughActiveNodes();

            selected[randomIndex] = true;
            address nodeAddr = activeNodes[randomIndex];
            selectedNodes[i] = nodeAddr;
            publicKeys[i] = nodes[nodeAddr].publicKey;

            unchecked {
                ++i;
            }
        }

        // Generate path ID
        pathId = keccak256(
            abi.encodePacked(selectedNodes, block.timestamp, pathNonce)
        );

        // Store path
        paths[pathId] = MixPath({
            pathId: pathId,
            nodes: selectedNodes,
            publicKeys: publicKeys,
            createdAt: block.timestamp,
            expiresAt: block.timestamp + pathValidityPeriod
        });

        emit PathGenerated(
            pathId,
            selectedNodes,
            hops,
            block.timestamp + pathValidityPeriod
        );
    }

    /**
     * @notice Get path info
     */
    function getPath(
        bytes32 pathId
    )
        external
        view
        returns (
            address[] memory nodeAddrs,
            bytes[] memory pubKeys,
            bool isValid
        )
    {
        MixPath storage path = paths[pathId];
        if (path.createdAt == 0) revert PathNotFound();

        nodeAddrs = path.nodes;
        pubKeys = path.publicKeys;
        isValid = block.timestamp < path.expiresAt;
    }

    // =========================================================================
    // MIX PROCESSING
    // =========================================================================

    /**
     * @notice Record a successful mix operation
     * @param inputCommitment Commitment of input message
     * @param outputCommitment Commitment of output message
     */
    function recordMixSuccess(
        bytes32 inputCommitment,
        bytes32 outputCommitment
    ) external {
        MixNode storage node = nodes[msg.sender];
        if (node.status != NodeStatus.ACTIVE) revert NodeNotActive();

        node.totalProcessed++;
        node.successfulMixes++;
        node.lastActiveAt = block.timestamp;

        // Update reputation (increase slightly for success)
        _updateReputation(msg.sender, true);

        emit MixProcessed(
            msg.sender,
            inputCommitment,
            outputCommitment,
            block.timestamp
        );
    }

    /**
     * @notice Record a failed mix operation (self-reported)
     */
    function recordMixFailure(
        bytes32 /* inputCommitment */,
        string calldata /* reason */
    ) external {
        MixNode storage node = nodes[msg.sender];
        if (node.status != NodeStatus.ACTIVE) revert NodeNotActive();

        node.totalProcessed++;
        node.failedMixes++;

        // Update reputation (decrease for failure)
        _updateReputation(msg.sender, false);
    }

    // =========================================================================
    // SLASHING
    // =========================================================================

    /**
     * @notice Slash a misbehaving node
     * @param operator Node operator to slash
     * @param reason Reason for slashing
     * @param evidence Cryptographic evidence of misbehavior
     */
    function slashNode(
        address operator,
        SlashReason reason,
        bytes calldata evidence
    ) external onlyRole(SLASHER_ROLE) {
        MixNode storage node = nodes[operator];
        if (node.registeredAt == 0) revert NodeNotFound();

        // Verify evidence (TODO: implement actual verification)
        if (evidence.length == 0) revert InvalidEvidence();

        uint256 slashAmount = (node.stake * SLASH_PERCENTAGE) / 10000;
        node.stake -= slashAmount;
        node.slashedAmount += slashAmount;
        node.slashedAt = block.timestamp;
        node.status = NodeStatus.SLASHED;
        node.reputation = 0;

        // Remove from active nodes
        _removeFromActiveNodes(operator);

        // Update total stake
        uint256 effectiveSlash = slashAmount > MAX_STAKE
            ? MAX_STAKE
            : slashAmount;
        if (totalActiveStake >= effectiveSlash) {
            totalActiveStake -= effectiveSlash;
        }

        emit NodeSlashed(operator, slashAmount, reason, evidence);
    }

    // =========================================================================
    // EXIT
    // =========================================================================

    /**
     * @notice Request to exit as a mix node
     */
    function requestExit() external nonReentrant {
        MixNode storage node = nodes[msg.sender];
        if (node.registeredAt == 0) revert NodeNotFound();
        if (
            node.status == NodeStatus.EXITING ||
            node.status == NodeStatus.EXITED
        ) {
            revert AlreadyExiting();
        }

        node.status = NodeStatus.EXITING;
        node.exitRequestedAt = block.timestamp;

        _removeFromActiveNodes(msg.sender);

        emit NodeExitRequested(msg.sender, block.timestamp + UNBONDING_PERIOD);
    }

    /**
     * @notice Complete exit and withdraw stake
     */
    function completeExit() external nonReentrant {
        MixNode storage node = nodes[msg.sender];
        if (node.status != NodeStatus.EXITING) revert NodeNotFound();
        if (block.timestamp < node.exitRequestedAt + UNBONDING_PERIOD) {
            revert UnbondingNotComplete();
        }

        uint256 stakeToReturn = node.stake;
        node.stake = 0;
        node.status = NodeStatus.EXITED;

        // Clear public key mapping
        delete publicKeyToOperator[node.publicKeyHash];

        (bool success, ) = msg.sender.call{value: stakeToReturn}("");
        require(success, "Transfer failed");

        emit NodeExited(msg.sender, stakeToReturn);
    }

    // =========================================================================
    // VIEW FUNCTIONS
    // =========================================================================

    /**
     * @notice Get node info
     */
    function getNodeInfo(
        address operator
    )
        external
        view
        returns (
            MixNode memory node,
            NodeCapabilities memory capabilities,
            bool isActive
        )
    {
        node = nodes[operator];
        capabilities = nodeCapabilities[operator];
        isActive = node.status == NodeStatus.ACTIVE;
    }

    /**
     * @notice Get active node count
     */
    function getActiveNodeCount() external view returns (uint256) {
        return activeNodes.length;
    }

    /**
     * @notice Check if mixnet has enough nodes
     */
    function isOperational() external view returns (bool) {
        return activeNodes.length >= MIN_ACTIVE_NODES;
    }

    /**
     * @notice Get all active node addresses
     */
    function getActiveNodes() external view returns (address[] memory) {
        return activeNodes;
    }

    // =========================================================================
    // INTERNAL FUNCTIONS
    // =========================================================================

    function _updateReputation(address operator, bool success) internal {
        MixNode storage node = nodes[operator];
        uint256 oldReputation = node.reputation;

        if (success) {
            // Increase by 0.1% per success, max 100%
            node.reputation = node.reputation + 10 > 10000
                ? 10000
                : node.reputation + 10;
        } else {
            // Decrease by 1% per failure
            node.reputation = node.reputation > 100 ? node.reputation - 100 : 0;
        }

        if (node.reputation != oldReputation) {
            emit ReputationUpdated(operator, oldReputation, node.reputation);
        }
    }

    function _removeFromActiveNodes(address operator) internal {
        uint256 index = activeNodeIndex[operator];
        uint256 lastIndex = activeNodes.length - 1;

        if (index != lastIndex) {
            address lastNode = activeNodes[lastIndex];
            activeNodes[index] = lastNode;
            activeNodeIndex[lastNode] = index;
        }

        activeNodes.pop();
        delete activeNodeIndex[operator];

        MixNode storage node = nodes[operator];
        uint256 effectiveStake = node.stake > MAX_STAKE
            ? MAX_STAKE
            : node.stake;
        if (totalActiveStake >= effectiveStake) {
            totalActiveStake -= effectiveStake;
        }

        emit NodeDeactivated(operator, "Removed from active set");
    }

    // =========================================================================
    // ADMIN FUNCTIONS
    // =========================================================================

    function setPathValidityPeriod(
        uint256 period
    ) external onlyRole(OPERATOR_ROLE) {
        require(period >= 10 minutes && period <= 24 hours, "Invalid period");
        pathValidityPeriod = period;
    }

    function pause() external onlyRole(OPERATOR_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(OPERATOR_ROLE) {
        _unpause();
    }

    // =========================================================================
    // UPGRADE AUTHORIZATION
    // =========================================================================

    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRole(UPGRADER_ROLE) {}
}
