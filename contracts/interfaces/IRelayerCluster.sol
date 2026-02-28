// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title IRelayerCluster
 * @notice Interface for cluster-based relayer grouping with collective SLAs
 * @dev Inspired by Arcium's cluster model — groups relayers into fault-tolerant
 *      units for specific chain pairs with health scoring and auto-management
 */
interface IRelayerCluster {
    /*//////////////////////////////////////////////////////////////
                                STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Core cluster metadata
    struct ClusterInfo {
        bytes32 clusterId;
        uint32 sourceChainId;
        uint32 destChainId;
        uint256 minStakePerMember;
        uint256 totalStake;
        uint8 memberCount;
        uint8 maxMembers;
        uint64 createdAt;
        bool active;
        uint8 healthScore; // 0-100
    }

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event ClusterCreated(
        bytes32 indexed clusterId,
        uint32 indexed sourceChainId,
        uint32 indexed destChainId,
        address creator,
        uint256 minStakePerMember
    );

    event RelayerJoinedCluster(
        bytes32 indexed clusterId,
        address indexed relayer,
        uint256 stake
    );

    event RelayerLeftCluster(
        bytes32 indexed clusterId,
        address indexed relayer
    );

    event ClusterActivated(bytes32 indexed clusterId, uint8 memberCount);

    event ClusterDeactivated(bytes32 indexed clusterId, string reason);

    event RelayRecorded(
        bytes32 indexed clusterId,
        address indexed relayer,
        bool success,
        uint256 latencyMs
    );

    event ClusterHealthUpdated(
        bytes32 indexed clusterId,
        uint8 oldScore,
        uint8 newScore
    );

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    error ClusterAlreadyExists(bytes32 clusterId);
    error ClusterDoesNotExist(bytes32 clusterId);
    error ClusterFull(bytes32 clusterId);
    error ClusterNotActive(bytes32 clusterId);
    error AlreadyInCluster(bytes32 clusterId, address relayer);
    error NotInCluster(bytes32 clusterId, address relayer);
    error InsufficientClusterStake(uint256 provided, uint256 required);
    error TooManyClusterMemberships(address relayer, uint256 max);
    error InvalidChainPair(uint32 sourceChainId, uint32 destChainId);
    error NotClusterCreator(bytes32 clusterId, address caller);

    /*//////////////////////////////////////////////////////////////
                            EXTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function createCluster(
        uint32 sourceChainId,
        uint32 destChainId,
        uint256 minStakePerMember,
        uint8 maxMembers
    ) external returns (bytes32 clusterId);

    function joinCluster(bytes32 clusterId) external payable;

    function leaveCluster(bytes32 clusterId) external;

    function recordRelay(
        bytes32 clusterId,
        address relayer,
        bool success,
        uint256 latencyMs
    ) external;

    function getCluster(
        bytes32 clusterId
    ) external view returns (ClusterInfo memory);

    function getClusterMembers(
        bytes32 clusterId
    ) external view returns (address[] memory);

    function getBestCluster(
        uint32 sourceChainId,
        uint32 destChainId
    ) external view returns (bytes32 clusterId);

    function isClusterMember(
        bytes32 clusterId,
        address relayer
    ) external view returns (bool);

    function getRelayerClusters(
        address relayer
    ) external view returns (bytes32[] memory);
}
