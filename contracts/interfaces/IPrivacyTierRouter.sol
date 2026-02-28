// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title IPrivacyTierRouter
 * @notice Interface for tiered privacy routing with auto-escalation
 * @dev Inspired by Arcium's configurable MXE trust assumptions — routes privacy
 *      operations through STANDARD / ENHANCED / MAXIMUM tiers based on value
 *      thresholds, user preferences, and security requirements
 */
interface IPrivacyTierRouter {
    /*//////////////////////////////////////////////////////////////
                                ENUMS
    //////////////////////////////////////////////////////////////*/

    /// @notice Privacy tier levels — higher tiers require more relayers and privacy features
    enum PrivacyTier {
        STANDARD, // 1 relayer, basic encryption
        ENHANCED, // 3+ relayers, ring signatures
        MAXIMUM // 5+ relayers, constant-time execution, mixnet, recursive proofs
    }

    /*//////////////////////////////////////////////////////////////
                                STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Configuration for a privacy tier
    struct TierConfig {
        uint8 minRelayers;
        bool requireRingSig;
        bool requireConstantTime;
        bool requireMixnet;
        bool requireRecursiveProof;
        uint256 escalationThreshold; // Value (in wei) above which auto-escalation kicks in
    }

    /// @notice A privacy operation routed through the system
    struct PrivacyOperation {
        bytes32 operationId;
        address sender;
        PrivacyTier tier;
        uint256 value;
        uint32 sourceChainId;
        uint32 destChainId;
        bytes32 assignedCluster;
        uint64 submittedAt;
        bool completed;
    }

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event OperationSubmitted(
        bytes32 indexed operationId,
        address indexed sender,
        PrivacyTier tier,
        uint256 value
    );

    event TierEscalated(
        bytes32 indexed operationId,
        PrivacyTier fromTier,
        PrivacyTier toTier,
        string reason
    );

    event ClusterAssigned(
        bytes32 indexed operationId,
        bytes32 indexed clusterId
    );

    event OperationCompleted(bytes32 indexed operationId, bool success);

    event TierConfigUpdated(PrivacyTier indexed tier, uint8 minRelayers);

    event UserDefaultTierSet(address indexed user, PrivacyTier tier);

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    error OperationAlreadyExists(bytes32 operationId);
    error OperationDoesNotExist(bytes32 operationId);
    error OperationAlreadyCompleted(bytes32 operationId);
    error TierDowngradeNotAllowed(PrivacyTier current, PrivacyTier requested);
    error NoClusterAvailable(
        uint32 sourceChainId,
        uint32 destChainId,
        PrivacyTier tier
    );
    error InvalidTierConfig(PrivacyTier tier);

    /*//////////////////////////////////////////////////////////////
                            EXTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function submitOperation(
        uint32 sourceChainId,
        uint32 destChainId,
        PrivacyTier requestedTier,
        uint256 value
    ) external returns (bytes32 operationId);

    function assignCluster(bytes32 operationId, bytes32 clusterId) external;

    function completeOperation(bytes32 operationId, bool success) external;

    function setUserDefaultTier(PrivacyTier tier) external;

    function configureTier(
        PrivacyTier tier,
        TierConfig calldata config
    ) external;

    function getOperation(
        bytes32 operationId
    ) external view returns (PrivacyOperation memory);

    function getEffectiveTier(
        address user,
        uint256 value
    ) external view returns (PrivacyTier);

    function getTierConfig(
        PrivacyTier tier
    ) external view returns (TierConfig memory);
}
