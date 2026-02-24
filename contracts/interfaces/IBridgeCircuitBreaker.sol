// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title IBridgeCircuitBreaker
 * @notice Interface for the BridgeCircuitBreaker anomaly detection contract
 * @dev Automatic circuit breaker with anomaly detection for bridge operations
 */
interface IBridgeCircuitBreaker {
    /*//////////////////////////////////////////////////////////////
                                 ENUMS
    //////////////////////////////////////////////////////////////*/

    enum SystemState {
        NORMAL,
        WARNING,
        DEGRADED,
        HALTED
    }

    enum AnomalyType {
        LARGE_TRANSFER,
        HIGH_VELOCITY,
        TVL_DROP,
        SUSPICIOUS_PATTERN,
        EXTERNAL_TRIGGER
    }

    /*//////////////////////////////////////////////////////////////
                                STRUCTS
    //////////////////////////////////////////////////////////////*/

    struct Thresholds {
        uint256 largeTransferAmount;
        uint256 largeTransferPercent;
        uint256 velocityTxPerHour;
        uint256 velocityAmountPerHour;
        uint256 tvlDropPercent;
        uint256 warningScore;
        uint256 degradedScore;
        uint256 haltedScore;
    }

    struct AnomalyEvent {
        AnomalyType anomalyType;
        uint256 timestamp;
        uint256 severity;
        bytes32 dataHash;
        bool resolved;
    }

    struct MetricsWindow {
        uint256 txCount;
        uint256 totalVolume;
        uint256 largestTx;
        uint256 windowStart;
        uint256 windowEnd;
    }

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event StateChanged(
        SystemState indexed oldState,
        SystemState indexed newState,
        uint256 anomalyScore
    );

    event AnomalyDetected(
        AnomalyType indexed anomalyType,
        uint256 severity,
        bytes32 dataHash
    );

    event AnomalyResolved(uint256 indexed anomalyId);

    event ThresholdsUpdated(
        uint256 largeTransferAmount,
        uint256 velocityTxPerHour
    );

    event RecoveryProposed(
        uint256 indexed proposalId,
        address proposer,
        SystemState targetState
    );

    event RecoveryApproved(uint256 indexed proposalId, address approver);

    event RecoveryExecuted(uint256 indexed proposalId, SystemState newState);

    event MetricsRecorded(uint256 txCount, uint256 volume, uint256 timestamp);

    event ScoreUpdated(uint256 oldScore, uint256 newScore);

    event EmergencyAction(address indexed caller, bytes32 indexed threatId);

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    error InvalidState(SystemState current, SystemState required);
    error InvalidThreshold();
    error RecoveryNotReady(uint256 timeRemaining);
    error AlreadyApproved();
    error ProposalExpired();
    error InsufficientApprovals(uint256 current, uint256 required);
    error InvalidAnomalyID();
    error AlreadyResolved();
    error InvalidStateTransition();
    error AlreadyExecuted();
    error RecoveryDelayNotPassed();

    /*//////////////////////////////////////////////////////////////
                          CONSTANTS / STATE
    //////////////////////////////////////////////////////////////*/

    function MONITOR_ROLE() external view returns (bytes32);

    function GUARDIAN_ROLE() external view returns (bytes32);

    function RECOVERY_ROLE() external view returns (bytes32);

    function BASIS_POINTS() external view returns (uint256);

    function HOUR() external view returns (uint256);

    function MAX_ANOMALY_AGE() external view returns (uint256);

    function RECOVERY_DELAY() external view returns (uint256);

    function MIN_RECOVERY_APPROVALS() external view returns (uint256);

    function MAX_SCORE() external view returns (uint256);

    function currentState() external view returns (SystemState);

    function anomalyScore() external view returns (uint256);

    function currentTVL() external view returns (uint256);

    function baselineTVL() external view returns (uint256);

    function activeAnomalyCount() external view returns (uint256);

    function lastPrunedIndex() external view returns (uint256);

    function recoveryProposalCount() external view returns (uint256);

    function lastStateChange() external view returns (uint256);

    function warningCooldown() external view returns (uint256);

    function degradedCooldown() external view returns (uint256);

    /*//////////////////////////////////////////////////////////////
                      MONITORING FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function recordTransaction(uint256 amount, address sender) external;

    function updateTVL(uint256 newTVL) external;

    function reportAnomaly(
        AnomalyType anomalyType,
        uint256 severity,
        bytes32 dataHash
    ) external;

    function resolveAnomaly(uint256 anomalyId) external;

    function pruneAnomalies(uint256 limit) external;

    /*//////////////////////////////////////////////////////////////
                      RECOVERY FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function proposeRecovery(
        SystemState targetState
    ) external returns (uint256 proposalId);

    function approveRecovery(uint256 proposalId) external;

    function executeRecovery(uint256 proposalId) external;

    function emergencyHalt() external;

    function emergencyPause(bytes32 threatId) external;

    /*//////////////////////////////////////////////////////////////
                    CONFIGURATION FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function setThresholds(
        uint256 largeTransferAmount,
        uint256 largeTransferPercent,
        uint256 velocityTxPerHour,
        uint256 velocityAmountPerHour,
        uint256 tvlDropPercent,
        uint256 warningScore,
        uint256 degradedScore,
        uint256 haltedScore
    ) external;

    function setCooldowns(
        uint256 _warningCooldown,
        uint256 _degradedCooldown
    ) external;

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function isOperational() external view returns (bool);

    function isDegraded() external view returns (bool);

    function getCurrentMetrics()
        external
        view
        returns (
            uint256 txCount,
            uint256 volume,
            uint256 largestTx,
            uint256 score,
            SystemState state
        );

    function getActiveAnomalyCount() external view returns (uint256);

    function getRecoveryProposal(
        uint256 proposalId
    )
        external
        view
        returns (
            address proposer,
            SystemState targetState,
            uint256 proposedAt,
            uint256 approvalCount,
            bool executed,
            bool canExecute
        );
}
