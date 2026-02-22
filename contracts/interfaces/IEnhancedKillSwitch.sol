// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title IEnhancedKillSwitch
 * @notice Interface for the EnhancedKillSwitch multi-level emergency response system
 * @dev Inherits: AccessControl, ReentrancyGuard, Pausable
 */
interface IEnhancedKillSwitch {
    /*//////////////////////////////////////////////////////////////
                                 ENUMS
    //////////////////////////////////////////////////////////////*/

    /// @notice Emergency levels from NONE to PERMANENT
    enum EmergencyLevel {
        NONE,
        WARNING,
        DEGRADED,
        HALTED,
        LOCKED,
        PERMANENT
    }

    enum ActionType {
        DEPOSIT,
        WITHDRAWAL,
        BRIDGE,
        GOVERNANCE,
        UPGRADE,
        EMERGENCY_WITHDRAWAL
    }

    /*//////////////////////////////////////////////////////////////
                                STRUCTS
    //////////////////////////////////////////////////////////////*/

    struct RecoveryRequest {
        EmergencyLevel targetLevel;
        address initiator;
        uint256 requestedAt;
        uint256 executableAt;
        uint256 confirmations;
        bool executed;
        bool cancelled;
    }

    struct EmergencyIncident {
        uint256 id;
        EmergencyLevel fromLevel;
        EmergencyLevel toLevel;
        address initiator;
        uint256 timestamp;
        string reason;
        bytes32 evidenceHash;
    }

    struct ProtocolState {
        bool depositsEnabled;
        bool withdrawalsEnabled;
        bool bridgingEnabled;
        bool governanceEnabled;
        bool upgradesEnabled;
        bool emergencyWithdrawalsEnabled;
    }

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event EmergencyLevelChanged(
        EmergencyLevel indexed fromLevel,
        EmergencyLevel indexed toLevel,
        address indexed initiator,
        string reason
    );

    event EscalationInitiated(
        EmergencyLevel indexed targetLevel,
        address indexed initiator,
        uint256 executableAt
    );

    event EscalationConfirmed(
        EmergencyLevel indexed level,
        address indexed confirmer,
        uint256 totalConfirmations
    );

    event EscalationExecuted(
        EmergencyLevel indexed level,
        address indexed executor
    );

    event EscalationCancelled(
        EmergencyLevel indexed level,
        address indexed canceller
    );

    event RecoveryInitiated(
        EmergencyLevel indexed targetLevel,
        address indexed initiator,
        uint256 executableAt
    );

    event RecoveryExecuted(
        EmergencyLevel indexed toLevel,
        address indexed executor
    );

    event RecoveryCancelled(address indexed canceller);

    event GuardianAdded(address indexed guardian);
    event GuardianRemoved(address indexed guardian);
    event ContractProtected(address indexed contractAddr, bool status);
    event ActionRestrictionUpdated(
        EmergencyLevel level,
        ActionType action,
        bool allowed
    );

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    error InvalidLevel();
    error LevelAlreadySet();
    error CooldownNotPassed();
    error InsufficientConfirmations();
    error AlreadyConfirmed();
    error NoRecoveryPending();
    error RecoveryNotExecutable();
    error PermanentLockdown();
    error ActionNotAllowed();
    error TooManyGuardians();
    error NotGuardian();
    error RecoveryDelayNotPassed();
    error EscalationPending();
    error NoEscalationPending();
    error AlreadyConfirmedRecovery();

    /*//////////////////////////////////////////////////////////////
                          CONSTANTS / STATE
    //////////////////////////////////////////////////////////////*/

    function GUARDIAN_ROLE() external view returns (bytes32);

    function EMERGENCY_ROLE() external view returns (bytes32);

    function RECOVERY_ROLE() external view returns (bytes32);

    function LEVEL_1_COOLDOWN() external view returns (uint256);

    function LEVEL_2_COOLDOWN() external view returns (uint256);

    function LEVEL_3_COOLDOWN() external view returns (uint256);

    function LEVEL_4_COOLDOWN() external view returns (uint256);

    function LEVEL_5_COOLDOWN() external view returns (uint256);

    function RECOVERY_DELAY() external view returns (uint256);

    function FULL_RECOVERY_DELAY() external view returns (uint256);

    function MAX_GUARDIANS() external view returns (uint256);

    function LEVEL_3_CONFIRMATIONS() external view returns (uint256);

    function LEVEL_4_CONFIRMATIONS() external view returns (uint256);

    function LEVEL_5_CONFIRMATIONS() external view returns (uint256);

    function currentLevel() external view returns (EmergencyLevel);

    function previousLevel() external view returns (EmergencyLevel);

    function levelSetAt() external view returns (uint256);

    function pendingLevel() external view returns (EmergencyLevel);

    function pendingLevelExecutableAt() external view returns (uint256);

    function escalationConfirmations(
        EmergencyLevel level,
        address guardian
    ) external view returns (bool);

    function confirmationCount(
        EmergencyLevel level
    ) external view returns (uint256);

    function recoveryRequest()
        external
        view
        returns (
            EmergencyLevel targetLevel,
            address initiator,
            uint256 requestedAt,
            uint256 executableAt,
            uint256 confirmations,
            bool executed,
            bool cancelled
        );

    function protectedContracts(
        address contractAddr
    ) external view returns (bool);

    function contractOverrides(
        address contractAddr
    ) external view returns (EmergencyLevel);

    function actionAllowed(
        EmergencyLevel level,
        ActionType action
    ) external view returns (bool);

    function incidents(
        uint256 index
    )
        external
        view
        returns (
            uint256 id,
            EmergencyLevel fromLevel,
            EmergencyLevel toLevel,
            address initiator,
            uint256 timestamp,
            string memory reason,
            bytes32 evidenceHash
        );

    function guardians(uint256 index) external view returns (address);

    function isGuardian(address addr) external view returns (bool);

    function recoveryConfirmed(
        uint256 requestedAt,
        address guardian
    ) external view returns (bool);

    /*//////////////////////////////////////////////////////////////
                      ESCALATION FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function escalateEmergency(
        EmergencyLevel newLevel,
        string calldata reason
    ) external;

    function confirmEscalation(EmergencyLevel level) external;

    function executeEscalation() external;

    function cancelEscalation() external;

    /*//////////////////////////////////////////////////////////////
                       RECOVERY FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function initiateRecovery(EmergencyLevel targetLevel) external;

    function confirmRecovery() external;

    function executeRecovery() external;

    function cancelRecovery() external;

    /*//////////////////////////////////////////////////////////////
                         VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function isActionAllowed(
        ActionType action
    ) external view returns (bool allowed);

    function getProtocolState()
        external
        view
        returns (ProtocolState memory state);

    function getIncidents() external view returns (EmergencyIncident[] memory);

    function getGuardians() external view returns (address[] memory);

    /*//////////////////////////////////////////////////////////////
                         ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function addGuardian(address guardian) external;

    function removeGuardian(address guardian) external;

    function setProtectedContract(address contractAddr, bool status) external;

    function setContractOverride(
        address contractAddr,
        EmergencyLevel level
    ) external;

    function setActionRestriction(
        EmergencyLevel level,
        ActionType action,
        bool allowed
    ) external;
}
