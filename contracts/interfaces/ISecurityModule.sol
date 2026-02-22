// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title ISecurityModule
 * @notice Interface for the SecurityModule abstract contract
 * @dev SecurityModule is an abstract contract (not deployed standalone).
 *      This interface exposes its public/external view functions, events, and errors
 *      for contracts that inherit it (e.g., CrossChainProofHubV3, ShieldedPool).
 *
 *      Inheriting contracts: AccessControl, Pausable, SecurityModule
 */
interface ISecurityModule {
    /*//////////////////////////////////////////////////////////////
                            CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    error RateLimitExceeded(
        address account,
        uint256 actionCount,
        uint256 maxActions
    );

    error CircuitBreakerTriggered(uint256 currentVolume, uint256 threshold);

    error FlashLoanDetected(
        address account,
        uint256 depositBlock,
        uint256 currentBlock
    );

    error SingleWithdrawalLimitExceeded(uint256 amount, uint256 maxAmount);

    error DailyWithdrawalLimitExceeded(uint256 requested, uint256 remaining);

    error CooldownNotElapsed(uint256 remaining);

    error WindowTooShort();
    error WindowTooLong();
    error MaxActionsTooLow();
    error MaxActionsTooHigh();
    error ThresholdTooLow();
    error CooldownTooShort(uint256 minCooldown);
    error CooldownTooLong(uint256 maxCooldown);
    error InvalidWithdrawalLimits();

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event RateLimitTriggered(address indexed account, uint256 actionCount);
    event CircuitBreakerActivated(uint256 volume, uint256 threshold);
    event CircuitBreakerReset();
    event FlashLoanAttemptBlocked(address indexed account);
    event WithdrawalLimitApplied(address indexed account, uint256 amount);
    event SecurityConfigUpdated(
        string parameter,
        uint256 oldValue,
        uint256 newValue
    );

    /*//////////////////////////////////////////////////////////////
                       PUBLIC STATE GETTERS
    //////////////////////////////////////////////////////////////*/

    // Rate Limiting
    function lastActionTime(address account) external view returns (uint256);

    function actionCount(address account) external view returns (uint256);

    function rateLimitWindow() external view returns (uint256);

    function maxActionsPerWindow() external view returns (uint256);

    // Circuit Breaker
    function lastHourlyVolume() external view returns (uint256);

    function lastHourTimestamp() external view returns (uint256);

    function volumeThreshold() external view returns (uint256);

    function circuitBreakerCooldown() external view returns (uint256);

    function circuitBreakerTrippedAt() external view returns (uint256);

    // Flash Loan Guard
    function lastDepositBlock(address account) external view returns (uint256);

    function lastActionBlock(address account) external view returns (uint256);

    function minBlocksForWithdrawal() external view returns (uint256);

    // Withdrawal Limits
    function maxSingleWithdrawal() external view returns (uint256);

    function maxDailyWithdrawal() external view returns (uint256);

    function dailyWithdrawn() external view returns (uint256);

    function lastWithdrawalDay() external view returns (uint256);

    function accountDailyWithdrawn(
        address account
    ) external view returns (uint256);

    function accountLastWithdrawalDay(
        address account
    ) external view returns (uint256);

    function accountMaxDailyWithdrawal() external view returns (uint256);

    /*//////////////////////////////////////////////////////////////
                     PACKED FLAG PUBLIC GETTERS
    //////////////////////////////////////////////////////////////*/

    function rateLimitingEnabled() external view returns (bool);

    function circuitBreakerEnabled() external view returns (bool);

    function circuitBreakerTripped() external view returns (bool);

    function flashLoanGuardEnabled() external view returns (bool);

    function withdrawalLimitsEnabled() external view returns (bool);

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function getRemainingActions(
        address account
    ) external view returns (uint256 remaining);

    function getRemainingWithdrawal()
        external
        view
        returns (uint256 globalRemaining, uint256 accountRemaining);

    function getCircuitBreakerStatus()
        external
        view
        returns (
            bool isTripped,
            uint256 cooldownRemaining,
            uint256 currentVolume
        );

    function canWithdrawFlashLoanCheck(
        address account
    ) external view returns (bool canWithdraw, uint256 blocksRemaining);
}
