// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IDynamicRoutingOrchestrator} from "./IDynamicRoutingOrchestrator.sol";

/**
 * @title ILiquidityAwareRouter
 * @notice Interface for the LiquidityAwareRouter cross-chain transfer contract
 * @dev Liquidity-aware router that executes routes from DynamicRoutingOrchestrator
 */
interface ILiquidityAwareRouter {
    /*//////////////////////////////////////////////////////////////
                                 ENUMS
    //////////////////////////////////////////////////////////////*/

    enum TransferStatus {
        NONE,
        COMMITTED,
        EXECUTING,
        SETTLED,
        FAILED,
        REFUNDED
    }

    /*//////////////////////////////////////////////////////////////
                                STRUCTS
    //////////////////////////////////////////////////////////////*/

    struct Transfer {
        bytes32 routeId;
        address user;
        uint256 sourceChainId;
        uint256 destChainId;
        uint256 amount;
        uint256 fee;
        uint256 protocolFee;
        TransferStatus status;
        uint48 committedAt;
        uint48 settledAt;
        address destRecipient;
    }

    struct PairMetrics {
        uint256 totalVolume;
        uint256 totalFees;
        uint256 transferCount;
        uint48 lastTransfer;
    }

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event TransferCommitted(
        bytes32 indexed transferId,
        bytes32 indexed routeId,
        address indexed user,
        uint256 sourceChainId,
        uint256 destChainId,
        uint256 amount,
        uint256 fee
    );

    event TransferExecuting(
        bytes32 indexed transferId,
        address indexed executor
    );

    event TransferSettled(
        bytes32 indexed transferId,
        uint48 settlementTime,
        uint256 actualFee
    );

    event TransferFailed(bytes32 indexed transferId, string reason);

    event TransferRefunded(
        bytes32 indexed transferId,
        address indexed user,
        uint256 amount
    );

    event FeesWithdrawn(address indexed recipient, uint256 amount);

    event CooldownUpdated(uint48 oldCooldown, uint48 newCooldown);

    event TimeoutUpdated(uint48 oldTimeout, uint48 newTimeout);

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    error ZeroAddress();
    error TransferTooLarge(uint256 amount, uint256 max);
    error CooldownNotElapsed(address user, uint48 remaining);
    error TransferNotFound(bytes32 transferId);
    error InvalidTransferStatus(
        bytes32 transferId,
        TransferStatus current,
        TransferStatus expected
    );
    error TransferTimedOut(bytes32 transferId);
    error TransferNotTimedOut(bytes32 transferId);
    error InsufficientPayment(uint256 required, uint256 provided);
    error NoFeesToWithdraw();
    error WithdrawFailed();

    /*//////////////////////////////////////////////////////////////
                          CONSTANTS / STATE
    //////////////////////////////////////////////////////////////*/

    function EXECUTOR_ROLE() external view returns (bytes32);

    function SETTLER_ROLE() external view returns (bytes32);

    function PROTOCOL_FEE_BPS() external view returns (uint16);

    function BPS() external view returns (uint16);

    function DEFAULT_COOLDOWN() external view returns (uint48);

    function MAX_TRANSFER_AMOUNT() external view returns (uint256);

    function orchestrator() external view returns (IDynamicRoutingOrchestrator);

    function accumulatedFees() external view returns (uint256);

    function transferTimeout() external view returns (uint48);

    function userCooldown() external view returns (uint48);

    function lastTransferAt(address user) external view returns (uint48);

    /*//////////////////////////////////////////////////////////////
                        TRANSFER LIFECYCLE
    //////////////////////////////////////////////////////////////*/

    function quoteTransfer(
        uint256 sourceChainId,
        uint256 destChainId,
        uint256 amount,
        IDynamicRoutingOrchestrator.Urgency urgency
    )
        external
        view
        returns (
            IDynamicRoutingOrchestrator.Route memory route,
            uint256 totalRequired
        );

    function commitTransfer(
        bytes32 routeId,
        address destRecipient
    ) external payable returns (bytes32 transferId);

    function beginExecution(bytes32 transferId) external;

    function settleTransfer(bytes32 transferId, uint48 actualLatency) external;

    function failTransfer(bytes32 transferId, string calldata reason) external;

    function refundTimedOut(bytes32 transferId) external;

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function getTransfer(
        bytes32 transferId
    ) external view returns (Transfer memory t);

    function getPairMetrics(
        uint256 sourceChainId,
        uint256 destChainId
    ) external view returns (PairMetrics memory metrics);

    function canUserTransfer(
        address user
    ) external view returns (bool canTransfer, uint48 cooldownRemaining);

    /*//////////////////////////////////////////////////////////////
                         ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function withdrawFees(address recipient) external;

    function setCooldown(uint48 newCooldown) external;

    function setTimeout(uint48 newTimeout) external;

    function pause() external;

    function unpause() external;
}
