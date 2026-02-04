// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/**
 * @title RelayerStaking
 * @author Soul Protocol
 * @notice Staking and slashing mechanism for Soul relayers
 * @dev Relayers must stake tokens to participate in the network
 *
 * Architecture:
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │                         Relayer Staking System                               │
 * ├─────────────────────────────────────────────────────────────────────────────┤
 * │                                                                              │
 * │  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐  │
 * │  │   Stake     │───▶│   Active    │───▶│   Relay     │───▶│   Rewards   │  │
 * │  │   Tokens    │    │   Relayer   │    │   Messages  │    │   Earned    │  │
 * │  └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘  │
 * │                           │                  │                              │
 * │                           ▼                  ▼                              │
 * │                    ┌─────────────┐    ┌─────────────┐                      │
 * │                    │  Slashing   │◀───│ Misbehavior │                      │
 * │                    │  Mechanism  │    │  Detection  │                      │
 * │                    └─────────────┘    └─────────────┘                      │
 * │                                                                              │
 * │  Security Features:                                                          │
 * │  • 7-day unbonding period                                                   │
 * │  • 1-day minimum stake duration (flash loan protection)                     │
 * │  • Configurable slashing (max 50%)                                          │
 * │  • VRF-based relayer selection (future)                                     │
 * │                                                                              │
 * └─────────────────────────────────────────────────────────────────────────────┘
 */
contract RelayerStaking is AccessControl, ReentrancyGuard, Pausable {
    using SafeERC20 for IERC20;

    // ============================================
    // ROLES
    // ============================================

    bytes32 public constant SLASHER_ROLE = keccak256("SLASHER_ROLE");
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    // ============================================
    // CONSTANTS
    // ============================================

    /// @notice Unbonding period (7 days)
    uint256 public constant UNBONDING_PERIOD = 7 days;

    /// @notice Flash loan protection: minimum stake duration before rewards accrue
    uint256 public constant MIN_STAKE_DURATION = 1 days;

    /// @notice Maximum slashing percentage (50%)
    uint256 public constant MAX_SLASHING_PERCENTAGE = 5000;

    /// @notice Precision for reward calculations
    uint256 public constant PRECISION = 1e18;

    // ============================================
    // ERRORS
    // ============================================

    error InvalidAmount();
    error InsufficientStake();
    error PendingUnstakeExists();
    error NoPendingUnstake();
    error UnbondingPeriodNotComplete();
    error NoStakeFound();
    error NoStakers();
    error InvalidSlashingPercentage();
    error ZeroAddress();
    error RelayerNotActive(address relayer);
    error AlreadyRegistered(address relayer);

    // ============================================
    // EVENTS
    // ============================================

    event Staked(address indexed relayer, uint256 amount);
    event UnstakeRequested(address indexed relayer, uint256 amount);
    event Unstaked(address indexed relayer, uint256 amount);
    event Slashed(address indexed relayer, uint256 amount, string reason);
    event RelayerActivated(address indexed relayer);
    event RelayerDeactivated(address indexed relayer);
    event RewardClaimed(address indexed relayer, uint256 amount);
    event RewardAdded(uint256 amount);
    event MinStakeUpdated(uint256 oldMinStake, uint256 newMinStake);
    event SlashingPercentageUpdated(
        uint256 oldPercentage,
        uint256 newPercentage
    );
    event RelayRecorded(address indexed relayer, bool success);
    event MetadataUpdated(address indexed relayer, string metadata);

    // ============================================
    // STRUCTS
    // ============================================

    /**
     * @notice Relayer information
     */
    struct Relayer {
        uint256 stakedAmount;
        uint256 pendingUnstake;
        uint256 unstakeRequestTime;
        uint256 rewardDebt;
        uint256 successfulRelays;
        uint256 failedRelays;
        uint256 lastRelayTimestamp;
        bool isActive;
        string metadata; // IPFS hash or URL for relayer info
    }

    /**
     * @notice Relayer stats (view struct)
     */
    struct RelayerStats {
        address relayerAddress;
        uint256 stakedAmount;
        uint256 pendingUnstake;
        uint256 successfulRelays;
        uint256 failedRelays;
        uint256 pendingRewards;
        bool isActive;
    }

    // ============================================
    // STATE VARIABLES
    // ============================================

    /// @notice Staking token (Soul token)
    IERC20 public immutable stakingToken;

    /// @notice Minimum stake required to be an active relayer
    uint256 public minStake;

    /// @notice Slashing percentage (in basis points, 1000 = 10%)
    uint256 public slashingPercentage;

    /// @notice Total staked across all relayers
    uint256 public totalStaked;

    /// @notice Reward pool
    uint256 public rewardPool;

    /// @notice Accumulated rewards per share
    uint256 public rewardPerShare;

    /// @notice Relayer address => Relayer info
    mapping(address => Relayer) public relayers;

    /// @notice List of active relayers
    address[] public activeRelayers;

    /// @notice Relayer address => index in activeRelayers
    mapping(address => uint256) public relayerIndex;

    /// @notice Staking timestamp for flash loan protection
    mapping(address => uint256) public stakingTimestamp;

    // ============================================
    // CONSTRUCTOR
    // ============================================

    /**
     * @notice Initialize the RelayerStaking contract
     * @param _stakingToken Address of the staking token
     * @param _minStake Minimum stake required
     * @param admin Admin address
     */
    constructor(address _stakingToken, uint256 _minStake, address admin) {
        if (_stakingToken == address(0) || admin == address(0)) {
            revert ZeroAddress();
        }

        stakingToken = IERC20(_stakingToken);
        minStake = _minStake;
        slashingPercentage = 1000; // 10% default

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(ADMIN_ROLE, admin);
        _grantRole(SLASHER_ROLE, admin);
        _grantRole(OPERATOR_ROLE, admin);
    }

    // ============================================
    // STAKING FUNCTIONS
    // ============================================

    /**
     * @notice Stake tokens to become a relayer
     * @param amount Amount to stake
     */
    function stake(uint256 amount) external nonReentrant whenNotPaused {
        if (amount == 0) revert InvalidAmount();

        stakingToken.safeTransferFrom(msg.sender, address(this), amount);

        Relayer storage relayer = relayers[msg.sender];

        // Claim pending rewards first (only if eligible)
        if (
            relayer.stakedAmount > 0 &&
            block.timestamp >= stakingTimestamp[msg.sender] + MIN_STAKE_DURATION
        ) {
            _claimRewards(msg.sender);
        }

        // Update staking timestamp for flash loan protection
        if (relayer.stakedAmount == 0) {
            stakingTimestamp[msg.sender] = block.timestamp;
        }

        relayer.stakedAmount += amount;
        relayer.rewardDebt =
            (relayer.stakedAmount * rewardPerShare) /
            PRECISION;
        totalStaked += amount;

        emit Staked(msg.sender, amount);

        // Activate if meets minimum stake
        if (!relayer.isActive && relayer.stakedAmount >= minStake) {
            _activateRelayer(msg.sender);
        }
    }

    /**
     * @notice Request to unstake tokens (starts unbonding period)
     * @param amount Amount to unstake
     */
    function requestUnstake(
        uint256 amount
    ) external nonReentrant whenNotPaused {
        Relayer storage relayer = relayers[msg.sender];
        if (relayer.stakedAmount < amount) revert InsufficientStake();
        if (relayer.pendingUnstake != 0) revert PendingUnstakeExists();

        // Claim pending rewards first
        _claimRewards(msg.sender);

        relayer.stakedAmount -= amount;
        relayer.pendingUnstake = amount;
        relayer.unstakeRequestTime = block.timestamp;
        relayer.rewardDebt =
            (relayer.stakedAmount * rewardPerShare) /
            PRECISION;
        totalStaked -= amount;

        emit UnstakeRequested(msg.sender, amount);

        // Deactivate if below minimum
        if (relayer.isActive && relayer.stakedAmount < minStake) {
            _deactivateRelayer(msg.sender);
        }
    }

    /**
     * @notice Complete unstaking after unbonding period
     */
    function completeUnstake() external nonReentrant {
        Relayer storage relayer = relayers[msg.sender];
        if (relayer.pendingUnstake == 0) revert NoPendingUnstake();
        if (block.timestamp < relayer.unstakeRequestTime + UNBONDING_PERIOD) {
            revert UnbondingPeriodNotComplete();
        }

        uint256 amount = relayer.pendingUnstake;
        relayer.pendingUnstake = 0;
        relayer.unstakeRequestTime = 0;

        stakingToken.safeTransfer(msg.sender, amount);

        emit Unstaked(msg.sender, amount);
    }

    /**
     * @notice Cancel pending unstake request
     */
    function cancelUnstake() external nonReentrant whenNotPaused {
        Relayer storage relayer = relayers[msg.sender];
        if (relayer.pendingUnstake == 0) revert NoPendingUnstake();

        uint256 amount = relayer.pendingUnstake;
        relayer.pendingUnstake = 0;
        relayer.unstakeRequestTime = 0;
        relayer.stakedAmount += amount;
        totalStaked += amount;

        // Reactivate if meets minimum
        if (!relayer.isActive && relayer.stakedAmount >= minStake) {
            _activateRelayer(msg.sender);
        }
    }

    // ============================================
    // SLASHING FUNCTIONS
    // ============================================

    /**
     * @notice Slash a relayer for misbehavior
     * @param relayerAddress Address of the relayer to slash
     * @param reason Reason for slashing
     */
    function slash(
        address relayerAddress,
        string calldata reason
    ) external onlyRole(SLASHER_ROLE) nonReentrant {
        Relayer storage relayer = relayers[relayerAddress];
        if (relayer.stakedAmount == 0) revert NoStakeFound();

        uint256 slashAmount = (relayer.stakedAmount * slashingPercentage) /
            10000;
        relayer.stakedAmount -= slashAmount;
        relayer.failedRelays++;
        totalStaked -= slashAmount;

        // Add slashed tokens to reward pool
        rewardPool += slashAmount;
        if (totalStaked > 0) {
            rewardPerShare += (slashAmount * PRECISION) / totalStaked;
        }

        emit Slashed(relayerAddress, slashAmount, reason);

        // Deactivate if below minimum
        if (relayer.isActive && relayer.stakedAmount < minStake) {
            _deactivateRelayer(relayerAddress);
        }
    }

    /**
     * @notice Slash with custom percentage (for severe violations)
     * @param relayerAddress Address of the relayer to slash
     * @param customPercentage Custom slashing percentage in basis points
     * @param reason Reason for slashing
     */
    function slashCustom(
        address relayerAddress,
        uint256 customPercentage,
        string calldata reason
    ) external onlyRole(SLASHER_ROLE) nonReentrant {
        if (customPercentage > MAX_SLASHING_PERCENTAGE) {
            revert InvalidSlashingPercentage();
        }

        Relayer storage relayer = relayers[relayerAddress];
        if (relayer.stakedAmount == 0) revert NoStakeFound();

        uint256 slashAmount = (relayer.stakedAmount * customPercentage) / 10000;
        relayer.stakedAmount -= slashAmount;
        relayer.failedRelays++;
        totalStaked -= slashAmount;

        // Add slashed tokens to reward pool
        rewardPool += slashAmount;
        if (totalStaked > 0) {
            rewardPerShare += (slashAmount * PRECISION) / totalStaked;
        }

        emit Slashed(relayerAddress, slashAmount, reason);

        // Deactivate if below minimum
        if (relayer.isActive && relayer.stakedAmount < minStake) {
            _deactivateRelayer(relayerAddress);
        }
    }

    // ============================================
    // REWARD FUNCTIONS
    // ============================================

    /**
     * @notice Claim accumulated rewards
     */
    function claimRewards() external nonReentrant whenNotPaused {
        _claimRewards(msg.sender);
    }

    /**
     * @notice Add rewards to the pool
     * @param amount Amount of tokens to add
     */
    function addRewards(uint256 amount) external nonReentrant whenNotPaused {
        if (amount == 0) revert InvalidAmount();
        if (totalStaked == 0) revert NoStakers();

        stakingToken.safeTransferFrom(msg.sender, address(this), amount);

        rewardPool += amount;
        rewardPerShare += (amount * PRECISION) / totalStaked;

        emit RewardAdded(amount);
    }

    /**
     * @dev Internal function to claim rewards
     * @notice Includes flash loan protection - minimum stake duration required
     */
    function _claimRewards(address relayerAddress) internal {
        Relayer storage relayer = relayers[relayerAddress];

        // Flash loan protection: require minimum stake duration
        if (
            block.timestamp <
            stakingTimestamp[relayerAddress] + MIN_STAKE_DURATION
        ) {
            return; // Silently return if stake is too new
        }

        uint256 pending = ((relayer.stakedAmount * rewardPerShare) /
            PRECISION) - relayer.rewardDebt;

        if (pending > 0) {
            relayer.rewardDebt =
                (relayer.stakedAmount * rewardPerShare) /
                PRECISION;
            stakingToken.safeTransfer(relayerAddress, pending);
            emit RewardClaimed(relayerAddress, pending);
        }
    }

    // ============================================
    // RELAY RECORDING
    // ============================================

    /**
     * @notice Record a successful relay
     * @param relayerAddress Address of the relayer
     */
    function recordSuccessfulRelay(
        address relayerAddress
    ) external onlyRole(OPERATOR_ROLE) {
        Relayer storage relayer = relayers[relayerAddress];
        relayer.successfulRelays++;
        relayer.lastRelayTimestamp = block.timestamp;
        emit RelayRecorded(relayerAddress, true);
    }

    /**
     * @notice Record a failed relay
     * @param relayerAddress Address of the relayer
     */
    function recordFailedRelay(
        address relayerAddress
    ) external onlyRole(OPERATOR_ROLE) {
        Relayer storage relayer = relayers[relayerAddress];
        relayer.failedRelays++;
        relayer.lastRelayTimestamp = block.timestamp;
        emit RelayRecorded(relayerAddress, false);
    }

    // ============================================
    // INTERNAL FUNCTIONS
    // ============================================

    /**
     * @dev Activate a relayer
     */
    function _activateRelayer(address relayerAddress) internal {
        Relayer storage relayer = relayers[relayerAddress];
        relayer.isActive = true;
        relayerIndex[relayerAddress] = activeRelayers.length;
        activeRelayers.push(relayerAddress);
        emit RelayerActivated(relayerAddress);
    }

    /**
     * @dev Deactivate a relayer
     */
    function _deactivateRelayer(address relayerAddress) internal {
        Relayer storage relayer = relayers[relayerAddress];
        relayer.isActive = false;

        // Remove from active list using swap-and-pop
        uint256 index = relayerIndex[relayerAddress];
        uint256 lastIndex = activeRelayers.length - 1;

        if (index != lastIndex) {
            address lastRelayer = activeRelayers[lastIndex];
            activeRelayers[index] = lastRelayer;
            relayerIndex[lastRelayer] = index;
        }

        activeRelayers.pop();
        delete relayerIndex[relayerAddress];

        emit RelayerDeactivated(relayerAddress);
    }

    // ============================================
    // VIEW FUNCTIONS
    // ============================================

    /**
     * @notice Get pending rewards for a relayer
     */
    function pendingRewards(
        address relayerAddress
    ) external view returns (uint256) {
        Relayer storage relayer = relayers[relayerAddress];
        return
            ((relayer.stakedAmount * rewardPerShare) / PRECISION) -
            relayer.rewardDebt;
    }

    /**
     * @notice Get all active relayers
     */
    function getActiveRelayers() external view returns (address[] memory) {
        return activeRelayers;
    }

    /**
     * @notice Get relayer count
     */
    function getActiveRelayerCount() external view returns (uint256) {
        return activeRelayers.length;
    }

    /**
     * @notice Check if address is an active relayer
     */
    function isActiveRelayer(
        address relayerAddress
    ) external view returns (bool) {
        return relayers[relayerAddress].isActive;
    }

    /**
     * @notice Get relayer stats
     */
    function getRelayerStats(
        address relayerAddress
    ) external view returns (RelayerStats memory stats) {
        Relayer storage relayer = relayers[relayerAddress];
        stats = RelayerStats({
            relayerAddress: relayerAddress,
            stakedAmount: relayer.stakedAmount,
            pendingUnstake: relayer.pendingUnstake,
            successfulRelays: relayer.successfulRelays,
            failedRelays: relayer.failedRelays,
            pendingRewards: ((relayer.stakedAmount * rewardPerShare) /
                PRECISION) - relayer.rewardDebt,
            isActive: relayer.isActive
        });
    }

    /**
     * @notice Get time remaining until unstake completes
     */
    function getUnstakeTimeRemaining(
        address relayerAddress
    ) external view returns (uint256) {
        Relayer storage relayer = relayers[relayerAddress];
        if (relayer.pendingUnstake == 0) return 0;

        uint256 unlockTime = relayer.unstakeRequestTime + UNBONDING_PERIOD;
        if (block.timestamp >= unlockTime) return 0;
        return unlockTime - block.timestamp;
    }

    // ============================================
    // ADMIN FUNCTIONS
    // ============================================

    /**
     * @notice Update minimum stake requirement
     */
    function setMinStake(uint256 _minStake) external onlyRole(ADMIN_ROLE) {
        uint256 oldMinStake = minStake;
        minStake = _minStake;
        emit MinStakeUpdated(oldMinStake, _minStake);
    }

    /**
     * @notice Update slashing percentage
     */
    function setSlashingPercentage(
        uint256 _slashingPercentage
    ) external onlyRole(ADMIN_ROLE) {
        if (_slashingPercentage > MAX_SLASHING_PERCENTAGE) {
            revert InvalidSlashingPercentage();
        }
        uint256 oldPercentage = slashingPercentage;
        slashingPercentage = _slashingPercentage;
        emit SlashingPercentageUpdated(oldPercentage, _slashingPercentage);
    }

    /**
     * @notice Update relayer metadata
     */
    function updateMetadata(string calldata metadata) external {
        relayers[msg.sender].metadata = metadata;
        emit MetadataUpdated(msg.sender, metadata);
    }

    /**
     * @notice Pause the contract
     */
    function pause() external onlyRole(ADMIN_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause the contract
     */
    function unpause() external onlyRole(ADMIN_ROLE) {
        _unpause();
    }

    /**
     * @notice Emergency withdraw for admin (only when paused)
     * @param token Token to withdraw
     * @param amount Amount to withdraw
     * @param recipient Recipient address
     */
    function emergencyWithdraw(
        address token,
        uint256 amount,
        address recipient
    ) external onlyRole(DEFAULT_ADMIN_ROLE) whenPaused {
        if (recipient == address(0)) revert ZeroAddress();
        IERC20(token).safeTransfer(recipient, amount);
    }
}
