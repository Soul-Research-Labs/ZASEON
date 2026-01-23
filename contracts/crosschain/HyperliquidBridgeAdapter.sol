// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import "../hyperliquid/HyperliquidPrimitives.sol";

/**
 * @title HyperliquidBridgeAdapter
 * @notice Bridge adapter for Hyperliquid L1 integration with PIL
 * @dev Hyperliquid uses Arbitrum as its L1 settlement layer
 *
 * Key Features:
 * - Validator committee management
 * - Block finality verification
 * - HIP-1 token transfers
 * - Cross-domain nullifier binding
 * - Sub-second finality (~200ms)
 */
contract HyperliquidBridgeAdapter is
    Initializable,
    UUPSUpgradeable,
    AccessControlUpgradeable,
    PausableUpgradeable,
    ReentrancyGuardUpgradeable
{
    using HyperliquidPrimitives for *;

    // =========================================================================
    // ROLES
    // =========================================================================

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");
    bytes32 public constant VALIDATOR_ROLE = keccak256("VALIDATOR_ROLE");

    // =========================================================================
    // CONSTANTS
    // =========================================================================

    uint256 public constant MAX_TRANSFER = 100_000 ether;
    uint256 public constant DAILY_LIMIT = 1_000_000 ether;
    uint256 public constant MAX_RELAYER_FEE_BPS = 500; // 5%
    uint256 public constant MIN_CONFIRMATIONS = 1; // Sub-second finality
    uint256 public constant MAX_VALIDATORS = 100;
    uint256 public constant QUORUM_THRESHOLD_BPS = 6667; // 66.67%

    // =========================================================================
    // STATE VARIABLES
    // =========================================================================

    /// @notice Current validator set
    mapping(address => HyperliquidPrimitives.Validator) public validators;
    address[] public validatorList;
    uint256 public totalVotingPower;

    /// @notice Finalized blocks
    mapping(uint64 => HyperliquidPrimitives.BlockHeader) public finalizedBlocks;
    uint64 public latestFinalizedHeight;

    /// @notice Deposits
    mapping(bytes32 => HyperliquidPrimitives.Deposit) public deposits;
    bytes32[] public depositHashes;

    /// @notice Withdrawals
    mapping(bytes32 => HyperliquidPrimitives.Withdrawal) public withdrawals;
    bytes32[] public withdrawalHashes;

    /// @notice Cross-domain nullifiers
    mapping(bytes32 => bytes32) public crossDomainNullifiers; // hlNf -> pilNf
    mapping(bytes32 => bytes32) public pilBindings; // pilNf -> hlNf
    mapping(bytes32 => bool) public usedNullifiers;

    /// @notice HIP-1 token mappings
    mapping(uint256 => address) public hip1ToErc20; // HIP-1 tokenId -> ERC20 address
    mapping(address => uint256) public erc20ToHip1; // ERC20 address -> HIP-1 tokenId

    /// @notice Relayer management
    mapping(address => bool) public registeredRelayers;
    uint256 public relayerFeeBps;

    /// @notice Rate limiting
    uint256 public dailyVolume;
    uint256 public lastVolumeReset;
    uint256 public totalValueLocked;

    /// @notice Circuit breaker
    bool public circuitBreakerActive;
    string public circuitBreakerReason;

    // =========================================================================
    // EVENTS
    // =========================================================================

    event ValidatorAdded(
        address indexed validator,
        bytes32 pubKeyHash,
        uint256 votingPower
    );
    event ValidatorRemoved(address indexed validator);
    event ValidatorUpdated(address indexed validator, uint256 newVotingPower);

    event BlockFinalized(
        uint64 indexed height,
        bytes32 blockHash,
        bytes32 stateRoot
    );

    event DepositInitiated(
        bytes32 indexed depositHash,
        address indexed depositor,
        address recipient,
        uint256 amount,
        uint256 tokenId
    );
    event DepositProcessed(bytes32 indexed depositHash);

    event WithdrawalInitiated(
        bytes32 indexed withdrawalHash,
        address indexed sender,
        address recipient,
        uint256 amount,
        uint256 tokenId
    );
    event WithdrawalFinalized(bytes32 indexed withdrawalHash);

    event CrossDomainNullifierRegistered(
        bytes32 indexed hlNullifier,
        bytes32 indexed pilNullifier,
        uint256 targetChain
    );

    event TokenMapped(
        uint256 indexed hip1TokenId,
        address indexed erc20Address
    );

    event RelayerRegistered(address indexed relayer);
    event RelayerUnregistered(address indexed relayer);
    event RelayerFeeUpdated(uint256 newFeeBps);

    event CircuitBreakerTriggered(string reason);
    event CircuitBreakerReset();

    // =========================================================================
    // ERRORS
    // =========================================================================

    error InvalidValidator();
    error ValidatorAlreadyExists();
    error ValidatorNotFound();
    error MaxValidatorsReached();
    error InsufficientQuorum();
    error InvalidBlock();
    error BlockNotFinalized();
    error InvalidDeposit();
    error DepositAlreadyProcessed();
    error InvalidWithdrawal();
    error WithdrawalAlreadyFinalized();
    error InvalidAmount();
    error ExceedsMaxTransfer();
    error ExceedsDailyLimit();
    error InvalidSignature();
    error NullifierAlreadyUsed();
    error InvalidNullifier();
    error TokenNotMapped();
    error CircuitBreakerOn();
    error InvalidRelayerFee();

    // =========================================================================
    // INITIALIZER
    // =========================================================================

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address admin, address guardian) external initializer {
        __UUPSUpgradeable_init();
        __AccessControl_init();
        __Pausable_init();
        __ReentrancyGuard_init();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(GUARDIAN_ROLE, admin);
        _grantRole(GUARDIAN_ROLE, guardian);
        _grantRole(UPGRADER_ROLE, admin);
        _grantRole(OPERATOR_ROLE, admin);

        lastVolumeReset = block.timestamp;
        relayerFeeBps = 50; // 0.5% default
    }

    // =========================================================================
    // VALIDATOR MANAGEMENT
    // =========================================================================

    /// @notice Add a validator to the set
    function addValidator(
        address validatorAddress,
        bytes32 pubKeyHash,
        uint256 votingPower
    ) external onlyRole(OPERATOR_ROLE) {
        if (validatorAddress == address(0)) revert InvalidValidator();
        if (validators[validatorAddress].isActive)
            revert ValidatorAlreadyExists();
        if (validatorList.length >= MAX_VALIDATORS)
            revert MaxValidatorsReached();

        validators[validatorAddress] = HyperliquidPrimitives.Validator({
            validatorAddress: validatorAddress,
            pubKeyHash: pubKeyHash,
            votingPower: votingPower,
            isActive: true,
            lastBlockSigned: 0
        });

        validatorList.push(validatorAddress);
        totalVotingPower += votingPower;

        emit ValidatorAdded(validatorAddress, pubKeyHash, votingPower);
    }

    /// @notice Remove a validator from the set
    function removeValidator(
        address validatorAddress
    ) external onlyRole(OPERATOR_ROLE) {
        if (!validators[validatorAddress].isActive) revert ValidatorNotFound();

        totalVotingPower -= validators[validatorAddress].votingPower;
        validators[validatorAddress].isActive = false;

        // Remove from list
        for (uint256 i = 0; i < validatorList.length; i++) {
            if (validatorList[i] == validatorAddress) {
                validatorList[i] = validatorList[validatorList.length - 1];
                validatorList.pop();
                break;
            }
        }

        emit ValidatorRemoved(validatorAddress);
    }

    /// @notice Update validator voting power
    function updateValidatorPower(
        address validatorAddress,
        uint256 newVotingPower
    ) external onlyRole(OPERATOR_ROLE) {
        if (!validators[validatorAddress].isActive) revert ValidatorNotFound();

        totalVotingPower =
            totalVotingPower -
            validators[validatorAddress].votingPower +
            newVotingPower;
        validators[validatorAddress].votingPower = newVotingPower;

        emit ValidatorUpdated(validatorAddress, newVotingPower);
    }

    // =========================================================================
    // BLOCK FINALIZATION
    // =========================================================================

    /// @notice Submit a finalized block with commit signatures
    function submitFinalizedBlock(
        HyperliquidPrimitives.BlockHeader calldata header,
        HyperliquidPrimitives.CommitSignature calldata commit
    ) external onlyRole(VALIDATOR_ROLE) whenNotPaused {
        if (circuitBreakerActive) revert CircuitBreakerOn();
        if (!header.isValidBlockHeader()) revert InvalidBlock();

        // Verify block hash matches commit
        bytes32 blockHash = header.computeBlockHash();
        if (commit.blockHash != blockHash) revert InvalidBlock();
        if (commit.height != header.height) revert InvalidBlock();

        // Verify quorum
        if (!commit.hasQuorum(totalVotingPower)) revert InsufficientQuorum();

        // Store finalized block
        finalizedBlocks[header.height] = header;

        if (header.height > latestFinalizedHeight) {
            latestFinalizedHeight = header.height;
        }

        emit BlockFinalized(header.height, blockHash, header.stateRoot);
    }

    /// @notice Check if a block is finalized
    function isBlockFinalized(uint64 height) external view returns (bool) {
        return finalizedBlocks[height].height > 0;
    }

    // =========================================================================
    // DEPOSITS
    // =========================================================================

    /// @notice Initiate a deposit to Hyperliquid
    function deposit(
        address recipient,
        uint256 tokenId
    ) external payable nonReentrant whenNotPaused {
        if (circuitBreakerActive) revert CircuitBreakerOn();
        if (msg.value == 0) revert InvalidAmount();
        if (msg.value > MAX_TRANSFER) revert ExceedsMaxTransfer();

        _checkDailyLimit(msg.value);

        bytes32 depositHash = keccak256(
            abi.encodePacked(
                msg.sender,
                recipient,
                msg.value,
                tokenId,
                block.number,
                block.timestamp
            )
        );

        deposits[depositHash] = HyperliquidPrimitives.Deposit({
            depositor: msg.sender,
            recipient: recipient,
            amount: msg.value,
            tokenId: tokenId,
            l1TxHash: bytes32(0), // Will be set by relayer
            l1BlockNumber: uint64(block.number),
            timestamp: block.timestamp,
            processed: false
        });

        depositHashes.push(depositHash);
        totalValueLocked += msg.value;

        emit DepositInitiated(
            depositHash,
            msg.sender,
            recipient,
            msg.value,
            tokenId
        );
    }

    /// @notice Mark deposit as processed (called by relayer after HL confirmation)
    function markDepositProcessed(
        bytes32 depositHash
    ) external onlyRole(OPERATOR_ROLE) {
        HyperliquidPrimitives.Deposit storage dep = deposits[depositHash];
        if (dep.depositor == address(0)) revert InvalidDeposit();
        if (dep.processed) revert DepositAlreadyProcessed();

        dep.processed = true;
        emit DepositProcessed(depositHash);
    }

    // =========================================================================
    // WITHDRAWALS
    // =========================================================================

    /// @notice Initiate a withdrawal from Hyperliquid
    function initiateWithdrawal(
        bytes32 withdrawalHash,
        address recipient,
        uint256 amount,
        uint256 tokenId,
        uint64 hlBlockHeight,
        bytes calldata proof
    ) external nonReentrant whenNotPaused {
        if (circuitBreakerActive) revert CircuitBreakerOn();
        if (amount == 0) revert InvalidAmount();
        if (amount > MAX_TRANSFER) revert ExceedsMaxTransfer();
        if (withdrawals[withdrawalHash].sender != address(0))
            revert WithdrawalAlreadyFinalized();

        // Verify block is finalized
        if (finalizedBlocks[hlBlockHeight].height == 0)
            revert BlockNotFinalized();

        // Verify withdrawal proof against state root
        // In production, this would verify a Merkle proof
        // For now, we trust the operator/relayer

        withdrawals[withdrawalHash] = HyperliquidPrimitives.Withdrawal({
            sender: msg.sender,
            recipient: recipient,
            amount: amount,
            tokenId: tokenId,
            withdrawalHash: withdrawalHash,
            hlBlockHeight: hlBlockHeight,
            timestamp: block.timestamp,
            finalized: false
        });

        withdrawalHashes.push(withdrawalHash);

        emit WithdrawalInitiated(
            withdrawalHash,
            msg.sender,
            recipient,
            amount,
            tokenId
        );
    }

    /// @notice Finalize withdrawal and transfer funds
    function finalizeWithdrawal(
        bytes32 withdrawalHash
    ) external nonReentrant whenNotPaused {
        if (circuitBreakerActive) revert CircuitBreakerOn();

        HyperliquidPrimitives.Withdrawal storage w = withdrawals[
            withdrawalHash
        ];
        if (w.sender == address(0)) revert InvalidWithdrawal();
        if (w.finalized) revert WithdrawalAlreadyFinalized();

        _checkDailyLimit(w.amount);

        w.finalized = true;
        totalValueLocked -= w.amount;

        // Transfer funds
        (bool success, ) = w.recipient.call{value: w.amount}("");
        require(success, "Transfer failed");

        emit WithdrawalFinalized(withdrawalHash);
    }

    // =========================================================================
    // CROSS-DOMAIN NULLIFIER
    // =========================================================================

    /// @notice Register a cross-domain nullifier binding
    function registerCrossDomainNullifier(
        bytes32 hlNullifier,
        uint256 targetChain
    ) external {
        if (hlNullifier == bytes32(0)) revert InvalidNullifier();

        // Check if already registered
        if (crossDomainNullifiers[hlNullifier] != bytes32(0)) {
            // Already registered, idempotent
            return;
        }

        // Derive cross-domain nullifier
        bytes32 crossNf = HyperliquidPrimitives.deriveCrossDomainNullifier(
            hlNullifier,
            block.chainid,
            targetChain
        );

        // Derive PIL binding
        bytes32 pilNf = HyperliquidPrimitives.derivePILBinding(crossNf);

        // Store bidirectional mapping
        crossDomainNullifiers[hlNullifier] = pilNf;
        pilBindings[pilNf] = hlNullifier;

        emit CrossDomainNullifierRegistered(hlNullifier, pilNf, targetChain);
    }

    /// @notice Mark nullifier as used
    function markNullifierUsed(
        bytes32 nullifier
    ) external onlyRole(OPERATOR_ROLE) {
        if (usedNullifiers[nullifier]) revert NullifierAlreadyUsed();
        usedNullifiers[nullifier] = true;
    }

    // =========================================================================
    // TOKEN MAPPING
    // =========================================================================

    /// @notice Map HIP-1 token to ERC20 address
    function mapToken(
        uint256 hip1TokenId,
        address erc20Address
    ) external onlyRole(OPERATOR_ROLE) {
        hip1ToErc20[hip1TokenId] = erc20Address;
        erc20ToHip1[erc20Address] = hip1TokenId;

        emit TokenMapped(hip1TokenId, erc20Address);
    }

    // =========================================================================
    // RELAYER MANAGEMENT
    // =========================================================================

    /// @notice Register as a relayer
    function registerRelayer() external {
        registeredRelayers[msg.sender] = true;
        emit RelayerRegistered(msg.sender);
    }

    /// @notice Unregister as a relayer
    function unregisterRelayer() external {
        registeredRelayers[msg.sender] = false;
        emit RelayerUnregistered(msg.sender);
    }

    /// @notice Update relayer fee
    function updateRelayerFee(
        uint256 newFeeBps
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (newFeeBps > MAX_RELAYER_FEE_BPS) revert InvalidRelayerFee();
        relayerFeeBps = newFeeBps;
        emit RelayerFeeUpdated(newFeeBps);
    }

    // =========================================================================
    // CIRCUIT BREAKER
    // =========================================================================

    /// @notice Trigger circuit breaker
    function triggerCircuitBreaker(
        string calldata reason
    ) external onlyRole(GUARDIAN_ROLE) {
        circuitBreakerActive = true;
        circuitBreakerReason = reason;
        _pause();
        emit CircuitBreakerTriggered(reason);
    }

    /// @notice Reset circuit breaker
    function resetCircuitBreaker() external onlyRole(DEFAULT_ADMIN_ROLE) {
        circuitBreakerActive = false;
        circuitBreakerReason = "";
        _unpause();
        emit CircuitBreakerReset();
    }

    // =========================================================================
    // ADMIN FUNCTIONS
    // =========================================================================

    /// @notice Pause the contract
    function pause() external onlyRole(GUARDIAN_ROLE) {
        _pause();
    }

    /// @notice Unpause the contract
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    /// @notice Emergency withdraw (admin only)
    function emergencyWithdraw(
        address recipient,
        uint256 amount
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        (bool success, ) = recipient.call{value: amount}("");
        require(success, "Transfer failed");
    }

    // =========================================================================
    // VIEW FUNCTIONS
    // =========================================================================

    /// @notice Get validator info
    function getValidator(
        address validatorAddress
    )
        external
        view
        returns (
            bytes32 pubKeyHash,
            uint256 votingPower,
            bool isActive,
            uint256 lastBlockSigned
        )
    {
        HyperliquidPrimitives.Validator storage v = validators[
            validatorAddress
        ];
        return (v.pubKeyHash, v.votingPower, v.isActive, v.lastBlockSigned);
    }

    /// @notice Get validator count
    function getValidatorCount() external view returns (uint256) {
        return validatorList.length;
    }

    /// @notice Get deposit info
    function getDeposit(
        bytes32 depositHash
    )
        external
        view
        returns (
            address depositor,
            address recipient,
            uint256 amount,
            uint256 tokenId,
            uint256 timestamp,
            bool processed
        )
    {
        HyperliquidPrimitives.Deposit storage d = deposits[depositHash];
        return (
            d.depositor,
            d.recipient,
            d.amount,
            d.tokenId,
            d.timestamp,
            d.processed
        );
    }

    /// @notice Get withdrawal info
    function getWithdrawal(
        bytes32 withdrawalHash
    )
        external
        view
        returns (
            address sender,
            address recipient,
            uint256 amount,
            uint256 tokenId,
            uint64 hlBlockHeight,
            bool finalized
        )
    {
        HyperliquidPrimitives.Withdrawal storage w = withdrawals[
            withdrawalHash
        ];
        return (
            w.sender,
            w.recipient,
            w.amount,
            w.tokenId,
            w.hlBlockHeight,
            w.finalized
        );
    }

    /// @notice Get bridge statistics
    function getStats()
        external
        view
        returns (
            uint256 validatorCount,
            uint64 latestHeight,
            uint256 tvl,
            uint256 depositCount,
            uint256 withdrawalCount,
            bool circuitBreaker
        )
    {
        return (
            validatorList.length,
            latestFinalizedHeight,
            totalValueLocked,
            depositHashes.length,
            withdrawalHashes.length,
            circuitBreakerActive
        );
    }

    // =========================================================================
    // INTERNAL FUNCTIONS
    // =========================================================================

    /// @notice Check and update daily volume limit
    function _checkDailyLimit(uint256 amount) internal {
        // Reset daily volume if 24 hours have passed
        if (block.timestamp >= lastVolumeReset + 1 days) {
            dailyVolume = 0;
            lastVolumeReset = block.timestamp;
        }

        if (dailyVolume + amount > DAILY_LIMIT) revert ExceedsDailyLimit();
        dailyVolume += amount;
    }

    /// @notice Authorize upgrade
    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRole(UPGRADER_ROLE) {}

    // =========================================================================
    // RECEIVE
    // =========================================================================

    receive() external payable {}
}
