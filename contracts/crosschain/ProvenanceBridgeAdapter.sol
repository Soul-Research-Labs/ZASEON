// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "../provenance/ProvenancePrimitives.sol";

/**
 * @title ProvenanceBridgeAdapter
 * @notice PIL bridge adapter for Provenance Blockchain (Cosmos SDK-based financial services chain)
 * @dev Integrates with Provenance's Marker module, IBC, and Tendermint consensus
 * @author PIL Protocol Team
 * @custom:security-contact security@pil.network
 */
contract ProvenanceBridgeAdapter is
    Initializable,
    AccessControlUpgradeable,
    ReentrancyGuardUpgradeable,
    PausableUpgradeable,
    UUPSUpgradeable
{
    // =========================================================================
    // CONSTANTS
    // =========================================================================

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");
    bytes32 public constant VALIDATOR_ROLE = keccak256("VALIDATOR_ROLE");
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");

    /// @notice Maximum validators
    uint256 public constant MAX_VALIDATORS = 100;

    /// @notice Finality threshold (2/3+1 = 66.67%)
    uint256 public constant FINALITY_THRESHOLD_BPS = 6667;

    /// @notice Maximum transfer per transaction
    uint256 public constant MAX_TRANSFER = 100_000 ether;

    /// @notice Daily volume limit
    uint256 public constant DAILY_LIMIT = 1_000_000 ether;

    /// @notice Maximum relayer fee (5%)
    uint256 public constant MAX_RELAYER_FEE_BPS = 500;

    /// @notice Minimum confirmations
    uint256 public constant MIN_CONFIRMATIONS = 1; // Instant finality with BFT

    // =========================================================================
    // STATE VARIABLES
    // =========================================================================

    /// @notice Validator set
    mapping(bytes32 => ValidatorInfo) public validators;
    bytes32[] public validatorList;
    uint256 public totalVotingPower;

    /// @notice Finalized blocks
    mapping(int64 => bytes32) public finalizedBlocks; // height -> blockHash
    int64 public latestFinalizedHeight;

    /// @notice IBC channels
    mapping(string => ProvenancePrimitives.IBCChannel) public ibcChannels;
    string[] public channelList;

    /// @notice Marker mappings (Provenance denom -> ERC20)
    mapping(string => address) public markerToToken;
    mapping(address => string) public tokenToMarker;

    /// @notice Deposits
    mapping(bytes32 => Deposit) public deposits;
    uint256 public depositNonce;

    /// @notice Withdrawals
    mapping(bytes32 => Withdrawal) public withdrawals;

    /// @notice Nullifiers (double-spend prevention)
    mapping(bytes32 => bool) public provenanceNullifiers;
    mapping(bytes32 => bytes32) public crossDomainNullifiers;
    mapping(bytes32 => bytes32) public pilBindings;

    /// @notice Daily volume tracking
    uint256 public dailyVolume;
    uint256 public lastVolumeReset;

    /// @notice Circuit breaker
    bool public circuitBreakerTriggered;
    uint256 public circuitBreakerThreshold;

    // =========================================================================
    // STRUCTS
    // =========================================================================

    struct ValidatorInfo {
        bytes pubkey;
        uint256 votingPower;
        string moniker;
        bool active;
        uint256 registeredAt;
    }

    struct Deposit {
        address depositor;
        string provenanceRecipient; // Bech32 address
        string denom;
        uint256 amount;
        uint256 timestamp;
        DepositStatus status;
        bytes32 ibcPacketHash;
    }

    enum DepositStatus {
        PENDING,
        CONFIRMED,
        COMPLETED,
        REFUNDED
    }

    struct Withdrawal {
        string provenanceSender; // Bech32 address
        address recipient;
        string denom;
        uint256 amount;
        int64 blockHeight;
        bytes32 txHash;
        uint256 timestamp;
        WithdrawalStatus status;
    }

    enum WithdrawalStatus {
        PENDING,
        FINALIZED,
        CLAIMED,
        EXPIRED
    }

    // =========================================================================
    // EVENTS
    // =========================================================================

    event ValidatorAdded(
        bytes32 indexed validatorId,
        bytes pubkey,
        uint256 votingPower
    );
    event ValidatorRemoved(bytes32 indexed validatorId);
    event ValidatorUpdated(bytes32 indexed validatorId, uint256 newVotingPower);

    event BlockFinalized(
        int64 indexed height,
        bytes32 blockHash,
        uint256 signingPower
    );

    event IBCChannelRegistered(string indexed channelId, string portId);
    event IBCChannelUpdated(
        string indexed channelId,
        ProvenancePrimitives.ChannelState newState
    );

    event MarkerMapped(string indexed denom, address indexed token);
    event MarkerUnmapped(string indexed denom, address indexed token);

    event DepositInitiated(
        bytes32 indexed depositId,
        address indexed depositor,
        string provenanceRecipient,
        string denom,
        uint256 amount
    );
    event DepositConfirmed(bytes32 indexed depositId, bytes32 ibcPacketHash);
    event DepositRefunded(bytes32 indexed depositId, uint256 amount);

    event WithdrawalInitiated(
        bytes32 indexed withdrawalId,
        string provenanceSender,
        address indexed recipient,
        string denom,
        uint256 amount
    );
    event WithdrawalFinalized(bytes32 indexed withdrawalId, int64 blockHeight);
    event WithdrawalClaimed(
        bytes32 indexed withdrawalId,
        address indexed recipient,
        uint256 amount
    );

    event NullifierRegistered(
        bytes32 indexed nullifier,
        bytes32 indexed txHash,
        int64 blockHeight
    );
    event CrossDomainNullifierRegistered(
        bytes32 indexed crossDomainNullifier,
        bytes32 indexed provenanceNullifier,
        uint256 targetDomain
    );
    event PILBindingCreated(
        bytes32 indexed pilBinding,
        bytes32 indexed provenanceNullifier,
        bytes32 pilDomain
    );

    event CircuitBreakerTriggered(uint256 volume, uint256 threshold);
    event CircuitBreakerReset();

    // =========================================================================
    // ERRORS
    // =========================================================================

    error InvalidValidator();
    error ValidatorAlreadyExists();
    error ValidatorNotFound();
    error InsufficientQuorum();
    error InvalidBlockHeight();
    error BlockNotFinalized();
    error InvalidChannel();
    error ChannelNotOpen();
    error InvalidMarker();
    error MarkerAlreadyMapped();
    error MarkerNotMapped();
    error InvalidDeposit();
    error DepositNotFound();
    error DepositAlreadyProcessed();
    error InvalidWithdrawal();
    error WithdrawalNotFound();
    error WithdrawalNotFinalized();
    error WithdrawalAlreadyClaimed();
    error NullifierAlreadyUsed();
    error NullifierNotRegistered();
    error ExceedsMaxTransfer();
    error ExceedsDailyLimit();
    error CircuitBreakerActive();
    error InvalidRelayerFee();
    error Unauthorized();

    // =========================================================================
    // INITIALIZER
    // =========================================================================

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice Initialize the bridge adapter
     * @param admin Admin address
     * @param _circuitBreakerThreshold Circuit breaker threshold
     */
    function initialize(
        address admin,
        uint256 _circuitBreakerThreshold
    ) external initializer {
        __AccessControl_init();
        __ReentrancyGuard_init();
        __Pausable_init();
        __UUPSUpgradeable_init();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(OPERATOR_ROLE, admin);
        _grantRole(GUARDIAN_ROLE, admin);
        _grantRole(UPGRADER_ROLE, admin);

        circuitBreakerThreshold = _circuitBreakerThreshold;
        lastVolumeReset = block.timestamp;
    }

    // =========================================================================
    // VALIDATOR MANAGEMENT
    // =========================================================================

    /**
     * @notice Add a new validator
     * @param pubkey 33-byte compressed secp256k1 public key
     * @param votingPower Validator voting power
     * @param moniker Validator moniker
     */
    function addValidator(
        bytes calldata pubkey,
        uint256 votingPower,
        string calldata moniker
    ) external onlyRole(OPERATOR_ROLE) {
        if (pubkey.length != 33) revert InvalidValidator();
        if (votingPower == 0) revert InvalidValidator();

        bytes32 validatorId = keccak256(pubkey);
        if (validators[validatorId].active) revert ValidatorAlreadyExists();

        validators[validatorId] = ValidatorInfo({
            pubkey: pubkey,
            votingPower: votingPower,
            moniker: moniker,
            active: true,
            registeredAt: block.timestamp
        });

        validatorList.push(validatorId);
        totalVotingPower += votingPower;

        emit ValidatorAdded(validatorId, pubkey, votingPower);
    }

    /**
     * @notice Remove a validator
     * @param validatorId Validator ID (keccak256 of pubkey)
     */
    function removeValidator(
        bytes32 validatorId
    ) external onlyRole(OPERATOR_ROLE) {
        ValidatorInfo storage validator = validators[validatorId];
        if (!validator.active) revert ValidatorNotFound();

        totalVotingPower -= validator.votingPower;
        validator.active = false;

        emit ValidatorRemoved(validatorId);
    }

    /**
     * @notice Update validator voting power
     * @param validatorId Validator ID
     * @param newVotingPower New voting power
     */
    function updateValidatorPower(
        bytes32 validatorId,
        uint256 newVotingPower
    ) external onlyRole(OPERATOR_ROLE) {
        ValidatorInfo storage validator = validators[validatorId];
        if (!validator.active) revert ValidatorNotFound();

        totalVotingPower =
            totalVotingPower -
            validator.votingPower +
            newVotingPower;
        validator.votingPower = newVotingPower;

        emit ValidatorUpdated(validatorId, newVotingPower);
    }

    // =========================================================================
    // BLOCK FINALIZATION
    // =========================================================================

    /**
     * @notice Submit a finalized block with validator signatures
     * @param height Block height
     * @param blockHash Block hash
     * @param signers Array of validator IDs that signed
     * @param signatures Aggregated signatures
     */
    function submitFinalizedBlock(
        int64 height,
        bytes32 blockHash,
        bytes32[] calldata signers,
        bytes calldata signatures
    ) external onlyRole(VALIDATOR_ROLE) whenNotPaused {
        if (height <= latestFinalizedHeight) revert InvalidBlockHeight();

        // Calculate signing power
        uint256 signingPower = 0;
        for (uint256 i = 0; i < signers.length; i++) {
            ValidatorInfo storage validator = validators[signers[i]];
            if (validator.active) {
                signingPower += validator.votingPower;
            }
        }

        // Check quorum (2/3+1)
        if (signingPower * 10000 <= totalVotingPower * FINALITY_THRESHOLD_BPS) {
            revert InsufficientQuorum();
        }

        // Store finalized block
        finalizedBlocks[height] = blockHash;
        latestFinalizedHeight = height;

        emit BlockFinalized(height, blockHash, signingPower);
    }

    // =========================================================================
    // IBC CHANNEL MANAGEMENT
    // =========================================================================

    /**
     * @notice Register an IBC channel
     * @param channel IBC channel data
     */
    function registerIBCChannel(
        ProvenancePrimitives.IBCChannel calldata channel
    ) external onlyRole(OPERATOR_ROLE) {
        if (!ProvenancePrimitives.isValidIBCChannel(channel))
            revert InvalidChannel();

        ibcChannels[channel.channelId] = channel;
        channelList.push(channel.channelId);

        emit IBCChannelRegistered(channel.channelId, channel.portId);
    }

    /**
     * @notice Update IBC channel state
     * @param channelId Channel ID
     * @param newState New channel state
     */
    function updateIBCChannelState(
        string calldata channelId,
        ProvenancePrimitives.ChannelState newState
    ) external onlyRole(OPERATOR_ROLE) {
        ProvenancePrimitives.IBCChannel storage channel = ibcChannels[
            channelId
        ];
        if (bytes(channel.channelId).length == 0) revert InvalidChannel();

        channel.state = newState;

        emit IBCChannelUpdated(channelId, newState);
    }

    // =========================================================================
    // MARKER MAPPING
    // =========================================================================

    /**
     * @notice Map a Provenance marker to an ERC20 token
     * @param denom Marker denomination
     * @param token ERC20 token address
     */
    function mapMarker(
        string calldata denom,
        address token
    ) external onlyRole(OPERATOR_ROLE) {
        if (bytes(denom).length == 0) revert InvalidMarker();
        if (token == address(0)) revert InvalidMarker();
        if (markerToToken[denom] != address(0)) revert MarkerAlreadyMapped();

        markerToToken[denom] = token;
        tokenToMarker[token] = denom;

        emit MarkerMapped(denom, token);
    }

    /**
     * @notice Unmap a marker
     * @param denom Marker denomination
     */
    function unmapMarker(
        string calldata denom
    ) external onlyRole(OPERATOR_ROLE) {
        address token = markerToToken[denom];
        if (token == address(0)) revert MarkerNotMapped();

        delete markerToToken[denom];
        delete tokenToMarker[token];

        emit MarkerUnmapped(denom, token);
    }

    // =========================================================================
    // DEPOSIT OPERATIONS
    // =========================================================================

    /**
     * @notice Initiate a deposit to Provenance
     * @param provenanceRecipient Bech32 recipient address on Provenance
     * @param denom Marker denomination
     */
    function deposit(
        string calldata provenanceRecipient,
        string calldata denom
    ) external payable nonReentrant whenNotPaused {
        if (circuitBreakerTriggered) revert CircuitBreakerActive();
        if (msg.value == 0) revert InvalidDeposit();
        if (msg.value > MAX_TRANSFER) revert ExceedsMaxTransfer();
        if (bytes(provenanceRecipient).length == 0) revert InvalidDeposit();

        _checkAndUpdateDailyVolume(msg.value);

        bytes32 depositId = keccak256(
            abi.encodePacked(
                msg.sender,
                provenanceRecipient,
                denom,
                msg.value,
                depositNonce++
            )
        );

        deposits[depositId] = Deposit({
            depositor: msg.sender,
            provenanceRecipient: provenanceRecipient,
            denom: denom,
            amount: msg.value,
            timestamp: block.timestamp,
            status: DepositStatus.PENDING,
            ibcPacketHash: bytes32(0)
        });

        emit DepositInitiated(
            depositId,
            msg.sender,
            provenanceRecipient,
            denom,
            msg.value
        );
    }

    /**
     * @notice Confirm deposit with IBC packet
     * @param depositId Deposit ID
     * @param ibcPacketHash IBC packet commitment hash
     */
    function confirmDeposit(
        bytes32 depositId,
        bytes32 ibcPacketHash
    ) external onlyRole(RELAYER_ROLE) {
        Deposit storage dep = deposits[depositId];
        if (dep.depositor == address(0)) revert DepositNotFound();
        if (dep.status != DepositStatus.PENDING)
            revert DepositAlreadyProcessed();

        dep.status = DepositStatus.CONFIRMED;
        dep.ibcPacketHash = ibcPacketHash;

        emit DepositConfirmed(depositId, ibcPacketHash);
    }

    /**
     * @notice Refund a failed deposit
     * @param depositId Deposit ID
     */
    function refundDeposit(bytes32 depositId) external nonReentrant {
        Deposit storage dep = deposits[depositId];
        if (dep.depositor == address(0)) revert DepositNotFound();
        if (dep.status != DepositStatus.PENDING)
            revert DepositAlreadyProcessed();
        if (
            dep.depositor != msg.sender && !hasRole(OPERATOR_ROLE, msg.sender)
        ) {
            revert Unauthorized();
        }

        // Only allow refund after timeout (24 hours)
        require(
            block.timestamp > dep.timestamp + 24 hours,
            "Deposit not expired"
        );

        dep.status = DepositStatus.REFUNDED;
        uint256 amount = dep.amount;

        (bool success, ) = dep.depositor.call{value: amount}("");
        require(success, "Refund failed");

        emit DepositRefunded(depositId, amount);
    }

    // =========================================================================
    // WITHDRAWAL OPERATIONS
    // =========================================================================

    /**
     * @notice Initiate a withdrawal from Provenance
     * @param provenanceSender Bech32 sender address on Provenance
     * @param recipient EVM recipient address
     * @param denom Marker denomination
     * @param amount Withdrawal amount
     * @param blockHeight Provenance block height
     * @param txHash Provenance transaction hash
     */
    function initiateWithdrawal(
        string calldata provenanceSender,
        address recipient,
        string calldata denom,
        uint256 amount,
        int64 blockHeight,
        bytes32 txHash
    ) external onlyRole(RELAYER_ROLE) whenNotPaused {
        if (circuitBreakerTriggered) revert CircuitBreakerActive();
        if (recipient == address(0)) revert InvalidWithdrawal();
        if (amount == 0) revert InvalidWithdrawal();
        if (amount > MAX_TRANSFER) revert ExceedsMaxTransfer();

        bytes32 withdrawalId = keccak256(
            abi.encodePacked(
                provenanceSender,
                recipient,
                denom,
                amount,
                blockHeight,
                txHash
            )
        );

        if (withdrawals[withdrawalId].recipient != address(0)) {
            revert InvalidWithdrawal(); // Already exists
        }

        withdrawals[withdrawalId] = Withdrawal({
            provenanceSender: provenanceSender,
            recipient: recipient,
            denom: denom,
            amount: amount,
            blockHeight: blockHeight,
            txHash: txHash,
            timestamp: block.timestamp,
            status: WithdrawalStatus.PENDING
        });

        emit WithdrawalInitiated(
            withdrawalId,
            provenanceSender,
            recipient,
            denom,
            amount
        );
    }

    /**
     * @notice Finalize a withdrawal after block finalization
     * @param withdrawalId Withdrawal ID
     */
    function finalizeWithdrawal(
        bytes32 withdrawalId
    ) external onlyRole(RELAYER_ROLE) {
        Withdrawal storage w = withdrawals[withdrawalId];
        if (w.recipient == address(0)) revert WithdrawalNotFound();
        if (w.status != WithdrawalStatus.PENDING) revert InvalidWithdrawal();

        // Check block is finalized
        if (finalizedBlocks[w.blockHeight] == bytes32(0))
            revert BlockNotFinalized();

        w.status = WithdrawalStatus.FINALIZED;

        emit WithdrawalFinalized(withdrawalId, w.blockHeight);
    }

    /**
     * @notice Claim a finalized withdrawal
     * @param withdrawalId Withdrawal ID
     * @param relayerFee Relayer fee in basis points
     */
    function claimWithdrawal(
        bytes32 withdrawalId,
        uint256 relayerFee
    ) external nonReentrant whenNotPaused {
        Withdrawal storage w = withdrawals[withdrawalId];
        if (w.recipient == address(0)) revert WithdrawalNotFound();
        if (w.status != WithdrawalStatus.FINALIZED)
            revert WithdrawalNotFinalized();
        if (relayerFee > MAX_RELAYER_FEE_BPS) revert InvalidRelayerFee();

        _checkAndUpdateDailyVolume(w.amount);

        w.status = WithdrawalStatus.CLAIMED;

        uint256 fee = (w.amount * relayerFee) / 10000;
        uint256 netAmount = w.amount - fee;

        // Pay relayer fee if applicable
        if (fee > 0 && hasRole(RELAYER_ROLE, msg.sender)) {
            (bool feeSuccess, ) = msg.sender.call{value: fee}("");
            require(feeSuccess, "Fee transfer failed");
        }

        // Transfer to recipient
        (bool success, ) = w.recipient.call{value: netAmount}("");
        require(success, "Withdrawal transfer failed");

        emit WithdrawalClaimed(withdrawalId, w.recipient, netAmount);
    }

    // =========================================================================
    // NULLIFIER OPERATIONS
    // =========================================================================

    /**
     * @notice Register a Provenance nullifier
     * @param txHash Transaction hash
     * @param blockHeight Block height
     * @param scopeId Scope ID (optional)
     * @param denom Token denomination
     * @return nullifier The derived nullifier
     */
    function registerNullifier(
        bytes32 txHash,
        int64 blockHeight,
        bytes32 scopeId,
        string calldata denom
    ) external onlyRole(OPERATOR_ROLE) returns (bytes32 nullifier) {
        nullifier = ProvenancePrimitives.deriveProvenanceNullifier(
            txHash,
            blockHeight,
            scopeId,
            denom
        );

        if (provenanceNullifiers[nullifier]) revert NullifierAlreadyUsed();

        provenanceNullifiers[nullifier] = true;

        emit NullifierRegistered(nullifier, txHash, blockHeight);
    }

    /**
     * @notice Register a cross-domain nullifier for PIL binding
     * @param provenanceNullifier Provenance nullifier
     * @param targetDomain Target domain ID
     * @return crossDomainNf Cross-domain nullifier
     */
    function registerCrossDomainNullifier(
        bytes32 provenanceNullifier,
        uint256 targetDomain
    ) external onlyRole(OPERATOR_ROLE) returns (bytes32 crossDomainNf) {
        if (!provenanceNullifiers[provenanceNullifier])
            revert NullifierNotRegistered();

        crossDomainNf = ProvenancePrimitives.deriveCrossDomainNullifier(
            provenanceNullifier,
            targetDomain
        );

        if (crossDomainNullifiers[crossDomainNf] != bytes32(0))
            revert NullifierAlreadyUsed();

        crossDomainNullifiers[crossDomainNf] = provenanceNullifier;

        emit CrossDomainNullifierRegistered(
            crossDomainNf,
            provenanceNullifier,
            targetDomain
        );
    }

    /**
     * @notice Create a PIL binding from Provenance nullifier
     * @param provenanceNullifier Provenance nullifier
     * @param pilDomain PIL domain identifier
     * @return pilBinding PIL binding hash
     */
    function createPILBinding(
        bytes32 provenanceNullifier,
        bytes32 pilDomain
    ) external onlyRole(OPERATOR_ROLE) returns (bytes32 pilBinding) {
        if (!provenanceNullifiers[provenanceNullifier])
            revert NullifierNotRegistered();

        pilBinding = ProvenancePrimitives.derivePILBinding(
            provenanceNullifier,
            pilDomain
        );

        if (pilBindings[pilBinding] != bytes32(0))
            revert NullifierAlreadyUsed();

        pilBindings[pilBinding] = provenanceNullifier;

        emit PILBindingCreated(pilBinding, provenanceNullifier, pilDomain);
    }

    // =========================================================================
    // VIEW FUNCTIONS
    // =========================================================================

    /**
     * @notice Check if nullifier has been used
     * @param nullifier Nullifier to check
     * @return True if used
     */
    function isNullifierUsed(bytes32 nullifier) external view returns (bool) {
        return provenanceNullifiers[nullifier];
    }

    /**
     * @notice Get Provenance nullifier from cross-domain nullifier
     * @param crossDomainNf Cross-domain nullifier
     * @return Provenance nullifier
     */
    function getProvenanceNullifier(
        bytes32 crossDomainNf
    ) external view returns (bytes32) {
        return crossDomainNullifiers[crossDomainNf];
    }

    /**
     * @notice Get validator count
     * @return Number of active validators
     */
    function getValidatorCount() external view returns (uint256) {
        uint256 count = 0;
        for (uint256 i = 0; i < validatorList.length; i++) {
            if (validators[validatorList[i]].active) {
                count++;
            }
        }
        return count;
    }

    /**
     * @notice Get IBC channel count
     * @return Number of registered channels
     */
    function getChannelCount() external view returns (uint256) {
        return channelList.length;
    }

    // =========================================================================
    // ADMIN FUNCTIONS
    // =========================================================================

    /**
     * @notice Trigger circuit breaker
     */
    function triggerCircuitBreaker() external onlyRole(GUARDIAN_ROLE) {
        circuitBreakerTriggered = true;
        emit CircuitBreakerTriggered(dailyVolume, circuitBreakerThreshold);
    }

    /**
     * @notice Reset circuit breaker
     */
    function resetCircuitBreaker() external onlyRole(GUARDIAN_ROLE) {
        circuitBreakerTriggered = false;
        emit CircuitBreakerReset();
    }

    /**
     * @notice Update circuit breaker threshold
     * @param newThreshold New threshold
     */
    function setCircuitBreakerThreshold(
        uint256 newThreshold
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        circuitBreakerThreshold = newThreshold;
    }

    /**
     * @notice Pause the bridge
     */
    function pause() external onlyRole(GUARDIAN_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause the bridge
     */
    function unpause() external onlyRole(GUARDIAN_ROLE) {
        _unpause();
    }

    // =========================================================================
    // INTERNAL FUNCTIONS
    // =========================================================================

    /**
     * @notice Check and update daily volume
     * @param amount Amount to add
     */
    function _checkAndUpdateDailyVolume(uint256 amount) internal {
        // Reset daily volume if new day
        if (block.timestamp >= lastVolumeReset + 1 days) {
            dailyVolume = 0;
            lastVolumeReset = block.timestamp - (block.timestamp % 1 days);
        }

        if (dailyVolume + amount > DAILY_LIMIT) revert ExceedsDailyLimit();
        dailyVolume += amount;

        // Auto-trigger circuit breaker
        if (dailyVolume > circuitBreakerThreshold && !circuitBreakerTriggered) {
            circuitBreakerTriggered = true;
            emit CircuitBreakerTriggered(dailyVolume, circuitBreakerThreshold);
        }
    }

    /**
     * @notice Authorize upgrade (UUPS)
     */
    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRole(UPGRADER_ROLE) {}

    // =========================================================================
    // RECEIVE
    // =========================================================================

    receive() external payable {}
}
