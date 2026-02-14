// SPDX-License-Identifier: MIT
// Coverage stub – assembly-free PrivateRelayerNetwork
pragma solidity ^0.8.24;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

contract PrivateRelayerNetwork is
    Initializable,
    UUPSUpgradeable,
    AccessControlUpgradeable,
    ReentrancyGuardUpgradeable
{
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");
    bytes32 public constant SLASHER_ROLE = keccak256("SLASHER_ROLE");
    uint256 public constant MIN_STAKE = 1 ether;
    uint256 public constant MAX_STAKE = 100 ether;
    uint256 public constant COMMITMENT_WINDOW = 3;
    uint256 public constant REVEAL_WINDOW = 10;
    uint256 public constant SLASH_PERCENTAGE = 1000;
    uint256 public constant LATE_SLASH_PERCENTAGE = 500;
    uint256 public constant MIN_RELAYERS = 3;
    bytes32 public constant VRF_DOMAIN = keccak256("Soul_RELAYER_VRF_V1");
    uint256 public constant SLASH_COOLDOWN = 1 days;

    enum RelayerStatus {
        INACTIVE,
        ACTIVE,
        JAILED,
        EXITING
    }
    enum CommitmentStatus {
        NONE,
        COMMITTED,
        REVEALED,
        EXPIRED,
        SLASHED
    }
    enum RelayType {
        STANDARD,
        PRIORITY,
        PRIVATE,
        BATCH
    }

    struct Relayer {
        address relayerAddress;
        bytes stealthMetaAddress;
        uint256 stake;
        uint256 totalRelayed;
        uint256 successfulRelays;
        uint256 failedRelays;
        uint256 slashedAmount;
        uint256 rewardsEarned;
        RelayerStatus status;
        uint256 registeredAt;
        uint256 lastActiveAt;
        uint256 jailedUntil;
        uint256 exitRequestedAt;
        bytes32 vrfKeyHash;
    }
    struct Commitment {
        bytes32 commitmentHash;
        address relayer;
        uint256 commitBlock;
        uint256 revealDeadline;
        CommitmentStatus status;
        bytes32 intentHash;
        uint256 stake;
    }
    struct RelayIntent {
        bytes32 transferId;
        uint256 sourceChainId;
        uint256 targetChainId;
        bytes32 proofHash;
        bytes payload;
        uint256 fee;
        uint256 deadline;
        RelayType relayType;
        bytes encryptedMetadata;
    }
    struct StealthFeePayment {
        address stealthAddress;
        bytes ephemeralPubKey;
        uint256 amount;
        bytes32 transferId;
        uint256 timestamp;
    }
    struct VRFRound {
        bytes32 roundId;
        bytes32 seed;
        bytes32 vrfOutput;
        address selectedRelayer;
        uint256 totalStake;
        uint256 timestamp;
        bool finalized;
    }

    mapping(address => Relayer) public relayers;
    address[] public activeRelayers;
    mapping(bytes32 => Commitment) public commitments;
    mapping(bytes32 => RelayIntent) public revealedIntents;
    mapping(bytes32 => StealthFeePayment) public stealthPayments;
    mapping(bytes32 => VRFRound) public vrfRounds;
    bytes32 public currentVRFRound;
    uint256 public totalStake;
    uint256 public totalRelays;
    uint256 public totalFees;
    uint256 public protocolFeeBps;
    address public protocolFeeRecipient;

    event RelayerRegistered(
        address indexed relayer,
        uint256 stake,
        bytes stealthMetaAddress
    );
    event RelayerStakeUpdated(
        address indexed relayer,
        uint256 oldStake,
        uint256 newStake
    );
    event RelayerJailed(
        address indexed relayer,
        uint256 jailedUntil,
        string reason
    );
    event RelayerExitRequested(address indexed relayer, uint256 exitTime);
    event CommitmentSubmitted(
        bytes32 indexed commitmentHash,
        address indexed relayer,
        uint256 commitBlock
    );
    event IntentRevealed(
        bytes32 indexed commitmentHash,
        bytes32 indexed intentHash,
        address indexed relayer
    );
    event RelayExecuted(
        bytes32 indexed transferId,
        address indexed relayer,
        uint256 fee
    );
    event RelayerSlashed(
        address indexed relayer,
        uint256 amount,
        string reason
    );
    event StealthFeePaid(
        bytes32 indexed paymentId,
        address indexed stealthAddress,
        uint256 amount
    );
    event VRFRoundStarted(bytes32 indexed roundId, bytes32 seed);
    event RelayerSelected(
        bytes32 indexed roundId,
        address indexed relayer,
        bytes32 vrfOutput
    );

    error InsufficientStake();
    error RelayerAlreadyRegistered();
    error RelayerNotFound();
    error RelayerNotActive();
    error RelayerJailedError();
    error InvalidCommitment();
    error CommitmentExpired();
    error RevealTooEarly();
    error RevealTooLate();
    error InvalidReveal();
    error IntentAlreadyRevealed();
    error NotSelectedRelayer();
    error InsufficientRelayers();
    error InvalidVRFProof();
    error ZeroAddress();
    error ZeroAmount();
    error ExitNotReady();
    error TransferFailed();

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(
        address admin,
        address _protocolFeeRecipient,
        uint256 _protocolFeeBps
    ) external initializer {
        __AccessControl_init();
        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(OPERATOR_ROLE, admin);
        _grantRole(SLASHER_ROLE, admin);
        _grantRole(UPGRADER_ROLE, admin);
        protocolFeeRecipient = _protocolFeeRecipient;
        protocolFeeBps = _protocolFeeBps;
    }

    function _authorizeUpgrade(
        address
    ) internal override onlyRole(UPGRADER_ROLE) {}

    function registerRelayer(
        bytes calldata stealthMetaAddress,
        bytes32 vrfKeyHash
    ) external payable {
        if (msg.value < MIN_STAKE) revert InsufficientStake();
        if (relayers[msg.sender].registeredAt != 0)
            revert RelayerAlreadyRegistered();
        relayers[msg.sender] = Relayer(
            msg.sender,
            stealthMetaAddress,
            msg.value,
            0,
            0,
            0,
            0,
            0,
            RelayerStatus.ACTIVE,
            block.timestamp,
            block.timestamp,
            0,
            0,
            vrfKeyHash
        );
        activeRelayers.push(msg.sender);
        totalStake += msg.value;
        _grantRole(RELAYER_ROLE, msg.sender);
        emit RelayerRegistered(msg.sender, msg.value, stealthMetaAddress);
    }

    function addStake() external payable {
        Relayer storage r = relayers[msg.sender];
        if (r.status != RelayerStatus.ACTIVE) revert RelayerNotActive();
        uint256 oldStake = r.stake;
        r.stake += msg.value;
        totalStake += msg.value;
        emit RelayerStakeUpdated(msg.sender, oldStake, r.stake);
    }

    function requestExit() external {
        Relayer storage r = relayers[msg.sender];
        if (r.status != RelayerStatus.ACTIVE) revert RelayerNotActive();
        r.status = RelayerStatus.EXITING;
        r.exitRequestedAt = block.timestamp;
        emit RelayerExitRequested(msg.sender, block.timestamp);
    }

    function completeExit() external nonReentrant {
        Relayer storage r = relayers[msg.sender];
        if (r.status != RelayerStatus.EXITING) revert ExitNotReady();
        uint256 amount = r.stake;
        r.stake = 0;
        r.status = RelayerStatus.INACTIVE;
        totalStake -= amount;
        _revokeRole(RELAYER_ROLE, msg.sender);
        (bool ok, ) = msg.sender.call{value: amount}("");
        if (!ok) revert TransferFailed();
    }

    function submitCommitment(bytes32 commitmentHash) external {
        if (relayers[msg.sender].status != RelayerStatus.ACTIVE)
            revert RelayerNotActive();
        commitments[commitmentHash] = Commitment(
            commitmentHash,
            msg.sender,
            block.number,
            block.number + REVEAL_WINDOW,
            CommitmentStatus.COMMITTED,
            bytes32(0),
            0
        );
        emit CommitmentSubmitted(commitmentHash, msg.sender, block.number);
    }

    function revealIntent(
        bytes32 commitmentHash,
        RelayIntent calldata intent,
        bytes32
    ) external {
        Commitment storage c = commitments[commitmentHash];
        if (c.status != CommitmentStatus.COMMITTED) revert InvalidCommitment();
        c.status = CommitmentStatus.REVEALED;
        c.intentHash = keccak256(abi.encodePacked(intent.transferId));
        revealedIntents[commitmentHash] = intent;
        emit IntentRevealed(commitmentHash, c.intentHash, msg.sender);
    }

    function executeRelay(
        bytes32 commitmentHash,
        bytes calldata
    ) external nonReentrant {
        Commitment storage c = commitments[commitmentHash];
        RelayIntent storage intent = revealedIntents[commitmentHash];
        relayers[c.relayer].totalRelayed++;
        relayers[c.relayer].successfulRelays++;
        totalRelays++;
        totalFees += intent.fee;
        emit RelayExecuted(intent.transferId, c.relayer, intent.fee);
    }

    function startVRFRound(bytes32 seed) external onlyRole(OPERATOR_ROLE) {
        bytes32 roundId = keccak256(abi.encodePacked(seed, block.timestamp));
        vrfRounds[roundId] = VRFRound(
            roundId,
            seed,
            bytes32(0),
            address(0),
            totalStake,
            block.timestamp,
            false
        );
        currentVRFRound = roundId;
        emit VRFRoundStarted(roundId, seed);
    }

    function selectRelayer(
        bytes32 roundId,
        bytes32 vrfProof,
        address selected
    ) external onlyRole(OPERATOR_ROLE) {
        VRFRound storage round = vrfRounds[roundId];
        round.vrfOutput = vrfProof;
        round.selectedRelayer = selected;
        round.finalized = true;
        emit RelayerSelected(roundId, selected, vrfProof);
    }

    function getSelectedRelayer(
        bytes32 roundId
    ) external view returns (address) {
        return vrfRounds[roundId].selectedRelayer;
    }

    function payStealthFee(
        address stealthAddress,
        bytes calldata ephemeralPubKey,
        bytes32 transferId
    ) external payable {
        bytes32 paymentId = keccak256(
            abi.encodePacked(stealthAddress, transferId)
        );
        stealthPayments[paymentId] = StealthFeePayment(
            stealthAddress,
            ephemeralPubKey,
            msg.value,
            transferId,
            block.timestamp
        );
        emit StealthFeePaid(paymentId, stealthAddress, msg.value);
    }

    function slashRelayer(
        address relayerAddress,
        uint256 amount,
        string calldata reason
    ) external onlyRole(SLASHER_ROLE) {
        Relayer storage r = relayers[relayerAddress];
        r.stake -= amount;
        r.slashedAmount += amount;
        totalStake -= amount;
        emit RelayerSlashed(relayerAddress, amount, reason);
    }

    function unjailRelayer() external {
        Relayer storage r = relayers[msg.sender];
        if (r.status != RelayerStatus.JAILED) revert RelayerNotActive();
        if (block.timestamp < r.jailedUntil) revert RelayerJailedError();
        r.status = RelayerStatus.ACTIVE;
    }

    function getRelayerCount() external view returns (uint256) {
        return activeRelayers.length;
    }

    function getRelayerInfo(
        address relayerAddress
    ) external view returns (Relayer memory) {
        return relayers[relayerAddress];
    }

    function getActiveRelayers() external view returns (address[] memory) {
        return activeRelayers;
    }

    function getCommitment(
        bytes32 commitmentHash
    ) external view returns (Commitment memory) {
        return commitments[commitmentHash];
    }
}
