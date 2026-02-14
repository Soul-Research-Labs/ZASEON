// SPDX-License-Identifier: MIT
// Coverage stub – assembly-free DirectL2Messenger
pragma solidity ^0.8.24;

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

contract DirectL2Messenger is ReentrancyGuard, AccessControl, Pausable {
    bytes32 public constant OPERATOR_ROLE =
        0x97667070c54ef182b0f5858b034beac1b6f3089aa2d3188bb1e8929f4fa9b929;
    bytes32 public constant RELAYER_ROLE =
        0xe2b7fb3b832174769106daebcfd6d1970523240dda11281102db9363b83b0dc4;

    enum MessagePath {
        SUPERCHAIN,
        SHARED_SEQUENCER,
        FAST_RELAYER,
        SLOW_L1
    }
    enum MessageStatus {
        NONE,
        SENT,
        RELAYED,
        CHALLENGED,
        EXECUTED,
        FAILED,
        REFUNDED
    }

    struct L2Message {
        bytes32 messageId;
        uint256 sourceChainId;
        uint256 destChainId;
        address sender;
        address recipient;
        bytes payload;
        uint256 value;
        uint256 nonce;
        uint256 timestamp;
        uint256 deadline;
        MessagePath path;
        MessageStatus status;
        bytes32 nullifierBinding;
    }

    struct Relayer {
        address addr;
        uint256 bond;
        uint256 successCount;
        uint256 failCount;
        uint256 slashedAmount;
        bool active;
        uint256 registeredAt;
    }

    struct RouteConfig {
        MessagePath preferredPath;
        address adapter;
        uint256 minConfirmations;
        uint256 challengeWindow;
        bool active;
    }

    struct RelayerConfirmation {
        address relayer;
        bytes signature;
        uint256 timestamp;
    }

    struct SharedSequencerConfig {
        address sequencerAddress;
        uint256 chainIds;
        uint256 threshold;
        bool active;
    }

    error InvalidDestinationChain();
    error InvalidMessage();
    error MessageAlreadyProcessed();
    error MessageExpired();
    error InvalidSignatureCount();
    error UnbondingPeriodNotComplete();
    error TransferFailed();
    error InvalidRelayer();
    error InsufficientBond();
    error ChallengeWindowOpen();
    error InvalidProof();
    error UnsupportedRoute();
    error RelayerAlreadySigned();
    error InsufficientConfirmations();
    error MessageNotFound();
    error WithdrawalFailed();
    error MessageExecutionFailed();
    error ZeroAddress();
    error InvalidConfirmationCount();

    event MessageSent(
        bytes32 indexed messageId,
        uint256 indexed destChainId,
        address indexed sender,
        address target,
        uint256 value
    );
    event MessageReceived(
        bytes32 indexed messageId,
        uint256 indexed sourceChainId,
        address indexed sender
    );
    event MessageExecuted(
        bytes32 indexed messageId,
        bool success,
        bytes returnData
    );
    event RelayerRegistered(address indexed relayer, uint256 bond);
    event RelayerSlashed(
        address indexed relayer,
        uint256 amount,
        string reason
    );
    event RouteConfigured(
        uint256 indexed sourceChainId,
        uint256 indexed destChainId,
        MessagePath path
    );

    address public soulHub;
    address public superchainMessenger;
    address public espressoSequencer;
    address public astriaSequencer;
    uint256 public requiredConfirmations;
    uint256 public challengerReward;
    uint256 public immutable currentChainId;
    uint256 public constant MIN_BOND = 0.1 ether;
    uint256 public constant CHALLENGE_WINDOW = 1 hours;
    uint256 public constant UNBONDING_PERIOD = 7 days;

    mapping(bytes32 => L2Message) private _messages;
    mapping(address => Relayer) private _relayers;
    mapping(uint256 => mapping(uint256 => RouteConfig)) private _routes;
    mapping(bytes32 => mapping(address => bool)) private _confirmations;
    mapping(bytes32 => uint256) private _confirmationCount;
    uint256 public globalNonce;
    uint256 private _relayerCount;

    constructor(address _admin, address _soulHub) {
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);
        soulHub = _soulHub;
        currentChainId = block.chainid;
        requiredConfirmations = 2;
        challengerReward = 0.01 ether;
    }

    function sendMessage(
        uint256 destChainId,
        address recipient,
        bytes calldata payload,
        MessagePath path,
        bytes32 nullifierBinding
    ) external payable nonReentrant whenNotPaused returns (bytes32 messageId) {
        if (destChainId == block.chainid) revert InvalidDestinationChain();
        messageId = keccak256(
            abi.encodePacked(
                block.chainid,
                destChainId,
                globalNonce,
                msg.sender
            )
        );
        _messages[messageId] = L2Message(
            messageId,
            block.chainid,
            destChainId,
            msg.sender,
            recipient,
            payload,
            msg.value,
            globalNonce,
            block.timestamp,
            block.timestamp + 1 days,
            path,
            MessageStatus.SENT,
            nullifierBinding
        );
        globalNonce++;
        emit MessageSent(
            messageId,
            destChainId,
            msg.sender,
            recipient,
            msg.value
        );
    }

    function receiveMessage(
        bytes32 messageId,
        uint256 sourceChainId,
        address sender,
        address recipient,
        bytes calldata payload,
        bytes calldata
    ) external onlyRole(RELAYER_ROLE) {
        if (_messages[messageId].timestamp != 0)
            revert MessageAlreadyProcessed();
        _messages[messageId] = L2Message(
            messageId,
            sourceChainId,
            block.chainid,
            sender,
            recipient,
            payload,
            0,
            0,
            block.timestamp,
            block.timestamp + 1 days,
            MessagePath.FAST_RELAYER,
            MessageStatus.RELAYED,
            bytes32(0)
        );
        emit MessageReceived(messageId, sourceChainId, sender);
    }

    function receiveViaRelayer(
        bytes32 messageId,
        uint256 sourceChainId,
        address sender,
        address recipient,
        bytes calldata payload,
        bytes[] calldata
    ) external {
        if (_messages[messageId].timestamp != 0)
            revert MessageAlreadyProcessed();
        _messages[messageId] = L2Message(
            messageId,
            sourceChainId,
            block.chainid,
            sender,
            recipient,
            payload,
            0,
            0,
            block.timestamp,
            block.timestamp + 1 days,
            MessagePath.FAST_RELAYER,
            MessageStatus.RELAYED,
            bytes32(0)
        );
        emit MessageReceived(messageId, sourceChainId, sender);
    }

    function executeMessage(bytes32 messageId) external nonReentrant {
        _executeMessage(messageId);
    }

    function _executeMessage(bytes32 messageId) internal {
        L2Message storage m = _messages[messageId];
        (bool success, bytes memory ret) = m.recipient.call(m.payload);
        m.status = success ? MessageStatus.EXECUTED : MessageStatus.FAILED;
        emit MessageExecuted(messageId, success, ret);
    }

    function registerRelayer() external payable nonReentrant {
        if (msg.value < MIN_BOND) revert InsufficientBond();
        _relayers[msg.sender] = Relayer(
            msg.sender,
            msg.value,
            0,
            0,
            0,
            true,
            block.timestamp
        );
        _grantRole(RELAYER_ROLE, msg.sender);
        _relayerCount++;
        emit RelayerRegistered(msg.sender, msg.value);
    }

    function withdrawRelayerBond() external nonReentrant {
        Relayer storage r = _relayers[msg.sender];
        if (!r.active) revert InvalidRelayer();
        uint256 amount = r.bond;
        r.bond = 0;
        r.active = false;
        _revokeRole(RELAYER_ROLE, msg.sender);
        _relayerCount--;
        (bool ok, ) = msg.sender.call{value: amount}("");
        if (!ok) revert TransferFailed();
    }

    function slashRelayer(
        address relayer,
        uint256 amount,
        string calldata reason
    ) external onlyRole(OPERATOR_ROLE) {
        _relayers[relayer].bond -= amount;
        emit RelayerSlashed(relayer, amount, reason);
    }

    function challengeMessage(bytes32, bytes calldata) external {} // stub

    function resolveChallenge(
        bytes32,
        bool,
        bytes calldata
    ) external onlyRole(OPERATOR_ROLE) {} // stub

    function configureRoute(
        uint256 sourceChainId,
        uint256 destChainId,
        MessagePath path,
        address adapter,
        uint256 minConf,
        uint256 challengeWin
    ) external onlyRole(OPERATOR_ROLE) {
        _routes[sourceChainId][destChainId] = RouteConfig(
            path,
            adapter,
            minConf,
            challengeWin,
            true
        );
        emit RouteConfigured(sourceChainId, destChainId, path);
    }

    function setSuperchainMessenger(
        address _messenger
    ) external onlyRole(OPERATOR_ROLE) {
        superchainMessenger = _messenger;
    }

    function setEspressoSequencer(
        address _sequencer
    ) external onlyRole(OPERATOR_ROLE) {
        espressoSequencer = _sequencer;
    }

    function setAstriaSequencer(
        address _sequencer
    ) external onlyRole(OPERATOR_ROLE) {
        astriaSequencer = _sequencer;
    }

    function setRequiredConfirmations(
        uint256 _required
    ) external onlyRole(OPERATOR_ROLE) {
        requiredConfirmations = _required;
    }

    function setChallengerReward(
        uint256 _reward
    ) external onlyRole(OPERATOR_ROLE) {
        challengerReward = _reward;
    }

    function pause() external onlyRole(OPERATOR_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(OPERATOR_ROLE) {
        _unpause();
    }

    function getMessage(
        bytes32 messageId
    ) external view returns (L2Message memory) {
        return _messages[messageId];
    }

    function getRelayer(address addr) external view returns (Relayer memory) {
        return _relayers[addr];
    }

    function getRoute(
        uint256 src,
        uint256 dst
    ) external view returns (RouteConfig memory) {
        return _routes[src][dst];
    }

    function getConfirmationCount(
        bytes32 messageId
    ) external view returns (uint256) {
        return _confirmationCount[messageId];
    }

    function isMessageProcessed(
        bytes32 messageId
    ) external view returns (bool) {
        return _messages[messageId].timestamp != 0;
    }

    function getRelayerCount() external view returns (uint256) {
        return _relayerCount;
    }
}
