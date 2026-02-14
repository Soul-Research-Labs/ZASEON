// SPDX-License-Identifier: MIT
// Coverage stub – assembly-free L2ChainAdapter
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

contract L2ChainAdapter is AccessControl, ReentrancyGuard {
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant ORACLE_ROLE = keccak256("ORACLE_ROLE");

    enum MessageStatus {
        PENDING,
        RELAYED,
        CONFIRMED,
        FAILED
    }

    struct ChainConfig {
        uint256 chainId;
        string name;
        address bridge;
        address messenger;
        uint256 confirmations;
        bool enabled;
        uint256 gasLimit;
    }

    struct Message {
        bytes32 id;
        uint256 sourceChain;
        uint256 targetChain;
        bytes payload;
        uint256 timestamp;
        MessageStatus status;
    }

    error ChainAlreadyExists();
    error ChainNotFound();
    error ChainNotEnabled();
    error InvalidMessageStatus();
    error InvalidProof();
    error InvalidMagicBytes();
    error PayloadHashMismatch();
    error ProofExpired();
    error InvalidMerkleProof();
    error InvalidOracleSignature();
    error InsufficientOracleSignatures();
    error StateRootNotSet();
    error SignatureMalleability();
    error ZeroAddress();

    mapping(uint256 => ChainConfig) public chainConfigs;
    uint256[] public supportedChains;
    mapping(bytes32 => Message) public messages;
    mapping(uint256 => mapping(uint256 => bytes32)) public stateRoots;
    mapping(uint256 => uint256) public latestBlockNumber;
    mapping(uint256 => address[]) public chainOracles;
    mapping(uint256 => uint256) public minOracleSignatures;

    event ChainAdded(uint256 indexed chainId, string name, address bridge);
    event ChainUpdated(uint256 indexed chainId, bool enabled);
    event StateRootUpdated(
        uint256 indexed chainId,
        uint256 indexed blockNumber,
        bytes32 stateRoot
    );
    event OracleAdded(uint256 indexed chainId, address indexed oracle);
    event OracleRemoved(uint256 indexed chainId, address indexed oracle);
    event MessageSent(
        bytes32 indexed messageId,
        uint256 sourceChain,
        uint256 targetChain
    );
    event MessageReceived(bytes32 indexed messageId, uint256 sourceChain);
    event MessageConfirmed(bytes32 indexed messageId);

    uint256 private _messageNonce;

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(ADMIN_ROLE, admin);
    }

    function addChain(
        uint256 chainId,
        string memory name,
        address bridge,
        address messenger,
        uint256 confirmations,
        uint256 gasLimit
    ) external onlyRole(ADMIN_ROLE) {
        if (chainConfigs[chainId].chainId != 0) revert ChainAlreadyExists();
        chainConfigs[chainId] = ChainConfig(
            chainId,
            name,
            bridge,
            messenger,
            confirmations,
            true,
            gasLimit
        );
        supportedChains.push(chainId);
        emit ChainAdded(chainId, name, bridge);
    }

    function updateChain(
        uint256 chainId,
        address bridge,
        address messenger,
        uint256 confirmations,
        uint256 gasLimit,
        bool enabled
    ) external onlyRole(ADMIN_ROLE) {
        if (chainConfigs[chainId].chainId == 0) revert ChainNotFound();
        ChainConfig storage config = chainConfigs[chainId];
        config.bridge = bridge;
        config.messenger = messenger;
        config.confirmations = confirmations;
        config.gasLimit = gasLimit;
        config.enabled = enabled;
        emit ChainUpdated(chainId, enabled);
    }

    function sendMessage(
        uint256 targetChain,
        bytes calldata payload
    ) external returns (bytes32 messageId) {
        if (chainConfigs[targetChain].chainId == 0) revert ChainNotFound();
        if (!chainConfigs[targetChain].enabled) revert ChainNotEnabled();
        messageId = keccak256(
            abi.encodePacked(
                block.chainid,
                targetChain,
                _messageNonce++,
                block.timestamp
            )
        );
        messages[messageId] = Message(
            messageId,
            block.chainid,
            targetChain,
            payload,
            block.timestamp,
            MessageStatus.PENDING
        );
        emit MessageSent(messageId, block.chainid, targetChain);
    }

    function receiveMessage(
        bytes32 messageId,
        uint256 sourceChain,
        bytes calldata payload,
        bytes calldata
    ) external onlyRole(RELAYER_ROLE) nonReentrant {
        messages[messageId] = Message(
            messageId,
            sourceChain,
            block.chainid,
            payload,
            block.timestamp,
            MessageStatus.RELAYED
        );
        emit MessageReceived(messageId, sourceChain);
    }

    function confirmMessage(bytes32 messageId) external onlyRole(RELAYER_ROLE) {
        messages[messageId].status = MessageStatus.CONFIRMED;
        emit MessageConfirmed(messageId);
    }

    function updateStateRoot(
        uint256 sourceChain,
        uint256 blockNumber,
        bytes32 stateRoot
    ) external onlyRole(ORACLE_ROLE) {
        stateRoots[sourceChain][blockNumber] = stateRoot;
        latestBlockNumber[sourceChain] = blockNumber;
        emit StateRootUpdated(sourceChain, blockNumber, stateRoot);
    }

    function addOracle(
        uint256 chainId,
        address oracle
    ) external onlyRole(ADMIN_ROLE) {
        chainOracles[chainId].push(oracle);
        _grantRole(ORACLE_ROLE, oracle);
        emit OracleAdded(chainId, oracle);
    }

    function removeOracle(
        uint256 chainId,
        address oracle
    ) external onlyRole(ADMIN_ROLE) {
        address[] storage oracles = chainOracles[chainId];
        for (uint256 i = 0; i < oracles.length; i++) {
            if (oracles[i] == oracle) {
                oracles[i] = oracles[oracles.length - 1];
                oracles.pop();
                break;
            }
        }
        emit OracleRemoved(chainId, oracle);
    }

    function setMinOracleSignatures(
        uint256 chainId,
        uint256 minSigs
    ) external onlyRole(ADMIN_ROLE) {
        minOracleSignatures[chainId] = minSigs;
    }

    function getSupportedChains() external view returns (uint256[] memory) {
        return supportedChains;
    }

    function getChainConfig(
        uint256 chainId
    ) external view returns (ChainConfig memory) {
        return chainConfigs[chainId];
    }

    function isChainSupported(uint256 chainId) external view returns (bool) {
        return chainConfigs[chainId].chainId != 0;
    }

    function getMessageStatus(
        bytes32 messageId
    ) external view returns (MessageStatus) {
        return messages[messageId].status;
    }
}
