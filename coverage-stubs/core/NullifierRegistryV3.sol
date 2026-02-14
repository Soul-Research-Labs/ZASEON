// SPDX-License-Identifier: MIT
// Coverage stub – assembly-free NullifierRegistryV3
pragma solidity ^0.8.20;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

contract NullifierRegistryV3 is AccessControl, Pausable {
    bytes32 public constant REGISTRAR_ROLE =
        0xd71e27a0cfbc80f527f81cf450e2175c21ffe4dbb0aba1e11283a01eea47eed0;
    bytes32 public constant BRIDGE_ROLE =
        0xa0e0fea2d8e1645949784c100317e2e94e1a3b2bd28a3b4a6b4f0f2a83345de0;
    bytes32 public constant EMERGENCY_ROLE =
        0xbf233dd2aafeb4d50879c4aa5c81e96d92f6e19c84f269f4f965a0643a5ef5a0;

    struct NullifierData {
        uint64 timestamp;
        uint64 blockNumber;
        uint64 sourceChainId;
        address registrar;
        bytes32 commitment;
        uint256 index;
    }

    uint256 public constant TREE_DEPTH = 32;
    uint256 public constant ROOT_HISTORY_SIZE = 100;

    mapping(bytes32 => bool) private _nullifiers;
    mapping(bytes32 => NullifierData) private _nullifierData;
    mapping(uint256 => uint256) private _chainNullifierCount;

    uint256 private _nextIndex;
    uint256 private _totalNullifiers;
    bytes32 private _currentRoot;
    bytes32[100] private _rootHistory;
    uint256 private _rootHistoryIndex;

    event NullifierRegistered(
        bytes32 indexed nullifier,
        bytes32 indexed commitment,
        uint256 indexed index,
        address registrar,
        uint64 chainId
    );
    event NullifierBatchRegistered(
        bytes32[] nullifiers,
        uint256 startIndex,
        uint256 count
    );
    event MerkleRootUpdated(
        bytes32 indexed oldRoot,
        bytes32 indexed newRoot,
        uint256 nullifierCount
    );
    event CrossChainNullifiersReceived(
        uint256 indexed sourceChainId,
        bytes32 indexed merkleRoot,
        uint256 count
    );
    event RegistrarAdded(address indexed registrar);
    event RegistrarRemoved(address indexed registrar);

    error NullifierAlreadyExists(bytes32 nullifier);
    error NullifierNotFound(bytes32 nullifier);
    error EmptyBatch();
    error ZeroNullifier();
    error InvalidMerkleProof();
    error BatchTooLarge(uint256 size, uint256 maxSize);
    error InvalidChainId();
    error RootNotInHistory(bytes32 root);

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(REGISTRAR_ROLE, msg.sender);
        _currentRoot = bytes32(0);
    }

    function registerNullifier(
        bytes32 nullifier,
        bytes32 commitment
    ) external onlyRole(REGISTRAR_ROLE) whenNotPaused returns (uint256) {
        return
            _registerNullifier(
                nullifier,
                commitment,
                block.chainid,
                msg.sender
            );
    }

    function batchRegisterNullifiers(
        bytes32[] calldata nullifiers,
        bytes32[] calldata commitments
    )
        external
        onlyRole(REGISTRAR_ROLE)
        whenNotPaused
        returns (uint256 startIndex)
    {
        if (nullifiers.length == 0) revert EmptyBatch();
        startIndex = _nextIndex;
        for (uint256 i = 0; i < nullifiers.length; i++) {
            _registerNullifier(
                nullifiers[i],
                commitments[i],
                block.chainid,
                msg.sender
            );
        }
        emit NullifierBatchRegistered(
            nullifiers,
            _nextIndex - nullifiers.length,
            nullifiers.length
        );
    }

    function receiveCrossChainNullifiers(
        bytes32[] calldata nullifiers,
        bytes32[] calldata commitments,
        uint256 sourceChainId,
        bytes calldata
    ) external onlyRole(BRIDGE_ROLE) whenNotPaused {
        bytes32 batchRoot = keccak256(abi.encodePacked(nullifiers));
        for (uint256 i = 0; i < nullifiers.length; i++) {
            _registerNullifier(
                nullifiers[i],
                commitments[i],
                sourceChainId,
                msg.sender
            );
        }
        emit CrossChainNullifiersReceived(
            sourceChainId,
            batchRoot,
            nullifiers.length
        );
    }

    function _registerNullifier(
        bytes32 nullifier,
        bytes32 commitment,
        uint256 sourceChainId,
        address registrar
    ) internal returns (uint256 index) {
        if (nullifier == bytes32(0)) revert ZeroNullifier();
        if (_nullifiers[nullifier]) revert NullifierAlreadyExists(nullifier);
        _nullifiers[nullifier] = true;
        index = _nextIndex;
        _nullifierData[nullifier] = NullifierData({
            timestamp: uint64(block.timestamp),
            blockNumber: uint64(block.number),
            sourceChainId: uint64(sourceChainId),
            registrar: registrar,
            commitment: commitment,
            index: index
        });
        _nextIndex++;
        _totalNullifiers++;
        _chainNullifierCount[sourceChainId]++;
        _currentRoot = keccak256(abi.encodePacked(_currentRoot, nullifier));
        _rootHistory[_rootHistoryIndex % ROOT_HISTORY_SIZE] = _currentRoot;
        _rootHistoryIndex++;
        emit NullifierRegistered(
            nullifier,
            commitment,
            index,
            registrar,
            uint64(sourceChainId)
        );
        bytes32 oldRoot = _rootHistory[
            (_rootHistoryIndex + ROOT_HISTORY_SIZE - 1) % ROOT_HISTORY_SIZE
        ];
        emit MerkleRootUpdated(oldRoot, _currentRoot, _totalNullifiers);
    }

    function exists(bytes32 nullifier) external view returns (bool) {
        return _nullifiers[nullifier];
    }

    function isNullifierUsed(bytes32 nullifier) external view returns (bool) {
        return _nullifiers[nullifier];
    }

    function totalNullifiers() external view returns (uint256) {
        return _totalNullifiers;
    }

    function merkleRoot() external view returns (bytes32) {
        return _currentRoot;
    }

    function batchExists(
        bytes32[] calldata nullifiers
    ) external view returns (bool[] memory results) {
        results = new bool[](nullifiers.length);
        for (uint256 i = 0; i < nullifiers.length; i++) {
            results[i] = _nullifiers[nullifiers[i]];
        }
    }

    function getNullifierData(
        bytes32 nullifier
    ) external view returns (NullifierData memory) {
        return _nullifierData[nullifier];
    }

    function isValidRoot(bytes32 root) external view returns (bool) {
        if (root == _currentRoot) return true;
        for (uint256 i = 0; i < ROOT_HISTORY_SIZE; i++) {
            if (_rootHistory[i] == root) return true;
        }
        return false;
    }

    function verifyMerkleProof(
        bytes32,
        bytes32[] calldata,
        bytes32
    ) external pure returns (bool) {
        return true;
    }

    function getTreeStats()
        external
        view
        returns (
            uint256 totalNullifiers,
            uint256 nextIndex,
            bytes32 currentRoot,
            uint256 treeDepth
        )
    {
        return (_totalNullifiers, _nextIndex, _currentRoot, TREE_DEPTH);
    }

    function getNullifierCountByChain(
        uint256 chainId
    ) external view returns (uint256) {
        return _chainNullifierCount[chainId];
    }

    function addRegistrar(
        address registrar
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _grantRole(REGISTRAR_ROLE, registrar);
        emit RegistrarAdded(registrar);
    }

    function removeRegistrar(
        address registrar
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _revokeRole(REGISTRAR_ROLE, registrar);
        emit RegistrarRemoved(registrar);
    }

    function pause() external onlyRole(EMERGENCY_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }
}
