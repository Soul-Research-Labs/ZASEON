// SPDX-License-Identifier: MIT
// Coverage stub – assembly-free ConfidentialStateContainerV3
pragma solidity ^0.8.20;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

contract ConfidentialStateContainerV3 is
    AccessControl,
    ReentrancyGuard,
    Pausable
{
    bytes32 public constant OPERATOR_ROLE =
        0x97667070c54ef182b0f5858b034beac1b6f3089aa2d3188bb1e8929f4fa9b929;
    bytes32 public constant EMERGENCY_ROLE =
        0xbf233dd2aafeb4d50879c4aa5c81e96d92f6e19c84f269f4f965a0643a5ef5a0;
    bytes32 public constant VERIFIER_ADMIN_ROLE =
        keccak256("VERIFIER_ADMIN_ROLE");

    enum StateStatus {
        Active,
        Locked,
        Frozen,
        Retired
    }

    struct EncryptedState {
        bytes32 commitment;
        bytes32 nullifier;
        bytes32 metadata;
        address owner;
        uint64 createdAt;
        uint64 updatedAt;
        uint32 version;
        StateStatus status;
        bytes encryptedState;
    }

    struct StateTransition {
        bytes32 oldCommitment;
        bytes32 newCommitment;
        address initiator;
        uint64 timestamp;
    }

    address private _verifier;
    uint256 private _totalStates;
    uint256 private _activeStates;
    uint256 private _proofValidityWindow;
    uint256 private _maxStateSize;

    mapping(bytes32 => EncryptedState) private _states;
    mapping(bytes32 => bool) private _nullifiers;
    mapping(bytes32 => bytes32) private _nullifierToCommitment;
    mapping(address => bytes32[]) private _ownerCommitments;
    mapping(bytes32 => StateTransition[]) private _stateHistory;
    mapping(address => uint256) private _nonces;

    event StateRegistered(
        bytes32 indexed commitment,
        address indexed owner,
        bytes32 nullifier
    );
    event StateTransferred(
        bytes32 indexed oldCommitment,
        bytes32 indexed newCommitment,
        address indexed initiator
    );
    event StateLocked(bytes32 indexed commitment);
    event StateUnlocked(bytes32 indexed commitment);
    event StateFrozen(bytes32 indexed commitment);

    error InvalidCommitment();
    error CommitmentAlreadyExists(bytes32 commitment);
    error NullifierAlreadyUsed(bytes32 nullifier);
    error StateNotFound(bytes32 commitment);
    error StateNotActive(bytes32 commitment);
    error InvalidProof();
    error ProofExpired();
    error InvalidSignature();
    error ExceedsMaxStateSize();
    error ZeroAddress();

    constructor(address verifier_) {
        if (verifier_ == address(0)) revert ZeroAddress();
        _verifier = verifier_;
        _proofValidityWindow = 1 hours;
        _maxStateSize = 32768;
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(OPERATOR_ROLE, msg.sender);
    }

    function totalStates() external view returns (uint256) {
        return _totalStates;
    }

    function activeStates() external view returns (uint256) {
        return _activeStates;
    }

    function proofValidityWindow() external view returns (uint256) {
        return _proofValidityWindow;
    }

    function maxStateSize() public view returns (uint256) {
        return _maxStateSize;
    }

    function states(
        bytes32 commitment
    ) external view returns (EncryptedState memory) {
        return _states[commitment];
    }

    function nullifiers(bytes32 nullifier) external view returns (bool) {
        return _nullifiers[nullifier];
    }

    function nullifierToCommitment(
        bytes32 nullifier
    ) external view returns (bytes32) {
        return _nullifierToCommitment[nullifier];
    }

    function ownerCommitments(
        address owner,
        uint256 index
    ) external view returns (bytes32) {
        return _ownerCommitments[owner][index];
    }

    function registerState(
        bytes32 commitment,
        bytes32 nullifier,
        bytes32 metadata,
        bytes calldata encryptedState,
        bytes calldata proof
    ) external nonReentrant whenNotPaused {
        _validateAndRegister(
            commitment,
            nullifier,
            metadata,
            encryptedState,
            proof,
            msg.sender
        );
    }

    function registerStateWithSignature(
        bytes32 commitment,
        bytes32 nullifier,
        bytes32 metadata,
        bytes calldata encryptedState,
        bytes calldata proof,
        address owner,
        uint256 deadline,
        bytes calldata signature
    ) external nonReentrant whenNotPaused {
        if (block.timestamp > deadline) revert ProofExpired();
        bytes32 hash = keccak256(
            abi.encodePacked(
                commitment,
                nullifier,
                owner,
                deadline,
                _nonces[owner]
            )
        );
        bytes32 ethHash = MessageHashUtils.toEthSignedMessageHash(hash);
        address signer = ECDSA.recover(ethHash, signature);
        if (signer != owner) revert InvalidSignature();
        _nonces[owner]++;
        _validateAndRegister(
            commitment,
            nullifier,
            metadata,
            encryptedState,
            proof,
            owner
        );
    }

    function batchRegisterStates(
        bytes32[] calldata commitments,
        bytes32[] calldata nullifier_s,
        bytes32[] calldata metadatas,
        bytes[] calldata encryptedStates,
        bytes[] calldata proofs
    ) external nonReentrant whenNotPaused {
        for (uint256 i = 0; i < commitments.length; i++) {
            _validateAndRegister(
                commitments[i],
                nullifier_s[i],
                metadatas[i],
                encryptedStates[i],
                proofs[i],
                msg.sender
            );
        }
    }

    function transferState(
        bytes32 oldCommitment,
        bytes32 newCommitment,
        bytes32 newNullifier,
        bytes calldata newEncryptedState,
        bytes calldata proof
    ) external nonReentrant whenNotPaused {
        EncryptedState storage state = _states[oldCommitment];
        if (state.createdAt == 0) revert StateNotFound(oldCommitment);
        if (state.status != StateStatus.Active)
            revert StateNotActive(oldCommitment);
        state.status = StateStatus.Retired;
        _activeStates--;
        _validateAndRegister(
            newCommitment,
            newNullifier,
            state.metadata,
            newEncryptedState,
            proof,
            msg.sender
        );
        _stateHistory[oldCommitment].push(
            StateTransition(
                oldCommitment,
                newCommitment,
                msg.sender,
                uint64(block.timestamp)
            )
        );
        emit StateTransferred(oldCommitment, newCommitment, msg.sender);
    }

    function _validateAndRegister(
        bytes32 commitment,
        bytes32 nullifier,
        bytes32 metadata,
        bytes calldata encryptedState,
        bytes calldata,
        address owner
    ) internal {
        if (commitment == bytes32(0)) revert InvalidCommitment();
        if (_states[commitment].createdAt != 0)
            revert CommitmentAlreadyExists(commitment);
        if (_nullifiers[nullifier]) revert NullifierAlreadyUsed(nullifier);
        if (encryptedState.length > _maxStateSize) revert ExceedsMaxStateSize();
        _nullifiers[nullifier] = true;
        _nullifierToCommitment[nullifier] = commitment;
        _states[commitment] = EncryptedState({
            commitment: commitment,
            nullifier: nullifier,
            metadata: metadata,
            owner: owner,
            createdAt: uint64(block.timestamp),
            updatedAt: uint64(block.timestamp),
            version: 1,
            status: StateStatus.Active,
            encryptedState: encryptedState
        });
        _ownerCommitments[owner].push(commitment);
        _totalStates++;
        _activeStates++;
        emit StateRegistered(commitment, owner, nullifier);
    }

    function isStateActive(bytes32 commitment) external view returns (bool) {
        return _states[commitment].status == StateStatus.Active;
    }

    function getState(
        bytes32 commitment
    ) external view returns (EncryptedState memory) {
        return _states[commitment];
    }

    function getOwnerCommitments(
        address owner
    ) external view returns (bytes32[] memory) {
        return _ownerCommitments[owner];
    }

    function getOwnerCommitmentsPaginated(
        address owner,
        uint256 offset,
        uint256 limit
    ) external view returns (bytes32[] memory result, uint256 total) {
        bytes32[] storage all = _ownerCommitments[owner];
        total = all.length;
        if (offset >= total) return (new bytes32[](0), total);
        uint256 end = offset + limit > total ? total : offset + limit;
        result = new bytes32[](end - offset);
        for (uint256 i = offset; i < end; i++) {
            result[i - offset] = all[i];
        }
    }

    function getStateHistory(
        bytes32 commitment
    ) external view returns (StateTransition[] memory) {
        return _stateHistory[commitment];
    }

    function getNonce(address account) external view returns (uint256) {
        return _nonces[account];
    }

    function setProofValidityWindow(
        uint256 window
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _proofValidityWindow = window;
    }

    function setMaxStateSize(
        uint256 size
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _maxStateSize = size;
    }

    function lockState(bytes32 commitment) external onlyRole(OPERATOR_ROLE) {
        EncryptedState storage state = _states[commitment];
        if (state.createdAt == 0) revert StateNotFound(commitment);
        state.status = StateStatus.Locked;
        emit StateLocked(commitment);
    }

    function unlockState(bytes32 commitment) external onlyRole(OPERATOR_ROLE) {
        EncryptedState storage state = _states[commitment];
        if (state.createdAt == 0) revert StateNotFound(commitment);
        state.status = StateStatus.Active;
        emit StateUnlocked(commitment);
    }

    function freezeState(bytes32 commitment) external onlyRole(EMERGENCY_ROLE) {
        EncryptedState storage state = _states[commitment];
        if (state.createdAt == 0) revert StateNotFound(commitment);
        state.status = StateStatus.Frozen;
        emit StateFrozen(commitment);
    }

    function pause() external onlyRole(EMERGENCY_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }
}
