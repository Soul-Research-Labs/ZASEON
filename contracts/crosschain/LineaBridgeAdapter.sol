// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title LineaBridgeAdapter
 * @notice PIL bridge adapter for Linea zkEVM (Consensys zero-knowledge rollup)
 * @dev Integrates with Linea's native bridge and message service
 * @author PIL Protocol Team
 * @custom:security-contact security@pil.network
 */
contract LineaBridgeAdapter is AccessControl, ReentrancyGuard, Pausable {
    // ============ Constants ============

    bytes32 public constant BRIDGE_OPERATOR_ROLE =
        keccak256("BRIDGE_OPERATOR_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 public constant POSTMAN_ROLE = keccak256("POSTMAN_ROLE");

    /// @notice Linea chain IDs
    uint256 public constant LINEA_MAINNET_CHAIN_ID = 59144;
    uint256 public constant LINEA_TESTNET_CHAIN_ID = 59140;

    /// @notice Message fee multiplier (basis points)
    uint256 public constant FEE_MULTIPLIER_BPS = 10050; // 0.5% buffer

    /// @notice Finality configuration
    uint256 public constant FINALITY_PERIOD = 32; // ~6 hours on Linea

    // ============ Immutable State ============

    /// @notice Linea Message Service (L1 -> L2)
    address public immutable lineaMessageService;

    /// @notice Linea Token Bridge
    address public immutable lineaTokenBridge;

    /// @notice Linea Rollup Contract (for proof verification)
    address public immutable lineaRollup;

    // ============ State Variables ============

    /// @notice PIL Hub on Linea L2
    address public pilHubL2;

    /// @notice Proof registry on L1
    address public proofRegistry;

    /// @notice Bridge limits
    uint256 public minBridgeAmount;
    uint256 public maxBridgeAmount;
    uint256 public dailyLimit;
    uint256 public dailyBridged;
    uint256 public lastResetTime;

    /// @notice Message nonce
    uint256 public messageNonce;

    /// @notice Fee configuration
    uint256 public baseFee;
    uint256 public feePerByte;

    /// @notice Outgoing L1 -> L2 messages
    mapping(bytes32 => OutgoingMessage) public outgoingMessages;

    /// @notice Incoming L2 -> L1 messages (anchored)
    mapping(bytes32 => bool) public anchoredMessages;

    /// @notice Claimed messages
    mapping(bytes32 => bool) public claimedMessages;

    /// @notice Proof finality tracking
    mapping(bytes32 => ProofFinality) public proofFinality;

    /// @notice Linea nullifiers (for double-spend prevention)
    mapping(bytes32 => bool) public lineaNullifiers;

    /// @notice Cross-domain nullifiers (Linea -> PIL binding)
    mapping(bytes32 => bytes32) public crossDomainNullifiers;

    /// @notice PIL bindings
    mapping(bytes32 => bytes32) public pilBindings;

    // ============ Structs ============

    struct OutgoingMessage {
        address sender;
        bytes32 proofHash;
        uint256 value;
        uint256 fee;
        uint256 timestamp;
        uint256 deadline;
        MessageStatus status;
    }

    struct ProofFinality {
        bytes32 proofHash;
        uint256 sourceChain;
        uint256 destChain;
        uint256 anchoredBlock;
        uint256 finalizedBlock;
        bool isFinalized;
    }

    enum MessageStatus {
        Pending,
        Delivered,
        Failed,
        Refunded
    }

    struct LineaClaim {
        bytes32 messageHash;
        uint256 nonce;
        uint256 fee;
        address sender;
        address recipient;
        uint256 value;
        bytes data;
        bytes32[] merkleProof;
    }

    // ============ Events ============

    event ProofSentToLinea(
        bytes32 indexed messageId,
        bytes32 indexed proofHash,
        address indexed sender,
        address recipient,
        uint256 value,
        uint256 fee
    );

    event ProofAnchoredFromLinea(
        bytes32 indexed messageId,
        bytes32 indexed proofHash,
        uint256 anchoredBlock
    );

    event ProofFinalizedFromLinea(
        bytes32 indexed messageId,
        bytes32 indexed proofHash,
        uint256 finalizedBlock
    );

    event MessageClaimed(
        bytes32 indexed messageId,
        address indexed recipient,
        uint256 value
    );

    event MessageRefunded(
        bytes32 indexed messageId,
        address indexed sender,
        uint256 amount
    );

    event FeeUpdated(uint256 baseFee, uint256 feePerByte);
    event LimitUpdated(string limitType, uint256 value);

    event NullifierRegistered(
        bytes32 indexed nullifier,
        bytes32 indexed messageHash,
        uint256 blockNumber
    );

    event CrossDomainNullifierRegistered(
        bytes32 indexed crossDomainNullifier,
        bytes32 indexed lineaNullifier,
        uint256 targetDomain
    );

    event PILBindingCreated(
        bytes32 indexed pilBinding,
        bytes32 indexed lineaNullifier,
        bytes32 pilDomain
    );

    // ============ Errors ============

    error InvalidAddress();
    error InvalidAmount();
    error InvalidFee();
    error MessageNotFound();
    error MessageAlreadyProcessed();
    error MessageNotAnchored();
    error MessageNotFinalized();
    error DailyLimitExceeded();
    error DeadlineExceeded();
    error InsufficientFee();
    error RefundFailed();
    error ClaimFailed();
    error UnauthorizedCaller();
    error InvalidProof();
    error NullifierAlreadyUsed();
    error NullifierNotRegistered();

    // ============ Modifiers ============

    modifier onlyMessageService() {
        if (msg.sender != lineaMessageService) {
            revert UnauthorizedCaller();
        }
        _;
    }

    // ============ Constructor ============

    /**
     * @notice Initialize Linea bridge adapter
     * @param _messageService Linea Message Service address
     * @param _tokenBridge Linea Token Bridge address
     * @param _rollup Linea Rollup contract address
     * @param _admin Admin address
     */
    constructor(
        address _messageService,
        address _tokenBridge,
        address _rollup,
        address _admin
    ) {
        if (
            _messageService == address(0) ||
            _tokenBridge == address(0) ||
            _rollup == address(0) ||
            _admin == address(0)
        ) {
            revert InvalidAddress();
        }

        lineaMessageService = _messageService;
        lineaTokenBridge = _tokenBridge;
        lineaRollup = _rollup;

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(BRIDGE_OPERATOR_ROLE, _admin);
        _grantRole(PAUSER_ROLE, _admin);
        _grantRole(POSTMAN_ROLE, _admin);

        minBridgeAmount = 0.001 ether;
        maxBridgeAmount = 100 ether;
        dailyLimit = 1000 ether;
        lastResetTime = block.timestamp;

        baseFee = 0.001 ether;
        feePerByte = 100 gwei;
    }

    // ============ External Functions ============

    /**
     * @notice Bridge proof to Linea L2
     * @param proofHash Hash of the ZK proof
     * @param proofData Serialized proof data
     * @param publicInputs Public inputs for verification
     * @param recipient Recipient address on Linea
     * @return messageId Unique message identifier
     */
    function bridgeProofToLinea(
        bytes32 proofHash,
        bytes calldata proofData,
        bytes calldata publicInputs,
        address recipient
    ) external payable nonReentrant whenNotPaused returns (bytes32 messageId) {
        if (recipient == address(0)) revert InvalidAddress();

        // Calculate required fee
        uint256 requiredFee = _calculateFee(
            proofData.length + publicInputs.length
        );
        uint256 bridgeValue = msg.value - requiredFee;

        if (msg.value < requiredFee) revert InsufficientFee();
        if (bridgeValue < minBridgeAmount || bridgeValue > maxBridgeAmount) {
            revert InvalidAmount();
        }

        _checkAndUpdateDailyLimit(bridgeValue);

        messageId = keccak256(
            abi.encodePacked(
                block.chainid,
                LINEA_MAINNET_CHAIN_ID,
                msg.sender,
                proofHash,
                messageNonce++
            )
        );

        // Encode calldata for L2
        bytes memory callData = abi.encodeWithSignature(
            "receiveProofFromL1(bytes32,bytes,bytes,address,address)",
            proofHash,
            proofData,
            publicInputs,
            msg.sender,
            recipient
        );

        // Send message via Linea Message Service
        _sendMessageToL2(pilHubL2, bridgeValue, callData, requiredFee);

        outgoingMessages[messageId] = OutgoingMessage({
            sender: msg.sender,
            proofHash: proofHash,
            value: bridgeValue,
            fee: requiredFee,
            timestamp: block.timestamp,
            deadline: block.timestamp + 7 days,
            status: MessageStatus.Pending
        });

        emit ProofSentToLinea(
            messageId,
            proofHash,
            msg.sender,
            recipient,
            bridgeValue,
            requiredFee
        );
    }

    /**
     * @notice Anchor L2 -> L1 message (called when message is included in L1 state)
     * @param messageId Message ID
     * @param proofHash Associated proof hash
     * @param blockNumber Block where message was anchored
     */
    function anchorL2Message(
        bytes32 messageId,
        bytes32 proofHash,
        uint256 blockNumber
    ) external onlyRole(POSTMAN_ROLE) {
        if (anchoredMessages[messageId]) {
            revert MessageAlreadyProcessed();
        }

        anchoredMessages[messageId] = true;

        proofFinality[proofHash] = ProofFinality({
            proofHash: proofHash,
            sourceChain: LINEA_MAINNET_CHAIN_ID,
            destChain: block.chainid,
            anchoredBlock: blockNumber,
            finalizedBlock: 0,
            isFinalized: false
        });

        emit ProofAnchoredFromLinea(messageId, proofHash, blockNumber);
    }

    /**
     * @notice Finalize and claim L2 -> L1 message after finality period
     * @param claim Claim data structure
     */
    function claimMessage(
        LineaClaim calldata claim
    ) external nonReentrant whenNotPaused {
        if (claimedMessages[claim.messageHash]) {
            revert MessageAlreadyProcessed();
        }
        if (!anchoredMessages[claim.messageHash]) {
            revert MessageNotAnchored();
        }

        // Verify Merkle proof against Linea rollup
        if (!_verifyClaimProof(claim)) {
            revert InvalidProof();
        }

        // Check finality period
        if (!_isMessageFinalized(claim.messageHash)) {
            revert MessageNotFinalized();
        }

        claimedMessages[claim.messageHash] = true;

        // Decode and process the message
        (
            bytes32 proofHash,
            address sender,
            address recipient,
            uint256 value
        ) = _decodeMessageData(claim.data);

        // Update proof finality
        proofFinality[proofHash].isFinalized = true;
        proofFinality[proofHash].finalizedBlock = block.number;

        emit ProofFinalizedFromLinea(
            claim.messageHash,
            proofHash,
            block.number
        );
        emit MessageClaimed(claim.messageHash, recipient, value);

        // Notify proof registry
        if (proofRegistry != address(0)) {
            _notifyRegistry(proofHash, sender, value);
        }

        // Transfer value
        if (value > 0 && recipient != address(0)) {
            (bool success, ) = recipient.call{value: value}("");
            if (!success) revert ClaimFailed();
        }
    }

    /**
     * @notice Claim refund for failed or expired message
     * @param messageId Message to refund
     */
    function claimRefund(bytes32 messageId) external nonReentrant {
        OutgoingMessage storage message = outgoingMessages[messageId];

        if (message.sender == address(0)) revert MessageNotFound();
        if (message.status != MessageStatus.Pending)
            revert MessageAlreadyProcessed();
        if (message.sender != msg.sender) revert UnauthorizedCaller();
        if (block.timestamp < message.deadline) revert DeadlineExceeded();

        message.status = MessageStatus.Refunded;

        uint256 refundAmount = message.value + message.fee;

        (bool success, ) = message.sender.call{value: refundAmount}("");
        if (!success) revert RefundFailed();

        emit MessageRefunded(messageId, message.sender, refundAmount);
    }

    /**
     * @notice Get current fee estimate
     * @param dataSize Size of proof data in bytes
     * @return fee Estimated fee in wei
     */
    function estimateFee(uint256 dataSize) external view returns (uint256 fee) {
        return _calculateFee(dataSize);
    }

    // ============ View Functions ============

    /**
     * @notice Check if proof is finalized
     * @param proofHash Hash of the proof
     * @return True if finalized
     */
    function isProofFinalized(bytes32 proofHash) external view returns (bool) {
        return proofFinality[proofHash].isFinalized;
    }

    /**
     * @notice Get message status
     * @param messageId Message ID
     * @return Status of the message
     */
    function getMessageStatus(
        bytes32 messageId
    ) external view returns (MessageStatus) {
        return outgoingMessages[messageId].status;
    }

    /**
     * @notice Get remaining daily limit
     */
    function getRemainingDailyLimit() external view returns (uint256) {
        if (block.timestamp >= lastResetTime + 1 days) {
            return dailyLimit;
        }
        return dailyLimit > dailyBridged ? dailyLimit - dailyBridged : 0;
    }

    // ============ Admin Functions ============

    function setPilHubL2(
        address _pilHubL2
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_pilHubL2 == address(0)) revert InvalidAddress();
        pilHubL2 = _pilHubL2;
    }

    function setProofRegistry(
        address _proofRegistry
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        proofRegistry = _proofRegistry;
    }

    function updateFees(
        uint256 _baseFee,
        uint256 _feePerByte
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        baseFee = _baseFee;
        feePerByte = _feePerByte;
        emit FeeUpdated(_baseFee, _feePerByte);
    }

    function updateLimits(
        uint256 _minAmount,
        uint256 _maxAmount,
        uint256 _dailyLimit
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_minAmount >= _maxAmount) revert InvalidAmount();

        minBridgeAmount = _minAmount;
        maxBridgeAmount = _maxAmount;
        dailyLimit = _dailyLimit;

        emit LimitUpdated("minBridgeAmount", _minAmount);
        emit LimitUpdated("maxBridgeAmount", _maxAmount);
        emit LimitUpdated("dailyLimit", _dailyLimit);
    }

    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    // ============ Internal Functions ============

    function _calculateFee(uint256 dataSize) internal view returns (uint256) {
        uint256 fee = baseFee + (dataSize * feePerByte);
        return (fee * FEE_MULTIPLIER_BPS) / 10000;
    }

    function _checkAndUpdateDailyLimit(uint256 amount) internal {
        if (block.timestamp >= lastResetTime + 1 days) {
            dailyBridged = 0;
            lastResetTime = block.timestamp - (block.timestamp % 1 days);
        }

        if (dailyBridged + amount > dailyLimit) {
            revert DailyLimitExceeded();
        }

        dailyBridged += amount;
    }

    function _sendMessageToL2(
        address target,
        uint256 value,
        bytes memory data,
        uint256 fee
    ) internal {
        (bool success, ) = lineaMessageService.call{value: value + fee}(
            abi.encodeWithSignature(
                "sendMessage(address,uint256,bytes)",
                target,
                fee,
                data
            )
        );

        if (!success) revert InvalidAmount();
    }

    function _verifyClaimProof(
        LineaClaim calldata claim
    ) internal view returns (bool) {
        // Verify against Linea rollup state root
        (bool success, bytes memory result) = lineaRollup.staticcall(
            abi.encodeWithSignature(
                "verifyMerkleProof(bytes32,bytes32[],bytes)",
                claim.messageHash,
                claim.merkleProof,
                claim.data
            )
        );

        if (!success) return false;
        return abi.decode(result, (bool));
    }

    function _isMessageFinalized(
        bytes32 messageHash
    ) internal view returns (bool) {
        // Check if sufficient blocks have passed since anchoring
        (bool success, bytes memory result) = lineaRollup.staticcall(
            abi.encodeWithSignature("isMessageFinalized(bytes32)", messageHash)
        );

        if (!success) return false;
        return abi.decode(result, (bool));
    }

    function _decodeMessageData(
        bytes calldata data
    )
        internal
        pure
        returns (
            bytes32 proofHash,
            address sender,
            address recipient,
            uint256 value
        )
    {
        // Decode the proof message format
        (proofHash, sender, recipient, value) = abi.decode(
            data,
            (bytes32, address, address, uint256)
        );
    }

    function _notifyRegistry(
        bytes32 proofHash,
        address sender,
        uint256 value
    ) internal {
        (bool success, ) = proofRegistry.call(
            abi.encodeWithSignature(
                "recordFinalizedProof(bytes32,address,uint256,uint256)",
                proofHash,
                sender,
                value,
                LINEA_MAINNET_CHAIN_ID
            )
        );
        success; // Silence unused warning
    }

    // ============ Nullifier Functions ============

    /**
     * @notice Register a Linea nullifier from a finalized message
     * @param messageHash The message hash
     * @param blockNumber The L2 block number
     * @param commitment The commitment value
     * @return nullifier The derived nullifier
     */
    function registerNullifier(
        bytes32 messageHash,
        uint256 blockNumber,
        bytes32 commitment
    ) external onlyRole(BRIDGE_OPERATOR_ROLE) returns (bytes32 nullifier) {
        nullifier = _deriveLineaNullifier(messageHash, blockNumber, commitment);

        if (lineaNullifiers[nullifier]) {
            revert NullifierAlreadyUsed();
        }

        lineaNullifiers[nullifier] = true;

        emit NullifierRegistered(nullifier, messageHash, blockNumber);
    }

    /**
     * @notice Register a cross-domain nullifier for PIL binding
     * @param lineaNullifier The Linea nullifier
     * @param targetDomain The target domain ID
     * @return crossDomainNf The derived cross-domain nullifier
     */
    function registerCrossDomainNullifier(
        bytes32 lineaNullifier,
        uint256 targetDomain
    ) external onlyRole(BRIDGE_OPERATOR_ROLE) returns (bytes32 crossDomainNf) {
        if (!lineaNullifiers[lineaNullifier]) {
            revert NullifierNotRegistered();
        }

        crossDomainNf = _deriveCrossDomainNullifier(
            lineaNullifier,
            targetDomain
        );

        if (crossDomainNullifiers[crossDomainNf] != bytes32(0)) {
            revert NullifierAlreadyUsed();
        }

        crossDomainNullifiers[crossDomainNf] = lineaNullifier;

        emit CrossDomainNullifierRegistered(
            crossDomainNf,
            lineaNullifier,
            targetDomain
        );
    }

    /**
     * @notice Create a PIL binding from a Linea nullifier
     * @param lineaNullifier The Linea nullifier
     * @param pilDomain The PIL domain identifier
     * @return pilBinding The derived PIL binding
     */
    function createPILBinding(
        bytes32 lineaNullifier,
        bytes32 pilDomain
    ) external onlyRole(BRIDGE_OPERATOR_ROLE) returns (bytes32 pilBinding) {
        if (!lineaNullifiers[lineaNullifier]) {
            revert NullifierNotRegistered();
        }

        pilBinding = _derivePILBinding(lineaNullifier, pilDomain);

        if (pilBindings[pilBinding] != bytes32(0)) {
            revert NullifierAlreadyUsed();
        }

        pilBindings[pilBinding] = lineaNullifier;

        emit PILBindingCreated(pilBinding, lineaNullifier, pilDomain);
    }

    /**
     * @notice Check if a nullifier has been used
     * @param nullifier The nullifier to check
     * @return True if the nullifier has been used
     */
    function isNullifierUsed(bytes32 nullifier) external view returns (bool) {
        return lineaNullifiers[nullifier];
    }

    /**
     * @notice Get the Linea nullifier from a cross-domain nullifier
     * @param crossDomainNf The cross-domain nullifier
     * @return The original Linea nullifier
     */
    function getLineaNullifier(
        bytes32 crossDomainNf
    ) external view returns (bytes32) {
        return crossDomainNullifiers[crossDomainNf];
    }

    /**
     * @notice Get the Linea nullifier from a PIL binding
     * @param pilBinding The PIL binding
     * @return The original Linea nullifier
     */
    function getNullifierFromBinding(
        bytes32 pilBinding
    ) external view returns (bytes32) {
        return pilBindings[pilBinding];
    }

    // ============ Internal Nullifier Derivation ============

    function _deriveLineaNullifier(
        bytes32 messageHash,
        uint256 blockNumber,
        bytes32 commitment
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(
                    messageHash,
                    blockNumber,
                    commitment,
                    "LINEA_NULLIFIER"
                )
            );
    }

    function _deriveCrossDomainNullifier(
        bytes32 lineaNullifier,
        uint256 targetDomain
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(lineaNullifier, targetDomain, "LINEA2PIL")
            );
    }

    function _derivePILBinding(
        bytes32 lineaNullifier,
        bytes32 pilDomain
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(lineaNullifier, pilDomain, "PIL_BINDING")
            );
    }

    receive() external payable {}
}
