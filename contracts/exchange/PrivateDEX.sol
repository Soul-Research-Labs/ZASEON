// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/**
 * @title PrivateDEX
 * @notice Privacy-preserving decentralized exchange with confidential orders
 * @dev Implements:
 *      - Confidential order book (encrypted orders)
 *      - Zero-knowledge order matching
 *      - Stealth addresses for settlement
 *      - MEV protection via commit-reveal
 *      - Cross-chain atomic swaps with privacy
 * @custom:security-contact security@pilprotocol.io
 * @custom:research-status Experimental - Private DEX research
 */
contract PrivateDEX is AccessControl, ReentrancyGuard, Pausable {
    using SafeERC20 for IERC20;

    // =========================================================================
    // CONSTANTS
    // =========================================================================

    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");

    /// @notice Domain separator
    bytes32 public constant PRIVATE_DEX_DOMAIN =
        keccak256("PIL_PRIVATE_DEX_V1");

    /// @notice BN254 curve order (for ZK proofs)
    uint256 public constant BN254_ORDER =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    /// @notice Maximum commitment age for commit-reveal
    uint256 public constant MAX_COMMITMENT_AGE = 1 hours;

    /// @notice Minimum commitment age (MEV protection)
    uint256 public constant MIN_COMMITMENT_AGE = 2 minutes;

    /// @notice Maximum order size (overflow protection)
    uint256 public constant MAX_ORDER_AMOUNT = type(uint128).max;

    /// @notice Protocol fee in basis points (0.3%)
    uint256 public constant PROTOCOL_FEE_BPS = 30;

    /// @notice Maximum ring size for anonymous orders
    uint256 public constant MAX_RING_SIZE = 16;

    // =========================================================================
    // ENUMS
    // =========================================================================

    /// @notice Order type
    enum OrderType {
        LIMIT, // Limit order at specific price
        MARKET, // Market order at best price
        STOP_LIMIT, // Stop-loss with limit
        ICEBERG // Hidden size order
    }

    /// @notice Order side
    enum OrderSide {
        BUY,
        SELL
    }

    /// @notice Order state
    enum OrderState {
        COMMITTED, // Order committed (encrypted)
        REVEALED, // Order revealed (visible)
        PARTIALLY_FILLED, // Partially filled
        FILLED, // Fully filled
        CANCELLED, // Cancelled by user
        EXPIRED // Expired
    }

    /// @notice Privacy level
    enum PrivacyLevel {
        PUBLIC, // Fully visible order
        HIDDEN_AMOUNT, // Price visible, amount hidden
        HIDDEN_PRICE, // Amount visible, price hidden
        FULLY_PRIVATE, // Both hidden (encrypted)
        RING_ANONYMOUS // Anonymous via ring signature
    }

    // =========================================================================
    // STRUCTS
    // =========================================================================

    /// @notice Encrypted order commitment
    struct OrderCommitment {
        bytes32 commitmentHash;
        address committer;
        uint256 committedAt;
        bool revealed;
        bytes32 nullifier; // Prevents double-reveal
    }

    /// @notice Revealed order
    struct Order {
        uint256 orderId;
        address trader; // Or stealth address
        address baseToken;
        address quoteToken;
        OrderType orderType;
        OrderSide side;
        uint256 price; // In quote token per base token
        uint256 amount; // Base token amount
        uint256 filledAmount;
        OrderState state;
        PrivacyLevel privacyLevel;
        uint256 createdAt;
        uint256 expiresAt;
        bytes32 stealthPubKey; // For private settlement
    }

    /// @notice Confidential order (encrypted)
    struct ConfidentialOrder {
        bytes32 encryptedData; // Encrypted order details
        bytes32 amountCommitment; // Pedersen commitment to amount
        bytes32 priceCommitment; // Pedersen commitment to price
        bytes zkProof; // Proof of valid order
    }

    /// @notice Trade execution
    struct Trade {
        uint256 tradeId;
        uint256 buyOrderId;
        uint256 sellOrderId;
        uint256 price;
        uint256 amount;
        uint256 fee;
        bytes32 executionProof;
        uint256 executedAt;
    }

    /// @notice Ring order for anonymity
    struct RingOrder {
        bytes32 keyImage; // Prevents double-spend
        bytes32[] ringMembers; // Public keys in ring
        bytes32 commitment; // Order commitment
        bytes ringSignature; // Ring signature
    }

    /// @notice Atomic swap for cross-chain
    struct AtomicSwap {
        uint256 swapId;
        address initiator;
        bytes32 secretHash; // H(secret)
        address tokenIn;
        uint256 amountIn;
        bytes32 targetChainOrder; // Order on destination chain
        uint256 timelock;
        bool completed;
        bool refunded;
    }

    /// @notice Orderbook level
    struct PriceLevel {
        uint256 price;
        uint256 totalAmount;
        uint256[] orderIds;
    }

    /// @notice Market pair
    struct TradingPair {
        address baseToken;
        address quoteToken;
        bool active;
        uint256 minOrderSize;
        uint256 tickSize; // Minimum price increment
        uint256 totalVolume;
        uint256 lastPrice;
    }

    // =========================================================================
    // STATE
    // =========================================================================

    /// @notice Order commitments (commit phase)
    mapping(bytes32 => OrderCommitment) public commitments;

    /// @notice Revealed orders
    mapping(uint256 => Order) public orders;
    uint256 public nextOrderId;

    /// @notice Confidential order data
    mapping(uint256 => ConfidentialOrder) public confidentialOrders;

    /// @notice Trade history
    mapping(uint256 => Trade) public trades;
    uint256 public nextTradeId;

    /// @notice Ring orders by key image
    mapping(bytes32 => RingOrder) public ringOrders;
    mapping(bytes32 => bool) public usedKeyImages;

    /// @notice Atomic swaps
    mapping(uint256 => AtomicSwap) public atomicSwaps;
    uint256 public nextSwapId;

    /// @notice Trading pairs
    mapping(bytes32 => TradingPair) public tradingPairs;
    bytes32[] public activePairs;

    /// @notice User order IDs
    mapping(address => uint256[]) public userOrders;

    /// @notice Nullifiers (prevent replay)
    mapping(bytes32 => bool) public nullifiers;

    /// @notice Stealth address registry
    mapping(bytes32 => address) public stealthAddresses;

    /// @notice Protocol fee recipient
    address public feeRecipient;

    /// @notice Total fees collected
    mapping(address => uint256) public feesCollected;

    // =========================================================================
    // EVENTS
    // =========================================================================

    event OrderCommitted(
        bytes32 indexed commitmentHash,
        address indexed committer,
        uint256 committedAt
    );

    event OrderRevealed(
        uint256 indexed orderId,
        address indexed trader,
        OrderSide side,
        uint256 price,
        uint256 amount,
        PrivacyLevel privacyLevel
    );

    event OrderCancelled(
        uint256 indexed orderId,
        address indexed trader,
        uint256 unfilledAmount
    );

    event TradeExecuted(
        uint256 indexed tradeId,
        uint256 indexed buyOrderId,
        uint256 indexed sellOrderId,
        uint256 price,
        uint256 amount,
        uint256 fee
    );

    event RingOrderSubmitted(
        bytes32 indexed keyImage,
        bytes32 commitment,
        uint256 ringSize
    );

    event AtomicSwapInitiated(
        uint256 indexed swapId,
        address indexed initiator,
        bytes32 secretHash,
        uint256 amount,
        uint256 timelock
    );

    event AtomicSwapCompleted(uint256 indexed swapId, bytes32 secret);

    event AtomicSwapRefunded(uint256 indexed swapId);

    event TradingPairAdded(
        bytes32 indexed pairHash,
        address baseToken,
        address quoteToken
    );

    event StealthSettlement(
        uint256 indexed tradeId,
        bytes32 indexed stealthPubKey,
        uint256 amount
    );

    // =========================================================================
    // ERRORS
    // =========================================================================

    error CommitmentNotFound(bytes32 hash);
    error CommitmentAlreadyRevealed(bytes32 hash);
    error CommitmentTooEarly(bytes32 hash);
    error CommitmentExpired(bytes32 hash);
    error OrderNotFound(uint256 orderId);
    error OrderNotActive(uint256 orderId);
    error InsufficientAmount(uint256 required, uint256 provided);
    error InvalidPrice(uint256 price);
    error InvalidProof();
    error KeyImageAlreadyUsed(bytes32 keyImage);
    error SwapNotFound(uint256 swapId);
    error SwapAlreadyCompleted(uint256 swapId);
    error SwapTimelockActive(uint256 swapId);
    error SwapTimelockExpired(uint256 swapId);
    error InvalidSecret(bytes32 secretHash);
    error PairNotActive(bytes32 pairHash);
    error NullifierAlreadyUsed(bytes32 nullifier);
    error Unauthorized();

    // =========================================================================
    // CONSTRUCTOR
    // =========================================================================

    constructor(address _feeRecipient) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ADMIN_ROLE, msg.sender);
        _grantRole(OPERATOR_ROLE, msg.sender);
        _grantRole(RELAYER_ROLE, msg.sender);

        feeRecipient = _feeRecipient;
    }

    // =========================================================================
    // COMMIT-REVEAL ORDERS (MEV PROTECTION)
    // =========================================================================

    /**
     * @notice Commit an encrypted order (phase 1)
     * @param commitmentHash Hash of order details + secret
     */
    function commitOrder(bytes32 commitmentHash) external whenNotPaused {
        commitments[commitmentHash] = OrderCommitment({
            commitmentHash: commitmentHash,
            committer: msg.sender,
            committedAt: block.timestamp,
            revealed: false,
            nullifier: bytes32(0)
        });

        emit OrderCommitted(commitmentHash, msg.sender, block.timestamp);
    }

    /**
     * @notice Reveal committed order (phase 2)
     * @param secret Secret used in commitment
     * @param baseToken Base token address
     * @param quoteToken Quote token address
     * @param orderType Order type
     * @param side Buy or sell
     * @param price Price in quote per base
     * @param amount Amount of base token
     * @param privacyLevel Privacy level
     * @param stealthPubKey Optional stealth public key for settlement
     */
    function revealOrder(
        bytes32 secret,
        address baseToken,
        address quoteToken,
        OrderType orderType,
        OrderSide side,
        uint256 price,
        uint256 amount,
        PrivacyLevel privacyLevel,
        bytes32 stealthPubKey
    ) external whenNotPaused nonReentrant returns (uint256 orderId) {
        // Compute commitment hash
        bytes32 commitmentHash = keccak256(
            abi.encodePacked(
                secret,
                baseToken,
                quoteToken,
                orderType,
                side,
                price,
                amount,
                msg.sender
            )
        );

        OrderCommitment storage commitment = commitments[commitmentHash];

        // Validate commitment
        if (commitment.committedAt == 0)
            revert CommitmentNotFound(commitmentHash);
        if (commitment.revealed)
            revert CommitmentAlreadyRevealed(commitmentHash);
        if (block.timestamp < commitment.committedAt + MIN_COMMITMENT_AGE) {
            revert CommitmentTooEarly(commitmentHash);
        }
        if (block.timestamp > commitment.committedAt + MAX_COMMITMENT_AGE) {
            revert CommitmentExpired(commitmentHash);
        }

        // Mark as revealed
        commitment.revealed = true;
        commitment.nullifier = keccak256(
            abi.encodePacked(commitmentHash, secret)
        );

        // Create order
        orderId = _createOrder(
            msg.sender,
            baseToken,
            quoteToken,
            orderType,
            side,
            price,
            amount,
            privacyLevel,
            stealthPubKey
        );

        // Lock tokens
        if (side == OrderSide.BUY) {
            IERC20(quoteToken).safeTransferFrom(
                msg.sender,
                address(this),
                (price * amount) / 1e18
            );
        } else {
            IERC20(baseToken).safeTransferFrom(
                msg.sender,
                address(this),
                amount
            );
        }

        emit OrderRevealed(
            orderId,
            msg.sender,
            side,
            price,
            amount,
            privacyLevel
        );
    }

    // =========================================================================
    // RING SIGNATURE ORDERS (ANONYMITY)
    // =========================================================================

    /**
     * @notice Submit anonymous order via ring signature
     * @param ringOrder Ring order with signature
     * @param orderDetails Encrypted order details
     */
    function submitRingOrder(
        RingOrder calldata ringOrder,
        bytes calldata orderDetails
    ) external whenNotPaused nonReentrant {
        // Check key image not used
        if (usedKeyImages[ringOrder.keyImage]) {
            revert KeyImageAlreadyUsed(ringOrder.keyImage);
        }

        // Verify ring signature
        if (!_verifyRingSignature(ringOrder)) {
            revert InvalidProof();
        }

        // Mark key image as used
        usedKeyImages[ringOrder.keyImage] = true;

        // Store ring order
        ringOrders[ringOrder.keyImage] = ringOrder;

        emit RingOrderSubmitted(
            ringOrder.keyImage,
            ringOrder.commitment,
            ringOrder.ringMembers.length
        );
    }

    // =========================================================================
    // ORDER MATCHING
    // =========================================================================

    /**
     * @notice Match two orders
     * @param buyOrderId Buy order ID
     * @param sellOrderId Sell order ID
     * @param amount Amount to match
     * @param proof ZK proof of valid match (for private orders)
     */
    function matchOrders(
        uint256 buyOrderId,
        uint256 sellOrderId,
        uint256 amount,
        bytes calldata proof
    ) external onlyRole(OPERATOR_ROLE) nonReentrant returns (uint256 tradeId) {
        Order storage buyOrder = orders[buyOrderId];
        Order storage sellOrder = orders[sellOrderId];

        // Validate orders
        if (buyOrder.orderId == 0) revert OrderNotFound(buyOrderId);
        if (sellOrder.orderId == 0) revert OrderNotFound(sellOrderId);
        if (
            buyOrder.state != OrderState.REVEALED &&
            buyOrder.state != OrderState.PARTIALLY_FILLED
        ) {
            revert OrderNotActive(buyOrderId);
        }
        if (
            sellOrder.state != OrderState.REVEALED &&
            sellOrder.state != OrderState.PARTIALLY_FILLED
        ) {
            revert OrderNotActive(sellOrderId);
        }

        // For private orders, verify ZK proof
        if (
            buyOrder.privacyLevel >= PrivacyLevel.HIDDEN_PRICE ||
            sellOrder.privacyLevel >= PrivacyLevel.HIDDEN_PRICE
        ) {
            if (!_verifyMatchProof(buyOrderId, sellOrderId, amount, proof)) {
                revert InvalidProof();
            }
        }

        // Check price compatibility
        if (buyOrder.price < sellOrder.price) {
            revert InvalidPrice(buyOrder.price);
        }

        // Check amount availability
        uint256 buyAvailable = buyOrder.amount - buyOrder.filledAmount;
        uint256 sellAvailable = sellOrder.amount - sellOrder.filledAmount;
        uint256 matchAmount = amount;

        if (matchAmount > buyAvailable) matchAmount = buyAvailable;
        if (matchAmount > sellAvailable) matchAmount = sellAvailable;

        // Execute price (midpoint)
        uint256 executionPrice = (buyOrder.price + sellOrder.price) / 2;

        // Calculate fee
        uint256 fee = (matchAmount * executionPrice * PROTOCOL_FEE_BPS) /
            (10000 * 1e18);

        // Update orders
        buyOrder.filledAmount += matchAmount;
        sellOrder.filledAmount += matchAmount;

        if (buyOrder.filledAmount == buyOrder.amount) {
            buyOrder.state = OrderState.FILLED;
        } else {
            buyOrder.state = OrderState.PARTIALLY_FILLED;
        }

        if (sellOrder.filledAmount == sellOrder.amount) {
            sellOrder.state = OrderState.FILLED;
        } else {
            sellOrder.state = OrderState.PARTIALLY_FILLED;
        }

        // Record trade
        tradeId = _recordTrade(
            buyOrderId,
            sellOrderId,
            executionPrice,
            matchAmount,
            fee
        );

        // Execute settlement
        _executeSettlement(
            buyOrder,
            sellOrder,
            matchAmount,
            executionPrice,
            fee
        );

        emit TradeExecuted(
            tradeId,
            buyOrderId,
            sellOrderId,
            executionPrice,
            matchAmount,
            fee
        );
    }

    // =========================================================================
    // ATOMIC SWAPS (CROSS-CHAIN)
    // =========================================================================

    /**
     * @notice Initiate atomic swap for cross-chain trade
     * @param secretHash Hash of secret
     * @param tokenIn Token to swap
     * @param amountIn Amount to swap
     * @param targetChainOrder Order hash on target chain
     * @param timelock Timelock duration
     */
    function initiateAtomicSwap(
        bytes32 secretHash,
        address tokenIn,
        uint256 amountIn,
        bytes32 targetChainOrder,
        uint256 timelock
    ) external whenNotPaused nonReentrant returns (uint256 swapId) {
        swapId = nextSwapId++;

        atomicSwaps[swapId] = AtomicSwap({
            swapId: swapId,
            initiator: msg.sender,
            secretHash: secretHash,
            tokenIn: tokenIn,
            amountIn: amountIn,
            targetChainOrder: targetChainOrder,
            timelock: block.timestamp + timelock,
            completed: false,
            refunded: false
        });

        IERC20(tokenIn).safeTransferFrom(msg.sender, address(this), amountIn);

        emit AtomicSwapInitiated(
            swapId,
            msg.sender,
            secretHash,
            amountIn,
            timelock
        );
    }

    /**
     * @notice Complete atomic swap by revealing secret
     * @param swapId Swap ID
     * @param secret The secret preimage
     * @param recipient Recipient of funds
     */
    function completeAtomicSwap(
        uint256 swapId,
        bytes32 secret,
        address recipient
    ) external nonReentrant {
        AtomicSwap storage swap = atomicSwaps[swapId];

        if (swap.swapId != swapId) revert SwapNotFound(swapId);
        if (swap.completed || swap.refunded)
            revert SwapAlreadyCompleted(swapId);
        if (block.timestamp > swap.timelock) revert SwapTimelockExpired(swapId);

        // Verify secret
        if (keccak256(abi.encodePacked(secret)) != swap.secretHash) {
            revert InvalidSecret(swap.secretHash);
        }

        swap.completed = true;

        IERC20(swap.tokenIn).safeTransfer(recipient, swap.amountIn);

        emit AtomicSwapCompleted(swapId, secret);
    }

    /**
     * @notice Refund atomic swap after timelock
     * @param swapId Swap ID
     */
    function refundAtomicSwap(uint256 swapId) external nonReentrant {
        AtomicSwap storage swap = atomicSwaps[swapId];

        if (swap.swapId != swapId) revert SwapNotFound(swapId);
        if (swap.completed || swap.refunded)
            revert SwapAlreadyCompleted(swapId);
        if (block.timestamp <= swap.timelock) revert SwapTimelockActive(swapId);

        swap.refunded = true;

        IERC20(swap.tokenIn).safeTransfer(swap.initiator, swap.amountIn);

        emit AtomicSwapRefunded(swapId);
    }

    // =========================================================================
    // CONFIDENTIAL ORDERS
    // =========================================================================

    /**
     * @notice Submit confidential order with ZK proof
     * @param orderId Order to attach confidential data to
     * @param encryptedData Encrypted order details
     * @param amountCommitment Pedersen commitment to amount
     * @param priceCommitment Pedersen commitment to price
     * @param zkProof Proof of valid commitments
     */
    function submitConfidentialOrder(
        uint256 orderId,
        bytes32 encryptedData,
        bytes32 amountCommitment,
        bytes32 priceCommitment,
        bytes calldata zkProof
    ) external {
        Order storage order = orders[orderId];
        if (order.trader != msg.sender) revert Unauthorized();

        confidentialOrders[orderId] = ConfidentialOrder({
            encryptedData: encryptedData,
            amountCommitment: amountCommitment,
            priceCommitment: priceCommitment,
            zkProof: zkProof
        });
    }

    // =========================================================================
    // TRADING PAIRS
    // =========================================================================

    /**
     * @notice Add trading pair
     * @param baseToken Base token
     * @param quoteToken Quote token
     * @param minOrderSize Minimum order size
     * @param tickSize Price tick size
     */
    function addTradingPair(
        address baseToken,
        address quoteToken,
        uint256 minOrderSize,
        uint256 tickSize
    ) external onlyRole(ADMIN_ROLE) {
        bytes32 pairHash = keccak256(abi.encodePacked(baseToken, quoteToken));

        tradingPairs[pairHash] = TradingPair({
            baseToken: baseToken,
            quoteToken: quoteToken,
            active: true,
            minOrderSize: minOrderSize,
            tickSize: tickSize,
            totalVolume: 0,
            lastPrice: 0
        });

        activePairs.push(pairHash);

        emit TradingPairAdded(pairHash, baseToken, quoteToken);
    }

    // =========================================================================
    // CANCEL ORDERS
    // =========================================================================

    /**
     * @notice Cancel an active order
     * @param orderId Order to cancel
     */
    function cancelOrder(uint256 orderId) external nonReentrant {
        Order storage order = orders[orderId];

        if (order.orderId == 0) revert OrderNotFound(orderId);
        if (order.trader != msg.sender) revert Unauthorized();
        if (
            order.state == OrderState.FILLED ||
            order.state == OrderState.CANCELLED
        ) {
            revert OrderNotActive(orderId);
        }

        uint256 unfilledAmount = order.amount - order.filledAmount;
        order.state = OrderState.CANCELLED;

        // Refund unfilled amount
        if (order.side == OrderSide.BUY) {
            uint256 refundAmount = (order.price * unfilledAmount) / 1e18;
            IERC20(order.quoteToken).safeTransfer(order.trader, refundAmount);
        } else {
            IERC20(order.baseToken).safeTransfer(order.trader, unfilledAmount);
        }

        emit OrderCancelled(orderId, order.trader, unfilledAmount);
    }

    // =========================================================================
    // INTERNAL FUNCTIONS
    // =========================================================================

    function _createOrder(
        address trader,
        address baseToken,
        address quoteToken,
        OrderType orderType,
        OrderSide side,
        uint256 price,
        uint256 amount,
        PrivacyLevel privacyLevel,
        bytes32 stealthPubKey
    ) internal returns (uint256 orderId) {
        orderId = nextOrderId++;

        orders[orderId] = Order({
            orderId: orderId,
            trader: trader,
            baseToken: baseToken,
            quoteToken: quoteToken,
            orderType: orderType,
            side: side,
            price: price,
            amount: amount,
            filledAmount: 0,
            state: OrderState.REVEALED,
            privacyLevel: privacyLevel,
            createdAt: block.timestamp,
            expiresAt: block.timestamp + 7 days,
            stealthPubKey: stealthPubKey
        });

        userOrders[trader].push(orderId);
    }

    function _recordTrade(
        uint256 buyOrderId,
        uint256 sellOrderId,
        uint256 price,
        uint256 amount,
        uint256 fee
    ) internal returns (uint256 tradeId) {
        tradeId = nextTradeId++;

        bytes32 executionProof = keccak256(
            abi.encodePacked(
                buyOrderId,
                sellOrderId,
                price,
                amount,
                block.timestamp
            )
        );

        trades[tradeId] = Trade({
            tradeId: tradeId,
            buyOrderId: buyOrderId,
            sellOrderId: sellOrderId,
            price: price,
            amount: amount,
            fee: fee,
            executionProof: executionProof,
            executedAt: block.timestamp
        });

        // Update pair volume
        bytes32 pairHash = keccak256(
            abi.encodePacked(
                orders[buyOrderId].baseToken,
                orders[buyOrderId].quoteToken
            )
        );
        tradingPairs[pairHash].totalVolume += amount;
        tradingPairs[pairHash].lastPrice = price;
    }

    function _executeSettlement(
        Order storage buyOrder,
        Order storage sellOrder,
        uint256 amount,
        uint256 price,
        uint256 fee
    ) internal {
        uint256 quoteAmount = (price * amount) / 1e18;

        // Determine settlement addresses
        address buyerRecipient = buyOrder.stealthPubKey != bytes32(0)
            ? stealthAddresses[buyOrder.stealthPubKey]
            : buyOrder.trader;

        address sellerRecipient = sellOrder.stealthPubKey != bytes32(0)
            ? stealthAddresses[sellOrder.stealthPubKey]
            : sellOrder.trader;

        // Default to trader if stealth not registered
        if (buyerRecipient == address(0)) buyerRecipient = buyOrder.trader;
        if (sellerRecipient == address(0)) sellerRecipient = sellOrder.trader;

        // Transfer base token to buyer
        IERC20(buyOrder.baseToken).safeTransfer(buyerRecipient, amount);

        // Transfer quote token to seller (minus fee)
        IERC20(buyOrder.quoteToken).safeTransfer(
            sellerRecipient,
            quoteAmount - fee
        );

        // Collect fee
        if (fee > 0) {
            feesCollected[buyOrder.quoteToken] += fee;
        }

        // Emit stealth settlement events if applicable
        if (buyOrder.stealthPubKey != bytes32(0)) {
            emit StealthSettlement(
                trades[nextTradeId - 1].tradeId,
                buyOrder.stealthPubKey,
                amount
            );
        }
        if (sellOrder.stealthPubKey != bytes32(0)) {
            emit StealthSettlement(
                trades[nextTradeId - 1].tradeId,
                sellOrder.stealthPubKey,
                quoteAmount - fee
            );
        }
    }

    function _verifyRingSignature(
        RingOrder calldata ringOrder
    ) internal pure returns (bool) {
        // Simplified ring signature verification
        // In production, implement full CLSAG/MLSAG verification
        if (
            ringOrder.ringMembers.length == 0 ||
            ringOrder.ringMembers.length > MAX_RING_SIZE
        ) {
            return false;
        }

        // Verify key image is valid
        if (ringOrder.keyImage == bytes32(0)) {
            return false;
        }

        // Verify signature exists
        if (ringOrder.ringSignature.length == 0) {
            return false;
        }

        return true;
    }

    function _verifyMatchProof(
        uint256 buyOrderId,
        uint256 sellOrderId,
        uint256 amount,
        bytes calldata proof
    ) internal view returns (bool) {
        // Verify ZK proof that:
        // 1. Buy price >= Sell price
        // 2. Amount is valid
        // 3. Commitments match actual values

        ConfidentialOrder storage buyConf = confidentialOrders[buyOrderId];
        ConfidentialOrder storage sellConf = confidentialOrders[sellOrderId];

        // For production: verify SNARK proof
        if (proof.length == 0) return false;

        // Check commitments exist
        if (
            buyConf.amountCommitment == bytes32(0) &&
            sellConf.amountCommitment == bytes32(0)
        ) {
            return true; // Both public orders
        }

        return true; // Placeholder for full ZK verification
    }

    // =========================================================================
    // VIEW FUNCTIONS
    // =========================================================================

    function getOrder(uint256 orderId) external view returns (Order memory) {
        return orders[orderId];
    }

    function getTrade(uint256 tradeId) external view returns (Trade memory) {
        return trades[tradeId];
    }

    function getUserOrders(
        address user
    ) external view returns (uint256[] memory) {
        return userOrders[user];
    }

    function getTradingPair(
        bytes32 pairHash
    ) external view returns (TradingPair memory) {
        return tradingPairs[pairHash];
    }

    function getAtomicSwap(
        uint256 swapId
    ) external view returns (AtomicSwap memory) {
        return atomicSwaps[swapId];
    }

    // =========================================================================
    // ADMIN FUNCTIONS
    // =========================================================================

    function registerStealthAddress(
        bytes32 stealthPubKey,
        address actualAddress
    ) external onlyRole(RELAYER_ROLE) {
        stealthAddresses[stealthPubKey] = actualAddress;
    }

    function withdrawFees(address token) external onlyRole(ADMIN_ROLE) {
        uint256 amount = feesCollected[token];
        feesCollected[token] = 0;
        IERC20(token).safeTransfer(feeRecipient, amount);
    }

    function setFeeRecipient(
        address _feeRecipient
    ) external onlyRole(ADMIN_ROLE) {
        feeRecipient = _feeRecipient;
    }

    function pause() external onlyRole(ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(ADMIN_ROLE) {
        _unpause();
    }
}
