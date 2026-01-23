// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title HyperliquidPrimitives
 * @notice Core cryptographic primitives and data structures for Hyperliquid L1 integration
 * @dev Hyperliquid is a high-performance L1 for perpetuals and spot trading with sub-second finality
 *
 * Key Features:
 * - secp256k1 signatures (Ethereum-compatible)
 * - HyperBFT consensus (Tendermint-based)
 * - Native perpetual and spot order book
 * - HIP-1 token standard (native asset standard)
 * - Sub-second block finality (~200ms)
 */
library HyperliquidPrimitives {
    // =========================================================================
    // CONSTANTS
    // =========================================================================

    /// @notice secp256k1 curve order
    uint256 public constant SECP256K1_N =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    /// @notice secp256k1 field prime
    uint256 public constant SECP256K1_P =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;

    /// @notice Maximum leverage for perpetuals (50x)
    uint256 public constant MAX_LEVERAGE = 50;

    /// @notice Minimum order size in USD (10 USD)
    uint256 public constant MIN_ORDER_SIZE_USD = 10e6; // 6 decimals

    /// @notice Price precision (6 decimals)
    uint256 public constant PRICE_DECIMALS = 6;

    /// @notice Size precision (8 decimals for most assets)
    uint256 public constant SIZE_DECIMALS = 8;

    /// @notice Funding rate precision (1e6)
    uint256 public constant FUNDING_PRECISION = 1e6;

    /// @notice Liquidation threshold (margin ratio below which liquidation occurs)
    uint256 public constant LIQUIDATION_THRESHOLD = 625; // 6.25% in basis points

    /// @notice Maintenance margin requirement (basis points)
    uint256 public constant MAINTENANCE_MARGIN_BPS = 300; // 3%

    /// @notice Initial margin requirement (basis points)
    uint256 public constant INITIAL_MARGIN_BPS = 500; // 5% for 20x leverage

    /// @notice Maximum number of open orders per user per asset
    uint256 public constant MAX_OPEN_ORDERS = 200;

    /// @notice Validator set size
    uint256 public constant MAX_VALIDATORS = 100;

    /// @notice Quorum threshold (2/3 + 1)
    uint256 public constant QUORUM_THRESHOLD_BPS = 6667; // 66.67%

    /// @notice Block time (~200ms)
    uint256 public constant BLOCK_TIME_MS = 200;

    /// @notice Signature length
    uint256 public constant SIGNATURE_LENGTH = 65;

    /// @notice Domain separator for Hyperliquid
    bytes32 public constant HYPERLIQUID_DOMAIN = keccak256("HYPERLIQUID_V1");

    /// @notice Nullifier domain tag
    bytes32 public constant NULLIFIER_TAG = keccak256("HYPERLIQUID_NULLIFIER");

    /// @notice PIL binding tag
    bytes32 public constant PIL_BINDING_TAG = keccak256("HL2PIL");

    // =========================================================================
    // ENUMS
    // =========================================================================

    /// @notice Order side (buy/sell)
    enum Side {
        BUY,
        SELL
    }

    /// @notice Order type
    enum OrderType {
        LIMIT,
        MARKET,
        STOP_LIMIT,
        STOP_MARKET,
        TAKE_PROFIT_LIMIT,
        TAKE_PROFIT_MARKET
    }

    /// @notice Time in force
    enum TimeInForce {
        GTC, // Good Till Cancel
        IOC, // Immediate Or Cancel
        FOK, // Fill Or Kill
        ALO // Add Liquidity Only (Post Only)
    }

    /// @notice Position side
    enum PositionSide {
        LONG,
        SHORT
    }

    /// @notice Order status
    enum OrderStatus {
        OPEN,
        PARTIALLY_FILLED,
        FILLED,
        CANCELLED,
        EXPIRED,
        REJECTED
    }

    /// @notice Asset type
    enum AssetType {
        PERP, // Perpetual futures
        SPOT // Spot trading
    }

    // =========================================================================
    // STRUCTS - ORDERS
    // =========================================================================

    /// @notice Perpetual order
    struct PerpOrder {
        address trader;
        uint256 asset; // Asset index
        Side side;
        OrderType orderType;
        TimeInForce tif;
        uint256 size; // In base asset units (8 decimals)
        uint256 price; // In USD (6 decimals)
        uint256 triggerPrice; // For stop/TP orders
        bool reduceOnly;
        uint256 leverage;
        uint256 nonce;
        uint256 timestamp;
        bytes signature;
    }

    /// @notice Spot order
    struct SpotOrder {
        address trader;
        uint256 baseAsset; // Base token index
        uint256 quoteAsset; // Quote token index (usually USDC)
        Side side;
        OrderType orderType;
        TimeInForce tif;
        uint256 baseSize; // Base asset amount
        uint256 quoteSize; // Quote asset amount
        uint256 price; // Price in quote per base
        uint256 nonce;
        uint256 timestamp;
        bytes signature;
    }

    /// @notice Order fill
    struct OrderFill {
        bytes32 orderId;
        uint256 fillSize;
        uint256 fillPrice;
        uint256 fee;
        uint256 timestamp;
        bytes32 tradeId;
    }

    // =========================================================================
    // STRUCTS - POSITIONS
    // =========================================================================

    /// @notice Perpetual position
    struct Position {
        address trader;
        uint256 asset;
        PositionSide side;
        uint256 size; // Position size
        uint256 entryPrice; // Average entry price
        uint256 leverage;
        uint256 margin; // Collateral margin
        int256 unrealizedPnl; // Current unrealized PnL
        int256 accumulatedFunding; // Accumulated funding payments
        uint256 liquidationPrice;
        uint256 lastUpdateTime;
    }

    /// @notice Margin account
    struct MarginAccount {
        address trader;
        uint256 totalCollateral; // Total margin collateral
        uint256 usedMargin; // Margin used by positions
        uint256 availableMargin; // Free margin
        int256 unrealizedPnl; // Total unrealized PnL
        uint256 maintenanceMargin; // Required maintenance margin
        bool isLiquidatable;
    }

    // =========================================================================
    // STRUCTS - CONSENSUS
    // =========================================================================

    /// @notice Validator info
    struct Validator {
        address validatorAddress;
        bytes32 pubKeyHash; // secp256k1 public key hash
        uint256 votingPower;
        bool isActive;
        uint256 lastBlockSigned;
    }

    /// @notice Block header
    struct BlockHeader {
        uint64 height;
        uint64 timestamp;
        bytes32 previousHash;
        bytes32 stateRoot;
        bytes32 transactionsRoot;
        bytes32 receiptsRoot;
        bytes32 validatorSetHash;
        uint256 totalVotingPower;
    }

    /// @notice Commit signature (aggregated)
    struct CommitSignature {
        bytes32 blockHash;
        uint64 height;
        bytes signature; // Aggregated signature
        bytes validatorBitmap; // Which validators signed
        uint256 signingPower; // Total signing power
    }

    // =========================================================================
    // STRUCTS - HIP-1 TOKENS
    // =========================================================================

    /// @notice HIP-1 token (native Hyperliquid token standard)
    struct HIP1Token {
        uint256 tokenId;
        string name;
        string symbol;
        uint8 decimals;
        uint256 totalSupply;
        address deployer;
        bool isTradeable;
        uint256 spotMarketId; // Associated spot market
    }

    /// @notice Token balance
    struct TokenBalance {
        uint256 tokenId;
        uint256 available;
        uint256 locked; // In open orders
        uint256 total;
    }

    // =========================================================================
    // STRUCTS - BRIDGE
    // =========================================================================

    /// @notice Deposit from L1 (Arbitrum)
    struct Deposit {
        address depositor;
        address recipient;
        uint256 amount;
        uint256 tokenId; // 0 for USDC
        bytes32 l1TxHash;
        uint64 l1BlockNumber;
        uint256 timestamp;
        bool processed;
    }

    /// @notice Withdrawal to L1
    struct Withdrawal {
        address sender;
        address recipient;
        uint256 amount;
        uint256 tokenId;
        bytes32 withdrawalHash;
        uint64 hlBlockHeight;
        uint256 timestamp;
        bool finalized;
    }

    /// @notice Cross-domain nullifier
    struct CrossDomainNullifier {
        bytes32 hlNullifier;
        bytes32 pilNullifier;
        uint256 sourceChain;
        uint256 targetChain;
        uint256 timestamp;
    }

    // =========================================================================
    // HASH FUNCTIONS
    // =========================================================================

    /// @notice Keccak256 hash
    function keccakHash(bytes memory data) internal pure returns (bytes32) {
        return keccak256(data);
    }

    /// @notice Hash two values
    function hash2(
        bytes32 left,
        bytes32 right
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(left, right));
    }

    /// @notice Hash array of values
    function hashN(bytes32[] memory inputs) internal pure returns (bytes32) {
        if (inputs.length == 0) return bytes32(0);
        if (inputs.length == 1) return inputs[0];

        bytes32 result = inputs[0];
        for (uint256 i = 1; i < inputs.length; i++) {
            result = hash2(result, inputs[i]);
        }
        return result;
    }

    // =========================================================================
    // ORDER FUNCTIONS
    // =========================================================================

    /// @notice Compute order hash for perpetual order
    function computePerpOrderHash(
        PerpOrder memory order
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    HYPERLIQUID_DOMAIN,
                    "PERP_ORDER",
                    order.trader,
                    order.asset,
                    order.side,
                    order.orderType,
                    order.tif,
                    order.size,
                    order.price,
                    order.triggerPrice,
                    order.reduceOnly,
                    order.leverage,
                    order.nonce,
                    order.timestamp
                )
            );
    }

    /// @notice Compute order hash for spot order
    function computeSpotOrderHash(
        SpotOrder memory order
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    HYPERLIQUID_DOMAIN,
                    "SPOT_ORDER",
                    order.trader,
                    order.baseAsset,
                    order.quoteAsset,
                    order.side,
                    order.orderType,
                    order.tif,
                    order.baseSize,
                    order.quoteSize,
                    order.price,
                    order.nonce,
                    order.timestamp
                )
            );
    }

    /// @notice Validate perpetual order parameters
    function isValidPerpOrder(
        PerpOrder memory order
    ) internal pure returns (bool) {
        return
            order.trader != address(0) &&
            order.size > 0 &&
            order.price > 0 &&
            order.leverage > 0 &&
            order.leverage <= MAX_LEVERAGE &&
            order.nonce > 0;
    }

    /// @notice Validate spot order parameters
    function isValidSpotOrder(
        SpotOrder memory order
    ) internal pure returns (bool) {
        return
            order.trader != address(0) &&
            order.baseSize > 0 &&
            order.price > 0 &&
            order.nonce > 0;
    }

    /// @notice Calculate required margin for order
    function calculateRequiredMargin(
        uint256 size,
        uint256 price,
        uint256 leverage
    ) internal pure returns (uint256) {
        if (leverage == 0) return 0;
        uint256 notionalValue = (size * price) / (10 ** SIZE_DECIMALS);
        return notionalValue / leverage;
    }

    /// @notice Calculate liquidation price
    function calculateLiquidationPrice(
        uint256 entryPrice,
        uint256 leverage,
        PositionSide side,
        uint256 maintenanceMarginBps
    ) internal pure returns (uint256) {
        if (leverage == 0) return 0;

        uint256 marginRatio = 10000 / leverage; // Initial margin in bps
        uint256 buffer = marginRatio - maintenanceMarginBps;

        if (side == PositionSide.LONG) {
            // Long: liq price = entry * (1 - buffer/10000)
            return (entryPrice * (10000 - buffer)) / 10000;
        } else {
            // Short: liq price = entry * (1 + buffer/10000)
            return (entryPrice * (10000 + buffer)) / 10000;
        }
    }

    // =========================================================================
    // POSITION FUNCTIONS
    // =========================================================================

    /// @notice Calculate unrealized PnL
    function calculateUnrealizedPnl(
        Position memory pos,
        uint256 markPrice
    ) internal pure returns (int256) {
        if (pos.size == 0) return 0;

        int256 priceDiff;
        if (pos.side == PositionSide.LONG) {
            priceDiff = int256(markPrice) - int256(pos.entryPrice);
        } else {
            priceDiff = int256(pos.entryPrice) - int256(markPrice);
        }

        return (priceDiff * int256(pos.size)) / int256(10 ** SIZE_DECIMALS);
    }

    /// @notice Check if position is liquidatable
    function isLiquidatable(
        Position memory pos,
        uint256 markPrice
    ) internal pure returns (bool) {
        if (pos.size == 0) return false;

        int256 unrealizedPnl = calculateUnrealizedPnl(pos, markPrice);
        int256 equity = int256(pos.margin) + unrealizedPnl;

        if (equity <= 0) return true;

        uint256 notionalValue = (pos.size * markPrice) / (10 ** SIZE_DECIMALS);
        uint256 requiredMargin = (notionalValue * MAINTENANCE_MARGIN_BPS) /
            10000;

        return uint256(equity) < requiredMargin;
    }

    /// @notice Calculate margin ratio (in basis points)
    function calculateMarginRatio(
        Position memory pos,
        uint256 markPrice
    ) internal pure returns (uint256) {
        if (pos.size == 0) return type(uint256).max;

        int256 unrealizedPnl = calculateUnrealizedPnl(pos, markPrice);
        int256 equity = int256(pos.margin) + unrealizedPnl;

        if (equity <= 0) return 0;

        uint256 notionalValue = (pos.size * markPrice) / (10 ** SIZE_DECIMALS);
        if (notionalValue == 0) return type(uint256).max;

        return (uint256(equity) * 10000) / notionalValue;
    }

    // =========================================================================
    // FUNDING RATE
    // =========================================================================

    /// @notice Calculate funding payment
    function calculateFundingPayment(
        Position memory pos,
        int256 fundingRate // In FUNDING_PRECISION
    ) internal pure returns (int256) {
        if (pos.size == 0) return 0;

        int256 payment = (int256(pos.size) * fundingRate) /
            int256(FUNDING_PRECISION);

        // Longs pay shorts when funding is positive
        if (pos.side == PositionSide.LONG) {
            return -payment;
        } else {
            return payment;
        }
    }

    // =========================================================================
    // SIGNATURE FUNCTIONS
    // =========================================================================

    /// @notice Recover signer from signature
    function recoverSigner(
        bytes32 messageHash,
        bytes memory signature
    ) internal pure returns (address) {
        if (signature.length != SIGNATURE_LENGTH) {
            return address(0);
        }

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }

        if (v < 27) {
            v += 27;
        }

        if (v != 27 && v != 28) {
            return address(0);
        }

        return ecrecover(messageHash, v, r, s);
    }

    /// @notice Verify signature with EIP-191 prefix
    function verifySignature(
        bytes32 messageHash,
        bytes memory signature,
        address expectedSigner
    ) internal pure returns (bool) {
        bytes32 prefixedHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash)
        );
        address recovered = recoverSigner(prefixedHash, signature);
        return recovered == expectedSigner && recovered != address(0);
    }

    /// @notice Verify order signature
    function verifyOrderSignature(
        PerpOrder memory order
    ) internal pure returns (bool) {
        bytes32 orderHash = computePerpOrderHash(order);
        return verifySignature(orderHash, order.signature, order.trader);
    }

    // =========================================================================
    // CONSENSUS FUNCTIONS
    // =========================================================================

    /// @notice Compute block hash
    function computeBlockHash(
        BlockHeader memory header
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    header.height,
                    header.timestamp,
                    header.previousHash,
                    header.stateRoot,
                    header.transactionsRoot,
                    header.receiptsRoot,
                    header.validatorSetHash
                )
            );
    }

    /// @notice Compute validator set hash
    function computeValidatorSetHash(
        Validator[] memory validators
    ) internal pure returns (bytes32) {
        bytes32[] memory hashes = new bytes32[](validators.length);
        for (uint256 i = 0; i < validators.length; i++) {
            hashes[i] = keccak256(
                abi.encode(
                    validators[i].validatorAddress,
                    validators[i].pubKeyHash,
                    validators[i].votingPower
                )
            );
        }
        return hashN(hashes);
    }

    /// @notice Check if commit has quorum
    function hasQuorum(
        CommitSignature memory commit,
        uint256 totalVotingPower
    ) internal pure returns (bool) {
        if (totalVotingPower == 0) return false;
        uint256 threshold = (totalVotingPower * QUORUM_THRESHOLD_BPS) / 10000;
        return commit.signingPower > threshold;
    }

    /// @notice Validate block header
    function isValidBlockHeader(
        BlockHeader memory header
    ) internal pure returns (bool) {
        return
            header.height > 0 &&
            header.timestamp > 0 &&
            header.stateRoot != bytes32(0) &&
            header.transactionsRoot != bytes32(0) &&
            header.validatorSetHash != bytes32(0) &&
            header.totalVotingPower > 0;
    }

    // =========================================================================
    // NULLIFIER FUNCTIONS
    // =========================================================================

    /// @notice Derive nullifier from trade
    function deriveTradeNullifier(
        bytes32 tradeId,
        uint64 blockHeight,
        address trader
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(NULLIFIER_TAG, tradeId, blockHeight, trader)
            );
    }

    /// @notice Derive nullifier from withdrawal
    function deriveWithdrawalNullifier(
        bytes32 withdrawalHash,
        uint64 blockHeight
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(
                    NULLIFIER_TAG,
                    "WITHDRAWAL",
                    withdrawalHash,
                    blockHeight
                )
            );
    }

    /// @notice Derive cross-domain nullifier
    function deriveCrossDomainNullifier(
        bytes32 hlNullifier,
        uint256 sourceChain,
        uint256 targetChain
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(
                    hlNullifier,
                    sourceChain,
                    targetChain,
                    "HL_CROSS_DOMAIN"
                )
            );
    }

    /// @notice Derive PIL binding from Hyperliquid nullifier
    function derivePILBinding(
        bytes32 hlNullifier
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(hlNullifier, PIL_BINDING_TAG));
    }

    // =========================================================================
    // CHAIN FUNCTIONS
    // =========================================================================

    /// @notice Check if chain ID is Hyperliquid
    function isHyperliquidChain(uint256 chainId) internal pure returns (bool) {
        return
            chainId == 998 || // Hyperliquid Mainnet
            chainId == 999; // Hyperliquid Testnet
    }

    /// @notice Get Hyperliquid chain ID constants
    function getHyperliquidMainnet() internal pure returns (uint256) {
        return 998;
    }

    function getHyperliquidTestnet() internal pure returns (uint256) {
        return 999;
    }

    // =========================================================================
    // UTILITY FUNCTIONS
    // =========================================================================

    /// @notice Convert price to fixed point
    function toFixedPoint(
        uint256 value,
        uint8 fromDecimals,
        uint8 toDecimals
    ) internal pure returns (uint256) {
        if (fromDecimals == toDecimals) return value;
        if (fromDecimals < toDecimals) {
            return value * (10 ** (toDecimals - fromDecimals));
        } else {
            return value / (10 ** (fromDecimals - toDecimals));
        }
    }

    /// @notice Calculate fee
    function calculateFee(
        uint256 notionalValue,
        uint256 feeRateBps
    ) internal pure returns (uint256) {
        return (notionalValue * feeRateBps) / 10000;
    }

    /// @notice Safe subtraction
    function safeSub(uint256 a, uint256 b) internal pure returns (uint256) {
        return a > b ? a - b : 0;
    }

    /// @notice Minimum
    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }

    /// @notice Maximum
    function max(uint256 a, uint256 b) internal pure returns (uint256) {
        return a > b ? a : b;
    }
}
