// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/hyperliquid/HyperliquidPrimitives.sol";
import "../../contracts/crosschain/HyperliquidBridgeAdapter.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/**
 * @title HyperliquidFuzz
 * @notice Comprehensive fuzz tests for Hyperliquid L1 integration
 * @dev Tests perpetual/spot trading primitives, consensus, and cross-domain nullifiers
 */
contract HyperliquidFuzz is Test {
    using HyperliquidPrimitives for *;

    HyperliquidBridgeAdapter public bridge;

    address public admin = address(0x1);
    address public operator = address(0x2);
    address public validator1 = address(0x3);
    address public validator2 = address(0x4);
    address public user1 = address(0x5);
    address public user2 = address(0x6);
    address public guardian = address(0x911);

    uint256 public userPrivateKey = 0xBEEF;
    address public userWithKey;

    function setUp() public {
        userWithKey = vm.addr(userPrivateKey);

        vm.startPrank(admin);

        // Deploy implementation
        HyperliquidBridgeAdapter implementation = new HyperliquidBridgeAdapter();

        // Deploy proxy
        bytes memory initData = abi.encodeWithSelector(
            HyperliquidBridgeAdapter.initialize.selector,
            admin,
            guardian
        );
        ERC1967Proxy proxy = new ERC1967Proxy(
            address(implementation),
            initData
        );
        bridge = HyperliquidBridgeAdapter(payable(address(proxy)));

        // Setup roles
        bridge.grantRole(bridge.OPERATOR_ROLE(), operator);
        bridge.grantRole(bridge.VALIDATOR_ROLE(), validator1);
        bridge.grantRole(bridge.VALIDATOR_ROLE(), validator2);

        vm.stopPrank();

        // Fund accounts
        vm.deal(user1, 1000 ether);
        vm.deal(user2, 1000 ether);
        vm.deal(userWithKey, 1000 ether);
        vm.deal(address(bridge), 10000 ether);
    }

    // =========================================================================
    // PRIMITIVE FUZZ TESTS - HASH FUNCTIONS
    // =========================================================================

    function testFuzz_KeccakHashDeterminism(bytes memory data) public pure {
        bytes32 hash1 = HyperliquidPrimitives.keccakHash(data);
        bytes32 hash2 = HyperliquidPrimitives.keccakHash(data);
        assertEq(hash1, hash2, "Keccak hash not deterministic");
    }

    function testFuzz_KeccakHashUniqueness(
        bytes memory data1,
        bytes memory data2
    ) public pure {
        vm.assume(keccak256(data1) != keccak256(data2));
        bytes32 hash1 = HyperliquidPrimitives.keccakHash(data1);
        bytes32 hash2 = HyperliquidPrimitives.keccakHash(data2);
        assertNotEq(hash1, hash2, "Different data produced same hash");
    }

    function testFuzz_Hash2Determinism(
        bytes32 left,
        bytes32 right
    ) public pure {
        bytes32 hash1 = HyperliquidPrimitives.hash2(left, right);
        bytes32 hash2 = HyperliquidPrimitives.hash2(left, right);
        assertEq(hash1, hash2, "Hash2 not deterministic");
    }

    function testFuzz_Hash2NonCommutative(
        bytes32 left,
        bytes32 right
    ) public pure {
        vm.assume(left != right);
        bytes32 hash1 = HyperliquidPrimitives.hash2(left, right);
        bytes32 hash2 = HyperliquidPrimitives.hash2(right, left);
        assertNotEq(hash1, hash2, "Hash2 should not be commutative");
    }

    function testFuzz_HashNDeterminism(bytes32[] memory inputs) public pure {
        vm.assume(inputs.length > 0 && inputs.length <= 10);
        bytes32 hash1 = HyperliquidPrimitives.hashN(inputs);
        bytes32 hash2 = HyperliquidPrimitives.hashN(inputs);
        assertEq(hash1, hash2, "HashN not deterministic");
    }

    // =========================================================================
    // PRIMITIVE FUZZ TESTS - ORDER VALIDATION
    // =========================================================================

    function testFuzz_PerpOrderValidation(
        address trader,
        uint256 asset,
        uint256 size,
        uint256 price,
        uint256 leverage,
        uint256 nonce
    ) public view {
        size = bound(size, 0, type(uint128).max);
        price = bound(price, 0, type(uint128).max);
        leverage = bound(leverage, 0, 100);
        nonce = bound(nonce, 0, type(uint64).max);

        HyperliquidPrimitives.PerpOrder memory order = HyperliquidPrimitives
            .PerpOrder({
                trader: trader,
                asset: asset,
                side: HyperliquidPrimitives.Side.BUY,
                orderType: HyperliquidPrimitives.OrderType.LIMIT,
                tif: HyperliquidPrimitives.TimeInForce.GTC,
                size: size,
                price: price,
                triggerPrice: 0,
                reduceOnly: false,
                leverage: leverage,
                nonce: nonce,
                timestamp: block.timestamp,
                signature: ""
            });

        bool valid = HyperliquidPrimitives.isValidPerpOrder(order);
        bool expected = trader != address(0) &&
            size > 0 &&
            price > 0 &&
            leverage > 0 &&
            leverage <= HyperliquidPrimitives.MAX_LEVERAGE &&
            nonce > 0;

        assertEq(valid, expected, "Perp order validation mismatch");
    }

    function testFuzz_SpotOrderValidation(
        address trader,
        uint256 baseAsset,
        uint256 quoteAsset,
        uint256 baseSize,
        uint256 price,
        uint256 nonce
    ) public view {
        baseSize = bound(baseSize, 0, type(uint128).max);
        price = bound(price, 0, type(uint128).max);
        nonce = bound(nonce, 0, type(uint64).max);

        HyperliquidPrimitives.SpotOrder memory order = HyperliquidPrimitives
            .SpotOrder({
                trader: trader,
                baseAsset: baseAsset,
                quoteAsset: quoteAsset,
                side: HyperliquidPrimitives.Side.BUY,
                orderType: HyperliquidPrimitives.OrderType.LIMIT,
                tif: HyperliquidPrimitives.TimeInForce.GTC,
                baseSize: baseSize,
                quoteSize: 0,
                price: price,
                nonce: nonce,
                timestamp: block.timestamp,
                signature: ""
            });

        bool valid = HyperliquidPrimitives.isValidSpotOrder(order);
        bool expected = trader != address(0) &&
            baseSize > 0 &&
            price > 0 &&
            nonce > 0;

        assertEq(valid, expected, "Spot order validation mismatch");
    }

    function testFuzz_PerpOrderHashDeterminism(
        address trader,
        uint256 asset,
        uint256 size,
        uint256 price,
        uint256 leverage,
        uint256 nonce
    ) public pure {
        size = bound(size, 1, type(uint128).max);
        price = bound(price, 1, type(uint128).max);
        leverage = bound(leverage, 1, 50);
        nonce = bound(nonce, 1, type(uint64).max);

        HyperliquidPrimitives.PerpOrder memory order = HyperliquidPrimitives
            .PerpOrder({
                trader: trader,
                asset: asset,
                side: HyperliquidPrimitives.Side.BUY,
                orderType: HyperliquidPrimitives.OrderType.LIMIT,
                tif: HyperliquidPrimitives.TimeInForce.GTC,
                size: size,
                price: price,
                triggerPrice: 0,
                reduceOnly: false,
                leverage: leverage,
                nonce: nonce,
                timestamp: 1000,
                signature: ""
            });

        bytes32 hash1 = HyperliquidPrimitives.computePerpOrderHash(order);
        bytes32 hash2 = HyperliquidPrimitives.computePerpOrderHash(order);

        assertEq(hash1, hash2, "Perp order hash not deterministic");
    }

    // =========================================================================
    // PRIMITIVE FUZZ TESTS - MARGIN CALCULATIONS
    // =========================================================================

    function testFuzz_RequiredMarginCalculation(
        uint256 size,
        uint256 price,
        uint256 leverage
    ) public pure {
        size = bound(size, 1, 10 ** 16); // Max 100M units
        price = bound(price, 1, 10 ** 12); // Max 1M USD
        leverage = bound(leverage, 1, 50);

        uint256 margin = HyperliquidPrimitives.calculateRequiredMargin(
            size,
            price,
            leverage
        );

        // Verify: margin = (size * price / 10^8) / leverage
        uint256 notional = (size * price) /
            (10 ** HyperliquidPrimitives.SIZE_DECIMALS);
        uint256 expected = notional / leverage;

        assertEq(margin, expected, "Required margin calculation mismatch");
    }

    function testFuzz_RequiredMarginZeroLeverage(
        uint256 size,
        uint256 price
    ) public pure {
        uint256 margin = HyperliquidPrimitives.calculateRequiredMargin(
            size,
            price,
            0
        );
        assertEq(margin, 0, "Zero leverage should return zero margin");
    }

    function testFuzz_LiquidationPriceLong(
        uint256 entryPrice,
        uint256 leverage,
        uint256 maintenanceMarginBps
    ) public pure {
        entryPrice = bound(entryPrice, 10 ** 6, 10 ** 12); // 1 to 1M USD
        leverage = bound(leverage, 2, 50);
        maintenanceMarginBps = bound(maintenanceMarginBps, 100, 1000); // 1% to 10%

        uint256 liqPrice = HyperliquidPrimitives.calculateLiquidationPrice(
            entryPrice,
            leverage,
            HyperliquidPrimitives.PositionSide.LONG,
            maintenanceMarginBps
        );

        // Long: liq price should be below entry price
        assertLt(liqPrice, entryPrice, "Long liq price should be below entry");
    }

    function testFuzz_LiquidationPriceShort(
        uint256 entryPrice,
        uint256 leverage,
        uint256 maintenanceMarginBps
    ) public pure {
        entryPrice = bound(entryPrice, 10 ** 6, 10 ** 12);
        leverage = bound(leverage, 2, 50);
        maintenanceMarginBps = bound(maintenanceMarginBps, 100, 1000);

        uint256 liqPrice = HyperliquidPrimitives.calculateLiquidationPrice(
            entryPrice,
            leverage,
            HyperliquidPrimitives.PositionSide.SHORT,
            maintenanceMarginBps
        );

        // Short: liq price should be above entry price
        assertGt(liqPrice, entryPrice, "Short liq price should be above entry");
    }

    // =========================================================================
    // PRIMITIVE FUZZ TESTS - PNL CALCULATIONS
    // =========================================================================

    function testFuzz_UnrealizedPnlLong(
        uint256 entryPrice,
        uint256 markPrice,
        uint256 size
    ) public view {
        entryPrice = bound(entryPrice, 10 ** 6, 10 ** 12);
        markPrice = bound(markPrice, 10 ** 6, 10 ** 12);
        size = bound(size, 10 ** 8, 10 ** 16);

        HyperliquidPrimitives.Position memory pos = HyperliquidPrimitives
            .Position({
                trader: address(0x1),
                asset: 0,
                side: HyperliquidPrimitives.PositionSide.LONG,
                size: size,
                entryPrice: entryPrice,
                leverage: 10,
                margin: 1000 ether,
                unrealizedPnl: 0,
                accumulatedFunding: 0,
                liquidationPrice: 0,
                lastUpdateTime: block.timestamp
            });

        int256 pnl = HyperliquidPrimitives.calculateUnrealizedPnl(
            pos,
            markPrice
        );

        // Long: PnL = (markPrice - entryPrice) * size / 10^8
        int256 expected = ((int256(markPrice) - int256(entryPrice)) *
            int256(size)) / int256(10 ** 8);

        assertEq(pnl, expected, "Long PnL calculation mismatch");
    }

    function testFuzz_UnrealizedPnlShort(
        uint256 entryPrice,
        uint256 markPrice,
        uint256 size
    ) public view {
        entryPrice = bound(entryPrice, 10 ** 6, 10 ** 12);
        markPrice = bound(markPrice, 10 ** 6, 10 ** 12);
        size = bound(size, 10 ** 8, 10 ** 16);

        HyperliquidPrimitives.Position memory pos = HyperliquidPrimitives
            .Position({
                trader: address(0x1),
                asset: 0,
                side: HyperliquidPrimitives.PositionSide.SHORT,
                size: size,
                entryPrice: entryPrice,
                leverage: 10,
                margin: 1000 ether,
                unrealizedPnl: 0,
                accumulatedFunding: 0,
                liquidationPrice: 0,
                lastUpdateTime: block.timestamp
            });

        int256 pnl = HyperliquidPrimitives.calculateUnrealizedPnl(
            pos,
            markPrice
        );

        // Short: PnL = (entryPrice - markPrice) * size / 10^8
        int256 expected = ((int256(entryPrice) - int256(markPrice)) *
            int256(size)) / int256(10 ** 8);

        assertEq(pnl, expected, "Short PnL calculation mismatch");
    }

    function testFuzz_ZeroSizePosition() public pure {
        HyperliquidPrimitives.Position memory pos = HyperliquidPrimitives
            .Position({
                trader: address(0x1),
                asset: 0,
                side: HyperliquidPrimitives.PositionSide.LONG,
                size: 0,
                entryPrice: 50000 * 10 ** 6,
                leverage: 10,
                margin: 0,
                unrealizedPnl: 0,
                accumulatedFunding: 0,
                liquidationPrice: 0,
                lastUpdateTime: 0
            });

        int256 pnl = HyperliquidPrimitives.calculateUnrealizedPnl(
            pos,
            60000 * 10 ** 6
        );
        assertEq(pnl, 0, "Zero size should have zero PnL");

        bool liq = HyperliquidPrimitives.isLiquidatable(pos, 60000 * 10 ** 6);
        assertFalse(liq, "Zero size should not be liquidatable");
    }

    // =========================================================================
    // PRIMITIVE FUZZ TESTS - FUNDING RATE
    // =========================================================================

    function testFuzz_FundingPaymentLong(
        uint256 size,
        int256 fundingRate
    ) public view {
        size = bound(size, 10 ** 8, 10 ** 16);
        fundingRate = bound(fundingRate, -10 ** 6, 10 ** 6);

        HyperliquidPrimitives.Position memory pos = HyperliquidPrimitives
            .Position({
                trader: address(0x1),
                asset: 0,
                side: HyperliquidPrimitives.PositionSide.LONG,
                size: size,
                entryPrice: 50000 * 10 ** 6,
                leverage: 10,
                margin: 1000 ether,
                unrealizedPnl: 0,
                accumulatedFunding: 0,
                liquidationPrice: 0,
                lastUpdateTime: block.timestamp
            });

        int256 payment = HyperliquidPrimitives.calculateFundingPayment(
            pos,
            fundingRate
        );

        // Longs pay shorts when funding is positive
        if (fundingRate > 0) {
            assertLe(payment, 0, "Long should pay when funding positive");
        } else if (fundingRate < 0) {
            assertGe(payment, 0, "Long should receive when funding negative");
        }
    }

    function testFuzz_FundingPaymentShort(
        uint256 size,
        int256 fundingRate
    ) public view {
        size = bound(size, 10 ** 8, 10 ** 16);
        fundingRate = bound(fundingRate, -10 ** 6, 10 ** 6);

        HyperliquidPrimitives.Position memory pos = HyperliquidPrimitives
            .Position({
                trader: address(0x1),
                asset: 0,
                side: HyperliquidPrimitives.PositionSide.SHORT,
                size: size,
                entryPrice: 50000 * 10 ** 6,
                leverage: 10,
                margin: 1000 ether,
                unrealizedPnl: 0,
                accumulatedFunding: 0,
                liquidationPrice: 0,
                lastUpdateTime: block.timestamp
            });

        int256 payment = HyperliquidPrimitives.calculateFundingPayment(
            pos,
            fundingRate
        );

        // Shorts receive from longs when funding is positive
        if (fundingRate > 0) {
            assertGe(payment, 0, "Short should receive when funding positive");
        } else if (fundingRate < 0) {
            assertLe(payment, 0, "Short should pay when funding negative");
        }
    }

    // =========================================================================
    // PRIMITIVE FUZZ TESTS - SIGNATURES
    // =========================================================================

    function testFuzz_SignatureRecovery(bytes32 messageHash) public view {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(userPrivateKey, messageHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        address recovered = HyperliquidPrimitives.recoverSigner(
            messageHash,
            signature
        );
        assertEq(recovered, userWithKey, "Signature recovery failed");
    }

    function testFuzz_SignatureVerification(bytes32 messageHash) public view {
        bytes32 prefixedHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(userPrivateKey, prefixedHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        bool valid = HyperliquidPrimitives.verifySignature(
            messageHash,
            signature,
            userWithKey
        );
        assertTrue(valid, "Signature verification failed");
    }

    function testFuzz_InvalidSignatureLength(
        bytes memory signature
    ) public pure {
        vm.assume(signature.length != 65);

        address recovered = HyperliquidPrimitives.recoverSigner(
            bytes32(0),
            signature
        );
        assertEq(
            recovered,
            address(0),
            "Invalid signature should return zero address"
        );
    }

    // =========================================================================
    // PRIMITIVE FUZZ TESTS - CONSENSUS
    // =========================================================================

    function testFuzz_BlockHeaderValidation(
        uint64 height,
        uint64 timestamp,
        bytes32 stateRoot,
        bytes32 txRoot,
        bytes32 validatorSetHash,
        uint256 totalPower
    ) public pure {
        HyperliquidPrimitives.BlockHeader memory header = HyperliquidPrimitives
            .BlockHeader({
                height: height,
                timestamp: timestamp,
                previousHash: bytes32(0),
                stateRoot: stateRoot,
                transactionsRoot: txRoot,
                receiptsRoot: bytes32(0),
                validatorSetHash: validatorSetHash,
                totalVotingPower: totalPower
            });

        bool valid = HyperliquidPrimitives.isValidBlockHeader(header);
        bool expected = height > 0 &&
            timestamp > 0 &&
            stateRoot != bytes32(0) &&
            txRoot != bytes32(0) &&
            validatorSetHash != bytes32(0) &&
            totalPower > 0;

        assertEq(valid, expected, "Block header validation mismatch");
    }

    function testFuzz_QuorumCheck(
        uint256 signingPower,
        uint256 totalPower
    ) public pure {
        signingPower = bound(signingPower, 0, type(uint128).max);
        totalPower = bound(totalPower, 1, type(uint128).max);

        HyperliquidPrimitives.CommitSignature
            memory commit = HyperliquidPrimitives.CommitSignature({
                blockHash: bytes32(0),
                height: 1,
                signature: "",
                validatorBitmap: "",
                signingPower: signingPower
            });

        bool hasQuorum = HyperliquidPrimitives.hasQuorum(commit, totalPower);
        uint256 threshold = (totalPower *
            HyperliquidPrimitives.QUORUM_THRESHOLD_BPS) / 10000;
        bool expected = signingPower > threshold;

        assertEq(hasQuorum, expected, "Quorum check mismatch");
    }

    function testFuzz_BlockHashDeterminism(
        uint64 height,
        uint64 timestamp,
        bytes32 prevHash,
        bytes32 stateRoot
    ) public pure {
        HyperliquidPrimitives.BlockHeader memory header = HyperliquidPrimitives
            .BlockHeader({
                height: height,
                timestamp: timestamp,
                previousHash: prevHash,
                stateRoot: stateRoot,
                transactionsRoot: bytes32(uint256(1)),
                receiptsRoot: bytes32(0),
                validatorSetHash: bytes32(uint256(2)),
                totalVotingPower: 1000
            });

        bytes32 hash1 = HyperliquidPrimitives.computeBlockHash(header);
        bytes32 hash2 = HyperliquidPrimitives.computeBlockHash(header);

        assertEq(hash1, hash2, "Block hash not deterministic");
    }

    // =========================================================================
    // PRIMITIVE FUZZ TESTS - NULLIFIER
    // =========================================================================

    function testFuzz_TradeNullifierDeterminism(
        bytes32 tradeId,
        uint64 blockHeight,
        address trader
    ) public pure {
        bytes32 nf1 = HyperliquidPrimitives.deriveTradeNullifier(
            tradeId,
            blockHeight,
            trader
        );
        bytes32 nf2 = HyperliquidPrimitives.deriveTradeNullifier(
            tradeId,
            blockHeight,
            trader
        );
        assertEq(nf1, nf2, "Trade nullifier not deterministic");
    }

    function testFuzz_TradeNullifierUniqueness(
        bytes32 tradeId1,
        bytes32 tradeId2,
        uint64 blockHeight,
        address trader
    ) public pure {
        vm.assume(tradeId1 != tradeId2);

        bytes32 nf1 = HyperliquidPrimitives.deriveTradeNullifier(
            tradeId1,
            blockHeight,
            trader
        );
        bytes32 nf2 = HyperliquidPrimitives.deriveTradeNullifier(
            tradeId2,
            blockHeight,
            trader
        );

        assertNotEq(
            nf1,
            nf2,
            "Different trades should produce different nullifiers"
        );
    }

    function testFuzz_CrossDomainNullifier(
        bytes32 hlNullifier,
        uint256 sourceChain,
        uint256 targetChain
    ) public pure {
        vm.assume(sourceChain != targetChain);

        bytes32 crossNf1 = HyperliquidPrimitives.deriveCrossDomainNullifier(
            hlNullifier,
            sourceChain,
            targetChain
        );
        bytes32 crossNf2 = HyperliquidPrimitives.deriveCrossDomainNullifier(
            hlNullifier,
            sourceChain,
            targetChain
        );

        assertEq(
            crossNf1,
            crossNf2,
            "Cross-domain nullifier not deterministic"
        );
    }

    function testFuzz_CrossDomainNullifierDirectionMatters(
        bytes32 hlNullifier,
        uint256 sourceChain,
        uint256 targetChain
    ) public pure {
        vm.assume(sourceChain != targetChain);
        vm.assume(sourceChain > 0 && targetChain > 0);

        bytes32 forward = HyperliquidPrimitives.deriveCrossDomainNullifier(
            hlNullifier,
            sourceChain,
            targetChain
        );
        bytes32 backward = HyperliquidPrimitives.deriveCrossDomainNullifier(
            hlNullifier,
            targetChain,
            sourceChain
        );

        assertNotEq(forward, backward, "Direction should matter");
    }

    function testFuzz_PILBinding(bytes32 hlNullifier) public pure {
        bytes32 binding1 = HyperliquidPrimitives.derivePILBinding(hlNullifier);
        bytes32 binding2 = HyperliquidPrimitives.derivePILBinding(hlNullifier);

        assertEq(binding1, binding2, "PIL binding not deterministic");
    }

    function testFuzz_PILBindingUniqueness(
        bytes32 nf1,
        bytes32 nf2
    ) public pure {
        vm.assume(nf1 != nf2);

        bytes32 binding1 = HyperliquidPrimitives.derivePILBinding(nf1);
        bytes32 binding2 = HyperliquidPrimitives.derivePILBinding(nf2);

        assertNotEq(
            binding1,
            binding2,
            "Different nullifiers should have different bindings"
        );
    }

    // =========================================================================
    // PRIMITIVE FUZZ TESTS - CHAIN DETECTION
    // =========================================================================

    function testFuzz_HyperliquidChainDetection(uint256 chainId) public pure {
        bool isHL = HyperliquidPrimitives.isHyperliquidChain(chainId);
        bool expected = chainId == 998 || chainId == 999;
        assertEq(isHL, expected, "Chain detection mismatch");
    }

    function test_KnownHyperliquidChains() public pure {
        assertTrue(HyperliquidPrimitives.isHyperliquidChain(998), "Mainnet");
        assertTrue(HyperliquidPrimitives.isHyperliquidChain(999), "Testnet");
        assertFalse(
            HyperliquidPrimitives.isHyperliquidChain(1),
            "Ethereum is not HL"
        );
        assertFalse(
            HyperliquidPrimitives.isHyperliquidChain(42161),
            "Arbitrum is not HL"
        );
    }

    // =========================================================================
    // PRIMITIVE FUZZ TESTS - UTILITY
    // =========================================================================

    function testFuzz_ToFixedPoint(
        uint256 value,
        uint8 fromDecimals,
        uint8 toDecimals
    ) public pure {
        value = bound(value, 0, 10 ** 30);
        fromDecimals = uint8(bound(fromDecimals, 0, 18));
        toDecimals = uint8(bound(toDecimals, 0, 18));

        uint256 result = HyperliquidPrimitives.toFixedPoint(
            value,
            fromDecimals,
            toDecimals
        );

        if (fromDecimals == toDecimals) {
            assertEq(result, value, "Same decimals should return same value");
        }
    }

    function testFuzz_CalculateFee(
        uint256 notionalValue,
        uint256 feeRateBps
    ) public pure {
        notionalValue = bound(notionalValue, 0, 10 ** 30);
        feeRateBps = bound(feeRateBps, 0, 10000);

        uint256 fee = HyperliquidPrimitives.calculateFee(
            notionalValue,
            feeRateBps
        );
        uint256 expected = (notionalValue * feeRateBps) / 10000;

        assertEq(fee, expected, "Fee calculation mismatch");
    }

    function testFuzz_SafeSub(uint256 a, uint256 b) public pure {
        uint256 result = HyperliquidPrimitives.safeSub(a, b);
        uint256 expected = a > b ? a - b : 0;
        assertEq(result, expected, "SafeSub mismatch");
    }

    function testFuzz_MinMax(uint256 a, uint256 b) public pure {
        assertEq(
            HyperliquidPrimitives.min(a, b),
            a < b ? a : b,
            "Min mismatch"
        );
        assertEq(
            HyperliquidPrimitives.max(a, b),
            a > b ? a : b,
            "Max mismatch"
        );
    }

    // =========================================================================
    // BRIDGE ADAPTER FUZZ TESTS - DEPOSITS
    // =========================================================================

    function testFuzz_Deposit(uint256 amount) public {
        amount = bound(amount, 1, bridge.MAX_TRANSFER());

        vm.prank(user1);
        bridge.deposit{value: amount}(user1, 0);

        (, , uint256 tvl, uint256 depositCount, , ) = bridge.getStats();
        assertEq(tvl, amount, "TVL mismatch");
        assertGt(depositCount, 0, "Deposit count should increase");
    }

    function testFuzz_DepositRevertsZeroAmount() public {
        vm.prank(user1);
        vm.expectRevert(HyperliquidBridgeAdapter.InvalidAmount.selector);
        bridge.deposit{value: 0}(user1, 0);
    }

    function testFuzz_DepositRevertsExceedsMax(uint256 seed) public {
        uint256 amount = bound(
            seed,
            bridge.MAX_TRANSFER() + 1,
            bridge.MAX_TRANSFER() + 100 ether
        );

        vm.deal(user1, amount);
        vm.prank(user1);
        vm.expectRevert(HyperliquidBridgeAdapter.ExceedsMaxTransfer.selector);
        bridge.deposit{value: amount}(user1, 0);
    }

    // =========================================================================
    // BRIDGE ADAPTER FUZZ TESTS - VALIDATORS
    // =========================================================================

    function testFuzz_AddValidator(
        address validatorAddr,
        bytes32 pubKeyHash,
        uint256 votingPower
    ) public {
        vm.assume(validatorAddr != address(0));
        vm.assume(validatorAddr != validator1 && validatorAddr != validator2);
        votingPower = bound(votingPower, 1, 10 ** 18);

        vm.prank(operator);
        bridge.addValidator(validatorAddr, pubKeyHash, votingPower);

        (bytes32 storedPubKey, uint256 storedPower, bool isActive, ) = bridge
            .getValidator(validatorAddr);
        assertEq(storedPubKey, pubKeyHash, "PubKey mismatch");
        assertEq(storedPower, votingPower, "Voting power mismatch");
        assertTrue(isActive, "Validator should be active");
    }

    function testFuzz_AddValidatorRevertsZeroAddress() public {
        vm.prank(operator);
        vm.expectRevert(HyperliquidBridgeAdapter.InvalidValidator.selector);
        bridge.addValidator(address(0), bytes32(0), 100);
    }

    function testFuzz_RemoveValidator() public {
        address newValidator = address(0x999);

        vm.startPrank(operator);
        bridge.addValidator(newValidator, bytes32(uint256(1)), 100);
        bridge.removeValidator(newValidator);
        vm.stopPrank();

        (, , bool isActive, ) = bridge.getValidator(newValidator);
        assertFalse(isActive, "Validator should be inactive");
    }

    function testFuzz_UpdateValidatorPower(uint256 newPower) public {
        address newValidator = address(0x999);
        newPower = bound(newPower, 1, 10 ** 18);

        vm.startPrank(operator);
        bridge.addValidator(newValidator, bytes32(uint256(1)), 100);
        bridge.updateValidatorPower(newValidator, newPower);
        vm.stopPrank();

        (, uint256 storedPower, , ) = bridge.getValidator(newValidator);
        assertEq(storedPower, newPower, "Voting power should be updated");
    }

    // =========================================================================
    // BRIDGE ADAPTER FUZZ TESTS - CROSS-DOMAIN NULLIFIER
    // =========================================================================

    function testFuzz_CrossDomainNullifierRegistration(
        bytes32 hlNullifier,
        uint256 targetChain
    ) public {
        vm.assume(hlNullifier != bytes32(0));
        targetChain = bound(targetChain, 1, type(uint64).max);

        vm.prank(user1);
        bridge.registerCrossDomainNullifier(hlNullifier, targetChain);

        bytes32 pilNullifier = bridge.crossDomainNullifiers(hlNullifier);
        assertNotEq(pilNullifier, bytes32(0), "PIL nullifier should be set");

        bytes32 reverse = bridge.pilBindings(pilNullifier);
        assertEq(reverse, hlNullifier, "Reverse mapping should match");
    }

    function testFuzz_CrossDomainNullifierIdempotent(
        bytes32 hlNullifier,
        uint256 targetChain
    ) public {
        vm.assume(hlNullifier != bytes32(0));
        targetChain = bound(targetChain, 1, type(uint64).max);

        vm.prank(user1);
        bridge.registerCrossDomainNullifier(hlNullifier, targetChain);
        bytes32 pilNf1 = bridge.crossDomainNullifiers(hlNullifier);

        vm.prank(user1);
        bridge.registerCrossDomainNullifier(hlNullifier, targetChain);
        bytes32 pilNf2 = bridge.crossDomainNullifiers(hlNullifier);

        assertEq(pilNf1, pilNf2, "Should be idempotent");
    }

    // =========================================================================
    // BRIDGE ADAPTER FUZZ TESTS - CIRCUIT BREAKER
    // =========================================================================

    function test_CircuitBreakerBlocksDeposits() public {
        vm.prank(admin);
        bridge.triggerCircuitBreaker("Test");

        assertTrue(
            bridge.circuitBreakerActive(),
            "Circuit breaker should be active"
        );

        vm.prank(user1);
        vm.expectRevert(HyperliquidBridgeAdapter.CircuitBreakerOn.selector);
        bridge.deposit{value: 1 ether}(user1, 0);
    }

    function test_CircuitBreakerReset() public {
        vm.prank(admin);
        bridge.triggerCircuitBreaker("Test");

        vm.prank(admin);
        bridge.resetCircuitBreaker();

        assertFalse(
            bridge.circuitBreakerActive(),
            "Circuit breaker should be reset"
        );

        vm.prank(user1);
        bridge.deposit{value: 1 ether}(user1, 0);
    }

    // =========================================================================
    // BRIDGE ADAPTER FUZZ TESTS - RELAYER
    // =========================================================================

    function testFuzz_RelayerRegistration(address relayer) public {
        vm.assume(relayer != address(0));

        vm.prank(relayer);
        bridge.registerRelayer();

        assertTrue(
            bridge.registeredRelayers(relayer),
            "Relayer should be registered"
        );
    }

    function testFuzz_RelayerFeeUpdate(uint256 newFee) public {
        if (newFee <= bridge.MAX_RELAYER_FEE_BPS()) {
            vm.prank(admin);
            bridge.updateRelayerFee(newFee);
            assertEq(bridge.relayerFeeBps(), newFee, "Fee should be updated");
        } else {
            vm.prank(admin);
            vm.expectRevert(
                HyperliquidBridgeAdapter.InvalidRelayerFee.selector
            );
            bridge.updateRelayerFee(newFee);
        }
    }

    // =========================================================================
    // BRIDGE ADAPTER FUZZ TESTS - TOKEN MAPPING
    // =========================================================================

    function testFuzz_TokenMapping(
        uint256 hip1TokenId,
        address erc20Address
    ) public {
        vm.assume(erc20Address != address(0));

        vm.prank(operator);
        bridge.mapToken(hip1TokenId, erc20Address);

        assertEq(
            bridge.hip1ToErc20(hip1TokenId),
            erc20Address,
            "HIP1 to ERC20 mapping"
        );
        assertEq(
            bridge.erc20ToHip1(erc20Address),
            hip1TokenId,
            "ERC20 to HIP1 mapping"
        );
    }

    // =========================================================================
    // BRIDGE ADAPTER FUZZ TESTS - ACCESS CONTROL
    // =========================================================================

    function testFuzz_OnlyGuardianCanTriggerBreaker(address attacker) public {
        vm.assume(attacker != admin && attacker != guardian);
        vm.assume(!bridge.hasRole(bridge.GUARDIAN_ROLE(), attacker));

        vm.prank(attacker);
        vm.expectRevert();
        bridge.triggerCircuitBreaker("Attack");
    }

    function testFuzz_OnlyOperatorCanAddValidator(address attacker) public {
        vm.assume(attacker != admin && attacker != operator);
        vm.assume(!bridge.hasRole(bridge.OPERATOR_ROLE(), attacker));

        vm.prank(attacker);
        vm.expectRevert();
        bridge.addValidator(address(0x999), bytes32(0), 100);
    }

    // =========================================================================
    // BRIDGE ADAPTER FUZZ TESTS - STATS
    // =========================================================================

    function test_GetStats() public view {
        (
            uint256 validatorCount,
            uint64 latestHeight,
            uint256 tvl,
            uint256 depositCount,
            uint256 withdrawalCount,
            bool circuitBreaker
        ) = bridge.getStats();

        assertEq(validatorCount, 0, "Initial validator count");
        assertEq(latestHeight, 0, "Initial latest height");
        assertEq(tvl, 0, "Initial TVL");
        assertEq(depositCount, 0, "Initial deposit count");
        assertEq(withdrawalCount, 0, "Initial withdrawal count");
        assertFalse(circuitBreaker, "Circuit breaker should be off");
    }

    // =========================================================================
    // CONSTANTS TESTS
    // =========================================================================

    function test_Constants() public pure {
        assertEq(HyperliquidPrimitives.MAX_LEVERAGE, 50);
        assertEq(HyperliquidPrimitives.PRICE_DECIMALS, 6);
        assertEq(HyperliquidPrimitives.SIZE_DECIMALS, 8);
        assertEq(HyperliquidPrimitives.MAX_VALIDATORS, 100);
        assertEq(HyperliquidPrimitives.QUORUM_THRESHOLD_BPS, 6667);
        assertEq(HyperliquidPrimitives.BLOCK_TIME_MS, 200);
        assertEq(HyperliquidPrimitives.SIGNATURE_LENGTH, 65);
    }
}
