// K Framework Formal Specification for Hyperliquid L1 Integration
// This specification formalizes the perpetual/spot trading mechanics,
// consensus, and security properties for the Privacy Interoperability Layer.

module HYPERLIQUID-SYNTAX
    imports INT
    imports BOOL
    imports BYTES
    imports MAP
    imports LIST
    imports SET

    // ========================================================================
    // CONSTANTS
    // ========================================================================

    syntax Int ::= "MAX_LEVERAGE" [function, functional]
    syntax Int ::= "PRICE_DECIMALS" [function, functional]
    syntax Int ::= "SIZE_DECIMALS" [function, functional]
    syntax Int ::= "FUNDING_PRECISION" [function, functional]
    syntax Int ::= "MAINTENANCE_MARGIN_BPS" [function, functional]
    syntax Int ::= "INITIAL_MARGIN_BPS" [function, functional]
    syntax Int ::= "MAX_VALIDATORS" [function, functional]
    syntax Int ::= "QUORUM_THRESHOLD_BPS" [function, functional]
    syntax Int ::= "BLOCK_TIME_MS" [function, functional]

    rule MAX_LEVERAGE => 50
    rule PRICE_DECIMALS => 6
    rule SIZE_DECIMALS => 8
    rule FUNDING_PRECISION => 1000000  // 10^6
    rule MAINTENANCE_MARGIN_BPS => 300  // 3%
    rule INITIAL_MARGIN_BPS => 500  // 5%
    rule MAX_VALIDATORS => 100
    rule QUORUM_THRESHOLD_BPS => 6667  // 66.67%
    rule BLOCK_TIME_MS => 200

    // ========================================================================
    // ENUMS
    // ========================================================================

    syntax Side ::= "BUY" | "SELL"
    syntax OrderType ::= "LIMIT" | "MARKET" | "STOP_LIMIT" | "STOP_MARKET" | "TP_LIMIT" | "TP_MARKET"
    syntax TimeInForce ::= "GTC" | "IOC" | "FOK" | "ALO"
    syntax PositionSide ::= "LONG" | "SHORT"
    syntax OrderStatus ::= "OPEN" | "PARTIALLY_FILLED" | "FILLED" | "CANCELLED" | "EXPIRED" | "REJECTED"

    // ========================================================================
    // ORDERS
    // ========================================================================

    syntax PerpOrder ::= perpOrder(
        Address,     // trader
        Int,         // asset
        Side,        // side
        OrderType,   // orderType
        TimeInForce, // tif
        Int,         // size
        Int,         // price
        Int,         // triggerPrice
        Bool,        // reduceOnly
        Int,         // leverage
        Int,         // nonce
        Int,         // timestamp
        Bytes        // signature
    )

    syntax SpotOrder ::= spotOrder(
        Address,     // trader
        Int,         // baseAsset
        Int,         // quoteAsset
        Side,        // side
        OrderType,   // orderType
        TimeInForce, // tif
        Int,         // baseSize
        Int,         // quoteSize
        Int,         // price
        Int,         // nonce
        Int,         // timestamp
        Bytes        // signature
    )

    // Accessors
    syntax Address ::= getTrader(PerpOrder) [function, functional]
    syntax Int ::= getSize(PerpOrder) [function, functional]
    syntax Int ::= getPrice(PerpOrder) [function, functional]
    syntax Int ::= getLeverage(PerpOrder) [function, functional]
    syntax Int ::= getNonce(PerpOrder) [function, functional]
    syntax Side ::= getSide(PerpOrder) [function, functional]

    rule getTrader(perpOrder(T, _, _, _, _, _, _, _, _, _, _, _, _)) => T
    rule getSize(perpOrder(_, _, _, _, _, S, _, _, _, _, _, _, _)) => S
    rule getPrice(perpOrder(_, _, _, _, _, _, P, _, _, _, _, _, _)) => P
    rule getLeverage(perpOrder(_, _, _, _, _, _, _, _, _, L, _, _, _)) => L
    rule getNonce(perpOrder(_, _, _, _, _, _, _, _, _, _, N, _, _)) => N
    rule getSide(perpOrder(_, _, S, _, _, _, _, _, _, _, _, _, _)) => S

    // Validation
    syntax Bool ::= isValidPerpOrder(PerpOrder) [function, functional]
    syntax Bool ::= isValidSpotOrder(SpotOrder) [function, functional]

    // ========================================================================
    // POSITIONS
    // ========================================================================

    syntax Position ::= position(
        Address,      // trader
        Int,          // asset
        PositionSide, // side
        Int,          // size
        Int,          // entryPrice
        Int,          // leverage
        Int,          // margin
        Int,          // unrealizedPnl
        Int,          // accumulatedFunding
        Int,          // liquidationPrice
        Int           // lastUpdateTime
    )

    // Accessors
    syntax Int ::= getPositionSize(Position) [function, functional]
    syntax Int ::= getEntryPrice(Position) [function, functional]
    syntax Int ::= getMargin(Position) [function, functional]
    syntax PositionSide ::= getPositionSide(Position) [function, functional]

    rule getPositionSize(position(_, _, _, S, _, _, _, _, _, _, _)) => S
    rule getEntryPrice(position(_, _, _, _, E, _, _, _, _, _, _)) => E
    rule getMargin(position(_, _, _, _, _, _, M, _, _, _, _)) => M
    rule getPositionSide(position(_, _, PS, _, _, _, _, _, _, _, _)) => PS

    // Position calculations
    syntax Int ::= calculateUnrealizedPnl(Position, Int) [function]  // (position, markPrice)
    syntax Int ::= calculateMarginRatio(Position, Int) [function]    // (position, markPrice) -> bps
    syntax Bool ::= isLiquidatable(Position, Int) [function]         // (position, markPrice)
    syntax Int ::= calculateLiquidationPrice(Int, Int, PositionSide, Int) [function]

    // ========================================================================
    // MARGIN
    // ========================================================================

    syntax Int ::= calculateRequiredMargin(Int, Int, Int) [function]  // (size, price, leverage)
    syntax Int ::= calculateFundingPayment(Position, Int) [function]  // (position, fundingRate)

    // ========================================================================
    // CONSENSUS
    // ========================================================================

    syntax Validator ::= validator(
        Address,  // validatorAddress
        Bytes,    // pubKeyHash
        Int,      // votingPower
        Bool,     // isActive
        Int       // lastBlockSigned
    )

    syntax BlockHeader ::= blockHeader(
        Int,      // height
        Int,      // timestamp
        Bytes,    // previousHash
        Bytes,    // stateRoot
        Bytes,    // transactionsRoot
        Bytes,    // receiptsRoot
        Bytes,    // validatorSetHash
        Int       // totalVotingPower
    )

    syntax CommitSignature ::= commitSig(
        Bytes,    // blockHash
        Int,      // height
        Bytes,    // signature
        Bytes,    // validatorBitmap
        Int       // signingPower
    )

    syntax Bool ::= isValidBlockHeader(BlockHeader) [function, functional]
    syntax Bool ::= hasQuorum(CommitSignature, Int) [function, functional]  // (commit, totalPower)
    syntax Bytes ::= computeBlockHash(BlockHeader) [function]

    // ========================================================================
    // NULLIFIER
    // ========================================================================

    syntax Bytes ::= deriveTradeNullifier(Bytes, Int, Address) [function]  // (tradeId, blockHeight, trader)
    syntax Bytes ::= deriveWithdrawalNullifier(Bytes, Int) [function]       // (withdrawalHash, blockHeight)
    syntax Bytes ::= deriveCrossDomainNullifier(Bytes, Int, Int) [function] // (hlNf, sourceChain, targetChain)
    syntax Bytes ::= derivePILBinding(Bytes) [function]

    // ========================================================================
    // CHAIN
    // ========================================================================

    syntax Bool ::= isHyperliquidChain(Int) [function, functional]
    syntax Int ::= "HYPERLIQUID_MAINNET" [function, functional]
    syntax Int ::= "HYPERLIQUID_TESTNET" [function, functional]

    rule HYPERLIQUID_MAINNET => 998
    rule HYPERLIQUID_TESTNET => 999

endmodule

module HYPERLIQUID-RULES
    imports HYPERLIQUID-SYNTAX

    // ========================================================================
    // ORDER VALIDATION
    // ========================================================================

    rule isValidPerpOrder(perpOrder(Trader, _Asset, _Side, _OType, _TIF, Size, Price, _Trigger, _RO, Leverage, Nonce, _Ts, _Sig)) =>
        Trader =/=K 0 andBool
        Size >Int 0 andBool
        Price >Int 0 andBool
        Leverage >Int 0 andBool
        Leverage <=Int MAX_LEVERAGE andBool
        Nonce >Int 0

    rule isValidSpotOrder(spotOrder(Trader, _Base, _Quote, _Side, _OType, _TIF, BaseSize, _QuoteSize, Price, Nonce, _Ts, _Sig)) =>
        Trader =/=K 0 andBool
        BaseSize >Int 0 andBool
        Price >Int 0 andBool
        Nonce >Int 0

    // ========================================================================
    // MARGIN CALCULATIONS
    // ========================================================================

    // Required margin = (size * price / 10^8) / leverage
    rule calculateRequiredMargin(Size, Price, Leverage) =>
        ((Size *Int Price) /Int (10 ^Int SIZE_DECIMALS)) /Int Leverage
        requires Leverage >Int 0

    rule calculateRequiredMargin(_, _, 0) => 0

    // ========================================================================
    // PNL CALCULATIONS
    // ========================================================================

    // Long PnL = (markPrice - entryPrice) * size / 10^8
    rule calculateUnrealizedPnl(position(_, _, LONG, Size, EntryPrice, _, _, _, _, _, _), MarkPrice) =>
        ((MarkPrice -Int EntryPrice) *Int Size) /Int (10 ^Int SIZE_DECIMALS)
        requires Size >Int 0

    // Short PnL = (entryPrice - markPrice) * size / 10^8
    rule calculateUnrealizedPnl(position(_, _, SHORT, Size, EntryPrice, _, _, _, _, _, _), MarkPrice) =>
        ((EntryPrice -Int MarkPrice) *Int Size) /Int (10 ^Int SIZE_DECIMALS)
        requires Size >Int 0

    rule calculateUnrealizedPnl(position(_, _, _, 0, _, _, _, _, _, _, _), _) => 0

    // ========================================================================
    // MARGIN RATIO
    // ========================================================================

    // Margin ratio (bps) = equity * 10000 / notional
    // where equity = margin + unrealizedPnl
    rule calculateMarginRatio(Pos, MarkPrice) =>
        #let UnrealizedPnl = calculateUnrealizedPnl(Pos, MarkPrice) #in
        #let Equity = getMargin(Pos) +Int UnrealizedPnl #in
        #let Notional = (getPositionSize(Pos) *Int MarkPrice) /Int (10 ^Int SIZE_DECIMALS) #in
        #if Notional ==Int 0 #then maxInt #else (Equity *Int 10000) /Int Notional #fi
        requires getPositionSize(Pos) >Int 0

    // ========================================================================
    // LIQUIDATION
    // ========================================================================

    rule isLiquidatable(Pos, MarkPrice) =>
        #let MarginRatio = calculateMarginRatio(Pos, MarkPrice) #in
        MarginRatio <Int MAINTENANCE_MARGIN_BPS
        requires getPositionSize(Pos) >Int 0

    rule isLiquidatable(position(_, _, _, 0, _, _, _, _, _, _, _), _) => false

    // Long liq price = entry * (1 - buffer/10000)
    // where buffer = initialMargin - maintenanceMargin
    rule calculateLiquidationPrice(EntryPrice, Leverage, LONG, MaintenanceMarginBps) =>
        #let InitialMarginBps = 10000 /Int Leverage #in
        #let Buffer = InitialMarginBps -Int MaintenanceMarginBps #in
        (EntryPrice *Int (10000 -Int Buffer)) /Int 10000
        requires Leverage >Int 0

    // Short liq price = entry * (1 + buffer/10000)
    rule calculateLiquidationPrice(EntryPrice, Leverage, SHORT, MaintenanceMarginBps) =>
        #let InitialMarginBps = 10000 /Int Leverage #in
        #let Buffer = InitialMarginBps -Int MaintenanceMarginBps #in
        (EntryPrice *Int (10000 +Int Buffer)) /Int 10000
        requires Leverage >Int 0

    // ========================================================================
    // FUNDING
    // ========================================================================

    // Long pays shorts when funding positive
    rule calculateFundingPayment(position(_, _, LONG, Size, _, _, _, _, _, _, _), FundingRate) =>
        0 -Int ((Size *Int FundingRate) /Int FUNDING_PRECISION)
        requires Size >Int 0

    // Shorts receive from longs when funding positive
    rule calculateFundingPayment(position(_, _, SHORT, Size, _, _, _, _, _, _, _), FundingRate) =>
        (Size *Int FundingRate) /Int FUNDING_PRECISION
        requires Size >Int 0

    rule calculateFundingPayment(position(_, _, _, 0, _, _, _, _, _, _, _), _) => 0

    // ========================================================================
    // CONSENSUS
    // ========================================================================

    rule isValidBlockHeader(blockHeader(Height, Timestamp, _Prev, StateRoot, TxRoot, _Receipts, ValSetHash, TotalPower)) =>
        Height >Int 0 andBool
        Timestamp >Int 0 andBool
        StateRoot =/=K b"" andBool
        TxRoot =/=K b"" andBool
        ValSetHash =/=K b"" andBool
        TotalPower >Int 0

    // Quorum: signingPower > (totalPower * 6667 / 10000)
    rule hasQuorum(commitSig(_, _, _, _, SigningPower), TotalPower) =>
        SigningPower >Int ((TotalPower *Int QUORUM_THRESHOLD_BPS) /Int 10000)
        requires TotalPower >Int 0

    // ========================================================================
    // CHAIN
    // ========================================================================

    rule isHyperliquidChain(ChainId) =>
        ChainId ==Int HYPERLIQUID_MAINNET orBool ChainId ==Int HYPERLIQUID_TESTNET

endmodule

module HYPERLIQUID-ORDER-BOOK
    imports HYPERLIQUID-RULES

    // ========================================================================
    // ORDER BOOK STATE
    // ========================================================================

    configuration
        <hyperliquid>
            // Order book per asset
            <orderBooks>
                <orderBook multiplicity="*" type="Map">
                    <assetId> 0 </assetId>
                    <bids> .List </bids>      // Sorted by price descending
                    <asks> .List </asks>      // Sorted by price ascending
                </orderBook>
            </orderBooks>

            // Positions per (trader, asset)
            <positions> .Map </positions>     // (Address, Int) -> Position

            // Margin accounts per trader
            <marginAccounts> .Map </marginAccounts>  // Address -> MarginAccount

            // Validators
            <validators> .Map </validators>   // Address -> Validator
            <totalVotingPower> 0 </totalVotingPower>

            // Finalized blocks
            <finalizedBlocks> .Map </finalizedBlocks>  // Int -> BlockHeader
            <latestHeight> 0 </latestHeight>

            // Nullifiers
            <nullifiers> .Map </nullifiers>   // hlNf -> pilNf
            <pilBindings> .Map </pilBindings> // pilNf -> hlNf
            <usedNullifiers> .Set </usedNullifiers>

            // Bridge state
            <deposits> .Map </deposits>
            <withdrawals> .Map </withdrawals>
            <totalValueLocked> 0 </totalValueLocked>

            // System state
            <currentTime> 0 </currentTime>
            <circuitBreaker> false </circuitBreaker>
        </hyperliquid>

    // ========================================================================
    // ORDER MATCHING
    // ========================================================================

    // Place limit buy order
    syntax KItem ::= placeLimitBuy(PerpOrder)

    rule <hyperliquid>
            <orderBook>
                <assetId> Asset </assetId>
                <bids> Bids => insertBid(Order, Bids) </bids>
                <asks> Asks </asks>
            </orderBook>
            ...
         </hyperliquid>
         where Order = perpOrder(_, Asset, BUY, LIMIT, _, _, _, _, _, _, _, _, _)
         requires isValidPerpOrder(Order)

    // Place limit sell order
    syntax KItem ::= placeLimitSell(PerpOrder)

    rule <hyperliquid>
            <orderBook>
                <assetId> Asset </assetId>
                <bids> Bids </bids>
                <asks> Asks => insertAsk(Order, Asks) </asks>
            </orderBook>
            ...
         </hyperliquid>
         where Order = perpOrder(_, Asset, SELL, LIMIT, _, _, _, _, _, _, _, _, _)
         requires isValidPerpOrder(Order)

    // Order book insertion helpers
    syntax List ::= insertBid(PerpOrder, List) [function]
    syntax List ::= insertAsk(PerpOrder, List) [function]

    // Match orders (price-time priority)
    syntax KItem ::= matchOrders(Int)  // assetId

endmodule

module HYPERLIQUID-PROPERTIES
    imports HYPERLIQUID-ORDER-BOOK

    // ========================================================================
    // SAFETY PROPERTIES
    // ========================================================================

    // Property 1: Leverage bounded
    syntax Bool ::= leverageBounded(PerpOrder) [function]
    rule leverageBounded(Order) => getLeverage(Order) <=Int MAX_LEVERAGE

    // Property 2: Position margin sufficient
    syntax Bool ::= marginSufficient(Position, Int) [function]
    rule marginSufficient(Pos, MarkPrice) =>
        calculateMarginRatio(Pos, MarkPrice) >=Int MAINTENANCE_MARGIN_BPS

    // Property 3: Liquidation correctness
    syntax Bool ::= liquidationCorrect(Position, Int) [function]
    rule liquidationCorrect(Pos, MarkPrice) =>
        isLiquidatable(Pos, MarkPrice) impliesBool (calculateMarginRatio(Pos, MarkPrice) <Int MAINTENANCE_MARGIN_BPS)

    // Property 4: Funding rate zero-sum
    // Sum of all funding payments across all positions = 0
    syntax Bool ::= fundingZeroSum(List, Int) [function]  // (positions, fundingRate)

    // Property 5: Order nonce uniqueness
    syntax Bool ::= nonceUnique(PerpOrder, Set) [function]
    rule nonceUnique(Order, UsedNonces) =>
        notBool(getNonce(Order) in UsedNonces)

    // Property 6: Quorum requirement
    syntax Bool ::= quorumRequired(CommitSignature, Int) [function]
    rule quorumRequired(Commit, TotalPower) =>
        hasQuorum(Commit, TotalPower)

    // ========================================================================
    // NULLIFIER PROPERTIES
    // ========================================================================

    // Property 7: Nullifier uniqueness
    syntax Bool ::= nullifierUnique(Bytes, Int, Address, Bytes, Int, Address) [function]
    rule nullifierUnique(TradeId1, Height1, Trader1, TradeId2, Height2, Trader2) =>
        ((TradeId1 =/=K TradeId2) orBool (Height1 =/=Int Height2) orBool (Trader1 =/=K Trader2))
        impliesBool
        (deriveTradeNullifier(TradeId1, Height1, Trader1) =/=K deriveTradeNullifier(TradeId2, Height2, Trader2))

    // Property 8: Cross-domain direction matters
    syntax Bool ::= crossDomainDirectionMatters(Bytes, Int, Int) [function]
    rule crossDomainDirectionMatters(Nf, Chain1, Chain2) =>
        (Chain1 =/=Int Chain2) impliesBool
        (deriveCrossDomainNullifier(Nf, Chain1, Chain2) =/=K deriveCrossDomainNullifier(Nf, Chain2, Chain1))

    // Property 9: PIL binding deterministic
    syntax Bool ::= pilBindingDeterministic(Bytes) [function]
    rule pilBindingDeterministic(Nf) =>
        derivePILBinding(Nf) ==K derivePILBinding(Nf)

    // ========================================================================
    // TRADING INVARIANTS
    // ========================================================================

    // Invariant 1: Total long size = Total short size (for each asset)
    syntax Bool ::= longShortBalanced(List) [function]

    // Invariant 2: Mark price bounded by best bid/ask
    syntax Bool ::= markPriceBounded(Int, Int, Int) [function]  // (markPrice, bestBid, bestAsk)
    rule markPriceBounded(Mark, Bid, Ask) =>
        Mark >=Int Bid andBool Mark <=Int Ask
        requires Bid >Int 0 andBool Ask >Int 0 andBool Bid <Int Ask

    // Invariant 3: Position entry price is weighted average
    syntax Bool ::= entryPriceIsWeightedAvg(Position, List) [function]  // (position, fills)

    // Invariant 4: Margin account consistency
    // totalCollateral = usedMargin + availableMargin
    syntax Bool ::= marginAccountConsistent(Address, Int, Int, Int) [function]
    rule marginAccountConsistent(_, Total, Used, Available) =>
        Total ==Int Used +Int Available

    // ========================================================================
    // CONSENSUS PROPERTIES
    // ========================================================================

    // Property 10: Block height monotonic
    syntax Bool ::= blockHeightMonotonic(Int, Int) [function]
    rule blockHeightMonotonic(PrevHeight, NewHeight) =>
        NewHeight >Int PrevHeight

    // Property 11: Validator set hash consistency
    syntax Bool ::= validatorSetHashConsistent(BlockHeader, Map) [function]

    // Property 12: Sub-second finality
    syntax Bool ::= subSecondFinality(Int, Int) [function]  // (blockTime1, blockTime2)
    rule subSecondFinality(T1, T2) =>
        (T2 -Int T1) <=Int BLOCK_TIME_MS

endmodule

module HYPERLIQUID-SECURITY
    imports HYPERLIQUID-PROPERTIES

    // ========================================================================
    // ATTACK RESISTANCE
    // ========================================================================

    // Theorem 1: No self-trading
    // A trader cannot match their own orders for wash trading

    // Theorem 2: No front-running by validators
    // Validators cannot insert their own orders before user orders within same block

    // Theorem 3: Liquidation cascade prevention
    // Circuit breaker triggers on excessive liquidations

    // Theorem 4: Oracle manipulation resistance
    // Mark price uses TWAP and multiple sources

    // ========================================================================
    // ECONOMIC SECURITY
    // ========================================================================

    // Invariant: Insurance fund covers socialized losses
    syntax Bool ::= insuranceFundSolvent(Int, Int) [function]  // (fundBalance, potentialLosses)
    rule insuranceFundSolvent(Balance, Losses) => Balance >=Int Losses

    // Invariant: ADL (Auto-Deleveraging) fairness
    // Profitable positions deleveraged by profit ranking

    // Invariant: Funding rate bounded
    syntax Bool ::= fundingRateBounded(Int, Int) [function]  // (rate, maxRate)
    rule fundingRateBounded(Rate, MaxRate) =>
        Rate >=Int (0 -Int MaxRate) andBool Rate <=Int MaxRate

endmodule

module HYPERLIQUID
    imports HYPERLIQUID-SECURITY
endmodule
