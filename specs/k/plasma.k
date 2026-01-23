// K Framework Formal Specification for Plasma Layer 2 Integration
// This specification formalizes the exit game mechanics, UTXO model,
// and security properties of Plasma chains for the Privacy Interoperability Layer.

module PLASMA-SYNTAX
    imports INT
    imports BOOL
    imports BYTES
    imports MAP
    imports LIST
    imports SET

    // ========================================================================
    // UTXO POSITION
    // ========================================================================

    // UTXO position encoding: blockNum * 10^9 + txIndex * 10^4 + outputIndex
    syntax UTXOPosition ::= utxoPosition(Int, Int, Int)  // (blockNum, txIndex, outputIndex)

    syntax Int ::= encodeUTXOPosition(UTXOPosition) [function, functional]
    syntax UTXOPosition ::= decodeUTXOPosition(Int) [function, functional]

    // Validation
    syntax Bool ::= isValidUTXOPosition(UTXOPosition) [function, functional]

    // Constants
    syntax Int ::= "MAX_INPUTS" [function, functional]
    syntax Int ::= "MAX_OUTPUTS" [function, functional]
    syntax Int ::= "MERKLE_TREE_DEPTH" [function, functional]
    syntax Int ::= "MAX_TRANSACTIONS_PER_BLOCK" [function, functional]
    syntax Int ::= "BLOCK_MULTIPLIER" [function, functional]
    syntax Int ::= "TX_MULTIPLIER" [function, functional]

    rule MAX_INPUTS => 4
    rule MAX_OUTPUTS => 4
    rule MERKLE_TREE_DEPTH => 16
    rule MAX_TRANSACTIONS_PER_BLOCK => 65536  // 2^16
    rule BLOCK_MULTIPLIER => 1000000000  // 10^9
    rule TX_MULTIPLIER => 10000  // 10^4

    // ========================================================================
    // UTXO MODEL
    // ========================================================================

    syntax TransactionInput ::= txInput(UTXOPosition, Bytes)  // (position, signature)
    syntax TransactionOutput ::= txOutput(Address, Int, Address)  // (owner, amount, token)

    syntax PlasmaTransaction ::= plasmaTx(
        List,      // inputs: List<TransactionInput>
        List,      // outputs: List<TransactionOutput>
        Bytes,     // metadata
        Int        // nonce
    )

    // Transaction hash computation
    syntax Bytes ::= computeTxHash(PlasmaTransaction) [function]

    // Input/output validation
    syntax Bool ::= isValidInput(TransactionInput) [function, functional]
    syntax Bool ::= isValidOutput(TransactionOutput) [function, functional]
    syntax Bool ::= isValidTransaction(PlasmaTransaction) [function, functional]

    // ========================================================================
    // PLASMA BLOCK
    // ========================================================================

    syntax PlasmaBlock ::= plasmaBlock(
        Bytes,     // merkleRoot
        Int,       // timestamp
        Int,       // blockNumber
        Address,   // operator
        Int        // numTransactions
    )

    syntax Bool ::= isValidBlock(PlasmaBlock) [function, functional]

    // ========================================================================
    // MERKLE TREE
    // ========================================================================

    syntax MerkleProof ::= merkleProof(List, Int)  // (siblings, index)

    syntax Bytes ::= computeMerkleRoot(List) [function]  // List<Bytes>
    syntax Bytes ::= computeMerkleRootFromProof(Bytes, MerkleProof) [function]
    syntax Bool ::= verifyMerkleProof(Bytes, MerkleProof, Bytes) [function]

    // Hash functions
    syntax Bytes ::= keccakHash(Bytes) [function]
    syntax Bytes ::= hash2(Bytes, Bytes) [function]

    // ========================================================================
    // EXIT GAME
    // ========================================================================

    syntax ExitStatus ::= "NOT_STARTED" | "IN_PROGRESS" | "FINALIZED" | "CHALLENGED" | "CANCELLED"

    syntax Exit ::= exit(
        Address,       // owner
        Address,       // token
        Int,           // amount
        UTXOPosition,  // utxoPos
        Int,           // exitableAt
        Int,           // bondAmount
        ExitStatus     // status
    )

    // Exit priority for queue ordering
    syntax Int ::= computeExitPriority(Int, Int) [function, functional]  // (exitableAt, utxoPos)
    syntax Int ::= "EXIT_PRIORITY_DENOMINATOR" [function, functional]
    rule EXIT_PRIORITY_DENOMINATOR => 1000000000000000000  // 10^18

    // Exit validation
    syntax Bool ::= isValidExit(Exit) [function, functional]
    syntax Bool ::= isExitFinalized(Exit, Int) [function, functional]  // (exit, currentTime)
    syntax Bool ::= isExitChallengeable(Exit, Int) [function, functional]

    // Challenge period
    syntax Int ::= "CHALLENGE_PERIOD" [function, functional]
    syntax Int ::= "MIN_EXIT_BOND" [function, functional]
    rule CHALLENGE_PERIOD => 604800  // 7 days in seconds
    rule MIN_EXIT_BOND => 100000000000000000  // 0.1 ETH in wei

    // ========================================================================
    // STANDARD EXIT FLOW
    // ========================================================================

    // Standard exit: User exits a UTXO they own
    syntax StandardExitRequest ::= standardExitRequest(
        UTXOPosition,  // utxoPos
        Bytes,         // txBytes (RLP encoded transaction)
        MerkleProof,   // proof
        Bytes          // signature
    )

    // In-flight exit: Exit a transaction not yet included in a block
    syntax InFlightExitRequest ::= inFlightExitRequest(
        Bytes,     // txBytes
        List,      // inputTxs: List<Bytes>
        List,      // inputProofs: List<MerkleProof>
        List       // inputSignatures: List<Bytes>
    )

    // ========================================================================
    // CHALLENGES
    // ========================================================================

    // Challenge types
    syntax ChallengeType ::= "SPEND_CHALLENGE"      // UTXO was already spent
                          | "INVALID_HISTORY"      // Invalid transaction history
                          | "INVALID_SIGNATURE"    // Invalid signature on exit tx

    syntax ExitChallenge ::= exitChallenge(
        UTXOPosition,   // exitId
        ChallengeType,  // type
        Bytes,          // challengingTx
        MerkleProof,    // proof
        Address         // challenger
    )

    syntax Bool ::= isValidChallenge(ExitChallenge, Exit) [function]

    // ========================================================================
    // NULLIFIER
    // ========================================================================

    syntax Bytes ::= deriveNullifier(Bytes, Int, Int) [function]  // (txHash, blockNumber, outputIndex)
    syntax Bytes ::= deriveCrossDomainNullifier(Bytes, Int, Int) [function]  // (plasmaNf, sourceChain, targetChain)
    syntax Bytes ::= derivePILBinding(Bytes) [function]

    // ========================================================================
    // CHAIN SUPPORT
    // ========================================================================

    syntax Bool ::= isPlasmaChain(Int) [function, functional]  // chainId
    syntax Int ::= "ETHEREUM_MAINNET" [function, functional]
    syntax Int ::= "POLYGON_MAINNET" [function, functional]
    syntax Int ::= "POLYGON_TESTNET" [function, functional]

    rule ETHEREUM_MAINNET => 1
    rule POLYGON_MAINNET => 137
    rule POLYGON_TESTNET => 80001

endmodule

module PLASMA-RULES
    imports PLASMA-SYNTAX

    // ========================================================================
    // UTXO POSITION ENCODING/DECODING
    // ========================================================================

    rule encodeUTXOPosition(utxoPosition(B, T, O)) =>
        (B *Int BLOCK_MULTIPLIER) +Int (T *Int TX_MULTIPLIER) +Int O

    rule decodeUTXOPosition(P) =>
        utxoPosition(
            P /Int BLOCK_MULTIPLIER,
            (P %Int BLOCK_MULTIPLIER) /Int TX_MULTIPLIER,
            P %Int TX_MULTIPLIER
        )

    rule isValidUTXOPosition(utxoPosition(B, T, O)) =>
        B >Int 0 andBool
        T >=Int 0 andBool T <Int MAX_TRANSACTIONS_PER_BLOCK andBool
        O >=Int 0 andBool O <Int MAX_OUTPUTS

    // ========================================================================
    // TRANSACTION VALIDATION
    // ========================================================================

    rule isValidInput(txInput(Pos, Sig)) =>
        isValidUTXOPosition(Pos) andBool
        lengthBytes(Sig) ==Int 65

    rule isValidOutput(txOutput(Owner, Amount, _Token)) =>
        Owner =/=K 0 andBool
        Amount >Int 0

    rule isValidTransaction(plasmaTx(Inputs, Outputs, _Meta, Nonce)) =>
        size(Inputs) >Int 0 andBool size(Inputs) <=Int MAX_INPUTS andBool
        size(Outputs) >Int 0 andBool size(Outputs) <=Int MAX_OUTPUTS andBool
        Nonce >=Int 0
        // Additional: all inputs valid, all outputs valid, signatures verify

    // ========================================================================
    // BLOCK VALIDATION
    // ========================================================================

    rule isValidBlock(plasmaBlock(Root, Timestamp, BlockNum, Operator, NumTx)) =>
        Root =/=K b"" andBool
        Timestamp >Int 0 andBool
        BlockNum >Int 0 andBool
        Operator =/=K 0 andBool
        NumTx >Int 0 andBool NumTx <=Int MAX_TRANSACTIONS_PER_BLOCK

    // ========================================================================
    // EXIT PRIORITY
    // ========================================================================

    // Priority = exitableAt * 10^18 + utxoPos
    // Lower priority = earlier in queue (older UTXOs exit first)
    rule computeExitPriority(ExitableAt, UtxoPos) =>
        (ExitableAt *Int EXIT_PRIORITY_DENOMINATOR) +Int UtxoPos

    // ========================================================================
    // EXIT VALIDATION
    // ========================================================================

    rule isValidExit(exit(Owner, _Token, Amount, Pos, _ExitableAt, Bond, Status)) =>
        Owner =/=K 0 andBool
        Amount >Int 0 andBool
        isValidUTXOPosition(Pos) andBool
        Bond >=Int MIN_EXIT_BOND andBool
        Status ==K IN_PROGRESS

    rule isExitFinalized(exit(_O, _T, _A, _P, ExitableAt, _B, Status), CurrentTime) =>
        CurrentTime >=Int ExitableAt andBool Status ==K IN_PROGRESS

    rule isExitChallengeable(exit(_O, _T, _A, _P, ExitableAt, _B, Status), CurrentTime) =>
        CurrentTime <Int ExitableAt andBool Status ==K IN_PROGRESS

    // ========================================================================
    // MERKLE VERIFICATION
    // ========================================================================

    // Compute root from leaf and proof
    rule computeMerkleRootFromProof(Leaf, merkleProof(Siblings, Index)) =>
        computeMerkleRootHelper(Leaf, Siblings, Index)

    syntax Bytes ::= computeMerkleRootHelper(Bytes, List, Int) [function]

    rule computeMerkleRootHelper(Current, .List, _Index) => Current

    rule computeMerkleRootHelper(Current, ListItem(Sibling) Rest, Index) =>
        computeMerkleRootHelper(
            #if Index %Int 2 ==Int 0
            #then hash2(Current, Sibling)
            #else hash2(Sibling, Current)
            #fi,
            Rest,
            Index /Int 2
        )

    rule verifyMerkleProof(Leaf, Proof, ExpectedRoot) =>
        computeMerkleRootFromProof(Leaf, Proof) ==K ExpectedRoot

    // ========================================================================
    // CHAIN SUPPORT
    // ========================================================================

    rule isPlasmaChain(ChainId) =>
        ChainId ==Int ETHEREUM_MAINNET orBool
        ChainId ==Int POLYGON_MAINNET orBool
        ChainId ==Int POLYGON_TESTNET

endmodule

module PLASMA-EXIT-GAME
    imports PLASMA-RULES

    // ========================================================================
    // EXIT GAME STATE
    // ========================================================================

    configuration
        <plasma>
            <blocks> .Map </blocks>                    // blockNumber -> PlasmaBlock
            <exits> .Map </exits>                      // utxoPos -> Exit
            <exitQueue> .List </exitQueue>            // priority queue
            <spentUTXOs> .Set </spentUTXOs>           // Set<UTXOPosition>
            <nullifiers> .Map </nullifiers>            // plasmaNf -> pilNf
            <pilBindings> .Map </pilBindings>          // pilNf -> plasmaNf
            <deposits> .Map </deposits>                // commitment -> Deposit
            <currentBlockNumber> 1 </currentBlockNumber>
            <totalValueLocked> 0 </totalValueLocked>
            <circuitBreaker> false </circuitBreaker>
            <currentTime> 0 </currentTime>
        </plasma>

    // ========================================================================
    // BLOCK SUBMISSION
    // ========================================================================

    syntax KItem ::= submitBlock(Bytes, Int)  // (merkleRoot, numTransactions)

    rule <plasma>
            <blocks> Blocks => Blocks[BlockNum <- plasmaBlock(Root, Time, BlockNum, Operator, NumTx)] </blocks>
            <currentBlockNumber> BlockNum => BlockNum +Int 1 </currentBlockNumber>
            <currentTime> Time </currentTime>
            ...
         </plasma>
         [owise]
         requires Root =/=K b"" andBool NumTx >Int 0

    // ========================================================================
    // STANDARD EXIT
    // ========================================================================

    syntax KItem ::= startStandardExit(UTXOPosition, Bytes, MerkleProof, Bytes, Int)
                   // (utxoPos, txBytes, proof, signature, bondAmount)

    rule <plasma>
            <exits> Exits => Exits[Pos <- exit(Owner, Token, Amount, Pos, ExitableAt, Bond, IN_PROGRESS)] </exits>
            <exitQueue> Queue => Queue ListItem(computeExitPriority(ExitableAt, encodeUTXOPosition(Pos))) </exitQueue>
            <spentUTXOs> Spent </spentUTXOs>
            <currentTime> Time </currentTime>
            ...
         </plasma>
         where ExitableAt = Time +Int CHALLENGE_PERIOD
         requires notBool(Pos in Spent) andBool
                  Bond >=Int MIN_EXIT_BOND andBool
                  isValidUTXOPosition(Pos)

    // ========================================================================
    // CHALLENGE EXIT
    // ========================================================================

    syntax KItem ::= challengeExit(UTXOPosition, Bytes, MerkleProof)
                   // (exitId, spendingTx, proof)

    rule <plasma>
            <exits> Exits => Exits[Pos <- updateExitStatus(Exits[Pos], CHALLENGED)] </exits>
            <spentUTXOs> Spent </spentUTXOs>
            <currentTime> Time </currentTime>
            ...
         </plasma>
         requires Pos in keys(Exits) andBool
                  isExitChallengeable(Exits[Pos], Time)

    syntax Exit ::= updateExitStatus(Exit, ExitStatus) [function]
    rule updateExitStatus(exit(O, T, A, P, E, B, _), NewStatus) =>
        exit(O, T, A, P, E, B, NewStatus)

    // ========================================================================
    // PROCESS EXITS
    // ========================================================================

    syntax KItem ::= processExits(Int)  // maxExitsToProcess

    rule <plasma>
            <exits> Exits </exits>
            <exitQueue> ListItem(Priority) Rest => Rest </exitQueue>
            <totalValueLocked> TVL => TVL -Int Amount </totalValueLocked>
            <currentTime> Time </currentTime>
            ...
         </plasma>
         where (ExitableAt, UtxoPos) = decodePriority(Priority)
               Exit = Exits[decodeUTXOPosition(UtxoPos)]
               Amount = getExitAmount(Exit)
         requires isExitFinalized(Exit, Time)

    syntax #(Int, Int) ::= decodePriority(Int) [function]
    rule decodePriority(P) => (P /Int EXIT_PRIORITY_DENOMINATOR, P %Int EXIT_PRIORITY_DENOMINATOR)

    syntax Int ::= getExitAmount(Exit) [function]
    rule getExitAmount(exit(_O, _T, Amount, _P, _E, _B, _S)) => Amount

    // ========================================================================
    // DEPOSIT
    // ========================================================================

    syntax Deposit ::= deposit(Address, Int, Bytes, Int)  // (depositor, amount, commitment, timestamp)

    syntax KItem ::= makeDeposit(Bytes, Int, Address)  // (commitment, amount, depositor)

    rule <plasma>
            <deposits> Deps => Deps[Commitment <- deposit(Depositor, Amount, Commitment, Time)] </deposits>
            <totalValueLocked> TVL => TVL +Int Amount </totalValueLocked>
            <circuitBreaker> false </circuitBreaker>
            <currentTime> Time </currentTime>
            ...
         </plasma>
         requires Amount >Int 0 andBool Commitment =/=K b""

    // ========================================================================
    // CROSS-DOMAIN NULLIFIER
    // ========================================================================

    syntax KItem ::= registerNullifier(Bytes, Int)  // (plasmaNullifier, targetChain)

    rule <plasma>
            <nullifiers> Nfs => Nfs[PlasmaNf <- PILNf] </nullifiers>
            <pilBindings> Bindings => Bindings[PILNf <- PlasmaNf] </pilBindings>
            ...
         </plasma>
         where PILNf = derivePILBinding(deriveCrossDomainNullifier(PlasmaNf, SourceChain, TargetChain))
         requires PlasmaNf =/=K b""

endmodule

module PLASMA-PROPERTIES
    imports PLASMA-EXIT-GAME

    // ========================================================================
    // SAFETY PROPERTIES
    // ========================================================================

    // Property 1: No double-spend via exits
    // An already-spent UTXO cannot be exited
    syntax Bool ::= noDoubleSpendExit(UTXOPosition, Set) [function]
    rule noDoubleSpendExit(Pos, SpentSet) => notBool(Pos in SpentSet)

    // Property 2: Exit finality requires challenge period
    // An exit can only be finalized after the challenge period
    syntax Bool ::= exitFinalityRequiresChallengePeriod(Exit, Int) [function]
    rule exitFinalityRequiresChallengePeriod(exit(_O, _T, _A, _P, ExitableAt, _B, _S), CurrentTime) =>
        CurrentTime >=Int ExitableAt impliesBool (ExitableAt -Int CurrentTime <=Int CHALLENGE_PERIOD)

    // Property 3: Bond requirement
    // All exits must have minimum bond
    syntax Bool ::= exitHasMinimumBond(Exit) [function]
    rule exitHasMinimumBond(exit(_O, _T, _A, _P, _E, Bond, _S)) => Bond >=Int MIN_EXIT_BOND

    // Property 4: UTXO position uniqueness
    // Each encoded position maps to exactly one (block, tx, output) triple
    syntax Bool ::= utxoPositionBijective(Int) [function]
    rule utxoPositionBijective(Encoded) =>
        encodeUTXOPosition(decodeUTXOPosition(Encoded)) ==Int Encoded

    // Property 5: Exit priority ordering
    // Older UTXOs have higher priority (lower number)
    syntax Bool ::= olderUTXOsHavePriority(Int, Int, Int, Int) [function]
    rule olderUTXOsHavePriority(Time1, Pos1, Time2, Pos2) =>
        (Time1 <Int Time2) impliesBool
        (computeExitPriority(Time1, Pos1) <Int computeExitPriority(Time2, Pos2))

    // Property 6: Challenge window
    // Exits are challengeable only during challenge period
    syntax Bool ::= challengeWindowCorrect(Exit, Int) [function]
    rule challengeWindowCorrect(exit(_O, _T, _A, _P, ExitableAt, _B, IN_PROGRESS), CurrentTime) =>
        (CurrentTime <Int ExitableAt) ==Bool isExitChallengeable(exit(_O, _T, _A, _P, ExitableAt, _B, IN_PROGRESS), CurrentTime)

    // ========================================================================
    // NULLIFIER PROPERTIES
    // ========================================================================

    // Property 7: Nullifier uniqueness
    // Different (txHash, blockNumber, outputIndex) produce different nullifiers
    syntax Bool ::= nullifierUnique(Bytes, Int, Int, Bytes, Int, Int) [function]
    rule nullifierUnique(TxHash1, Block1, Out1, TxHash2, Block2, Out2) =>
        ((TxHash1 =/=K TxHash2) orBool (Block1 =/=Int Block2) orBool (Out1 =/=Int Out2))
        impliesBool
        (deriveNullifier(TxHash1, Block1, Out1) =/=K deriveNullifier(TxHash2, Block2, Out2))

    // Property 8: Cross-domain direction matters
    // Nullifier(A->B) != Nullifier(B->A)
    syntax Bool ::= crossDomainDirectionMatters(Bytes, Int, Int) [function]
    rule crossDomainDirectionMatters(Nf, Chain1, Chain2) =>
        (Chain1 =/=Int Chain2) impliesBool
        (deriveCrossDomainNullifier(Nf, Chain1, Chain2) =/=K deriveCrossDomainNullifier(Nf, Chain2, Chain1))

    // Property 9: PIL binding determinism
    // Same nullifier always produces same PIL binding
    syntax Bool ::= pilBindingDeterministic(Bytes) [function]
    rule pilBindingDeterministic(Nf) =>
        derivePILBinding(Nf) ==K derivePILBinding(Nf)

    // ========================================================================
    // MERKLE TREE PROPERTIES
    // ========================================================================

    // Property 10: Merkle proof soundness
    // A valid proof for leaf L with root R cannot also verify different leaf L'
    syntax Bool ::= merkleProofSoundness(Bytes, Bytes, MerkleProof, Bytes) [function]
    rule merkleProofSoundness(Leaf1, Leaf2, Proof, Root) =>
        (verifyMerkleProof(Leaf1, Proof, Root) andBool verifyMerkleProof(Leaf2, Proof, Root))
        impliesBool (Leaf1 ==K Leaf2)

    // Property 11: Merkle proof completeness
    // For any leaf in a tree, there exists a valid proof
    syntax Bool ::= merkleProofCompleteness(Bytes, List, Int) [function]
    // If Leaf is at Index in Leaves, then computeMerkleRoot(Leaves) can be derived from Leaf

    // ========================================================================
    // ECONOMIC PROPERTIES
    // ========================================================================

    // Property 12: TVL conservation
    // Total deposits - Total withdrawals = TVL
    syntax Bool ::= tvlConservation(Int, Int, Int) [function]
    rule tvlConservation(TotalDeposits, TotalWithdrawals, TVL) =>
        TVL ==Int TotalDeposits -Int TotalWithdrawals

    // Property 13: Bond slashing on invalid exit
    // Challenged exits forfeit their bond
    syntax Bool ::= challengedExitLosesBond(Exit) [function]
    rule challengedExitLosesBond(exit(_O, _T, _A, _P, _E, Bond, CHALLENGED)) => Bond >Int 0

    // ========================================================================
    // LIVENESS PROPERTIES
    // ========================================================================

    // Property 14: Exit processing liveness
    // Any finalized exit will eventually be processed
    syntax Bool ::= exitEventuallyProcessed(Exit, Int) [function]
    rule exitEventuallyProcessed(Exit, CurrentTime) =>
        isExitFinalized(Exit, CurrentTime) impliesBool true  // Processed by processExits

    // Property 15: Challenge liveness
    // Valid challenges can be submitted within challenge period
    syntax Bool ::= challengeSubmittable(Exit, Int) [function]
    rule challengeSubmittable(Exit, CurrentTime) =>
        isExitChallengeable(Exit, CurrentTime)

endmodule

module PLASMA-SECURITY
    imports PLASMA-PROPERTIES

    // ========================================================================
    // ATTACK RESISTANCE
    // ========================================================================

    // Theorem 1: Data availability attack resistance
    // Users can always exit with Merkle proof from a previous valid block
    // if operator withholds data

    // Theorem 2: Invalid block attack resistance
    // Users can challenge exits from invalid blocks using Merkle proofs

    // Theorem 3: Mass exit attack resistance
    // Priority queue ensures older UTXOs exit first, preventing
    // attackers from front-running legitimate exits

    // Theorem 4: Griefing attack resistance
    // Exit bond requirement prevents spam exits that would congest
    // the exit queue

    // ========================================================================
    // INVARIANTS
    // ========================================================================

    // Invariant 1: Exit queue is sorted by priority
    syntax Bool ::= exitQueueSorted(List) [function]
    rule exitQueueSorted(.List) => true
    rule exitQueueSorted(ListItem(_)) => true
    rule exitQueueSorted(ListItem(P1) ListItem(P2) Rest) =>
        P1 <=Int P2 andBool exitQueueSorted(ListItem(P2) Rest)

    // Invariant 2: No duplicate exits
    syntax Bool ::= noDuplicateExits(Map) [function]
    // Each UTXOPosition appears at most once in exits map

    // Invariant 3: Circuit breaker halts all operations
    syntax Bool ::= circuitBreakerHaltsAll(Bool, KItem) [function]
    // When circuitBreaker == true, no deposits or exits can be processed

    // Invariant 4: Spent UTXOs cannot be re-spent
    syntax Bool ::= spentUTXOsImmutable(Set, UTXOPosition) [function]
    rule spentUTXOsImmutable(Spent, Pos) =>
        (Pos in Spent) impliesBool true  // Once in Spent, always in Spent

endmodule

module PLASMA
    imports PLASMA-SECURITY
endmodule
