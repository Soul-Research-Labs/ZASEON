// K Framework Formal Specification for Bitcoin
// Privacy Interoperability Layer (PIL) - Bitcoin Bridge Formalization

module BITCOIN-TYPES
    imports INT
    imports BOOL
    imports BYTES
    imports STRING
    imports LIST
    imports MAP
    imports SET

    // =========================================================================
    // BITCOIN CONSTANTS
    // =========================================================================

    // secp256k1 Curve Constants
    syntax Int ::= "SECP256K1_ORDER"        [function, total]
                 | "SECP256K1_PRIME"        [function, total]
                 | "SECP256K1_GX"           [function, total]
                 | "SECP256K1_GY"           [function, total]

    rule SECP256K1_ORDER => 115792089237316195423570985008687907852837564279074904382605163141518161494337
    rule SECP256K1_PRIME => 115792089237316195423570985008687907853269984665640564039457584007908834671663
    rule SECP256K1_GX => 55066263022277343669578718895168534326250603453777594175500187360389116729240
    rule SECP256K1_GY => 32670510020758816978083085130507043184471273380659243275938904335757337482424

    // Block Constants
    syntax Int ::= "COINBASE_MATURITY"      [function, total]
                 | "FINALITY_CONFIRMATIONS" [function, total]
                 | "DIFFICULTY_ADJUSTMENT_INTERVAL" [function, total]
                 | "TARGET_TIMESPAN"        [function, total]

    rule COINBASE_MATURITY => 100
    rule FINALITY_CONFIRMATIONS => 6
    rule DIFFICULTY_ADJUSTMENT_INTERVAL => 2016
    rule TARGET_TIMESPAN => 1209600  // 2 weeks in seconds

    // =========================================================================
    // BITCOIN DATA STRUCTURES
    // =========================================================================

    // Transaction Outpoint
    syntax Outpoint ::= outpoint(
        txid: Bytes,
        vout: Int
    )

    // Transaction Input
    syntax TxIn ::= txIn(
        prevOut: Outpoint,
        scriptSig: Bytes,
        sequence: Int,
        witness: List  // For SegWit
    )

    // Transaction Output
    syntax TxOut ::= txOut(
        value: Int,
        scriptPubKey: Bytes
    )

    // Bitcoin Transaction
    syntax BitcoinTx ::= bitcoinTx(
        version: Int,
        inputs: List,
        outputs: List,
        lockTime: Int,
        txid: Bytes,
        wtxid: Bytes
    )

    // Block Header
    syntax BlockHeader ::= blockHeader(
        version: Int,
        prevBlockHash: Bytes,
        merkleRoot: Bytes,
        timestamp: Int,
        bits: Int,
        nonce: Int,
        blockHash: Bytes
    )

    // Merkle Proof (SPV)
    syntax MerkleProof ::= merkleProof(
        txid: Bytes,
        index: Int,
        siblings: List,
        blockHeader: BlockHeader
    )

    // Script Types
    syntax ScriptType ::= "P2PKH"    // Pay to Public Key Hash
                        | "P2SH"     // Pay to Script Hash
                        | "P2WPKH"   // Pay to Witness Public Key Hash
                        | "P2WSH"    // Pay to Witness Script Hash
                        | "P2TR"     // Pay to Taproot
                        | "UNKNOWN"

    // Cross-chain Transfer (Bitcoin -> PIL)
    syntax BitcoinTransfer ::= bitcoinTransfer(
        transferId: Bytes,
        btcTxid: Bytes,
        vout: Int,
        sender: Bytes,     // Bitcoin address/script
        recipient: Bytes,  // PIL address
        amount: Int,       // satoshis
        proof: MerkleProof,
        confirmations: Int,
        status: String
    )

endmodule

module BITCOIN-HASH
    imports BITCOIN-TYPES

    // =========================================================================
    // HASH FUNCTIONS (Bitcoin uses double SHA256)
    // =========================================================================

    // Abstract SHA256 function
    syntax Bytes ::= sha256(Bytes) [function, smtlib(sha256)]

    // Double SHA256 (Bitcoin standard)
    syntax Bytes ::= doubleSha256(Bytes) [function]
    rule doubleSha256(Data) => sha256(sha256(Data))

    // HASH160 (SHA256 + RIPEMD160) - for addresses
    syntax Bytes ::= hash160(Bytes) [function, smtlib(hash160)]

    // Compute transaction ID
    syntax Bytes ::= computeTxid(BitcoinTx) [function]
    rule computeTxid(bitcoinTx(Version, Inputs, Outputs, LockTime, _, _)) =>
        doubleSha256(Int2Bytes(Version, LE, Signed) +Bytes encodeInputs(Inputs) +Bytes
                     encodeOutputs(Outputs) +Bytes Int2Bytes(LockTime, LE, Unsigned))

    // Encode inputs (simplified)
    syntax Bytes ::= encodeInputs(List) [function]
    rule encodeInputs(.List) => b""
    rule encodeInputs(ListItem(txIn(outpoint(Txid, Vout), ScriptSig, Seq, _)) Rest) =>
        Txid +Bytes Int2Bytes(Vout, LE, Unsigned) +Bytes ScriptSig +Bytes Int2Bytes(Seq, LE, Unsigned) +Bytes encodeInputs(Rest)

    // Encode outputs (simplified)
    syntax Bytes ::= encodeOutputs(List) [function]
    rule encodeOutputs(.List) => b""
    rule encodeOutputs(ListItem(txOut(Value, Script)) Rest) =>
        Int2Bytes(Value, LE, Signed) +Bytes Script +Bytes encodeOutputs(Rest)

    // =========================================================================
    // NULLIFIER DERIVATION
    // =========================================================================

    // Derive Bitcoin nullifier (from UTXO)
    syntax Bytes ::= deriveBitcoinNullifier(Bytes, Int, Int, Bytes) [function]
    rule deriveBitcoinNullifier(Txid, Vout, BlockHeight, Domain) =>
        doubleSha256(Txid +Bytes Int2Bytes(Vout, BE, Unsigned) +Bytes Int2Bytes(BlockHeight, BE, Unsigned) +Bytes Domain +Bytes b"BITCOIN_NULLIFIER")

    // Derive cross-domain PIL nullifier
    syntax Bytes ::= derivePILNullifier(Bytes, Bytes) [function]
    rule derivePILNullifier(BitcoinNullifier, Domain) =>
        doubleSha256(BitcoinNullifier +Bytes Domain +Bytes b"BTC2PIL")

endmodule

module BITCOIN-SPV
    imports BITCOIN-HASH

    // =========================================================================
    // SPV (SIMPLIFIED PAYMENT VERIFICATION)
    // =========================================================================

    // Verify Merkle proof
    syntax Bool ::= verifyMerkleProof(MerkleProof) [function]
    rule verifyMerkleProof(merkleProof(Txid, Index, Siblings, blockHeader(_, _, MerkleRoot, _, _, _, _))) =>
        computeMerkleRoot(Txid, Index, Siblings) ==K MerkleRoot

    // Compute Merkle root from proof
    syntax Bytes ::= computeMerkleRoot(Bytes, Int, List) [function]
    rule computeMerkleRoot(Current, _, .List) => Current
    rule computeMerkleRoot(Current, Index, ListItem(Sibling) Rest) =>
        computeMerkleRoot(
            #if Index %Int 2 ==Int 0
            #then doubleSha256(Current +Bytes Sibling)
            #else doubleSha256(Sibling +Bytes Current)
            #fi,
            Index /Int 2,
            Rest
        )

    // Verify proof of work
    syntax Bool ::= verifyPoW(BlockHeader) [function]
    rule verifyPoW(blockHeader(_, _, _, _, Bits, _, BlockHash)) =>
        Bytes2Int(BlockHash, BE, Unsigned) <Int bitsToTarget(Bits)

    // Convert bits to target (simplified)
    syntax Int ::= bitsToTarget(Int) [function]
    rule bitsToTarget(Bits) =>
        (Bits %Int 16777216) *Int (2 ^Int (8 *Int ((Bits /Int 16777216) -Int 3)))

    // Verify block header chain
    syntax Bool ::= verifyHeaderChain(List) [function]
    rule verifyHeaderChain(.List) => true
    rule verifyHeaderChain(ListItem(_)) => true
    rule verifyHeaderChain(ListItem(blockHeader(_, _, _, _, _, _, Hash)) ListItem(blockHeader(_, PrevHash, _, _, _, _, _)) Rest) =>
        Hash ==K PrevHash andBool verifyHeaderChain(ListItem(blockHeader(_, PrevHash, _, _, _, _, _)) Rest)

endmodule

module BITCOIN-BRIDGE-SECURITY
    imports BITCOIN-SPV

    // =========================================================================
    // SECURITY INVARIANTS
    // =========================================================================

    // INVARIANT 1: Nullifier uniqueness
    syntax Bool ::= nullifierUnique(Bytes, Set) [function]
    rule nullifierUnique(Nf, NfSet) => notBool (Nf in NfSet)

    // INVARIANT 2: SPV proof required
    syntax Bool ::= spvProofRequired(MerkleProof) [function]
    rule spvProofRequired(Proof) => verifyMerkleProof(Proof)

    // INVARIANT 3: Sufficient confirmations
    syntax Bool ::= sufficientConfirmations(Int) [function]
    rule sufficientConfirmations(Confirmations) =>
        Confirmations >=Int FINALITY_CONFIRMATIONS

    // INVARIANT 4: Cross-domain nullifier determinism
    syntax Bool ::= crossDomainNullifierDeterministic(Bytes, Int, Int, Bytes, Int, Int) [function]
    rule crossDomainNullifierDeterministic(Txid1, Vout1, Height1, Txid2, Vout2, Height2) =>
        (Txid1 ==K Txid2 andBool Vout1 ==Int Vout2 andBool Height1 ==Int Height2) impliesBool
        (deriveBitcoinNullifier(Txid1, Vout1, Height1, b"PIL") ==K deriveBitcoinNullifier(Txid2, Vout2, Height2, b"PIL"))

    // INVARIANT 5: Different UTXOs produce different nullifiers
    syntax Bool ::= differentUTXOsUniqueNullifiers(Bytes, Int, Int, Bytes, Int, Int, Bytes) [function]
    rule differentUTXOsUniqueNullifiers(Txid1, Vout1, Height1, Txid2, Vout2, Height2, Domain) =>
        (Txid1 =/=K Txid2 orBool Vout1 =/=Int Vout2 orBool Height1 =/=Int Height2) impliesBool
        (deriveBitcoinNullifier(Txid1, Vout1, Height1, Domain) =/=K deriveBitcoinNullifier(Txid2, Vout2, Height2, Domain))

    // INVARIANT 6: PoW verification required
    syntax Bool ::= powRequired(BlockHeader) [function]
    rule powRequired(Header) => verifyPoW(Header)

    // INVARIANT 7: Cross-domain direction matters
    syntax Bool ::= crossDomainDirectionMatters(Bytes, Bytes, Bytes) [function]
    rule crossDomainDirectionMatters(Nf, DomainA, DomainB) =>
        (DomainA =/=K DomainB) impliesBool
        (derivePILNullifier(Nf, DomainA) =/=K derivePILNullifier(Nf, DomainB))

endmodule

module BITCOIN-BRIDGE
    imports BITCOIN-BRIDGE-SECURITY

    configuration
        <bitcoin>
            <headers> .Map </headers>
            <bestBlock> b"" </bestBlock>
            <bestHeight> 0 </bestHeight>
            <transfers> .Map </transfers>
            <nullifiers> .Set </nullifiers>
            <processedUTXOs> .Set </processedUTXOs>
            <totalBridged> 0 </totalBridged>
        </bitcoin>

endmodule
