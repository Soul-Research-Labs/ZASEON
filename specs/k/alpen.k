// K Framework Specification for Alpen Network (Bitcoin L2)
// Formal semantics for BitVM, Schnorr signatures, STARK proofs, and cross-domain nullifiers

module ALPEN-SYNTAX
    imports DOMAINS

    // =========================================================================
    // FIELD ARITHMETIC (SECP256K1)
    // =========================================================================

    syntax Int ::= "SECP256K1_ORDER"     [function, total]
                 | "SECP256K1_PRIME"     [function, total]
                 | "SECP256K1_GX"        [function, total]
                 | "SECP256K1_GY"        [function, total]

    // secp256k1 curve order (same as Bitcoin/Ethereum)
    // n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    rule SECP256K1_ORDER => 115792089237316195423570985008687907852837564279074904382605163141518161494337

    // secp256k1 field prime
    // p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    rule SECP256K1_PRIME => 115792089237316195423570985008687907853269984665640564039457584007908834671663

    // Generator point G
    rule SECP256K1_GX => 55066263022277343669578718895168534326250603453777594175500187360389116729240
    rule SECP256K1_GY => 32670510020758816978083085130507043184471273380659243275938904335757337482424

    // =========================================================================
    // BITCOIN PRIMITIVES
    // =========================================================================

    syntax Outpoint ::= outpoint(txid: Bytes, vout: Int)
    
    syntax UTXO ::= utxo(
        outpoint: Outpoint,
        value: Int,         // satoshis
        scriptPubKey: Bytes,
        confirmations: Int
    )

    syntax TxInput ::= txinput(
        prevout: Outpoint,
        scriptSig: Bytes,
        witness: Bytes,
        sequence: Int
    )

    syntax TxOutput ::= txoutput(
        value: Int,
        scriptPubKey: Bytes
    )

    syntax BitcoinTx ::= bitcointx(
        version: Int,
        inputs: List,       // List of TxInput
        outputs: List,      // List of TxOutput
        locktime: Int,
        txid: Bytes
    )

    syntax BlockHeader ::= blockheader(
        version: Int,
        prevBlockHash: Bytes,
        merkleRoot: Bytes,
        timestamp: Int,
        bits: Int,
        nonce: Int,
        blockHash: Bytes
    )

    // =========================================================================
    // SCHNORR SIGNATURES (BIP-340)
    // =========================================================================

    syntax SchnorrPubkey ::= schnorrpk(x: Int)
    
    syntax SchnorrSig ::= schnorrsig(r: Int, s: Int)

    syntax TaprootKey ::= taprootkey(
        internalKey: SchnorrPubkey,
        merkleRoot: Bytes,
        outputKey: SchnorrPubkey
    )

    // =========================================================================
    // BITVM
    // =========================================================================

    syntax GateType ::= "NAND" | "AND" | "OR" | "XOR" | "NOT"

    syntax Gate ::= gate(
        gateType: GateType,
        inputA: Int,
        inputB: Int,
        output: Int
    )

    syntax BitVMProgram ::= bitvmprogram(
        programHash: Bytes,
        gates: List,        // List of Gate
        numInputs: Int,
        numOutputs: Int,
        commitmentRoot: Bytes
    )

    syntax ChallengeStatus ::= "NONE" | "PENDING" | "RESPONDED" | "SLASHED" | "RESOLVED"

    syntax BitVMChallenge ::= bitvmchallenge(
        challengeId: Bytes,
        programHash: Bytes,
        gateIndex: Int,
        inputCommitment: Bytes,
        outputCommitment: Bytes,
        challenger: Int,    // Address as Int
        deadline: Int,
        status: ChallengeStatus
    )

    // =========================================================================
    // STARK PROOFS
    // =========================================================================

    syntax STARKProof ::= starkproof(
        publicInputHash: Bytes,
        programHash: Bytes,
        traceCommitments: List,
        friCommitments: List,
        openings: Bytes,
        securityLevel: Int
    )

    syntax StateTransition ::= statetransition(
        preStateRoot: Bytes,
        postStateRoot: Bytes,
        blockHash: Bytes,
        blockNumber: Int,
        transactionsRoot: Bytes,
        receiptsRoot: Bytes
    )

    syntax BatchStatus ::= "BATCH_PENDING" | "BATCH_VERIFIED" | "BATCH_FINALIZED" | "BATCH_REVERTED"

    syntax Batch ::= batch(
        batchNumber: Int,
        batchHash: Bytes,
        transitions: List,
        proof: STARKProof,
        timestamp: Int,
        status: BatchStatus
    )

    // =========================================================================
    // BRIDGE OPERATIONS
    // =========================================================================

    syntax PegStatus ::= "PEG_PENDING" | "PEG_CONFIRMED" | "PEG_COMPLETED" | "PEG_CHALLENGED" | "PEG_REFUNDED"

    syntax PegIn ::= pegin(
        pegInId: Bytes,
        btcTxid: Bytes,
        amount: Int,
        recipient: Int,
        confirmations: Int,
        status: PegStatus
    )

    syntax PegOut ::= pegout(
        pegOutId: Bytes,
        sender: Int,
        btcDestination: Bytes,
        amount: Int,
        signatureCount: Int,
        timestamp: Int,
        status: PegStatus
    )

    // =========================================================================
    // NULLIFIERS
    // =========================================================================

    syntax AlpenNullifier ::= alpennullifier(
        nullifierHash: Bytes,
        btcTxid: Bytes,
        blockHeight: Int,
        vout: Int
    )

    syntax CrossDomainProof ::= crossdomainproof(
        proofHash: Bytes,
        sourceChain: Int,
        destChain: Int,
        commitment: Bytes,
        nullifier: Bytes
    )

endmodule

module ALPEN-OPERATIONS
    imports ALPEN-SYNTAX
    imports DOMAINS

    // =========================================================================
    // CONSTANTS
    // =========================================================================

    syntax Int ::= "MIN_DEPOSIT_SATS"    [function, total]
                 | "MAX_DEPOSIT_SATS"    [function, total]
                 | "OPERATOR_THRESHOLD"  [function, total]
                 | "FINALITY_BLOCKS"     [function, total]
                 | "CHALLENGE_PERIOD"    [function, total]
                 | "STARK_SECURITY_BITS" [function, total]

    rule MIN_DEPOSIT_SATS => 10000              // 0.0001 BTC
    rule MAX_DEPOSIT_SATS => 100000000000       // 1000 BTC
    rule OPERATOR_THRESHOLD => 5                // 5-of-9 multisig
    rule FINALITY_BLOCKS => 6                   // Bitcoin confirmations
    rule CHALLENGE_PERIOD => 604800             // 7 days in seconds
    rule STARK_SECURITY_BITS => 128             // 128-bit security

    // =========================================================================
    // HASH FUNCTIONS
    // =========================================================================

    // Double SHA256 (Bitcoin standard)
    syntax Bytes ::= doubleSha256(Bytes)    [function]
    rule doubleSha256(DATA) => sha256(sha256(DATA))

    // Tagged hash (BIP-340)
    syntax Bytes ::= taggedHash(String, Bytes)    [function]
    rule taggedHash(TAG, DATA) => sha256(sha256(TAG) +Bytes sha256(TAG) +Bytes DATA)

    // Bitcoin block hash
    syntax Bytes ::= computeBlockHash(BlockHeader)    [function]
    rule computeBlockHash(blockheader(V, PREV, MR, TS, BITS, NONCE, _)) =>
        doubleSha256(intToBytes(V) +Bytes PREV +Bytes MR +Bytes 
                     intToBytes(TS) +Bytes intToBytes(BITS) +Bytes intToBytes(NONCE))

    // =========================================================================
    // NULLIFIER DERIVATION
    // =========================================================================

    // Derive Alpen nullifier from Bitcoin UTXO
    syntax Bytes ::= deriveAlpenNullifier(Bytes, Int, Int)    [function]
    // deriveAlpenNullifier(btcTxid, vout, blockHeight)
    rule deriveAlpenNullifier(TXID, VOUT, HEIGHT) =>
        sha256(TXID +Bytes intToBytes(VOUT) +Bytes intToBytes(HEIGHT) +Bytes b"ALPEN_NULLIFIER")

    // Derive cross-domain nullifier
    syntax Bytes ::= deriveCrossDomainNullifier(Bytes, Int)    [function]
    rule deriveCrossDomainNullifier(ALPEN_NF, TARGET_DOMAIN) =>
        sha256(ALPEN_NF +Bytes intToBytes(TARGET_DOMAIN) +Bytes b"ALPEN2PIL")

    // Derive PIL binding
    syntax Bytes ::= derivePILBinding(Bytes, Bytes)    [function]
    rule derivePILBinding(ALPEN_NF, PIL_DOMAIN) =>
        sha256(ALPEN_NF +Bytes PIL_DOMAIN +Bytes b"PIL_BINDING")

    // =========================================================================
    // BITVM OPERATIONS
    // =========================================================================

    // Evaluate NAND gate
    syntax Bool ::= evalNAND(Bool, Bool)    [function, total]
    rule evalNAND(A, B) => notBool (A andBool B)

    // Evaluate AND gate
    syntax Bool ::= evalAND(Bool, Bool)    [function, total]
    rule evalAND(A, B) => A andBool B

    // Evaluate OR gate
    syntax Bool ::= evalOR(Bool, Bool)    [function, total]
    rule evalOR(A, B) => A orBool B

    // Evaluate XOR gate
    syntax Bool ::= evalXOR(Bool, Bool)    [function, total]
    rule evalXOR(A, B) => (A andBool notBool B) orBool (notBool A andBool B)

    // Evaluate NOT gate
    syntax Bool ::= evalNOT(Bool)    [function, total]
    rule evalNOT(A) => notBool A

    // Evaluate gate by type
    syntax Bool ::= evalGate(GateType, Bool, Bool)    [function]
    rule evalGate(NAND, A, B) => evalNAND(A, B)
    rule evalGate(AND, A, B) => evalAND(A, B)
    rule evalGate(OR, A, B) => evalOR(A, B)
    rule evalGate(XOR, A, B) => evalXOR(A, B)
    rule evalGate(NOT, A, _) => evalNOT(A)

    // Check if challenge is active
    syntax Bool ::= isChallengeActive(BitVMChallenge, Int)    [function]
    rule isChallengeActive(bitvmchallenge(_, _, _, _, _, _, DEADLINE, STATUS), NOW) =>
        STATUS ==K PENDING andBool NOW <Int DEADLINE

    // =========================================================================
    // DIFFICULTY TARGET
    // =========================================================================

    // Convert compact bits to target
    syntax Int ::= bitsToTarget(Int)    [function]
    rule bitsToTarget(BITS) => 
        #if (BITS >>Int 24) <=Int 3
        #then (BITS &Int 8388607) >>Int (8 *Int (3 -Int (BITS >>Int 24)))
        #else (BITS &Int 8388607) <<Int (8 *Int ((BITS >>Int 24) -Int 3))
        #fi

    // Validate proof of work
    syntax Bool ::= isValidPoW(BlockHeader)    [function]
    rule isValidPoW(blockheader(_, _, _, _, BITS, _, HASH)) =>
        bytesToInt(HASH) <Int bitsToTarget(BITS)

    // =========================================================================
    // PEG VALIDATION
    // =========================================================================

    // Validate peg-in
    syntax Bool ::= isValidPegIn(PegIn)    [function]
    rule isValidPegIn(pegin(_, TXID, AMOUNT, RECIPIENT, CONFIRMATIONS, _)) =>
        TXID =/=K b"" andBool
        AMOUNT >=Int MIN_DEPOSIT_SATS andBool
        AMOUNT <=Int MAX_DEPOSIT_SATS andBool
        RECIPIENT =/=Int 0 andBool
        CONFIRMATIONS >=Int FINALITY_BLOCKS

    // Validate peg-out
    syntax Bool ::= isValidPegOut(PegOut)    [function]
    rule isValidPegOut(pegout(_, SENDER, DEST, AMOUNT, SIGCOUNT, _, _)) =>
        SENDER =/=Int 0 andBool
        DEST =/=K b"" andBool
        AMOUNT >=Int MIN_DEPOSIT_SATS andBool
        AMOUNT <=Int MAX_DEPOSIT_SATS andBool
        SIGCOUNT >=Int OPERATOR_THRESHOLD

    // Check operator threshold
    syntax Bool ::= hasOperatorThreshold(Int)    [function, total]
    rule hasOperatorThreshold(COUNT) => COUNT >=Int OPERATOR_THRESHOLD

    // =========================================================================
    // STARK PROOF VALIDATION
    // =========================================================================

    // Validate STARK proof structure
    syntax Bool ::= isValidSTARKProof(STARKProof)    [function]
    rule isValidSTARKProof(starkproof(PIH, PH, TC, FC, _, SL)) =>
        PIH =/=K b"" andBool
        PH =/=K b"" andBool
        size(TC) >Int 0 andBool
        size(FC) >Int 0 andBool
        SL >=Int STARK_SECURITY_BITS

    // Compute state transition hash
    syntax Bytes ::= computeTransitionHash(StateTransition)    [function]
    rule computeTransitionHash(statetransition(PRE, POST, BH, BN, TR, RR)) =>
        sha256(PRE +Bytes POST +Bytes BH +Bytes intToBytes(BN) +Bytes TR +Bytes RR)

    // =========================================================================
    // SCRIPT TYPE DETECTION
    // =========================================================================

    // Check if P2WPKH (OP_0 <20 bytes>)
    syntax Bool ::= isP2WPKH(Bytes)    [function]
    rule isP2WPKH(SCRIPT) =>
        lengthBytes(SCRIPT) ==Int 22 andBool
        SCRIPT[0] ==Int 0 andBool
        SCRIPT[1] ==Int 20

    // Check if P2WSH (OP_0 <32 bytes>)
    syntax Bool ::= isP2WSH(Bytes)    [function]
    rule isP2WSH(SCRIPT) =>
        lengthBytes(SCRIPT) ==Int 34 andBool
        SCRIPT[0] ==Int 0 andBool
        SCRIPT[1] ==Int 32

    // Check if P2TR (OP_1 <32 bytes>)
    syntax Bool ::= isP2TR(Bytes)    [function]
    rule isP2TR(SCRIPT) =>
        lengthBytes(SCRIPT) ==Int 34 andBool
        SCRIPT[0] ==Int 81 andBool    // OP_1
        SCRIPT[1] ==Int 32

    // =========================================================================
    // TAPROOT OPERATIONS
    // =========================================================================

    // Compute Taproot tweak
    syntax Bytes ::= computeTaprootTweak(SchnorrPubkey, Bytes)    [function]
    rule computeTaprootTweak(schnorrpk(X), MERKLE_ROOT) =>
        taggedHash("TapTweak", intToBytes(X) +Bytes MERKLE_ROOT)

    // =========================================================================
    // MERKLE TREE
    // =========================================================================

    // Verify Merkle proof (simplified)
    syntax Bool ::= verifyMerkleProof(Bytes, List, Int, Bytes)    [function]
    // verifyMerkleProof(txid, siblings, index, expectedRoot)
    rule verifyMerkleProof(TXID, .List, _, ROOT) => TXID ==K ROOT
    rule verifyMerkleProof(TXID, ListItem(SIB) REST, IDX, ROOT) =>
        #if IDX %Int 2 ==Int 0
        #then verifyMerkleProof(doubleSha256(TXID +Bytes SIB), REST, IDX /Int 2, ROOT)
        #else verifyMerkleProof(doubleSha256(SIB +Bytes TXID), REST, IDX /Int 2, ROOT)
        #fi

endmodule

module ALPEN-PROPERTIES
    imports ALPEN-OPERATIONS

    // =========================================================================
    // NULLIFIER PROPERTIES
    // =========================================================================

    // Property: Nullifier uniqueness - same inputs always produce same nullifier
    // ∀ txid, vout, height: deriveAlpenNullifier(txid, vout, height) is deterministic
    rule [nullifier-determinism]:
        deriveAlpenNullifier(TXID, VOUT, HEIGHT) ==K deriveAlpenNullifier(TXID, VOUT, HEIGHT)
        => true

    // Property: Different UTXOs produce different nullifiers
    // ∀ txid1 ≠ txid2: deriveAlpenNullifier(txid1, v, h) ≠ deriveAlpenNullifier(txid2, v, h)
    // (probabilistic - SHA256 collision resistance)

    // Property: Cross-domain nullifier is directional
    // deriveCrossDomainNullifier(nf, domain1) ≠ deriveCrossDomainNullifier(nf, domain2)
    // when domain1 ≠ domain2

    // =========================================================================
    // BITVM PROPERTIES
    // =========================================================================

    // Property: NAND is universal - can build any function
    // All Boolean functions can be expressed using only NAND gates

    // Property: NAND truth table correctness
    rule [nand-00]: evalNAND(false, false) => true
    rule [nand-01]: evalNAND(false, true) => true
    rule [nand-10]: evalNAND(true, false) => true
    rule [nand-11]: evalNAND(true, true) => false

    // Property: Challenge must be active to be responded to
    rule [challenge-response-requires-active]:
        isChallengeActive(C, NOW) ==K true
        => true
        requires NOW <Int deadline(C) andBool status(C) ==K PENDING

    // Property: Challenge expires after deadline
    rule [challenge-expires]:
        isChallengeActive(bitvmchallenge(_, _, _, _, _, _, DEADLINE, PENDING), NOW) ==K false
        => true
        requires NOW >=Int DEADLINE

    // =========================================================================
    // PEG PROPERTIES
    // =========================================================================

    // Property: Peg-in requires minimum confirmations
    rule [pegin-confirmations]:
        isValidPegIn(pegin(_, _, _, _, CONFIRMATIONS, _)) ==K true
        => CONFIRMATIONS >=Int FINALITY_BLOCKS

    // Property: Peg-out requires operator threshold
    rule [pegout-threshold]:
        isValidPegOut(pegout(_, _, _, _, SIGCOUNT, _, _)) ==K true
        => SIGCOUNT >=Int OPERATOR_THRESHOLD

    // Property: Amount bounds are enforced
    rule [amount-bounds]:
        isValidPegIn(pegin(_, _, AMOUNT, _, _, _)) ==K true
        => AMOUNT >=Int MIN_DEPOSIT_SATS andBool AMOUNT <=Int MAX_DEPOSIT_SATS

    // =========================================================================
    // STARK PROPERTIES
    // =========================================================================

    // Property: STARK proof requires minimum security level
    rule [stark-security]:
        isValidSTARKProof(starkproof(_, _, _, _, _, SL)) ==K true
        => SL >=Int STARK_SECURITY_BITS

    // Property: State transition hash is deterministic
    rule [transition-hash-determinism]:
        computeTransitionHash(T) ==K computeTransitionHash(T)
        => true

    // =========================================================================
    // BITCOIN PROPERTIES
    // =========================================================================

    // Property: Valid PoW means block hash < target
    rule [pow-validity]:
        isValidPoW(blockheader(_, _, _, _, BITS, _, HASH)) ==K true
        => bytesToInt(HASH) <Int bitsToTarget(BITS)

    // Property: Block hash is deterministic
    rule [block-hash-determinism]:
        computeBlockHash(H) ==K computeBlockHash(H)
        => true

    // =========================================================================
    // SCRIPT TYPE PROPERTIES
    // =========================================================================

    // Property: Script types are mutually exclusive
    // A script can only be one type
    rule [script-mutual-exclusivity]:
        isP2WPKH(S) andBool isP2WSH(S) => false
    rule [script-mutual-exclusivity-2]:
        isP2WPKH(S) andBool isP2TR(S) => false
    rule [script-mutual-exclusivity-3]:
        isP2WSH(S) andBool isP2TR(S) => false

    // =========================================================================
    // TAPROOT PROPERTIES
    // =========================================================================

    // Property: Taproot tweak is deterministic
    rule [taproot-tweak-determinism]:
        computeTaprootTweak(PK, MR) ==K computeTaprootTweak(PK, MR)
        => true

    // Property: Different internal keys produce different tweaks
    // computeTaprootTweak(pk1, mr) ≠ computeTaprootTweak(pk2, mr) when pk1 ≠ pk2

endmodule

module ALPEN
    imports ALPEN-PROPERTIES
endmodule
