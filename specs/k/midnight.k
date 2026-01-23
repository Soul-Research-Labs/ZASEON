// K Framework Formal Specification for Midnight Network
// Privacy Interoperability Layer (PIL) - Midnight Bridge Formalization

module MIDNIGHT-TYPES
    imports INT
    imports BOOL
    imports BYTES
    imports STRING
    imports LIST
    imports MAP
    imports SET

    // =========================================================================
    // MIDNIGHT CONSTANTS
    // =========================================================================

    // BLS12-381 Curve Constants (Midnight uses this for ZK proofs)
    syntax Int ::= "BLS12_381_ORDER"        [function, total]
                 | "BLS12_381_PRIME"        [function, total]

    rule BLS12_381_ORDER => 52435875175126190479447740508185965837690552500527637822603658699938581184513
    rule BLS12_381_PRIME => 4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787

    // Ed25519 for signing
    syntax Int ::= "ED25519_ORDER"          [function, total]

    rule ED25519_ORDER => 7237005577332262213973186563042994240857116359379907606001950938285454250989

    // Block Constants
    syntax Int ::= "BLOCK_TIME_SECONDS"     [function, total]
                 | "FINALITY_BLOCKS"        [function, total]
                 | "EPOCH_LENGTH"           [function, total]

    rule BLOCK_TIME_SECONDS => 20
    rule FINALITY_BLOCKS => 10
    rule EPOCH_LENGTH => 21600  // ~5 days

    // =========================================================================
    // MIDNIGHT DATA STRUCTURES
    // =========================================================================

    // Compact (Privacy-preserving data structure)
    syntax Compact ::= compact(
        value: Bytes,
        blinding: Bytes
    )

    // Shielded Value
    syntax ShieldedValue ::= shieldedValue(
        commitment: Bytes,    // Pedersen commitment
        rangeProof: Bytes,    // Bulletproof
        encryptedAmount: Bytes
    )

    // ZK Proof Types
    syntax ZKProofType ::= "SPEND"
                         | "OUTPUT"
                         | "BINDING"
                         | "POLICY"

    // Midnight ZK Proof
    syntax MidnightProof ::= midnightProof(
        proofType: ZKProofType,
        publicInputs: Bytes,
        proof: Bytes,
        vkHash: Bytes
    )

    // Midnight Transaction
    syntax MidnightTx ::= midnightTx(
        txId: Bytes,
        inputs: List,         // List of nullifiers being spent
        outputs: List,        // List of new commitments
        proofs: List,         // ZK proofs
        fee: Int,
        anchor: Bytes,        // State commitment anchor
        memo: Bytes
    )

    // Midnight Block
    syntax MidnightBlock ::= midnightBlock(
        blockNumber: Int,
        blockHash: Bytes,
        prevHash: Bytes,
        timestamp: Int,
        stateRoot: Bytes,
        nullifierRoot: Bytes,
        commitmentRoot: Bytes,
        transactions: List
    )

    // State Transition
    syntax StateTransition ::= stateTransition(
        oldState: Bytes,
        newState: Bytes,
        proof: MidnightProof
    )

    // Cross-chain Transfer
    syntax MidnightTransfer ::= midnightTransfer(
        transferId: Bytes,
        direction: String,     // "SHIELD" or "UNSHIELD"
        publicValue: Int,      // Public amount (for bridging)
        shieldedCommitment: Bytes,
        proof: MidnightProof,
        status: String
    )

    // Dust-based UTXO (Midnight's term for private UTXOs)
    syntax Dust ::= dust(
        commitment: Bytes,
        nullifier: Bytes,
        value: Int,
        owner: Bytes,
        blinding: Bytes
    )

endmodule

module MIDNIGHT-POSEIDON
    imports MIDNIGHT-TYPES

    // =========================================================================
    // HASH FUNCTIONS (Midnight uses Poseidon for ZK-friendliness)
    // =========================================================================

    // Abstract Poseidon hash function
    syntax Bytes ::= poseidon(Bytes) [function, smtlib(poseidon)]
    syntax Bytes ::= poseidon2(Bytes, Bytes) [function, smtlib(poseidon2)]

    // Compute Pedersen commitment (value commitment)
    syntax Bytes ::= pedersenCommit(Int, Bytes) [function]
    rule pedersenCommit(Value, Blinding) =>
        poseidon(Int2Bytes(Value, BE, Unsigned) +Bytes Blinding +Bytes b"PEDERSEN")

    // Compute nullifier from dust
    syntax Bytes ::= computeDustNullifier(Dust) [function]
    rule computeDustNullifier(dust(Commitment, _, _, Owner, Blinding)) =>
        poseidon(Commitment +Bytes Owner +Bytes Blinding +Bytes b"NULLIFIER")

    // Compute transaction ID
    syntax Bytes ::= computeTxId(MidnightTx) [function]
    rule computeTxId(midnightTx(_, Inputs, Outputs, _, Fee, Anchor, _)) =>
        poseidon(encodeList(Inputs) +Bytes encodeList(Outputs) +Bytes Int2Bytes(Fee, BE, Unsigned) +Bytes Anchor)

    syntax Bytes ::= encodeList(List) [function]
    rule encodeList(.List) => b""
    rule encodeList(ListItem(B:Bytes) Rest) => B +Bytes encodeList(Rest)

    // =========================================================================
    // NULLIFIER DERIVATION FOR PIL
    // =========================================================================

    // Derive Midnight nullifier for cross-domain use
    syntax Bytes ::= deriveMidnightNullifier(Bytes, Bytes, Int, Bytes) [function]
    rule deriveMidnightNullifier(Commitment, Owner, BlockNumber, Domain) =>
        poseidon(Commitment +Bytes Owner +Bytes Int2Bytes(BlockNumber, BE, Unsigned) +Bytes Domain +Bytes b"MIDNIGHT_NULLIFIER")

    // Derive cross-domain PIL nullifier
    syntax Bytes ::= derivePILNullifier(Bytes, Bytes) [function]
    rule derivePILNullifier(MidnightNullifier, Domain) =>
        poseidon(MidnightNullifier +Bytes Domain +Bytes b"MIDNIGHT2PIL")

endmodule

module MIDNIGHT-ZK
    imports MIDNIGHT-POSEIDON

    // =========================================================================
    // ZK PROOF VERIFICATION (Simplified)
    // =========================================================================

    // Verify PLONK proof structure
    syntax Bool ::= verifyPLONKStructure(MidnightProof) [function]
    rule verifyPLONKStructure(midnightProof(_, PublicInputs, Proof, VkHash)) =>
        lengthBytes(PublicInputs) >Int 0 andBool
        lengthBytes(Proof) >=Int 384 andBool  // Minimum PLONK proof size
        lengthBytes(VkHash) ==Int 32

    // Verify spend proof
    syntax Bool ::= verifySpendProof(MidnightProof, Bytes, Bytes) [function]
    rule verifySpendProof(midnightProof(SPEND, PublicInputs, _, _), NullifierRoot, Anchor) =>
        extractNullifierRoot(PublicInputs) ==K NullifierRoot andBool
        extractAnchor(PublicInputs) ==K Anchor

    // Extract nullifier root from public inputs
    syntax Bytes ::= extractNullifierRoot(Bytes) [function]
    rule extractNullifierRoot(Inputs) => substrBytes(Inputs, 0, 32) requires lengthBytes(Inputs) >=Int 32

    // Extract anchor from public inputs
    syntax Bytes ::= extractAnchor(Bytes) [function]
    rule extractAnchor(Inputs) => substrBytes(Inputs, 32, 64) requires lengthBytes(Inputs) >=Int 64

    // Verify output proof
    syntax Bool ::= verifyOutputProof(MidnightProof, Bytes) [function]
    rule verifyOutputProof(midnightProof(OUTPUT, PublicInputs, _, _), CommitmentRoot) =>
        extractCommitmentRoot(PublicInputs) ==K CommitmentRoot

    syntax Bytes ::= extractCommitmentRoot(Bytes) [function]
    rule extractCommitmentRoot(Inputs) => substrBytes(Inputs, 0, 32) requires lengthBytes(Inputs) >=Int 32

endmodule

module MIDNIGHT-BRIDGE-SECURITY
    imports MIDNIGHT-ZK

    // =========================================================================
    // SECURITY INVARIANTS
    // =========================================================================

    // INVARIANT 1: Nullifier uniqueness
    syntax Bool ::= nullifierUnique(Bytes, Set) [function]
    rule nullifierUnique(Nf, NfSet) => notBool (Nf in NfSet)

    // INVARIANT 2: Valid ZK proof required
    syntax Bool ::= zkProofRequired(MidnightProof) [function]
    rule zkProofRequired(Proof) => verifyPLONKStructure(Proof)

    // INVARIANT 3: Cross-domain nullifier determinism
    syntax Bool ::= crossDomainNullifierDeterministic(Bytes, Bytes, Int, Bytes, Bytes, Int) [function]
    rule crossDomainNullifierDeterministic(Commit1, Owner1, Block1, Commit2, Owner2, Block2) =>
        (Commit1 ==K Commit2 andBool Owner1 ==K Owner2 andBool Block1 ==Int Block2) impliesBool
        (deriveMidnightNullifier(Commit1, Owner1, Block1, b"PIL") ==K deriveMidnightNullifier(Commit2, Owner2, Block2, b"PIL"))

    // INVARIANT 4: Different dust produce different nullifiers
    syntax Bool ::= differentDustUniqueNullifiers(Bytes, Bytes, Int, Bytes, Bytes, Int, Bytes) [function]
    rule differentDustUniqueNullifiers(Commit1, Owner1, Block1, Commit2, Owner2, Block2, Domain) =>
        (Commit1 =/=K Commit2 orBool Owner1 =/=K Owner2 orBool Block1 =/=Int Block2) impliesBool
        (deriveMidnightNullifier(Commit1, Owner1, Block1, Domain) =/=K deriveMidnightNullifier(Commit2, Owner2, Block2, Domain))

    // INVARIANT 5: Block number monotonicity
    syntax Bool ::= blockNumberMonotonic(Int, Int) [function]
    rule blockNumberMonotonic(PrevBlock, NewBlock) => NewBlock >Int PrevBlock

    // INVARIANT 6: Cross-domain direction matters
    syntax Bool ::= crossDomainDirectionMatters(Bytes, Bytes, Bytes) [function]
    rule crossDomainDirectionMatters(Nf, DomainA, DomainB) =>
        (DomainA =/=K DomainB) impliesBool
        (derivePILNullifier(Nf, DomainA) =/=K derivePILNullifier(Nf, DomainB))

    // INVARIANT 7: Shield/unshield value conservation
    syntax Bool ::= valueConservation(Int, Int, Int) [function]
    rule valueConservation(InputValue, OutputValue, Fee) =>
        InputValue ==Int OutputValue +Int Fee

endmodule

module MIDNIGHT-BRIDGE
    imports MIDNIGHT-BRIDGE-SECURITY

    configuration
        <midnight>
            <stateRoot> b"" </stateRoot>
            <nullifierRoot> b"" </nullifierRoot>
            <commitmentRoot> b"" </commitmentRoot>
            <nullifiers> .Set </nullifiers>
            <commitments> .Set </commitments>
            <pendingShields> .Map </pendingShields>
            <pendingUnshields> .Map </pendingUnshields>
            <currentBlock> 0 </currentBlock>
            <totalShielded> 0 </totalShielded>
        </midnight>

endmodule
