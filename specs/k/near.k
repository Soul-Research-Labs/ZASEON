// K Framework Formal Specification for NEAR Protocol
// Privacy Interoperability Layer (PIL) - NEAR Bridge Formalization

module NEAR-TYPES
    imports INT
    imports BOOL
    imports BYTES
    imports STRING
    imports LIST
    imports MAP
    imports SET

    // =========================================================================
    // NEAR CONSTANTS
    // =========================================================================

    // Ed25519 Curve Constants (NEAR default)
    syntax Int ::= "ED25519_ORDER"          [function, total]
                 | "ED25519_PRIME"          [function, total]

    rule ED25519_ORDER => 7237005577332262213973186563042994240857116359379907606001950938285454250989
    rule ED25519_PRIME => 57896044618658097711785492504343953926634992332820282019728792003956564819949  // 2^255 - 19

    // Block Production Constants
    syntax Int ::= "BLOCK_TIME_MS"          [function, total]
                 | "EPOCH_BLOCKS"           [function, total]
                 | "FINALITY_BLOCKS"        [function, total]

    rule BLOCK_TIME_MS => 1000   // ~1 second
    rule EPOCH_BLOCKS => 43200   // ~12 hours
    rule FINALITY_BLOCKS => 2    // Doomslug finality

    // =========================================================================
    // NEAR DATA STRUCTURES
    // =========================================================================

    // Account ID (human-readable)
    syntax AccountId ::= accountId(String)

    // Ed25519 Public Key
    syntax PublicKey ::= ed25519Key(Bytes)

    // Block Header
    syntax NearBlockHeader ::= nearBlockHeader(
        height: Int,
        epochId: Bytes,
        nextEpochId: Bytes,
        hash: Bytes,
        prevHash: Bytes,
        timestamp: Int,
        approvals: List,
        blockMerkleRoot: Bytes,
        chunkMask: List
    )

    // Light Client Block
    syntax LightClientBlock ::= lightClientBlock(
        header: NearBlockHeader,
        nextBps: List,
        approvalsAfterNext: List
    )

    // Execution Outcome
    syntax ExecutionOutcome ::= executionOutcome(
        receiptIds: List,
        gasBurnt: Int,
        tokensBurnt: Int,
        executorId: AccountId,
        status: String,
        logs: List
    )

    // Execution Outcome Proof
    syntax ExecutionOutcomeProof ::= executionOutcomeProof(
        outcome: ExecutionOutcome,
        proof: List,
        blockHash: Bytes,
        outcomeRoot: Bytes
    )

    // Receipt
    syntax Receipt ::= receipt(
        receiptId: Bytes,
        predecessorId: AccountId,
        receiverId: AccountId,
        actions: List
    )

    // Rainbow Bridge Transfer
    syntax NearTransfer ::= nearTransfer(
        transferId: Bytes,
        sender: AccountId,
        recipient: Bytes,
        token: AccountId,
        amount: Int,
        proof: ExecutionOutcomeProof,
        status: String
    )

endmodule

module NEAR-SHA256
    imports NEAR-TYPES

    // =========================================================================
    // HASH FUNCTIONS (NEAR uses SHA256)
    // =========================================================================

    // Abstract SHA256 function
    syntax Bytes ::= sha256(Bytes) [function, smtlib(sha256)]

    // Compute block hash
    syntax Bytes ::= computeBlockHash(NearBlockHeader) [function]
    rule computeBlockHash(nearBlockHeader(Height, EpochId, NextEpochId, _, PrevHash, Timestamp, _, BlockMerkleRoot, _)) =>
        sha256(Int2Bytes(Height, BE, Unsigned) +Bytes EpochId +Bytes NextEpochId +Bytes PrevHash +Bytes
               Int2Bytes(Timestamp, BE, Unsigned) +Bytes BlockMerkleRoot)

    // Compute receipt hash
    syntax Bytes ::= computeReceiptHash(Receipt) [function]
    rule computeReceiptHash(receipt(ReceiptId, predecessorId, receiverId, Actions)) =>
        sha256(ReceiptId +Bytes encodeActions(Actions))

    syntax Bytes ::= encodeActions(List) [function]
    rule encodeActions(.List) => b""
    rule encodeActions(ListItem(A) Rest) => A +Bytes encodeActions(Rest)

    // =========================================================================
    // NULLIFIER DERIVATION
    // =========================================================================

    // Derive NEAR nullifier (from receipt/transaction)
    syntax Bytes ::= deriveNearNullifier(Bytes, Int, Bytes) [function]
    rule deriveNearNullifier(ReceiptId, BlockHeight, Domain) =>
        sha256(ReceiptId +Bytes Int2Bytes(BlockHeight, BE, Unsigned) +Bytes Domain +Bytes b"NEAR_NULLIFIER")

    // Derive cross-domain PIL nullifier
    syntax Bytes ::= derivePILNullifier(Bytes, Bytes) [function]
    rule derivePILNullifier(NearNullifier, Domain) =>
        sha256(NearNullifier +Bytes Domain +Bytes b"NEAR2PIL")

endmodule

module NEAR-LIGHT-CLIENT
    imports NEAR-SHA256

    // =========================================================================
    // DOOMSLUG FINALITY VERIFICATION
    // =========================================================================

    // Verify block has sufficient approvals (>50% for Doomslug)
    syntax Bool ::= hasDoomslugFinality(LightClientBlock, Int) [function]
    rule hasDoomslugFinality(lightClientBlock(_, _, Approvals), ValidatorCount) =>
        size(Approvals) *Int 2 >Int ValidatorCount

    // Verify BFT finality (2/3 + 1)
    syntax Bool ::= hasBFTFinality(Int, Int) [function]
    rule hasBFTFinality(ApprovalCount, ValidatorCount) =>
        ApprovalCount *Int 3 >Int ValidatorCount *Int 2

    // Verify epoch transition
    syntax Bool ::= isEpochTransition(NearBlockHeader, NearBlockHeader) [function]
    rule isEpochTransition(
        nearBlockHeader(_, EpochId1, _, _, _, _, _, _, _),
        nearBlockHeader(_, EpochId2, _, _, _, _, _, _, _)
    ) => EpochId1 =/=K EpochId2

    // =========================================================================
    // OUTCOME PROOF VERIFICATION
    // =========================================================================

    // Verify outcome proof against outcome root
    syntax Bool ::= verifyOutcomeProof(ExecutionOutcomeProof, Bytes) [function]
    rule verifyOutcomeProof(executionOutcomeProof(_, Proof, _, OutcomeRoot), ExpectedRoot) =>
        verifyMerklePath(Proof, OutcomeRoot, ExpectedRoot)

    // Verify Merkle path (simplified)
    syntax Bool ::= verifyMerklePath(List, Bytes, Bytes) [function]
    rule verifyMerklePath(.List, Leaf, Root) => Leaf ==K Root
    rule verifyMerklePath(ListItem(Sibling) Rest, Current, Root) =>
        verifyMerklePath(Rest, sha256(Current +Bytes Sibling), Root)

endmodule

module NEAR-BRIDGE-SECURITY
    imports NEAR-LIGHT-CLIENT

    // =========================================================================
    // SECURITY INVARIANTS
    // =========================================================================

    // INVARIANT 1: Nullifier uniqueness
    syntax Bool ::= nullifierUnique(Bytes, Set) [function]
    rule nullifierUnique(Nf, NfSet) => notBool (Nf in NfSet)

    // INVARIANT 2: Doomslug finality required
    syntax Bool ::= doomslugFinalityRequired(LightClientBlock, Int) [function]
    rule doomslugFinalityRequired(Block, ValidatorCount) => hasDoomslugFinality(Block, ValidatorCount)

    // INVARIANT 3: Block height monotonicity
    syntax Bool ::= heightMonotonic(Int, Int) [function]
    rule heightMonotonic(PrevHeight, NewHeight) => NewHeight >Int PrevHeight

    // INVARIANT 4: Cross-domain nullifier determinism
    syntax Bool ::= crossDomainNullifierDeterministic(Bytes, Int, Bytes, Int) [function]
    rule crossDomainNullifierDeterministic(ReceiptId1, Height1, ReceiptId2, Height2) =>
        (ReceiptId1 ==K ReceiptId2 andBool Height1 ==Int Height2) impliesBool
        (deriveNearNullifier(ReceiptId1, Height1, b"PIL") ==K deriveNearNullifier(ReceiptId2, Height2, b"PIL"))

    // INVARIANT 5: Different receipts produce different nullifiers
    syntax Bool ::= differentReceiptsUniqueNullifiers(Bytes, Int, Bytes, Int, Bytes) [function]
    rule differentReceiptsUniqueNullifiers(ReceiptId1, Height1, ReceiptId2, Height2, Domain) =>
        (ReceiptId1 =/=K ReceiptId2 orBool Height1 =/=Int Height2) impliesBool
        (deriveNearNullifier(ReceiptId1, Height1, Domain) =/=K deriveNearNullifier(ReceiptId2, Height2, Domain))

    // INVARIANT 6: Execution status validity
    syntax Bool ::= validExecutionStatus(String) [function]
    rule validExecutionStatus(Status) =>
        Status ==String "SUCCESS" orBool Status ==String "FAILURE" orBool Status ==String "UNKNOWN"

    // INVARIANT 7: Cross-domain direction matters
    syntax Bool ::= crossDomainDirectionMatters(Bytes, Bytes, Bytes) [function]
    rule crossDomainDirectionMatters(Nf, DomainA, DomainB) =>
        (DomainA =/=K DomainB) impliesBool
        (derivePILNullifier(Nf, DomainA) =/=K derivePILNullifier(Nf, DomainB))

endmodule

module NEAR-BRIDGE
    imports NEAR-BRIDGE-SECURITY

    configuration
        <near>
            <lightClient>
                <finalizedHead> .K </finalizedHead>
                <validatorSet> .Map </validatorSet>
                <validatorCount> 0 </validatorCount>
                <currentEpoch> b"" </currentEpoch>
            </lightClient>
            <transfers> .Map </transfers>
            <nullifiers> .Set </nullifiers>
            <processedReceipts> .Set </processedReceipts>
            <currentHeight> 0 </currentHeight>
            <totalBridged> 0 </totalBridged>
        </near>

endmodule
