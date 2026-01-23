// K Framework Formal Specification for Provenance Blockchain Integration
// Cosmos SDK-based blockchain for financial services

module PROVENANCE-SYNTAX
    imports INT
    imports BOOL
    imports STRING
    imports BYTES

    // =========================================================================
    // SECP256K1 CURVE (Cosmos Standard)
    // =========================================================================

    syntax Int ::= "SECP256K1_ORDER"     [function, total]
                 | "SECP256K1_PRIME"     [function, total]
                 | "QUORUM_THRESHOLD"    [function, total]

    rule SECP256K1_ORDER => 115792089237316195423570985008687907852837564279074904382605163141518161494337

    rule SECP256K1_PRIME => 115792089237316195423570985008687907853269984665640564039457584007908834671663

    // 2/3+1 = 6667 basis points
    rule QUORUM_THRESHOLD => 6667

    // =========================================================================
    // CHAIN IDENTIFIERS
    // =========================================================================

    syntax ChainId ::= "pio-mainnet-1" | "pio-testnet-1"

    syntax Int ::= chainIdNumeric(ChainId) [function, total]

    rule chainIdNumeric(pio-mainnet-1) => 1
    rule chainIdNumeric(pio-testnet-1) => 2

    // =========================================================================
    // TENDERMINT CONSENSUS
    // =========================================================================

    syntax Pubkey ::= pubkey(Bytes)  // 33-byte compressed secp256k1
    syntax Address ::= address(Bytes) // 20-byte address

    syntax Validator ::= validator(Pubkey, Int, Int)  // pubkey, votingPower, proposerPriority

    syntax ValidatorSet ::= List{Validator, ","}

    syntax BlockHeader ::= blockHeader(
        Int,      // height
        Int,      // timestamp
        Bytes,    // lastBlockId
        Bytes,    // dataHash
        Bytes,    // validatorsHash
        Bytes,    // nextValidatorsHash
        Bytes,    // consensusHash
        Bytes,    // appHash
        Bytes,    // lastResultsHash
        Bytes,    // evidenceHash
        Address   // proposerAddress
    )

    syntax CommitSig ::= commitSig(Int, Address, Bytes, Int) // blockIdFlag, validatorAddress, timestamp, signature
    syntax Commit ::= commit(Int, Int, Bytes, List{CommitSig, ","})  // height, round, blockId, signatures

    // =========================================================================
    // MARKER MODULE (Asset Tokenization)
    // =========================================================================

    syntax MarkerType ::= "COIN" | "RESTRICTED"

    syntax MarkerStatus ::= "PROPOSED" | "FINALIZED" | "ACTIVE" | "CANCELLED" | "DESTROYED"

    syntax AccessType ::= "UNSPECIFIED" | "MINT" | "BURN" | "DEPOSIT" | "WITHDRAW" | "DELETE" | "ADMIN"

    syntax AccessGrant ::= accessGrant(Address, AccessType)
    syntax AccessGrants ::= List{AccessGrant, ","}

    syntax Marker ::= marker(
        String,       // denom
        Int,          // totalSupply
        Address,      // manager
        MarkerType,   // type
        MarkerStatus, // status
        Bool,         // supplyFixed
        Bool,         // allowGovernanceControl
        AccessGrants  // accessGrants
    )

    // =========================================================================
    // NAME MODULE
    // =========================================================================

    syntax NameRecord ::= nameRecord(
        String,  // name
        Address, // address
        Bool     // restricted
    )

    // =========================================================================
    // ATTRIBUTE MODULE
    // =========================================================================

    syntax AttributeType ::= "UNSPECIFIED_ATTR" | "UUID" | "JSON" | "STRING_ATTR" | "URI" | "INT_ATTR" | "FLOAT" | "PROTO" | "BYTES_ATTR"

    syntax Attribute ::= attribute(
        String,        // name
        Bytes,         // value
        AttributeType, // type
        Address        // address
    )

    // =========================================================================
    // METADATA MODULE (Scope/Record Management)
    // =========================================================================

    syntax Scope ::= scope(
        Bytes,           // scopeId
        String,          // specificationId
        List{Address, ","}, // owners
        List{Address, ","}, // dataAccess
        Address          // valueOwner
    )

    syntax RecordInput ::= recordInput(String, Bytes, String, Address) // name, hash, typeName, source
    syntax RecordOutput ::= recordOutput(Bytes, String) // hash, status

    syntax Record ::= record(
        String,              // name
        Bytes,               // sessionId
        List{RecordInput, ","},
        List{RecordOutput, ","},
        String               // specificationId
    )

    // =========================================================================
    // IBC (Inter-Blockchain Communication)
    // =========================================================================

    syntax ChannelState ::= "UNINITIALIZED" | "INIT" | "TRYOPEN" | "OPEN" | "CLOSED"

    syntax IBCChannel ::= ibcChannel(
        String,       // channelId
        String,       // portId
        String,       // counterpartyChannelId
        String,       // counterpartyPortId
        String,       // connectionId
        String,       // version
        ChannelState, // state
        Int           // ordering (0 = UNORDERED, 1 = ORDERED)
    )

    syntax IBCPacket ::= ibcPacket(
        Int,    // sequence
        String, // sourcePort
        String, // sourceChannel
        String, // destinationPort
        String, // destinationChannel
        Bytes,  // data
        Int,    // timeoutHeight
        Int     // timeoutTimestamp
    )

    syntax IBCTransfer ::= ibcTransfer(
        String, // sender
        String, // receiver
        String, // denom
        Int,    // amount
        String  // memo
    )

    // =========================================================================
    // NULLIFIERS AND CROSS-DOMAIN
    // =========================================================================

    syntax Nullifier ::= nullifier(Bytes)
    syntax PILBinding ::= pilBinding(Bytes)

    syntax CrossDomainProof ::= crossDomainProof(
        Nullifier, // nullifier
        Int,       // sourceChainId
        Int,       // targetChainId
        Bytes,     // commitment
        Int,       // timestamp
        Bytes      // proof
    )

    // =========================================================================
    // BRIDGE OPERATIONS
    // =========================================================================

    syntax BridgeOp ::= deposit(Address, String, String, Int)     // depositor, recipient, denom, amount
                      | withdraw(String, Address, String, Int)    // sender, recipient, denom, amount
                      | registerNullifier(Bytes, Int, Bytes, String) // txHash, height, scopeId, denom
                      | finalizeBlock(Int, Bytes, Int)            // height, hash, signingPower

endmodule

module PROVENANCE-RULES
    imports PROVENANCE-SYNTAX

    // =========================================================================
    // HASH FUNCTIONS
    // =========================================================================

    syntax Bytes ::= sha256(Bytes) [function]
                   | keccak256(Bytes) [function]
                   | pubkeyToAddress(Pubkey) [function]

    // Address derivation: RIPEMD160(SHA256(pubkey))
    rule pubkeyToAddress(pubkey(P)) => address(ripemd160(sha256(P)))

    syntax Bytes ::= ripemd160(Bytes) [function]

    // Block header hash
    syntax Bytes ::= computeBlockHeaderHash(BlockHeader) [function]

    rule computeBlockHeaderHash(blockHeader(H, T, LB, DH, VH, NVH, CH, AH, LRH, EH, PA))
        => sha256(encodeBlockHeader(H, T, LB, DH, VH, NVH, CH, AH, LRH, EH, PA))

    syntax Bytes ::= encodeBlockHeader(Int, Int, Bytes, Bytes, Bytes, Bytes, Bytes, Bytes, Bytes, Bytes, Address) [function]

    // =========================================================================
    // NULLIFIER DERIVATION
    // =========================================================================

    // Provenance nullifier: SHA256(txHash || blockHeight || scopeId || denom || "PROVENANCE_NULLIFIER")
    syntax Bytes ::= deriveProvenanceNullifier(Bytes, Int, Bytes, String) [function]

    rule deriveProvenanceNullifier(TxHash, BlockHeight, ScopeId, Denom)
        => sha256(TxHash +Bytes intToBytes(BlockHeight) +Bytes ScopeId +Bytes stringToBytes(Denom) +Bytes b"PROVENANCE_NULLIFIER")

    // Cross-domain nullifier: Keccak256(provNf || targetDomain || "PROV2TARGET")
    syntax Bytes ::= deriveCrossDomainNullifier(Bytes, Int) [function]

    rule deriveCrossDomainNullifier(ProvNf, TargetDomain)
        => keccak256(ProvNf +Bytes intToBytes(TargetDomain) +Bytes b"PROV2TARGET")

    // PIL binding: Keccak256(provNf || pilDomain || "PROV2PIL")
    syntax Bytes ::= derivePILBinding(Bytes, Bytes) [function]

    rule derivePILBinding(ProvNf, PILDomain)
        => keccak256(ProvNf +Bytes PILDomain +Bytes b"PROV2PIL")

    // =========================================================================
    // CONSENSUS VALIDATION
    // =========================================================================

    syntax Int ::= getTotalVotingPower(ValidatorSet) [function]

    rule getTotalVotingPower(.List) => 0
    rule getTotalVotingPower(validator(_, P, _), Rest) => P +Int getTotalVotingPower(Rest)

    syntax Bool ::= hasQuorum(Int, Int) [function]  // signingPower, totalPower

    // Quorum requires > 2/3 (6667 bps) of voting power
    rule hasQuorum(SigningPower, TotalPower)
        => SigningPower *Int 10000 >Int TotalPower *Int QUORUM_THRESHOLD
        requires TotalPower >Int 0

    rule hasQuorum(_, 0) => false

    // Validate commit signatures reach quorum
    syntax Bool ::= validateCommit(Commit, ValidatorSet) [function]

    rule validateCommit(commit(H, R, BId, Sigs), Validators)
        => hasQuorum(getSigningPower(Sigs, Validators), getTotalVotingPower(Validators))

    syntax Int ::= getSigningPower(List{CommitSig, ","}, ValidatorSet) [function]

    // =========================================================================
    // MARKER VALIDATION
    // =========================================================================

    syntax Bool ::= isValidMarker(Marker) [function]

    rule isValidMarker(marker(Denom, Supply, Manager, Type, Status, Fixed, Gov, Grants))
        => lengthString(Denom) >Int 0 andBool Status ==K ACTIVE

    syntax Bool ::= hasMarkerAccess(Marker, Address, AccessType) [function]

    rule hasMarkerAccess(marker(_, _, _, _, _, _, _, Grants), Account, AccessType)
        => hasAccessGrant(Grants, Account, AccessType)

    syntax Bool ::= hasAccessGrant(AccessGrants, Address, AccessType) [function]

    rule hasAccessGrant(.List, _, _) => false
    rule hasAccessGrant(accessGrant(A, T), Rest, Account, AccessType)
        => (A ==K Account andBool T ==K AccessType) orBool hasAccessGrant(Rest, Account, AccessType)

    // =========================================================================
    // IBC VALIDATION
    // =========================================================================

    syntax Bool ::= isValidIBCChannel(IBCChannel) [function]

    rule isValidIBCChannel(ibcChannel(CId, PId, CCId, CPId, ConnId, Ver, State, Ord))
        => lengthString(CId) >Int 0 andBool lengthString(PId) >Int 0
           andBool lengthString(CCId) >Int 0 andBool lengthString(CPId) >Int 0

    syntax Bool ::= isChannelOpen(IBCChannel) [function]

    rule isChannelOpen(ibcChannel(_, _, _, _, _, _, OPEN, _)) => true
    rule isChannelOpen(_) => false [owise]

    syntax Bool ::= isValidIBCPacket(IBCPacket, Int, Int) [function]  // packet, currentHeight, currentTime

    rule isValidIBCPacket(ibcPacket(Seq, SP, SC, DP, DC, Data, TH, TT), CurrentHeight, CurrentTime)
        => lengthString(SP) >Int 0 andBool lengthString(SC) >Int 0
           andBool lengthString(DP) >Int 0 andBool lengthString(DC) >Int 0
           andBool lengthBytes(Data) >Int 0
           andBool (TH >Int CurrentHeight orBool TT >Int CurrentTime)

    // Packet commitment: SHA256(timeoutTimestamp || timeoutRevision || timeoutHeight || sha256(data))
    syntax Bytes ::= computePacketCommitment(IBCPacket) [function]

    rule computePacketCommitment(ibcPacket(_, _, _, _, _, Data, TH, TT))
        => sha256(intToBytes(TT) +Bytes intToBytes(0) +Bytes intToBytes(TH) +Bytes sha256(Data))

    // =========================================================================
    // SCOPE/METADATA VALIDATION
    // =========================================================================

    syntax Bool ::= isValidScope(Scope) [function]

    rule isValidScope(scope(ScopeId, SpecId, Owners, DataAccess, ValueOwner))
        => lengthBytes(ScopeId) >Int 0 andBool lengthString(SpecId) >Int 0
           andBool size(Owners) >Int 0

    syntax Bool ::= isScopeOwner(Scope, Address) [function]

    rule isScopeOwner(scope(_, _, Owners, _, _), Account)
        => Account inList Owners

    syntax Bool ::= inList(Address, List{Address, ","}) [function]

    rule inList(_, .List) => false
    rule inList(A, (A, Rest)) => true
    rule inList(A, (B, Rest)) => inList(A, Rest) requires A =/=K B

    // Scope hash
    syntax Bytes ::= computeScopeHash(Scope) [function]

    rule computeScopeHash(scope(ScopeId, SpecId, Owners, DataAccess, ValueOwner))
        => sha256(ScopeId +Bytes stringToBytes(SpecId) +Bytes encodeAddresses(Owners) +Bytes addressToBytes(ValueOwner))

    syntax Bytes ::= encodeAddresses(List{Address, ","}) [function]
    syntax Bytes ::= addressToBytes(Address) [function]

    rule addressToBytes(address(B)) => B

    // =========================================================================
    // SIGNATURE VERIFICATION
    // =========================================================================

    // Cosmos sign hash
    syntax Bytes ::= computeCosmosSignHash(String, Int, Int, Bytes, Int, Int) [function]
        // chainId, accountNumber, sequence, messages, gasLimit, feeAmount

    rule computeCosmosSignHash(ChainId, AccNum, Seq, Msgs, GasLimit, FeeAmount)
        => sha256(encodeCosmosSignDoc(ChainId, AccNum, Seq, Msgs, GasLimit, FeeAmount))

    syntax Bytes ::= encodeCosmosSignDoc(String, Int, Int, Bytes, Int, Int) [function]

    // ECDSA verification (secp256k1)
    syntax Bool ::= verifySignature(Bytes, Bytes, Pubkey) [function]  // hash, signature, pubkey

    // =========================================================================
    // HELPER FUNCTIONS
    // =========================================================================

    syntax Bytes ::= intToBytes(Int) [function]
    syntax Bytes ::= stringToBytes(String) [function]
    syntax Bytes ::= _+Bytes_(Bytes, Bytes) [function, left]

endmodule

module PROVENANCE-SECURITY
    imports PROVENANCE-RULES

    // =========================================================================
    // SECURITY INVARIANTS
    // =========================================================================

    // INV-1: Nullifier uniqueness - same inputs always produce same nullifier
    rule deriveProvenanceNullifier(T, H, S, D) ==K deriveProvenanceNullifier(T, H, S, D) => true

    // INV-2: Different inputs produce different nullifiers
    rule deriveProvenanceNullifier(T1, H1, S1, D1) ==K deriveProvenanceNullifier(T2, H2, S2, D2) => false
        requires T1 =/=K T2 orBool H1 =/=Int H2 orBool S1 =/=K S2 orBool D1 =/=K D2

    // INV-3: Cross-domain nullifiers are domain-sensitive
    rule deriveCrossDomainNullifier(N, D1) ==K deriveCrossDomainNullifier(N, D2) => false
        requires D1 =/=Int D2

    // INV-4: PIL bindings are deterministic
    rule derivePILBinding(N, D) ==K derivePILBinding(N, D) => true

    // INV-5: Quorum requires strict majority
    rule hasQuorum(P, T) => false requires P *Int 10000 <=Int T *Int QUORUM_THRESHOLD

    // INV-6: Active marker is valid
    rule isValidMarker(marker(D, _, _, _, ACTIVE, _, _, _)) => true requires lengthString(D) >Int 0

    // INV-7: IBC packet with valid timeout is valid
    rule isValidIBCPacket(ibcPacket(_, SP, SC, DP, DC, Data, TH, _), H, _) => true
        requires lengthString(SP) >Int 0 andBool lengthString(SC) >Int 0
                 andBool lengthString(DP) >Int 0 andBool lengthString(DC) >Int 0
                 andBool lengthBytes(Data) >Int 0 andBool TH >Int H

    // INV-8: Scope owner is in owners list
    rule isScopeOwner(scope(_, _, Owners, _, _), A) => true requires A inList Owners

    // INV-9: Block height monotonicity
    // New blocks must have strictly increasing heights
    syntax Bool ::= isValidBlockSequence(BlockHeader, BlockHeader) [function]

    rule isValidBlockSequence(
        blockHeader(H1, _, _, _, _, _, _, _, _, _, _),
        blockHeader(H2, _, _, _, _, _, _, _, _, _, _)
    ) => H2 >Int H1

    // INV-10: Commit must be for matching height
    syntax Bool ::= commitMatchesBlock(Commit, BlockHeader) [function]

    rule commitMatchesBlock(commit(H, _, _, _), blockHeader(H, _, _, _, _, _, _, _, _, _, _)) => true
    rule commitMatchesBlock(_, _) => false [owise]

endmodule

module PROVENANCE-BRIDGE-STATE
    imports PROVENANCE-SECURITY

    // =========================================================================
    // BRIDGE STATE MACHINE
    // =========================================================================

    configuration
        <provenance>
            <validators> .Map </validators>
            <totalVotingPower> 0 </totalVotingPower>
            <finalizedBlocks> .Map </finalizedBlocks>
            <latestHeight> 0 </latestHeight>
            <ibcChannels> .Map </ibcChannels>
            <markers> .Map </markers>
            <deposits> .Map </deposits>
            <withdrawals> .Map </withdrawals>
            <nullifiers> .Set </nullifiers>
            <crossDomainNullifiers> .Map </crossDomainNullifiers>
            <pilBindings> .Map </pilBindings>
            <dailyVolume> 0 </dailyVolume>
            <dailyLimit> 1000000000000000000000000 </dailyLimit>  // 1M ETH
            <circuitBreaker> false </circuitBreaker>
        </provenance>

    // =========================================================================
    // VALIDATOR OPERATIONS
    // =========================================================================

    // Add validator
    rule <provenance>
            <validators> V => V[Id <- validator(P, Power, 0)] </validators>
            <totalVotingPower> T => T +Int Power </totalVotingPower>
            ...
         </provenance>
        requires notBool Id in_keys(V)
         andBool Power >Int 0
         andBool lengthBytes(P) ==Int 33
        where Id = keccak256(P)

    // Remove validator
    rule <provenance>
            <validators> V => V[Id <- undef] </validators>
            <totalVotingPower> T => T -Int Power </totalVotingPower>
            ...
         </provenance>
        requires Id in_keys(V)
         andBool V[Id] ==K validator(_, Power, _)

    // =========================================================================
    // BLOCK FINALIZATION
    // =========================================================================

    // Finalize block with quorum
    rule <provenance>
            <finalizedBlocks> FB => FB[Height <- Hash] </finalizedBlocks>
            <latestHeight> _ => Height </latestHeight>
            <totalVotingPower> Total </totalVotingPower>
            ...
         </provenance>
        when finalizeBlock(Height, Hash, SigningPower)
        requires Height >Int latestHeight
         andBool hasQuorum(SigningPower, Total)

    // =========================================================================
    // NULLIFIER REGISTRATION
    // =========================================================================

    // Register nullifier
    rule <provenance>
            <nullifiers> N => N |Set SetItem(Nf) </nullifiers>
            ...
         </provenance>
        when registerNullifier(TxHash, Height, ScopeId, Denom)
        requires notBool Nf in N
        where Nf = deriveProvenanceNullifier(TxHash, Height, ScopeId, Denom)

    // Cross-domain nullifier
    rule <provenance>
            <nullifiers> N </nullifiers>
            <crossDomainNullifiers> CN => CN[CrossNf <- ProvNf] </crossDomainNullifiers>
            ...
         </provenance>
        requires ProvNf in N
         andBool notBool CrossNf in_keys(CN)
        where CrossNf = deriveCrossDomainNullifier(ProvNf, TargetDomain)

    // PIL binding
    rule <provenance>
            <nullifiers> N </nullifiers>
            <pilBindings> PB => PB[Binding <- ProvNf] </pilBindings>
            ...
         </provenance>
        requires ProvNf in N
         andBool notBool Binding in_keys(PB)
        where Binding = derivePILBinding(ProvNf, PILDomain)

    // =========================================================================
    // DEPOSIT/WITHDRAWAL
    // =========================================================================

    // Deposit
    rule <provenance>
            <deposits> D => D[DepId <- deposit(Depositor, Recipient, Denom, Amount)] </deposits>
            <dailyVolume> V => V +Int Amount </dailyVolume>
            <circuitBreaker> false </circuitBreaker>
            <dailyLimit> Limit </dailyLimit>
            ...
         </provenance>
        when deposit(Depositor, Recipient, Denom, Amount)
        requires Amount >Int 0
         andBool V +Int Amount <=Int Limit

    // Withdrawal
    rule <provenance>
            <withdrawals> W => W[WId <- withdraw(Sender, Recipient, Denom, Amount)] </withdrawals>
            <finalizedBlocks> FB </finalizedBlocks>
            ...
         </provenance>
        when withdraw(Sender, Recipient, Denom, Amount)
        requires Height in_keys(FB)  // Block must be finalized

endmodule

module PROVENANCE
    imports PROVENANCE-BRIDGE-STATE
endmodule
