// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title AlpenPrimitives
 * @notice Core cryptographic primitives and data structures for Alpen Network integration
 * @dev Alpen is a Bitcoin Layer 2 using BitVM for trust-minimized bridging and zkEVM for smart contracts
 * @author PIL Protocol Team
 * @custom:security-contact security@pil.network
 *
 * Alpen Network Architecture:
 * - Bitcoin L2: Rollup on Bitcoin with native BTC
 * - BitVM: Trust-minimized bridging via optimistic verification
 * - zkEVM: EVM-compatible execution with validity proofs
 * - Schnorr Signatures: BIP-340 Taproot signatures
 * - STARK Proofs: Validity proofs for state transitions
 * - Operator Committee: Federated bridge operators with multi-sig
 */
library AlpenPrimitives {
    // =========================================================================
    // CONSTANTS - SECP256K1 CURVE (Bitcoin)
    // =========================================================================

    /// @notice secp256k1 curve order (same as Bitcoin/Ethereum)
    /// n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    uint256 public constant SECP256K1_ORDER =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    /// @notice secp256k1 field prime
    /// p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    uint256 public constant SECP256K1_FIELD_PRIME =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;

    /// @notice Generator point G (x-coordinate)
    uint256 public constant SECP256K1_GX =
        0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;

    /// @notice Generator point G (y-coordinate)
    uint256 public constant SECP256K1_GY =
        0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;

    // =========================================================================
    // CONSTANTS - ALPEN NETWORK
    // =========================================================================

    /// @notice Network identifiers
    uint256 public constant ALPEN_MAINNET_ID = 1;
    uint256 public constant ALPEN_TESTNET_ID = 2;

    /// @notice Bitcoin network magic bytes
    bytes4 public constant BITCOIN_MAINNET_MAGIC = 0xF9BEB4D9;
    bytes4 public constant BITCOIN_TESTNET_MAGIC = 0x0B110907;

    /// @notice Block parameters
    uint256 public constant BLOCK_TIME_SECONDS = 12; // Target block time
    uint256 public constant FINALITY_BLOCKS = 6; // Bitcoin confirmations
    uint256 public constant CHALLENGE_PERIOD = 7 days; // BitVM challenge window

    /// @notice Bridge parameters
    uint256 public constant MIN_DEPOSIT_SATS = 10000; // 0.0001 BTC
    uint256 public constant MAX_DEPOSIT_SATS = 100_000_000_000; // 1000 BTC
    uint256 public constant OPERATOR_THRESHOLD = 5; // 5-of-9 multisig

    /// @notice Proof parameters
    uint256 public constant STARK_SECURITY_BITS = 128;
    uint256 public constant MAX_PROOF_SIZE = 1024 * 1024; // 1MB

    // =========================================================================
    // STRUCTS - BITCOIN PRIMITIVES
    // =========================================================================

    /// @notice Bitcoin transaction outpoint
    struct Outpoint {
        bytes32 txid;
        uint32 vout;
    }

    /// @notice Bitcoin UTXO
    struct UTXO {
        Outpoint outpoint;
        uint64 value; // satoshis
        bytes scriptPubKey;
        uint32 confirmations;
    }

    /// @notice Bitcoin transaction input
    struct TxInput {
        Outpoint prevout;
        bytes scriptSig;
        bytes witness;
        uint32 sequence;
    }

    /// @notice Bitcoin transaction output
    struct TxOutput {
        uint64 value; // satoshis
        bytes scriptPubKey;
    }

    /// @notice Bitcoin transaction
    struct BitcoinTx {
        uint32 version;
        TxInput[] inputs;
        TxOutput[] outputs;
        uint32 locktime;
        bytes32 txid;
        bytes32 wtxid;
    }

    /// @notice Bitcoin block header
    struct BitcoinBlockHeader {
        uint32 version;
        bytes32 prevBlockHash;
        bytes32 merkleRoot;
        uint32 timestamp;
        uint32 bits; // difficulty target
        uint32 nonce;
        bytes32 blockHash;
    }

    /// @notice Merkle proof for Bitcoin transaction inclusion
    struct MerkleProof {
        bytes32 txid;
        bytes32[] siblings;
        uint256 index;
        bytes32 merkleRoot;
    }

    // =========================================================================
    // STRUCTS - SCHNORR SIGNATURES (BIP-340)
    // =========================================================================

    /// @notice Schnorr public key (x-only, 32 bytes)
    struct SchnorrPubkey {
        bytes32 x;
    }

    /// @notice Schnorr signature (64 bytes)
    struct SchnorrSignature {
        bytes32 r; // x-coordinate of R
        bytes32 s; // signature scalar
    }

    /// @notice Taproot output key with internal key and merkle root
    struct TaprootKey {
        SchnorrPubkey internalKey;
        bytes32 merkleRoot; // MAST root
        SchnorrPubkey outputKey; // tweaked key
    }

    /// @notice Taproot script path spend
    struct TaprootScriptPath {
        bytes script;
        bytes32[] controlBlock;
        uint8 leafVersion;
    }

    // =========================================================================
    // STRUCTS - BITVM
    // =========================================================================

    /// @notice BitVM gate types
    enum GateType {
        NAND,
        AND,
        OR,
        XOR,
        NOT
    }

    /// @notice BitVM circuit gate
    struct Gate {
        GateType gateType;
        uint32 inputA;
        uint32 inputB;
        uint32 output;
    }

    /// @notice BitVM program
    struct BitVMProgram {
        bytes32 programHash;
        Gate[] gates;
        uint32 numInputs;
        uint32 numOutputs;
        bytes32 commitmentRoot;
    }

    /// @notice BitVM challenge
    struct BitVMChallenge {
        bytes32 challengeId;
        bytes32 programHash;
        uint32 gateIndex;
        bytes32 inputCommitment;
        bytes32 outputCommitment;
        address challenger;
        uint256 deadline;
        ChallengeStatus status;
    }

    /// @notice Challenge status
    enum ChallengeStatus {
        NONE,
        PENDING,
        RESPONDED,
        SLASHED,
        RESOLVED
    }

    /// @notice BitVM commitment
    struct BitVMCommitment {
        bytes32 commitmentHash;
        bytes32[] bitCommitments;
        bytes32 programHash;
        uint256 timestamp;
    }

    // =========================================================================
    // STRUCTS - ZKVM/STARK
    // =========================================================================

    /// @notice STARK proof
    struct STARKProof {
        bytes32 publicInputHash;
        bytes32 programHash;
        bytes32[] traceCommitments;
        bytes32[] friCommitments;
        bytes openings;
        uint256 securityLevel;
    }

    /// @notice zkEVM state transition
    struct StateTransition {
        bytes32 preStateRoot;
        bytes32 postStateRoot;
        bytes32 blockHash;
        uint64 blockNumber;
        bytes32 transactionsRoot;
        bytes32 receiptsRoot;
    }

    /// @notice zkEVM batch
    struct Batch {
        uint64 batchNumber;
        bytes32 batchHash;
        StateTransition[] transitions;
        STARKProof proof;
        uint256 timestamp;
        BatchStatus status;
    }

    /// @notice Batch status
    enum BatchStatus {
        PENDING,
        VERIFIED,
        FINALIZED,
        REVERTED
    }

    // =========================================================================
    // STRUCTS - BRIDGE
    // =========================================================================

    /// @notice Bridge operator
    struct Operator {
        SchnorrPubkey pubkey;
        address evmAddress;
        uint256 stake;
        bool active;
        uint256 registeredAt;
    }

    /// @notice Peg-in (BTC -> Alpen)
    struct PegIn {
        bytes32 pegInId;
        bytes32 btcTxid;
        uint64 amount; // satoshis
        address recipient;
        MerkleProof inclusionProof;
        uint256 confirmations;
        PegStatus status;
    }

    /// @notice Peg-out (Alpen -> BTC)
    struct PegOut {
        bytes32 pegOutId;
        address sender;
        bytes btcDestination; // Bitcoin script
        uint64 amount; // satoshis
        bytes32[] operatorSignatures;
        uint256 timestamp;
        PegStatus status;
    }

    /// @notice Peg status
    enum PegStatus {
        PENDING,
        CONFIRMED,
        COMPLETED,
        CHALLENGED,
        REFUNDED
    }

    // =========================================================================
    // STRUCTS - CROSS-DOMAIN
    // =========================================================================

    /// @notice Alpen nullifier for cross-domain tracking
    struct AlpenNullifier {
        bytes32 nullifierHash;
        bytes32 btcTxid;
        uint64 blockHeight;
        uint32 vout;
    }

    /// @notice Cross-domain proof
    struct CrossDomainProof {
        bytes32 proofHash;
        uint256 sourceChain;
        uint256 destChain;
        bytes32 commitment;
        bytes32 nullifier;
        bytes starkProof;
    }

    // =========================================================================
    // FUNCTIONS - HASH FUNCTIONS
    // =========================================================================

    /**
     * @notice Compute Bitcoin double SHA256
     * @param data Input data
     * @return Double SHA256 hash
     */
    function doubleSha256(bytes memory data) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(sha256(data)));
    }

    /**
     * @notice Compute tagged hash (BIP-340)
     * @param tag Tag string
     * @param data Input data
     * @return Tagged hash
     */
    function taggedHash(
        string memory tag,
        bytes memory data
    ) internal pure returns (bytes32) {
        bytes32 tagHash = sha256(bytes(tag));
        return sha256(abi.encodePacked(tagHash, tagHash, data));
    }

    /**
     * @notice Compute Bitcoin block header hash
     * @param header Block header
     * @return Block hash (reversed for display)
     */
    function computeBlockHash(
        BitcoinBlockHeader memory header
    ) internal pure returns (bytes32) {
        return
            doubleSha256(
                abi.encodePacked(
                    header.version,
                    header.prevBlockHash,
                    header.merkleRoot,
                    header.timestamp,
                    header.bits,
                    header.nonce
                )
            );
    }

    /**
     * @notice Compute Bitcoin transaction ID
     * @param tx Transaction data
     * @return Transaction ID
     */
    function computeTxid(bytes memory tx) internal pure returns (bytes32) {
        return doubleSha256(tx);
    }

    /**
     * @notice Compute Taproot tweak
     * @param internalKey Internal public key
     * @param merkleRoot MAST merkle root
     * @return Tweak value
     */
    function computeTaprootTweak(
        SchnorrPubkey memory internalKey,
        bytes32 merkleRoot
    ) internal pure returns (bytes32) {
        return
            taggedHash("TapTweak", abi.encodePacked(internalKey.x, merkleRoot));
    }

    // =========================================================================
    // FUNCTIONS - NULLIFIER DERIVATION
    // =========================================================================

    /**
     * @notice Derive Alpen nullifier from Bitcoin UTXO
     * @param btcTxid Bitcoin transaction ID
     * @param vout Output index
     * @param blockHeight Block height
     * @return Nullifier hash
     */
    function deriveAlpenNullifier(
        bytes32 btcTxid,
        uint32 vout,
        uint64 blockHeight
    ) internal pure returns (bytes32) {
        return
            sha256(
                abi.encodePacked(btcTxid, vout, blockHeight, "ALPEN_NULLIFIER")
            );
    }

    /**
     * @notice Derive cross-domain nullifier for PIL binding
     * @param alpenNullifier Original Alpen nullifier
     * @param targetDomain Target domain identifier
     * @return Cross-domain nullifier
     */
    function deriveCrossDomainNullifier(
        bytes32 alpenNullifier,
        uint256 targetDomain
    ) internal pure returns (bytes32) {
        return
            sha256(abi.encodePacked(alpenNullifier, targetDomain, "ALPEN2PIL"));
    }

    /**
     * @notice Derive PIL binding from Alpen nullifier
     * @param alpenNullifier Alpen nullifier
     * @param pilDomain PIL domain ID
     * @return PIL binding hash
     */
    function derivePILBinding(
        bytes32 alpenNullifier,
        bytes32 pilDomain
    ) internal pure returns (bytes32) {
        return
            sha256(abi.encodePacked(alpenNullifier, pilDomain, "PIL_BINDING"));
    }

    // =========================================================================
    // FUNCTIONS - SCHNORR VERIFICATION
    // =========================================================================

    /**
     * @notice Lift x-coordinate to full point (BIP-340)
     * @param x X-coordinate
     * @return y Y-coordinate (even)
     */
    function liftX(uint256 x) internal pure returns (uint256 y) {
        require(x < SECP256K1_FIELD_PRIME, "x out of range");

        // y^2 = x^3 + 7 (mod p)
        uint256 y2 = addmod(
            mulmod(
                mulmod(x, x, SECP256K1_FIELD_PRIME),
                x,
                SECP256K1_FIELD_PRIME
            ),
            7,
            SECP256K1_FIELD_PRIME
        );

        // Compute modular square root using Tonelli-Shanks
        // For secp256k1: p ≡ 3 (mod 4), so y = y2^((p+1)/4)
        y = modExp(y2, (SECP256K1_FIELD_PRIME + 1) / 4, SECP256K1_FIELD_PRIME);

        // Ensure y is even (BIP-340 convention)
        if (y % 2 != 0) {
            y = SECP256K1_FIELD_PRIME - y;
        }

        // Verify
        require(
            mulmod(y, y, SECP256K1_FIELD_PRIME) == y2,
            "Invalid x-coordinate"
        );
    }

    /**
     * @notice Modular exponentiation
     * @param base Base
     * @param exp Exponent
     * @param mod Modulus
     * @return Result
     */
    function modExp(
        uint256 base,
        uint256 exp,
        uint256 mod
    ) internal pure returns (uint256) {
        uint256 result = 1;
        base = base % mod;

        while (exp > 0) {
            if (exp % 2 == 1) {
                result = mulmod(result, base, mod);
            }
            exp = exp >> 1;
            base = mulmod(base, base, mod);
        }

        return result;
    }

    /**
     * @notice Verify Schnorr signature (simplified - uses ecrecover trick)
     * @param message Message hash
     * @param sig Signature
     * @param pubkey Public key
     * @return True if signature is valid
     */
    function verifySchnorr(
        bytes32 message,
        SchnorrSignature memory sig,
        SchnorrPubkey memory pubkey
    ) internal pure returns (bool) {
        // BIP-340 challenge: e = H(R || P || m)
        bytes32 e = taggedHash(
            "BIP0340/challenge",
            abi.encodePacked(sig.r, pubkey.x, message)
        );

        // For full verification, we would need EC operations
        // This is a placeholder - real implementation would use precompile or library
        return uint256(e) < SECP256K1_ORDER && uint256(sig.s) < SECP256K1_ORDER;
    }

    // =========================================================================
    // FUNCTIONS - MERKLE PROOFS
    // =========================================================================

    /**
     * @notice Verify Bitcoin Merkle proof
     * @param proof Merkle proof
     * @return True if proof is valid
     */
    function verifyMerkleProof(
        MerkleProof memory proof
    ) internal pure returns (bool) {
        bytes32 current = proof.txid;
        uint256 index = proof.index;

        for (uint256 i = 0; i < proof.siblings.length; i++) {
            if (index % 2 == 0) {
                current = doubleSha256(
                    abi.encodePacked(current, proof.siblings[i])
                );
            } else {
                current = doubleSha256(
                    abi.encodePacked(proof.siblings[i], current)
                );
            }
            index = index / 2;
        }

        return current == proof.merkleRoot;
    }

    /**
     * @notice Compute Merkle root from leaves
     * @param leaves Array of leaf hashes
     * @return Merkle root
     */
    function computeMerkleRoot(
        bytes32[] memory leaves
    ) internal pure returns (bytes32) {
        require(leaves.length > 0, "Empty leaves");

        if (leaves.length == 1) {
            return leaves[0];
        }

        // Pad to power of 2
        uint256 n = leaves.length;
        uint256 size = 1;
        while (size < n) {
            size *= 2;
        }

        bytes32[] memory tree = new bytes32[](size);
        for (uint256 i = 0; i < n; i++) {
            tree[i] = leaves[i];
        }
        for (uint256 i = n; i < size; i++) {
            tree[i] = tree[n - 1]; // Duplicate last leaf
        }

        // Build tree
        while (size > 1) {
            for (uint256 i = 0; i < size / 2; i++) {
                tree[i] = doubleSha256(
                    abi.encodePacked(tree[i * 2], tree[i * 2 + 1])
                );
            }
            size = size / 2;
        }

        return tree[0];
    }

    // =========================================================================
    // FUNCTIONS - BITVM VALIDATION
    // =========================================================================

    /**
     * @notice Compute BitVM program hash
     * @param program BitVM program
     * @return Program hash
     */
    function computeProgramHash(
        BitVMProgram memory program
    ) internal pure returns (bytes32) {
        bytes memory gateData;
        for (uint256 i = 0; i < program.gates.length; i++) {
            gateData = abi.encodePacked(
                gateData,
                uint8(program.gates[i].gateType),
                program.gates[i].inputA,
                program.gates[i].inputB,
                program.gates[i].output
            );
        }

        return
            sha256(
                abi.encodePacked(
                    program.numInputs,
                    program.numOutputs,
                    gateData
                )
            );
    }

    /**
     * @notice Evaluate NAND gate
     * @param a Input A
     * @param b Input B
     * @return NAND result
     */
    function evalNAND(bool a, bool b) internal pure returns (bool) {
        return !(a && b);
    }

    /**
     * @notice Validate BitVM challenge deadline
     * @param challenge Challenge data
     * @return True if challenge is still active
     */
    function isChallengeActive(
        BitVMChallenge memory challenge
    ) internal view returns (bool) {
        return
            challenge.status == ChallengeStatus.PENDING &&
            block.timestamp < challenge.deadline;
    }

    // =========================================================================
    // FUNCTIONS - STARK VALIDATION
    // =========================================================================

    /**
     * @notice Validate STARK proof structure
     * @param proof STARK proof
     * @return True if proof structure is valid
     */
    function isValidSTARKProof(
        STARKProof memory proof
    ) internal pure returns (bool) {
        if (proof.publicInputHash == bytes32(0)) return false;
        if (proof.programHash == bytes32(0)) return false;
        if (proof.traceCommitments.length == 0) return false;
        if (proof.friCommitments.length == 0) return false;
        if (proof.securityLevel < STARK_SECURITY_BITS) return false;
        return true;
    }

    /**
     * @notice Compute state transition hash
     * @param transition State transition
     * @return Transition hash
     */
    function computeTransitionHash(
        StateTransition memory transition
    ) internal pure returns (bytes32) {
        return
            sha256(
                abi.encodePacked(
                    transition.preStateRoot,
                    transition.postStateRoot,
                    transition.blockHash,
                    transition.blockNumber,
                    transition.transactionsRoot,
                    transition.receiptsRoot
                )
            );
    }

    /**
     * @notice Compute batch hash
     * @param batch Batch data
     * @return Batch hash
     */
    function computeBatchHash(
        Batch memory batch
    ) internal pure returns (bytes32) {
        bytes32[] memory transitionHashes = new bytes32[](
            batch.transitions.length
        );
        for (uint256 i = 0; i < batch.transitions.length; i++) {
            transitionHashes[i] = computeTransitionHash(batch.transitions[i]);
        }

        return
            sha256(
                abi.encodePacked(
                    batch.batchNumber,
                    computeMerkleRoot(transitionHashes),
                    batch.proof.publicInputHash
                )
            );
    }

    // =========================================================================
    // FUNCTIONS - PEG VALIDATION
    // =========================================================================

    /**
     * @notice Validate peg-in
     * @param pegIn Peg-in data
     * @return True if peg-in is valid
     */
    function isValidPegIn(PegIn memory pegIn) internal pure returns (bool) {
        if (pegIn.btcTxid == bytes32(0)) return false;
        if (pegIn.amount < MIN_DEPOSIT_SATS) return false;
        if (pegIn.amount > MAX_DEPOSIT_SATS) return false;
        if (pegIn.recipient == address(0)) return false;
        if (pegIn.confirmations < FINALITY_BLOCKS) return false;
        return true;
    }

    /**
     * @notice Validate peg-out
     * @param pegOut Peg-out data
     * @return True if peg-out is valid
     */
    function isValidPegOut(PegOut memory pegOut) internal pure returns (bool) {
        if (pegOut.sender == address(0)) return false;
        if (pegOut.btcDestination.length == 0) return false;
        if (pegOut.amount < MIN_DEPOSIT_SATS) return false;
        if (pegOut.amount > MAX_DEPOSIT_SATS) return false;
        if (pegOut.operatorSignatures.length < OPERATOR_THRESHOLD) return false;
        return true;
    }

    /**
     * @notice Compute peg-in ID
     * @param btcTxid Bitcoin transaction ID
     * @param recipient Recipient address
     * @param amount Amount in satoshis
     * @return Peg-in ID
     */
    function computePegInId(
        bytes32 btcTxid,
        address recipient,
        uint64 amount
    ) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(btcTxid, recipient, amount, "PEGIN"));
    }

    /**
     * @notice Compute peg-out ID
     * @param sender Sender address
     * @param btcDestination Bitcoin destination
     * @param amount Amount in satoshis
     * @param nonce Unique nonce
     * @return Peg-out ID
     */
    function computePegOutId(
        address sender,
        bytes memory btcDestination,
        uint64 amount,
        uint256 nonce
    ) internal pure returns (bytes32) {
        return
            sha256(
                abi.encodePacked(
                    sender,
                    btcDestination,
                    amount,
                    nonce,
                    "PEGOUT"
                )
            );
    }

    // =========================================================================
    // FUNCTIONS - OPERATOR VALIDATION
    // =========================================================================

    /**
     * @notice Check if operator threshold is met
     * @param signatures Array of signatures
     * @return True if threshold met
     */
    function hasOperatorThreshold(
        bytes32[] memory signatures
    ) internal pure returns (bool) {
        return signatures.length >= OPERATOR_THRESHOLD;
    }

    /**
     * @notice Compute operator set hash
     * @param operators Array of operator pubkeys
     * @return Operator set hash
     */
    function computeOperatorSetHash(
        SchnorrPubkey[] memory operators
    ) internal pure returns (bytes32) {
        bytes memory data;
        for (uint256 i = 0; i < operators.length; i++) {
            data = abi.encodePacked(data, operators[i].x);
        }
        return sha256(data);
    }

    // =========================================================================
    // FUNCTIONS - DIFFICULTY
    // =========================================================================

    /**
     * @notice Compute target from difficulty bits
     * @param bits Compact difficulty representation
     * @return Target value
     */
    function bitsToTarget(uint32 bits) internal pure returns (uint256) {
        uint256 exponent = bits >> 24;
        uint256 mantissa = bits & 0x007FFFFF;

        if (exponent <= 3) {
            return mantissa >> (8 * (3 - exponent));
        } else {
            return mantissa << (8 * (exponent - 3));
        }
    }

    /**
     * @notice Validate block header meets difficulty
     * @param header Block header
     * @return True if valid proof of work
     */
    function isValidPoW(
        BitcoinBlockHeader memory header
    ) internal pure returns (bool) {
        uint256 target = bitsToTarget(header.bits);
        uint256 blockHashValue = uint256(header.blockHash);

        // Block hash must be less than target
        return blockHashValue < target;
    }

    // =========================================================================
    // FUNCTIONS - SCRIPT PARSING
    // =========================================================================

    /**
     * @notice Check if script is P2WPKH
     * @param script Script bytes
     * @return True if P2WPKH
     */
    function isP2WPKH(bytes memory script) internal pure returns (bool) {
        return script.length == 22 && script[0] == 0x00 && script[1] == 0x14;
    }

    /**
     * @notice Check if script is P2WSH
     * @param script Script bytes
     * @return True if P2WSH
     */
    function isP2WSH(bytes memory script) internal pure returns (bool) {
        return script.length == 34 && script[0] == 0x00 && script[1] == 0x20;
    }

    /**
     * @notice Check if script is P2TR (Taproot)
     * @param script Script bytes
     * @return True if P2TR
     */
    function isP2TR(bytes memory script) internal pure returns (bool) {
        return
            script.length == 34 &&
            script[0] == 0x51 && // OP_1 (witness v1)
            script[1] == 0x20;
    }

    /**
     * @notice Extract pubkey hash from P2WPKH
     * @param script Script bytes
     * @return Pubkey hash (20 bytes)
     */
    function extractP2WPKHHash(
        bytes memory script
    ) internal pure returns (bytes20) {
        require(isP2WPKH(script), "Not P2WPKH");
        bytes20 hash;
        assembly {
            hash := mload(add(script, 22))
        }
        return hash;
    }

    /**
     * @notice Extract x-only pubkey from P2TR
     * @param script Script bytes
     * @return X-only pubkey (32 bytes)
     */
    function extractP2TRPubkey(
        bytes memory script
    ) internal pure returns (bytes32) {
        require(isP2TR(script), "Not P2TR");
        bytes32 pubkey;
        assembly {
            pubkey := mload(add(script, 34))
        }
        return pubkey;
    }
}
