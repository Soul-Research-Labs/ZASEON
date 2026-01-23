// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title LineaPrimitives
 * @notice Core cryptographic primitives and data structures for Linea zkEVM integration
 * @dev Linea is a zkEVM L2 by Consensys using PLONK proofs and type 2 zkEVM
 * @author PIL Protocol Team
 * @custom:security-contact security@pil.network
 *
 * Linea Architecture:
 * - Type 2 zkEVM: EVM-equivalent with minimal modifications
 * - PLONK proof system: Efficient verification with trusted setup
 * - Vortex prover: Custom prover for EVM trace generation
 * - BLS12-381 curve: For pairing-based proof verification
 * - Message Service: Canonical L1 <-> L2 messaging
 * - Finality: ~6 hours on L1 (32 Ethereum blocks)
 */
library LineaPrimitives {
    // =========================================================================
    // CONSTANTS - BLS12-381 CURVE
    // =========================================================================

    /// @notice BLS12-381 field prime (base field) - split into two uint256 for 384-bit representation
    /// p = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    /// Low 256 bits and high 128 bits stored separately
    uint256 public constant BLS12_381_FIELD_PRIME_LOW = 0xb9feffffffffaaab;
    uint256 public constant BLS12_381_FIELD_PRIME_MID =
        0x1eabfffeb153ffffb9feffffffffaaab;
    // Note: Full prime requires multi-precision arithmetic

    /// @notice BLS12-381 scalar field order (for scalars) - fits in uint256
    /// r = 52435875175126190479447740508185965837690552500527637822603658699938581184513
    uint256 public constant BLS12_381_SCALAR_ORDER =
        52435875175126190479447740508185965837690552500527637822603658699938581184513;

    /// @notice PLONK verification constants
    uint256 public constant PLONK_DOMAIN_SIZE_BITS = 20; // 2^20 = ~1M gates
    uint256 public constant PLONK_NUM_ADVICE_COLUMNS = 5;
    uint256 public constant PLONK_NUM_FIXED_COLUMNS = 3;
    uint256 public constant PLONK_NUM_CHALLENGE_ROUNDS = 5;

    /// @notice Linea-specific parameters
    uint256 public constant LINEA_MAINNET_CHAIN_ID = 59144;
    uint256 public constant LINEA_SEPOLIA_CHAIN_ID = 59141;
    uint256 public constant LINEA_GOERLI_CHAIN_ID = 59140; // Deprecated

    /// @notice Finality parameters
    uint256 public constant FINALITY_BLOCKS_L1 = 32; // ~6 hours
    uint256 public constant MESSAGE_FEE_BASE = 0.001 ether;
    uint256 public constant MESSAGE_FEE_PER_BYTE = 100 gwei;

    /// @notice Block production parameters
    uint256 public constant BLOCK_TIME_SECONDS = 3; // Target block time
    uint256 public constant BLOCKS_PER_EPOCH = 1000;
    uint256 public constant CONFLATION_INTERVAL = 100; // Blocks per batch

    // =========================================================================
    // STRUCTS - PLONK PROOF SYSTEM
    // =========================================================================

    /// @notice PLONK proof structure for zkEVM verification
    struct PLONKProof {
        // Commitment polynomials (G1 points on BLS12-381)
        G1Point a; // Advice polynomial commitment
        G1Point b; // Second advice commitment
        G1Point c; // Third advice commitment
        // Permutation commitments
        G1Point z; // Permutation polynomial
        G1Point t_lo; // Quotient polynomial (low)
        G1Point t_mid; // Quotient polynomial (mid)
        G1Point t_hi; // Quotient polynomial (high)
        // Opening proofs
        G1Point w_omega; // Opening at omega
        G1Point w_omega_zeta; // Opening at omega * zeta
        // Evaluation values
        uint256 a_eval;
        uint256 b_eval;
        uint256 c_eval;
        uint256 s_sigma1_eval;
        uint256 s_sigma2_eval;
        uint256 z_omega_eval;
    }

    /// @notice G1 point on BLS12-381 curve
    struct G1Point {
        uint256 x_lo;
        uint256 x_hi;
        uint256 y_lo;
        uint256 y_hi;
    }

    /// @notice G2 point on BLS12-381 curve (extension field)
    struct G2Point {
        uint256[2] x; // Fp2 element (c0, c1)
        uint256[2] y; // Fp2 element (c0, c1)
    }

    /// @notice PLONK verification key
    struct PLONKVerificationKey {
        uint256 domainSize; // Power of 2
        uint256 numPublicInputs;
        G1Point q_m; // Multiplication selector
        G1Point q_l; // Left selector
        G1Point q_r; // Right selector
        G1Point q_o; // Output selector
        G1Point q_c; // Constant selector
        G1Point s_sigma1; // Permutation polynomial 1
        G1Point s_sigma2; // Permutation polynomial 2
        G1Point s_sigma3; // Permutation polynomial 3
        G2Point x_2; // SRS element in G2
        bytes32 vkHash; // Hash of verification key
    }

    // =========================================================================
    // STRUCTS - LINEA MESSAGING
    // =========================================================================

    /// @notice L1 to L2 message structure
    struct L1L2Message {
        address sender; // L1 sender
        address recipient; // L2 recipient
        uint256 value; // ETH value
        uint256 fee; // Message fee
        uint256 nonce; // Unique nonce
        uint256 deadline; // Expiration timestamp
        bytes data; // Calldata
        bytes32 messageHash; // keccak256 hash
    }

    /// @notice L2 to L1 message structure
    struct L2L1Message {
        address sender; // L2 sender
        address recipient; // L1 recipient
        uint256 value; // ETH value
        uint256 nonce; // Unique nonce
        uint256 blockNumber; // L2 block number
        bytes data; // Calldata
        bytes32 messageHash; // keccak256 hash
        bool finalized; // Whether finalized on L1
    }

    /// @notice Message status enum
    enum MessageStatus {
        UNKNOWN,
        PENDING,
        DELIVERED,
        FAILED,
        REFUNDED,
        CLAIMED
    }

    /// @notice Message claim proof
    struct MessageClaimProof {
        bytes32 messageHash;
        bytes32[] merkleProof;
        uint256 leafIndex;
        bytes32 root;
        uint256 l2BlockNumber;
        bytes32 l2StateRoot;
    }

    // =========================================================================
    // STRUCTS - LINEA STATE
    // =========================================================================

    /// @notice Linea block header
    struct LineaBlockHeader {
        uint256 blockNumber;
        bytes32 stateRoot;
        bytes32 transactionsRoot;
        bytes32 receiptsRoot;
        bytes32 logsBloom;
        uint256 timestamp;
        uint256 gasLimit;
        uint256 gasUsed;
        address coinbase;
        bytes32 parentHash;
        bytes32 mixHash;
        uint256 baseFee;
    }

    /// @notice Batch submission data (conflation)
    struct LineaBatch {
        uint256 batchIndex;
        uint256 firstBlockNumber;
        uint256 lastBlockNumber;
        bytes32 batchDataHash;
        bytes32 previousStateRoot;
        bytes32 newStateRoot;
        uint256 timestamp;
        bytes32[] l2MessageHashes;
        PLONKProof proof;
    }

    /// @notice Finalization data
    struct FinalizationData {
        bytes32 parentStateRootHash;
        uint256 finalBlockInData;
        bytes32 finalStateRootHash;
        bytes32 l2MerkleRoot;
        bytes32 l2MessageServiceAddress;
        uint256 l2MessagingBlocksOffset;
        bytes32[] l2MerkleTreeRoots;
    }

    // =========================================================================
    // STRUCTS - NULLIFIER AND CROSS-DOMAIN
    // =========================================================================

    /// @notice Linea nullifier for cross-domain tracking
    struct LineaNullifier {
        bytes32 nullifierHash;
        bytes32 messageHash;
        uint256 l2BlockNumber;
        uint256 l1FinalizedBlock;
        bytes32 proofHash;
    }

    /// @notice Cross-domain proof transfer
    struct CrossDomainProof {
        bytes32 proofHash;
        uint256 sourceChain;
        uint256 destChain;
        bytes32 commitment;
        bytes32 nullifier;
        bytes publicInputs;
        bytes proof;
    }

    // =========================================================================
    // FUNCTIONS - HASH FUNCTIONS
    // =========================================================================

    /**
     * @notice Compute keccak256 hash (Linea's native hash function)
     * @param data Input data
     * @return Hash result
     */
    function keccak256Hash(bytes memory data) internal pure returns (bytes32) {
        return keccak256(data);
    }

    /**
     * @notice Compute message hash for L1 -> L2 messages
     * @param sender Sender address
     * @param recipient Recipient address
     * @param value ETH value
     * @param nonce Message nonce
     * @param data Calldata
     * @return Message hash
     */
    function computeL1L2MessageHash(
        address sender,
        address recipient,
        uint256 value,
        uint256 nonce,
        bytes memory data
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(
                    "LINEA_L1_L2_MESSAGE",
                    sender,
                    recipient,
                    value,
                    nonce,
                    keccak256(data)
                )
            );
    }

    /**
     * @notice Compute message hash for L2 -> L1 messages
     * @param sender Sender address on L2
     * @param recipient Recipient address on L1
     * @param value ETH value
     * @param nonce Message nonce
     * @param blockNumber L2 block number
     * @param data Calldata
     * @return Message hash
     */
    function computeL2L1MessageHash(
        address sender,
        address recipient,
        uint256 value,
        uint256 nonce,
        uint256 blockNumber,
        bytes memory data
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(
                    "LINEA_L2_L1_MESSAGE",
                    sender,
                    recipient,
                    value,
                    nonce,
                    blockNumber,
                    keccak256(data)
                )
            );
    }

    /**
     * @notice Compute batch data hash
     * @param batch Batch data
     * @return Hash of batch
     */
    function computeBatchHash(
        LineaBatch memory batch
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(
                    batch.batchIndex,
                    batch.firstBlockNumber,
                    batch.lastBlockNumber,
                    batch.previousStateRoot,
                    batch.newStateRoot,
                    batch.timestamp
                )
            );
    }

    // =========================================================================
    // FUNCTIONS - NULLIFIER DERIVATION
    // =========================================================================

    /**
     * @notice Derive Linea nullifier from message hash
     * @param messageHash Message hash
     * @param blockNumber L2 block number
     * @param commitment Commitment value
     * @return Nullifier hash
     */
    function deriveLineaNullifier(
        bytes32 messageHash,
        uint256 blockNumber,
        bytes32 commitment
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(
                    messageHash,
                    blockNumber,
                    commitment,
                    "LINEA_NULLIFIER"
                )
            );
    }

    /**
     * @notice Derive cross-domain nullifier for PIL binding
     * @param lineaNullifier Original Linea nullifier
     * @param targetDomain Target domain identifier
     * @return Cross-domain nullifier
     */
    function deriveCrossDomainNullifier(
        bytes32 lineaNullifier,
        uint256 targetDomain
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(lineaNullifier, targetDomain, "LINEA2PIL")
            );
    }

    /**
     * @notice Derive PIL binding from Linea nullifier
     * @param lineaNullifier Linea nullifier
     * @param pilDomain PIL domain ID
     * @return PIL binding hash
     */
    function derivePILBinding(
        bytes32 lineaNullifier,
        bytes32 pilDomain
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(lineaNullifier, pilDomain, "PIL_BINDING")
            );
    }

    // =========================================================================
    // FUNCTIONS - MERKLE PROOFS
    // =========================================================================

    /**
     * @notice Verify Merkle proof for message inclusion
     * @param root Merkle root
     * @param leaf Leaf hash
     * @param proof Merkle proof (sibling hashes)
     * @param index Leaf index
     * @return True if proof is valid
     */
    function verifyMerkleProof(
        bytes32 root,
        bytes32 leaf,
        bytes32[] memory proof,
        uint256 index
    ) internal pure returns (bool) {
        bytes32 computedHash = leaf;

        for (uint256 i = 0; i < proof.length; i++) {
            if (index % 2 == 0) {
                computedHash = keccak256(
                    abi.encodePacked(computedHash, proof[i])
                );
            } else {
                computedHash = keccak256(
                    abi.encodePacked(proof[i], computedHash)
                );
            }
            index = index / 2;
        }

        return computedHash == root;
    }

    /**
     * @notice Compute Merkle root from leaves
     * @param leaves Array of leaf hashes
     * @return Merkle root
     */
    function computeMerkleRoot(
        bytes32[] memory leaves
    ) internal pure returns (bytes32) {
        if (leaves.length == 0) return bytes32(0);
        if (leaves.length == 1) return leaves[0];

        uint256 n = leaves.length;
        bytes32[] memory nodes = new bytes32[](n);
        for (uint256 i = 0; i < n; i++) {
            nodes[i] = leaves[i];
        }

        while (n > 1) {
            uint256 newN = (n + 1) / 2;
            for (uint256 i = 0; i < newN; i++) {
                uint256 left = i * 2;
                uint256 right = left + 1;
                if (right < n) {
                    nodes[i] = keccak256(
                        abi.encodePacked(nodes[left], nodes[right])
                    );
                } else {
                    nodes[i] = nodes[left];
                }
            }
            n = newN;
        }

        return nodes[0];
    }

    // =========================================================================
    // FUNCTIONS - PLONK VERIFICATION HELPERS
    // =========================================================================

    /**
     * @notice Validate PLONK proof structure
     * @param proof The proof to validate
     * @return True if proof structure is valid
     */
    function isValidPLONKProof(
        PLONKProof memory proof
    ) internal pure returns (bool) {
        // Check that G1 points are not at infinity (both coordinates zero)
        if (!isValidG1Point(proof.a)) return false;
        if (!isValidG1Point(proof.b)) return false;
        if (!isValidG1Point(proof.c)) return false;
        if (!isValidG1Point(proof.z)) return false;

        // Check evaluation values are in scalar field
        if (proof.a_eval >= BLS12_381_SCALAR_ORDER) return false;
        if (proof.b_eval >= BLS12_381_SCALAR_ORDER) return false;
        if (proof.c_eval >= BLS12_381_SCALAR_ORDER) return false;
        if (proof.s_sigma1_eval >= BLS12_381_SCALAR_ORDER) return false;
        if (proof.s_sigma2_eval >= BLS12_381_SCALAR_ORDER) return false;
        if (proof.z_omega_eval >= BLS12_381_SCALAR_ORDER) return false;

        return true;
    }

    /**
     * @notice Check if G1 point is valid (not infinity)
     * @param point G1 point to check
     * @return True if point is valid
     */
    function isValidG1Point(G1Point memory point) internal pure returns (bool) {
        // Point at infinity has all zeros
        return
            !(point.x_lo == 0 &&
                point.x_hi == 0 &&
                point.y_lo == 0 &&
                point.y_hi == 0);
    }

    /**
     * @notice Compute verification key hash
     * @param vk Verification key
     * @return Hash of the verification key
     */
    function computeVKHash(
        PLONKVerificationKey memory vk
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(
                    vk.domainSize,
                    vk.numPublicInputs,
                    vk.q_m.x_lo,
                    vk.q_m.x_hi,
                    vk.q_m.y_lo,
                    vk.q_m.y_hi,
                    vk.q_l.x_lo,
                    vk.q_l.x_hi,
                    vk.q_l.y_lo,
                    vk.q_l.y_hi,
                    vk.q_r.x_lo,
                    vk.q_r.x_hi,
                    vk.q_r.y_lo,
                    vk.q_r.y_hi,
                    vk.q_o.x_lo,
                    vk.q_o.x_hi,
                    vk.q_o.y_lo,
                    vk.q_o.y_hi
                )
            );
    }

    /**
     * @notice Compute challenge from transcript (Fiat-Shamir)
     * @param transcript Current transcript hash
     * @param data New data to add
     * @return New challenge value
     */
    function computeChallenge(
        bytes32 transcript,
        bytes memory data
    ) internal pure returns (uint256) {
        bytes32 hash = keccak256(abi.encodePacked(transcript, data));
        return uint256(hash) % BLS12_381_SCALAR_ORDER;
    }

    // =========================================================================
    // FUNCTIONS - MESSAGE VALIDATION
    // =========================================================================

    /**
     * @notice Validate L1 to L2 message
     * @param message Message to validate
     * @return True if message is valid
     */
    function isValidL1L2Message(
        L1L2Message memory message
    ) internal view returns (bool) {
        if (message.sender == address(0)) return false;
        if (message.recipient == address(0)) return false;
        if (message.nonce == 0) return false;
        if (message.deadline != 0 && message.deadline < block.timestamp)
            return false;

        // Verify message hash
        bytes32 expectedHash = computeL1L2MessageHash(
            message.sender,
            message.recipient,
            message.value,
            message.nonce,
            message.data
        );

        return message.messageHash == expectedHash;
    }

    /**
     * @notice Validate L2 to L1 message
     * @param message Message to validate
     * @return True if message is valid
     */
    function isValidL2L1Message(
        L2L1Message memory message
    ) internal pure returns (bool) {
        if (message.sender == address(0)) return false;
        if (message.recipient == address(0)) return false;
        if (message.nonce == 0) return false;
        if (message.blockNumber == 0) return false;

        // Verify message hash
        bytes32 expectedHash = computeL2L1MessageHash(
            message.sender,
            message.recipient,
            message.value,
            message.nonce,
            message.blockNumber,
            message.data
        );

        return message.messageHash == expectedHash;
    }

    /**
     * @notice Calculate message fee
     * @param dataLength Length of message data in bytes
     * @return Fee in wei
     */
    function calculateMessageFee(
        uint256 dataLength
    ) internal pure returns (uint256) {
        return MESSAGE_FEE_BASE + (dataLength * MESSAGE_FEE_PER_BYTE);
    }

    // =========================================================================
    // FUNCTIONS - BATCH VALIDATION
    // =========================================================================

    /**
     * @notice Validate batch submission
     * @param batch Batch to validate
     * @return True if batch is valid
     */
    function isValidBatch(
        LineaBatch memory batch
    ) internal pure returns (bool) {
        // Check block range
        if (batch.firstBlockNumber >= batch.lastBlockNumber) return false;
        if (
            batch.lastBlockNumber - batch.firstBlockNumber > CONFLATION_INTERVAL
        ) return false;

        // Check state roots
        if (batch.previousStateRoot == bytes32(0)) return false;
        if (batch.newStateRoot == bytes32(0)) return false;
        if (batch.previousStateRoot == batch.newStateRoot) return false;

        // Validate proof
        if (!isValidPLONKProof(batch.proof)) return false;

        return true;
    }

    /**
     * @notice Calculate blocks until finalization
     * @param submissionBlock L1 block when batch was submitted
     * @param currentBlock Current L1 block
     * @return Blocks remaining until finalization (0 if finalized)
     */
    function blocksUntilFinalization(
        uint256 submissionBlock,
        uint256 currentBlock
    ) internal pure returns (uint256) {
        if (currentBlock >= submissionBlock + FINALITY_BLOCKS_L1) {
            return 0;
        }
        return (submissionBlock + FINALITY_BLOCKS_L1) - currentBlock;
    }

    /**
     * @notice Check if batch is finalized
     * @param submissionBlock L1 block when batch was submitted
     * @param currentBlock Current L1 block
     * @return True if finalized
     */
    function isBatchFinalized(
        uint256 submissionBlock,
        uint256 currentBlock
    ) internal pure returns (bool) {
        return currentBlock >= submissionBlock + FINALITY_BLOCKS_L1;
    }

    // =========================================================================
    // FUNCTIONS - TYPE 2 ZKEVM
    // =========================================================================

    /**
     * @notice Compute EVM state root after transaction execution
     * @dev This is a simplified version - actual implementation uses full MPT
     * @param prevStateRoot Previous state root
     * @param txHash Transaction hash
     * @param postState Post-transaction state changes
     * @return New state root
     */
    function computeStateTransition(
        bytes32 prevStateRoot,
        bytes32 txHash,
        bytes memory postState
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(prevStateRoot, txHash, keccak256(postState))
            );
    }

    /**
     * @notice Encode EVM trace for proving
     * @param from Sender address
     * @param to Recipient address
     * @param value Transfer value
     * @param gasLimit Gas limit
     * @param gasPrice Gas price
     * @param data Call data
     * @param nonce Sender nonce
     * @return Encoded trace data
     */
    function encodeEVMTrace(
        address from,
        address to,
        uint256 value,
        uint256 gasLimit,
        uint256 gasPrice,
        bytes memory data,
        uint256 nonce
    ) internal pure returns (bytes memory) {
        return abi.encode(from, to, value, gasLimit, gasPrice, data, nonce);
    }

    // =========================================================================
    // FUNCTIONS - UTILITY
    // =========================================================================

    /**
     * @notice Get Linea chain ID based on network
     * @param isMainnet True for mainnet, false for testnet
     * @return Chain ID
     */
    function getChainId(bool isMainnet) internal pure returns (uint256) {
        return isMainnet ? LINEA_MAINNET_CHAIN_ID : LINEA_SEPOLIA_CHAIN_ID;
    }

    /**
     * @notice Encode proof for cross-chain transfer
     * @param proof Cross-domain proof
     * @return Encoded proof bytes
     */
    function encodeCrossDomainProof(
        CrossDomainProof memory proof
    ) internal pure returns (bytes memory) {
        return
            abi.encode(
                proof.proofHash,
                proof.sourceChain,
                proof.destChain,
                proof.commitment,
                proof.nullifier,
                proof.publicInputs,
                proof.proof
            );
    }

    /**
     * @notice Decode cross-domain proof
     * @param encoded Encoded proof bytes
     * @return Decoded proof
     */
    function decodeCrossDomainProof(
        bytes memory encoded
    ) internal pure returns (CrossDomainProof memory) {
        (
            bytes32 proofHash,
            uint256 sourceChain,
            uint256 destChain,
            bytes32 commitment,
            bytes32 nullifier,
            bytes memory publicInputs,
            bytes memory proof
        ) = abi.decode(
                encoded,
                (bytes32, uint256, uint256, bytes32, bytes32, bytes, bytes)
            );

        return
            CrossDomainProof({
                proofHash: proofHash,
                sourceChain: sourceChain,
                destChain: destChain,
                commitment: commitment,
                nullifier: nullifier,
                publicInputs: publicInputs,
                proof: proof
            });
    }

    /**
     * @notice Compute block header hash
     * @param header Block header
     * @return Header hash
     */
    function computeBlockHeaderHash(
        LineaBlockHeader memory header
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(
                    header.parentHash,
                    header.coinbase,
                    header.stateRoot,
                    header.transactionsRoot,
                    header.receiptsRoot,
                    header.logsBloom,
                    header.blockNumber,
                    header.gasLimit,
                    header.gasUsed,
                    header.timestamp,
                    header.mixHash,
                    header.baseFee
                )
            );
    }
}
